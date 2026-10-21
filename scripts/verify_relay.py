#!/usr/bin/env python3
"""Real A -> B -> C relay checks in disposable Linux network namespaces.

Run with STUNNEL_BIN_DIR pointing at built certgen/client/server binaries.
Requires Linux unprivileged user namespaces, iproute2, unshare and nsenter.
Isolation is mandatory; fixture failures never fall back to the host network.
"""
import argparse
import concurrent.futures
import contextlib
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True

import verify_anytls as smoke

TRANSPORTS = ('anytls', 'tlstcp', 'quic', 's2n-quic')
TARGET, BULK, HTTP, UDP = 23101, 23102, 23103, 23104


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def backend():
    servers = [smoke.TcpServer(('127.0.0.1', TARGET), smoke.AfterEof),
               smoke.TcpServer(('127.0.0.1', BULK), smoke.BulkReply),
               smoke.http.server.ThreadingHTTPServer(('127.0.0.1', HTTP), smoke.HttpReply)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(('127.0.0.1', UDP))
        while True:
            data, address = udp.recvfrom(65535)
            udp.sendto(data, address)


class Topology:
    def __init__(self, stack):
        self.pids = {}
        run('ip', 'link', 'set', 'lo', 'up')
        for name in ('b', 'c'):
            child = stack.enter_context(child_process(['unshare', '--net', 'sleep', 'infinity']))
            self.pids[name] = child.pid
            for _ in range(100):
                if os.readlink('/proc/%d/ns/net' % child.pid) != os.readlink('/proc/self/ns/net'):
                    break
                time.sleep(.01)
            else:
                raise AssertionError('network namespace did not start')
            self.ip(name, 'link', 'set', 'lo', 'up')
        for left, right, subnet, names in [('a', 'b', '10.211.1', ('ab-a', 'ab-b')),
                                            ('b', 'c', '10.211.2', ('bc-b', 'bc-c'))]:
            run('ip', 'link', 'add', names[0], 'type', 'veth', 'peer', 'name', names[1])
            for index, (node, interface) in enumerate(zip((left, right), names), 1):
                if node != 'a':
                    run('ip', 'link', 'set', interface, 'netns', str(self.pids[node]))
                self.ip(node, 'addr', 'add', subnet + '.%d/24' % index, 'dev', interface)
                self.ip(node, 'link', 'set', interface, 'up')
        self.command('b', [sys.executable, '-c', "open('/proc/sys/net/ipv4/ip_forward','w').write('0')"], check=True)

    def prefix(self, node):
        return [] if node == 'a' else ['nsenter', '--net=/proc/%d/ns/net' % self.pids[node]]

    def ip(self, node, *args):
        run(*(self.prefix(node) + ['ip', *args]))

    def command(self, node, args, **kwargs):
        return subprocess.run(self.prefix(node) + args, **kwargs)

    def ready(self, node, child):
        port = 23200
        probe = "import socket; socket.create_connection(('127.0.0.1',%d),.2).close()" % port
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert child.poll() is None, node + ' exited during startup'
            result = self.command(node, [sys.executable, '-c', probe], capture_output=True)
            if result.returncode == 0:
                return
            time.sleep(.05)
        raise AssertionError(node + ' TCP listener did not start')

    def denied(self, node, host, port):
        probe = "import socket; s=socket.socket(); s.settimeout(.5); r=s.connect_ex((%r,%d)); assert r != 0, 'unexpected direct reachability'" % (host, port)
        self.command(node, [sys.executable, '-c', probe], check=True)


@contextlib.contextmanager
def child_process(command, **kwargs):
    child = subprocess.Popen(command, **kwargs)
    try:
        yield child
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


@contextlib.contextmanager
def service(topology, node, binary, config, directory, name):
    with (directory / (name + '.log')).open('w+') as log:
        with child_process(topology.prefix(node) + [str(smoke.BIN / binary), '--config', str(config)], stdout=log, stderr=log) as child:
            try:
                yield child
            except BaseException:
                log.flush()
                log.seek(0)
                print(name, log.read()[-8000:], file=sys.stderr)
                raise


def peer(directory, transport, addr, password):
    return '''server_addr = "%s"
server_name = "stunnel"
server_cert = "%s"
private_key = "%s"
tunnel_type = "%s"
''' % (addr, directory / 'stunnel_cert.pem', directory / 'private_key.pem', transport) + '[anytls]\npassword = "%s"\n' % password


def server_config(path, credentials, transport, password, upstream=None):
    text = '''listen = "0.0.0.0:23200"
cert = "%s"
priv_key = "%s"
[quic]
server_type = "%s"
[anytls]
password = "%s"
''' % (credentials / 'stunnel_cert.pem', credentials / 'private_key.pem', 's2n-quic' if transport == 's2n-quic' else 'quic', password)
    if upstream:
        text += '\n[upstream]\n' + upstream.replace('[anytls]', '[upstream.anytls]')
    path.write_text(text)


def no_success(port, target=TARGET):
    with socket.create_connection(('127.0.0.1', port), timeout=15) as conn:
        conn.sendall(('CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: localhost\r\n\r\n' % target).encode())
        response = bytearray()
        deadline = time.monotonic() + 15
        while not response.endswith(b'\r\n\r\n'):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('relay setup did not reject within 15 seconds')
            conn.settimeout(remaining)
            try:
                chunk = conn.recv(1)
            except ConnectionResetError:
                return
            if not chunk:
                return
            response.extend(chunk)
            assert len(response) < 65536, 'oversized rejection response'
        assert b' 200 ' not in response, 'proxy reported success on failed relay setup'


def verify(directory, topology):
    bkeys, ckeys = directory / 'bkeys', directory / 'ckeys'
    for keys in (bkeys, ckeys):
        keys.mkdir()
        subprocess.run([str(smoke.BIN / 'certgen')], cwd=keys, check=True, capture_output=True)
    with child_process(topology.prefix('c') + [sys.executable, __file__, '--backend']):
        for _ in range(100):
            result = topology.command('c', [sys.executable, '-c', "import socket; socket.create_connection(('127.0.0.1',23101),.1).close()"], capture_output=True)
            if result.returncode == 0:
                break
            time.sleep(.05)
        else:
            raise AssertionError('destination fixture failed to start')
        for node in ('a', 'b'):
            topology.denied(node, '127.0.0.1', TARGET)
        assert topology.command('a', ['ip', 'route', 'get', '10.211.2.2'], capture_output=True).returncode != 0, 'A unexpectedly has a route to C'
        topology.denied('a', '10.211.2.2', 23200)
        print('PASS strict namespace isolation A cannot route to C; A/B cannot reach destination', flush=True)
        for ingress in TRANSPORTS:
            for egress in TRANSPORTS:
                label = ingress + '-' + egress
                cconfig, bconfig, aconfig = [directory / (label + n + '.toml') for n in ('c', 'b', 'a')]
                server_config(cconfig, ckeys, egress, 'BC-secret')
                upstream = peer(ckeys, egress, '10.211.2.2:23200', 'BC-secret')
                server_config(bconfig, bkeys, ingress, 'AB-secret', upstream)
                socks, http = smoke.free_port(), smoke.free_port()
                aconfig.write_text('socks5_listen = "127.0.0.1:%d"\nhttp_listen = "127.0.0.1:%d"\n' % (socks, http) + peer(bkeys, ingress, '10.211.1.2:23200', 'AB-secret'))
                with contextlib.ExitStack() as stack:
                    c = stack.enter_context(service(topology, 'c', 'stunnel_server', cconfig, directory, label + '-c'))
                    b = stack.enter_context(service(topology, 'b', 'stunnel_server', bconfig, directory, label + '-b'))
                    topology.ready('c', c)
                    topology.ready('b', b)
                    a = stack.enter_context(service(topology, 'a', 'stunnel_client', aconfig, directory, label + '-a'))
                    smoke.ready(a, http)
                    smoke.connect_flow(http, TARGET, smoke.PAYLOAD)
                    smoke.socks_flow(socks, TARGET, b'relay-socks-eof')
                    smoke.udp_flow(socks, UDP)
                    no_success(http, 23999)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                        list(pool.map(lambda n: smoke.connect_flow(http, TARGET, bytes([n]) * 65537), range(8)))
                    if ingress == egress:
                        smoke.slow_reader_flow(http, BULK)
                        with socket.create_connection(('127.0.0.1', http), timeout=15) as conn:
                            conn.sendall(('GET http://127.0.0.1:%d/probe HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n' % (HTTP, HTTP)).encode())
                            response = smoke.until_eof(conn)
                            assert b' 200 ' in response and response.endswith(b'http-forward-through-stunnel')
                        print('PASS', label, '8 MiB slow reader and HTTP forwarding', flush=True)
                    c.terminate()
                    c.wait(timeout=5)
                    no_success(http)
                    c = stack.enter_context(service(topology, 'c', 'stunnel_server', cconfig, directory, label + '-c-restart'))
                    topology.ready('c', c)
                    deadline = time.monotonic() + 20
                    while True:
                        try:
                            smoke.connect_flow(http, TARGET, b'new-flow-after-restart')
                            break
                        except (OSError, AssertionError):
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(.2)
                    print('PASS', label, 'CONNECT/SOCKS EOF, UDP, concurrent flows, refused target, C-down, restart', flush=True)
                    c.terminate()
                    c.wait(timeout=5)
                    server_config(cconfig, ckeys if egress == 'anytls' else bkeys,
                                  egress, 'incorrect-BC-secret')
                    c = stack.enter_context(service(topology, 'c', 'stunnel_server', cconfig, directory, label + '-auth-c'))
                    topology.ready('c', c)
                    assert a.poll() is None and b.poll() is None, 'authenticated A/B processes exited'
                    no_success(http)
                print('PASS', label, 'wrong BC credentials rejected', flush=True)


def direct_reverse(directory, topology):
    """Exercise the legacy direct control route on both QUIC backends."""
    keys = directory / 'bkeys'
    with child_process([sys.executable, __file__, '--backend']):
        for transport in ('quic', 's2n-quic'):
            server = directory / ('reverse-' + transport + '-server.toml')
            client = directory / ('reverse-' + transport + '-client.toml')
            server_config(server, keys, transport, 'unused')
            socks, http = smoke.free_port(), smoke.free_port()
            config = 'socks5_listen = "127.0.0.1:%d"\nhttp_listen = "127.0.0.1:%d"\n' % (socks, http)
            config += peer(keys, transport, '10.211.1.2:23200', 'unused')
            config += '[[reverse_proxy]]\nlisten = "127.0.0.1:23300"\ntarget = "127.0.0.1:%d"\n' % TARGET
            client.write_text(config)
            with service(topology, 'b', 'stunnel_server', server, directory, 'reverse-' + transport + '-b') as b:
                topology.ready('b', b)
                with service(topology, 'a', 'stunnel_client', client, directory, 'reverse-' + transport + '-a') as a:
                    smoke.ready(a, http)
                    probe = "import socket; s=socket.create_connection(('127.0.0.1',23300),2); s.sendall(b'reverse'); s.shutdown(socket.SHUT_WR); data=b''\nwhile True:\n x=s.recv(4096)\n if not x: break\n data+=x\nassert data == b'reply-after-eof:esrever', data"
                    deadline = time.monotonic() + 15
                    while True:
                        result = topology.command('b', [sys.executable, '-c', probe], capture_output=True)
                        if result.returncode == 0:
                            break
                        if time.monotonic() >= deadline:
                            raise AssertionError('direct reverse failed: ' + result.stderr.decode())
                        time.sleep(.1)
                    print('PASS', transport, 'legacy direct reverse TCP half-close', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--backend', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--isolated', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--outer-net-fd', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.backend:
        backend()
        return
    if not args.isolated:
        outer_net = os.open('/proc/self/ns/net', os.O_RDONLY)
        os.set_inheritable(outer_net, True)
        os.execvp('unshare', ['unshare', '--user', '--map-root-user', '--net', sys.executable, str(pathlib.Path(__file__).resolve()), '--isolated', '--outer-net-fd', str(outer_net)])
    if args.outer_net_fd is None:
        parser.error('--isolated requires the launcher namespace descriptor')
    try:
        if not os.readlink('/proc/self/fd/%d' % args.outer_net_fd).startswith('net:['):
            parser.error('launcher descriptor is not a network namespace')
        outer_net = os.fstat(args.outer_net_fd)
        current_net = os.stat('/proc/self/ns/net')
        if (outer_net.st_dev, outer_net.st_ino) == (current_net.st_dev, current_net.st_ino):
            parser.error('--isolated requires a separate network namespace')
    except OSError as error:
        parser.error('cannot verify namespace isolation: ' + str(error))
    os.close(args.outer_net_fd)
    uid_map = pathlib.Path('/proc/self/uid_map').read_text().split()
    if len(uid_map) != 3 or uid_map[0] != '0' or uid_map[2] != '1':
        parser.error('--isolated requires a single mapped root user')
    with tempfile.TemporaryDirectory(prefix='stunnel-relay-') as raw, contextlib.ExitStack() as stack:
        topology = Topology(stack)
        verify(pathlib.Path(raw), topology)
        direct_reverse(pathlib.Path(raw), topology)
    print('PASS all 16 encrypted relay transport pairs', flush=True)


if __name__ == '__main__':
    main()
