#!/usr/bin/env python3
"""Verify ordered client/relay failover with real encrypted transports.

Run with STUNNEL_BIN_DIR pointing at built certgen/client/server binaries.
Requires Linux user/network namespaces, iproute2 and nsenter. Each peer has
its own loopback destination, so reply markers prove the selected peer.
This checks selection, not the relay harness's restricted-network topology.
"""
import argparse
import contextlib
import dataclasses
import json
import os
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
import verify_anytls as smoke
import verify_relay as relay

smoke.BIN = smoke.BIN.resolve()

TARGET, BACKUP_ONLY, CARRIER = 24101, 24102, 24200
TRANSPORTS = ('anytls', 'tlstcp', 'quic', 's2n-quic')


def record(path, kind, data=b''):
    with path.open('a') as output:
        output.write(json.dumps([kind, data.hex()]) + '\n')


def fixture(directory, name, mode):
    events = directory / (name + '.events')

    class Destination(smoke.socketserver.BaseRequestHandler):
        def handle(self):
            record(events, 'connect')
            self.request.settimeout(60)
            stream = self.request.makefile('rb')
            while data := stream.readline():
                record(events, 'tcp', data)
                self.request.sendall(name.encode() + b':' + data)

    def udp_echo():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(('127.0.0.1', TARGET))
            while True:
                data, address = udp.recvfrom(65535)
                record(events, 'udp', data)
                udp.sendto(name.encode() + b':' + data, address)

    def fault(conn):
        with conn:
            conn.settimeout(60)
            if mode == 'hang':
                record(events, 'carrier')
                while conn.recv(4096):
                    pass
                return
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(directory / name / 'stunnel_cert.pem', directory / name / 'private_key.pem')
            context.load_verify_locations(directory / name / 'stunnel_cert.pem')
            context.verify_mode = ssl.CERT_REQUIRED
            context.set_alpn_protocols(['stunnel'])
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    kind = smoke.exact(tls, 1)
                    if kind == b'\x01':
                        smoke.exact(tls, smoke.exact(tls, 1)[0])
                    record(events, 'metadata')
                    if mode == 'badbind':
                        tls.settimeout(.1)
                        try:
                            if data := tls.recv(4096):
                                record(events, 'premature', data)
                        except TimeoutError:
                            pass
                        tls.settimeout(60)
                    bind = b'not-an-address' if mode == 'badbind' else b'127.0.0.1:1'
                    tls.sendall(bytes([len(bind)]) + bind)
                    if mode == 'committed':
                        if kind == b'\x00':
                            smoke.exact(tls, smoke.exact(tls, 1)[0])
                            size = struct.unpack('!H', smoke.exact(tls, 2))[0]
                            record(events, 'committed-udp', smoke.exact(tls, size))
                        else:
                            record(events, 'committed', tls.makefile('rb').readline())
            except (OSError, AssertionError):
                pass

    for port in [TARGET] + ([BACKUP_ONLY] if name == 'backup' else []):
        server = smoke.TcpServer(('127.0.0.1', port), Destination)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=udp_echo, daemon=True).start()
    if mode == 'destination':
        (directory / (name + '.ready')).touch()
        threading.Event().wait()
    else:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('0.0.0.0', CARRIER))
            listener.listen()
            (directory / (name + '.ready')).touch()
            while True:
                conn, _ = listener.accept()
                threading.Thread(target=fault, args=(conn,), daemon=True).start()


@dataclasses.dataclass
class Peer:
    name: str
    transport: str
    address: str
    password: str = 'correct-secret'

    def config(self, directory, table):
        text = relay.peer(directory / self.name, self.transport, self.address, self.password)
        return '[[' + table + ']]\n' + text.replace('[anytls]', '[' + table + '.anytls]')


class Topology(relay.Topology):
    def __init__(self, directory, stack):
        self.directory, self.pids = directory, {}
        relay.run('ip', 'link', 'set', 'lo', 'up')
        for index, name in enumerate(('primary', 'backup', 'middle'), 1):
            process = stack.enter_context(relay.child_process(['unshare', '--net', 'sleep', 'infinity']))
            self.pids[name] = process.pid
            deadline = time.monotonic() + 5
            while os.readlink('/proc/%d/ns/net' % process.pid) == os.readlink('/proc/self/ns/net'):
                assert time.monotonic() < deadline, 'peer namespace did not start'
                time.sleep(.01)
            host, peer = 'fv%d-a' % index, 'fv%d-b' % index
            relay.run('ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer)
            relay.run('ip', 'link', 'set', peer, 'netns', str(process.pid))
            relay.run('ip', 'addr', 'add', '10.219.%d.1/24' % index, 'dev', host)
            relay.run('ip', 'link', 'set', host, 'up')
            self.ip(name, 'addr', 'add', '10.219.%d.2/24' % index, 'dev', peer)
            self.ip(name, 'link', 'set', peer, 'up')
            self.ip(name, 'link', 'set', 'lo', 'up')

    def peer(self, name, transport, password=None):
        index = ('primary', 'backup', 'middle').index(name) + 1
        return Peer(name, transport, '10.219.%d.2:%d' % (index, CARRIER), password or name + '-secret')

    def events(self, name, kind):
        path = self.directory / (name + '.events')
        rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [bytes.fromhex(data) for event, data in rows if event == kind]

    @contextlib.contextmanager
    def backend(self, name, mode='destination'):
        ready = self.directory / (name + '.ready')
        ready.unlink(missing_ok=True)
        command = self.prefix(name) + [sys.executable, str(pathlib.Path(__file__).resolve()), '--fixture', name, '--mode', mode, '--directory', str(self.directory)]
        with relay.child_process(command) as child:
            deadline = time.monotonic() + 5
            while not ready.exists():
                assert child.poll() is None, 'fixture exited'
                assert time.monotonic() < deadline, 'fixture startup timed out'
                time.sleep(.02)
            yield child

    @contextlib.contextmanager
    def server(self, peer):
        path = self.directory / (peer.name + '-server.toml')
        relay.server_config(path, self.directory / peer.name, peer.transport, peer.name + '-secret')
        path.write_text(path.read_text().replace('23200', str(CARRIER)))
        with relay.service(self, peer.name, 'stunnel_server', path, self.directory, peer.name + '-server') as child:
            deadline = time.monotonic() + 15
            while True:
                assert child.poll() is None, 'peer server exited'
                try:
                    with socket.create_connection(tuple([peer.address.split(':')[0], CARRIER]), timeout=.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, 'peer server startup timed out'
                    time.sleep(.05)
            yield child

    @contextlib.contextmanager
    def frontend(self, side, peers):
        socks, http = smoke.free_port(), smoke.free_port()
        config = 'socks5_listen = "127.0.0.1:%d"\nhttp_listen = "127.0.0.1:%d"\n' % (socks, http)
        with contextlib.ExitStack() as stack:
            if side == 'relay':
                port = smoke.free_port()
                path = self.directory / 'relay.toml'
                relay.server_config(path, self.directory, 'tlstcp', 'correct-secret')
                path.write_text(path.read_text().replace('23200', str(port)) + '\n' + '\n'.join(peer.config(self.directory, 'upstreams') for peer in peers))
                process = stack.enter_context(smoke.process('stunnel_server', path, self.directory, 'relay'))
                smoke.ready(process, port)
                config += relay.peer(self.directory, 'tlstcp', '127.0.0.1:%d' % port, 'correct-secret')
            else:
                config += '\n'.join(peer.config(self.directory, 'servers') for peer in peers)
            path = self.directory / 'client.toml'
            path.write_text(config)
            child = stack.enter_context(smoke.process('stunnel_client', path, self.directory, 'client'))
            smoke.ready(child, http)
            yield socks, http


def tcp_open(http, target=TARGET):
    conn = socket.create_connection(('127.0.0.1', http), timeout=13)
    try:
        conn.sendall(('CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: localhost\r\n\r\n' % target).encode())
        assert b' 200 ' in smoke.headers(conn), 'TCP setup rejected'
        return conn
    except BaseException:
        conn.close()
        raise


def exchange(conn, marker, payload):
    conn.sendall(payload)
    assert smoke.exact(conn, len(marker) + 1 + len(payload)) == marker.encode() + b':' + payload


def flows(topology, ports, marker, label, target=TARGET):
    socks, http = ports
    tcp = (label + '-tcp\n').encode()
    before = {name: len(topology.events(name, 'tcp')) for name in topology.pids}
    started = time.monotonic()
    with tcp_open(http, target) as conn:
        assert time.monotonic() - started < 12, 'TCP setup exceeded budget plus tolerance'
        exchange(conn, marker, tcp)
    for name in topology.pids:
        assert topology.events(name, 'tcp')[before[name]:] == ([tcp] if name == marker else []), 'TCP application data duplicated or sent to wrong peer'
    if target != TARGET:
        return
    udp_payload = (label + '-udp').encode()
    before = {name: len(topology.events(name, 'udp')) for name in topology.pids}
    control, address = smoke.socks_open(socks, 3, ('0.0.0.0', 0))
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(13)
        packet = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', TARGET)
        started = time.monotonic()
        udp.sendto(packet + udp_payload, ('127.0.0.1', address[1]))
        response, _ = udp.recvfrom(65535)
        assert time.monotonic() - started < 12, 'UDP setup exceeded budget plus tolerance'
        assert response == packet + marker.encode() + b':' + udp_payload, 'UDP selected wrong peer or corrupted datagram'
    for name in topology.pids:
        assert topology.events(name, 'udp')[before[name]:] == ([udp_payload] if name == marker else []), 'UDP application data duplicated or sent to wrong peer'


def rejected(http):
    started = time.monotonic()
    with socket.create_connection(('127.0.0.1', http), timeout=13) as conn:
        conn.sendall(('CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: localhost\r\n\r\n' % TARGET).encode())
        assert b' 200 ' not in smoke.headers(conn), 'all-down setup succeeded'
    assert time.monotonic() - started < 12, 'all-down exceeded setup budget plus tolerance'


def rejected_udp(topology, socks):
    before = {name: len(topology.events(name, 'udp')) for name in topology.pids}
    control, address = smoke.socks_open(socks, 3, ('0.0.0.0', 0))
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        control.settimeout(13)
        packet = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', TARGET)
        started = time.monotonic()
        udp.sendto(packet + b'all-down-must-not-arrive', ('127.0.0.1', address[1]))
        assert control.recv(1) == b'', 'all-down UDP association stayed open'
        assert time.monotonic() - started < 12, 'UDP rejection exceeded setup budget plus tolerance'
    for name in before:
        assert len(topology.events(name, 'udp')) == before[name], 'all-down UDP payload reached a destination'


def verify(topology, exhaustive):
    for side in ('client', 'relay'):
        for index, transport in enumerate(TRANSPORTS):
            primary = topology.peer('primary', transport)
            backup = topology.peer('backup', TRANSPORTS[(index + 1) % len(TRANSPORTS)])
            with topology.backend('primary'), topology.backend('backup'), topology.server(backup):
                with topology.server(primary), topology.frontend(side, [primary, backup]) as ports:
                    flows(topology, ports, 'primary', side + '-' + transport + '-ordered')
                    flows(topology, ports, 'backup', side + '-' + transport + '-destination-refused', BACKUP_ONLY)
                    flows(topology, ports, 'primary', side + '-' + transport + '-healthy-after-refusal')
                with topology.frontend(side, [primary, backup]) as ports:
                    flows(topology, ports, 'backup', side + '-' + transport + '-primary-down')
            print('PASS', side, transport, 'ordered primary, mixed backup, destination refusal keeps primary healthy, TCP/UDP exact once', flush=True)
        primary = topology.peer('primary', 'anytls', 'wrong-secret')
        backup = topology.peer('backup', 'tlstcp')
        with topology.backend('primary'), topology.backend('backup'), topology.server(primary), topology.server(backup), topology.frontend(side, [primary, backup]) as ports:
            flows(topology, ports, 'backup', side + '-wrong-anytls-auth')
        print('PASS', side, 'wrong AnyTLS auth falls back before application data', flush=True)
        for fault in ('hang', 'badbind'):
            primary = topology.peer('primary', 'tlstcp')
            with topology.backend('primary', fault), topology.backend('backup'), topology.server(backup), topology.frontend(side, [primary, backup]) as ports:
                before = len(topology.events('primary', 'carrier' if fault == 'hang' else 'metadata'))
                premature_before = len(topology.events('primary', 'premature'))
                flows(topology, ports, 'backup', side + '-' + fault)
                assert len(topology.events('primary', 'carrier' if fault == 'hang' else 'metadata')) > before, 'fault fixture was not attempted'
                assert len(topology.events('primary', 'premature')) == premature_before, 'application data sent before valid bind'
            print('PASS', side, fault, 'fallback with bounded setup', flush=True)
        with topology.backend('primary', 'hang'), topology.backend('middle', 'hang'), topology.backend('backup'), topology.server(backup):
            peers = [topology.peer(name, 'tlstcp') for name in ('primary', 'middle', 'backup')]
            with topology.frontend(side, peers) as ports:
                before = {name: len(topology.events(name, 'carrier')) for name in ('primary', 'middle')}
                flows(topology, ports, 'backup', side + '-three-peer-budget')
                for name in before:
                    assert len(topology.events(name, 'carrier')) > before[name], 'three-peer test skipped a hanging peer'
        with topology.backend('primary', 'hang'), topology.backend('backup', 'hang'), topology.frontend(side, [topology.peer('primary', 'tlstcp'), backup]) as ports:
            rejected(ports[1])
            rejected_udp(topology, ports[0])
        primary = topology.peer('primary', 'tlstcp')
        with topology.backend('primary'), topology.frontend(side, [primary]) as ports:
            rejected(ports[1])
            with topology.server(primary):
                flows(topology, ports, 'primary', side + '-singleton-recovery')
        print('PASS', side, 'three-peer fair budget, bounded TCP/UDP all-down rejection, singleton immediate recovery', flush=True)
        with topology.backend('primary', 'committed'), topology.backend('backup'), topology.server(backup), topology.frontend(side, [topology.peer('primary', 'tlstcp'), backup]) as ports:
            before = len(topology.events('backup', 'connect'))
            committed_before = len(topology.events('primary', 'committed'))
            with tcp_open(ports[1]) as conn:
                conn.sendall(b'never-replay-after-bind\n')
                assert conn.recv(1) == b'', 'committed fixture did not close'
            time.sleep(.2)
            assert topology.events('primary', 'committed')[committed_before:] == [b'never-replay-after-bind\n'], 'committed peer did not receive application data'
            assert len(topology.events('backup', 'connect')) == before, 'setup retried after valid bind'
            udp_before = len(topology.events('backup', 'udp'))
            committed_before = len(topology.events('primary', 'committed-udp'))
            control, address = smoke.socks_open(ports[0], 3, ('0.0.0.0', 0))
            with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                control.settimeout(13)
                packet = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', TARGET)
                udp.sendto(packet + b'never-replay-udp', ('127.0.0.1', address[1]))
                assert control.recv(1) == b'', 'committed UDP association stayed open'
            assert topology.events('primary', 'committed-udp')[committed_before:] == [b'never-replay-udp'], 'committed peer did not receive UDP payload'
            assert len(topology.events('backup', 'udp')) == udp_before, 'UDP application data replayed after valid bind'
        print('PASS', side, 'no retry after valid bind and established close', flush=True)
        if exhaustive:
            primary = topology.peer('primary', 'tlstcp')
            with topology.backend('primary'), topology.backend('backup'), topology.server(backup), topology.frontend(side, [primary, backup]) as ports:
                with tcp_open(ports[1]) as pinned:
                    exchange(pinned, 'backup', b'before-recovery\n')
                    with topology.server(primary):
                        flows(topology, ports, 'backup', side + '-before-cooldown-expiry')
                        time.sleep(31)
                        flows(topology, ports, 'primary', side + '-failback')
                        exchange(pinned, 'backup', b'after-recovery\n')
            print('PASS', side, 'cooldown expiry restores primary while established backup survives', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exhaustive', action='store_true', help='also wait for real 30-second cooldown expiry on client and relay')
    parser.add_argument('--isolated', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--outer-net-fd', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--fixture', choices=('primary', 'backup', 'middle'), help=argparse.SUPPRESS)
    parser.add_argument('--mode', default='destination', help=argparse.SUPPRESS)
    parser.add_argument('--directory', type=pathlib.Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.fixture:
        fixture(args.directory, args.fixture, args.mode)
        return
    if not args.isolated:
        descriptor = os.open('/proc/self/ns/net', os.O_RDONLY)
        os.set_inheritable(descriptor, True)
        command = ['unshare', '--user', '--map-root-user', '--net', sys.executable, str(pathlib.Path(__file__).resolve()), '--isolated', '--outer-net-fd', str(descriptor)]
        os.execvp('unshare', command + (['--exhaustive'] if args.exhaustive else []))
    if args.outer_net_fd is None or os.fstat(args.outer_net_fd).st_ino == os.stat('/proc/self/ns/net').st_ino:
        parser.error('launcher must create a separate network namespace')
    os.close(args.outer_net_fd)
    with tempfile.TemporaryDirectory(prefix='stunnel-failover-') as raw, contextlib.ExitStack() as stack:
        directory = pathlib.Path(raw)
        subprocess.run([str(smoke.BIN / 'certgen')], cwd=directory, check=True, capture_output=True)
        for name in ('primary', 'backup', 'middle'):
            keys = directory / name
            keys.mkdir()
            subprocess.run([str(smoke.BIN / 'certgen')], cwd=keys, check=True, capture_output=True)
        topology = Topology(directory, stack)
        verify(topology, args.exhaustive)
    print('PASS ordered failover runtime checks', flush=True)


if __name__ == '__main__':
    main()
