#!/usr/bin/env python3
import concurrent.futures
import contextlib
import http.server
import os
import pathlib
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = pathlib.Path(os.environ.get('STUNNEL_BIN_DIR', ROOT / 'target/debug'))
PAYLOAD = bytes(range(256)) * 2048
BULK_PAYLOAD = bytes(range(256)) * 32768
PREFIX = b'reply-after-eof:'


def exact(conn, count):
    result = bytearray()
    while len(result) < count:
        chunk = conn.recv(count - len(result))
        if not chunk:
            raise AssertionError('premature EOF')
        result.extend(chunk)
    return bytes(result)


def until_eof(conn):
    result = bytearray()
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            return bytes(result)
        result.extend(chunk)


def headers(conn):
    result = bytearray()
    while not result.endswith(b'\r\n\r\n'):
        result.extend(exact(conn, 1))
        assert len(result) < 65536
    return bytes(result)


def free_port():
    with socket.socket() as conn:
        conn.bind(('127.0.0.1', 0))
        return conn.getsockname()[1]


def socks_address(conn):
    kind = exact(conn, 1)[0]
    if kind == 1:
        return socket.inet_ntop(socket.AF_INET, exact(conn, 4)), struct.unpack('!H', exact(conn, 2))[0]
    if kind == 4:
        return socket.inet_ntop(socket.AF_INET6, exact(conn, 16)), struct.unpack('!H', exact(conn, 2))[0]
    if kind == 3:
        return exact(conn, exact(conn, 1)[0]).decode(), struct.unpack('!H', exact(conn, 2))[0]
    raise AssertionError('invalid SOCKS address')


def socks_open(proxy_port, command, target):
    conn = socket.create_connection(('127.0.0.1', proxy_port), timeout=8)
    conn.sendall(b'\x05\x01\x00')
    assert exact(conn, 2) == b'\x05\x00'
    conn.sendall(bytes([5, command, 0, 1]) + socket.inet_aton(target[0]) + struct.pack('!H', target[1]))
    assert exact(conn, 3) == b'\x05\x00\x00'
    bound = socks_address(conn)
    return conn, bound


class TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class AfterEof(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        request = until_eof(self.request)
        self.request.sendall(PREFIX + request[::-1])


class BulkReply(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        assert self.request.recv(1) == b'!'
        self.request.sendall(BULK_PAYLOAD)
        self.request.shutdown(socket.SHUT_WR)


class HttpReply(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b'http-forward-through-stunnel'
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


@contextlib.contextmanager
def process(binary, config, directory, name):
    log = (directory / (name + '.log')).open('w+')
    child = subprocess.Popen([str(BIN / binary), '--config', str(config)], stdout=log, stderr=log)
    try:
        yield child
    except BaseException:
        log.flush()
        log.seek(0)
        print(log.read()[-6000:], file=sys.stderr)
        raise
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        log.close()


def ready(child, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise AssertionError('process exited during startup')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError('listener did not start')


def connect_flow(http_port, target_port, payload):
    with socket.create_connection(('127.0.0.1', http_port), timeout=8) as conn:
        conn.sendall(('CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n' % (target_port, target_port)).encode())
        assert b' 200 ' in headers(conn)
        conn.sendall(payload)
        conn.shutdown(socket.SHUT_WR)
        assert until_eof(conn) == PREFIX + payload[::-1]


def socks_flow(socks_port, target_port, payload):
    conn, _ = socks_open(socks_port, 1, ('127.0.0.1', target_port))
    with conn:
        conn.sendall(payload)
        conn.shutdown(socket.SHUT_WR)
        assert until_eof(conn) == PREFIX + payload[::-1]


def slow_reader_flow(http_port, target_port):
    with socket.socket() as conn:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
        conn.settimeout(10)
        conn.connect(('127.0.0.1', http_port))
        conn.sendall(('CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n' % (target_port, target_port)).encode())
        assert b' 200 ' in headers(conn)
        conn.sendall(b'!')
        time.sleep(1)
        response = until_eof(conn)
        assert response == BULK_PAYLOAD, 'slow reader received %d of %d bytes' % (len(response), len(BULK_PAYLOAD))


def udp_flow(socks_port, udp_target):
    conn, relay = socks_open(socks_port, 3, ('0.0.0.0', 0))
    with conn, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(8)
        packet = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', udp_target)
        for payload in [b'first-datagram', b'second-datagram', bytes(range(256)) * 4]:
            udp.sendto(packet + payload, ('127.0.0.1', relay[1]))
            result, _ = udp.recvfrom(2048)
            assert result == packet + payload


def client_config(directory, name, transport, server_port, password='integration-secret'):
    socks, http = free_port(), free_port()
    path = directory / (name + '.toml')
    path.write_text('''socks5_listen = "127.0.0.1:%d"
http_listen = "127.0.0.1:%d"
server_addr = "127.0.0.1:%d"
server_name = "stunnel"
server_cert = "%s"
private_key = "%s"
tunnel_type = "%s"
[anytls]
password = "%s"
''' % (socks, http, server_port, directory / 'stunnel_cert.pem', directory / 'private_key.pem', transport, password))
    return path, socks, http


def main():
    with tempfile.TemporaryDirectory(prefix='stunnel-binary-smoke-') as raw:
        directory = pathlib.Path(raw)
        subprocess.run([str(BIN / 'certgen')], cwd=directory, check=True, capture_output=True)
        tcp = TcpServer(('127.0.0.1', 0), AfterEof)
        bulk = TcpServer(('127.0.0.1', 0), BulkReply)
        http_backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), HttpReply)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(('127.0.0.1', 0))
        def echo_udp():
            while True:
                try:
                    data, address = udp.recvfrom(65535)
                    udp.sendto(data, address)
                except OSError:
                    return
        for target in [tcp.serve_forever, bulk.serve_forever, http_backend.serve_forever, echo_udp]:
            threading.Thread(target=target, daemon=True).start()
        try:
            for backend, transports in [('quic', ['anytls', 'tlstcp', 'quic']), ('s2n-quic', ['s2n-quic'])]:
                server_port = free_port()
                server_config = directory / 'server.toml'
                server_config.write_text('''listen = "127.0.0.1:%d"
cert = "%s"
priv_key = "%s"
[quic]
server_type = "%s"
[anytls]
password = "integration-secret"
''' % (server_port, directory / 'stunnel_cert.pem', directory / 'private_key.pem', backend))
                with process('stunnel_server', server_config, directory, 'server-' + backend) as server:
                    ready(server, server_port)
                    for transport in transports:
                        config, socks, http_port = client_config(directory, transport, transport, server_port)
                        with process('stunnel_client', config, directory, 'client-' + transport) as client:
                            ready(client, http_port)
                            connect_flow(http_port, tcp.server_address[1], PAYLOAD)
                            slow_reader_flow(http_port, bulk.server_address[1])
                            socks_flow(socks, tcp.server_address[1], b'socks-request-needing-eof')
                            udp_flow(socks, udp.getsockname()[1])
                            with socket.create_connection(('127.0.0.1', http_port), timeout=8) as conn:
                                target = '127.0.0.1:%d' % http_backend.server_address[1]
                                conn.sendall(('GET http://%s/probe HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % (target, target)).encode())
                                response = until_eof(conn)
                                assert b' 200 ' in response and response.endswith(b'http-forward-through-stunnel')
                            if transport == 'anytls':
                                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                                    futures = [pool.submit(connect_flow, http_port, tcp.server_address[1], bytes([n]) * 65537) for n in range(8)]
                                    for future in futures:
                                        future.result(timeout=15)
                            print('PASS', transport, 'HTTP CONNECT half-close, 8 MiB slow reader, HTTP forwarding, SOCKS TCP, SOCKS UDP', flush=True)
                    if backend == 'quic':
                        bad_config, _, bad_http = client_config(directory, 'bad-password', 'anytls', server_port, password='wrong-password')
                        with process('stunnel_client', bad_config, directory, 'bad-password') as bad_client:
                            ready(bad_client, bad_http)
                            with socket.create_connection(('127.0.0.1', bad_http), timeout=8) as conn:
                                conn.sendall(b'CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n')
                                assert b' 404 ' in headers(conn)
                            print('PASS anytls wrong password rejected through HTTP frontend', flush=True)
        finally:
            tcp.shutdown()
            tcp.server_close()
            bulk.shutdown()
            bulk.server_close()
            http_backend.shutdown()
            http_backend.server_close()
            udp.close()


if __name__ == '__main__':
    main()
