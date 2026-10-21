#!/usr/bin/env python3
"""Measure verified AnyTLS traffic through the real HTTP CONNECT frontend."""
import argparse
import concurrent.futures
import contextlib
import json
import os
import pathlib
import signal
import socket
import socketserver
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib

import verify_anytls as verify

BLOCK = bytes(range(256)) * 4096


class Bulk(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        size = struct.unpack('!Q', verify.exact(self.request, 8))[0]
        assert self.request.recv(1) == b''
        while size:
            count = min(size, len(BLOCK))
            self.request.sendall(BLOCK[:count])
            size -= count
        self.request.shutdown(socket.SHUT_WR)


def cpu_seconds(pid):
    fields = pathlib.Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')


@contextlib.contextmanager
def child(binary, config, directory, name, trace):
    command = [str(verify.BIN / binary), '--config', str(config)]
    if trace:
        command = ['strace', '-f', '-c', '-o', str(trace / (name + '.strace')), *command]
    with (directory / (name + '.log')).open('w+') as log:
        process = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
        try:
            yield process
        except BaseException:
            log.flush()
            log.seek(0)
            print(log.read()[-6000:], file=sys.stderr)
            raise
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def expected_crc(size):
    value = 0
    while size:
        count = min(size, len(BLOCK))
        value = zlib.crc32(BLOCK[:count], value)
        size -= count
    return value


def transfer(port, target, size, checksum, include_open):
    started = time.perf_counter()
    deadline = started + 30
    with socket.create_connection(('127.0.0.1', port), timeout=30) as connection:
        connection.sendall(('CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n' % (target, target)).encode())
        assert b' 200 ' in verify.headers(connection)
        if not include_open:
            started = time.perf_counter()
        connection.sendall(struct.pack('!Q', size))
        connection.shutdown(socket.SHUT_WR)
        received, actual = 0, 0
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise TimeoutError('transfer exceeded 30 seconds')
            connection.settimeout(remaining)
            data = connection.recv(256 * 1024)
            if not data:
                break
            received += len(data)
            assert received <= size, (received, size)
            actual = zlib.crc32(data, actual)
        elapsed = time.perf_counter() - started
        assert received == size and actual == checksum, (received, size, actual, checksum)
        return elapsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=pathlib.Path, required=True)
    parser.add_argument('--variant', required=True)
    parser.add_argument('--samples', type=int, default=6)
    parser.add_argument('--bytes', type=int, default=128 * 1024 * 1024)
    parser.add_argument('--trace-dir', type=pathlib.Path)
    args = parser.parse_args()
    assert args.samples > 0 and args.bytes > 0
    verify.BIN = args.bin_dir.resolve()
    if args.trace_dir:
        args.trace_dir.mkdir(parents=True, exist_ok=True)
    crc = expected_crc(args.bytes)
    rows = []
    with tempfile.TemporaryDirectory(prefix='stunnel-anytls-benchmark-') as raw:
        directory = pathlib.Path(raw)
        subprocess.run([str(verify.BIN / 'certgen')], cwd=directory, check=True, capture_output=True)
        backend = verify.TcpServer(('127.0.0.1', 0), Bulk)
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        try:
            server_port = verify.free_port()
            server_config = directory / 'server.toml'
            server_config.write_text('listen = "127.0.0.1:%d"\ncert = "%s"\npriv_key = "%s"\n[anytls]\npassword = "integration-secret"\n' % (server_port, directory / 'stunnel_cert.pem', directory / 'private_key.pem'))
            client_config, _, http = verify.client_config(directory, 'anytls', 'anytls', server_port)
            with child('stunnel_server', server_config, directory, 'server', args.trace_dir) as server:
                verify.ready(server, server_port)
                with child('stunnel_client', client_config, directory, 'client', args.trace_dir) as client:
                    verify.ready(client, http)
                    for _ in range(2):
                        transfer(http, backend.server_address[1], len(BLOCK), expected_crc(len(BLOCK)), False)
                    for concurrency in [1, 4]:
                        for sample in range(args.samples):
                            client_before = cpu_seconds(client.pid) if not args.trace_dir else None
                            server_before = cpu_seconds(server.pid) if not args.trace_dir else None
                            driver_before = time.process_time()
                            started = time.perf_counter()
                            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                                futures = [pool.submit(transfer, http, backend.server_address[1], args.bytes, crc, False) for _ in range(concurrency)]
                                durations = [future.result() for future in futures]
                            elapsed = time.perf_counter() - started
                            rows.append({'case': 'bulk', 'concurrency': concurrency, 'sample': sample,
                                         'bytes': args.bytes * concurrency, 'errors': 0, 'wall_s': elapsed,
                                         'flow_s': durations,
                                         'client_cpu_s': cpu_seconds(client.pid) - client_before if client_before is not None else None,
                                         'server_cpu_s': cpu_seconds(server.pid) - server_before if server_before is not None else None,
                                         'driver_and_backend_cpu_s': time.process_time() - driver_before})
                    small = 1024
                    small_crc = expected_crc(small)
                    for sample in range(args.samples):
                        durations = [transfer(http, backend.server_address[1], small, small_crc, True) for _ in range(100)]
                        rows.append({'case': 'short-sequential', 'sample': sample, 'bytes': small * 100, 'errors': 0,
                                     'median_s': statistics.median(durations), 'max_s': max(durations),
                                     'total_s': sum(durations)})
        finally:
            backend.shutdown()
            backend.server_close()
    print(json.dumps({'variant': args.variant, 'profile_only': bool(args.trace_dir),
                      'wall_scope': 'CONNECT setup, all transfers and executor setup; flow_s excludes CONNECT',
                      'load_average': os.getloadavg(), 'cpus': os.cpu_count(), 'rows': rows}, indent=2))


if __name__ == '__main__':
    main()
