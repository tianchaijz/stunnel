#!/usr/bin/env python3
"""Generate portable STunnel role bundles using the built Rust certgen."""

import argparse
from dataclasses import dataclass, field
import ipaddress
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Sequence


@dataclass(frozen=True)
class Endpoint:
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    port: int

    def __str__(self) -> str:
        host = f'[{self.ip}]' if self.ip.version == 6 else str(self.ip)
        return f'{host}:{self.port}'

    @property
    def canonical_ip(self):
        return getattr(self.ip, 'ipv4_mapped', None) or self.ip

    @property
    def bind(self) -> str:
        return f'[::]:{self.port}' if self.ip.version == 6 else f'0.0.0.0:{self.port}'


@dataclass(frozen=True)
class Options:
    servers: tuple[Endpoint, ...]
    relay: Endpoint | None
    transport: str
    socks5_listen: Endpoint
    http_listen: Endpoint
    output: Path
    certgen: Path


@dataclass(frozen=True)
class Listener:
    name: str
    endpoint: Endpoint
    material_dir: Path
    password: str | None = field(repr=False)


def endpoint(value: str) -> Endpoint:
    try:
        if value.startswith('['):
            host, port = value[1:].split(']:')
            if ':' not in host:
                raise ValueError
        else:
            host, port = value.split(':')
        if '%' in host or not port.isascii() or not port.isdecimal():
            raise ValueError
        ip = ipaddress.ip_address(host)
        if not 1 <= int(port) <= 65535:
            raise ValueError
        return Endpoint(ip, int(port))
    except ValueError:
        raise argparse.ArgumentTypeError('expected numeric IP:PORT (bracket IPv6), port 1..65535') from None


def parse_options(argv: Sequence[str]) -> Options:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=endpoint, action='append',
                        help='advertised server IP:PORT (default: 203.0.113.10:12345); repeat for ordered backups')
    relay = parser.add_mutually_exclusive_group()
    relay.add_argument('--relay', type=endpoint, default=endpoint('198.51.100.20:12345'),
                       help='advertised relay IP:PORT (default: 198.51.100.20:12345)')
    relay.add_argument('--no-relay', action='store_true', help='connect directly to the servers')
    parser.add_argument('--transport', choices=('anytls', 'tlstcp', 'quic', 's2n-quic'), default='anytls')
    parser.add_argument('--socks5-listen', type=endpoint, default=endpoint('127.0.0.1:1080'),
                        help='SOCKS5 proxy listener (default: 127.0.0.1:1080)')
    parser.add_argument('--http-listen', type=endpoint, default=endpoint('127.0.0.1:8080'),
                        help='HTTP proxy listener (default: 127.0.0.1:8080)')
    parser.add_argument('--output', type=Path, default=Path('deployment'),
                        help='new directory under an existing parent (default: ./deployment in the current working directory)')
    parser.add_argument('--certgen', help='built Rust certgen path or executable on PATH')
    args = parser.parse_args(argv)
    if args.server is None:
        args.server = [endpoint('203.0.113.10:12345')]
    if args.no_relay:
        args.relay = None
    endpoints = args.server + ([args.relay] if args.relay else [])
    identities = [(item.canonical_ip, item.port) for item in endpoints]
    if any(item.canonical_ip.is_unspecified or item.canonical_ip.is_multicast for item in endpoints):
        parser.error('advertised endpoints must be unicast, non-wildcard addresses')
    if len(set(identities)) != len(identities):
        parser.error('advertised endpoints must be distinct')
    if args.relay and any(item.port == args.relay.port and item.canonical_ip.is_loopback
                          and (args.relay.ip.version == 6 or item.canonical_ip.version == 4)
                          for item in args.server):
        parser.error('upstream points to the relay wildcard listener')
    socks, http = args.socks5_listen, args.http_listen
    if socks.port == http.port and (socks.canonical_ip == http.canonical_ip
            or (socks.canonical_ip.is_unspecified and (socks.canonical_ip.version == 6 or http.canonical_ip.version == 4))
            or (http.canonical_ip.is_unspecified and (http.canonical_ip.version == 6 or socks.canonical_ip.version == 4))):
        parser.error('SOCKS5 and HTTP listeners conflict')
    output = Path(os.path.abspath(args.output))
    if os.path.lexists(output):
        parser.error('output already exists (including symlinks)')
    if not output.parent.is_dir():
        parser.error('output parent must be an existing directory')
    root = Path(__file__).resolve().parents[1]
    candidates = [args.certgen] if args.certgen else [str(Path(__file__).resolve().with_name('certgen')),
                                                     str(root / 'target/release/certgen'),
                                                     str(root / 'target/debug/certgen')]
    binary = next((shutil.which(value) for value in candidates if shutil.which(value)), None)
    if binary is None:
        parser.error('certgen executable not found; run cargo build --bins or pass --certgen')
    return Options(tuple(args.server), args.relay, args.transport, socks, http,
                   output, Path(binary).resolve())


def create_listener(name: str, address: Endpoint, options: Options, scratch: Path) -> Listener:
    directory = scratch / name
    directory.mkdir(mode=0o700)
    try:
        subprocess.run([str(options.certgen)], cwd=directory, check=True, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise ValueError(f'certgen timed out for {name}') from None
    except subprocess.CalledProcessError:
        raise ValueError(f'certgen failed for {name}') from None
    for filename in ('stunnel_cert.pem', 'private_key.pem'):
        path = directory / filename
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
            raise ValueError(f'certgen did not produce regular, nonempty PEM files for {name}')
        path.chmod(0o600)
    password = secrets.token_urlsafe(32) if options.transport == 'anytls' else None
    return Listener(name, address, directory, password)


def copy_credentials(directory: Path, listeners: Sequence[Listener]) -> None:
    for listener in listeners:
        for source, suffix in [('stunnel_cert.pem', 'cert'), ('private_key.pem', 'key')]:
            target = directory / f'{listener.name}-{suffix}.pem'
            shutil.copyfile(listener.material_dir / source, target)
            target.chmod(0o600)


def render_peers(table: str, peers: Sequence[Listener], transport: str) -> str:
    result = ''
    for peer in peers:
        result += (f'\n[[{table}]]\nserver_addr = "{peer.endpoint}"\n'
                   f'server_name = "stunnel"\nserver_cert = "{peer.name}-cert.pem"\n'
                   f'private_key = "{peer.name}-key.pem"\ntunnel_type = "{transport}"\n')
        if peer.password:
            result += f'\n[{table}.anytls]\npassword = "{peer.password}"\n'
    return result


def write_client(directory: Path, options: Options, peers: Sequence[Listener]) -> None:
    directory.mkdir(mode=0o700)
    config = (f'socks5_listen = "{options.socks5_listen}"\n'
              f'http_listen = "{options.http_listen}"\n')
    (directory / 'config.toml').write_text(config + render_peers('servers', peers, options.transport))
    copy_credentials(directory, peers)


def write_server(directory: Path, options: Options, listener: Listener,
                 upstreams: Sequence[Listener] = ()) -> None:
    directory.mkdir(mode=0o700)
    config = (f'listen = "{listener.endpoint.bind}"\npriv_key = "{listener.name}-key.pem"\n'
              f'cert = "{listener.name}-cert.pem"\n')
    if options.transport in ('quic', 's2n-quic'):
        config += f'\n[quic]\nserver_type = "{options.transport}"\n'
    if listener.password:
        config += f'\n[anytls]\npassword = "{listener.password}"\n'
    (directory / 'config.toml').write_text(config + render_peers('upstreams', upstreams, options.transport))
    copy_credentials(directory, (listener, *upstreams))


def generate(options: Options) -> None:
    previous_umask = os.umask(0o077)
    owns_output = False
    try:
        with tempfile.TemporaryDirectory(prefix='.stunnel-', dir=options.output.parent) as temporary:
            staged = Path(temporary)
            scratch = staged / 'credentials'
            scratch.mkdir(mode=0o700)
            servers = tuple(create_listener(f'server-{i}', address, options, scratch)
                            for i, address in enumerate(options.servers, 1))
            for server in servers:
                write_server(staged / server.name, options, server)
            peers = servers
            if options.relay:
                relay = create_listener('relay', options.relay, options, scratch)
                write_server(staged / 'relay', options, relay, servers)
                peers = (relay,)
            write_client(staged / 'client', options, peers)
            shutil.rmtree(scratch)
            roles = [s.name for s in servers] + (['relay'] if options.relay else []) + ['client']
            instructions = ('# STunnel deployment\n\nGenerate with `python3 scripts/generate_configs.py`. '
                            'Output defaults to `./deployment` in the current working directory; override it with `--output`. '
                            'The default relay address 198.51.100.20:12345 and server address 203.0.113.10:12345 are placeholders. '
                            'They assume separate hosts; use distinct relay and server ports for a same-host setup. '
                            'Before deployment, edit `client/config.toml` servers[].server_addr and, when present, '
                            '`relay/config.toml` upstreams[].server_addr to your hosts. '
                            'Use --no-relay when generating direct client-to-server bundles.\n\nCopy each complete role directory to its host. '
                            'Run each command from the parent of the copied role directory. Certificate paths resolve from the working directory. Put the binaries on PATH.\n\n')
            for role in roles:
                binary = 'stunnel_client' if role == 'client' else 'stunnel_server'
                instructions += f'```sh\ncd {role}\n{binary} --config config.toml\n```\n\n'
            instructions += ('Servers start TCP and UDP listeners on the configured port. '
                             'The server still starts its default UDP QUIC listener when [quic] is omitted. '
                             'Servers are tried in their listed order. The TLS name stunnel matches the certificate SAN; it is not a DNS destination. Keep all bundles private.\n')
            (staged / 'README.md').write_text(instructions)
            options.output.mkdir(mode=0o700)
            owns_output = True
            for child in staged.iterdir():
                child.rename(options.output / child.name)
    except BaseException:
        if owns_output:
            shutil.rmtree(options.output)
        raise
    finally:
        os.umask(previous_umask)


def main(argv: Sequence[str] | None = None) -> int:
    options = parse_options(sys.argv[1:] if argv is None else argv)
    try:
        generate(options)
    except (OSError, ValueError) as error:
        print(f'generation failed: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('generation interrupted', file=sys.stderr)
        return 130
    print(f'Generated deployment at {options.output}. See README.md; cd into each role before launch.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
