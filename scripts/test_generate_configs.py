#!/usr/bin/env python3
"""Filesystem and command-line checks for deployment generation."""

import contextlib
import importlib.util
import io
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).with_name('generate_configs.py')
SPEC = importlib.util.spec_from_file_location('generate_configs', SCRIPT)
generator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = generator
SPEC.loader.exec_module(generator)


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'deployment'
        self.certgen = self.root / 'certgen'
        self.certgen.write_text('#!/bin/sh\nprintf CERT > stunnel_cert.pem\nprintf KEY > private_key.pem\n')
        self.certgen.chmod(0o700)
        self.arguments = ['--server', '192.0.2.1:443', '--certgen', str(self.certgen),
                          '--output', str(self.output)]

    def options(self, extra=(), real=False):
        arguments = self.arguments + list(extra)
        if real:
            root = SCRIPT.resolve().parents[1]
            candidates = [Path(os.environ['STUNNEL_CERTGEN'])] if 'STUNNEL_CERTGEN' in os.environ else [root / 'target/release/certgen', root / 'target/debug/certgen']
            binary = next((p for p in candidates if p.is_file()), None)
            if binary is None:
                self.skipTest('build certgen or set STUNNEL_CERTGEN for generation checks')
            arguments += ['--certgen', str(binary)]
        return generator.parse_options(arguments)

    def assert_clean_failure(self):
        self.assertFalse(os.path.lexists(self.output))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['certgen'])

    def test_cli_help(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('--server', result.stdout)

    def test_cli_defaults_generate_deployment_and_refuse_repeat(self):
        binary = self.options(real=True).certgen
        command = [sys.executable, str(SCRIPT.resolve()), '--certgen', str(binary)]
        result = subprocess.run(command, cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name for p in self.output.iterdir()},
                         {'server-1', 'relay', 'client', 'README.md'})
        client = (self.output / 'client/config.toml').read_text()
        self.assertIn('socks5_listen = "127.0.0.1:1080"', client)
        self.assertIn('http_listen = "127.0.0.1:8080"', client)
        original = {p.relative_to(self.output): p.read_bytes()
                    for p in self.output.rglob('*') if p.is_file()}
        repeated = subprocess.run(command, cwd=self.root, capture_output=True, text=True)
        self.assertNotEqual(repeated.returncode, 0)
        self.assertIn('output already exists', repeated.stderr)
        self.assertEqual(original, {p.relative_to(self.output): p.read_bytes()
                                   for p in self.output.rglob('*') if p.is_file()})

    def test_defaults_generate_relay_and_server_placeholders(self):
        options = generator.parse_options(self.arguments[2:])
        generator.generate(options)
        self.assertEqual(str(options.servers[0]), '203.0.113.10:12345')
        self.assertEqual(str(options.relay), '198.51.100.20:12345')
        self.assertIn('198.51.100.20:12345', (self.output / 'client/config.toml').read_text())
        self.assertIn('203.0.113.10:12345', (self.output / 'relay/config.toml').read_text())
        instructions = (self.output / 'README.md').read_text()
        self.assertIn('servers[].server_addr', instructions)
        self.assertIn('upstreams[].server_addr', instructions)

    def test_explicit_addresses_replace_defaults_and_preserve_server_order(self):
        options = self.options(['--server', '[2001:db8::1]:8443', '--relay', '198.51.100.1:443'])
        self.assertEqual([str(item) for item in options.servers], ['192.0.2.1:443', '[2001:db8::1]:8443'])
        self.assertEqual(str(options.relay), '198.51.100.1:443')

    def test_no_relay_generates_direct_client(self):
        options = generator.parse_options(self.arguments[2:] + ['--no-relay'])
        generator.generate(options)
        self.assertFalse((self.output / 'relay').exists())
        client = (self.output / 'client/config.toml').read_text()
        self.assertIn('203.0.113.10:12345', client)
        self.assertNotIn('198.51.100.20', client)

    def test_explicit_relay_keeps_default_server(self):
        options = generator.parse_options(self.arguments[2:] + ['--relay', '198.51.100.1:443'])
        self.assertEqual([str(item) for item in options.servers], ['203.0.113.10:12345'])
        self.assertEqual(str(options.relay), '198.51.100.1:443')

    def test_relay_and_no_relay_conflict(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.options(['--relay', '198.51.100.1:443', '--no-relay'])
        self.assert_clean_failure()

    def test_quic_table_matches_transport(self):
        for transport in ('anytls', 'tlstcp', 'quic', 's2n-quic'):
            with self.subTest(transport=transport):
                generator.generate(self.options(['--transport', transport]))
                for role in ('server-1', 'relay'):
                    config = (self.output / role / 'config.toml').read_text()
                    if transport in ('quic', 's2n-quic'):
                        self.assertIn(f'[quic]\nserver_type = "{transport}"', config)
                    else:
                        self.assertNotIn('[quic]', config)
                shutil.rmtree(self.output)

    def test_relay_bundles_are_private_and_contain_only_needed_credentials(self):
        generator.generate(self.options(['--server', '[2001:db8::1]:8443', '--relay', '198.51.100.1:443'], real=True))
        expected = {'client': {'relay'}, 'relay': {'relay', 'server-1', 'server-2'},
                    'server-1': {'server-1'}, 'server-2': {'server-2'}}
        for role, listeners in expected.items():
            files = {p.name for p in (self.output / role).iterdir()}
            self.assertEqual(files, {'config.toml'} | {f'{name}-{suffix}.pem'
                             for name in listeners for suffix in ('cert', 'key')})
        for path in [self.output, *self.output.rglob('*')]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
        client = (self.output / 'client/config.toml').read_text()
        relay = (self.output / 'relay/config.toml').read_text()
        self.assertIn('127.0.0.1:1080', client)
        self.assertNotIn('192.0.2.1', client)
        self.assertLess(relay.index('192.0.2.1:443'), relay.index('[2001:db8::1]:8443'))
        self.assertIn('listen = "[::]:8443"', (self.output / 'server-2/config.toml').read_text())
        password = client.split('password = "')[1].split('"')[0]
        self.assertIn(password, relay)
        self.assertNotIn(password, (self.output / 'server-1/config.toml').read_text())
        self.assertNotIn(password, (self.output / 'README.md').read_text())

    def test_separate_ipv4_wildcard_and_ipv6_loopback_proxies(self):
        options = self.options(['--socks5-listen', '0.0.0.0:1080',
                                '--http-listen', '[::1]:1080'], real=True)
        result = subprocess.run([sys.executable, str(SCRIPT), *self.arguments,
                                 '--certgen', str(options.certgen),
                                 '--socks5-listen', '0.0.0.0:1080', '--http-listen', '[::1]:1080'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = (self.output / 'client/config.toml').read_text()
        self.assertIn('socks5_listen = "0.0.0.0:1080"', config)
        self.assertIn('http_listen = "[::1]:1080"', config)

    def test_invalid_arguments_do_not_write(self):
        invalid = [ ['--server', 'example.com:443'], ['--server', '0.0.0.0:443'],
                    ['--server', '[::]:443'], ['--server', '192.0.2.1:443'],
                    ['--server', '[::ffff:192.0.2.1]:443'],
                    ['--server', '192.0.2.2:0'], ['--server', '[fe80::1%eth0]:443'],
                    ['--http-listen', '127.0.0.1:1080'],
                    ['--socks5-listen', '[::ffff:0.0.0.0]:1080', '--http-listen', '127.0.0.1:1080'],
                    ['--relay', '198.51.100.1:443', '--server', '127.0.0.1:443'] ]
        for extra in invalid:
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.options(extra)
                self.assert_clean_failure()

    def test_existing_outputs_are_preserved(self):
        for kind in ('empty', 'nonempty', 'file', 'dangling', 'symlink'):
            with self.subTest(kind=kind):
                if kind in ('empty', 'nonempty'):
                    self.output.mkdir()
                    if kind == 'nonempty':
                        (self.output / 'keep').write_text('original')
                elif kind == 'file':
                    self.output.write_text('original')
                else:
                    self.output.symlink_to(self.root / ('missing' if kind == 'dangling' else 'certgen'))
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    self.options()
                self.assertTrue(os.path.lexists(self.output))
                if kind == 'nonempty':
                    self.assertEqual((self.output / 'keep').read_text(), 'original')
                if kind == 'file':
                    self.assertEqual(self.output.read_text(), 'original')
                if self.output.is_symlink() or self.output.is_file():
                    self.output.unlink()
                else:
                    shutil.rmtree(self.output)

    def test_certgen_failure_and_bad_outputs_clean_staging(self):
        for body in ('exit 1', 'printf CERT > stunnel_cert.pem',
                     'ln -s /etc/passwd stunnel_cert.pem; printf KEY > private_key.pem',
                     'touch stunnel_cert.pem private_key.pem'):
            with self.subTest(body=body):
                self.certgen.write_text('#!/bin/sh\n' + body + '\n')
                with self.assertRaises((ValueError, OSError)):
                    generator.generate(self.options())
                self.assert_clean_failure()

    def test_timeout_cleans_staging(self):
        options = self.options()
        with patch.object(generator.subprocess, 'run', side_effect=subprocess.TimeoutExpired('certgen', 30)):
            with self.assertRaisesRegex(ValueError, 'timed out'):
                generator.generate(options)
        self.assert_clean_failure()

    def test_publish_failure_cleans_owned_output(self):
        options = self.options(real=True)
        original = Path.rename
        calls = 0

        def fail_second(source, target):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('injected move failure')
            return original(source, target)

        with patch.object(Path, 'rename', fail_second), self.assertRaises(OSError):
            generator.generate(options)
        self.assert_clean_failure()

    def test_racing_output_is_not_removed(self):
        options = self.options(real=True)
        original = Path.mkdir

        def race(path, *args, **kwargs):
            if path == self.output:
                original(path)
                (path / 'keep').write_text('racer')
            return original(path, *args, **kwargs)

        with patch.object(Path, 'mkdir', race), self.assertRaises(FileExistsError):
            generator.generate(options)
        self.assertEqual((self.output / 'keep').read_text(), 'racer')
        self.assertFalse(any(p.name.startswith('.stunnel-') for p in self.root.iterdir()))

    def test_real_certgen_if_built(self):
        options = self.options(['--no-relay'], real=True)
        generator.generate(options)
        certificate = (self.output / 'client/server-1-cert.pem').read_text()
        self.assertIn('BEGIN CERTIFICATE', certificate)
        self.assertEqual(certificate, (self.output / 'server-1/server-1-cert.pem').read_text())
        self.assertIn('PRIVATE KEY', (self.output / 'client/server-1-key.pem').read_text())


if __name__ == '__main__':
    unittest.main()
