#!/usr/bin/env python3
"""Export or verify the complete committed local AnyTLS source."""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=pathlib.Path, default=ROOT.parent / 'anytls-rs')
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    source = args.source.expanduser().resolve()
    target = ROOT / 'vendor/anytls-rs'
    if source == target.resolve():
        parser.error('source must be the separate library checkout')
    if git(source, 'status', '--porcelain', '--untracked-files=normal').strip():
        parser.error('commit the library changes before exporting them')
    revision = git(source, 'rev-parse', 'HEAD').decode().strip()
    entries = [pathlib.Path(p.decode()) for p in git(source, 'ls-files', '-z').split(b'\0') if p]
    expected = {path: git(source, 'show', f'{revision}:{path.as_posix()}') for path in entries}
    digest = hashlib.sha256()
    for path, content in sorted(expected.items()):
        digest.update(path.as_posix().encode() + b'\0' + hashlib.sha256(content).digest())
    metadata = json.dumps({'repository': 'anytls-rs (local fork)', 'revision': revision,
                           'source_sha256': digest.hexdigest(), 'files': len(entries)}, indent=2) + '\n'
    expected[pathlib.Path('VENDORED.json')] = metadata.encode()
    actual = {pathlib.Path(p.decode()).relative_to('vendor/anytls-rs'): ROOT / p.decode()
              for p in git(ROOT, 'ls-files', '-z', '--cached', '--others', '--exclude-standard',
                           '--', 'vendor/anytls-rs').split(b'\0') if p and (ROOT / p.decode()).is_file()}
    changed = [path for path, content in expected.items()
               if path not in actual or actual[path].read_bytes() != content]
    extra = actual.keys() - expected.keys()
    if args.write:
        for path in extra:
            actual[path].unlink()
        for path in changed:
            destination = target / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(expected[path])
        for path in entries:
            shutil.copymode(source / path, target / path)
    elif changed or extra:
        for path in sorted(changed):
            print('DIFF', path)
        for path in sorted(extra):
            print('EXTRA', path)
        raise SystemExit(1)
    print(f'PASS AnyTLS source: {len(entries)} files at {revision}')


if __name__ == '__main__':
    main()
