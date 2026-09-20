#!/usr/bin/env python3
"""Builds the release manifest and SHA256SUMS for a CONVERGE release.

    python3 scripts/release-manifest.py dist/

`dist` is a directory holding exactly the files a release publishes: the bridge binaries, the
skill, the live renderer, the updater, the installer and the source tarball. This writes
`manifest.json` and `SHA256SUMS` beside them and prints what it found.

The manifest is the one thing the installer and the updater read to decide what to fetch and
what it should hash to. It therefore states, for every artifact:

    a name relative to the release, never a URL
        An updater that took its origin out of a manifest would be an updater that a
        compromised manifest could point anywhere. The release source is the one the
        installation was set up with, and nothing in this file can move it.

    the SHA-256 of the exact bytes published
        Computed here, from the files that are about to be uploaded.

    the size, and for a bridge the executable format and its platform
        So that a download can be rejected for being the wrong kind of thing before it is
        installed, and not only for hashing differently than expected.

A checksum published beside the binary it describes is not independent authenticity: whoever
could replace one could replace the other. The SHA-256 is what makes a download reproducible
and a mismatch loud; a detached signature over this manifest is what makes it attributable, and
`scripts/sign-manifest.py` is where that is applied. See SECURITY.md.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r'\A\d{1,9}\.\d{1,9}\.\d{1,9}\Z')

# Every platform a CONVERGE release publishes a bridge for, and the first bytes of an executable
# that belongs on it. The installer and the updater check the same thing on the way in, so a
# macOS binary uploaded under the Windows name is caught here, at the point it is still cheap.
PLATFORMS = {
    'linux-x86_64':   ('elf',   (b'\x7fELF',)),
    'windows-x86_64': ('pe',    (b'MZ',)),
    'macos-arm64':    ('macho', (b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe')),
    'macos-x86_64':   ('macho', (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe')),
}

# What a release always carries besides the binaries. `updater` is published so that a new
# installation gets the current one; it is not in `files`, because it is the thing that reads
# this manifest and it does not replace itself mid-check.
SUPPORT = {
    'skill':    'skill.md',
    'renderer': 'converge-live.py',
}
EXTRA = ('converge-update.py', 'install.sh', 'converge-src.tar.gz')


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def fail(message):
    print('release manifest: ' + message, file=sys.stderr)
    raise SystemExit(1)


def main():
    if len(sys.argv) != 2:
        fail('usage: release-manifest.py DIST_DIR')
    dist = Path(sys.argv[1]).resolve()
    if not dist.is_dir():
        fail('%s is not a directory' % dist)

    version = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
    if not SEMVER.match(version):
        fail('VERSION is not MAJOR.MINOR.PATCH: %r' % version)

    # The packaged skill must state the release's version. A release whose own files disagree
    # about what it is cannot be published; an installation would then never settle.
    skill = dist / SUPPORT['skill']
    if not skill.is_file():
        fail('missing %s' % skill.name)
    stated = [l for l in skill.read_text(encoding='utf-8').split('\n---\n')[0].split('\n') if l.startswith('version:')]
    if not stated or stated[0].split(':', 1)[1].strip() != version:
        fail('%s does not state version %s' % (skill.name, version))

    manifest = {
        'schema': 1,
        'product': 'converge',
        'component': 'client',
        'version': version,
        'repository': 'converge-pairwork/converge',
        'license': 'GPL-3.0-or-later',
        'files': {},
        'bridge': {},
    }

    for key, name in SUPPORT.items():
        path = dist / name
        if not path.is_file():
            fail('missing %s' % name)
        manifest['files'][key] = {'path': name, 'sha256': sha256(path), 'size': path.stat().st_size}

    for key, (fmt, heads) in PLATFORMS.items():
        suffix = '.exe' if key.startswith('windows') else ''
        name = 'converge-bridge-%s-%s%s' % (version, key, suffix)
        path = dist / name
        if not path.is_file():
            print('  -- no binary for %s (%s); the release will not carry one' % (key, name))
            continue
        head = path.read_bytes()[:4]
        if not any(head.startswith(h) for h in heads):
            fail('%s is not a %s executable' % (name, fmt))
        if version.encode() not in path.read_bytes():
            fail('%s does not carry version %s' % (name, version))
        manifest['bridge'][key] = {'path': name, 'sha256': sha256(path),
                                   'size': path.stat().st_size, 'format': fmt}
        print('  ok %-16s %s' % (key, name))

    if not manifest['bridge']:
        fail('no bridge binary found in %s' % dist)

    for name in EXTRA:
        path = dist / name
        if path.is_file():
            manifest.setdefault('extra', {})[name] = {'path': name, 'sha256': sha256(path),
                                                      'size': path.stat().st_size}
        elif name != 'converge-src.tar.gz':
            fail('missing %s' % name)

    # Written with a stable serialisation, because the signature is over these exact bytes.
    body = json.dumps(manifest, indent=2, sort_keys=True) + '\n'
    (dist / 'manifest.json').write_text(body, encoding='utf-8')

    sums = []
    for path in sorted(dist.iterdir()):
        if path.is_file() and path.name != 'SHA256SUMS':
            sums.append('%s  %s' % (sha256(path), path.name))
    (dist / 'SHA256SUMS').write_text('\n'.join(sums) + '\n', encoding='utf-8')

    print('release manifest ok: v%s, %d bridge binaries, %d files'
          % (version, len(manifest['bridge']), len(sums)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
