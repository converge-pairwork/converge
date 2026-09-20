#!/usr/bin/env python3
"""Builds the release manifest and SHA256SUMS for a CONVERGE release.

    python3 scripts/release-manifest.py dist/
    python3 scripts/release-manifest.py dist/ --complete --tag v0.1.1 --commit "$GITHUB_SHA"

`dist` is a directory holding exactly the files a release publishes: the bridge binaries, the
skill, the live renderer, the updater, the installer and the source tarball. This writes
`manifest.json` and `SHA256SUMS` beside them and prints what it found.

`--complete` is what a real release is built with. It refuses a directory that is missing a
platform, that carries a file the release does not publish, or that names the same platform
twice: a release which quietly goes out with three binaries instead of four is a release that
leaves a quarter of its users on an old version with no sign that anything happened.

The manifest is the one thing the installer and the updater read to decide what to fetch and
what it should hash to. It therefore states, for every artifact:

    a name relative to the release, never a URL
        An updater that took its origin out of a manifest would be an updater that a
        compromised manifest could point anywhere. The release source is the one the
        installation was set up with, and nothing in this file can move it.

    the SHA-256 of the exact bytes published
        Computed here, from the files that are about to be uploaded.

    the byte size, and for a bridge the executable format, the operating system and the
    architecture it was built for
        So that a download can be rejected for being the wrong kind of thing, or the right kind
        of thing for the wrong machine, before it is installed, and not only for hashing
        differently than expected.

and, for the release as a whole, the version, the tag and the commit it was built from: the
three facts a person needs in order to decide whether the manifest in front of them is the one
their own repository would have produced, which is the question they answer before they sign it.

The bytes written here are the bytes that get signed, so they are deterministic: sorted keys,
two-space indent, one trailing newline, and nothing in them that depends on when or where this
ran. Running this twice over the same files produces the same file. `scripts/sign-manifest.py`
is where the owner's detached signature over those bytes is made, offline; nothing in CI holds
that key. See SECURITY.md and docs/RELEASE.md.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r'\A\d{1,9}\.\d{1,9}\.\d{1,9}\Z')
COMMIT_RE = re.compile(r'\A[0-9a-f]{40}\Z')
TAG_RE = re.compile(r'\Av\d{1,9}\.\d{1,9}\.\d{1,9}\Z')

# The manifest format. 2 added the tag, the commit, the per-artifact byte size, and the
# operating system and architecture each bridge binary was built for. An updater that
# understands a lower number refuses this rather than reading it part way.
SCHEMA = 2

# Every platform a CONVERGE release publishes a bridge for: the operating system, the
# architecture, the executable format, and the first bytes of an executable that belongs on it.
# The installer and the updater check the same thing on the way in, so a macOS binary uploaded
# under the Windows name is caught here, at the point it is still cheap.
PLATFORMS = {
    'linux-x86_64':   ('linux',   'x86_64', 'elf',   (b'\x7fELF',)),
    'windows-x86_64': ('windows', 'x86_64', 'pe',    (b'MZ',)),
    'macos-arm64':    ('macos',   'arm64',  'macho', (b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe')),
    'macos-x86_64':   ('macos',   'x86_64', 'macho', (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe',
                                                      b'\xca\xfe\xba\xbe')),
}

# What a release always carries besides the binaries. `updater` is published so that a new
# installation gets the current one; it is not in `files`, because it is the thing that reads
# this manifest and it does not replace itself mid-check.
SUPPORT = {
    'skill':    'skill.md',
    'renderer': 'converge-live.py',
}
EXTRA = ('converge-update.py', 'install.sh', 'converge-src.tar.gz')
# Written by this script, so never inputs to it.
WRITTEN = ('manifest.json', 'SHA256SUMS', 'manifest.json.sig')


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def fail(message):
    print('release manifest: ' + message, file=sys.stderr)
    raise SystemExit(1)


def bridge_name(version, platform):
    """The one name a bridge binary may be published under, for this version and platform.
    There is exactly one, which is what makes a duplicate or a near-miss detectable."""
    return 'converge-bridge-%s-%s%s' % (version, platform, '.exe' if platform.startswith('windows') else '')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('dist', help='the directory holding exactly what the release publishes')
    parser.add_argument('--complete', action='store_true',
                        help='refuse a release that is missing a platform or carries a stray file')
    parser.add_argument('--tag', help='the release tag, e.g. v0.1.1')
    parser.add_argument('--commit', help='the 40-character commit the release is built from')
    args = parser.parse_args()

    dist = Path(args.dist).resolve()
    if not dist.is_dir():
        fail('%s is not a directory' % dist)

    version = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
    if not SEMVER.match(version):
        fail('VERSION is not MAJOR.MINOR.PATCH: %r' % version)

    tag = args.tag or ('v' + version)
    if not TAG_RE.match(tag):
        fail('tag is not vMAJOR.MINOR.PATCH: %r' % tag)
    if tag != 'v' + version:
        fail('tag %s does not match VERSION %s' % (tag, version))
    commit = (args.commit or '').strip().lower()
    if commit and not COMMIT_RE.match(commit):
        fail('commit is not a 40-character hex object name: %r' % args.commit)
    if args.complete and not commit:
        fail('a complete release states the commit it was built from (--commit)')

    # The packaged skill must state the release's version. A release whose own files disagree
    # about what it is cannot be published; an installation would then never settle.
    skill = dist / SUPPORT['skill']
    if not skill.is_file():
        fail('missing %s' % skill.name)
    stated = [l for l in skill.read_text(encoding='utf-8').split('\n---\n')[0].split('\n') if l.startswith('version:')]
    if not stated or stated[0].split(':', 1)[1].strip() != version:
        fail('%s does not state version %s' % (skill.name, version))

    manifest = {
        'schema': SCHEMA,
        'product': 'converge',
        'component': 'client',
        'version': version,
        'tag': tag,
        'repository': 'converge-pairwork/converge',
        'license': 'GPL-3.0-or-later',
        'files': {},
        'bridge': {},
    }
    if commit:
        manifest['commit'] = commit

    for key, name in SUPPORT.items():
        path = dist / name
        if not path.is_file():
            fail('missing %s' % name)
        manifest['files'][key] = {'path': name, 'sha256': sha256(path), 'size': path.stat().st_size}

    # One canonical name per platform, so a second file that looks like a bridge binary is a
    # stray or a duplicate rather than a choice to be made.
    canonical = {bridge_name(version, key): key for key in PLATFORMS}
    strays = sorted(p.name for p in dist.iterdir()
                    if p.is_file() and p.name.startswith('converge-bridge') and p.name not in canonical)
    if strays:
        fail('these are not canonical release names for v%s: %s' % (version, ', '.join(strays)))

    missing = []
    for key, (system, architecture, fmt, heads) in PLATFORMS.items():
        name = bridge_name(version, key)
        path = dist / name
        if not path.is_file():
            missing.append(key)
            print('  -- no binary for %s (%s)' % (key, name))
            continue
        data = path.read_bytes()
        if not any(data.startswith(h) for h in heads):
            fail('%s is not a %s executable' % (name, fmt))
        if version.encode() not in data:
            fail('%s does not carry version %s' % (name, version))
        manifest['bridge'][key] = {'path': name, 'sha256': sha256(path), 'size': path.stat().st_size,
                                   'os': system, 'arch': architecture, 'format': fmt}
        print('  ok %-16s %s' % (key, name))

    if not manifest['bridge']:
        fail('no bridge binary found in %s' % dist)
    if args.complete and missing:
        fail('a complete release carries every platform; missing: %s' % ', '.join(sorted(missing)))

    for name in EXTRA:
        path = dist / name
        if path.is_file():
            manifest.setdefault('extra', {})[name] = {'path': name, 'sha256': sha256(path),
                                                      'size': path.stat().st_size}
        elif name != 'converge-src.tar.gz' or args.complete:
            fail('missing %s' % name)

    if args.complete:
        published = set(canonical) | set(SUPPORT.values()) | set(EXTRA) | set(WRITTEN)
        unexpected = sorted(p.name for p in dist.iterdir() if p.name not in published)
        if unexpected:
            fail('a release publishes only what it names; found also: %s' % ', '.join(unexpected))

    # Written with a stable serialisation, because the signature is over these exact bytes.
    body = json.dumps(manifest, indent=2, sort_keys=True) + '\n'
    (dist / 'manifest.json').write_text(body, encoding='utf-8', newline='\n')

    sums = []
    for path in sorted(dist.iterdir()):
        if path.is_file() and path.name not in ('SHA256SUMS', 'manifest.json.sig'):
            sums.append('%s  %s' % (sha256(path), path.name))
    (dist / 'SHA256SUMS').write_text('\n'.join(sums) + '\n', encoding='utf-8', newline='\n')

    print('release manifest ok: %s (v%s%s), %d bridge binaries, %d files'
          % (tag, version, ', ' + commit[:12] if commit else '', len(manifest['bridge']), len(sums)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
