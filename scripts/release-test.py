#!/usr/bin/env python3
"""The release tooling, tested the way a release would exercise it.

    python3 scripts/release-test.py

A release happens rarely, by hand, under time pressure, and it is the one thing in this
repository whose mistakes reach every installation at once. So the tooling that builds it is
tested on ordinary days instead: a whole release directory is assembled here from fabricated
binaries, a throwaway Ed25519 key is made in this process and never written anywhere, the
manifest is signed with it, and then each thing that could go wrong is made to go wrong.

What it establishes, in the order the file runs them:

    the manifest is deterministic          the same inputs produce the same bytes, because the
                                           signature is over those bytes and nothing else
    the manifest says what it must         schema, version, tag, commit, and for every artifact
                                           a canonical name, a size, a SHA-256, and for a
                                           binary its OS, architecture and executable format
    a release cannot omit a platform       --complete refuses three binaries out of four
    a release cannot carry a stray         a file the release does not publish, or a bridge
                                           under a name that is not the canonical one
    a duplicate mapping is refused         two platforms naming one file, and a manifest that
                                           names the same key twice
    the wrong machine's binary is refused  an entry filed under one platform that says it is
                                           for another
    a tampered manifest is refused         one byte changed anywhere in it
    a tampered signature is refused        and a signature from a key nobody pinned
    a tampered artifact is refused         a changed binary fails on size and on digest
    a missing artifact is refused          and a missing signature is not quietly accepted
    the signer behaves offline             explicit paths, no environment, no key material on
                                           stdout or stderr, and the manifest is never modified
    one trust root, not two                install.sh verifies with the same algorithm and the
                                           same pinned key as converge-update.py
    no placeholder is trusted              every pinned key is a real 32-byte key or there are
                                           none at all
    CI cannot sign                         the release workflow refers to no signing key, and
                                           drafts rather than publishes

It needs no network, no relay and no account, and it never touches the real ~/.converge.
"""
import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / 'agent'
DIST_TOOL = ROOT / 'scripts/release-manifest.py'
SIGN_TOOL = ROOT / 'scripts/sign-manifest.py'
VERIFY_TOOL = ROOT / 'scripts/release-verify.py'

failures = []


def check(ok, what):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok:
        failures.append(what)
    return ok


def updater():
    spec = importlib.util.spec_from_file_location('converge_update', AGENT / 'converge-update.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cu = updater()


# ---------------------------------------------------------------- a key that exists only here
# Signing, on top of the verifier the client already carries. Making the key in this process
# means no key file is ever written, nothing has to be cleaned up, and the test does not depend
# on which openssl this machine calls `openssl` (macOS ships a LibreSSL that cannot do Ed25519
# the way a release is signed).
def _encode_point(point):
    x = point[0] * pow(point[2], cu._P - 2, cu._P) % cu._P
    y = point[1] * pow(point[2], cu._P - 2, cu._P) % cu._P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def keypair(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:], _encode_point(cu._scalar_mult(cu._BASE, a))


def sign(seed, message):
    a, prefix, public = keypair(seed)
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), 'little') % cu._L
    R = _encode_point(cu._scalar_mult(cu._BASE, r))
    k = int.from_bytes(hashlib.sha512(R + public + message).digest(), 'little') % cu._L
    return R + ((r + k * a) % cu._L).to_bytes(32, 'little')


# ---------------------------------------------------------------- a release directory
PLATFORMS = ('linux-x86_64', 'windows-x86_64', 'macos-arm64', 'macos-x86_64')
HEADS = {'linux-x86_64': b'\x7fELF', 'windows-x86_64': b'MZ',
         'macos-arm64': b'\xcf\xfa\xed\xfe', 'macos-x86_64': b'\xcf\xfa\xed\xfe'}


def fake_bridge(platform, version):
    """Something with the right first bytes, the version in it, and a size no real binary
    shares with another, so a swap between platforms is visible."""
    body = HEADS[platform] + b'\0' * 64 + version.encode() + b'\n' + platform.encode()
    return body + b'\0' * (120 * 1024 + len(platform))


def assemble(dist, version, platforms=PLATFORMS, extras=True):
    dist.mkdir(parents=True, exist_ok=True)
    for platform in platforms:
        suffix = '.exe' if platform.startswith('windows') else ''
        (dist / ('converge-bridge-%s-%s%s' % (version, platform, suffix))).write_bytes(
            fake_bridge(platform, version))
    (dist / 'skill.md').write_text('---\nname: converge\nversion: %s\n---\n\nCONVERGE.\n' % version,
                                   encoding='utf-8')
    for name in ('converge-live.py', 'converge-update.py', 'install.sh'):
        shutil.copyfile(AGENT / name, dist / name)
    if extras:
        with tarfile.open(dist / 'converge-src.tar.gz', 'w:gz') as archive:
            archive.add(ROOT / 'VERSION', arcname='converge-%s/VERSION' % version)
    return dist


def build_manifest(dist, *args):
    return subprocess.run([sys.executable, str(DIST_TOOL), str(dist)] + list(args),
                          capture_output=True, text=True, encoding='utf-8', errors='replace')


COMMIT = 'a' * 40


def main():
    version = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
    tag = 'v' + version
    with tempfile.TemporaryDirectory(prefix='converge-release-test-') as scratch:
        run_all(Path(scratch), version, tag)
    print()
    if failures:
        print('%d failed' % len(failures))
        for what in failures:
            print('  - ' + what)
        return 1
    print('release tooling: all checks passed')
    return 0


def run_all(scratch, version, tag):
    # ---- a complete release, and the same bytes twice ----------------------------------------
    print('the manifest')
    dist = assemble(scratch / 'dist', version)
    first = build_manifest(dist, '--complete', '--tag', tag, '--commit', COMMIT)
    check(first.returncode == 0, 'a complete release directory produces a manifest%s'
          % ('' if first.returncode == 0 else ': ' + first.stderr.strip()))
    body = (dist / 'manifest.json').read_bytes()
    sums = (dist / 'SHA256SUMS').read_bytes()

    again = build_manifest(dist, '--complete', '--tag', tag, '--commit', COMMIT)
    check(again.returncode == 0 and (dist / 'manifest.json').read_bytes() == body,
          'the manifest is byte for byte deterministic: the same inputs, the same bytes')
    check((dist / 'SHA256SUMS').read_bytes() == sums, 'so is SHA256SUMS')
    check(body.endswith(b'\n') and b'\r\n' not in body,
          'the manifest ends in one newline and carries no CRLF, on every platform')

    manifest = json.loads(body.decode())
    check(manifest.get('schema') == 2, 'the manifest states its schema (2)')
    check(manifest.get('version') == version, 'the manifest states the CONVERGE version')
    check(manifest.get('tag') == tag, 'the manifest states the release tag')
    check(manifest.get('commit') == COMMIT, 'the manifest states the source commit')
    check(manifest.get('product') == 'converge' and manifest.get('component') == 'client',
          'the manifest says what product and component it describes')
    check(sorted(manifest['bridge']) == sorted(PLATFORMS), 'every platform is described')
    for platform, item in sorted(manifest['bridge'].items()):
        system, _, architecture = platform.partition('-')
        expected = 'converge-bridge-%s-%s%s' % (version, platform,
                                                '.exe' if system == 'windows' else '')
        ok = (item['path'] == expected and item['os'] == system and item['arch'] == architecture
              and item['format'] in ('elf', 'pe', 'macho')
              and item['size'] == (dist / expected).stat().st_size
              and item['sha256'] == hashlib.sha256((dist / expected).read_bytes()).hexdigest())
        check(ok, '%s: canonical name, os, arch, format, size and digest' % platform)
    for key in ('skill', 'renderer'):
        item = manifest['files'][key]
        check(isinstance(item.get('size'), int) and re.fullmatch(r'[0-9a-f]{64}', item['sha256'] or ''),
              '%s: size and digest' % key)
    check('converge-src.tar.gz' in manifest.get('extra', {}) and
          'converge-update.py' in manifest['extra'] and 'install.sh' in manifest['extra'],
          'the updater, the installer and the source tarball are covered too')
    check(all(not re.search(r'https?://', item['path'])
              for section in ('files', 'bridge', 'extra')
              for item in manifest.get(section, {}).values()),
          'no artifact is named by a URL: the manifest cannot move the download')

    # ---- a release that is not complete -------------------------------------------------------
    print('a release cannot go out short or strange')
    short = assemble(scratch / 'short', version, platforms=PLATFORMS[:3])
    out = build_manifest(short, '--complete', '--tag', tag, '--commit', COMMIT)
    check(out.returncode != 0 and 'macos-x86_64' in out.stderr,
          'three binaries out of four: refused, and it names the missing one')
    lenient = build_manifest(short, '--tag', tag)
    check(lenient.returncode == 0, 'without --complete a partial directory is still allowed (make dist)')

    stray = assemble(scratch / 'stray', version)
    (stray / ('converge-bridge-%s-linux-x86_64.bak' % version)).write_bytes(b'\x7fELF')
    out = build_manifest(stray, '--complete', '--tag', tag, '--commit', COMMIT)
    check(out.returncode != 0 and 'canonical' in out.stderr,
          'a second file that looks like a bridge: refused as a non-canonical name')

    extra = assemble(scratch / 'extra', version)
    (extra / 'notes.txt').write_text('hello', encoding='utf-8')
    out = build_manifest(extra, '--complete', '--tag', tag, '--commit', COMMIT)
    check(out.returncode != 0 and 'notes.txt' in out.stderr,
          'a file the release does not publish: refused')

    swapped = assemble(scratch / 'swapped', version)
    (swapped / ('converge-bridge-%s-linux-x86_64' % version)).write_bytes(
        fake_bridge('macos-arm64', version))
    out = build_manifest(swapped, '--complete', '--tag', tag, '--commit', COMMIT)
    check(out.returncode != 0 and 'elf' in out.stderr,
          'a Mach-O uploaded under the Linux name: refused')

    out = build_manifest(assemble(scratch / 'untagged', version), '--complete', '--commit', COMMIT,
                         '--tag', 'v9.9.9')
    check(out.returncode != 0 and 'VERSION' in out.stderr, 'a tag that is not VERSION: refused')
    out = build_manifest(assemble(scratch / 'nocommit', version), '--complete', '--tag', tag)
    check(out.returncode != 0 and 'commit' in out.stderr, 'a complete release with no commit: refused')

    # ---- what the client refuses to read ------------------------------------------------------
    print('the client refuses an ambiguous or unreadable manifest')
    duplicate = body.replace(b'"schema": 2,', b'"schema": 2,\n  "schema": 3,', 1)
    try:
        cu.load_manifest(duplicate)
        check(False, 'a manifest that names the same key twice is refused')
    except ValueError:
        check(True, 'a manifest that names the same key twice is refused')

    future = json.loads(body.decode())
    future['schema'] = 99
    try:
        cu.load_manifest(json.dumps(future).encode())
        check(False, 'a manifest from a newer schema is refused rather than half read')
    except ValueError:
        check(True, 'a manifest from a newer schema is refused rather than half read')

    ambiguous = json.loads(body.decode())
    one_path = ambiguous['bridge']['linux-x86_64']['path']
    ambiguous['bridge']['macos-arm64'] = dict(ambiguous['bridge']['macos-arm64'], path=one_path)
    try:
        cu._one_binary_per_platform(ambiguous['bridge'])
        check(False, 'two platforms mapped to the same file: refused')
    except ValueError:
        check(True, 'two platforms mapped to the same file: refused')

    for field, value in (('os', 'windows'), ('arch', 'arm64')):
        try:
            cu._for_this_machine('linux-x86_64', dict(manifest['bridge']['linux-x86_64'], **{field: value}))
            check(False, 'an entry filed under linux-x86_64 that says %s=%s: refused' % (field, value))
        except ValueError:
            check(True, 'an entry filed under linux-x86_64 that says %s=%s: refused' % (field, value))

    described = cu._described('skill', manifest['files']['skill'], 2)
    check(described[2] == manifest['files']['skill']['size'], 'a schema 2 entry carries its size through')
    for bad in ({'path': 'skill.md', 'sha256': '0' * 64},
                {'path': 'skill.md', 'sha256': '0' * 64, 'size': 0},
                {'path': 'skill.md', 'sha256': '0' * 64, 'size': '12'},
                {'path': 'skill.md', 'sha256': '0' * 64, 'size': True}):
        try:
            cu._described('skill', bad, 2)
            check(False, 'schema 2 entry without a usable size is refused: %r' % (bad.get('size'),))
        except ValueError:
            check(True, 'schema 2 entry without a usable size is refused: %r' % (bad.get('size'),))
    check(cu._described('skill', {'path': 'skill.md', 'sha256': '0' * 64}, 1)[2] is None,
          'a schema 1 manifest, which never stated a size, is still readable')

    # ---- signatures ---------------------------------------------------------------------------
    print('signatures')
    seed = bytes(range(32))
    _, _, public = keypair(seed)
    public_b64 = base64.b64encode(public).decode()
    signature = sign(seed, body)
    signature_text = base64.b64encode(signature).decode() + '\n'

    check(cu.ed25519_verify(public, signature, body),
          'a signature over the manifest verifies with the client verifier')
    check(not cu.ed25519_verify(public, signature, body + b' '),
          'one byte appended to the manifest: refused')
    tampered = body.replace(b'"version"', b'"Version"', 1)
    check(tampered != body and not cu.ed25519_verify(public, signature, tampered),
          'one byte changed inside the manifest: refused')
    check(not cu.ed25519_verify(public, signature[:32] + bytes(32), body),
          'a signature with its scalar replaced: refused')
    _, _, other = keypair(bytes(range(1, 33)))
    check(not cu.ed25519_verify(other, signature, body),
          'a good signature checked against a different key: refused')
    check(not cu.ed25519_verify(public, sign(bytes(range(1, 33)), body), body),
          'a signature by a key nobody pinned: refused')

    # What the client says about a signature made by a key it does not pin. With the production
    # key pinned this must be a refusal, not an abstention: the throwaway key above is exactly
    # the shape of an attacker's key, and it signed this manifest correctly.
    verdict = cu.signed_by_converge(body, signature_text)
    if cu.RELEASE_KEYS:
        check(verdict is False,
              'a manifest signed by a key the client does not pin: refused, not abstained')
    else:
        check(verdict is None, 'with no key pinned, the client reports None, never True')
    for junk in ('', 'not base64!!', base64.b64encode(b'short').decode()):
        check(cu.signed_by_converge(body, junk) is not True,
          'a malformed signature is never accepted (%r)' % junk[:16])

    # ---- the artifacts the manifest describes -------------------------------------------------
    print('artifacts against the manifest')
    signed = dist / 'manifest.json.sig'
    signed.write_text(signature_text, encoding='utf-8')
    out = verify(dist, public_b64)
    check(out.returncode == 0, 'a signed, intact release verifies end to end')

    victim = dist / manifest['bridge']['linux-x86_64']['path']
    keep = victim.read_bytes()
    victim.write_bytes(keep[:-1])                      # one byte shorter
    out = verify(dist, public_b64)
    check(out.returncode != 0 and 'bytes as stated' in out.stdout,
          'a binary one byte short: caught on size before its digest is believed')
    victim.write_bytes(keep[:-1] + b'\1')              # same length, different bytes
    out = verify(dist, public_b64)
    check(out.returncode != 0 and 'SHA-256 as stated' in out.stdout, 'a binary with one byte changed: caught')
    victim.write_bytes(keep)

    gone = dist / manifest['files']['renderer']['path']
    body_of_gone = gone.read_bytes()
    gone.unlink()
    out = verify(dist, public_b64)
    check(out.returncode != 0 and 'is present' in out.stdout, 'an artifact the manifest names but the release lacks: caught')
    gone.write_bytes(body_of_gone)

    signed.write_text(base64.b64encode(b'\0' * 64).decode() + '\n', encoding='utf-8')
    out = verify(dist, public_b64)
    check(out.returncode != 0, 'a signature of the right shape that is not the signature: refused')
    signed.write_text(signature_text, encoding='utf-8')

    # release-verify.py with no --key asks the honest question: would an installation that has
    # this client accept this release? For a release signed by anything but the pinned key the
    # answer has to be no, and while nothing is pinned it has to be no as well.
    out = subprocess.run([sys.executable, str(VERIFY_TOOL), '--manifest', str(dist / 'manifest.json'),
                          '--signature', str(signed)], capture_output=True, text=True,
                         encoding='utf-8', errors='replace')
    if cu.RELEASE_KEYS:
        check(out.returncode != 0 and 'verifies against a key pinned in the client' in out.stdout,
              'a release the pinned key did not sign: verification fails closed')
    else:
        check(out.returncode != 0 and 'RELEASE_KEYS is empty' in out.stdout,
              'with no key pinned in the client, verification fails closed and says why')

    # ---- the signer, offline ------------------------------------------------------------------
    print('the offline signer')
    out = subprocess.run([sys.executable, str(SIGN_TOOL), '--manifest', str(dist / 'manifest.json')],
                         capture_output=True, text=True, encoding='utf-8', errors='replace')
    check(out.returncode != 0 and '--key' in (out.stderr + out.stdout),
          'the signer will not run without an explicit --key')
    text = SIGN_TOOL.read_text(encoding='utf-8')
    check('os.environ' not in text and 'getenv' not in text,
          'the signer reads no key out of the environment')
    check('genpkey' not in text.split('"""')[2] if text.count('"""') > 2 else True,
          'the signer generates no key outside its own documentation')
    check("'-sign'" in text or '"-sign"' in text, 'the signer signs with openssl pkeyutl')
    check('-rawin' in text, 'and signs the message whole, as Ed25519 requires')
    key_pem = scratch / 'not-a-key.pem'
    key_pem.write_text('hello', encoding='utf-8')
    out = subprocess.run([sys.executable, str(SIGN_TOOL), '--key', str(key_pem),
                          '--manifest', str(dist / 'manifest.json')],
                         capture_output=True, text=True, encoding='utf-8', errors='replace')
    check(out.returncode != 0 and 'not a PEM private key' in out.stderr,
          'a file that is not a PEM private key: refused, with no attempt to use it')
    check('hello' not in out.stdout + out.stderr, 'and the contents of that file are not printed')

    signer_openssl = ed25519_openssl(scratch)
    if signer_openssl:
        real = scratch / 'key.pem'
        subprocess.run([signer_openssl, 'genpkey', '-algorithm', 'ed25519', '-out', str(real)],
                       check=True, capture_output=True)
        os.chmod(real, 0o600)
        target = scratch / 'signing'
        target.mkdir()
        shutil.copyfile(dist / 'manifest.json', target / 'manifest.json')
        before = (target / 'manifest.json').read_bytes()
        out = subprocess.run([sys.executable, str(SIGN_TOOL), '--key', str(real), '--public-key',
                              '--manifest', str(target / 'manifest.json'), '--openssl', signer_openssl],
                             capture_output=True, text=True, encoding='utf-8', errors='replace')
        check(out.returncode == 0, 'the signer signs a real manifest with a real key%s'
              % ('' if out.returncode == 0 else ': ' + out.stderr.strip()))
        check((target / 'manifest.json').read_bytes() == before,
              'and does not modify the manifest it signed')
        check('PRIVATE KEY' not in out.stdout and 'PRIVATE KEY' not in out.stderr,
              'and prints no private key material')
        printed = re.search(r'public key \(RELEASE_KEYS entry\): (\S+)', out.stdout)
        check(printed is not None, 'it prints the RELEASE_KEYS entry')
        check('fingerprint:' in out.stdout and 'SHA256:' in out.stdout,
              'and the fingerprint that gets published')
        if printed:
            made = base64.b64decode((target / 'manifest.json.sig').read_text(encoding='utf-8').strip())
            check(cu.ed25519_verify(base64.b64decode(printed.group(1)), made, before),
                  'the signature the signer wrote verifies with the client verifier')
        out = subprocess.run([sys.executable, str(SIGN_TOOL), '--key', str(real),
                              '--manifest', str(target / 'manifest.json'), '--openssl', signer_openssl],
                             capture_output=True, text=True, encoding='utf-8', errors='replace')
        check(out.returncode != 0 and 'already exists' in out.stderr,
              'it will not overwrite an existing signature without --force')
        reformatted = target / 'reformatted.json'
        reformatted.write_text(json.dumps(json.loads(before.decode())), encoding='utf-8')
        out = subprocess.run([sys.executable, str(SIGN_TOOL), '--key', str(real),
                              '--manifest', str(reformatted), '--openssl', signer_openssl],
                             capture_output=True, text=True, encoding='utf-8', errors='replace')
        check(out.returncode != 0 and 'canonical' in out.stderr,
              'it refuses a manifest that has been reformatted since it was built')
        foreign = target / 'foreign.json'
        foreign.write_text('{"product": "something-else"}\n', encoding='utf-8')
        out = subprocess.run([sys.executable, str(SIGN_TOOL), '--key', str(real),
                              '--manifest', str(foreign), '--openssl', signer_openssl],
                             capture_output=True, text=True, encoding='utf-8', errors='replace')
        check(out.returncode != 0 and 'not a CONVERGE release manifest' in out.stderr,
              'it refuses to sign a document that is not a CONVERGE release manifest')
    else:
        print('  SKIP the signer against a real key: no openssl here supports Ed25519 -rawin '
              '(macOS ships LibreSSL as `openssl`; brew install openssl@3 provides one)')

    # ---- one trust root -----------------------------------------------------------------------
    print('one trust root, install time and update time')
    installer = (AGENT / 'install.sh').read_text(encoding='utf-8')
    pinned_here = re.search(r'^RELEASE_KEY="\$\{CONVERGE_RELEASE_KEY-(.*)\}"$', installer, re.M)
    check(pinned_here is not None, 'install.sh carries a RELEASE_KEY of its own')
    installer_key = pinned_here.group(1) if pinned_here else None
    check(list(cu.RELEASE_KEYS)[:1] == ([installer_key] if installer_key else []),
          'install.sh and converge-update.py pin the same key (or both pin none)')
    for key in cu.RELEASE_KEYS:
        raw = None
        try:
            raw = base64.b64decode(key, validate=True)
        except Exception:
            pass
        check(raw is not None and len(raw) == 32, 'RELEASE_KEYS entry is a raw 32-byte key')
        check(raw != bytes(32), 'RELEASE_KEYS entry is not an all-zero placeholder')
        # Thirty-two bytes is not the same as a key. This one has to decode to a point on the
        # curve, or every signature check against it would fail for a reason nobody could see.
        check(raw is not None and cu._decode_point(raw) is not None,
              'RELEASE_KEYS entry decodes to a point on the curve')
        digest = hashlib.sha256(raw).hexdigest()
        print('  pinned key fingerprint: SHA256:%s'
              % ' '.join(digest[i:i + 8] for i in range(0, 64, 8)))
    check('RELEASE_KEY' in installer and 'not installing' in installer,
          'install.sh fails closed on a signature it cannot verify')
    for phrase in ('could not fetch the release manifest', 'carries no manifest signature',
                   'does not verify against the CONVERGE release key'):
        check(phrase in installer, 'install.sh refuses: %s' % phrase)

    # The installer's verifier and the updater's must agree, because they are what stands
    # between a user and a substituted release at the two moments it matters.
    with tempfile.TemporaryDirectory(prefix='converge-installer-verify-') as verify_dir:
        vectors = [(public, signature, body, True),
                   (public, signature, body + b' ', False),
                   (other, signature, body, False),
                   (public, signature[:32] + bytes(32), body, False),
                   (public, sign(bytes(range(1, 33)), body), body, False)]
        agreed = all(installer_verify(Path(verify_dir), installer, k, s, m) == cu.ed25519_verify(k, s, m)
                     and cu.ed25519_verify(k, s, m) == want
                     for k, s, m, want in vectors)
    check(agreed, "install.sh's verifier answers exactly as converge-update.py's does")

    # ---- CI cannot sign -------------------------------------------------------------------------
    print('the release workflow')
    workflow = (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8')
    check('CONVERGE_SIGNING_KEY' not in workflow, 'the workflow never names a signing key')
    check('secrets.' not in workflow, 'the workflow reads no repository secret at all')
    check('draft: true' in workflow, 'the workflow creates a draft')
    check('draft: false' not in workflow, 'and nothing in it publishes one')
    check('--complete' in workflow, 'the workflow builds the manifest with --complete')
    check('fail-fast: true' in workflow, 'one platform failing fails the release')
    check('safety-check.py' in workflow, 'the workflow runs the publication-safety check')
    check('release-test.py' in workflow, 'and this file')
    for platform in PLATFORMS:
        check(platform in workflow, 'the workflow builds %s' % platform)
    # Naming the signer in a comment is how the workflow explains what it does not do; the
    # check is that no step actually runs it.
    steps = '\n'.join(line for line in workflow.split('\n') if not line.lstrip().startswith('#'))
    check('sign-manifest.py' not in steps,
          'no step runs the signer: signing is the owner\'s, offline')
    # The only openssl a release job installs is the one macOS needs to build against, and the
    # only one it mentions otherwise is in the release notes, telling a reader how to check the
    # signature for themselves.
    check('genpkey' not in workflow and 'pkeyutl -sign' not in workflow,
          'and no step makes or uses a private key')


def verify(dist, key):
    return subprocess.run([sys.executable, str(VERIFY_TOOL),
                           '--manifest', str(dist / 'manifest.json'),
                           '--signature', str(dist / 'manifest.json.sig'),
                           '--key', key, '--dist', str(dist)],
                          capture_output=True, text=True, encoding='utf-8', errors='replace')


def installer_verify(scratch, installer, public, signature, message):
    """Run install.sh's own signature check, in isolation, over bytes chosen here. The function
    is extracted from the shipped script rather than reimplemented, so what is tested is what
    users run."""
    (scratch / 'manifest.json').write_bytes(message)
    (scratch / 'manifest.json.sig').write_text(base64.b64encode(signature).decode() + '\n',
                                               encoding='utf-8')
    body = installer.split('verify_signature() {', 1)[1]
    depth, end = 1, 0
    for index, character in enumerate(body):
        if character == '{':
            depth += 1
        elif character == '}':
            depth -= 1
            if depth == 0:
                end = index
                break
    script = 'TMP=%s\nverify_signature() {%s}\nverify_signature "$1"\n' % (
        shell_quote(str(scratch)), body[:end])
    done = subprocess.run(['sh', '-c', script, 'converge', base64.b64encode(public).decode()],
                          capture_output=True)
    return done.returncode == 0


def shell_quote(text):
    return "'" + text.replace("'", "'\\''") + "'"


def ed25519_openssl(scratch):
    """An openssl that can sign the way a CONVERGE release is signed, or None. Ed25519 signs a
    message whole rather than a digest of it, which openssl spells `-rawin`, and the first
    `openssl` on PATH is not always the one that can do it."""
    candidates = ['openssl']
    for prefix in ('/opt/homebrew/opt/openssl@3/bin', '/usr/local/opt/openssl@3/bin', '/usr/bin'):
        candidates.append(str(Path(prefix) / 'openssl'))
    message = scratch / '.probe'
    message.write_bytes(b'probe')
    for exe in candidates:
        if not shutil.which(exe):
            continue
        try:
            key = scratch / '.probe.pem'
            subprocess.run([exe, 'genpkey', '-algorithm', 'ed25519', '-out', str(key)],
                           check=True, capture_output=True)
            subprocess.run([exe, 'pkeyutl', '-sign', '-inkey', str(key), '-rawin',
                            '-in', str(message), '-out', str(scratch / '.probe.sig')],
                           check=True, capture_output=True)
            return exe
        except (OSError, subprocess.CalledProcessError):
            continue
    return None


if __name__ == '__main__':
    sys.exit(main())
