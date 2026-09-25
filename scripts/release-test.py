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
    one trust root, not two                the installers verify nothing themselves: they hand
                                           the download to `converge-bridge verify-release`,
                                           and the bridge pins the key (release_key.hpp)
    no placeholder is trusted              every pinned key is a real 32-byte key or there are
                                           none at all
    CI cannot sign                         the release workflow refers to no signing key, and
                                           drafts rather than publishes
    CI cannot overwrite a publication      the guard refuses a tag whose release is already
                                           published, and refuses when it cannot find out

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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ed25519  # noqa: E402

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


# ---------------------------------------------------------------- a key that exists only here
# Signing, with the same arithmetic the release tooling verifies with (scripts/ed25519.py).
# Making the key in this process means no key file is ever written, nothing has to be cleaned
# up, and the test does not depend on which openssl this machine calls `openssl`.
keypair = ed25519.keypair
sign = ed25519.sign


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
    for name in ('converge-live.py', 'install.sh', 'install.ps1'):
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
          'install.sh' in manifest['extra'] and 'install.ps1' in manifest['extra'],
          'the installers and the source tarball are covered too')
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

    # What the client refuses to read (a duplicate key, a newer schema, two platforms on one
    # file, an entry filed under the wrong machine, a size that is not a byte count) is asked of
    # the bridge itself, through real update runs, in scripts/skill-update-test.py.

    # ---- signatures ---------------------------------------------------------------------------
    print('signatures')
    seed = bytes(range(32))
    _, _, public = keypair(seed)
    public_b64 = base64.b64encode(public).decode()
    signature = sign(seed, body)
    signature_text = base64.b64encode(signature).decode() + '\n'

    check(ed25519.verify(public, signature, body),
          'a signature over the manifest verifies with the client verifier')
    check(not ed25519.verify(public, signature, body + b' '),
          'one byte appended to the manifest: refused')
    tampered = body.replace(b'"version"', b'"Version"', 1)
    check(tampered != body and not ed25519.verify(public, signature, tampered),
          'one byte changed inside the manifest: refused')
    check(not ed25519.verify(public, signature[:32] + bytes(32), body),
          'a signature with its scalar replaced: refused')
    _, _, other = keypair(bytes(range(1, 33)))
    check(not ed25519.verify(other, signature, body),
          'a good signature checked against a different key: refused')
    check(not ed25519.verify(public, sign(bytes(range(1, 33)), body), body),
          'a signature by a key nobody pinned: refused')

    # What the client says about a signature made by a key it does not pin. With the production
    # key pinned this must be a refusal, not an abstention: the throwaway key above is exactly
    # the shape of an attacker's key, and it signed this manifest correctly.
    verdict = ed25519.signed_by_converge(body, signature_text)
    if ed25519.release_keys():
        check(verdict is False,
              'a manifest signed by a key the client does not pin: refused, not abstained')
    else:
        check(verdict is None, 'with no key pinned, the client reports None, never True')
    for junk in ('', 'not base64!!', base64.b64encode(b'short').decode()):
        check(ed25519.signed_by_converge(body, junk) is not True,
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
    if ed25519.release_keys():
        check(out.returncode != 0 and 'verifies against a key pinned in the client' in out.stdout,
              'a release the pinned key did not sign: verification fails closed')
    else:
        check(out.returncode != 0 and 'none is' in out.stdout,
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
        printed = re.search(r'public key \(release_key.hpp entry\): (\S+)', out.stdout)
        check(printed is not None, 'it prints the release_key.hpp entry')
        check('fingerprint:' in out.stdout and 'SHA256:' in out.stdout,
              'and the fingerprint that gets published')
        if printed:
            made = base64.b64decode((target / 'manifest.json.sig').read_text(encoding='utf-8').strip())
            check(ed25519.verify(base64.b64decode(printed.group(1)), made, before),
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
    keys = ed25519.release_keys()
    check(len(keys) >= 1, 'the bridge pins a release key (bridge/src/release_key.hpp)')
    for key in keys:
        raw = None
        try:
            raw = base64.b64decode(key, validate=True)
        except Exception:
            pass
        check(raw is not None and len(raw) == 32, 'the pinned key is a raw 32-byte key')
        check(raw != bytes(32), 'the pinned key is not an all-zero placeholder')
        # Thirty-two bytes is not the same as a key. This one has to decode to a point on the
        # curve, or every signature check against it would fail for a reason nobody could see.
        check(raw is not None and ed25519.decode_point(raw) is not None,
              'the pinned key decodes to a point on the curve')
        digest = hashlib.sha256(raw).hexdigest()
        print('  pinned key fingerprint: SHA256:%s'
              % ' '.join(digest[i:i + 8] for i in range(0, 64, 8)))
    # The installers carry no key and no verifier: they check size and digest against the
    # manifest and then hand the download to the bridge, which verifies the signature against
    # the key compiled into it. There is one verifier and one key, in one place.
    for name in ('install.sh', 'install.ps1'):
        installer = (AGENT / name).read_text(encoding='utf-8')
        check('python3' not in installer.lower() and 'python ' not in installer.lower(), '%s needs no Python' % name)
        check('verify-release' in installer, '%s asks the bridge to verify the release' % name)
        check('RELEASE_KEY' not in installer, '%s carries no key of its own' % name)
        for phrase in ('could not fetch the release manifest', 'does not verify against the CONVERGE release key',
                       'not installing', 'checksum mismatch', 'size mismatch'):
            check(phrase in installer, '%s fails closed: %s' % (name, phrase))

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

    # A published release is the owner's signed statement about a set of bytes. The workflow
    # may fill a draft and may create one, and may not write to a release a person has already
    # published: on 2026-09-20 a moved tag started this workflow against the published v0.1.1
    # and replaced every asset but the signature, which left a manifest nobody had signed and
    # an installation base that refused the release. The guard is asked twice, because four
    # platform builds separate the first answer from the upload.
    check('release-guard.py' in workflow, 'the workflow asks the release guard')
    guard_steps = [line for line in steps.split('\n') if 'release-guard.py' in line]
    check(len(guard_steps) == 2,
          'and asks it twice: before the builds, and again before the upload')
    package = workflow.split('name: manifest and draft', 1)[1]
    before_upload = package.split('Draft the release', 1)[0]
    check('release-guard.py' in before_upload,
          'the second time is inside the job that uploads, ahead of the upload')

    print()
    print('the release guard')
    guard = ROOT / 'scripts/release-guard.py'
    check(guard.is_file(), 'scripts/release-guard.py exists')
    spec = importlib.util.spec_from_file_location('release_guard', guard)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    decide = module.decide

    check(decide(None)[0], 'no release for the tag: the draft may be created')
    check(decide({'draft': True, 'tag_name': tag})[0],
          'a draft release for the tag: CI may fill its own draft')
    refused, why = decide({'draft': False, 'tag_name': tag})
    check(not refused, 'a PUBLISHED release for the tag: refused')
    check('PUBLISHED' in why, 'and it says so plainly enough to read in a log')
    # Everything unreadable is refused rather than allowed. A guard that opens when it cannot
    # see is not a guard, and each of these is a shape a changed API could hand it.
    for bad, what in (({}, 'a record that does not say whether it is a draft'),
                      ({'draft': None}, 'a draft field of null'),
                      ({'draft': 'false'}, 'a draft field that is a string'),
                      ({'draft': 0}, 'a draft field that is a number'),
                      ([], 'a record that is not an object at all'),
                      ('published', 'a record that is a bare string')):
        check(not decide(bad)[0], 'refused: ' + what)

    # The same table, through the command line, since that is how the workflow reaches it.
    guarded = lambda payload: subprocess.run(
        [sys.executable, str(guard), '--tag', tag, '--release-json', '-'],
        input=payload, capture_output=True, text=True)
    check(guarded('none').returncode == 0, 'the command line allows a tag with no release')
    check(guarded('{"draft": true}').returncode == 0, 'and a draft')
    published = guarded('{"draft": false}')
    check(published.returncode != 0, 'and refuses a published release')
    check('release guard' in published.stderr, 'saying which guard refused it')
    check(guarded('not json at all').returncode != 0, 'and refuses a record it cannot parse')

    # The Linux release binary is built fully static, in an Alpine container, by one script that
    # a developer, ordinary CI's packaging job and the release all run. That job is the only thing
    # that exercises the recipe before a release day, so it has to be the same recipe: the same
    # script, the same architecture argument, and nothing installed on the runner for it.
    ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
    linux_build = 'scripts/build-static-linux.sh x86_64'
    check(linux_build in workflow and linux_build in ci, 'the release and ordinary CI build Linux with the one static script')
    check('libboost-dev' not in steps and 'libssl-dev' not in steps and 'ubuntu-toolchain-r' not in steps,
          'nothing is apt-installed for the Linux release: the container holds the whole toolchain')
    check('CONVERGE_BRIDGE_FULLY_STATIC=ON' in workflow and 'x64-windows-static' in workflow
          and 'build-static-openssl.sh' in workflow,
          'macOS and Windows link OpenSSL and the runtime statically')
    check('scripts/check-static.py "staged/$name"' in steps, 'every staged binary is proven self contained before upload')
    check('make dist PREBUILT=1' in ci, 'the packaging job packages the static binary rather than building another')
    static_script = (ROOT / 'scripts/build-static-linux.sh').read_text(encoding='utf-8')
    check('alpine:' in static_script and '-DCONVERGE_BRIDGE_FULLY_STATIC=ON' in static_script
          and 'check-static.py' in static_script, 'the Linux script builds in Alpine, fully static, and checks the result')
    openssl_script = (ROOT / 'scripts/build-static-openssl.sh').read_text(encoding='utf-8')
    check(re.search(r'^SHA256=[0-9a-f]{64}$', openssl_script, re.M) is not None and 'no-shared' in openssl_script,
          'the OpenSSL source is pinned by digest and built as archives only')
    # Whole-recipe equality for the Linux build step, not a list of things that happen to
    # appear in both. The `if:` guard is the one line that differs, because only one of them
    # runs on a matrix.
    def recipe(text, marker):
        body = text.split(marker, 1)[1].split('run: |', 1)[1]
        out = []
        for line in body.split('\n'):
            if line.strip() and not line.startswith('          '):
                break
            if line.strip() and not line.strip().startswith('#'):
                out.append(line.strip())
        return out
    check(recipe(workflow, 'Build (Linux, static, in a container)') == recipe(ci, 'Build, the way the release does'),
          'and the two recipes are the same recipe, line for line')


def verify(dist, key):
    return subprocess.run([sys.executable, str(VERIFY_TOOL),
                           '--manifest', str(dist / 'manifest.json'),
                           '--signature', str(dist / 'manifest.json.sig'),
                           '--key', key, '--dist', str(dist)],
                          capture_output=True, text=True, encoding='utf-8', errors='replace')


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
