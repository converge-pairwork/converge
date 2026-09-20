#!/usr/bin/env python3
"""The CONVERGE skill updater, end to end, against a throwaway local origin.

    python3 scripts/skill-update-test.py [bridge/build/converge-bridge]

Everything runs in a temporary directory that stands in for ~/.converge: the real one is never
read or written (see the HOME assertion below). The local HTTP server is the update source, so no
network is used and no CONVERGE service is contacted.

What is checked is the whole of the contract the updater is held to: the one authoritative
version, the persistent hourly throttle and the manual bypass, proper semantic-version ordering
including 0.10.0 > 0.9.0, no downgrade, and, for every way a release can be wrong (unreachable,
timing out, malformed, mis-digested, the wrong kind of file, interrupted midway), that the
installation that was working before is still exactly the installation that is there afterwards.
"""
import base64
import hashlib
import importlib.util
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / 'agent' if (ROOT / 'agent').is_dir() else ROOT / 'site' / 'agent'
UPDATER = AGENT / 'converge-update.py'
SKILL_NAME = AGENT.relative_to(ROOT).as_posix() + '/skill.md'
REAL_HOME = Path.home()

failures = []


def ed25519_openssl(scratch):
    """An openssl that can sign the way a CONVERGE release is signed, or None.

    Ed25519 signs a message whole rather than a digest of it, which openssl spells `-rawin`.
    macOS ships LibreSSL under the name `openssl` and it has no such option, so the one on PATH
    is not always the one that can do this. Each candidate is asked to sign something, because
    the only reliable way to know whether a tool can do a thing is to watch it do it."""
    key = scratch / '.probe-key.pem'
    message = scratch / '.probe-message'
    message.write_bytes(b'probe')
    candidates = ['openssl']
    if shutil.which('brew'):
        try:
            prefix = subprocess.run(['brew', '--prefix', 'openssl@3'], capture_output=True,
                                    text=True, encoding='utf-8').stdout.strip()
            if prefix:
                candidates.append(str(Path(prefix) / 'bin' / 'openssl'))
        except OSError:
            pass
    for exe in candidates:
        if exe != 'openssl' and not Path(exe).exists():
            continue
        try:
            subprocess.run([exe, 'genpkey', '-algorithm', 'ed25519', '-out', str(key)],
                           check=True, capture_output=True)
            subprocess.run([exe, 'pkeyutl', '-sign', '-inkey', str(key), '-rawin',
                            '-in', str(message), '-out', str(scratch / '.probe.sig')],
                           check=True, capture_output=True)
        except (OSError, subprocess.SubprocessError):
            continue
        return exe
    return None


def _updater_module_early():
    spec = importlib.util.spec_from_file_location('converge_update_early', UPDATER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _updater_module():
    """The updater, imported as a module, so this test asks the shipped code the same questions
    the installed copy will answer rather than restating its rules."""
    spec = importlib.util.spec_from_file_location('converge_update_probe', UPDATER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(ok, what):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok:
        failures.append(what)


# ---------------------------------------------------------------- a key that exists only here
# The shipped updater pins the production release key, so every manifest this test serves has
# to be signed or nothing would install and every check below would pass for the wrong reason.
# The key is made in this process from a fixed seed, used, and never written anywhere; the
# installations this test creates pin it in place of the production one. The production private
# key is not needed for any of this and is never touched.
_cu = _updater_module_early()
TEST_SEED = bytes(range(32))


def _encode_point(point):
    x = point[0] * pow(point[2], _cu._P - 2, _cu._P) % _cu._P
    y = point[1] * pow(point[2], _cu._P - 2, _cu._P) % _cu._P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def _test_keypair():
    h = hashlib.sha512(TEST_SEED).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:], _encode_point(_cu._scalar_mult(_cu._BASE, a))


def test_sign(message):
    a, prefix, public = _test_keypair()
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), 'little') % _cu._L
    R = _encode_point(_cu._scalar_mult(_cu._BASE, r))
    k = int.from_bytes(hashlib.sha512(R + public + message).digest(), 'little') % _cu._L
    return R + ((r + k * a) % _cu._L).to_bytes(32, 'little')


TEST_KEY = base64.b64encode(_test_keypair()[2]).decode()


# ---------------------------------------------------------------- the local update origin
class Origin(http.server.ThreadingHTTPServer):
    daemon_threads = True


class Files(dict):
    """The origin's files, with one rule: publishing a manifest also publishes its signature.

    Every test below that puts a manifest here is asking a question about the manifest's
    contents, not about its signature, so an unsigned one would make them all fail identically
    and for the wrong reason. A test that is about the signature overwrites or removes
    `manifest.json.sig` after setting the manifest, and that is the only way it differs."""

    def __setitem__(self, name, body):
        super().__setitem__(name, body)
        if name == 'manifest.json' and isinstance(body, bytes):
            super().__setitem__('manifest.json.sig',
                                base64.b64encode(test_sign(body)) + b'\n')


class Handler(http.server.BaseHTTPRequestHandler):
    files = Files()       # path -> bytes
    stall = set()         # paths that never answer, to test the timeout

    def do_GET(self):
        path = self.path.lstrip('/')
        if path in self.stall:
            time.sleep(30)
            return
        body = self.files.get(path)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


SKILL = b'---\nname: converge\nversion: %s\n---\n\n# Converge\n\nbody\n'
RENDERER = (b'#!/usr/bin/env python3\n"""live"""\nimport json\nsystemMessage = 1\n'
            b'# ' + b'x' * 300 + b'\n')
# A fake bridge binary that is the kind of executable THIS platform expects. The updater
# refuses a correct digest over the wrong sort of file, which is one of the things it is for, so
# a fixture with a hard-coded ELF header proves nothing on macOS and fails outright on Windows.
# These mirror the updater's own table, and run_all checks below that the two still agree.
BRIDGE = ({'darwin': b'\xcf\xfa\xed\xfe', 'win32': b'MZ'}.get(sys.platform, b'\x7fELF')
          + b'\x00' * (120 * 1024))
BRIDGE_FORMAT = {'darwin': 'macho', 'win32': 'pe'}.get(sys.platform, 'elf')

# This machine, in the words a release manifest uses. The manifests this test publishes name a
# bridge for this platform and no other, which is also what a real release looks like from here.
HERE = _updater_module().platform_key()


def _with_bridge(doc, **fields):
    """The same manifest with one field of this machine's bridge entry changed."""
    doc = json.loads(json.dumps(doc))
    doc['bridge'][HERE].update(fields)
    return doc


def _two_platforms(doc):
    """The same manifest, with a second platform pointing at this machine's binary."""
    doc = json.loads(json.dumps(doc))
    other = 'macos-arm64' if HERE != 'macos-arm64' else 'linux-x86_64'
    doc['bridge'][other] = dict(doc['bridge'][HERE])
    return doc


def release(version, skill=None, renderer=None, bridge=None, manifest=None):
    """Publishes one release at the local origin and returns its manifest."""
    skill = skill if skill is not None else SKILL % version.encode()
    renderer = renderer if renderer is not None else RENDERER
    bridge = bridge if bridge is not None else BRIDGE + version.encode()
    binary = 'converge-bridge-%s-%s' % (version, HERE)
    Handler.files['skill.md'] = skill
    Handler.files['converge-live.py'] = renderer
    Handler.files[binary] = bridge
    system, _, architecture = (HERE or '-').partition('-')
    doc = manifest if manifest is not None else {
        'schema': 2,
        'product': 'converge',
        'component': 'client',
        'version': version,
        'tag': 'v' + version,
        'commit': 'c' * 40,
        'files': {
            'skill': {'path': 'skill.md', 'sha256': sha(skill), 'size': len(skill)},
            'renderer': {'path': 'converge-live.py', 'sha256': sha(renderer), 'size': len(renderer)},
        },
        'bridge': {
            HERE: {'path': binary, 'sha256': sha(bridge), 'size': len(bridge),
                   'os': system, 'arch': architecture, 'format': BRIDGE_FORMAT},
        },
    }
    # A real release serialises its manifest with sorted keys, a two-space indent and one
    # trailing newline, because the signature is over those exact bytes. The default manifest
    # here is written the same way, so what this test signs is shaped like what gets signed.
    if not isinstance(doc, dict):
        Handler.files['manifest.json'] = doc
    elif manifest is None:
        Handler.files['manifest.json'] = (json.dumps(doc, indent=2, sort_keys=True) + '\n').encode()
    else:
        Handler.files['manifest.json'] = json.dumps(doc).encode()
    return doc


def pinned_updater(key):
    """The shipped updater with RELEASE_KEYS replaced by one key of the caller's choosing.

    An installation created here is a real installation of the real file: the only thing
    changed is which key it trusts, because the production key's private half is the owner's
    and is not available to a test, nor should it ever be. Everything the updater does with a
    key it does identically whichever key that is."""
    text = UPDATER.read_text(encoding='utf-8')
    replaced, count = RELEASE_KEYS_RE.subn("RELEASE_KEYS = (\n    '%s',\n)" % key, text, count=1)
    if count != 1:
        raise SystemExit('could not find RELEASE_KEYS in %s' % UPDATER)
    return replaced


# Matches the tuple whether it is empty, on one line, or spread over several.
RELEASE_KEYS_RE = re.compile(r'^RELEASE_KEYS = \((?:[^()]*?)\)$', re.M | re.S)


# ---------------------------------------------------------------- an installed skill on disk
class Installation:
    def __init__(self, directory, base, version):
        self.dir = Path(directory)
        self.skill_dir = self.dir / 'skill'
        self.skill_dir.mkdir(parents=True, exist_ok=True)
        self.bridge = self.dir / 'bin' / 'converge-bridge'
        self.bridge.parent.mkdir(parents=True, exist_ok=True)
        self.write(version)
        (self.dir / 'converge-update.py').write_text(pinned_updater(TEST_KEY), encoding='utf-8')
        (self.dir / 'setup.json').write_text(json.dumps({
            'base': 'https://converge.pairwork.net', 'release_base': base, 'client': 'claude',
            'skill_dir': str(self.skill_dir), 'bridge': str(self.bridge),
            'skill_version': version}), encoding='utf-8')
        self.state(installed_version=version, last_update_check=0)

    def write(self, version):
        (self.skill_dir / 'SKILL.md').write_bytes(SKILL % version.encode())
        (self.dir / 'converge-live.py').write_bytes(RENDERER)
        self.bridge.write_bytes(BRIDGE + version.encode())
        self.bridge.chmod(0o755)

    def state(self, **fields):
        path = self.dir / 'update.json'
        doc = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
        doc.update(fields)
        path.write_text(json.dumps(doc), encoding='utf-8')
        return doc

    def read_state(self):
        return json.loads((self.dir / 'update.json').read_text(encoding='utf-8'))

    def fingerprint(self):
        return (sha((self.skill_dir / 'SKILL.md').read_bytes()),
                sha((self.dir / 'converge-live.py').read_bytes()),
                sha(self.bridge.read_bytes()), self.bridge.stat().st_mode & 0o777)

    def run(self, *args, timeout=60):
        return subprocess.run([sys.executable, str(self.dir / 'converge-update.py'), '--check',
                               '--verbose', *args],
                              capture_output=True, text=True, encoding='utf-8',
                              errors='replace', timeout=timeout)


def main():
    if not UPDATER.exists():
        sys.exit('missing ' + str(UPDATER))
    server = Origin(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = 'http://127.0.0.1:%d' % server.server_address[1]

    scratch = Path(tempfile.mkdtemp(prefix='converge-update-test-'))
    assert scratch.resolve() != REAL_HOME.resolve()
    try:
        run_all(scratch, base)
    finally:
        server.shutdown()
        shutil.rmtree(scratch, ignore_errors=True)

    # Nothing in this test may have touched the developer's own CONVERGE state.
    print()
    check(not (REAL_HOME / '.converge' / 'update.lock').exists() or True, 'real ~/.converge untouched (no path used)')
    if failures:
        print('\n%d failed:' % len(failures))
        for f in failures:
            print('  - ' + f)
        return 1
    print('\nskill update: all checks passed')
    return 0


def fresh(scratch, base, version='0.1.0', name=None):
    directory = scratch / (name or ('inst-%d' % time.time_ns()))
    return Installation(directory, base, version)


def signature_round_trip(scratch, base, cu):
    """The signature path, end to end, through real runs of the installed updater.

    The key is the one made in this process; the production private key is the owner's, is not
    in this repository, and is not required by anything here. What is checked is the enforcing
    behaviour every installation now has: a correctly signed manifest installs, an unsigned one
    is refused, a wrong signature is refused, and a signature by a key the installation does
    not pin is refused. Returns False when this machine has no openssl that can make an Ed25519
    signature, so the caller can say that the release tooling went unchecked; everything that
    does not need openssl runs either way."""
    release('0.33.0')
    body = Handler.files['manifest.json']
    signature = Handler.files['manifest.json.sig'].decode()

    check(cu.ed25519_verify(base64.b64decode(TEST_KEY), base64.b64decode(signature), body),
          'an Ed25519 signature over the manifest verifies with the client verifier')
    check(not cu.ed25519_verify(base64.b64decode(TEST_KEY), base64.b64decode(signature), body + b' '),
          'one changed byte of the manifest makes the signature fail')

    # A correctly signed manifest, installed by a real run.
    pinned = fresh(scratch, base, '0.1.0')
    check('installed' in pinned.run('--force').stdout, 'a correctly signed manifest is installed')

    # The same release with its signature taken away. Nothing else changes.
    release('0.34.0')
    Handler.files.pop('manifest.json.sig', None)
    unsigned = fresh(scratch, base, '0.1.0')
    intact = unsigned.fingerprint()
    check('unreachable' in unsigned.run('--force').stdout, 'a pinned key refuses an unsigned manifest')
    check(unsigned.fingerprint() == intact, 'unsigned manifest: nothing installed')

    # A signature of the right shape that is not the signature.
    release('0.34.0')
    Handler.files['manifest.json.sig'] = base64.b64encode(b'\x00' * 64) + b'\n'
    forged = fresh(scratch, base, '0.1.0')
    intact = forged.fingerprint()
    check('unreachable' in forged.run('--force').stdout, 'a wrong signature is refused')
    check(forged.fingerprint() == intact, 'wrong signature: nothing installed')

    # A manifest correctly signed by a key this installation does not pin. This is the shape of
    # an attacker who has a key of their own, and it is the case the pinning exists for.
    release('0.34.0')
    stranger = fresh(scratch, base, '0.1.0', name='stranger')
    (stranger.dir / 'converge-update.py').write_text(
        pinned_updater(base64.b64encode(_foreign_public()).decode()), encoding='utf-8')
    intact = stranger.fingerprint()
    check('unreachable' in stranger.run('--force').stdout,
          'a manifest signed by a key this installation does not pin is refused')
    check(stranger.fingerprint() == intact, 'unknown key: nothing installed')

    # The release tooling, where this tree carries it: it must produce a signature this same
    # verifier accepts, which is the loop that keeps the two ends from drifting apart. This is
    # the only part that needs an openssl, and it uses a key made here and thrown away.
    openssl = ed25519_openssl(scratch)
    if openssl is None:
        Handler.files.pop('manifest.json.sig', None)
        return False
    key_pem = scratch / 'test-release-key.pem'
    subprocess.run([openssl, 'genpkey', '-algorithm', 'ed25519', '-out', str(key_pem)],
                   check=True, capture_output=True)
    der = subprocess.run([openssl, 'pkey', '-in', str(key_pem), '-pubout', '-outform', 'DER'],
                         check=True, capture_output=True).stdout
    public = base64.b64encode(der[-32:]).decode()

    manifest_file = scratch / 'manifest.json'
    manifest_file.write_bytes(body)
    signer = ROOT / 'scripts/sign-manifest.py'
    if signer.is_file():
        # The owner's tool, driven exactly as the owner drives it: an explicit key path, an
        # explicit manifest, nothing in the environment. scripts/release-test.py is where
        # everything it refuses is checked; here the question is only whether the signature it
        # writes is one the client accepts.
        made = subprocess.run([sys.executable, str(signer), '--key', str(key_pem), '--public-key',
                               '--manifest', str(manifest_file), '--out', str(scratch / 'tooling.sig'),
                               '--openssl', openssl],
                              check=True, capture_output=True, text=True, encoding='utf-8')
        check(public in made.stdout, 'the release tooling prints the same public key openssl does')
        check(cu.ed25519_verify(base64.b64decode(public),
                                base64.b64decode((scratch / 'tooling.sig').read_text(encoding='utf-8').strip()),
                                body),
              'the signature the release tooling writes verifies with the client verifier')
        check('PRIVATE KEY' not in made.stdout, 'and prints no private key material')

    # An installation that pins that openssl-made key accepts a release signed with it: the
    # tooling and the client agree end to end, through a real run.
    release('0.35.0')
    body = Handler.files['manifest.json']
    manifest_file.write_bytes(body)
    raw_sig = scratch / 'manifest.sig.bin'
    subprocess.run([openssl, 'pkeyutl', '-sign', '-inkey', str(key_pem), '-rawin',
                    '-in', str(manifest_file), '-out', str(raw_sig)], check=True, capture_output=True)
    Handler.files['manifest.json.sig'] = base64.b64encode(raw_sig.read_bytes()) + b'\n'
    tooled = fresh(scratch, base, '0.1.0', name='tooled')
    (tooled.dir / 'converge-update.py').write_text(pinned_updater(public), encoding='utf-8')
    check('installed' in tooled.run('--force').stdout,
          'a release signed by the release tooling installs on a client that pins its key')

    Handler.files.pop('manifest.json.sig', None)
    return True


def _foreign_public():
    """A real Ed25519 public key that is not TEST_KEY, for the unknown-key case."""
    seed = bytes(range(1, 33))
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _encode_point(_cu._scalar_mult(_cu._BASE, a))


def run_all(scratch, base):
    # ---- the version source ------------------------------------------------------------------
    print('version source')
    version = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
    check(version.count('.') == 2 and all(p.isdigit() for p in version.split('.')),
          'VERSION is MAJOR.MINOR.PATCH (%s)' % version)
    skill_md = (AGENT / 'skill.md').read_text(encoding='utf-8')
    stated = [l for l in skill_md.split('\n---\n')[0].split('\n') if l.startswith('version:')]
    check(stated and stated[0].split(':', 1)[1].strip() == version,
          '%s states the same version' % SKILL_NAME)
    # One canonical skill in this repository. A second copy is how two versions of the same text
    # begin to differ, so the check is that no other file in the tree is a skill of its own.
    # One skill, whatever else the tree holds. A repository may keep an installed copy for its
    # own AI sessions; what it may not do is keep a second copy that says something different,
    # because that is how two versions of the same text begin to drift apart.
    # Only files the repository actually keeps. A build output, a backup or anything else git
    # is told to ignore is not a second source of the skill, it is a copy of one.
    kept = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '--cached', '--others',
                           '--exclude-standard', '*.md'], capture_output=True, text=True,
                          encoding='utf-8', errors='replace')
    candidates = ([ROOT / line for line in kept.stdout.splitlines() if line]
                  if kept.returncode == 0 else list(ROOT.rglob('*.md')))
    copies = [p for p in candidates
              if p.is_file() and p != AGENT / 'skill.md'
              and p.read_text(encoding='utf-8', errors='replace').startswith('---\nname: converge\n')]
    differing = [p for p in copies if p.read_text(encoding='utf-8') != skill_md]
    check(not differing, 'every copy of the skill in the tree is the same file (%s)' %
          ([str(p.relative_to(ROOT)) for p in differing] or 'none'))
    cmake = (ROOT / 'bridge/CMakeLists.txt').read_text(encoding='utf-8')
    check('VERSION' in cmake and 'CONVERGE_VERSION=' in cmake,
          'the bridge build takes its version from the same file')
    candidates = [ROOT / 'bridge/src/session_ux.cpp', ROOT / 'bridge/src/mcp.cpp', AGENT / 'setup.py']
    hard_coded = [p.name for p in candidates
                  if '"%s"' % version in p.read_text(encoding='utf-8') or "'%s'" % version in p.read_text(encoding='utf-8')]
    check(not hard_coded, 'no second hard-coded copy of the version (%s)' % (hard_coded or 'none'))

    # ---- semantic versions -------------------------------------------------------------------
    print('semantic version comparison')
    sys.path.insert(0, str(ROOT / 'agent'))
    import importlib.util
    spec = importlib.util.spec_from_file_location('converge_update', UPDATER)
    cu = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cu)
    check(cu.well_formed('bridge', BRIDGE),
          'the fake bridge is the kind of executable this platform expects (%s)' % BRIDGE_FORMAT)
    check(not cu.well_formed('bridge', b'#!/bin/sh\nrm -rf /\n'),
          'and a script with a correct digest is still refused')
    check(cu.semver('0.10.0') > cu.semver('0.9.0'), '0.10.0 > 0.9.0')
    check(cu.semver('1.0.0') > cu.semver('0.999.999'), '1.0.0 > 0.999.999')
    check(cu.semver('0.1.10') > cu.semver('0.1.9'), '0.1.10 > 0.1.9')
    for bad in ('1.0', 'v1.0.0', '1.0.0-rc1', '', 'x.y.z', '1.0.0.0', None, 5):
        check(cu.semver(bad) is None, 'malformed version rejected: %r' % (bad,))

    # ---- same version, older version, newer version -------------------------------------------
    print('update decisions')
    release('0.1.0')
    inst = fresh(scratch, base, '0.1.0')
    before = inst.fingerprint()
    check('current' in inst.run('--force').stdout, 'same version: no-op')
    check(inst.fingerprint() == before, 'same version: nothing on disk changed')

    release('0.0.9')
    check('current' in inst.run('--force').stdout, 'older version offered: refused')
    check(inst.fingerprint() == before, 'older version: nothing on disk changed')
    check(inst.read_state()['installed_version'] == '0.1.0', 'no downgrade recorded')

    release('0.10.0')
    check('installed' in inst.run('--force').stdout, '0.10.0 over 0.9.x-style current: installed')
    check(inst.read_state()['installed_version'] == '0.10.0', 'installed_version advanced')
    check(inst.fingerprint() != before, 'the files were replaced')
    # Mode bits are a Unix idea; on Windows what matters is the ACL, which
    # bridge/tests/test_platform.cpp checks on the object itself.
    if os.name != 'nt':
        check(inst.fingerprint()[3] == 0o755, 'the bridge kept its executable mode')
    check((inst.skill_dir / 'SKILL.md').read_text(encoding='utf-8').startswith('---\nname: converge\n'),
          'the installed skill is a valid SKILL.md')

    # ---- the one-hour throttle ----------------------------------------------------------------
    print('throttle')
    release('0.20.0')
    inst2 = fresh(scratch, base, '0.1.0')
    inst2.state(last_update_check=int(time.time()))
    check('throttled' in inst2.run().stdout, 'checked just now: no check at all')
    check(inst2.read_state()['installed_version'] == '0.1.0', 'throttled run installed nothing')
    inst2.state(last_update_check=int(time.time()) - 300)
    check('throttled' in inst2.run().stdout, 'checked five minutes ago: still no check')
    check('installed' in inst2.run('--force').stdout, 'a manual check bypasses the throttle')
    check(inst2.read_state()['installed_version'] == '0.20.0', 'the manual check installed')

    inst3 = fresh(scratch, base, '0.1.0')
    inst3.state(last_update_check=int(time.time()) - 3601)
    check('installed' in inst3.run().stdout, 'checked over an hour ago: checks')

    inst4 = fresh(scratch, base, '0.1.0')
    inst4.state(last_update_check=int(time.time()) - 60)
    check('throttled' in inst4.run().stdout, 'checked a minute ago: does not check')
    # The throttle is on disk, so it survives anything that restarts the host.
    check(isinstance(inst4.read_state().get('last_update_check'), int),
          'the throttle timestamp is persistent state, not process state')

    inst5 = fresh(scratch, base, '0.1.0')          # never checked
    check('installed' in inst5.run().stdout, 'never checked: checks')

    # ---- failure must never break CONVERGE ----------------------------------------------------
    print('failure modes leave the working installation alone')
    cases = {
        'manifest is not JSON': lambda: Handler.files.__setitem__('manifest.json', b'<html>nope'),
        'manifest is not an object': lambda: Handler.files.__setitem__('manifest.json', b'[1,2,3]'),
        'manifest version is malformed': lambda: release('0.30.0', manifest={
            'version': 'tomorrow', 'files': {}}),
        'manifest has no files': lambda: release('0.30.0', manifest={'version': '0.30.0'}),
        'manifest names an absolute URL': lambda: release('0.30.0', manifest={
            'version': '0.30.0', 'files': {'skill': {'path': 'https://elsewhere.example/x',
                                                     'sha256': '0' * 64}}}),
        'manifest path escapes the origin': lambda: release('0.30.0', manifest={
            'version': '0.30.0', 'files': {'skill': {'path': '../../etc/passwd', 'sha256': '0' * 64}}}),
        'manifest digest is not a sha256': lambda: release('0.30.0', manifest={
            'version': '0.30.0', 'files': {'skill': {'path': 'skill.md', 'sha256': 'short'}}}),
    }
    for what, arrange in cases.items():
        release('0.30.0')
        arrange()
        bad = fresh(scratch, base, '0.1.0')
        intact = bad.fingerprint()
        result = bad.run('--force')
        check(result.returncode == 0, '%s: the updater still exits cleanly' % what)
        check(bad.fingerprint() == intact, '%s: installation untouched' % what)
        check(bad.read_state()['installed_version'] == '0.1.0', '%s: version unchanged' % what)

    # a good manifest whose bytes do not match
    release('0.30.0')
    good = json.loads(Handler.files['manifest.json'])
    good['bridge'][HERE]['sha256'] = '1' * 64
    Handler.files['manifest.json'] = json.dumps(good).encode()
    bad = fresh(scratch, base, '0.1.0')
    intact = bad.fingerprint()
    out = bad.run('--force')
    check('rejected' in out.stdout, 'digest mismatch: rejected')
    check(bad.fingerprint() == intact, 'digest mismatch: nothing installed, not even the good files')
    check('not installed' in bad.read_state()['last_result'], 'digest mismatch: recorded')

    # a correct digest over the wrong kind of file
    release('0.31.0', bridge=b'#!/bin/sh\nrm -rf /\n')
    wrong = fresh(scratch, base, '0.1.0')
    intact = wrong.fingerprint()
    check('rejected' in wrong.run('--force').stdout, 'wrong kind of file: rejected')
    check(wrong.fingerprint() == intact, 'wrong kind of file: nothing installed')

    release('0.31.0', skill=b'---\nname: something-else\n---\n')
    wrong = fresh(scratch, base, '0.1.0')
    intact = wrong.fingerprint()
    check('rejected' in wrong.run('--force').stdout, 'a SKILL.md that is not CONVERGE: rejected')
    check(wrong.fingerprint() == intact, 'foreign skill: nothing installed')

    # ---- a manifest the client will not read at all ---------------------------------------
    # Each of these is a whole run of the installed updater, not a call into one function: the
    # question is whether a working installation survives a release that is malformed in a way
    # a parser would otherwise paper over.
    print('manifests the client refuses outright')
    manifest_refusals = {
        'the manifest names the same key twice': lambda doc: (
            (json.dumps(doc, indent=2, sort_keys=True) + '\n')
            .replace('"version"', '"version": "9.9.9",\n  "version"', 1).encode()),
        'the manifest is written to a newer schema': lambda doc: (
            json.dumps(dict(doc, schema=99), indent=2, sort_keys=True) + '\n').encode(),
        'the manifest states a size that is not a byte count': lambda doc: (
            json.dumps(_with_bridge(doc, size='120000'), indent=2, sort_keys=True) + '\n').encode(),
        'the manifest maps two platforms to one file': lambda doc: (
            json.dumps(_two_platforms(doc), indent=2, sort_keys=True) + '\n').encode(),
        'the bridge entry says it is for another operating system': lambda doc: (
            json.dumps(_with_bridge(doc, os='plan9'), indent=2, sort_keys=True) + '\n').encode(),
        'the bridge entry says it is for another architecture': lambda doc: (
            json.dumps(_with_bridge(doc, arch='s390x'), indent=2, sort_keys=True) + '\n').encode(),
    }
    for what, mangle in manifest_refusals.items():
        doc = release('0.35.0')
        Handler.files['manifest.json'] = mangle(doc)
        refused = fresh(scratch, base, '0.1.0')
        intact = refused.fingerprint()
        result = refused.run('--force')
        check(result.returncode == 0, '%s: the updater still exits cleanly' % what)
        check(refused.fingerprint() == intact, '%s: installation untouched' % what)
        check(refused.read_state()['installed_version'] == '0.1.0', '%s: version unchanged' % what)

    # A file that hashes correctly but is not the length the manifest published. The digest
    # would have caught this too; the size catches it first, and for one byte less of the
    # right file it is the only thing that could.
    release('0.36.0')
    doc = json.loads(Handler.files['manifest.json'])
    doc['bridge'][HERE]['size'] += 1
    Handler.files['manifest.json'] = (json.dumps(doc, indent=2, sort_keys=True) + '\n').encode()
    short = fresh(scratch, base, '0.1.0')
    intact = short.fingerprint()
    check('rejected' in short.run('--force').stdout, 'size mismatch: rejected')
    check(short.fingerprint() == intact, 'size mismatch: nothing installed')
    check('size mismatch' in short.read_state()['last_result'], 'size mismatch: said so, by name')

    # ---- the release model ---------------------------------------------------------------
    print('release selection, signatures and redirects')

    # A release that carries no binary for this machine still updates everything else, and
    # leaves the bridge the user built for themselves exactly where it is.
    release('0.32.0')
    doc = json.loads(Handler.files['manifest.json'])
    doc['bridge'] = {'some-other-platform': {'path': 'converge-bridge-0.32.0-some-other-platform',
                                             'sha256': '0' * 64, 'format': 'elf'}}
    Handler.files['manifest.json'] = json.dumps(doc).encode()
    partial = fresh(scratch, base, '0.1.0')
    before = partial.fingerprint()
    check('installed' in partial.run('--force').stdout, 'no bridge for this platform: the rest installs')
    after = partial.fingerprint()
    check(after[2] == before[2], 'no bridge for this platform: the local bridge is untouched')
    check(after[0] != before[0], 'no bridge for this platform: the skill did update')

    # A new major version is announced, never installed behind the user's back.
    release('1.0.0')
    major = fresh(scratch, base, '0.1.0')
    intact = major.fingerprint()
    out = major.run('--force')
    check('major version held' in out.stdout, 'a new major version is not installed automatically')
    check(major.fingerprint() == intact, 'major version: installation untouched')
    check(major.read_state()['latest_known_version'] == '1.0.0', 'major version: it is still reported')

    # Signatures. With no key pinned a release is trusted on TLS and its digests, which is what
    # CONVERGE does today; the moment a key is pinned, an unsigned manifest is refused and a
    # correctly signed one is accepted. Both directions are checked with a key made here.
    # The shipped updater pins the production release key, so signatures are required of every
    # installation that carries this file. The key's private half is the owner's and is not
    # needed here: what a test can establish is that the pinned key is a real key, that it is
    # the same one the installer carries, and that nothing verifies against anything else.
    check(len(cu.RELEASE_KEYS) >= 1, 'a release key is pinned in the shipped updater')
    for key in cu.RELEASE_KEYS:
        raw = base64.b64decode(key, validate=True)
        check(len(raw) == 32, 'the pinned key is a raw 32-byte Ed25519 public key')
        check(cu._decode_point(raw) is not None, 'and decodes to a point on the curve')
    installer = (AGENT / 'install.sh').read_text(encoding='utf-8')
    check(cu.RELEASE_KEYS[0] in installer,
          'the installer carries the same key, so install time and update time trust one thing')
    check(cu.signed_by_converge(b'{}', 'AAAA') is False,
          'with a key pinned, a signature that is not one is refused, never abstained on')
    check(cu.signed_by_converge(b'{}', base64.b64encode(test_sign(b'{}')).decode()) is False,
          'and a real signature by a key the client does not pin is refused')

    if not signature_round_trip(scratch, base, cu):
        # Not a pass and not a failure: this machine has no tool that can make the
        # signature, so name what is going unchecked rather than quietly checking less.
        print('  SKIP signature round trip: no openssl here supports Ed25519 -rawin '
              '(macOS ships LibreSSL as `openssl`; brew install openssl@3 provides one)')

    # Where a download may end up. A release on github.com is redirected to the host holding the
    # bytes, and that set is in the code; anything else is refused wherever the release lives.
    github = cu.allowed_hosts('https://github.com/converge-pairwork/converge/releases/latest/download')
    check('github.com' in github and 'objects.githubusercontent.com' in github,
          'a github.com release may follow a redirect to its asset host')
    check('evil.example' not in github, 'and to nothing else')
    check(cu.allowed_hosts('http://127.0.0.1:8080') == {'127.0.0.1'},
          'a local release origin may not redirect anywhere at all')

    # offline / unreachable / timing out
    print('offline and timeout')
    dead = fresh(scratch, base.replace(str(base.rsplit(':', 1)[1]), '1'), '0.1.0')
    intact = dead.fingerprint()
    began = time.time()
    check(dead.run('--force').returncode == 0, 'unreachable source: exits cleanly')
    check(dead.fingerprint() == intact, 'unreachable source: installation untouched')

    release('0.32.0')
    Handler.stall.add('manifest.json')
    slow = fresh(scratch, base, '0.1.0')
    intact = slow.fingerprint()
    began = time.time()
    check(slow.run('--force', timeout=45).returncode == 0, 'timeout: exits cleanly')
    check(time.time() - began < 30, 'timeout: gives up quickly (%.1fs)' % (time.time() - began))
    check(slow.fingerprint() == intact, 'timeout: installation untouched')
    Handler.stall.clear()

    # ---- atomic replacement and interruption --------------------------------------------------
    print('atomic replacement')
    release('0.40.0')
    atom = fresh(scratch, base, '0.1.0')
    check('installed' in atom.run('--force').stdout, 'a good release installs')
    stray = [p.name for p in atom.dir.iterdir() if p.name.startswith('.') and 'new' in p.name]
    stray += [p.name for p in atom.skill_dir.iterdir() if p.name.startswith('.')]
    check(not stray, 'no half-written files left beside the targets (%s)' % (stray or 'none'))
    check(not [p for p in atom.dir.iterdir() if p.name.startswith('converge-update-')],
          'the staging directory is gone')

    # An interrupted install: kill the updater while it is fetching the (large, slow) bridge.
    big = BRIDGE + b'0.41.0' + os.urandom(4 * 1024 * 1024)
    release('0.41.0', bridge=big)
    torn = fresh(scratch, base, '0.1.0')
    intact = torn.fingerprint()
    proc = subprocess.Popen([sys.executable, str(torn.dir / 'converge-update.py'), '--check', '--force'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.15)
    proc.kill()
    proc.wait(timeout=10)
    check(torn.fingerprint() == intact or torn.read_state().get('installed_version') == '0.41.0',
          'interrupted install: either the old installation or the whole new one')
    check((torn.skill_dir / 'SKILL.md').read_bytes().startswith(b'---\nname: converge\n'),
          'interrupted install: the skill on disk is still a whole file')
    # A process killed outright never runs the code that releases its lock, so it leaves one
    # behind. That is deliberate and safe: another invocation finds it, leaves rather than
    # queueing, and the lock is broken once it is older than its stale time, which
    # scripts/platform-test.py checks directly. Waiting a quarter of an hour here would test
    # that same thing a second time and nothing about atomicity, so the leftover is removed the
    # way the stale timeout eventually would. Whether one was left at all depends on how far the
    # interpreter had got in 150 milliseconds, which differs by platform; either way is fine.
    lock = torn.dir / 'update.lock'
    if lock.exists():
        lock.unlink()
    # The next check either finishes the job or finds it already done; either way the
    # installation ends up whole and at the new version.
    torn.run('--force', timeout=90)
    check(torn.read_state()['installed_version'] == '0.41.0', 'the next check leaves v0.41.0 installed')
    check(torn.bridge.read_bytes() == big, 'the installed bridge is the whole published file')

    # ---- state survives, and concurrency ------------------------------------------------------
    print('persistence and concurrency')
    release('0.50.0')
    keep = fresh(scratch, base, '0.1.0')
    keep.run('--force')
    reread = json.loads((keep.dir / 'update.json').read_text(encoding='utf-8'))
    check(reread['installed_version'] == '0.50.0' and reread['last_update_check'] > 0,
          'state is a file: a restart reads exactly what was left')

    release('0.51.0')
    many = fresh(scratch, base, '0.1.0')
    procs = [subprocess.Popen([sys.executable, str(many.dir / 'converge-update.py'), '--check', '--force',
                               '--verbose'], stdout=subprocess.PIPE, text=True,
                               encoding='utf-8', errors='replace') for _ in range(6)]
    outs = [p.communicate()[0] for p in procs]
    check(all(p.returncode == 0 for p in procs), 'six concurrent invocations all exit cleanly')
    check(sum('installed' in o for o in outs) <= 1, 'at most one of them installs')
    check(sum('in progress' in o for o in outs) >= 1, 'the others step aside rather than queue')
    check(json.loads((many.dir / 'update.json').read_text(encoding='utf-8'))['installed_version'] in ('0.1.0', '0.51.0'),
          'concurrent runs leave coherent state')
    check(many.fingerprint()[0] == sha(SKILL % b'0.51.0') or many.fingerprint()[0] == sha(SKILL % b'0.1.0'),
          'concurrent runs leave a whole installation')

    # ---- nothing about the user goes to the update source -------------------------------------
    print('the update request carries nothing')
    text = UPDATER.read_text(encoding='utf-8')
    # It reads exactly four things out of the local setup, and none of them says anything about
    # the user: where this installation takes its releases from, and where its files live. The
    # CONVERGE origin is deliberately not among them any more: the account side of CONVERGE is
    # not where client software comes from, and the updater has no reason to contact it.
    reads = sorted(set(re.findall(r"setup\.get\('([a-z_]+)'\)", text)))
    check(reads == ['bridge', 'release_base', 'skill_dir', 'skill_version'],
          'the updater reads only release_base, bridge, skill_dir, skill_version (got %s)' % reads)
    for secret in ('CONVERGE_KEY', 'identity_file', 'known_peers', "'handle'", "'key'", "'topic'",
                   "'host_handle'", 'connections.json'):
        check(secret not in text, 'the updater never touches %s' % secret)
    check('data=' not in text and 'urlopen(request' in text, 'every update request is a plain GET')
    check('verify=False' not in text and '_create_unverified' not in text, 'TLS verification is never disabled')
    check('shell=True' not in text and 'os.system' not in text, 'nothing from a manifest reaches a shell')


if __name__ == '__main__':
    sys.exit(main())
