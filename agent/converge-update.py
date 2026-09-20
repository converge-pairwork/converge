#!/usr/bin/env python3
"""CONVERGE skill updater. Runs beside the installed skill, never inside it.

The bridge starts this as its own short-lived process whenever CONVERGE is invoked, and never
waits for the outcome. That separation is the point: an update that cannot happen, for any reason
at all, is not a CONVERGE failure. This script therefore has exactly one obligation, which it
keeps even when everything else goes wrong: leave the known-good installation exactly as it was.

What it does, in order:
  1. take the update lock, or leave (another invocation is already on it)
  2. unless --force, stop if the last check was less than an hour ago
  3. fetch the release manifest over HTTPS, from the release source this installation uses
  4. verify the manifest's signature against a public key compiled into this file, when one is
     pinned; a manifest that carries a bad signature is refused outright
  5. compare versions properly; never install the same version again and never go backwards
  6. fetch each file the manifest names, by a name relative to that same release
  7. verify the SHA-256 the manifest states, then check the file is the kind of thing it claims,
     and that a bridge binary is the one built for this operating system and architecture
  8. stage everything in a scratch directory, and only then replace each target atomically
  9. record what happened in update.json

It has no third-party dependencies, and it sends nothing: no wallet, session, account or
negotiation material ever reaches the update source, and no value out of the manifest is ever
executed, expanded by a shell, or used as an origin of its own.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# Where releases come from. The public source repository publishes them, and that is the only
# thing this script ever downloads from: the CONVERGE service itself carries accounts, balances
# and negotiations, and has no business being the place a binary comes from as well.
DEFAULT_RELEASE = 'https://github.com/converge-pairwork/converge/releases/latest/download'
MANIFEST_PATH = 'manifest.json'
SIGNATURE_PATH = 'manifest.json.sig'
CHECK_INTERVAL = 3600                  # at most one automatic check an hour, persistently
TIMEOUT = 8                            # short: this must never hold anything up
MAX_MANIFEST = 256 * 1024
MAX_FILE = 64 * 1024 * 1024
WINDOWS = os.name == 'nt'

# The public halves of the keys a CONVERGE release manifest may be signed with, base64, newest
# first. They are here, in the code, and never taken from a manifest, a server or a setting:
# a key an attacker can supply is not a key.
#
# While this tuple is empty no signature is required, and a release is trusted on TLS to the
# release host plus the SHA-256 the manifest states, which is the model CONVERGE has today.
# Adding the first key here turns signature verification on for every installation that has
# this file, and from then on an unsigned or wrongly signed manifest is refused. Rotation is
# adding the new key in front and leaving the old one until installations have moved.
RELEASE_KEYS = ()

# A release download starts at the repository host and is redirected to wherever that host
# keeps its asset bytes. Following it is necessary; following it anywhere is not. These are the
# hosts a github.com release is allowed to end up on, and a redirect to anything else is an
# error rather than a download.
GITHUB_HOSTS = ('github.com', 'objects.githubusercontent.com',
                'release-assets.githubusercontent.com', 'raw.githubusercontent.com')
VERSION_RE = re.compile(r'\A(\d{1,9})\.(\d{1,9})\.(\d{1,9})\Z')
SHA_RE = re.compile(r'\A[0-9a-f]{64}\Z')
# A manifest names files by a path under the release, never by a URL: the release source is the
# one this installation was set up with, and the manifest cannot move it.
PATH_RE = re.compile(r'\A[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*\Z')

# What may be updated, and what each file has to look like before it replaces anything. The keys
# are the manifest's; the target comes from setup.json, so a manifest cannot choose where to write.
KINDS = ('skill', 'renderer', 'bridge')


class Lock:
    """One updater at a time, per installation, without ever making anything wait.

    flock is POSIX only, and Windows has no equivalent that behaves the same way, so the lock is
    what both platforms do have: an exclusive create of a file. O_EXCL either succeeds or does
    not, on every filesystem this runs on, and a second invocation that finds the file simply
    leaves rather than queueing. A lock left behind by a process that was killed is broken after
    STALE seconds, which is many times the longest a check can honestly take; the cost of
    getting that wrong is one extra concurrent check, which the version comparison and the atomic
    install already tolerate."""

    STALE = 900

    def __init__(self, path):
        self.path = path
        self.held = False

    def __enter__(self):
        for attempt in (1, 2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                if attempt == 2:
                    return self
                try:
                    if time.time() - os.path.getmtime(self.path) < self.STALE:
                        return self
                    os.unlink(self.path)          # abandoned by a process that did not finish
                except OSError:
                    return self
                continue
            except OSError:
                return self
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write('%d\n' % os.getpid())
            self.held = True
            return self
        return self

    def __exit__(self, *_):
        if self.held:
            try:
                os.unlink(self.path)
            except OSError:
                pass
        return False


def semver(text):
    """(major, minor, patch), or None when it is not a plain MAJOR.MINOR.PATCH. Compared as
    numbers, so 0.10.0 is newer than 0.9.0 and no string ordering can say otherwise."""
    if not isinstance(text, str):
        return None
    m = VERSION_RE.match(text.strip())
    return tuple(int(g) for g in m.groups()) if m else None


def read_state(path):
    try:
        state = json.loads(path.read_text(encoding='utf-8'))
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(path, state):
    """Atomic, private, and complete or not at all: a half-written state file would make the
    version screen lie."""
    fd, temporary = tempfile.mkstemp(prefix='.update', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(json.dumps(state, indent=2, sort_keys=True) + '\n')
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def allowed_hosts(base):
    """Where a download that starts at `base` is allowed to finish.

    Its own host, always. A release on github.com additionally redirects to the host that holds
    the asset bytes, so those hosts are named here, in the code. Nothing a manifest, a server or
    a setting says can add to this set."""
    host = (urllib.parse.urlsplit(base).hostname or '').lower()
    if host == 'github.com' or host.endswith('.github.com'):
        return set(GITHUB_HOSTS)
    return {host}


def get(base, path, limit):
    """One HTTPS GET of `path` under `base`. TLS verification is the default and is never
    relaxed; a redirect that lands on a host outside `allowed_hosts` is refused, so neither a
    manifest nor a compromised redirect can move the download somewhere of its own choosing."""
    url = base.rstrip('/') + '/' + path.lstrip('/')
    origin = urllib.parse.urlsplit(base)
    request = urllib.request.Request(url, headers={'User-Agent': 'converge-update/1',
                                                   'Accept': 'application/octet-stream'})
    context = ssl.create_default_context() if origin.scheme == 'https' else None
    permitted = allowed_hosts(base)
    with urllib.request.urlopen(request, timeout=TIMEOUT, context=context) as response:
        final = urllib.parse.urlsplit(response.geturl())
        # A plain-HTTP local development release may stay on plain HTTP; anything that started
        # on HTTPS must still be on HTTPS at the end of the chain.
        if origin.scheme == 'https' and final.scheme != 'https':
            raise ValueError('update source redirected off HTTPS')
        if (final.hostname or '').lower() not in permitted:
            raise ValueError('update source redirected to an unexpected host')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('update response is too large')
    return data


# ---- release signatures --------------------------------------------------------------------
# Ed25519 verification, written out here rather than imported, because this file is installed on
# its own and must keep working on a Python with no third-party packages at all. It is the
# standard reference formulation of RFC 8032 verification and nothing more: it only ever says
# yes or no about a signature, holds no secret, and generates nothing.
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if (x * x - xx) % _P != 0:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = t1 * 2 * _D * t2 % _P
    D = z1 * 2 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _scalar_mult(point, e):
    result = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            result = _add(result, point)
        point = _add(point, point)
        e >>= 1
    return result


_BY = 4 * pow(5, _P - 2, _P) % _P
_BASE = (_recover_x(_BY, 0), _BY, 1, _recover_x(_BY, 0) * _BY % _P)


def _decode_point(data):
    if len(data) != 32:
        return None
    number = int.from_bytes(data, 'little')
    y = number & ((1 << 255) - 1)
    x = _recover_x(y, number >> 255)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_verify(public_key, signature, message):
    """True only when `signature` is a valid Ed25519 signature of `message` by `public_key`.
    Every malformed input is a False, never an exception: a caller of this is deciding whether
    to install something, and an unexpected error there must read as "do not"."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        point = _decode_point(public_key)
        if point is None:
            return False
        r = _decode_point(signature[:32])
        if r is None:
            return False
        s = int.from_bytes(signature[32:], 'little')
        if s >= _L:
            return False
        h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), 'little') % _L
        left = _scalar_mult(_BASE, s)
        right = _add(r, _scalar_mult(point, h))
        # Compare in affine coordinates: the projective ones are not unique.
        lx = left[0] * pow(left[2], _P - 2, _P) % _P
        ly = left[1] * pow(left[2], _P - 2, _P) % _P
        rx = right[0] * pow(right[2], _P - 2, _P) % _P
        ry = right[1] * pow(right[2], _P - 2, _P) % _P
        return lx == rx and ly == ry
    except Exception:
        return False


def signed_by_converge(manifest_bytes, signature_text):
    """Is this exactly the manifest CONVERGE published? The signature covers the manifest bytes
    as served, so a manifest that has been re-serialised, re-ordered or edited by one byte does
    not verify, whoever served it."""
    if not RELEASE_KEYS:
        return None                                 # no key pinned: nothing to verify against
    try:
        signature = base64.b64decode(signature_text.split()[0], validate=True)
    except Exception:
        return False
    for key in RELEASE_KEYS:
        try:
            public_key = base64.b64decode(key, validate=True)
        except Exception:
            continue
        if ed25519_verify(public_key, signature, manifest_bytes):
            return True
    return False


def platform_key():
    """This machine, in the words a release manifest uses. None when CONVERGE publishes nothing
    for it, which is not an error: it simply means this installation updates everything except
    its bridge, and the user builds that from source."""
    machine = platform.machine().lower()
    arch = {'x86_64': 'x86_64', 'amd64': 'x86_64', 'x64': 'x86_64',
            'arm64': 'arm64', 'aarch64': 'arm64'}.get(machine)
    system = {'linux': 'linux', 'darwin': 'macos', 'windows': 'windows'}.get(platform.system().lower())
    return '%s-%s' % (system, arch) if system and arch else None


def entry(manifest, key):
    """The manifest's description of one file, validated down to its shape before use.

    A bridge is per platform, because a release carries one for each: the manifest describes
    them under `bridge`, keyed by operating system and architecture, and this picks the entry
    for the machine the script is running on and nothing else. The flat `files.bridge` of the
    first CONVERGE manifests is still read, so an installation made before releases moved to the
    public repository updates itself once and then follows the new shape like everything else."""
    if key == 'bridge':
        binaries = manifest.get('bridge')
        if isinstance(binaries, dict):
            here = platform_key()
            if here is None:
                raise ValueError('no CONVERGE bridge is published for this platform')
            item = binaries.get(here)
            if not isinstance(item, dict):
                raise ValueError('the release has no bridge for ' + here)
            return _path_and_digest(here, item)
    files = manifest.get('files')
    if not isinstance(files, dict):
        raise ValueError('manifest has no files')
    item = files.get(key)
    if not isinstance(item, dict):
        raise ValueError('manifest is missing ' + key)
    return _path_and_digest(key, item)


def _path_and_digest(key, item):
    path, digest = item.get('path'), item.get('sha256')
    if not isinstance(path, str) or not PATH_RE.match(path) or '..' in path.split('/'):
        raise ValueError('manifest path for ' + key + ' is not a plain path under the origin')
    if not isinstance(digest, str) or not SHA_RE.match(digest):
        raise ValueError('manifest digest for ' + key + ' is not a SHA-256')
    return path, digest


def well_formed(kind, data):
    """A digest proves the bytes are the ones the manifest meant. This asks the other question:
    are they the kind of file that belongs at this target? A correct digest over the wrong file
    would still be an installation that cannot run."""
    if kind == 'skill':
        try:
            text = data.decode()
        except UnicodeDecodeError:
            return False
        return text.startswith('---\nname: converge\n') and '\n---\n' in text[4:]
    if kind == 'renderer':
        try:
            text = data.decode()
        except UnicodeDecodeError:
            return False
        return text.startswith('#!') and 'systemMessage' in text and len(text) > 200
    if kind == 'bridge':
        # The kind of file that belongs at this target, on whichever platform this is. A correct
        # digest over the wrong file would still be an installation that cannot run.
        heads = (b'\x7fELF',)                      # Linux
        if WINDOWS:
            heads = (b'MZ',)                       # PE
        elif sys.platform == 'darwin':
            heads = (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe')   # Mach-O, fat
        return any(data.startswith(h) for h in heads) and len(data) > 100 * 1024
    return False


def install(staged, target):
    """Replace one file, completely or not at all.

    os.replace either puts the new file there or leaves the old one untouched: there is no moment
    where the target is missing or half written. On Unix a running bridge keeps the inode it is
    executing, so replacing it is safe and simply means the next start is the new version.

    Windows is different and this is the one place it matters: a file that some process has open
    for execution cannot be replaced, and the attempt fails with a sharing violation. So the old
    file is first renamed out of the way, which Windows does allow for a running image, and the
    new one is put in its place. The running bridge carries on from the renamed file until it
    exits; the next start is the new version, which is exactly the Unix behaviour. The leftover
    is removed on the next run, when nothing holds it any more."""
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = target.stat().st_mode & 0o7777 if target.exists() else None
    beside = target.with_name('.' + target.name + '.converge-new')
    shutil.copyfile(staged, beside)
    os.chmod(beside, mode if mode is not None else (0o755 if target.stem == 'converge-bridge' else 0o600))
    try:
        os.replace(beside, target)
        return
    except OSError:
        if not WINDOWS:
            os.unlink(beside)
            raise
    retired = target.with_name('.' + target.name + '.converge-old')
    try:
        os.unlink(retired)                        # from a previous update, if nothing holds it
    except OSError:
        pass
    os.replace(target, retired)                   # allowed even while it is being executed
    try:
        os.replace(beside, target)
    except OSError:
        os.replace(retired, target)               # put back what was working, then give up
        os.unlink(beside)
        raise


def targets(directory, setup):
    """Where each updatable file lives on this machine, taken from the setup this installation
    already has. Anything the setup does not name is simply not updated."""
    out = {'renderer': directory / 'converge-live.py'}
    if setup.get('skill_dir'):
        out['skill'] = Path(setup['skill_dir']) / 'SKILL.md'
    if setup.get('bridge'):
        out['bridge'] = Path(setup['bridge'])
    return {k: v for k, v in out.items() if v.parent.is_dir()}


def check(directory, forced, verbose):
    state_path = directory / 'update.json'
    state = read_state(state_path)
    setup = read_state(directory / 'setup.json')
    now = int(time.time())

    last = state.get('last_update_check')
    # A clock that has moved backwards (last > now) is not a reason to keep checking for ever, but
    # it is also not a throttle we can trust, so it simply lets the next check through.
    if not forced and isinstance(last, int) and 0 <= now - last < CHECK_INTERVAL:
        return 'throttled'

    # The release source, which is the public source repository's releases and not the CONVERGE
    # service. An installation made before that was true carries no release_base and simply
    # starts using the default, which is the same release its next version comes from anyway.
    base = setup.get('release_base') or DEFAULT_RELEASE
    if urllib.parse.urlsplit(base).scheme not in ('https', 'http'):
        return 'no update source'
    # From here on the check has happened, whatever its outcome: record the attempt first, so a
    # source that hangs or fails every time is still only contacted once an hour.
    state['last_update_check'] = now
    state.setdefault('installed_version', None)
    write_state(state_path, state)

    try:
        raw = get(base, MANIFEST_PATH, MAX_MANIFEST)
        # The signature is checked against the bytes as served, before they are parsed, and
        # before one value out of them is looked at. A manifest that does not verify is not a
        # manifest with a problem; it is not a CONVERGE manifest.
        if RELEASE_KEYS:
            try:
                signature = get(base, SIGNATURE_PATH, MAX_MANIFEST).decode()
            except (OSError, ValueError, urllib.error.URLError, ssl.SSLError):
                raise ValueError('release manifest is not signed')
            if signed_by_converge(raw, signature) is not True:
                raise ValueError('release manifest signature does not verify')
        manifest = json.loads(raw.decode())
        if not isinstance(manifest, dict):
            raise ValueError('manifest is not an object')
        offered = semver(manifest.get('version'))
        if offered is None:
            raise ValueError('manifest version is not MAJOR.MINOR.PATCH')
    except (OSError, ValueError, urllib.error.URLError, ssl.SSLError) as e:
        state['last_result'] = 'check failed: %s' % type(e).__name__
        write_state(state_path, state)
        return 'unreachable'

    offered_text = '.'.join(str(n) for n in offered)
    state['latest_known_version'] = offered_text
    current = semver(state.get('installed_version')) or semver(setup.get('skill_version'))
    if current is None:
        # Nothing trustworthy to compare against: record what is offered and leave the working
        # installation alone rather than guess which way round they go.
        state['last_result'] = 'installed version unknown; no update applied'
        write_state(state_path, state)
        return 'unknown current version'
    if offered <= current:
        state['last_result'] = 'up to date'
        write_state(state_path, state)
        return 'current'
    if offered[0] != current[0]:
        # A new major version is a deliberate step, not something an hourly check takes on the
        # user's behalf: it is the one number that says the installation may not simply carry
        # on. Say it is there, and leave the working installation exactly as it is.
        state['last_result'] = ('v%s is available and is a new major version; it is not installed '
                                'automatically' % offered_text)
        write_state(state_path, state)
        return 'major version held'

    where = targets(directory, setup)
    if not where:
        state['last_result'] = 'nothing to update'
        write_state(state_path, state)
        return 'nothing to update'

    with tempfile.TemporaryDirectory(prefix='converge-update-', dir=str(directory)) as scratch:
        staged = {}
        try:
            for kind in KINDS:
                if kind not in where:
                    continue
                try:
                    path, digest = entry(manifest, kind)
                except ValueError:
                    # No build published for this machine. Everything else still updates, and
                    # the bridge the user built themselves is left alone, which is the right
                    # outcome on a platform CONVERGE does not ship a binary for.
                    if kind == 'bridge':
                        continue
                    raise
                data = get(base, path, MAX_FILE)
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError('digest mismatch for ' + kind)
                if not well_formed(kind, data):
                    raise ValueError('unexpected content for ' + kind)
                blob = Path(scratch) / kind
                blob.write_bytes(data)
                staged[kind] = blob
        except (OSError, ValueError, KeyError, urllib.error.URLError, ssl.SSLError) as e:
            state['last_result'] = 'v%s not installed: %s' % (offered_text, e)
            write_state(state_path, state)
            return 'rejected'
        # Everything is present and verified before anything on disk is touched. An interruption
        # inside this loop leaves each file either the old one or the new one, never a fragment;
        # installed_version is written last, so a partial run is retried at the next check.
        try:
            for kind in KINDS:
                if kind in staged:
                    install(staged[kind], where[kind])
        except OSError as e:
            state['last_result'] = 'v%s partly installed: %s (retried at the next check)' % (offered_text, e)
            write_state(state_path, state)
            return 'failed'

    state['installed_version'] = offered_text
    state['last_result'] = 'v%s installed; it runs from the next CONVERGE start' % offered_text
    write_state(state_path, state)
    if verbose:
        print('CONVERGE v%s installed' % offered_text)
    return 'installed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check for an update (the only mode)')
    parser.add_argument('--force', action='store_true', help='Ignore the one-hour throttle: the user asked')
    parser.add_argument('--state-dir', help='CONVERGE state directory; default: this script\'s own directory, '
                                             'which is where setup installs it')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    directory = Path(args.state_dir).expanduser().resolve() if args.state_dir else Path(__file__).resolve().parent
    if not directory.is_dir():
        return 0
    with Lock(directory / 'update.lock') as lock:
        if not lock.held:
            # Another invocation is checking or installing. This one does not queue behind it and
            # does not check again: it simply goes on with the installation that is already there.
            if args.verbose:
                print('another CONVERGE update is in progress')
            return 0
        try:
            outcome = check(directory, args.force, args.verbose)
        except Exception as e:                       # nothing here may ever escape into the host
            if args.verbose:
                print('converge update: %s: %s' % (type(e).__name__, e), file=sys.stderr)
            return 0
        if args.verbose:
            print(outcome)
    return 0


if __name__ == '__main__':
    sys.exit(main())
