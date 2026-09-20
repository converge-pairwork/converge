#!/usr/bin/env python3
"""Portability of the local AI-session pieces: where state goes, how it is locked, how a file in
use is replaced, and what happens to paths that are not plain ASCII without spaces.

    python3 scripts/platform-test.py [bridge/build/converge-bridge]

Everything runs against a scratch directory and a throwaway environment; nothing here reaches the
network, the real CONVERGE state, or the real Claude or Codex configuration. The Windows-only
behaviour that cannot be executed on this machine is exercised where it can be: the resolver is
asked the Windows question directly, and the replacement path Windows forces is driven by making
the ordinary one fail exactly as Windows makes it fail. That is not the same as running on
Windows and is not reported as if it were; it is the part a test on Linux can honestly hold.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
# The installed AI-session pieces. They are canonical in the public client repository, where
# they sit at agent/; the private CONVERGE repository serves the same files from site/agent/
# while the two trees are being separated. Asking the tree which layout it is lets this file be
# byte for byte the same in both, which is what makes a divergence between them detectable.
AGENT = ROOT / 'agent' if (ROOT / 'agent').is_dir() else ROOT / 'site' / 'agent'
BRIDGE = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'bridge/build/converge-bridge'
REAL_HOME = Path.home()
failures = []


def check(ok, what):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok:
        failures.append(what)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


setup = load(AGENT / 'setup.py', 'converge_setup')
updater = load(AGENT / 'converge-update.py', 'converge_updater')


class Env:
    """This process's environment, restored whatever happens."""

    def __init__(self, **values):
        self.values = values
        self.saved = {}

    def __enter__(self):
        for k, v in self.values.items():
            self.saved[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *_):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


# ---------------------------------------------------------------- where state goes
def test_state_location():
    print('state location')
    with Env(CONVERGE_HOME='/somewhere/chosen'):
        check(setup.state_home() == Path('/somewhere/chosen'),
              'CONVERGE_HOME wins on every platform, which is what makes a test isolable')

    with Env(CONVERGE_HOME=None):
        was = setup.WINDOWS
        try:
            setup.WINDOWS = False
            check(setup.state_home() == Path.home() / '.converge',
                  'Unix keeps the existing ~/.converge convention')
            setup.WINDOWS = True
            with Env(LOCALAPPDATA=r'C:\Users\Jo Blogs\AppData\Local'):
                got = setup.state_home()
                check(got.name == 'CONVERGE' and 'Local' in str(got) and 'Roaming' not in str(got),
                      'Windows uses %LOCALAPPDATA%, not Roaming: a private key must not follow a '
                      'roaming profile between machines')
            with Env(LOCALAPPDATA=None):
                got = setup.state_home()
                check('AppData' in got.parts and 'Local' in got.parts and got.name == 'CONVERGE',
                      'Windows without %LOCALAPPDATA% falls back to the same place under the profile')
        finally:
            setup.WINDOWS = was

    # Host configuration is a different question: both hosts keep theirs under the user's own
    # home on every platform, so this one must NOT move with CONVERGE's state.
    with Env(CONVERGE_HOME='/somewhere/chosen'):
        check(setup.host_home() == Path.home(),
              'host configuration stays under the user home, apart from CONVERGE state')


# ---------------------------------------------------------------- the hook command line
def test_hook_quoting():
    print('hook command line')
    was = setup.WINDOWS
    try:
        setup.WINDOWS = False
        posix = setup.quote_for_host('claude', ['/usr/bin/python3', '/home/jo blogs/.converge/converge-live.py'])
        check("'/home/jo blogs/.converge/converge-live.py'" in posix,
              'a POSIX hook command quotes a path with a space')
        setup.WINDOWS = True
        win = setup.quote_for_host('claude', [r'C:\Python\python.exe', r'C:\Users\Jo Blogs\converge-live.py'])
        check(win.startswith('& "'),
              'a Windows hook command uses the PowerShell call operator, because Claude Code runs '
              'the command through PowerShell and a bare quoted path there is a string, not a command')
        check('"C:\\Users\\Jo Blogs\\converge-live.py"' in win,
              'a Windows hook command quotes a path with a space')
        check('`"' in setup.quote_for_host('claude', ['py', 'we"ird.py']),
              'a quote inside a path is escaped the way PowerShell escapes it')
    finally:
        setup.WINDOWS = was


# ---------------------------------------------------------------- the update lock
def test_lock(scratch):
    print('update lock')
    lock = scratch / 'update.lock'
    with updater.Lock(lock) as first:
        check(first.held, 'the first invocation takes the lock')
        with updater.Lock(lock) as second:
            check(not second.held, 'a second invocation does not take it, and does not queue')
    check(not lock.exists(), 'the lock is released when the invocation finishes')

    # Killed mid-update: the lock is left behind. It must not block updates for ever.
    lock.write_text('1\n')
    old = time.time() - updater.Lock.STALE - 60
    os.utime(lock, (old, old))
    with updater.Lock(lock) as after:
        check(after.held, 'a lock abandoned by a process that died is broken after its stale time')
    fresh = scratch / 'fresh.lock'
    fresh.write_text('1\n')
    with updater.Lock(fresh) as blocked:
        check(not blocked.held, 'a lock that is merely recent is respected')
    fresh.unlink()

    # Many at once: exactly one may hold it.
    held = []
    barrier = threading.Barrier(8)
    def contend():
        barrier.wait()
        with updater.Lock(scratch / 'race.lock') as l:
            if l.held:
                held.append(1)
                time.sleep(0.05)
    threads = [threading.Thread(target=contend) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(len(held) == 1, 'exactly one of eight concurrent invocations holds the lock (got %d)' % len(held))


# ---------------------------------------------------------------- replacing a file in use
def test_install(scratch):
    print('installing over a file that is in use')
    target = scratch / 'converge-bridge'
    target.write_bytes(b'old' * 100)
    os.chmod(target, 0o755)
    staged = scratch / 'staged'
    staged.write_bytes(b'new' * 100)

    updater.install(staged, target)
    check(target.read_bytes() == b'new' * 100, 'the target is replaced')
    # Mode bits are a Unix idea. Windows has none, and what stands in for them there is the ACL
    # the bridge sets (platform.hpp), which bridge/tests/test_platform.cpp checks directly.
    if os.name != 'nt':
        check(os.stat(target).st_mode & 0o777 == 0o755, 'the target keeps its mode')

    # Windows refuses to replace a file that is being executed. Force the ordinary path to fail
    # exactly as it does there and check that the fallback leaves a working installation: the old
    # file renamed aside, the new one in place, and nothing missing at any point.
    was, calls = os.replace, []
    def refuse_first(src, dst):
        calls.append((str(src), str(dst)))
        if len(calls) == 1:
            raise PermissionError(32, 'The process cannot access the file because it is being used')
        return was(src, dst)
    windows_was = updater.WINDOWS
    try:
        updater.WINDOWS = True
        os.replace = refuse_first
        staged.write_bytes(b'newer' * 100)
        updater.install(staged, target)
    finally:
        os.replace = was
        updater.WINDOWS = windows_was
    check(target.read_bytes() == b'newer' * 100,
          'on the Windows path the new file still ends up in place')
    check((scratch / '.converge-bridge.converge-old').exists(),
          'the file that was in use is renamed aside rather than deleted, so a running bridge '
          'carries on from it until it exits')
    check(not (scratch / '.converge-bridge.converge-new').exists(),
          'no half-installed file is left behind')

    # And if even the second step fails, what was working must be put back.
    def refuse_both(src, dst):
        if 'converge-new' in str(src):
            raise PermissionError(32, 'in use')
        return was(src, dst)
    try:
        updater.WINDOWS = True
        os.replace = refuse_both
        staged.write_bytes(b'bad' * 100)
        try:
            updater.install(staged, target)
            check(False, 'a failed install reports the failure')
        except OSError:
            check(True, 'a failed install reports the failure')
    finally:
        os.replace = was
        updater.WINDOWS = windows_was
    check(target.read_bytes() == b'newer' * 100,
          'a failed install puts the working file back: rollback, not a broken installation')


# ---------------------------------------------------------------- awkward paths
def test_awkward_paths(scratch):
    print('paths with spaces and non-ASCII characters')
    for label, name in (('a space', 'a state dir'), ('non-ASCII', 'estado convergé 状態')):
        home = scratch / name
        state = home / 'converge-state'
        state.mkdir(parents=True)
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), CONVERGE_HOME=str(state),
                   LANG='C.UTF-8')
        out = subprocess.run([str(BRIDGE), '--print-identity'], env=env, capture_output=True, text=True)
        key = (state / 'identity')
        check(out.returncode == 0 and out.stdout.startswith('ssh-ed25519 '),
              'the bridge produces an identity under a state directory whose path has %s' % label)
        check(key.exists() and key.stat().st_size > 0,
              'the identity key is written inside that directory, not somewhere else')
        if os.name != 'nt':
            check(oct(key.stat().st_mode & 0o777) == '0o600',
                  'the identity key is readable only by its owner (%s)' % label)

    # The state directory resolver, not $HOME, is what decides.
    home = scratch / 'ignored-home'
    (home / '.converge').mkdir(parents=True)
    chosen = scratch / 'chosen state'
    chosen.mkdir()
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), CONVERGE_HOME=str(chosen))
    subprocess.run([str(BRIDGE), '--print-identity'], env=env, capture_output=True, text=True)
    check((chosen / 'identity').exists() and not (home / '.converge' / 'identity').exists(),
          'CONVERGE_HOME decides, and nothing is written to the home it overrides')


# ---------------------------------------------------------------- the renderer's path checks
def test_ack_path_checks(scratch):
    print('live acknowledgement path')
    live = load(AGENT / 'converge-live.py', 'converge_live')
    good = scratch / 'state' / 'live'
    good.mkdir(parents=True)
    os.chmod(good, 0o700)
    live.record(str(good / '4242.ack'), 7)
    check((good / '4242.ack').read_text().strip() == '7', 'an acknowledgement in CONVERGE\'s own live directory is recorded')

    for bad, why in (
        (scratch / 'state' / 'live' / 'evil.ack', 'a name that is not a process id is refused'),
        (scratch / 'state' / 'elsewhere' / '1.ack', 'a directory that is not "live" is refused'),
    ):
        bad.parent.mkdir(parents=True, exist_ok=True)
        live.record(str(bad), 7)
        check(not bad.exists(), why)

    if os.name != 'nt':
        wide = scratch / 'wide' / 'live'
        wide.mkdir(parents=True)
        os.chmod(wide, 0o777)
        live.record(str(wide / '99.ack'), 7)
        check(not (wide / '99.ack').exists(), 'a live directory others can write to is refused')

        target = scratch / 'target.txt'
        target.write_text('')
        linked = scratch / 'state' / 'live' / '4243.ack'
        os.symlink(target, linked)
        live.record(str(linked), 9)
        check(target.read_text() == '', 'a symbolic link in place of an acknowledgement file is not followed')


# ---------------------------------------------------------------- removing the live hook
def test_remove_live_hook(scratch):
    print('removing the live render hook')
    home = scratch / 'hookhome'
    (home / '.claude').mkdir(parents=True)
    settings = home / '.claude' / 'settings.json'
    theirs = {'matcher': 'Write', 'hooks': [{'type': 'command', 'command': 'their-formatter'}]}
    ours = {'matcher': 'mcp__converge__converge_session',
            'hooks': [{'type': 'command', 'command': 'python3 /x/converge-live.py'}]}
    settings.write_text(json.dumps({'model': 'theirs', 'hooks': {'PostToolUse': [theirs, ours],
                                                                'PreToolUse': [theirs]}}))
    with Env(HOME=str(home), USERPROFILE=str(home)):
        outcome = setup.remove_live_hook('claude')
        after = json.loads(settings.read_text())
        check(outcome.startswith('removed'), 'the CONVERGE hook is reported as removed')
        check(after['hooks']['PostToolUse'] == [theirs], 'the other PostToolUse hook is kept exactly')
        check(after['hooks']['PreToolUse'] == [theirs], 'other events are untouched')
        check(after['model'] == 'theirs', 'the rest of the host configuration is untouched')
        check(setup.remove_live_hook('claude') == 'nothing to remove',
              'running it a second time is not an error and changes nothing')

        # Only CONVERGE's own entry: a configuration that cannot be parsed is left alone.
        broken = home / '.claude' / 'settings.json'
        broken.write_text('{ not json')
        check(setup.remove_live_hook('claude').startswith('left alone'),
              'a malformed host configuration is reported and left exactly as it is')
        check(broken.read_text() == '{ not json', 'and really is left as it is')


# ---------------------------------------------------------------- nothing touches the real user
def test_isolation():
    print('test isolation')
    sys.path.insert(0, str(ROOT / 'scripts'))
    out = subprocess.run(
        [sys.executable, '-c',
         'import sys; sys.path.insert(0, %r)\n'
         'import testhome, os, json\n'
         'print(json.dumps({k: os.environ.get(k) for k in '
         '("HOME","USERPROFILE","CONVERGE_HOME","LOCALAPPDATA","APPDATA","XDG_CONFIG_HOME",'
         '"CONVERGE_TEST_HOME")}))'
         % str(ROOT / 'scripts')],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    check(out.returncode == 0, 'scripts/testhome.py imports cleanly')
    if out.returncode != 0:
        print(out.stderr)
        return
    seen = json.loads(out.stdout)
    # The property that matters is that everything the resolvers read points inside the scratch
    # home that testhome made, and that the scratch home is not the real one. "Not underneath
    # the real home" would say the same thing on Unix and something false on Windows, where
    # the temporary directory lives under the user's own profile by design.
    scratch_home = seen.get('CONVERGE_TEST_HOME')
    check(bool(scratch_home) and os.path.realpath(scratch_home) != os.path.realpath(str(REAL_HOME)),
          'a test process gets a scratch home that is not the real one')
    root = os.path.realpath(scratch_home) if scratch_home else ''
    for name in ('HOME', 'USERPROFILE', 'CONVERGE_HOME', 'LOCALAPPDATA', 'APPDATA'):
        value = seen.get(name)
        resolved = os.path.realpath(value) if value else ''
        check(bool(value) and (resolved == root or resolved.startswith(root + os.sep)),
              'a test process reads %s from its own scratch directory, never the real user\'s' % name)
    check(seen.get('XDG_CONFIG_HOME') is None, 'XDG variables from the real session are cleared')


def main():
    if not BRIDGE.exists():
        print('platform-test: no bridge at %s (build it first)' % BRIDGE, file=sys.stderr)
        return 2
    scratch = Path(tempfile.mkdtemp(prefix='converge-platform-'))
    try:
        test_state_location()
        test_hook_quoting()
        test_lock(scratch)
        (scratch / 'install').mkdir()
        test_install(scratch / 'install')
        test_awkward_paths(scratch)
        test_ack_path_checks(scratch)
        test_remove_live_hook(scratch)
        test_isolation()
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    print('PLATFORM OK' if not failures else 'PLATFORM FAILED (%d)' % len(failures))
    for f in failures:
        print('  - ' + f)
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
