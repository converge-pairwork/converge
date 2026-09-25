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


def run_bridge(*args, env=None, stdin=None, timeout=60):
    """One run of the built bridge, output captured."""
    return subprocess.run([str(BRIDGE), *args], env=env if env is not None else dict(os.environ),
                          input=stdin, capture_output=True, text=True, encoding='utf-8',
                          errors='replace', timeout=timeout)


# ---------------------------------------------------------------- where state goes
def test_state_location(scratch):
    print('state location')
    chosen = scratch / 'somewhere chosen'
    chosen.mkdir()
    out = run_bridge('setup', '--status', env=dict(os.environ, CONVERGE_HOME=str(chosen)))
    check(out.returncode == 0 and json.loads(out.stdout)['state_file'] == str(chosen / 'setup.json'),
          'CONVERGE_HOME wins on every platform, which is what makes a test isolable')
    home = scratch / 'plain home'
    home.mkdir()
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
    env.pop('CONVERGE_HOME', None)
    out = run_bridge('setup', '--status', env=env)
    where = Path(json.loads(out.stdout)['state_file']).parent
    if os.name == 'nt':
        check(where.name == 'CONVERGE' and 'Local' in where.parts and 'Roaming' not in where.parts,
              'Windows uses %LOCALAPPDATA%, not Roaming: a private key must not follow a roaming '
              'profile between machines')
    else:
        check(where == home / '.converge', 'Unix keeps the existing ~/.converge convention')
    # The Windows and Unix answers are both asked of the resolver itself by
    # bridge/tests/test_platform.cpp, on every platform; here the built binary is asked the
    # question this machine can answer.


# ---------------------------------------------------------------- the hook command line
def test_hook_command(scratch):
    print('hook command line')
    # The command setup writes into the host's hook file is this executable and its `live`
    # subcommand, quoted for the shell that host runs it through (platform.hpp quote_for_host).
    # scripts/host-check.py and the onboarding suite exercise the written file; here the binary
    # itself is run from a path with a space, which is the case the quoting exists for.
    spaced = scratch / 'a dir with spaces'
    spaced.mkdir()
    copy = spaced / BRIDGE.name
    shutil.copyfile(BRIDGE, copy)
    copy.chmod(0o755)
    home = scratch / 'hook home'
    (home / '.claude').mkdir(parents=True)
    state = scratch / 'hook state'
    state.mkdir()
    hook = json.dumps({'hooks': {'PostToolUse': [{'matcher': 'mcp__converge__converge_session',
                                                  'hooks': [{'type': 'command', 'command': 'placeholder'}]}]}})
    (home / '.claude' / 'settings.json').write_text(hook, encoding='utf-8')
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), CONVERGE_HOME=str(state))
    out = subprocess.run([str(copy), 'setup', '--remove-live-hook', '--client', 'claude'], env=env,
                         capture_output=True, text=True, encoding='utf-8', errors='replace')
    check(out.returncode == 0 and 'removed' in out.stdout,
          'the binary at a path with spaces runs and edits the host configuration')


# ---------------------------------------------------------------- the update lock
def test_lock(scratch):
    print('update lock')
    inst = scratch / 'locked'
    inst.mkdir()
    # A release source that answers nothing, quickly: the run is about the lock, not the update.
    (inst / 'setup.json').write_text(json.dumps({'release_base': 'http://127.0.0.1:1', 'skill_dir': str(inst)}), encoding='utf-8')
    lock = inst / 'update.lock'
    lock.write_text('1\n', encoding='utf-8')
    out = run_bridge('update', '--check', '--force', '--verbose', '--state-dir', str(inst))
    check(out.returncode == 0 and 'in progress' in out.stdout,
          'a second invocation does not take a held lock, and does not queue')
    check(lock.exists(), 'and leaves the lock to its holder')

    # Killed mid-update: the lock is left behind. It must not block updates for ever.
    old = time.time() - 900 - 60
    os.utime(lock, (old, old))
    out = run_bridge('update', '--check', '--force', '--verbose', '--state-dir', str(inst))
    check('in progress' not in out.stdout and 'unreachable' in out.stdout,
          'a lock abandoned by a process that died is broken after its stale time')
    check(not lock.exists(), 'the lock is released when the invocation finishes')

    # Many at once: exactly one may hold it.
    procs = [subprocess.Popen([str(BRIDGE), 'update', '--check', '--force', '--verbose', '--state-dir', str(inst)],
                              stdout=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
             for _ in range(8)]
    outs = [p.communicate()[0] for p in procs]
    check(sum('in progress' not in o for o in outs) == 1,
          'exactly one of eight concurrent invocations holds the lock (got %d)' % sum('in progress' not in o for o in outs))


# Replacing a file that is in use, the Windows way and the Unix way, is the updater's
# install_file (bridge/src/tools.cpp); scripts/skill-update-test.py drives it through real
# updates, including a bridge replaced while the test holds it open.

# ---------------------------------------------------------------- awkward paths
def test_awkward_paths(scratch):
    print('paths with spaces and non-ASCII characters')
    for label, name in (('a space', 'a state dir'), ('non-ASCII', 'estado convergé 状態')):
        home = scratch / name
        state = home / 'converge-state'
        state.mkdir(parents=True)
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), CONVERGE_HOME=str(state),
                   LANG='C.UTF-8')
        out = subprocess.run([str(BRIDGE), '--print-identity'], env=env, capture_output=True,
                             text=True, encoding='utf-8', errors='replace')
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
    subprocess.run([str(BRIDGE), '--print-identity'], env=env, capture_output=True,
                   text=True, encoding='utf-8', errors='replace')
    check((chosen / 'identity').exists() and not (home / '.converge' / 'identity').exists(),
          'CONVERGE_HOME decides, and nothing is written to the home it overrides')


# ---------------------------------------------------------------- the renderer's path checks
def test_ack_path_checks(scratch):
    print('live acknowledgement path')

    def render(ack, piece_id=7):
        event = {'tool_name': 'mcp__converge__converge_session',
                 'tool_response': [{'type': 'text', 'text': json.dumps({'live': {'id': piece_id, 'text': 'shown', 'ack': str(ack)}})}]}
        return run_bridge('live', stdin=json.dumps(event))

    good = scratch / 'state' / 'live'
    good.mkdir(parents=True)
    os.chmod(good, 0o700)
    out = render(good / '4242.ack')
    check(json.loads(out.stdout)['systemMessage'] == 'shown', 'the hook shows the piece')
    check((good / '4242.ack').read_text(encoding='utf-8').strip() == '7', 'an acknowledgement in CONVERGE\'s own live directory is recorded')

    for bad, why in (
        (scratch / 'state' / 'live' / 'evil.ack', 'a name that is not a process id is refused'),
        (scratch / 'state' / 'elsewhere' / '1.ack', 'a directory that is not "live" is refused'),
    ):
        bad.parent.mkdir(parents=True, exist_ok=True)
        render(bad)
        check(not bad.exists(), why)

    other = {'tool_name': 'mcp__other__tool', 'tool_response': 'x'}
    out = run_bridge('live', stdin=json.dumps(other))
    check(out.returncode == 0 and out.stdout.strip() == '', 'another tool\'s result is not rendered')
    out = run_bridge('live', stdin='{ not json')
    check(out.returncode == 0, 'a renderer never breaks the tool call it watches')

    if os.name != 'nt':
        wide = scratch / 'wide' / 'live'
        wide.mkdir(parents=True)
        os.chmod(wide, 0o777)
        render(wide / '99.ack')
        check(not (wide / '99.ack').exists(), 'a live directory others can write to is refused')

        target = scratch / 'target.txt'
        target.write_text('', encoding='utf-8')
        linked = scratch / 'state' / 'live' / '4243.ack'
        os.symlink(target, linked)
        render(linked, 9)
        check(target.read_text(encoding='utf-8') == '', 'a symbolic link in place of an acknowledgement file is not followed')


# ---------------------------------------------------------------- removing the live hook
def test_remove_live_hook(scratch):
    print('removing the live render hook')
    home = scratch / 'hookhome'
    (home / '.claude').mkdir(parents=True)
    state = scratch / 'hookstate'
    state.mkdir()
    settings = home / '.claude' / 'settings.json'
    theirs = {'matcher': 'Write', 'hooks': [{'type': 'command', 'command': 'their-formatter'}]}
    ours = {'matcher': 'mcp__converge__converge_session',
            'hooks': [{'type': 'command', 'command': "'/x/converge-bridge' 'live'"}]}
    settings.write_text(json.dumps({'model': 'theirs', 'hooks': {'PostToolUse': [theirs, ours],
                                                                'PreToolUse': [theirs]}}),
                        encoding='utf-8')
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), CONVERGE_HOME=str(state))
    remove = lambda: run_bridge('setup', '--remove-live-hook', '--client', 'claude', env=env)
    out = remove()
    after = json.loads(settings.read_text(encoding='utf-8'))
    check(out.returncode == 0 and json.loads(out.stdout)['live_hook'].startswith('removed'),
          'the CONVERGE hook is reported as removed')
    check(after['hooks']['PostToolUse'] == [theirs], 'the other PostToolUse hook is kept exactly')
    check(after['hooks']['PreToolUse'] == [theirs], 'other events are untouched')
    check(after['model'] == 'theirs', 'the rest of the host configuration is untouched')
    check(json.loads(remove().stdout)['live_hook'] == 'nothing to remove',
          'running it a second time is not an error and changes nothing')

    # Only CONVERGE's own entry: a configuration that cannot be parsed is left alone.
    settings.write_text('{ not json', encoding='utf-8')
    check(json.loads(remove().stdout)['live_hook'].startswith('left alone'),
          'a malformed host configuration is reported and left exactly as it is')
    check(settings.read_text(encoding='utf-8') == '{ not json', 'and really is left as it is')


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
        test_state_location(scratch)
        test_hook_command(scratch)
        test_lock(scratch)
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
