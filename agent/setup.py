#!/usr/bin/env python3
"""Converge onboarding and private stdio launcher. No third-party Python dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE = 'https://converge.pairwork.net'
# Two sources, deliberately kept apart. The CONVERGE service holds accounts, balances and
# negotiations; the public source repository publishes the client software. Everything this
# helper installs on the machine comes from a release of the second, verified against that
# release's own manifest; only the account questions go to the first.
DEFAULT_RELEASE = 'https://github.com/converge-pairwork/converge/releases/latest/download'
REPOSITORY = 'https://github.com/converge-pairwork/converge'
WINDOWS = os.name == 'nt'


# ---- where things live ---------------------------------------------------------------------
# One rule, in one place, for every platform. Everything else in this file (and the updater,
# which is handed the answer) asks for it rather than spelling out a path of its own.
#
#   CONVERGE_HOME set  use it. Automated tests set this; it is also the escape hatch for a home
#                      directory that is not writable.
#   Windows            %LOCALAPPDATA%\CONVERGE. Local, not Roaming, deliberately: this directory
#                      holds a private key and per-process live files, and a roaming profile
#                      would copy them between machines.
#   Linux, macOS       ~/.converge, the existing convention, unchanged.
#
# Host configuration is a different question with a different answer, and `host_home()` is it:
# Claude Code and Codex both keep theirs under the user's own home on every platform they
# support, so that one is simply Path.home() everywhere. Keeping the two apart is the point.
def state_home():
    forced = os.environ.get('CONVERGE_HOME')
    if forced:
        return Path(forced)
    if WINDOWS:
        local = os.environ.get('LOCALAPPDATA')
        return Path(local) / 'CONVERGE' if local else Path.home() / 'AppData' / 'Local' / 'CONVERGE'
    return Path.home() / '.converge'


def host_home():
    return Path.home()


def bridge_default():
    """Where a bridge this helper installs for you goes. ~/.local/bin is a Unix convention with
    no Windows equivalent, so on Windows it lives beside the rest of CONVERGE's own state."""
    if WINDOWS:
        return state_home() / 'bin' / 'converge-bridge.exe'
    return Path.home() / '.local' / 'bin' / 'converge-bridge'


def quote_for_host(client, parts):
    """One command line for this host to run, quoted the way this host's shell will read it.

    Claude Code runs a hook command through the platform shell, which on Windows is PowerShell,
    where a bare quoted path is a string expression and not a command: it needs the call
    operator. Codex is the same shape. Getting this wrong is silent on a path without spaces and
    breaks for every user whose name has one, which is most of them on Windows."""
    if WINDOWS:
        quoted = ' '.join('"%s"' % str(p).replace('"', '`"') for p in parts)
        return '& ' + quoted
    return ' '.join(shlex.quote(str(p)) for p in parts)

# Everything that differs between AI hosts in installation and activation. CONVERGE itself never
# needs a restart: whether a running session can pick up a newly registered MCP server is the
# host's capability, and the instruction below is given only when that host's tools did not appear.
HOSTS = {
    'claude': {
        'skills': '.claude/skills',
        'mcp_add': ['--scope', 'user', '--transport', 'stdio'],
        'invoke': '/converge',
        'hooks_file': '.claude/settings.json',
        'hook_note': '',
        'hook_trust': '',
        'if_tools_missing': 'Claude Code starts MCP servers when a session starts. Open /mcp and reconnect "converge" if it '
                            'is listed. If it is not listed, leave this session and run `claude --continue`: the '
                            'conversation is kept.',
    },
    'codex': {
        'skills': '.agents/skills',
        'mcp_add': [],
        'invoke': '$converge',
        'hooks_file': '.codex/hooks.json',
        'hook_note': ' Codex asks you to review this hook before it runs; see hook_trust.',
        # Codex records trust against the hook definition's hash, so a newly installed or updated
        # hook is skipped until the user reviews it. Say so plainly, say what it does, and leave
        # the decision entirely with them: nothing here ever writes Codex's trust state.
        'hook_trust': 'CONVERGE registers one Codex hook (PostToolUse on the converge_session tool) whose only job is to '
                      'show each negotiation message to you the moment it arrives. Codex will ask you to review it before '
                      'it runs: open /hooks, read what it does, and trust it only if you want to. Live per-exchange '
                      'rendering starts once you do. Until then, and if you decline, CONVERGE works exactly as before: '
                      'every message is still shown, together, when your AI ends its turn. Nothing is lost either way.',
        'if_tools_missing': 'Codex starts MCP servers when a session starts. Leave this session and run `codex resume`: '
                            'the conversation is kept.',
    },
}


def write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_state(directory):
    path = directory / 'setup.json'
    return json.loads(path.read_text()) if path.exists() else {}


def save_state(directory, state):
    write_private(directory / 'setup.json', json.dumps(state, indent=2) + '\n')


def public_status(state, directory):
    allowed = ('stage', 'client', 'handle', 'host_handle', 'relay', 'topic', 'identity_public_key',
               'skill_version', 'release_base')
    out = {k: state[k] for k in allowed if k in state}
    out['state_file'] = str(directory / 'setup.json')
    out['resume_prompt'] = 'Continue my Converge setup.'
    if state.get('stage') == 'needs_account':
        out['next'] = ('Open ' + state['base'] + '/, sign in with a Solana wallet, add a member under Team, register '
                       'identity_public_key under Identity keys, and give your assistant the public cvh_ handle.')
    elif state.get('stage') == 'registered':
        host = HOSTS.get(state.get('client'), {})
        out['next'] = 'If converge_* tools are available in this session, CONVERGE is usable now: call converge_status.'
        out['activation'] = {
            'usable_now_if': 'converge_status is callable in this session',
            'if_tools_missing': host.get('if_tools_missing', 'Reload MCP servers in your AI client.')
                                + ' Then say: ' + out['resume_prompt'],
            'invoke': host.get('invoke', 'say "converge menu"'),
            'live_view': ('Each exchange is shown live through a host hook.' + host.get('hook_note', ''))
                         if state.get('live_hook') == 'installed' else
                         'No live hook: exchanges are shown when the AI ends its turn.',
        }
        if state.get('live_hook') == 'installed' and host.get('hook_trust'):
            out['activation']['hook_trust'] = host['hook_trust']
    return out


def install_live_hook(client, script):
    """Registers the live renderer as a PostToolUse hook of this host. It is how each exchange of
    an automatic negotiation reaches the user while it happens; without it the bridge still shows
    everything, in the display that ends the AI's turn. Never fatal: other hooks are preserved."""
    path = host_home() / HOSTS[client]['hooks_file']
    command = quote_for_host(client, [sys.executable, script])
    try:
        config = json.loads(path.read_text()) if path.exists() else {}
        if not isinstance(config, dict) or not isinstance(config.setdefault('hooks', {}), dict):
            return 'unreadable'
        entries = config['hooks'].setdefault('PostToolUse', [])
        if not isinstance(entries, list):
            return 'unreadable'
        ours = {'matcher': 'mcp__converge__converge_session',
                'hooks': [{'type': 'command', 'command': command, 'timeout': 10}]}
        kept = [e for e in entries if 'converge-live.py' not in json.dumps(e)]
        if kept + [ours] == entries:
            return 'installed'
        if path.exists():
            backup = path.with_name(path.name + '.before-converge')
            if not backup.exists():
                write_private(backup, path.read_text())
        config['hooks']['PostToolUse'] = kept + [ours]
        write_private(path, json.dumps(config, indent=2) + '\n')
        return 'installed'
    except (OSError, ValueError):
        return 'unreadable'


def remove_live_hook(client):
    """Takes CONVERGE's live-render hook out of this host's configuration and leaves everything
    else exactly as it was. The counterpart of --no-live-hook, which only ever prevented the
    installation; until now there was no way to undo one.

    Deliberately narrow. It removes PostToolUse entries that name converge-live.py and nothing
    else: not other hooks, not other events, not the host's other settings, and not any trust
    state, which belongs to the user and to the host. Running it twice is not an error, and a
    configuration file it cannot parse is left untouched rather than rewritten."""
    path = host_home() / HOSTS[client]['hooks_file']
    if not path.exists():
        return 'nothing to remove'
    try:
        config = json.loads(path.read_text())
    except (OSError, ValueError):
        return 'left alone: this host configuration could not be read'
    hooks = config.get('hooks') if isinstance(config, dict) else None
    entries = hooks.get('PostToolUse') if isinstance(hooks, dict) else None
    if not isinstance(entries, list):
        return 'nothing to remove'
    kept = [e for e in entries if 'converge-live.py' not in json.dumps(e)]
    if len(kept) == len(entries):
        return 'nothing to remove'
    backup = path.with_name(path.name + '.before-converge')
    if not backup.exists():
        write_private(backup, path.read_text())
    if kept:
        hooks['PostToolUse'] = kept
    else:
        hooks.pop('PostToolUse')
        if not hooks:
            config.pop('hooks')
    write_private(path, json.dumps(config, indent=2) + '\n')
    return 'removed %d CONVERGE hook entr%s' % (len(entries) - len(kept), 'y' if len(entries) - len(kept) == 1 else 'ies')


def skill_version_of(text):
    """The version the downloaded SKILL.md states. One authoritative string travels with the
    skill; the bridge carries the same one compiled in, and that is the one that is executing."""
    for line in text.split('\n---\n', 1)[0].split('\n'):
        if line.startswith('version:'):
            value = line.split(':', 1)[1].strip()
            if re.fullmatch(r'\d{1,9}\.\d{1,9}\.\d{1,9}', value):
                return value
    return None


def seed_update_state(directory, skill_version):
    """What the updater compares against. Setup is the only thing that knows the version of an
    installation it just made; after that the updater owns this file. An existing file is left
    alone except for the version, which setup has just made true again."""
    path = directory / 'update.json'
    try:
        state = json.loads(path.read_text())
        if not isinstance(state, dict):
            state = {}
    except (OSError, ValueError):
        state = {}
    if skill_version:
        state['installed_version'] = skill_version
        state.setdefault('latest_known_version', skill_version)
    state.setdefault('last_update_check', 0)
    state.setdefault('last_result', 'installed by setup')
    write_private(path, json.dumps(state, indent=2, sort_keys=True) + '\n')


def fetch(url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Content-Type': 'application/json', 'User-Agent': 'converge-setup/1'})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError('Request failed (HTTP %s): %s' % (e.code, url.split('/v1/invite/')[0])) from None
    except urllib.error.URLError:
        raise RuntimeError('Could not reach Converge; check the connection and retry setup.') from None


def origin(value):
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ('https', 'http') or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in ('', '/'):
        raise ValueError('--base must be an HTTPS origin')
    if parts.scheme != 'https' and parts.hostname not in ('127.0.0.1', 'localhost', '::1'):
        raise ValueError('HTTP is permitted only for a local development relay')
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, '', '', ''))


def serve(directory):
    state = read_state(directory)
    if not state.get('handle') or not state.get('bridge'):
        raise RuntimeError('Setup is incomplete; run setup.py --status to see the next step.')
    env = os.environ.copy()
    for key in ('CONVERGE_KEY', 'CONVERGE_TOKEN', 'CONVERGE_HANDLE'):
        env.pop(key, None)
    command = [state['bridge'], '--relay', state['relay'], '--pin-store', str(directory / 'known_peers')]
    if state.get('key'):
        env['CONVERGE_KEY'] = state['key']
    else:
        command += ['--handle', state['handle'], '--identity-file', state['identity_file']]
    # stdout belongs exclusively to MCP. No credentials appear in process arguments.
    if WINDOWS:
        # Windows has no exec that replaces this process in place: os.execv there starts a new
        # process and lets this one return, which would hand the host a closed pipe in the middle
        # of a session. Run the bridge as a child instead, inheriting this process's stdio, and
        # pass its exit code on. The host sees one long-lived stdio server either way.
        return subprocess.run(command, env=env).returncode
    os.execve(command[0], command, env)
    return 0


def setup(args, directory):
    state = read_state(directory)
    if args.status:
        print(json.dumps(public_status(state, directory), indent=2))
        return
    base = origin(args.base or state.get('base', DEFAULT_BASE))
    release = (args.release_base or state.get('release_base') or DEFAULT_RELEASE).rstrip('/')
    client = args.client or state.get('client')
    if client is None:
        found = [name for name in HOSTS if shutil.which(name)]
        if len(found) != 1:
            raise ValueError('Specify the client running this session: --client claude or --client codex.')
        client = found[0]
    cli = shutil.which(client)
    if not cli:
        raise RuntimeError(client + ' CLI not found. Use the manual MCP registration section in /agent/setup.md.')
    subprocess.run([cli, '--version'], stdout=subprocess.DEVNULL, check=True)
    if state and (state.get('base') != base or state.get('client') != client):
        raise ValueError('This setup belongs to another client or relay; use a separate --state-dir.')
    if args.handle and not re.fullmatch(r'cvh_[0-9a-f]{12}', args.handle):
        raise ValueError('--handle must be the public cvh_ handle from the Team section at the Converge site')
    if args.invite and not re.fullmatch(r'cvi_[0-9a-f]+', args.invite):
        raise ValueError('--invite must be a cvi_ invitation code')
    if args.handle and args.invite:
        raise ValueError('Use --handle or --invite, not both')
    if args.handle and state.get('handle') and args.handle != state['handle']:
        raise ValueError('This setup already has a different member; use a separate --state-dir.')
    if args.invite and state.get('handle') and state.get('invite_hash') != hashlib.sha256(args.invite.encode()).hexdigest():
        raise ValueError('This session already has a member. Keep it and follow the existing-account pairing guide.')

    # Detect an existing manually managed registration before touching local setup.
    existing = subprocess.run([cli, 'mcp', 'get', 'converge'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if existing.returncode == 0 and not state.get('registered_command'):
        raise RuntimeError('Converge is already registered outside this helper. Use converge_status and the setup guide; existing configuration was preserved.')

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    skill_dir = Path(args.skill_dir or state.get('skill_dir') or
                     host_home() / HOSTS[client]['skills'] / 'converge').expanduser().resolve()
    skill = fetch(release + '/skill.md').decode()
    if not skill.startswith('---\nname: converge\n') or '\n---\n' not in skill[4:]:
        raise RuntimeError('The downloaded Converge skill is not a valid SKILL.md; nothing installed.')
    skill_version = skill_version_of(skill)
    target = skill_dir / 'SKILL.md'
    if target.exists() and target.read_text() != skill:
        backup = target.with_name('SKILL.md.before-converge-setup')
        if not backup.exists():
            write_private(backup, target.read_text())
    write_private(target, skill)
    write_private(skill_dir / 'setup-location.txt', str(directory) + '\n')
    launcher = directory / 'setup.py'
    if Path(__file__).resolve() != launcher:
        write_private(launcher, Path(__file__).read_text())
    if not args.no_live_hook:
        renderer = directory / 'converge-live.py'
        write_private(renderer, fetch(release + '/converge-live.py').decode())
        state['live_hook'] = install_live_hook(client, renderer)
    # The updater lives in this private state directory, never inside the skill: a skill directory
    # is not guaranteed to be writable, and the thing that replaces an installation should not be
    # part of what it replaces. Not having it is not an error; CONVERGE then simply never updates.
    try:
        write_private(directory / 'converge-update.py', fetch(release + '/converge-update.py').decode())
    except (OSError, RuntimeError):
        pass

    default_bridge = bridge_default().resolve()
    bridge = Path(args.bridge).expanduser().resolve() if args.bridge else Path(state.get('bridge', str(default_bridge))).resolve()
    managed_bridge = bridge == default_bridge and not args.bridge
    state.update({'version': 1, 'base': base, 'release_base': release, 'client': client, 'bridge': str(bridge),
                  'relay': ('wss://' if base.startswith('https:') else 'ws://') + urllib.parse.urlsplit(base).netloc + '/v1/ws',
                  'identity_file': state.get('identity_file', str(directory / 'identity')),
                  'skill_dir': str(skill_dir), 'skill_version': skill_version,
                  'stage': state.get('stage', 'installed_skill')})
    seed_update_state(directory, skill_version)
    if args.topic:
        state['topic'] = args.topic
    save_state(directory, state)
    if managed_bridge:
        # Keep managed installs current so new MCP tools and security fixes become available
        # when a user resumes setup. The installer verifies the published binary checksum.
        #
        # It is a POSIX shell script, so it runs wherever there is a shell: Linux and macOS
        # both, and it picks the binary for the machine out of the release manifest. Windows
        # has no shell it can run in, so there the honest answer is to say what to do instead.
        # --bridge takes a converge-bridge the user already has, whether they downloaded it
        # from the release page or built it, and everything after this point is identical.
        if WINDOWS:
            raise RuntimeError(
                'On Windows, download converge-bridge-<version>-windows-x86_64.exe from '
                + REPOSITORY + '/releases (or build it from source), then run setup again with '
                '--bridge <path to converge-bridge.exe>. Everything else in this setup works '
                'on this platform.')
        with tempfile.TemporaryDirectory(prefix='converge-install-') as scratch:
            installer = Path(scratch) / 'install.sh'
            installer.write_bytes(fetch(release + '/install.sh'))
            env = dict(os.environ, CONVERGE_BASE=base, CONVERGE_RELEASE_BASE=release,
                       PREFIX=str(bridge.parent))
            subprocess.run(['sh', str(installer)], env=env, check=True)
    elif not bridge.exists():
        raise RuntimeError('--bridge does not exist')
    subprocess.run([str(bridge), '--help'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    if args.invite and not state.get('handle'):
        info = json.loads(fetch(base + '/v1/invite/' + args.invite))
        if info.get('billing', 'host') != 'host':
            raise RuntimeError('This is a split-billing introduction. Set up your own account, then use the existing-account pairing guide.')
        pub = subprocess.check_output([str(bridge), '--identity-file', state['identity_file'], '--print-identity'], text=True).strip()
        # Redeeming atomically binds this public key, creates the member and consumes the code.
        guest = json.loads(fetch(base + '/v1/invite/' + args.invite + '/redeem',
                                 {'alias': args.alias or 'guest', 'pubkey': pub}))
        if guest.get('auth') != 'identity' or not guest.get('handle'):
            raise RuntimeError('Invite redemption did not register the local identity; request a fresh invite if it was consumed.')
        # Persist the handle immediately: if client registration fails, rerunning setup won't
        # attempt to redeem the now-consumed code again.
        state.update({'handle': guest['handle'], 'host_handle': info['host_handle'],
                      'identity_public_key': pub,
                      'invite_hash': hashlib.sha256(args.invite.encode()).hexdigest(), 'stage': 'credential_saved'})
        save_state(directory, state)
    elif not state.get('key'):
        pub = subprocess.check_output([str(bridge), '--identity-file', state['identity_file'], '--print-identity'], text=True).strip()
        state['identity_public_key'] = pub
        if args.handle:
            state['handle'] = args.handle
        if not state.get('handle'):
            state['stage'] = 'needs_account'
            save_state(directory, state)
            print(json.dumps(public_status(state, directory), indent=2))
            return
        if state.get('stage') != 'registered':
            state['stage'] = 'credential_saved'
        save_state(directory, state)

    command = [sys.executable, str(launcher), '--serve', '--state-dir', str(directory)]
    if state.get('registered_command') != command or existing.returncode != 0:
        registration = [cli, 'mcp', 'add'] + HOSTS[client]['mcp_add']
        subprocess.run(registration + ['converge', '--'] + command, check=True)
        state['registered_command'] = command
    state['stage'] = 'registered'
    save_state(directory, state)
    print(json.dumps(public_status(state, directory), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', choices=tuple(HOSTS))
    parser.add_argument('--base', help='Converge origin; default https://converge.pairwork.net')
    parser.add_argument('--release-base', help='Where the client software is downloaded from; default the '
                                               'latest release of ' + REPOSITORY)
    parser.add_argument('--state-dir', default=str(state_home()), help='Private resumable setup directory')
    parser.add_argument('--skill-dir', help='Override the client-specific Converge skill directory')
    parser.add_argument('--bridge', help='Use an existing bridge binary')
    parser.add_argument('--handle', help='Public member handle after browser registration')
    parser.add_argument('--invite', help='Host-paid invitation code')
    parser.add_argument('--alias', help='Invited member name')
    parser.add_argument('--topic', help='Remember the discussion topic locally across reloads')
    parser.add_argument('--no-live-hook', action='store_true', help='Do not register the live renderer hook with the AI client')
    parser.add_argument('--remove-live-hook', action='store_true',
                        help='Remove CONVERGE\'s live renderer hook from the AI client and leave everything else alone')
    parser.add_argument('--status', action='store_true', help='Print setup progress without secrets')
    parser.add_argument('--serve', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    directory = Path(args.state_dir).expanduser().resolve()
    try:
        if args.serve:
            return serve(directory) or 0
        if args.remove_live_hook:
            state = read_state(directory)
            client = args.client or state.get('client')
            if not client:
                raise ValueError('Specify which client to remove the hook from: --client claude or --client codex.')
            outcome = remove_live_hook(client)
            if state.get('live_hook') == 'installed' and outcome.startswith('removed'):
                state['live_hook'] = 'removed'
                save_state(directory, state)
            print(json.dumps({'client': client, 'live_hook': outcome,
                              'note': 'Only CONVERGE\'s own PostToolUse entry was touched. Nothing else in this '
                                      'host\'s configuration, and no trust state, was changed. CONVERGE still '
                                      'shows every exchange; without the hook they appear together when the AI '
                                      'ends its turn.'}, indent=2))
            return 0
        setup(args, directory)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as e:
        print('converge setup: ' + str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
