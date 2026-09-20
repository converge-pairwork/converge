#!/usr/bin/env python3
"""What each AI host sees at the moment CONVERGE is invoked, from the real bridge binary.

    python3 scripts/host-check.py

It speaks stdio MCP to the built bridge exactly as Claude Code and Codex do, once per host, with
that host's clientInfo, a throwaway HOME and no relay at all, so it runs anywhere in a second.
What it holds the binary to is the invocation contract: one banner and only one, carrying the
version that is actually executing and only the command this host really has; the menu, not a
second banner, on a later invocation; a version screen that claims nothing it does not know; and
a tool schema that tells the host model not to invent max_turns. It is not a substitute for
running CONVERGE inside a real Claude Code or Codex session, which only a person can do.
"""
import json, os, subprocess, sys, tempfile, shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def bridge_path():
    """The bridge to drive: the one named on the command line, or the one a build just made.

    Where that is depends on the generator, not only on the platform. A single-configuration
    build puts it straight in the build directory; MSVC is multi-configuration and puts it under
    the configuration's own name, with an .exe on the end. Looking rather than assuming is what
    lets this run unchanged on all three."""
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    build = ROOT / 'bridge' / 'build'
    for candidate in (build / 'converge-bridge', build / 'converge-bridge.exe',
                      build / 'Release' / 'converge-bridge.exe',
                      build / 'Debug' / 'converge-bridge.exe'):
        if candidate.is_file():
            return candidate
    return build / 'converge-bridge'          # the message below names what is missing


BRIDGE = bridge_path()
if not BRIDGE.is_file():
    sys.exit('host check: no converge-bridge at %s; build it first, or name one as an argument'
             % BRIDGE)
VERSION = (ROOT / 'VERSION').read_text().strip()
ok = True
def check(c, what):
    global ok
    print(('PASS ' if c else 'FAIL ') + what); ok &= bool(c)

def run(client, home, extra_env=None):
    # CONVERGE_HOME is what the bridge's own resolver reads first on every platform, so saying it
    # here is what makes this test isolated rather than only isolated on Unix. HOME/USERPROFILE
    # still move too, because the host configuration this exercises lives under the user's home.
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home),
               CONVERGE_HOME=str(Path(home) / 'converge-state'),
               LANG='C.UTF-8', COLUMNS='100', **(extra_env or {}))
    p = subprocess.Popen([str(BRIDGE), '--relay', 'ws://127.0.0.1:1/v1/ws', '--key', 'cvg_' + '0'*32],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         text=True, bufsize=1, env=env)
    n = [0]
    def rpc(method, params):
        n[0] += 1
        p.stdin.write(json.dumps({'jsonrpc':'2.0','id':n[0],'method':method,'params':params}) + '\n')
        return json.loads(p.stdout.readline())['result']
    rpc('initialize', {'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':client}})
    def session(action, **a):
        return json.loads(rpc('tools/call', {'name':'converge_session','arguments':dict(action=action, **a)})['content'][0]['text'])
    return p, session, rpc

for client, word, reload_word in (('claude-code', '/converge', '/mcp'), ('codex-mcp-client', '$converge', 'codex resume')):
    home = Path(tempfile.mkdtemp(prefix='hostcheck-'))
    try:
        p, session, rpc = run(client, home)
        first = session('activate')
        d = first['display']
        check('██████╗' in d, f'{client}: the banner is drawn once, on invocation')
        check(d.count('converge.pairwork.net') == 1, f'{client}: exactly one banner in the first display')
        check(f'v{VERSION}' in d, f'{client}: the banner states the executing version v{VERSION}')
        check(word in d and (('$converge' not in d) if word == '/converge' else ('/converge' not in d)),
              f'{client}: only this host\'s real command is advertised')
        again = session('activate')
        # No renderer here, so the unacknowledged banner is carried and heads this display. It is
        # the SAME banner, carried once, not a second one, and the menu follows it.
        check('CONVERGE · Menu' in again['display'] and again['display'].count('converge.pairwork.net') == 1
              and again['display'].index('converge.pairwork.net') < again['display'].index('CONVERGE · Menu'),
              f'{client}: a later invocation shows the menu, with the unshown banner carried once above it')
        check('██████╗' not in again['live']['text'] and 'CONVERGE · Menu' in again['live']['text'],
              f'{client}: this call\'s own piece is the menu alone: the banner is never produced twice')
        v = session('version')
        check(f'Running: v{VERSION}' in v['display'] and 'Last checked: never' in v['display'],
              f'{client}: the version screen reports the running version and an honest update status')
        check('installed' not in v['display'] and 'checking' not in v['display'].lower(),
              f'{client}: nothing is claimed about a version that is not running')
        check('Version and updates' in session('menu')['display'], f'{client}: the menu offers it')
        # max_turns: omitted means the bridge's own default; a number the user named is honoured.
        check(not session('choose', choice='automatic')['ok'], f'{client}: no call, so no mode to choose (refused cleanly)')
        tools = rpc('tools/list', {})['tools']
        schema = next(t for t in tools if t['name'] == 'converge_session')
        mt = schema['inputSchema']['properties']['max_turns']['description']
        check('only when the USER named a number' in mt and 'otherwise leave it out' in mt,
              f'{client}: the tool schema tells the host model not to invent max_turns')
        check('version' in schema['inputSchema']['properties']['action']['description'],
              f'{client}: the version action is discoverable')
        p.stdin.close(); p.wait(timeout=5)
        live = home / 'converge-state' / 'live'
        check(live.is_dir() and (os.name == 'nt' or oct(live.stat().st_mode & 0o777) == '0o700'),
              f'{client}: the live directory is private to the user')
        check(not list(live.glob('*.ack')) or all(f.stat().st_size == 0 for f in live.glob('*.ack')),
              f'{client}: no acknowledgement was invented for a display the host never rendered')
    finally:
        shutil.rmtree(home, ignore_errors=True)

# With the host's hook configuration naming the renderer, the bridge expects live rendering and
# tells the AI not to print the display a second time.
for client, rel, cfg in (('claude-code', '.claude/settings.json',
                          {'hooks': {'PostToolUse': [{'matcher': 'mcp__converge__converge_session',
                                                      'hooks': [{'type': 'command', 'command': 'python3 /x/converge-live.py'}]}]}}),
                         ('codex-mcp-client', '.codex/hooks.json',
                          {'hooks': {'PostToolUse': [{'matcher': 'mcp__converge__converge_session',
                                                      'hooks': [{'type': 'command', 'command': 'python3 /x/converge-live.py'}]}]}})):
    home = Path(tempfile.mkdtemp(prefix='hostcheck-hook-'))
    try:
        f = home / rel; f.parent.mkdir(parents=True); f.write_text(json.dumps(cfg))
        p, session, rpc = run(client, home)
        first = session('activate')
        check('Do NOT print' in first['display_rule'],
              f'{client}: with the hook registered, the first display is not printed twice')
        check(first['live']['text'].count('converge.pairwork.net') == 1 and f"v{VERSION}" in first['live']['text'],
              f'{client}: the live piece is the banner itself, version and all')
        ack = Path(first['live']['ack'])
        check(ack.suffix == '.ack' and ack.parent.name == 'live'
              and ack.parent.parent == (home / 'converge-state'),
              f'{client}: the acknowledgement path is CONVERGE\'s own, built locally')
        p.stdin.close(); p.wait(timeout=5)
    finally:
        shutil.rmtree(home, ignore_errors=True)

print('HOST CHECK OK' if ok else 'HOST CHECK FAILED')
sys.exit(0 if ok else 1)
