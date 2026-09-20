"""TEST ONLY: keeps automated tests out of the developer's real CONVERGE state.

A bridge keeps its identity key, pinned peers and saved connections in CONVERGE's state
directory; setup and the updater keep setup.json, update.json and the live renderer there too.
Importing this module, before anything is launched, points THIS process (and so every bridge,
helper or client it starts) at a fresh private temporary directory, which is removed when the
process exits.

It is not enough to move HOME. The production resolver (site/agent/setup.py `state_home`,
bridge/src/platform.hpp `state_dir`) answers a different question on each platform, and the AI
hosts answer another one again, so every variable any of them reads is redirected:

    CONVERGE_HOME                     CONVERGE's own state, on every platform
    HOME                              Unix home: ~/.converge, ~/.claude, ~/.codex
    USERPROFILE, HOMEDRIVE, HOMEPATH  what Path.home() reads on Windows
    LOCALAPPDATA, APPDATA             where CONVERGE state and host data live on Windows
    XDG_*                             cleared, so nothing leaks in from the real session

Nothing global is touched: only this process's environment. Each test process gets its own
directory, so parallel runs cannot collide, and no run reads or leaves anything in the real
CONVERGE state or in the real Claude or Codex configuration on any supported platform.

Under scripts/integration-test.py the runner has already done this for the whole suite (its
scratch directory); the marker CONVERGE_TEST_HOME says so and this module then does nothing.
"""
import atexit
import os
from pathlib import Path
import shutil
import tempfile

# The real home, from the platform itself rather than from $HOME, so that the assertion at the
# bottom cannot be fooled by an environment that has already been moved.
try:
    import pwd
    REAL_HOME = pwd.getpwuid(os.getuid()).pw_dir
except ImportError:                                  # Windows has no passwd database
    REAL_HOME = os.environ.get('USERPROFILE') or str(Path.home())

# Every variable the production resolvers read, and what each one is pointed at inside the
# scratch directory. Keeping this list here, next to the docstring that says why, is what makes
# it reviewable when a resolver learns about a new one.
def _layout(home):
    return {
        'CONVERGE_HOME': os.path.join(home, 'converge-state'),
        'HOME': home,
        'USERPROFILE': home,
        'HOMEDRIVE': os.path.splitdrive(home)[0] or '',
        'HOMEPATH': os.path.splitdrive(home)[1] or home,
        'APPDATA': os.path.join(home, 'AppData', 'Roaming'),
        'LOCALAPPDATA': os.path.join(home, 'AppData', 'Local'),
    }


def isolate():
    marked = os.environ.get('CONVERGE_TEST_HOME')
    if marked and marked == os.environ.get('HOME') and os.path.isdir(marked):
        return marked
    home = tempfile.mkdtemp(prefix='converge-test-home-')   # 0700, unique per process
    for name, value in _layout(home).items():
        if value:
            os.environ[name] = value
            if name.endswith('APPDATA') or name == 'CONVERGE_HOME':
                os.makedirs(value, exist_ok=True)
        else:
            os.environ.pop(name, None)
    os.environ['CONVERGE_TEST_HOME'] = home
    for name in ('XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME'):
        os.environ.pop(name, None)
    atexit.register(shutil.rmtree, home, ignore_errors=True)
    return home


HOME = isolate()
assert os.path.realpath(HOME) != os.path.realpath(REAL_HOME), 'test HOME is the real HOME'
for _name in ('CONVERGE_HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA'):
    assert os.path.realpath(os.environ[_name]).startswith(os.path.realpath(HOME)), \
        _name + ' still points outside the test home'
