#!/usr/bin/env python3
"""One version, stated once, and the same everywhere it is stated again.

    python3 scripts/version-check.py [path/to/converge-bridge ...]

VERSION at the repository root is the only place the number is written. The packaged skill
carries it in its frontmatter because that is how an installation knows what it has; the bridge
carries it compiled in because that is what is actually executing. This refuses a tree where
those three disagree, which is the state that makes a release lie about itself.

Given one or more built binaries it checks those too, so the release workflow can assert that
every artifact it is about to publish is the version it says it is.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r'\A\d{1,9}\.\d{1,9}\.\d{1,9}\Z')
AGENT = ROOT / 'agent' if (ROOT / 'agent').is_dir() else ROOT / 'site' / 'agent'

failures = []


def check(ok, what):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok:
        failures.append(what)


def main():
    version = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
    check(bool(SEMVER.match(version)), 'VERSION is MAJOR.MINOR.PATCH (%s)' % version)

    skill = (AGENT / 'skill.md').read_text(encoding='utf-8')
    stated = [l for l in skill.split('\n---\n')[0].split('\n') if l.startswith('version:')]
    check(bool(stated) and stated[0].split(':', 1)[1].strip() == version,
          '%s frontmatter states %s' % (AGENT.relative_to(ROOT).as_posix() + '/skill.md', version))

    cmake = (ROOT / 'bridge/CMakeLists.txt').read_text(encoding='utf-8')
    check('CONVERGE_VERSION="${CONVERGE_VERSION}"' in cmake,
          'the bridge compiles in the version from the same file')

    # A second hard-coded copy of the number is a second thing to forget to change.
    sources = [ROOT / 'bridge/src/session_ux.cpp', ROOT / 'bridge/src/mcp.cpp',
               ROOT / 'bridge/src/mcp_session.cpp', AGENT / 'setup.py',
               AGENT / 'converge-update.py', AGENT / 'install.sh']
    hard_coded = [p.name for p in sources
                  if '"%s"' % version in p.read_text(encoding='utf-8') or "'%s'" % version in p.read_text(encoding='utf-8')]
    check(not hard_coded, 'no second hard-coded copy of the version (%s)' % (hard_coded or 'none'))

    for argument in sys.argv[1:]:
        binary = Path(argument)
        data = binary.read_bytes() if binary.is_file() else b''
        check(version.encode() in data, '%s carries version %s' % (binary.name, version))

    print('version: %s' % version)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
