#!/usr/bin/env python3
"""Is this tree safe to publish?

    python3 scripts/safety-check.py

This repository is world readable. That is the whole point of it, and it is also the reason a
mistake here cannot be taken back: a secret pushed once has been published, whatever happens to
the commit afterwards. So this asks the question mechanically, every time, rather than relying
on anyone remembering to look.

It reads every file in the working tree, not only the files that are committed and not only the
files that are staged, because the thing that gets published is what is in the tree when
somebody runs `git add`. Build outputs and anything git is told to ignore are skipped, except
that a build output found inside the tree is itself reported: a compiled object carries the
absolute paths of the machine that built it.

What it looks for, and why each one:

    credentials             the obvious catastrophe: keys, tokens, passwords, wallet material
    private key blocks      a PEM private key in a public repository is a published private key
    developer paths         /home/<someone>, /Users/<someone>: who built this and what else is
                            on their machine, which is nobody's business and is not needed here
    private infrastructure  server addresses, deployment hosts, internal names: the public
                            client has no reason to know where the relay is operated from
    private repository      paths and documents that belong to the private tree
    build artifacts         object files, CMake caches, __pycache__, dist directories

A hit is not always a secret, and this prints what it found and where rather than only a count,
so that a false positive can be read and dismissed by a person in a few seconds. It exits
non-zero on anything it found, which is what makes it useful in CI.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {'.git', 'build', 'dist', '__pycache__', 'node_modules', '.venv'}
# Files whose bytes are not text to be pattern matched. The SVG is text and is checked.
BINARY_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf',
                   '.zip', '.gz', '.tar', '.pdf', '.exe', '.o', '.a', '.so', '.dylib'}

PATTERNS = [
    ('private key block',   re.compile(r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----')),
    ('ssh private key',     re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----')),
    ('aws access key',      re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('github token',        re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}')),
    ('slack token',         re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}')),
    ('assigned secret',     re.compile(r'(?i)\b(?:password|passwd|api[_-]?key|secret[_-]?key|access[_-]?token|'
                                       r'private[_-]?key|client[_-]?secret)\s*[:=]\s*["\'][^"\'\n]{8,}["\']')),
    ('seed phrase',         re.compile(r'(?i)\b(?:mnemonic|seed phrase|recovery phrase)\s*[:=]')),
    ('CONVERGE bearer key', re.compile(r'\bcvg_[0-9a-f]{16,}')),
    ('developer home path', re.compile(r'(?:/home/|/Users/)(?!<|\$|\{|jo blogs)[a-z][a-z0-9._-]{2,}')),
    # A routable address written into client source is a server somebody operates. Loopback and
    # the private ranges are fine, and `routable_address` below says what else is not an
    # address at all.
    ('bare IPv4 address',   re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')),
    ('private host',        re.compile(r'(?i)\b(?:domm|converge\.mm-studios\.com)\b')),
    ('root shell target',   re.compile(r'\broot@[a-z0-9.-]+')),
    ('private tree path',   re.compile(r'\b(?:backend/src|webapp/src|gateway/converge-|deploy/converged|'
                                       r'doc/CONVERGE_[A-Z_]+|scripts/deploy-|scripts/backup-)')),
]

# Lines that match a pattern but are the thing the pattern is meant to let through. Each one is
# a deliberate, readable exception rather than a hole in the pattern itself.
ALLOWED = (
    'scripts/safety-check.py',        # this file names every pattern it looks for
)

def routable_address(text):
    """Is this candidate really a server address? Four octets in range, not loopback and not a
    private range, and with at least two octets of more than one digit, which is what tells an
    address apart from a version number such as 1.0.0.0 without needing to know the context it
    was written in. The cost is not catching something like 1.2.3.4, which nothing in a client
    would legitimately contain either way."""
    octets = text.split('.')
    if len(octets) != 4 or not all(o.isdigit() and int(o) < 256 for o in octets):
        return False
    if text.startswith(('127.', '10.', '192.168.', '172.16.', '0.')):
        return False
    return sum(1 for o in octets if len(o) > 1) >= 2


# A pattern whose match still has to answer a question before it counts as a finding.
VALIDATORS = {'bare IPv4 address': routable_address}

ARTIFACTS = ('.o', '.a', '.so', '.obj', '.pyc', '.dll', '.dylib')
ARTIFACT_NAMES = ('CMakeCache.txt', 'compile_commands.json', '.env')


def tracked_and_untracked():
    """Everything in the working tree that git would publish: what is committed, plus what is
    not committed but is not ignored either. The second half is the one that matters, because
    nothing in this repository is committed yet."""
    try:
        out = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '--cached', '--others',
                              '--exclude-standard'], capture_output=True, text=True,
                             encoding='utf-8', errors='replace', check=True)
        return [ROOT / line for line in out.stdout.splitlines() if line]
    except (OSError, subprocess.CalledProcessError):
        return [p for p in ROOT.rglob('*') if p.is_file()
                and not any(part in SKIP_DIRS for part in p.parts)]


def main():
    findings = []
    checked = 0
    for path in sorted(tracked_and_untracked()):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            findings.append((relative, 0, 'build artifact', 'inside ' + relative.split('/')[0]))
            continue
        if path.suffix in ARTIFACTS or path.name in ARTIFACT_NAMES:
            findings.append((relative, 0, 'build artifact', path.name))
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        checked += 1
        if relative in ALLOWED:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for name, pattern in PATTERNS:
                match = pattern.search(line)
                if match:
                    validator = VALIDATORS.get(name)
                    if validator and not validator(match.group(0)):
                        continue
                    excerpt = line.strip()
                    findings.append((relative, number, name,
                                     excerpt[:100] + ('...' if len(excerpt) > 100 else '')))

    print('safety check: read %d text files' % checked)
    if not findings:
        print('nothing found: no credentials, developer paths, private infrastructure or build '
              'artifacts in the publishable tree')
        return 0
    print('\n%d finding(s):\n' % len(findings))
    for relative, number, name, excerpt in findings:
        where = '%s:%d' % (relative, number) if number else relative
        print('  %-40s %-22s %s' % (where, name, excerpt))
    print('\nEach line above is either something that must not be published, or a pattern that '
          'needs a deliberate exception in this script. Neither is resolved by ignoring it.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
