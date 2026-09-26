#!/usr/bin/env python3
"""Does the client's own text still say the true thing about price and about the protocol?

    python3 scripts/text-check.py

Three questions, asked over the files a user actually reads. Both used to be asked in the
CONVERGE service repository, which held a copy of this client while the two trees were being
separated. The copy is gone; the questions are not, so they moved here with the files they are
about.

    1. "Free Software" is a statement about rights, never about price.

       CONVERGE usage is paid: traffic is metered against an account balance, and an account
       without usable balance keeps every function with progressively delayed delivery. There
       is no free tier, no free session and no signup credit, and the licensing copy must never
       be written anywhere it could be read as one of those. So every occurrence of the word in
       user-facing text has to be a licensing sense, a compound that is plainly not a price
       claim (a dependency-free installer), or part of a sentence that denies a price claim.
       Anything else is a promise the service does not keep.

    2. The wire protocol description matches the relay a client actually talks to.

       agent/protocol.md is the reference an integrator reads before writing code against
       CONVERGE. Routes that were removed must not be documented as if they still answered, and
       the ones that replaced them must be there. A stale protocol document is a client that
       gets written against an endpoint returning 404.

    3. There is one route, and nothing offers another.

       The bridge reaches a peer through the relay over WSS, sealed end to end. An SSH gateway
       once offered a second route on which the server did the encrypting; it is gone, and so is
       the bridge's gateway login. Nothing a user reads may offer it again, and no bridge source
       may accept a gateway secret or send one.

It reads the working tree, exits non-zero on anything it finds, and prints the file, the line
and the text so that a person can judge a hit in a few seconds.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# What a user reads. LICENSE is the GPL verbatim and is not ours to edit or to lint; the
# workflow files and the test scripts are not user-facing text.
USER_FACING = ['README.md', 'SECURITY.md', 'CONTRIBUTING.md',
               'agent/skill.md', 'agent/setup.md', 'agent/protocol.md',
               'agent/install.sh', 'agent/install.ps1']

# The economics that do not exist, in the forms they would be written in. A phrase here is one
# that cannot be true of CONVERGE in any context, so it is banned outright rather than judged.
DEAD = ('free tier', 'free plan', 'free version', 'free trial', 'free forever',
        'free of charge', 'at no charge', 'no cost', 'free to use', 'use it free',
        'signup credit', 'sign-up credit', 'free allowance', 'free usage', 'free credits',
        'free credit', 'free session', 'free sessions', 'daily session',
        'holding threshold', 'qualification', 'qualifying', '200,000 free units')

# The licensing senses, and the compounds that are about how something is reached rather than
# what it costs. Matched at the start of the word, case insensitively.
ALLOWED = ('free software', 'free as in freedom', 'freedom', 'freely', 'free-form', 'free of i/o')
# A compound whose left half is the thing being done without: a dependency-free installer is a
# claim about setup, not about price.
COMPOUND = re.compile(r'[a-z]-free\b', re.IGNORECASE)
# A sentence that denies a price claim may name one. This is what lets the README say plainly
# that Free Software does not mean free usage, which is the sentence most worth having.
DENIAL = ('does not mean', 'do not mean', 'none of those', 'there is no', 'has no ',
          'is not a price', 'never about price', 'not about price')

WORD = re.compile(r'(?i)\bfree')


def sentence_around(text, at):
    start = max(text.rfind('. ', 0, at), text.rfind('\n\n', 0, at), 0)
    end = text.find('. ', at)
    end = len(text) if end == -1 else end + 1
    return text[start:end].lower()


def check_price_language():
    problems = []
    for name in USER_FACING:
        path = ROOT / name
        if not path.is_file():
            problems.append((name, 0, 'user-facing file is missing'))
            continue
        text = path.read_text(encoding='utf-8')
        lower = text.lower()
        for phrase in DEAD:
            at = lower.find(phrase)
            while at != -1:
                if not any(marker in sentence_around(text, at) for marker in DENIAL):
                    problems.append((name, text[:at].count('\n') + 1, 'reads as free usage: ' + phrase))
                at = lower.find(phrase, at + 1)
        for match in WORD.finditer(text):
            at = match.start()
            tail = lower[at:at + 24]
            if any(tail.startswith(sense) for sense in ALLOWED):
                continue
            if COMPOUND.search(text, max(0, at - 12), at + 5):
                continue
            sentence = sentence_around(text, at)
            if any(marker in sentence for marker in DENIAL):
                continue
            problems.append((name, text[:at].count('\n') + 1,
                             'price-sense "free": ' + text[at:at + 48].replace('\n', ' ')))
    # The other side of the same rule: the statement itself has to be there. A guard that only
    # forbids can be satisfied by saying nothing at all.
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    for required in ('Free Software', 'GPLv3', 'does not mean free usage'):
        if required not in readme:
            problems.append(('README.md', 0, 'the licensing statement no longer says: ' + required))
    return problems


# The relay as it answers today. Removed with the EVM sign-in, the plan catalogue and the
# browser credit purchase, then the whole authenticated JSON interface (account, members,
# usage, wallet sign-in, top-up, relay key), and last the invitation routes: invitations are
# redeemed and linked in the handshake. No JSON route is left but /healthz.
RETIRED_ROUTES = ('/v1/auth/', '/v1/plans', '/v1/plan/claim', '/v1/credits/claim', '/v1/solana/', '/v1/account',
                  '/v1/keys', '/v1/usage', '/v1/relay-key', '/v1/invites/', '/v1/invite/')
CURRENT_ROUTES = ('/healthz', '/link')
# The metering rate, in the words the protocol states it in. One product, one rate.
REQUIRED_TEXT = ('50,000 base units per MiB',)


def check_protocol():
    problems = []
    path = ROOT / 'agent' / 'protocol.md'
    if not path.is_file():
        return [('agent/protocol.md', 0, 'the wire protocol reference is missing')]
    text = path.read_text(encoding='utf-8')
    for route in RETIRED_ROUTES:
        at = text.find(route)
        if at != -1:
            problems.append(('agent/protocol.md', text[:at].count('\n') + 1,
                             'documents a route the relay no longer answers: ' + route))
    for needed in CURRENT_ROUTES + REQUIRED_TEXT:
        if needed not in text:
            problems.append(('agent/protocol.md', 0, 'no longer documents: ' + needed))
    return problems


# How the SSH route was offered, and how the bridge logged in on its behalf. Said again anywhere
# a user reads or in the bridge itself, it would be a second route coming back.
ROUTE_TEXT = ['README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'docs/ARCHITECTURE.md',
              'agent/skill.md', 'agent/setup.md', 'agent/protocol.md', 'agent/install.sh',
              'agent/install.ps1']
OTHER_ROUTE = re.compile(r'(?i)ssh -p|converge@|\b2222\b|gateway[-_ ]secret|gateway sessions|'
                         r'ssh alternative|ssh is an (?:optional|alternative)|"gateway"|\bcreds\.gateway')


def check_one_route():
    problems = []
    files = ROUTE_TEXT + sorted(str(f.relative_to(ROOT)).replace('\\', '/')
                                for f in (ROOT / 'bridge').rglob('*')
                                if f.suffix in ('.cpp', '.hpp') and 'build' not in f.parts)
    for name in files:
        path = ROOT / name
        if not path.is_file():
            continue
        text = path.read_text(encoding='utf-8')
        for m in OTHER_ROUTE.finditer(text):
            problems.append((name, text[:m.start()].count('\n') + 1,
                             'offers a route other than the relay, or a gateway login: ' + m.group(0)))
    return problems


def main():
    problems = check_price_language() + check_protocol() + check_one_route()
    for name, line, message in problems:
        print('%s:%d: %s' % (name, line, message), file=sys.stderr)
    if problems:
        print('text check: %d problem(s)' % len(problems), file=sys.stderr)
        return 1
    print('text check ok: %d user-facing files, the protocol reference, and one route' % len(USER_FACING))
    return 0


if __name__ == '__main__':
    sys.exit(main())
