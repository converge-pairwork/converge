#!/usr/bin/env python3
"""Refuses to let release automation touch a release a person has already published.

    python3 scripts/release-guard.py --tag v0.1.1
    python3 scripts/release-guard.py --tag v0.1.1 --release-json FILE   # decide on given JSON

Why this exists. On 2026-09-20 the v0.1.1 tag was moved and force-pushed. A tag push starts the
release workflow, and the workflow's upload step found the existing published v0.1.1 release and
replaced its assets with newly built ones. The owner's detached signature was not among them, so
what was left was a freshly built manifest.json beside a signature over the bytes it replaced.
Every installation refused the release, correctly and silently, and the only way back was
another offline signing.

A draft is CI's to fill. A published release has been read, signed and vouched for by a person,
and its bytes are what every installation checks against. Nothing automatic may write to it.

The rule, and it is the whole of the rule:

    no release for this tag        CI may create the draft
    a draft release for this tag   CI may fill its own draft again
    a published release            refused, and the run fails

Anything else, including an API call that does not come back or an answer this cannot read, is
refused too. The question is whether publishing is known to be safe, not whether it is known to
be unsafe, so silence is a refusal.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = 'https://api.github.com'


def fail(message):
    print('release guard: ' + message, file=sys.stderr)
    raise SystemExit(1)


def decide(release):
    """(may_proceed, why) for what the API said about this tag. `release` is None for no release.

    Kept apart from the fetching so the table above can be tested without a network or a token.
    """
    if release is None:
        return True, 'no release exists for this tag yet; CI may create the draft'
    if not isinstance(release, dict):
        return False, 'the release record is not an object, so nothing here can read it'
    if 'draft' not in release:
        return False, 'the release record does not say whether it is a draft'
    draft = release['draft']
    if draft is not True and draft is not False:
        return False, 'the release record\'s draft field is %r, which is neither true nor false' % draft
    if draft:
        return True, 'the release for this tag is still a draft; CI may fill it'
    return False, ('a PUBLISHED release already exists for this tag. Its assets are what every '
                   'installation verifies against, and the owner signed them. Automation does '
                   'not overwrite them. To build this tag again, publish it under a new version.')


def lookup(repository, tag, token):
    """The release for this tag, None if there is none. Any other outcome raises."""
    request = urllib.request.Request(
        '%s/repos/%s/releases/tags/%s' % (API, repository, tag),
        headers={'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28',
                 'User-Agent': 'converge-release-guard'})
    if token:
        request.add_header('Authorization', 'Bearer ' + token)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--tag', required=True, help='the tag this run would publish')
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'),
                        help='owner/name; the default is GITHUB_REPOSITORY')
    parser.add_argument('--release-json', metavar='FILE',
                        help='decide on this saved API response instead of asking GitHub; '
                             '"-" reads stdin and the literal "none" means no release exists')
    args = parser.parse_args()

    if args.release_json:
        if args.release_json == 'none':
            release = None
        else:
            text = sys.stdin.read() if args.release_json == '-' else \
                open(args.release_json, encoding='utf-8').read()
            if text.strip() in ('', 'none', 'null'):
                release = None
            else:
                try:
                    release = json.loads(text)
                except ValueError as error:
                    fail('the release record is not JSON: %s' % error)
    else:
        if not args.repository:
            fail('no repository given and GITHUB_REPOSITORY is not set')
        try:
            release = lookup(args.repository, args.tag,
                             os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN'))
        except Exception as error:
            # Refused rather than allowed: not knowing is not the same as knowing it is safe.
            fail('could not ask GitHub whether %s is already published (%s), refusing'
                 % (args.tag, error))

    ok, why = decide(release)
    if not ok:
        fail('%s: %s' % (args.tag, why))
    print('release guard: %s: %s' % (args.tag, why))


if __name__ == '__main__':
    main()
