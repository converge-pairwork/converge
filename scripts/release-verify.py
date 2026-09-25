#!/usr/bin/env python3
"""Verifies a release manifest's signature the way an installed client would.

    python3 scripts/release-verify.py --manifest dist/manifest.json \
        --signature dist/manifest.json.sig [--key BASE64] [--dist dist/]

This is the step between signing a manifest offline and publishing the release. It answers the
question that matters to everyone who is not the owner: would an installed CONVERGE client
accept this? The bridge carries its verifier and its pinned keys compiled in
(bridge/src/release_key.hpp); this tool verifies with scripts/ed25519.py against the keys read
out of that same header, so what is checked here is what the client will check.

With no `--key` it uses the keys pinned in the bridge, which is the honest test: it asks whether
the release verifies for an installation that has this client, not whether it verifies for
somebody who was handed the right key. With no key pinned that has no answer, and this says so
and exits non-zero rather than passing.

With `--dist` it also checks every artifact the manifest names: present, the stated byte size,
the stated SHA-256. That is integrity, which the signature does not by itself give you; the two
together are what "this release is what CONVERGE published" means.
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ed25519  # noqa: E402

failures = []


def check(ok, what):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok:
        failures.append(what)
    return ok


def unique(pairs):
    seen = set()
    for name, _ in pairs:
        if name in seen:
            raise ValueError('manifest names %r twice' % name)
        seen.add(name)
    return dict(pairs)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--signature', required=True)
    parser.add_argument('--key', metavar='BASE64',
                        help='the public key to verify against; default: the keys pinned in the bridge')
    parser.add_argument('--dist', metavar='DIR',
                        help='also check every artifact the manifest names, in this directory')
    args = parser.parse_args()

    body = Path(args.manifest).read_bytes()
    signature_text = Path(args.signature).read_text(encoding='utf-8')

    # The manifest has to be readable before its signature means anything: an object, no
    # duplicate keys, a schema the client knows.
    try:
        manifest = json.loads(body.decode('utf-8'), object_pairs_hook=unique)
        if not isinstance(manifest, dict):
            raise ValueError('manifest is not an object')
        schema = manifest.get('schema', 1)
        if not isinstance(schema, int) or isinstance(schema, bool) or not 1 <= schema <= 2:
            raise ValueError('manifest schema %r is not one the client reads' % (schema,))
        check(True, 'the client reads the manifest (schema %d, %s)' % (schema, manifest.get('tag')))
    except (ValueError, UnicodeDecodeError) as e:
        check(False, 'the client reads the manifest: %s' % e)
        return 1

    if args.key:
        try:
            public = base64.b64decode(args.key, validate=True)
        except Exception:
            check(False, '--key is base64')
            return 1
        check(len(public) == 32, '--key is a raw 32-byte Ed25519 public key')
        try:
            signature = base64.b64decode(signature_text.split()[0], validate=True)
        except Exception:
            check(False, 'the signature file is base64')
            return 1
        check(len(signature) == 64, 'the signature is 64 bytes')
        check(ed25519.verify(public, signature, body),
              'the signature verifies over the manifest bytes as published')
        digest = hashlib.sha256(public).hexdigest()
        print('  key fingerprint: SHA256:%s' % ' '.join(digest[i:i + 8] for i in range(0, 64, 8)))
    else:
        verdict = ed25519.signed_by_converge(body, signature_text)
        if verdict is None:
            check(False, 'a key is pinned in bridge/src/release_key.hpp to verify against '
                         '(none is: authenticity cannot be established)')
        else:
            check(verdict is True, 'the signature verifies against a key pinned in the client')

    if args.dist:
        dist = Path(args.dist)
        named = dict(manifest.get('files', {}))
        named.update({'bridge:' + k: v for k, v in manifest.get('bridge', {}).items()})
        named.update({'extra:' + k: v for k, v in manifest.get('extra', {}).items()})
        for key, item in sorted(named.items()):
            path = dist / item['path']
            if not check(path.is_file(), '%s: %s is present' % (key, item['path'])):
                continue
            data = path.read_bytes()
            check(len(data) == item.get('size'), '%s: %d bytes as stated' % (key, len(data)))
            check(hashlib.sha256(data).hexdigest() == item.get('sha256'), '%s: SHA-256 as stated' % key)

    print(json.dumps({'tag': manifest.get('tag'), 'version': manifest.get('version'),
                      'commit': manifest.get('commit')}, sort_keys=True))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
