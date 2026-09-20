#!/usr/bin/env python3
"""Verifies a release manifest's signature with the client's own verifier.

    python3 scripts/release-verify.py --manifest dist/manifest.json \
        --signature dist/manifest.json.sig [--key BASE64] [--dist dist/]

This is the step between signing a manifest offline and publishing the release. It answers the
question that matters to everyone who is not the owner: would an installed CONVERGE client
accept this? So it does not verify with openssl, and it does not verify with a second
implementation written for the purpose. It imports `ed25519_verify` out of
`agent/converge-update.py` and uses that, because signing with one implementation and verifying
with another is exactly how a release ships a signature that nothing in the field can check.

With no `--key` it uses the keys pinned in the shipped updater, which is the honest test: it
asks whether the release verifies for an installation that has this client, not whether it
verifies for somebody who was handed the right key. While RELEASE_KEYS is empty that has no
answer, and this says so and exits non-zero rather than passing: an unsigned or unpinnable
release is not authentic, and nothing here will report it as though it were.

With `--dist` it also checks every artifact the manifest names: present, the stated byte size,
the stated SHA-256. That is integrity, which the signature does not by itself give you; the two
together are what "this release is what CONVERGE published" means.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

failures = []


def check(ok, what):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok:
        failures.append(what)
    return ok


def updater():
    spec = importlib.util.spec_from_file_location('converge_update', ROOT / 'agent/converge-update.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--signature', required=True)
    parser.add_argument('--key', metavar='BASE64',
                        help='the public key to verify against; default: the keys pinned in the client')
    parser.add_argument('--dist', metavar='DIR',
                        help='also check every artifact the manifest names, in this directory')
    args = parser.parse_args()

    cu = updater()
    body = Path(args.manifest).read_bytes()
    signature_text = Path(args.signature).read_text(encoding='utf-8')

    # The manifest has to be readable by the client before its signature means anything: schema,
    # no duplicate keys, an object at the top.
    try:
        manifest, schema = cu.load_manifest(body)
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
        check(cu.ed25519_verify(public, signature, body),
              'the signature verifies over the manifest bytes as published')
        digest = hashlib.sha256(public).hexdigest()
        print('  key fingerprint: SHA256:%s' % ' '.join(digest[i:i + 8] for i in range(0, 64, 8)))
    else:
        verdict = cu.signed_by_converge(body, signature_text)
        if verdict is None:
            check(False, 'a key is pinned in agent/converge-update.py to verify against '
                         '(RELEASE_KEYS is empty: authenticity cannot be established)')
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
