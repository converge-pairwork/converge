#!/usr/bin/env python3
"""Signs a release manifest, and prints the public key that verifies it.

    python3 scripts/sign-manifest.py --public-key           # from the key in the environment
    python3 scripts/sign-manifest.py dist/manifest.json     # writes dist/manifest.json.sig

Why this exists. A binary and a checksum served from the same release are not two independent
statements: whoever could replace one could replace the other, and a reader who checks the
second against the first has learned that the download was not corrupted in transit, which is a
different and much smaller claim than knowing who published it. A detached signature over the
manifest is the part that is about authorship. It is made once, by the holder of a key that is
not on the release host, and every installation can check it against a public key that is in
the client's own source code rather than fetched alongside the thing it is meant to vouch for.

The key. Ed25519, held by the project owner, never in this repository and never on a machine
that serves releases. In CI it is a repository secret read from the environment; the workflow
that uses it runs only for a tag, and it is never exposed to a pull request. Generating it is a
deliberate act by a person:

    openssl genpkey -algorithm ed25519 -out converge-release.pem   # keep this offline
    CONVERGE_SIGNING_KEY="$(cat converge-release.pem)" \\
        python3 scripts/sign-manifest.py --public-key              # paste into RELEASE_KEYS

This script never generates a key, never writes one, and never prints the private half.
"""
import argparse
import base64
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = 'CONVERGE_SIGNING_KEY'


def signing_key():
    """The private key, from the environment only. Nothing here reads a key out of the
    repository, out of a release, or from a path a caller supplies: a signing key that can be
    pointed at is a signing key that can be substituted."""
    pem = os.environ.get(ENV, '').strip()
    if not pem:
        print('%s is not set. This is the owner-held release key; see the module docstring.' % ENV,
              file=sys.stderr)
        raise SystemExit(2)
    if 'PRIVATE KEY' not in pem:
        print('%s does not look like a PEM private key' % ENV, file=sys.stderr)
        raise SystemExit(2)
    return pem + '\n'


def openssl(args, **kwargs):
    return subprocess.run(['openssl'] + args, check=True, capture_output=True, **kwargs)


def public_key_b64(key_path):
    """The raw 32-byte Ed25519 public key, base64. OpenSSL prints a DER SubjectPublicKeyInfo,
    whose last 32 bytes are the key itself; the 12-byte prefix is the algorithm identifier."""
    der = openssl(['pkey', '-in', str(key_path), '-pubout', '-outform', 'DER']).stdout
    if len(der) != 44:
        print('unexpected public key encoding (%d bytes)' % len(der), file=sys.stderr)
        raise SystemExit(1)
    return base64.b64encode(der[-32:]).decode()


def verify_with_the_client(manifest, signature, public_key):
    """Check the signature with the same code the installed updater will use. Signing with one
    implementation and verifying with another is how a release ships a signature that nothing
    in the field can check."""
    spec = importlib.util.spec_from_file_location('converge_update', ROOT / 'agent/converge-update.py')
    updater = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(updater)
    return updater.ed25519_verify(base64.b64decode(public_key), signature, manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('manifest', nargs='?', help='the manifest.json to sign')
    parser.add_argument('--public-key', action='store_true',
                        help='print the public half of the key, for RELEASE_KEYS in agent/converge-update.py')
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix='converge-sign-') as scratch:
        key_path = Path(scratch) / 'key.pem'
        key_path.write_text(signing_key(), encoding='utf-8')
        os.chmod(key_path, 0o600)
        public = public_key_b64(key_path)

        if args.public_key:
            print(public)
            if not args.manifest:
                return 0

        if not args.manifest:
            parser.error('give a manifest to sign, or --public-key')
        manifest = Path(args.manifest)
        body = manifest.read_bytes()
        raw = Path(scratch) / 'sig.bin'
        # -rawin is Ed25519's own mode: the message is signed whole, not a digest of it.
        openssl(['pkeyutl', '-sign', '-inkey', str(key_path), '-rawin',
                 '-in', str(manifest), '-out', str(raw)])
        signature = raw.read_bytes()

        if not verify_with_the_client(body, signature, public):
            print('the signature does not verify with the client\'s own verifier', file=sys.stderr)
            return 1

        out = manifest.with_name(manifest.name + '.sig')
        out.write_text(base64.b64encode(signature).decode() + '\n', encoding='utf-8')
        print('signed %s -> %s' % (manifest.name, out.name))
        print('public key: %s' % public)
    return 0


if __name__ == '__main__':
    sys.exit(main())
