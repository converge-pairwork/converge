#!/usr/bin/env python3
"""Signs a CONVERGE release manifest, offline, with the owner's key.

    python3 sign-manifest.py --key ~/keys/converge-release.pem --public-key
    python3 sign-manifest.py --key ~/keys/converge-release.pem \
        --manifest manifest.json --out manifest.json.sig

This is an owner's tool, not a build step. CI never runs it, never has the key, and cannot: the
release workflow builds, packages and drafts, and the signature is added afterwards by a person
on a machine that is not the one serving releases. That is the whole point of a detached
signature. A binary and a checksum served from the same release are not two independent
statements, because whoever could replace one could replace the other; a signature made
somewhere else, under a key that was never uploaded anywhere, is the part that is about
authorship rather than transport.

It is a single file with no imports outside the standard library and no dependency on the
CONVERGE source tree: copy it to the offline machine that holds the key and it works there. It
needs an `openssl` that can do Ed25519 `-rawin`, which is OpenSSL 3; macOS ships LibreSSL under
that name, so on macOS use the one from `brew install openssl@3`.

What it will not do, deliberately:

  - it never generates a key, and never writes one
  - it never searches for a key: the path is given, once, explicitly
  - it never reads a key out of the environment, a repository or a release
  - it never prints the private half, nor any part of it, on any path including errors
  - it never modifies, reformats or re-serialises the manifest: it signs the exact bytes
  - it refuses to overwrite an existing signature unless told to
  - it refuses a manifest that is not a well-formed CONVERGE release manifest

Generating the key is a separate, deliberate act by the owner, done once, offline:

    openssl genpkey -algorithm ed25519 -out converge-release.pem
    chmod 600 converge-release.pem

Then `--public-key` prints the base64 of the raw public key, which is what goes into
RELEASE_KEYS in agent/converge-update.py, and its fingerprint, which is what gets published.
docs/RELEASE.md has the procedure around all of this.
"""
import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_KEY = 64 * 1024
MAX_MANIFEST = 256 * 1024


def die(message):
    """Anything that goes wrong ends here, with a message that never contains key material:
    the only thing this ever says about the key is the path it was given."""
    print('sign-manifest: ' + message, file=sys.stderr)
    raise SystemExit(2)


def openssl(args, binary='openssl'):
    try:
        done = subprocess.run([binary] + args, capture_output=True)
    except OSError as e:
        die('cannot run %s: %s' % (binary, e.strerror or type(e).__name__))
    if done.returncode != 0:
        # openssl's diagnostics describe the operation, not the key, but the key path is the
        # only thing worth naming here anyway.
        die('%s %s failed' % (binary, args[0]))
    return done.stdout


def read_private_key(path):
    """The key, from exactly the path that was given. A PEM private key and nothing else: a
    public key, a certificate or a manifest handed over by mistake is refused here rather than
    producing a confusing failure three steps later."""
    key = Path(path).expanduser()
    if not key.is_file():
        die('no such key file: %s' % key)
    if key.stat().st_size > MAX_KEY:
        die('%s is too large to be a private key' % key)
    try:
        text = key.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        die('%s is not a readable PEM file' % key)
    if '-----BEGIN PRIVATE KEY-----' not in text or '-----END PRIVATE KEY-----' not in text:
        die('%s is not a PEM private key' % key)
    if os.name != 'nt' and (key.stat().st_mode & 0o077):
        print('sign-manifest: warning: %s is readable by others; chmod 600 it' % key, file=sys.stderr)
    return key


def public_key_b64(key_path, binary):
    """The raw 32-byte Ed25519 public key, base64. OpenSSL prints a DER SubjectPublicKeyInfo,
    whose last 32 bytes are the key itself; the 12-byte prefix is the algorithm identifier. A
    key of any other type produces a different length, and is refused rather than truncated."""
    der = openssl(['pkey', '-in', str(key_path), '-pubout', '-outform', 'DER'], binary)
    if len(der) != 44:
        die('%s is not an Ed25519 key' % key_path)
    return base64.b64encode(der[-32:]).decode()


def fingerprint(public_b64):
    """The published form of the key: the SHA-256 of the raw 32 bytes, grouped for reading
    aloud. Two people comparing a key over a phone call compare this."""
    digest = hashlib.sha256(base64.b64decode(public_b64)).hexdigest()
    return 'SHA256:' + ' '.join(digest[i:i + 8] for i in range(0, 64, 8))


def check_manifest(body):
    """Is this a CONVERGE release manifest? Signing is a statement about a specific document,
    so the owner is not allowed to sign an arbitrary file by giving it the wrong path."""
    if len(body) > MAX_MANIFEST:
        die('manifest is implausibly large (%d bytes)' % len(body))
    try:
        doc = json.loads(body.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        die('manifest is not UTF-8 JSON')
    if not isinstance(doc, dict) or doc.get('product') != 'converge':
        die('this is not a CONVERGE release manifest')
    for field in ('schema', 'version', 'tag'):
        if field not in doc:
            die('manifest has no %s' % field)
    if body != json.dumps(doc, indent=2, sort_keys=True).encode('utf-8') + b'\n':
        die('manifest is not in the canonical serialisation the release tooling writes; '
            'sign the manifest as published, do not reformat it')
    return doc


def verify(public_b64, body, signature, binary):
    """Check the signature that was just made, with the public half, before writing it out. A
    signature that does not verify is a signature that would have failed in the field, and it
    is better to find that here than on somebody's machine."""
    with tempfile.TemporaryDirectory(prefix='converge-verify-') as scratch:
        pub = Path(scratch) / 'pub.der'
        pub.write_bytes(bytes.fromhex('302a300506032b6570032100') + base64.b64decode(public_b64))
        message = Path(scratch) / 'manifest'
        message.write_bytes(body)
        sig = Path(scratch) / 'sig.bin'
        sig.write_bytes(signature)
        done = subprocess.run([binary, 'pkeyutl', '-verify', '-pubin', '-inkey', str(pub),
                               '-keyform', 'DER', '-rawin', '-in', str(message),
                               '-sigfile', str(sig)], capture_output=True)
        return done.returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--key', required=True, metavar='PATH',
                        help='the Ed25519 private key, PEM. Given explicitly, never searched for.')
    parser.add_argument('--manifest', metavar='PATH', help='the manifest.json to sign, byte for byte')
    parser.add_argument('--out', metavar='PATH',
                        help='where to write the detached signature; default: MANIFEST.sig')
    parser.add_argument('--public-key', action='store_true',
                        help='print the public half and its fingerprint, and stop unless --manifest')
    parser.add_argument('--force', action='store_true', help='overwrite an existing signature file')
    parser.add_argument('--openssl', default='openssl', metavar='PATH',
                        help='an openssl that supports Ed25519 -rawin (macOS: brew openssl@3)')
    args = parser.parse_args()

    if not args.manifest and not args.public_key:
        parser.error('give --manifest to sign, or --public-key to print the public half')

    key_path = read_private_key(args.key)
    public = public_key_b64(key_path, args.openssl)

    if args.public_key:
        print('public key (RELEASE_KEYS entry): %s' % public)
        print('fingerprint:                     %s' % fingerprint(public))
        if not args.manifest:
            return 0

    manifest = Path(args.manifest).expanduser()
    if not manifest.is_file():
        die('no such manifest: %s' % manifest)
    body = manifest.read_bytes()
    doc = check_manifest(body)

    out = Path(args.out).expanduser() if args.out else manifest.with_name(manifest.name + '.sig')
    if out.exists() and not args.force:
        die('%s already exists; --force to replace it' % out)

    with tempfile.TemporaryDirectory(prefix='converge-sign-') as scratch:
        raw = Path(scratch) / 'sig.bin'
        # -rawin is Ed25519's own mode: the message is signed whole, not a digest of it.
        openssl(['pkeyutl', '-sign', '-inkey', str(key_path), '-rawin',
                 '-in', str(manifest), '-out', str(raw)], args.openssl)
        signature = raw.read_bytes()
        if len(signature) != 64:
            die('the signature is not 64 bytes; is %s an Ed25519 key?' % key_path)
        if not verify(public, body, signature, args.openssl):
            die('the signature does not verify against its own public key')

    if manifest.read_bytes() != body:
        die('the manifest changed while it was being signed; nothing written')

    out.write_text(base64.b64encode(signature).decode() + '\n', encoding='utf-8', newline='\n')
    print('signed  %s  (%s %s)' % (manifest.name, doc.get('tag'), doc.get('commit', '')[:12]))
    print('wrote   %s' % out)
    print('verify with the client\'s own verifier before publishing:')
    print('    python3 scripts/release-verify.py --manifest %s --signature %s --key %s'
          % (manifest.name, out.name, public))
    return 0


if __name__ == '__main__':
    sys.exit(main())
