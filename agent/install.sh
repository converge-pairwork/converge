#!/bin/sh
# Installs converge-bridge, the MCP server that connects an AI session to CONVERGE.
#
#   curl -fsSL https://converge.pairwork.net/agent/install.sh | sh
#
# Everything it installs comes from a published release of the public CONVERGE source
# repository, github.com/converge-pairwork/converge. It reads that release's manifest, takes
# the binary named there for this operating system and architecture, verifies its byte size and
# SHA-256 against the manifest, and refuses to install anything that does not match. Where a
# release has no binary for this machine it builds one from that same release's source tarball.
#
# Where a release key is pinned below, the manifest's detached signature is checked first, with
# a key that came with this script rather than with the release it is vouching for, and nothing
# is installed if that fails. See the note at RELEASE_KEY.
#
# Installs to ~/.local/bin. Nothing is run as root, and nothing is registered with your AI
# client: the last line tells you the command for that.
set -eu

# The public half of the CONVERGE release key, base64 of the raw 32 bytes. The same key as
# RELEASE_KEYS in converge-update.py: what verifies the first install and what verifies every
# update after it are deliberately the same key, so trust does not change hands at any point.
#
# This script usually arrives from converge.pairwork.net while the release it checks comes from
# github.com. Those are two different origins, and a key carried here is a key the release
# cannot supply for itself. That is the whole value of it; it is also its limit, and
# docs/RELEASE.md is plain about what a first install does and does not establish.
#
# Empty means no signature is required and the release is trusted on TLS plus the digests and
# sizes the manifest states. It is not empty: this is the production CONVERGE release-signing
# public key, fingerprint
# SHA256:cdd8d54f 0c027837 f387bcfa 0536c738 2b49acd7 43966ad9 7d98dbaa 99555ae8.
RELEASE_KEY="${CONVERGE_RELEASE_KEY-6STokPtBRPz4vlJ8C/n1yb8MD47bXYQz+x7mhUJLxTs=}"

REPO="${CONVERGE_REPO:-converge-pairwork/converge}"
# The release to install. A version pins it; the default is whatever is current.
VERSION="${CONVERGE_VERSION:-latest}"
if [ "$VERSION" = latest ]; then
    RELEASE="${CONVERGE_RELEASE_BASE:-https://github.com/$REPO/releases/latest/download}"
else
    RELEASE="${CONVERGE_RELEASE_BASE:-https://github.com/$REPO/releases/download/v$VERSION}"
fi
SITE="${CONVERGE_BASE:-https://converge.pairwork.net}"
WSS="wss://${SITE#https://}/v1/ws"
PREFIX="${PREFIX:-$HOME/.local/bin}"
OS="$(uname -s)"
ARCH="$(uname -m)"

say() { printf '%s\n' "$*"; }
die() { printf 'converge: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have curl || die "curl is required"
have sha256sum || have shasum || die "sha256sum or shasum is required to verify the download"

sha256_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$PREFIX"
TMP="$(mktemp -d)"
INSTALL_TMP=""
trap 'rm -rf "$TMP"; [ -z "$INSTALL_TMP" ] || rm -f "$INSTALL_TMP"' EXIT

replace_bridge() {
    INSTALL_TMP="$(mktemp "$PREFIX/.converge-bridge.new.XXXXXX")"
    install -m 755 "$1" "$INSTALL_TMP"
    mv -f "$INSTALL_TMP" "$PREFIX/converge-bridge"
    INSTALL_TMP=""
}

# This machine, in the words the release manifest uses. An unknown one is not an error: it
# means there is no published binary and the source build below is the whole answer.
case "$OS" in
  Linux)  os=linux ;;
  Darwin) os=macos ;;
  *)      os="" ;;
esac
case "$ARCH" in
  x86_64|amd64) arch=x86_64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) arch="" ;;
esac
KEY=""
[ -n "$os" ] && [ -n "$arch" ] && KEY="$os-$arch"

# One field out of the release manifest, read with the interpreter CONVERGE already requires.
# Nothing read here is ever executed or expanded by a shell: it is a file name, a digest or a
# byte count, and the shape of each is checked before any of it is used. A manifest that names
# the same thing twice, or that is written to a schema this script does not know, is refused
# outright rather than resolved one way or the other.
manifest_field() {
    python3 - "$TMP/manifest.json" "$1" "$2" "$3" <<'PY'
import json, re, sys


def unique(pairs):
    seen = set()
    for name, _ in pairs:
        if name in seen:
            raise ValueError('duplicate key')
        seen.add(name)
    return dict(pairs)


try:
    with open(sys.argv[1], 'rb') as stream:
        doc = json.loads(stream.read().decode('utf-8'), object_pairs_hook=unique)
    if not isinstance(doc, dict) or doc.get('product') != 'converge':
        raise ValueError('not a CONVERGE manifest')
    schema = doc.get('schema', 1)
    if not isinstance(schema, int) or isinstance(schema, bool) or not 1 <= schema <= 2:
        raise ValueError('unsupported schema')
    # Two platforms naming the same file is an ambiguous mapping, not a choice to make.
    paths = [v.get('path') for v in (doc.get('bridge') or {}).values() if isinstance(v, dict)]
    if len(paths) != len(set(paths)):
        raise ValueError('ambiguous platform mapping')
    section = doc.get(sys.argv[2]) or {}
    item = section.get(sys.argv[3]) if isinstance(section, dict) else None
    value = (item or {}).get(sys.argv[4], '')
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
except Exception:
    value = ''
if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,128}', value):
    value = ''
print(value)
PY
}

# The manifest's detached signature, checked with the key this script carries. The verification
# is RFC 8032 Ed25519 and nothing else: it holds no secret, generates nothing, and only ever
# says yes or no. It is written out here rather than fetched, because a verifier that arrived
# with the thing it is meant to vouch for would not be vouching for anything.
verify_signature() {
    python3 - "$1" "$TMP/manifest.json" "$TMP/manifest.json.sig" <<'PY'
import base64, hashlib, sys

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)
B = (15112221349535400772501151409588531511454012693041857206046113283949847762202,
     46316835694926478169428394003475163141307993866256225615783033603165251855960,
     1,
     46827403850823179245072216630277197565144205554125654976674165829533817101731)


def recover_x(y, sign):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * I % P
    if (x * x - xx) % P != 0:
        return None
    if x & 1 != sign:
        x = P - x
    return x


def add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    m = (y1 - x1) * (y2 - x2) % P
    n = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    e = z1 * 2 * z2 % P
    f, g, h, j = n - m, e - c, e + c, n + m
    return (f * g % P, h * j % P, g * h % P, f * j % P)


def mult(point, e):
    out = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            out = add(out, point)
        point = add(point, point)
        e >>= 1
    return out


def decode(data):
    y = int.from_bytes(data, 'little') & ((1 << 255) - 1)
    if y >= P:
        return None
    x = recover_x(y, data[31] >> 7)
    return None if x is None else (x, y, 1, x * y % P)


def verify(public, signature, message):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = decode(public)
    r = decode(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], 'little')
    if s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), 'little') % L
    left = mult(B, s)
    right = add(r, mult(a, h))
    lx = left[0] * pow(left[2], P - 2, P) % P
    ly = left[1] * pow(left[2], P - 2, P) % P
    rx = right[0] * pow(right[2], P - 2, P) % P
    ry = right[1] * pow(right[2], P - 2, P) % P
    return lx == rx and ly == ry


try:
    key = base64.b64decode(sys.argv[1].strip(), validate=True)
    with open(sys.argv[2], 'rb') as stream:
        body = stream.read()
    with open(sys.argv[3], 'rb') as stream:
        signature = base64.b64decode(stream.read().split()[0], validate=True)
    ok = verify(key, signature, body)
except Exception:
    ok = False
sys.exit(0 if ok else 1)
PY
}

ASSET=""
WANT=""
BYTES=""
HAVE_MANIFEST=""
if have python3 && curl -fsSL -o "$TMP/manifest.json" "$RELEASE/manifest.json" 2>/dev/null; then
    HAVE_MANIFEST=yes
fi

# Authenticity, where a key is pinned. This is fail closed on purpose and in every direction: a
# manifest that could not be fetched, a signature that is missing, a signature that does not
# verify, and a python3 that is not there, all stop the install rather than falling through to
# the unsigned path. A pinned key that can be skipped is not a pinned key.
if [ -n "$RELEASE_KEY" ]; then
    have python3 || die "python3 is required to verify the release signature"
    [ -n "$HAVE_MANIFEST" ] || die "could not fetch the release manifest from $RELEASE - not installing"
    curl -fsSL -o "$TMP/manifest.json.sig" "$RELEASE/manifest.json.sig" \
        || die "this release carries no manifest signature - not installing"
    verify_signature "$RELEASE_KEY" \
        || die "the release manifest signature does not verify against the CONVERGE release key - not installing"
    say "-> release manifest signature verified"
fi

if [ -n "$HAVE_MANIFEST" ] && [ -n "$KEY" ]; then
    ASSET="$(manifest_field bridge "$KEY" path)"
    WANT="$(manifest_field bridge "$KEY" sha256)"
    BYTES="$(manifest_field bridge "$KEY" size)"
fi

if [ -n "$ASSET" ] && [ -n "$WANT" ]; then
    curl -fsSL -o "$TMP/bridge" "$RELEASE/$ASSET" || die "could not download $ASSET"
    say "-> downloaded $ASSET"
    if [ -n "$BYTES" ]; then
        got_bytes="$(wc -c < "$TMP/bridge" | tr -d " ")"
        [ "$BYTES" = "$got_bytes" ] \
            || die "size mismatch for $ASSET (expected $BYTES bytes, got $got_bytes) - not installing"
    fi
    got="$(sha256_of "$TMP/bridge")"
    [ "$WANT" = "$got" ] || die "checksum mismatch for $ASSET (expected $WANT, got $got) - not installing"
    say "-> size and sha256 verified against the release manifest"
    replace_bridge "$TMP/bridge"
else
    # With a key pinned, the signed manifest is the authority on what this release contains. If
    # it names no bridge for this machine there is nothing here to fall back to that the key
    # would still be vouching for, so the source build below is not offered silently.
    if [ -n "$RELEASE_KEY" ] && [ -n "$KEY" ]; then
        die "the signed manifest names no bridge for $KEY - not installing"
    fi
    if [ -n "$KEY" ]; then
        say "-> no verified binary for $KEY in this release; building from source"
    else
        say "-> no published binary for $OS-$ARCH; building from source"
    fi
    for t in cmake c++ tar; do have "$t" || die "$t is required to build from source"; done
    curl -fsSL -o "$TMP/src.tar.gz" "$RELEASE/converge-src.tar.gz" \
        || die "could not fetch the source tarball from $RELEASE"
    # A build from unverified source is a build of whatever happened to arrive. The manifest is
    # the better authority of the two, because where a key is pinned it is the one that has
    # been signed; SHA256SUMS is the fallback for a release that predates the manifest saying
    # anything about the tarball, and where a key is pinned there is no fallback at all.
    want=""
    if [ -n "$HAVE_MANIFEST" ]; then
        want="$(manifest_field extra converge-src.tar.gz sha256)"
    fi
    if [ -z "$want" ]; then
        [ -z "$RELEASE_KEY" ] || die "the signed manifest does not cover the source tarball - not building"
        curl -fsSL -o "$TMP/sums" "$RELEASE/SHA256SUMS" \
            || die "could not fetch SHA256SUMS; refusing to build unverified source"
        want="$(awk '$2 == "converge-src.tar.gz" || $2 == "*converge-src.tar.gz" {print $1}' "$TMP/sums" | head -1)"
    fi
    [ -n "$want" ] || die "no checksum published for converge-src.tar.gz"
    got="$(sha256_of "$TMP/src.tar.gz")"
    [ "$want" = "$got" ] || die "checksum mismatch for the source tarball - not building"
    say "-> source sha256 verified"
    mkdir -p "$TMP/src" && tar -xzf "$TMP/src.tar.gz" -C "$TMP/src"
    ROOT="$(find "$TMP/src" -maxdepth 3 -path '*/bridge/CMakeLists.txt' -print -quit)"
    [ -n "$ROOT" ] || die "unexpected source layout"
    ROOT="$(dirname "$ROOT")"
    say "-> building (this needs Boost headers and OpenSSL; a minute or two)"
    cmake -S "$ROOT" -B "$TMP/build" -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "$TMP/build" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >/dev/null
    replace_bridge "$TMP/build/converge-bridge"
fi

"$PREFIX/converge-bridge" --help >/dev/null 2>&1 || die "the installed binary does not run"
say ""
say "installed: $PREFIX/converge-bridge"
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) say "note: $PREFIX is not on your PATH - add it, or use the full path below" ;;
esac
say ""
say "Next: get a handle at $SITE (sign in with a Solana wallet under Wallet, add a member under Team), then register it:"
say ""
say "  claude mcp add converge -s user -- \"$PREFIX/converge-bridge\" --relay $WSS --handle cvh_YOUR_HANDLE"
say ""
say "Full walkthrough: $SITE/agent/setup.md"
say "Source, licence and releases: https://github.com/$REPO"
