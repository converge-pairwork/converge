#!/bin/sh
# Installs converge-bridge, the MCP server that connects an AI session to CONVERGE.
#
#   curl -fsSL https://converge.pairwork.net/agent/install.sh | sh
#
# Everything it installs comes from a published release of the public CONVERGE source
# repository, github.com/converge-pairwork/converge. It reads that release's manifest, takes
# the binary named there for this operating system and architecture, verifies its SHA-256
# against the manifest, and refuses to install anything that does not match. Where a release
# has no binary for this machine it builds one from that same release's source tarball.
#
# Installs to ~/.local/bin. Nothing is run as root, and nothing is registered with your AI
# client: the last line tells you the command for that.
set -eu

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
# Nothing read here is ever executed or expanded by a shell: it is a file name and a digest,
# and the shape of both is checked before either is used.
manifest_field() {
    python3 - "$TMP/manifest.json" "$1" "$2" <<'PY'
import json, re, sys
try:
    doc = json.load(open(sys.argv[1]))
    item = doc.get('bridge', {}).get(sys.argv[2])
    value = (item or {}).get(sys.argv[3], '')
except Exception:
    value = ''
if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,128}', value):
    value = ''
print(value)
PY
}

ASSET=""
WANT=""
if have python3 && [ -n "$KEY" ] && curl -fsSL -o "$TMP/manifest.json" "$RELEASE/manifest.json" 2>/dev/null; then
    ASSET="$(manifest_field "$KEY" path)"
    WANT="$(manifest_field "$KEY" sha256)"
fi

if [ -n "$ASSET" ] && [ -n "$WANT" ]; then
    curl -fsSL -o "$TMP/bridge" "$RELEASE/$ASSET" || die "could not download $ASSET"
    say "-> downloaded $ASSET"
    got="$(sha256_of "$TMP/bridge")"
    [ "$WANT" = "$got" ] || die "checksum mismatch for $ASSET (expected $WANT, got $got) - not installing"
    say "-> sha256 verified against the release manifest"
    replace_bridge "$TMP/bridge"
else
    if [ -n "$KEY" ]; then
        say "-> no verified binary for $KEY in this release; building from source"
    else
        say "-> no published binary for $OS-$ARCH; building from source"
    fi
    for t in cmake c++ tar; do have "$t" || die "$t is required to build from source"; done
    curl -fsSL -o "$TMP/src.tar.gz" "$RELEASE/converge-src.tar.gz" \
        || die "could not fetch the source tarball from $RELEASE"
    # The source tarball is checksummed in the same release's SHA256SUMS. A build from
    # unverified source is a build of whatever happened to arrive.
    curl -fsSL -o "$TMP/sums" "$RELEASE/SHA256SUMS" \
        || die "could not fetch SHA256SUMS; refusing to build unverified source"
    want="$(awk '$2 == "converge-src.tar.gz" || $2 == "*converge-src.tar.gz" {print $1}' "$TMP/sums" | head -1)"
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
