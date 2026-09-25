#!/bin/sh
# Installs converge-bridge, the one executable that connects an AI session to CONVERGE.
#
#   curl -fsSL https://converge.pairwork.net/agent/install.sh | sh
#
# Everything it installs comes from a published release of the public CONVERGE source
# repository, github.com/converge-pairwork/converge. It reads that release's manifest, takes
# the binary named there for this operating system and architecture, checks its byte size and
# SHA-256 against the manifest, and then asks the binary itself to verify the manifest's
# signature against the CONVERGE release key it carries (`converge-bridge verify-release`).
# Nothing is installed if any of that fails. What a first install does and does not establish
# is written down plainly in docs/RELEASE.md; every update after it is checked by the installed
# bridge against the key compiled into it.
#
# Needs curl and sha256sum or shasum, and nothing else: no Python, no compiler. Installs to
# ~/.local/bin. Nothing is run as root, and nothing is registered with your AI client: the last
# lines tell you the one command for that.
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
PREFIX="${PREFIX:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'converge: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have curl || die "curl is required"
have sha256sum || have shasum || die "sha256sum or shasum is required to verify the download"

sha256_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# This machine, in the words the release manifest uses.
case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=macos ;;
  *)      die "no published CONVERGE bridge for $(uname -s); build it from source: https://github.com/$REPO" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch=x86_64 ;;
  arm64|aarch64) arch=arm64 ;;
  *)             die "no published CONVERGE bridge for $(uname -m); build it from source: https://github.com/$REPO" ;;
esac
KEY="$os-$arch"

TMP="$(mktemp -d)"
INSTALL_TMP=""
trap 'rm -rf "$TMP"; [ -z "$INSTALL_TMP" ] || rm -f "$INSTALL_TMP"' EXIT

curl -fsSL -o "$TMP/manifest.json" "$RELEASE/manifest.json" \
    || die "could not fetch the release manifest from $RELEASE; not installing"

# Three fields out of the manifest's entry for this machine. The manifest is written with sorted
# keys and a two-space indent (scripts/release-manifest.py), so the entry is the lines between
# its name and the closing brace; nothing read here is executed or expanded by a shell, and the
# shape of each value is checked before it is used.
manifest_field() {
    awk -v key="\"$1\": {" -v field="\"$2\":" '
        index($0, key) { inside = 1; next }
        inside && $0 ~ /^ *}/ { inside = 0 }
        inside && index($0, field) {
            sub(/^[^:]*: */, ""); sub(/,? *$/, ""); gsub(/"/, ""); print; exit
        }' "$TMP/manifest.json"
}
ASSET="$(manifest_field "$KEY" path)"
WANT="$(manifest_field "$KEY" sha256)"
BYTES="$(manifest_field "$KEY" size)"
case "$ASSET" in
  converge-bridge-*) ;;
  *) die "the release manifest names no bridge for $KEY; build it from source: https://github.com/$REPO" ;;
esac
printf '%s' "$WANT" | grep -Eq '^[0-9a-f]{64}$' || die "the release manifest carries no SHA-256 for $ASSET; not installing"
printf '%s' "$BYTES" | grep -Eq '^[0-9]+$' || die "the release manifest carries no size for $ASSET; not installing"

curl -fsSL -o "$TMP/bridge" "$RELEASE/$ASSET" || die "could not download $ASSET"
say "-> downloaded $ASSET"
got_bytes="$(wc -c < "$TMP/bridge" | tr -d ' ')"
[ "$BYTES" = "$got_bytes" ] || die "size mismatch for $ASSET (expected $BYTES bytes, got $got_bytes); not installing"
got="$(sha256_of "$TMP/bridge")"
[ "$WANT" = "$got" ] || die "checksum mismatch for $ASSET (expected $WANT, got $got); not installing"
say "-> size and sha256 verified against the release manifest"
chmod 755 "$TMP/bridge"

# The signature. The bridge carries the CONVERGE release key and the verifier; it fetches the
# manifest and its signature again itself, from the same release, and refuses a manifest that
# does not verify or that does not describe the file it was handed.
"$TMP/bridge" verify-release --release "$RELEASE" --file "$TMP/bridge" \
    || die "the release manifest signature does not verify against the CONVERGE release key; not installing"

mkdir -p "$PREFIX"
INSTALL_TMP="$(mktemp "$PREFIX/.converge-bridge.new.XXXXXX")"
cp "$TMP/bridge" "$INSTALL_TMP"
chmod 755 "$INSTALL_TMP"
mv -f "$INSTALL_TMP" "$PREFIX/converge-bridge"
INSTALL_TMP=""

"$PREFIX/converge-bridge" --help >/dev/null 2>&1 || die "the installed binary does not run"
say ""
say "installed: $PREFIX/converge-bridge"
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) say "note: $PREFIX is not on your PATH; add it, or use the full path below" ;;
esac
say ""
say "Next, from the AI session you want to connect (Claude Code or Codex):"
say ""
say "  \"$PREFIX/converge-bridge\" setup --client claude"
say ""
say "It installs the skill, registers the MCP server, and prints what to do next."
say "Full walkthrough: $SITE/agent/setup.md"
say "Source, licence and releases: https://github.com/$REPO"
