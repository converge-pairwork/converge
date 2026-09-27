#!/bin/sh
# Installs converge-bridge, the one executable that connects an AI session to CONVERGE.
#
#   curl -fsSLo install.sh https://converge.pairwork.net/agent/install.sh
#   less install.sh
#   sh install.sh --client claude
#
# or, in one line: curl -fsSL https://converge.pairwork.net/agent/install.sh | sh -s -- --client claude
#
# With arguments, it runs `converge-bridge setup` with them once the bridge is installed, so one
# command connects Claude Code or Codex (`--client`, and `--invite cvi_...` for an invited guest).
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
# ~/.local/bin. Nothing is run as root. Without arguments nothing is registered with your AI
# client: the last lines tell you the one command for that.
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

# Setup, when asked for. Its standard input is not this script: under `curl | sh` that is the
# rest of the script itself.
if [ "$#" -gt 0 ]; then
    "$PREFIX/converge-bridge" setup "$@" </dev/null \
        || die "the bridge is installed, but setup did not finish (the reason is just above); once it is dealt with, run the same command again, or: \"$PREFIX/converge-bridge\" setup $*"
    say ""
    # Whether the AI client may use CONVERGE's tools without asking is the person's decision, made
    # in the client's own terms (setup --allow-tools). Asked only of a person at a terminal (this
    # script's stdin is often the download itself, so the answer is read from the terminal);
    # where there is none, as when an AI runs this, nothing is asked and nothing is set. Anything
    # but y leaves the client's settings as they were.
    client="$("$PREFIX/converge-bridge" setup --status 2>/dev/null | sed -n 's/.*"client": *"\([a-z]*\)".*/\1/p' | head -n 1)"
    case "$client" in
      claude) app="Claude Code"; how="/permissions in Claude Code, allow mcp__converge" ;;
      codex)  app="Codex"; how="default_tools_approval_mode = \"approve\" under [mcp_servers.converge] in ~/.codex/config.toml" ;;
      *)      app="" ;;
    esac
    if [ -n "$app" ]; then
        allowed=""
        if [ -t 1 ] && (: </dev/tty) 2>/dev/null; then
            say "$app asks before an AI uses tools it does not know yet, and may refuse them in its"
            say "more automatic modes. Let $app use Converge's tools without asking each time? [y/N]"
            printf '%s' "> "
            answer=""
            read -r answer </dev/tty || answer=""
            case "$answer" in
              y|Y|yes|YES|Yes)
                "$PREFIX/converge-bridge" setup --allow-tools >/dev/null && allowed=1
                say "Allowed. To take it back: \"$PREFIX/converge-bridge\" setup --disallow-tools" ;;
              *) say "Nothing changed." ;;
            esac
            say ""
        fi
        if [ -z "$allowed" ]; then
            say "If $app blocks or asks about Converge's tools, allowing them is your choice:"
            say "$how (or: \"$PREFIX/converge-bridge\" setup --allow-tools)."
            say ""
        fi
    fi
    say "Converge is set up. Start a new session of your AI client and say:"
    say ""
    say "  Continue my Converge setup."
    say ""
    say "Full walkthrough: $SITE/agent/setup.md"
    exit 0
fi

say "Next, from the AI session you want to connect (Claude Code or Codex):"
say ""
say "  \"$PREFIX/converge-bridge\" setup --client claude"
say ""
say "It installs the skill, registers the MCP server, and prints what to do next."
say "Full walkthrough: $SITE/agent/setup.md"
say "Source, licence and releases: https://github.com/$REPO"
