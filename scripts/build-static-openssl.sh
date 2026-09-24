#!/bin/sh
# Builds OpenSSL as static archives from the pinned source release, for linking into the bridge
# so that the published executable needs no OpenSSL on the machine that runs it. Used by the
# macOS release build (Linux gets Alpine's own static OpenSSL, Windows vcpkg's static triplet).
#
#   scripts/build-static-openssl.sh <prefix>      -> <prefix>/lib/libssl.a, libcrypto.a, include/
#
# The tarball is pinned by digest: it is a build input of a published binary.
set -eu
PREFIX="$(cd "$(dirname "$1")" 2>/dev/null && pwd || pwd)/$(basename "$1")"
VERSION=3.5.1
SHA256=529043b15cffa5f36077a4d0af83f3de399807181d607441d734196d889b641f
URL="https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
curl -fsSL -o openssl.tar.gz "$URL"
if command -v sha256sum >/dev/null; then echo "$SHA256  openssl.tar.gz" | sha256sum -c - >/dev/null
else echo "$SHA256  openssl.tar.gz" | shasum -a 256 -c - >/dev/null; fi
tar -xzf openssl.tar.gz
cd "openssl-$VERSION"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  TARGET=darwin64-arm64-cc ;;
  Darwin-x86_64) TARGET=darwin64-x86_64-cc ;;
  Linux-x86_64)  TARGET=linux-x86_64 ;;
  Linux-aarch64) TARGET=linux-aarch64 ;;
  *) echo "no OpenSSL target for $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac
# no-shared: archives only. no-tests, no-apps: the library is all the bridge links; the `openssl`
# command the tests use comes from the system or Homebrew, not from here.
./Configure "$TARGET" no-shared no-tests no-apps no-docs --prefix="$PREFIX" --libdir=lib >/dev/null
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)" >/dev/null
make install_sw >/dev/null
echo "OpenSSL $VERSION static archives in $PREFIX/lib"
