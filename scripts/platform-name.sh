#!/bin/sh
# This machine, in the words a CONVERGE release manifest uses: <os>-<arch>.
# One place answers this, so the Makefile, the installer and the release workflow cannot
# disagree about what a binary built here should be called.
set -eu
case "$(uname -s)" in
  Linux)                 os=linux ;;
  Darwin)                os=macos ;;
  MINGW*|MSYS*|CYGWIN*)  os=windows ;;
  *)                     echo "unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch=x86_64 ;;
  arm64|aarch64) arch=arm64 ;;
  *)             echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
printf '%s-%s\n' "$os" "$arch"
