#!/bin/sh
# Builds converge-bridge as one fully static Linux executable, in an Alpine container, so the
# result depends on nothing on the machine that runs it: no glibc floor, no OpenSSL, no
# libstdc++. The same commands run in the release workflow's Linux job (container: alpine).
#
#   scripts/build-static-linux.sh [x86_64|aarch64]     -> bridge/build-static-<arch>/converge-bridge
#
# Needs docker (or podman via DOCKER=podman). Boost is headers only, so Alpine's boost-dev is
# enough; OpenSSL comes from openssl-libs-static, which is Alpine's own build of the same
# release the dynamic library is.
set -eu
ARCH="${1:-x86_64}"
DOCKER="${DOCKER:-docker}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "$ARCH" in
  x86_64)  PLATFORM=linux/amd64 ;;
  aarch64) PLATFORM=linux/arm64 ;;
  *) echo "unknown arch $ARCH" >&2; exit 2 ;;
esac
OUT="bridge/build-static-$ARCH"
$DOCKER run --rm --platform "$PLATFORM" -v "$ROOT:/src" -w /src alpine:3.21 sh -eu -c "
  apk add --no-cache build-base cmake boost-dev openssl-dev openssl-libs-static linux-headers >/dev/null
  cmake -S bridge -B $OUT -DCMAKE_BUILD_TYPE=Release -DCONVERGE_BRIDGE_FULLY_STATIC=ON >/dev/null
  cmake --build $OUT -j\$(nproc)
  ctest --test-dir $OUT --output-on-failure
"
python3 "$ROOT/scripts/check-static.py" "$ROOT/$OUT/converge-bridge"
echo "built $OUT/converge-bridge"
