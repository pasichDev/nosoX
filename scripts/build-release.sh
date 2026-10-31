#!/usr/bin/env bash
# Build a reproducible NosoX release.
#
# Produces:
#   release/<version>/nosoxd-<os>-<arch>
#   release/<version>/nosox-cli-<os>-<arch>
#   release/<version>/SHA256SUMS
#   release/<version>/SHA256SUMS.minisig   (optional, if LAUNCHER_MINISIGN_KEY is set)
#
# Reproducibility comes from:
#   * -trimpath (no local file paths in binaries)
#   * -buildvcs=false (no git state)
#   * CGO disabled
#   * Fixed -ldflags (no timestamp)
#   * Pinned go version (caller picks)
#
# Usage:
#   scripts/build-release.sh <version>             # build for linux/amd64 only
#   scripts/build-release.sh <version> --all       # build all 4 supported platforms
#   scripts/build-release.sh <version> --sign      # also produce SHA256SUMS.minisig

set -euo pipefail

VERSION="${1:-dev}"
shift || true
if [[ ! "$VERSION" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
  echo "invalid version component" >&2; exit 2
fi

PLATFORMS=("linux/amd64")
SIGN=0
for arg in "$@"; do
  case "$arg" in
    --all)  PLATFORMS=("linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64") ;;
    --sign) SIGN=1 ;;
    *)      echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")"/.. && pwd)"
OUT="$ROOT/release/$VERSION"
mkdir -p "$OUT"
cd "$ROOT"
ARTIFACTS=()

BINS=(nosoxd nosox-cli)

for plat in "${PLATFORMS[@]}"; do
  os="${plat%/*}"
  arch="${plat#*/}"
  for bin in "${BINS[@]}"; do
    out="$OUT/${bin}-${os}-${arch}"
    ARTIFACTS+=("${bin}-${os}-${arch}")
    echo "==> $out"
    CGO_ENABLED=0 \
      GOOS="$os" GOARCH="$arch" \
      go build \
        -trimpath \
        -buildvcs=false \
        -ldflags="-s -w -buildid=" \
        -o "$out" \
        "./cmd/$bin"
  done
done

# SHA256 over every artefact, deterministic order.
( cd "$OUT" && printf '%s\n' "${ARTIFACTS[@]}" | LC_ALL=C sort | while IFS= read -r artifact; do sha256sum -- "$artifact"; done ) > "$OUT/SHA256SUMS"
echo "==> $OUT/SHA256SUMS"
cat "$OUT/SHA256SUMS"

if [[ "$SIGN" == "1" ]]; then
  if ! command -v minisign >/dev/null 2>&1; then
    echo "minisign not found in PATH; install it for signing" >&2
    exit 1
  fi
  if [[ -z "${LAUNCHER_MINISIGN_KEY:-}" ]]; then
    echo "LAUNCHER_MINISIGN_KEY env var must point at the secret key file" >&2
    exit 1
  fi
  minisign -S -s "$LAUNCHER_MINISIGN_KEY" -m "$OUT/SHA256SUMS"
  echo "==> signed: $OUT/SHA256SUMS.minisig"
fi

echo ""
echo "Release artefacts ready at: $OUT"
