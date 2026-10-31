#!/usr/bin/env bash
# Verify a downloaded NosoX release.
#
# Usage:
#   scripts/verify-release.sh path/to/release-dir
#   scripts/verify-release.sh path/to/release-dir launcher.pub  # also verify signature

set -euo pipefail

DIR="${1:?usage: verify-release.sh <dir> [launcher.pub]}"
PUB="${2:-}"
if [[ -n "$PUB" ]]; then PUB="$(realpath -- "$PUB")"; fi

cd "$DIR"

if [[ ! -f SHA256SUMS ]]; then
  echo "no SHA256SUMS in $DIR" >&2
  exit 1
fi

echo "==> Verifying SHA256SUMS against actual files"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c SHA256SUMS
else
  shasum -a 256 -c SHA256SUMS
fi
echo "  ✓ all hashes match"

if [[ -n "$PUB" ]]; then
  if [[ ! -f SHA256SUMS.minisig ]]; then
    echo "no SHA256SUMS.minisig (launcher did not sign this release)" >&2
    exit 1
  fi
  if ! command -v minisign >/dev/null 2>&1; then
    echo "minisign required to verify signature; install it first" >&2
    exit 1
  fi
  echo "==> Verifying launcher signature"
  minisign -V -p "$PUB" -m SHA256SUMS
  echo "  ✓ signature verifies under $PUB"
fi
if [[ -z "$PUB" ]]; then
  echo "Checksums match; publisher authenticity was not checked."
else
  echo "Checksums and publisher signature verified."
fi
