#!/usr/bin/env bash
# Verify a downloaded Noso v2 release.
#
# Usage:
#   scripts/verify-release.sh path/to/release-dir
#   scripts/verify-release.sh path/to/release-dir launcher.pub  # also verify signature

set -euo pipefail

DIR="${1:?usage: verify-release.sh <dir> [launcher.pub]}"
PUB="${2:-}"

cd "$DIR"

if [[ ! -f SHA256SUMS ]]; then
  echo "no SHA256SUMS in $DIR" >&2
  exit 1
fi

echo "==> Verifying SHA256SUMS against actual files"
sha256sum -c SHA256SUMS
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
echo "Release is good."
