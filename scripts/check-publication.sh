#!/usr/bin/env bash
# Required maintainer preflight before changing repository visibility.
# Scan BOTH reachable Git history and current files. Do not upload scan
# reports or print unredacted credentials in logs.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

if [[ "$(git rev-parse --is-shallow-repository)" != "false" ]]; then
  echo "BLOCKED: shallow checkout. Fetch complete refs/history before scanning." >&2
  exit 2
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "BLOCKED: gitleaks is required. No scan was performed." >&2
  exit 2
fi

if [[ -z "$(git for-each-ref --format='%(refname)' | head -n 1)" ]]; then
  echo "BLOCKED: no local Git refs available to scan." >&2
  exit 2
fi

echo "Scanning all locally reachable Git refs and historical patches..."
if ! gitleaks git --redact --log-opts="--all"; then
  echo "BLOCKED: history scan found potential secrets or could not finish." >&2
  exit 1
fi

echo "Scanning current working tree, including uncommitted files..."
if ! gitleaks dir --redact .; then
  echo "BLOCKED: working-tree scan found potential secrets or could not finish." >&2
  exit 1
fi

echo "Automated checks completed without findings."
echo "This does NOT certify remote/unfetched refs, unreachable Git objects,"
echo "binary archives, rotated credentials, or semantic privacy disclosures."
echo "Human review and release approval are still required."
