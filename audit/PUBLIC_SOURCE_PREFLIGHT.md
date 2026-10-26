# Public source-code release preflight

**Decision: NOT CLEARED.** This checklist is not an approval to open this
repository or launch a cryptocurrency. Mainnet remains blocked by
`audit/RELEASE_READINESS.md` and `audit/BLOCKERS_V4.md`.

Before making the repository public, the maintainer must run the following
on a fully fetched clone containing all relevant reachable branches and tags:

```bash
git fetch --all --tags --prune
git rev-parse --is-shallow-repository # must print false
bash scripts/check-publication.sh
```

The script requires `gitleaks`, scans locally reachable Git history
(including deleted file versions) and the current working tree, prints
redacted findings, and exits nonzero on a failed or unavailable scan. It
never changes GitHub settings, deletes history, publishes results, or marks
a finding as safe. It has **not** been run against a complete current clone
in this review. The CI runner currently fails before any job steps start.

## Manual maintainer gates

1. Inspect flagged historical content, including audit logs, artifacts,
   archived raw Noso files, fixtures and released binaries. Distinguish
   demonstrably public test material from credentials. **Do not dismiss
   a finding just because its file was later deleted.**
2. Rotate and revoke exposed credentials independently of history rewriting.
   Evaluate whether shared Git history, forks, cached clones, package
   archives and release attachments may still contain secrets.
3. Check documentation, screenshots, author metadata and logs for personal
   or proprietary information not identifiable by entropy or token detectors.
4. Verify third-party licenses, historical-source redistribution rights,
   vulnerability-disclosure contact and source-code provenance.
5. Publish only with conspicuous `RESEARCH ONLY / MAINNET BLOCKED`
   documentation and unambiguous instructions not to hold real value.
6. Do not make a statement of independent audit, sound cryptography or
   authenticated legacy supply until those reports actually exist.

## What the script does not prove

`--all` visits only refs available in the *local* clone. It does not prove
GitHub has no inaccessible or dangling objects, un-fetched refs or deleted
branch commits. Automated scanners miss secrets and produce false positives;
a completed zero-finding run must still be manually reviewed.

A source-code publication approval is separate from testnet or mainnet
readiness and separate from NX-018/NX-019 independent crypto review or NX-020
economic provenance and genesis reconciliation.
