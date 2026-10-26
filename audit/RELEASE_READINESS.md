# Release readiness — strict gates

Decision: **RESEARCH ONLY / MAINNET BLOCKED**. No independent audit has occurred.
No mainnet/public-testnet deployment is authorized by this review. Current small
local devnet tests are evidence, not a blanket LOCAL DEVNET READY designation.

| Gate | Status | Evidence / blocker |
|---|---|---|
| Baseline commit/toolchain/results preserved | Met | BASELINE_TREE.tsv; TEST_REPORT.md; baseline logs |
| Required native signatures and exact subsidy | Covered locally | Real AddBlock negative controls on both stores, schedule boundaries |
| Legacy ownership | Implemented for trusted genesis, historical approval blocked | Version4 ECDSA ownership binds canonical source/network/genesis/exact destination leg; real proof/kernel/conservation tests on both stores/restart/reorg; no authenticated mainnet snapshot |
| Proof-shape bypass removal | Met for stated bypass | Legacy proof rejected; real cryptographic verification retained |
| Independently reviewed proof system and signing | Blocked | Custom Schnorr/OR range proof; variable-time secret paths |
| Complete body binding and history uniqueness | Covered locally | Version4 complete roots/TxID, existing kernel/output IDs, mutation/replay tests and persisted historical indexes |
| Atomic small reorg and storage fault recovery | Covered locally | Full-state equality, actual Badger limit failure, abrupt process exit |
| All legal backend transition capacity/parity | Blocked | Version4 bounds4/4/4 items,64KiB body and predecode undo; fenced batches preserve aggregate atomic visibility;1024 raw maximum-shape transitions measured, full maximum valid fork still unmeasured |
| Bounded long-chain reorg/restart resources | Blocked | Suffix-only staging; reader-safe discard,65536-key recovery cap, separate dirty restore and disk-backed streaming startup implemented; physical failure-loop growth and whole-process capacity remain limited |
| Fee transfer conservation and usable repeated fees | Covered locally | Version3 context tweak preserves F/recipient and supports repeated fees; off-repo wallet must adopt tweak helper |
| Fork choice by valid accumulated work | Covered locally | Fully mined shorter-heavier fork; strict ties; exact target-derived work |
| Timestamp/difficulty design | Partial | Overflow/freeze checks covered; clocks and published-LWMA equivalence unresolved |
| Independently reconciled migration/genesis | Blocked | Malformed historical accounts and no authenticated issuance reconstruction |
| Safe public P2P/RPC operation | Blocked | Bounded local tests do not establish global budgets, Sybil/eclipse resilience |
| Wallet usability/secret assurance | Blocked | Intent envelopes are not complete MW payments; plaintext miner secrets and CT gaps |
| Full current checks | Consult TEST_REPORT | Exact exit statuses; unavailable tools not marked successful |
| Exhaustive crash/power-loss and long-term tests | Blocked | Finite subprocess/fault tests, no full OS power-cut matrix |
| Dedicated history secret scan | Incomplete | Not completed; dedicated scanners unavailable; no new scanning in verification pass |
| Repository publication authorization/settings | Not changed | Private+archived observed; archive prevents requested PR |

Source-code publication: feasible only as explicitly unsafe research after
maintainer review of findings, disclosures and residual secrets. This task has
not changed visibility or published a repository/release.

Independent review: useful as input to a targeted cryptographic/design review.
**Not a final external release-audit candidate** until the High blockers above
are resolved and scope/compatibility decisions stabilize. Automated test success
must never be substituted for an independent audit or supply reconciliation.

Current SP1/SP2/SP3 implementation and exact integrated verification supersede
previous open-finding descriptions: see SP123_COMPLETION.md. Closing specific
code defects does not close the broader resource, crypto or migration gates.

## Version4 follow-up disposition

BLOCKERS_V4.md, the frozen source manifest and logs/blockers-v4-final/ supersede
older technical descriptions of disabled claims, discard timestamp zero and
history-sized persistent RAM replay. They do not supersede external evidence
requirements. NX-018/NX-019 cryptographic/side-channel assurance and NX-020
historical economic authenticity remain **High release blockers**. Ordinary
claim signatures are now required and implemented for explicitly trusted
experimental genesis; that is not an approved historical mainnet migration.

The experimental capacity target is at least2GiB, not a guaranteed memory ceiling.
The latest1024-block raw storage fixtures use synthetic proof bytes and cannot
stand in for a full maximum cryptographically valid fork. Tests, reviewed source
and unresolved verification gaps are distinguished in the new reports.

An external reviewer can begin targeted cryptographic/design assessment using
EXTERNAL_CRYPTO_REVIEW_PACKET.md. The repository is not a final release-audit
candidate, and no independent reviewer has certified it. No publication or
repository visibility/archive change has occurred.

## Follow-up: stacked defensive PR #5 (unverified)

PR #5 adds fail-closed Badger historical lookup behavior, malformed hash-index
rejection, miner cancellation/listener lifecycle fixes, HTTPS-only seed list
retrieval (including rejection of redirects downgraded to HTTP), and isolated
regression tests. It also adds `scripts/check-publication.sh` and
`audit/PUBLIC_SOURCE_PREFLIGHT.md` for the source-code publication gate.

**None of these changes have an executed green full-suite/race result yet.**
GitHub Actions runs on this private repo terminate before executing any steps:
the separate echo-only runner-smoke job fails too, and job logs are unavailable.
Do not interpret that pre-runner failure as a verified Go test failure or
assume it resolves after changing the workflow. Check Actions billing/budget,
runner eligibility and account/repository restrictions; obtain a successful
runner and repeat the documented checks before merging.

The repo was observed private and unarchived at PR #5 creation; earlier
"private+archived" status above is historical, not a current setting claim.

Source-publication scanning has been *prepared*, not executed. It still needs
a full local checkout, installed gitleaks, a scan of all local refs/working tree,
human secret/privacy review, and explicit maintainer authorization.

NX-018/NX-019 independent cryptographic review, NX-020 independently verified
legacy supply/genesis, full valid-fork/capacity/durability experiments, and
wallet/P2P assurances remain release blockers. No audit certification, public
release or mainnet approval is implied by this PR.
