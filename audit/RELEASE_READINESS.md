# Release readiness — strict gates

Decision: **RESEARCH ONLY / MAINNET BLOCKED**. No independent audit has occurred.
No mainnet/public-testnet deployment is authorized by this review. Current small
local devnet tests are evidence, not a blanket LOCAL DEVNET READY designation.

| Gate | Status | Evidence / blocker |
|---|---|---|
| Baseline commit/toolchain/results preserved | Met | BASELINE_TREE.tsv; TEST_REPORT.md; baseline logs |
| Required native signatures and exact subsidy | Covered locally | Real AddBlock negative controls on both stores, schedule boundaries |
| Legacy ownership | Blocked | All claims fail closed; no approved canonical historical key/context format |
| Proof-shape bypass removal | Met for stated bypass | Legacy proof rejected; real cryptographic verification retained |
| Independently reviewed proof system and signing | Blocked | Custom Schnorr/OR range proof; variable-time secret paths |
| Complete body binding and history uniqueness | Covered locally | Version2 roots/IDs, mutation/replay tests and persisted historical indexes |
| Atomic small reorg and storage fault recovery | Covered locally | Full-state equality, actual Badger limit failure, abrupt process exit |
| All legal backend transition capacity/parity | Blocked | Version3 removes aggregate single-transaction cap via fenced batches; individual-record bound argued, worst-case valid proof/delta resource campaign still incomplete |
| Bounded long-chain reorg/restart resources | Blocked | Suffix-only staging implemented; full startup replay, retained MVCC versions and worst-case suffix memory still need budgets |
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
