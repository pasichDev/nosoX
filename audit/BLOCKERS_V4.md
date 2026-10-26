# Version4 blocker remediation and local verification

Scope: continue the existing defensive work, preserving commits, fixtures and
test logs. Base is `1f4b2d2` on `security/consensus-hardening`; source identity is
`BLOCKERS_V4_SOURCE.sha256`. This is an internal follow-up, not an independent
cryptographic audit. No deployment, publication, public-network testing, merge
or repository-setting change occurred. Go remains1.27.3.

## Implemented defensive changes

| Work | Affected files/functions | Enforced invariant | Regression evidence |
|---|---|---|---|
| Explicit legacy ownership | `v2/legacyclaim/claim.go` Digest/Verify; `v2/chain/legacy_claim.go` validateLegacyClaims; `validation.go` validateBody | Trusted active source, canonical genesis/network and exact destination leg; actual historical key possession; one-to-one legs; individual and aggregate conservation; no shared or unreferenced claim kernels | TestLegacyClaimV4BothBackends, TestLegacyClaimV4DurableRestart; helper context/DER/Base64 vectors |
| Safe claim construction | `v2/wallet/legacy_claim_v4.go` BuildLegacyClaimV4/BuildGVTRedeemV4; `builder.go` | Explicit context, imported canonical secret, low-S ECDSA-SHA256 plus native Schnorr/proof; old context-free builders fail explicitly | Wallet positive shape/conservation/proof/kernel checks, old API rejection tests; complete chain-entry claim tests |
| Reader-safe reclamation | `v2/chain/badger_store.go` snapshot/view/advanceDiscardLocked/Reclaim | Discard cutoff never passes oldest pinned reader; release discards transaction before unpin; maintenance serialized with Close | TestBadgerLifecyclePinnedReaders, ConcurrentViewPublish, CompactionReclaimsVersions, MaintenanceLimits |
| Bounded abandoned-stage recovery | Same file: publish/restoreDirty/recoverDirtyKeys | Restore unchanged canonical state before staging different keys; no failed-candidate dirty-key union; at most65536 recovery keys, skipping old same-key versions; limit failure does not publish/delete data | TestBadgerLifecycleFailedStageRecovery, RepeatedFailuresBoundDirtyKeys; TestBadgerRecoveryDistinctKeyBudgetAndSeek, EmptyZeroBudget; existing abrupt-exit tests |
| Streaming persistent verification | `replay_verify.go` streamingVerifyHistory/replayBlockAt/compareReplayState; `validation.go` verifyHistory | Validate every stored block, compare complete derived state with ordered iterators; no history-sized Go map; encoded record bounds before decode; scratch cleanup | TestStreamingReplayMatchesAndRejectsCorruptState, PinsTrustedGenesis; legacy durable restart |
| Explicit consensus resource limits | `types/protocol_limits.go`, chain resource_budget/Store.UndoAtBudget, mem/fork/Badger implementations | Native4/4/4 items,64KiB body,14529-byte proofs; depth1024 unchanged; preflight before rollback allocation; bounded undo before cloning/decoding | TestResourceV4ShapeBoundaries, MaximumEncodedUndoBoundAndIsolation, BadgerUndoPredecodeGuard, StoresRejectOversizedUndoAtomic, V4MaximumShapeStoreParity, V4NativePaymentFullPipeline |
| Admission and miner consistency | `v2/mempool/mempool.go`, `v2/p2p/libp2p_host.go` checkBody, `v2/miner/miner.go` makeCandidate | Claim fields included in charge; native network envelope shared with chain; miner and transaction admission reserve required coinbase/fee slots | TestPoolV4ClaimBudgetAndRemoval, TestDecoderV4NativeEnvelope, TestCandidateReservesMandatoryV4Outputs |
| Periodic maintenance | `cmd/nosoxd/{main,maintenance}.go`, chain maintenance.go | One synchronous GC attempt per interval; cancellation stops future attempts; no overlapping worker | TestMaintenance* |

Full ordinary/storage test results are recorded in TEST_REPORT.md and the final
JSON/logs; the complete executed command, environment, elapsed time and exit
status are authoritative. Independent internal source review of the combined
fixes is in REMAINING_BLOCKERS_SECOND_PASS.md. It is not an external audit.

## Compatibility and resource decisions

Protocol version4 deliberately changes acceptance and body/transaction domains.
Legacy inputs add public-key text and exact output/kernel IDs. KernelID and
OutputID retain their existing formats; ownership signatures use a NEW
SHA256/strict-DER/low-S procedure rather than historical SHA1. Old wallet APIs
return explicit errors. Existing version3 fee tweaks remain. No subsidy, premine,
allocation, fee recipient, GVT700NOSO constant or1024-block depth was changed.
Malformed original snapshot bytes are preserved and still rejected. Fresh
isolated data/reset/import is required; no automatic historical upgrade is claimed.

Trusted genesis retains its separate10000-allocation/8MiB envelope and cannot be
an incoming reorg block. Remote gossip/sync uses the native envelope; genesis is
configured locally. The maximum charged native shape is63592 bytes. An incoming
1024-block body envelope is64MiB, undo58.254MiB, not the previous8GiB body plus
potentially much larger undo. Charge units are not Go heap/RSS limits.

The opt-in maximum-shape fixture uses synthetic INVALID proof bytes through raw
Store APIs, never an accepted fake proof. The final memory/Badger runs publish
1024 replacements and read all undo records, with observed peak RSS380748KiB
and810512KiB respectively, no swaps, exit0. These observations support an
experimental at-least2GiB target; they do not prove a process ceiling, full
Chain.ReorgTo maximum capacity or universal latency. GOMEMLIMIT512MiB is soft.

## What remains blocked, with concrete next steps

1. **NX-018/NX-019 — High:** independent mathematical/implementation review of
   custom Schnorr/range proofs and secret arithmetic is absent. Functional
   fixes cannot manufacture that evidence. EXTERNAL_CRYPTO_REVIEW_PACKET.md
   identifies source, assumptions, vectors and required deliverables. Obtain
   an independent report, remediate findings and explicitly version any
   reviewed replacement; do not substitute an unreviewed new primitive.
2. **NX-020 — High:** legacy economic legitimacy and canonical provenance are
   not established. A local180032-block archive was found and scanned read-only
   in4.261s; headers and declared sizes alone cannot authenticate1424238 orders,
   PoS/MN trails or balances. Full historical rule/version/config reconstruction,
   linkage/signature verification and independent per-owner reconciliation are
   required. Eleven malformed summary addresses,400NOSO discrepancy and the
   historical GVT policy still need explicit resolution. A valid claim only
   proves control of a key for an operator-trusted allocation.
3. **Capacity/durability assurance:** concrete history-sized RAM replay and
   indefinite dirty-key union defects are addressed. Remaining tests include
   long-history replay RSS/scratch capacity, a full cryptographically valid
   maximum suffix, eligible value-log rewrite and deeper crash/I/O/power-loss
   cases. Long readers intentionally pin versions. Persistent failed writes can
   retain physical future versions until successful restoration; this is not
   a universal disk quota. Interrupted trusted bulk imports above65536 keys or
   oversized old abandoned data may require explicit offline recovery.
4. Earlier unrelated gates remain open: production wallet/secret lifetime,
   published-LWMA equivalence, global P2P/Sybil assumptions and dedicated history
   secret scanning. This pass does not silently certify them.

Decision: **RESEARCH ONLY / MAINNET BLOCKED**. The code is suitable for targeted
independent cryptographic/design review as an unsafe research subject, not for a
final release security sign-off. Public source release requires maintainer
review of disclosures and remaining secret/history concerns. No publication was
performed, and no claim that all release blockers are closed is justified.

Verified implementation commit: `f4169f5f25853be6031fe39fc9bf9e15c20acabb` (local only).

## Final executed result

All final checks exited0: build/vet/modverify; ordinary18-package test run
118.666s; full race294.124s; selected storage/consensus suite95.616s.
VERIFICATION_V4_SUMMARY.md records exact commands, per-test results and limits.
The initial stale maximum-shape expectation failure is preserved in separate
logs and was fixed without relaxing validation.155 source/module hashes and
all final verification log hashes were checked after execution. No additional
source change followed the frozen successful runs.
