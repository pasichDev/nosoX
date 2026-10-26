# Remaining blockers: independent scoped second pass

Scope: read-only review of Badger snapshot lifetime, discard cutoff, abandoned
stage restoration and disk-backed startup replay. Reviewed
`v2/chain/badger_store.go`, `v2/chain/replay_verify.go`, their lifecycle/replay
regressions and pinned Badger v4.9.1 implementation. No consensus, proof,
legacy-ownership or unrelated network review is claimed here. No source was
changed by this pass. Runtime verification is owned by the integration run;
this report distinguishes inspected tests from freshly executed evidence.

## Findings

No blocking correctness defect was identified in the four scoped mechanisms.
The conclusions below are source-review findings, not an external audit or a
whole-node resource guarantee.

### 1. Inclusive discard cutoff preserves pinned readers

`BadgerStore.snapshot` registers the active timestamp and creates the Badger
transaction while holding `readersMu`. Publication changes `active` and advances
the discard cutoff under that same mutex. A reader therefore either registers
before advancement and pins its timestamp, or observes the newer timestamp.
There is no gap in which an unregistered old snapshot can be reclaimed.
Release discards the transaction before removing its registration, so a
transaction is never used after its protection is removed.

`advanceDiscardLocked` uses `min(active, every registered read timestamp)` and
advances monotonically. Inclusive Badger semantics do not require subtracting
one: pinned dependency `badger/v4@v4.9.1/managed_db.go::SetDiscardTs` permits
invalid/deleted versions at or below the cutoff to be discarded;
`levels.go` around lines 754–785 counts only versions `<= discardTs`, retains
the newest such nondeleted value with `NumVersionsToKeep(1)`, and discards
older versions. A newer version above the cutoff does not consume that one
retained version. A tombstone visible at the cutoff can remove its own older
values because all pinned snapshots are at or above that cutoff and must see
absence. A tombstone newer than the cutoff cannot remove the required older
value. This matches the chosen inclusive minimum-reader cutoff.

Durable fence commit occurs before changing the in-process active timestamp.
Readers that register during that interval still pin the old canonical
snapshot, which remains valid. Reopen discovers the durable fence instead.

Inspected evidence: `TestBadgerLifecyclePinnedReaders`,
`TestBadgerLifecycleConcurrentViewPublish`, and
`TestBadgerLifecycleCompactionReclaimsVersions`. The last performs real
Flatten-based version removal and confirms a pinned old nondeleted value
survives, followed by removal after release.

### 2. Abandoned keys are restored before a different candidate is staged

`publish` runs `restoreDirty` as a separate same-logical-state publication
before `publishStage(entries)` for the candidate. Restoration reads every
previous dirty key from one committed snapshot, representing absent keys as
tombstones. Its writes involve only that existing key set. If restoration
fails, the candidate is never staged. If it succeeds, its durable fence retires
the old dirty set before the new candidate can introduce keys. Thus failed,
different candidates cannot accumulate a union of key identities indefinitely.

This also handles a candidate delta computed before restoration: the
restoration changes physical timestamps while preserving exactly the logical
canonical state against which that delta was computed. It therefore does not
invalidate the consistency checks. Mutations are serialized by `mu`.

At reopen, the code scans versions newer than the durable active fence,
including tombstones, before enabling discard. The cutoff never exceeds active
while those versions remain unpublished. A later restoration uses the newest
committed value visible at active, rather than any abandoned newer value.
This prevents the subsequent candidate fence from exposing abandoned writes.

Inspected evidence: `TestBadgerLifecycleFailedStageRecovery` covers both fault
positions, reopen and real compaction before a different retry;
`TestBadgerLifecycleRepeatedFailuresBoundDirtyKeys` checks twelve failed
restorations followed by twelve successful-restoration/failed-candidate cycles,
with bounded key cardinality and no eventual abandoned-key visibility.
Existing abrupt-exit fence tests remain relevant to durable publication.

**Limit:** bounded dirty key cardinality does not bound physical disk growth
under an arbitrarily long sequence of failed restorations. Each failed attempt
can add newer versions above active. They must remain protected until a
restoration successfully advances the fence. Recovery scan time can likewise
grow with unpublished version count even though its deduplicated Go map stays
bounded by one stage. Reclamation requires successful durable forward progress;
this code must not be described as a universal disk quota or failure-loop disk
bound.

### 3. Startup replay does not rebuild whole history in Go maps

The persistent branch of `verifyHistory` calls `streamingVerifyHistory`.
It pins one source snapshot, reads one canonical block at a time and performs
full Chain validation into a disposable Badger store. Scratch cache, index and
memtable sizes are explicitly configured. It does not call `orderedBlocks`,
`stateEntries` or the old in-memory full-history replay for the Badger path.
The scratch database holds the historical/derived state on disk, and its
per-block mutation map is cleared after publication.

`replayBlockAt` checks encoded value size before decoding. The separate trusted
genesis envelope is retained. `compareReplayState` walks two ordered iterators
with value prefetch disabled, checks identical logical key sets and compares
one source/expected record pair at a time. Structured values are decoded for
semantic equality because gob identifiers can depend on registration order.
The expected value controls the source record size guard before comparison.
No history-sized map or slice is built by this comparison.

The scratch store closes before removal because of defer ordering; creation,
validation, comparison and close failures propagate through the named error
return. Tests inspect absence of leftover scratch paths after success and
validation failures.

Inspected evidence: `TestStreamingReplayMatchesAndRejectsCorruptState` covers a
valid four-block history plus missing/extra keys, corrupt values, invalid block
authorization and an oversized encoded block. `TestStreamingReplayPinsTrustedGenesis`
rejects a different trusted genesis. These are meaningful correctness tests;
they are not long-history capacity measurements.

## Concrete remaining verification gaps

1. Force real compaction while an old reader spans a later deletion, then read
   the older value and the newer tombstone from distinct pinned snapshots.
   Existing tests separately cover deletion visibility and actual compaction;
   combining those exact conditions would strengthen inclusive-cutoff evidence.
2. Add abrupt process-exit cases specifically during standalone dirty
   restoration, including a restored committed value and an abandoned delete,
   followed by reopen, compaction, different retry and streaming replay. Current
   injected restoration failures and candidate process-exit cases do not claim
   this complete crash sequence.
3. Measure long-history streaming startup with real accepted blocks and a
   materially sized UTXO set, recording peak RSS, scratch disk, replay time and
   source-state integrity. Four-block comparison tests establish behavior, not
   maximum replay capacity. Source versions remain pinned for the duration,
   so concurrent raw-store writers, if used outside normal startup locking,
   can retain versions until replay releases its source snapshot.
4. Exercise eligible value-log files and observe an actual value-log rewrite
   and eventual disk reuse. `Reclaim` returning nil on `ErrNoRewrite` proves
   safe maintenance behavior but does not prove that a rewrite occurred.
5. Inject scratch disk/open/write/close failures to check cleanup and error
   reporting under actual I/O failures, rather than only invalid source data.

These are assurance gaps rather than newly identified acceptance or atomicity
bugs. Real OS/filesystem power loss and persistent I/O failure remain outside
fault-hook equivalence. Full history still has O(history) replay time and
scratch disk cost. The resource report's maximum-shape fixtures use synthetic
proof bytes; a complete 1024-block maximum cryptographically valid reorg is
still a separate missing capacity experiment.

Result: the reviewed implementations address the concrete reader lifetime,
failed-candidate dirty-union and full-history heap-materialization defects.
No independent cryptographic or mainnet readiness conclusion follows.
**RESEARCH ONLY / MAINNET BLOCKED** remains applicable.

## 2026-10-26: final v4 claim integration disposition

Read-only review additionally covered `chain/legacy_claim.go`,
`legacyclaim/claim.go`, `wallet/legacy_claim_v4.go`, claim-related validation,
canonical input/output encoding, resource accounting, pool accounting and P2P
native-body checks. No additional blocking integration defect was identified.
This is source inspection; frozen integration runs provide runtime evidence.

Authorization uses the active stored source and canonical stored genesis/network,
not claimant-supplied context. Strict canonical historical public-key text must
derive the source address; strict low-S ECDSA signs the source commitment,
address, amount, deployment context and exact output/kernel leg digest. The
output ID includes its proof. The kernel ID excludes only its Schnorr signature,
avoiding circular signing while binding kernel features, excess, fee and lock.
Missing, shared and unreferenced claim legs are rejected. Native inputs reject
all legacy authorization fields.

Each leg requires a Plain output, zero-fee/unlocked claim kernel,
`destination commitment - source commitment == kernel excess`, and a valid
Schnorr signature under that excess. Full output range-proof verification and
the unchanged aggregate balance equation still run. An ECDSA ownership proof
therefore does not bypass conservation or authorize inflation. Source consumption
and historical uniqueness continue through the ordinary atomic backend path.
The wallet separately checks canonical allocation commitments and historical key
consistency before signing. GVT redemption retains its existing amount; ownership
proofs do not authenticate the legitimacy of the historical allocation itself.

Claim IDs add 64 fixed input bytes and canonical uncompressed public-key text
adds at most 88 bytes. Chain body accounting and both pool add/remove accounting
include these fields. The maximum structural shape is now 63592 bytes, still
below 64 KiB; output-only undo charges are unchanged. The initially observed
P2P mismatch was resolved: `checkBody` now delegates to `chain.BodyResourceBytes`
with native height 1, preventing the trusted-genesis exception from being used
through network decoding. No further source edit was requested by this review.
