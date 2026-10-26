# Independent second pass: SP1 algebra, SP2 suffix state, SP3 durable fence

This is a local, source-level second pass over the combined remediation. It is independent review by the SP1 implementation agent of the SP2/SP3 production changes; it is not an external audit or cryptographic security guarantee. No other production files were changed during this pass. No public-network queries, node interaction, publishing or production secrets were used. The earlier SP1 primary-reference lookup consulted only the public BIP 341 specification.

## SP1 follow-up

The lead identified a worthwhile fail-closed requirement: checking only final `F H + P_dev + tG` misses an identity adjusted recipient `P_dev+tG`, which would remove secret ownership even though `F H` remains nonidentity. `ExpectedDevFundCommit` now separately constructs and rejects an identity/noncanonical adjusted recipient, then constructs and rejects an identity/noncanonical final commitment. It uses only existing `PedersenCommit`, `PointAdd` and `ValidPublicPoint` operations. A canonical internal zero tG/FH addend remains supported by existing point-operation semantics; no external identity input exception was introduced.

The fixed production key makes that cancellation practically unconstructable without its unknown scalar or a hash preimage, so this check is defense in depth rather than an exploit demonstration. General group, hash, proof and signature security remain assumptions; neither this review nor a matching public-tweak equation provides an independent external guarantee.

## SP2 reviewed invariants

Files read: `suffix_overlay.go`, `suffix_overlay_test.go`, `store_delta.go`, relevant `Chain.ReorgTo` and memory-store publication code.

- Descending rollback removes orphan-produced UTXOs, historical output/kernel identities, hash indices and blocks, then restores full spent metadata from undo. A restored input produced earlier in the same orphan suffix is subsequently removed while unwinding that earlier block, as required.
- Tombstones take precedence over base lookups. After rollback, the retained prefix remains lazily readable, and removed hash/height entries cannot leak through fallback. `UndoAt` and UTXO reads clone proof bytes before returning owned state.
- Incoming blocks pass complete consensus validation against the isolated fork before canonical mutation. Raw-store checks additionally enforce duplicate/replayed identities and exact input metadata. Strict greater-work comparison occurs before publication.
- Memory publication constructs and checks the entire touched delta first; the subsequent map application has no ordinary error-return path. Readers through Chain share its mutex. This supports atomic visibility under the documented serialized Chain access model; it is not a guarantee for concurrent unsynchronized raw-memory-store access or process OOM/panic.
- Ordinary rollback/validation/publication enumerates the removed/new suffix plus the fixed difficulty window, rather than retained history. Full startup validation, trusted import and explicit snapshots retain their documented full-history cost.

No concrete SP2 correctness or atomicity blocker was identified in these paths.

## SP3 reviewed invariants

Files read: `badger_store.go`, `badger_fence_test.go`, overlay-to-Badger suffix encoding. Pinned Badger source was checked for iterator behavior (`github.com/dgraph-io/badger/v4@v4.9.1/iterator.go`): `AllVersions=true` explicitly returns deletion versions, and `SinceTs` excludes versions at or below the active fence.

- Each reader opens an MVCC snapshot at the in-memory active timestamp. Serialized mutations read that committed snapshot, write staged data at a later timestamp, and expose it only after a separately durable active-marker transaction succeeds.
- `WithSyncWrites(true)` makes successful stage flushes and the final marker synchronous in the Badger durability model. Publishing the in-memory atomic timestamp follows the durable marker, so process restart may see a completed publication even if the process exits before updating its local atomic value.
- An unpublished stage is invisible at the old timestamp. Reopen reads/validates the active marker at the latest database version and rebuilds the dirty-key set from all newer versions, including tombstones. The next timestamp is greater than the database maximum, not merely greater than the last published marker.
- Before advancing the fence, a different retry restores every abandoned dirty key omitted by its own delta to the active snapshot's value or tombstone. This prevents earlier partial spends, outputs, hashes or undo records from becoming visible merely because a later fence passes their timestamps.
- The initial schema marker distinguishes interrupted genesis staging from an unfenced legacy/incomplete database; legacy unfenced data fails closed. Startup history/state replay remains separate from the marker protocol.
- Full replacement, append, undo and suffix replacement all route publication through the same fence protocol. A legal large body can span multiple Badger write transactions without splitting logical visibility.

No concrete SP3 atomicity/recovery blocker was identified. Ordinary disk failures can still leave commit outcome uncertain as in standard storage APIs; the deterministic hooks cover specified pre-publication stages, not every possible device/controller failure. Actual hardware power loss and filesystem durability are not established by source review or process-exit tests.

## Operational limits retained

The managed store deliberately keeps old MVCC versions to preserve unpublished-stage tombstones. Physical disk usage and reopening scans can grow with accumulated history/failed writes; no version-pruning or compaction lifecycle was introduced. Dirty restoration work can reflect accumulated abandoned touched keys. These are operational limits, not a claim of constant total storage/startup cost. Legal maximum-length suffixes can still consume substantial resources despite their explicit bound. None of these limitations warrants weakening the historical uniqueness or durable publication rules.

## Executed verification

After the adjusted-recipient check, the SP1 focused suite passed:

```
GOTOOLCHAIN=go1.27.3 GOMODCACHE=/home/pasich/go/pkg/mod GOCACHE=/home/pasich/.cache/go-build \
  go test -p 2 ./v2/chain -run 'TestSP1|TestDevFund|TestExpectedDevFund' -count=1
```

Result: PASS, 18.583 seconds. This includes full memory/Badger fee-block acceptance, rejection, restart and reorg regression tests and the independent Jacobian/test-recipient spend equation.

The second-pass storage verification below passed (3.490 seconds). It exercises existing tests rather than claiming the synthetic maximal-body/raw-store cases are consensus-valid spends.

```
GOTOOLCHAIN=go1.27.3 GOMODCACHE=/home/pasich/go/pkg/mod GOCACHE=/home/pasich/.cache/go-build \
  go test -p 2 ./v2/chain -run 'TestBadgerFence|TestSecurity(ReorgLateInvalid|SuffixOverlay|LargeHistory)' -count=1
```

The lead's final combined-tree verification remains authoritative for the complete task. This review does not assert a full repository test pass or external audit.
