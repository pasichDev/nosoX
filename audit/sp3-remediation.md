# SP3 persistent storage remediation

Local changes, 2026-10-26. This is an implementation/verification record, not a production security certification.

Badger now opens in managed mode. Every transition is serialized by the store mutex, reads a committed active timestamp, validates its cheap store preconditions against that snapshot, and collects its mutation delta. `NewWriteBatchAt(freshTimestamp)` stages the delta in as many Badger transactions as necessary. Only after `Flush` succeeds does a small synchronous transaction publish the active timestamp fence. Public reads use the active timestamp; composite tip/hash/legacy reads use one transaction. Both stages and fence use synchronous writes. Conflict tracking is disabled because the store serializes writers; retaining managed conflict records indefinitely would otherwise grow memory.

The public state remains the complete old snapshot before fence publication and the complete new snapshot afterward. Appends use the same publication mechanism as suffix replacement, including duplicated block/output persistence. There is no consensus dependence on the size of one aggregate Badger transaction. Individual legal records remain bounded by the existing body and field limits. A block has at most an approximately 8 MiB encoded body; the largest undo record contains at most 10,000 outputs, each with at most a 65,536-byte proof and 256-byte legacy address (under approximately 660 MB including gob overhead). These are below Badger’s default `ValueLogFileSize` single-value limit of 1 GiB minus one byte (`txn.go:368`, `options.go:165`). Values above the 1 MiB threshold use value-log pointers for transaction-size accounting. The large undo bound is an argument from field limits, not an executed 660 MB fixture. `ReplaceSuffix` serializes only the touched suffix/index/UTXO/undo delta. Trusted full-chain replacement and startup verification still build complete derived state intentionally.

Every block records the complete outputs it spent in a persistent undo key. `UndoAt` supplies this metadata to the bounded fork overlay. Replacement deletes removed undo entries and persists new ones in the same fenced transition.

## Interrupted stage recovery

Fresh timestamps alone are insufficient: a later fence would expose old abandoned stage writes. The store records every touched stage key in memory. On reopen it recovers keys of every version newer than the active fence, including deletion tombstones, using the managed all-versions iterator. Before any subsequent publication it restores every such key from the active snapshot unless the new delta supersedes the key. Thus retrying a *different* candidate cannot inherit an abandoned spend, output, history identity, block, hash or tip.

`DB.MaxVersion()` includes current/immutable memtables and table maximum versions in pinned Badger v4.9.1 (`db.go:415`), so restart allocation remains above partially flushed stages. `managed_db.go` supplies explicit managed timestamps and `batch.go` splits on `ErrTxnTooBig`, waits for asynchronous writes in `Flush`, and documents that `Cancel` does not undo already committed batch pieces. `iterator.go` documents exclusive `SinceTs` semantics and returns deleted versions with `AllVersions`. These dependency sources were inspected locally before implementation.

A synchronous schema fence is established in an empty database before staging genesis. Nonempty databases without that fence are rejected; operators must explicitly reset/import for this protocol version. There is no silent old-schema migration.

Managed discard timestamp stays zero. No version reclamation or value-log garbage collection is enabled by this store: compaction must retain the old active snapshot and tombstones required to recover abandoned stages. **Disk use therefore grows with overwritten/deleted versions and abandoned stages.** Designing a safe reclaim/checkpoint protocol with reader tracking is future work. Startup and interrupted-stage recovery can scan stored history; normal successful reorgs do not scan the retained prefix. Disk exhaustion remains an I/O failure; the fence preserves old public state when stage writes fail. Durability still depends on OS/filesystem/device guarantees.

Gob record type identifiers depend on process registration order. Startup compares decoded block/output/undo records semantically and compares fixed-width index/metadata bytes exactly. This avoids false corruption errors across fresh processes while continuing to check every persisted logical key/value against replayed history.

## Regression evidence

Updated the previous oversized backend regression: it now injects a specific prepublication failure, checks unchanged public state, then proves the same large replacement succeeds. It no longer expects `ErrTxnTooBig` as acceptable parity behavior. Synthetic backend fixtures do not claim full cryptographic consensus validity.

New tests cover partial durable stages, prepublication interruption, close/reopen, retrying a different candidate, abandoned input-deletion/output/hash cleanup, unfenced schema rejection, and an exact 8 MiB body-bound/10,000-output append and suffix replacement compared with memory-derived state. The maximum-body fixture uses synthetic proof bytes and demonstrates storage capacity at structural bounds, not a fully valid signed/proven maximum-size consensus block. Existing abrupt-process-exit coverage verifies a published reorg survives `os.Exit`; new subprocess tests exit during partial stage and immediately before publication, then verify old complete state and a different successful retry.

Executed commands (writable caches set to `/home/pasich/go/pkg/mod` and `/home/pasich/.cache/go-build`):

- `go test -p 2 ./v2/chain -run '^(TestBadgerFence|TestSecurityBadger|TestSecurityStoreBadger)' -count=1`: PASS, package 4.531s before adding the new abrupt-unpublished subprocess regression.
- `go test -race -p 2 ./v2/chain -run '^(TestBadgerFence|TestSecurityBadger|TestSecurityStoreBadger)' -count=1`: PASS, package 33.220s; repeated after first-genesis crash coverage and Open cleanup, PASS 30.326s.
- After the final serialized `UndoBlock` and strict gob record-EOF changes, `go test -p 2 ./v2/chain -run '^(TestBadgerFence|TestSecurityBadger|TestSecurityStoreBadger|TestSecurityNativeAuthorizationMaturityAndUndo)' -count=1`: PASS, package 15.880s.
- `git diff --check`: PASS.

No maximum 1,024 × 8 MiB cryptographically valid suffix was constructed. Aggregate atomic publication is implemented through arbitrarily many bounded batches rather than empirically claiming this maximum fixture was executed. The existing protocol bounds cap aggregate memory; large accepted deltas can still require substantial memory and disk. No deployment, network experimentation, commit or publication occurred.
