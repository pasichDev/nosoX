# SP2 remediation: bounded suffix overlay

The original root cause was `Chain.ReorgTo` replaying genesis through the
ancestor into a fresh memory store before validating the new suffix. Raw
`UndoBlock`, memory replacement resizing, and Badger full-state replacement
could repeat whole-history work. Cheap malformed-body preflight alone did not
bound a structurally valid candidate failing later authorization.

`ReorgTo` now creates an isolated overlay by rolling back only the canonical
suffix (at most 1,024 blocks). Each block has an exact spent-output undo record,
including proof bytes, feature, legacy address and amount. The overlay tracks
block, undo, hash, UTXO, output-history, kernel-history and legacy-index changes,
including tombstones. Retained state is read lazily. Incoming blocks still pass
the same `Chain.validate`, checkpoints, clock, proof, signature, economics,
maturity and difficulty checks. Strict accumulated work still gates the final
atomic `ReplaceSuffix`; no candidate delta is published during validation.

Memory block history uses a height map, avoiding a slice-capacity resize that
would copy the retained pointer prefix during suffix publication. Memory
`ReplaceSuffix` prepares and checks the complete delta before changing canonical
maps. `UndoBlock` uses that same suffix path. Full history replay remains
intentional for trusted `ReplaceChain`, startup verification and the explicit
memory `Save` snapshot; these are not the ordinary reorg path. Badger's separate
SP3 implementation consumes the same overlay delta for fenced publication.

## Regression evidence

Executed locally with `GOTOOLCHAIN=go1.27.3`, existing module/build caches and
`-p 2`; no public-node traffic, network attack or load testing.

- RED: `go test -p 2 ./v2/chain -run
  '^TestSecurityReorgLateInvalidDoesNotReadPrefix$' -count=1` failed on the
  original implementation, panicking at the guarded unrelated-prefix read
  in `Chain.ReorgTo` (old chain.go:270).
- GREEN: new overlay/large-history/late-invalid tests passed, package 1.430s.
  The 100- and 10,000-block synthetic fixtures each need exactly two block reads
  to stage a one-block rollback; staging contains one block/undo/hash entry.
  Actual late-invalid `ReorgTo` on both fixtures reads exactly
  `DifficultyWindow+2` blocks (ancestor plus fixed difficulty window), with a
  guard forbidding any earlier prefix read. These are raw synthetic histories,
  not claims that 10,000 blocks were cryptographically mined and replayed.
- The exact-undo test checks proof isolation and complete legacy metadata;
  orphan output/kernel/hash identities disappear in the overlay and after
  publication. A later impossible raw-store suffix leaves old memory state and
  undo available.
- Existing strict-work/rollback/commit-failure, shorter-heavier fork and native
  maturity/undo tests together with new tests passed, package 35.450s. Existing
  backend helpers exercise both memory and Badger where applicable.

## Remaining limits

Cost is bounded by removed/new suffix bodies and the fixed difficulty window,
not by total retained history. The legal maximum suffix can still be large;
this is a complexity bound, not a low-memory benchmark or production readiness
claim. Initial loading, full verification, explicit full replacement and memory
snapshots deliberately remain O(total history). Public boolean Store lookups
still have the SP5 API limitation; the overlay's raw consistency checks support
an optional error-preserving backend reader so suffix publication can preserve
read failures. SP1 and SP3 are documented by their respective remediation work.

Fresh broader verification during implementation:

- `go test -p 2 ./v2/chain -count=1`: PASS, package 88.548s.
- `go test -race -p 2 ./v2/chain -run
  'TestSecurity(ReorgLateInvalid|SuffixOverlay|LargeHistory|ReorgCommitFailureUnchanged)'
  -count=1`: PASS, package 6.241s, including raw-reader error propagation.
- `go vet -p 2 ./v2/chain`: PASS.
- `git diff --check`: PASS.

Other agents were implementing SP1/SP3 concurrently; the lead's final combined
verification remains authoritative for the completed combined source tree.
