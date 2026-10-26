# Consensus invariants (written before validation changes)

Baseline: 6179eb56d53768a19950f07e9c806fd384572c5d, clean tree, main.
These are requirements, not assertions about the implementation.

1. Issued supply at h equals the explicitly trusted genesis allocation plus
   sum(BlockReward(i), i=1..h). Fees transfer existing value to the configured
   destination; they are neither subsidy nor burn. Issued supply includes locked
   and unclaimed outputs. Circulating supply is not established by this audit.
2. Exactly the authorized subsidy is created per non-genesis block; no other
   feature flag may mint value. Coinbase output/kernel count, signature, amount,
   fee and maturity must be checked, including after issuance ends.
3. Each input matches exactly one existing UTXO, is unique in the block, matches
   stored features and ownership metadata, and satisfies maturity/lock rules.
   Legacy public blindings are not ownership: claims require a reviewed proof
   tying a supplied historical key to its address and network-bound message.
   Until that procedure exists, legacy spends must fail closed.
4. For native transfers: sum(plain outputs) - sum(inputs) + fees*H equals
   sum(transaction excesses); each excess has a valid Schnorr signature and each
   plain output has a cryptographically verified nonnegative range proof.
   Coinbase and transparent fee outputs are separately constrained. Offsets are
   unsupported and must be zero until their semantics are specified and tested.
5. The header binds every input, output, proof, kernel signature and ordered
   body field. Encodings are domain separated and length delimited. Validators
   independently recompute roots. Unknown versions/features are rejected.
6. Failure leaves tip, height/hash indices, UTXOs (all metadata), and persistent
   state unchanged. Reorgs are atomic across the whole suffix and only choose
   strictly greater accumulated valid work, never height alone.
7. Same trusted genesis and history imply byte-identical state on all backends.
   Stored/caller-owned slices must not mutate accepted history.
8. All untrusted decoding and validation are explicitly bounded; cheap
   structural rejection precedes expensive curve and Argon2 operations.
9. Expected difficulty uses exact overflow-safe integer arithmetic; timestamps
   cannot cause overflow or nondeterministic state acceptance.

Implementation/test references and unresolved gaps will be appended after review.

## Implementation evidence and limits after hardening

The requirements above remain requirements, not a proof of security. Exact
executed results and source manifests are in TEST_REPORT.md and
VERIFICATION_SUMMARY.md. The current isolated tests cover:

| Property | Implementation | Executed regression evidence |
|---|---|---|
| Scheduled subsidy / no unaccounted mint | chain.validateBody, wallet.VerifyCoinbase, types.BlockReward | BlockAuthorizationMutations, MissingCoinbaseRejected, SyntheticScheduleEdgesThroughAddBlock; types.IssuanceScheduleIndependentSum |
| Input authorization / maturity / unique spend | chain.validateBody, crypto.SchnorrVerify | NativeAuthorizationMaturityAndUndo, LegacyClaimFailsClosed; direct StoreRejectsImpossibleDeltas |
| Commitment conservation | chain.validateBalance, crypto.PedersenSumZero | NativeAuthorizationMaturityAndUndo including aggregate active UTXO commitments after consume/undo; balance negative tests |
| Real range verification | crypto.VerifyRange/VerifyRangeBorromean | Fake v1 and mutated proofs through AddBlock, opening/encoding/OR checks; independent arithmetic vectors are partial evidence |
| Complete body integrity | types.BlockRoots/TransactionID, chain.validateStructure | Full-body field mutations, stale-root versus invalid-proof rejection; canonical encoding fuzz results from earlier scope |
| Deterministic canonical state / history uniqueness | both stores, outputSeen/kernelSeen, genesis pin/replay | BackendParityAndNestedSlices, ReopenPinsGenesis, native historical replay rejection |
| Atomic failure / reorg | staged Chain.ReorgTo, Store.ReplaceChain, checkStoreDelta | ReorgRollbackAndStrictWork, ReorgCommitFailureUnchanged, BadgerAbruptExit, BadgerOversizeTransactionRollback (specific ErrTxnTooBig), StoreBadgerDecodeFailureUnchanged |
| Valid accumulated work | chain.blockWork / expectedDifficulty, pow.LWMA3 | ShorterHeavierForkWins, maximum arithmetic and zero-difficulty negative tests |
| Cheap bounded rejection | bodyBounds, ReorgTo preflight, bounded P2P/RPC codecs | ReorgRejectsMalformedBeforePrefixRead plus decoder/sync regression tests |

Names above omit the TestSecurity/Test prefix for readability where unambiguous.
All complete names and durations are recorded in TEST_REPORT.md and verbose logs.

Known exceptions to unqualified invariant claims:

- Time admission assumes synchronized UTC clocks; validators straddling the2h
  future bound may temporarily disagree. Identical deterministic encodings and
  state transitions do not eliminate this environmental assumption.
- Legacy authorization is mitigated by rejecting all claims, not implementing a
  verified migration. Snapshot economic legitimacy is unverified.
- No-inflation arguments remain conditional on custom proof/signature soundness,
  generator independence and discrete-log hardness; no independent crypto proof.
- Same-fee destination collisions block repeated fees under historical uniqueness
  (SP1). No destination/issuance constants were silently changed.
- Full-history staging and atomic Badger capacity are unresolved (SP2/SP3).
  Failure atomicity tests do not prove every legal transition can be applied.
- Memory AddBlock state is not durably committed per block; explicit Save/Close
  provides a snapshot. Badger sync-write durability still depends on OS/storage.
- Remote codec bounds do not establish arbitrary long-history resource bounds,
  maximum-size backend parity, complete crash recovery or Sybil resilience.

## Version3 follow-up evidence (supersedes earlier SP1/SP2/SP3 open dispositions)

SP123_COMPLETION.md records the frozen-source full build/vet/test/race and
combined storage results. SP1 preserves fee value/recipient with a context-bound
public blinding tweak; SP2 preserves the state equation through exact UndoAt and
suffix overlay; SP3 preserves atomic visibility through a durable MVCC fence.

New real AddBlock equal-fee/restart/reorg and negative-context regressions cover
SP1. Large-history count/read guards and exact undo/history tombstones cover the
SP2 algorithm change. Interrupted stage/genesis/different retry, large aggregate
publication and exact structural-body storage parity cover SP3. Synthetic large
storage fixtures are not claimed as cryptographically valid maximum-size blocks.

Normal reorg cost no longer scales with retained prefix length. Full startup,
trusted import and explicit memory Save still inspect history. Bounded protocol
suffixes may still be large, and retained MVCC versions/recovery scans lack an
independently verified lifecycle budget. These limits, cryptographic assurance,
legacy trust and actual device durability remain release gates.
