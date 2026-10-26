# Chain and persistence audit

Scope: `v2/chain/**`, baseline `6179eb56d53768a19950f07e9c806fd384572c5d`.
This records observed fixes and limitations, not a claim that the chain is secure.

## Reproduced before production changes

`GOMODCACHE=/home/pasich/go/pkg/mod GOCACHE=/home/pasich/.cache/go-build go test -p 2 ./v2/chain -run '^TestSecurity' -count=1` exited 1:

- `TestSecurityMissingCoinbaseRejected`: accepted a non-genesis block without subsidy output, kernel, or signature.
- `TestSecurityStoredBlocksAreImmutable`: caller mutation rewrote accepted genesis.
- `TestSecurityReopenPinsGenesis`: state reopened under a different configured genesis.

Source inspection additionally established absent ordinary kernel authorization,
missing maturity/metadata/duplicate/feature checks, incomplete input reconstruction
on undo, reorg mutation before complete validation, ignored rollback errors,
and fork choice with no accumulated work comparison. These paths were replaced
and negative pipeline coverage added.

## Implemented rules

- Require current version, full ordered body roots, network continuity, zero
  unsupported offset, positive difficulty, nonnegative advancing timestamps,
  parent/height/difficulty/checkpoints, and valid PoW. Structural/body count,
  field length, and aggregate size bounds precede expensive verification. PoW
  verification precedes body signatures/range proofs to reject cheap-to-forge
  invalid-PoW bodies before hundreds of proof verifications.
- Exactly one output and one matching coinbase kernel while subsidy is positive,
  no coinbase after issuance, zero coinbase fee, exact maturity lock height,
  mandatory Schnorr authorization under commitment minus scheduled reward.
  Spending coinbase is checked against its actual creation block.
- Every input must be unique and match an existing UTXO's stored feature/address/
  amount. Legacy/GVT claims fail closed; no historical ownership scheme invented.
- Only supported ordinary output/kernel features are accepted. Enforce canonical
  nonidentity public points, all ordinary kernel signatures, lock heights,
  cryptographic range proofs, and balance. Reject duplicate outputs, existing
  UTXO collisions, and duplicate kernels. Fee sums are bounded to signed-int64.
- Mempool admission can use `Chain.ValidateTransaction`, with the same state,
  proof, authorization, maturity, and balance checks; miners add subsidy and the
  separately constrained fee destination output.
- The supplied genesis is an explicit trust anchor, structurally checked with
  pinned full-body roots. Existing state must match that genesis and every
  non-genesis block is replayed through validation before startup succeeds.
  Badger's full derived state is compared against replay to detect missing,
  extra, or inconsistent persistent UTXOs/indices.
- Memory writes/getters clone all dynamic slices. Undo rebuilds complete output
  records from retained history rather than trusting lossy input metadata.
- Reorg validates an isolated candidate before mutation. Only strictly greater
  accumulated `floor(2^256/(target+1))` work wins. Badger replaces canonical blocks,
  hashes, UTXOs, and legacy indices in one transaction; memory swaps prepared
  state. Errors before commit leave the old state intact. Badger sync-writes are
  enabled. Memory snapshots use file fsync, rename, and directory fsync.

## Verification so far

After fixes, `go test -p 2 ./v2/chain -run '^TestSecurity' -count=1`
passed in 14.635s (module/cache environment as above). Tests include both
backends; mandatory subsidy and signed reward mutation; network, version,
offset, features, fee and maturity mutation; invalid later fork block rollback;
equal-work rejection; greater-work selection; injected reorg commit failure;
valid mature native spend versus forged excess signature and duplicate input;
complete undo restoration; Badger abrupt subprocess exit without Close followed
by pinned-genesis reopen and state verification. More verification follows below.

## Unresolved / material limitations

1. **Fee destination collision / liveness:** Existing economics pays all public
   fees to `F*H + DevFundPoint`, not the miner. Equal fee totals generate identical
   commitments. Previously storage silently overwrote the earlier UTXO; hardened
   validation rejects that collision while it remains unspent. A reviewed
   height-bound tweak/accumulator design is needed for repeated equal fee totals.
   The existing fee destination was preserved; changing it is not an audit fix.
2. **Legacy migration blocked:** No independently justified procedure ties the
   supplied historical public key to a v1 address with a network-bound claim.
   Legacy/GVT spends remain disabled, including legitimate holder claims.
3. **Reorg scalability:** Atomic replacement currently materializes/re-encodes the
   full retained history in RAM; writes only changed keys in a single transaction.
   Badger transaction size limits fail closed and can prevent otherwise valid
   large-suffix reorgs. Never
   fix this by splitting the replacement into independent transactions.
4. **Storage trust and resource use:** Gob state is local trusted storage, not a
   bounded hostile network codec. Startup replay is linear in history and proof
   verification; malicious local snapshots can exhaust resources. Boolean Store
   read APIs conflate missing keys and backend errors; startup checks detect many
   corruptions, but operational error propagation should be redesigned.
5. **Crash coverage:** Tested abrupt process exit after successful whole-reorg
   commit, not randomized power loss at every Badger WAL/fsync boundary. Underlying
   Badger/OS durability semantics remain dependencies.
6. **Timestamp policy:** Advancing timestamps and overflow-safe deltas are enforced.
   A new consensus admission rule rejects timestamps more than two hours ahead
   of the local validator UTC Unix clock. Arithmetic uses big integers so
   MaxInt64 cannot wrap the bound. Accurate sufficiently synchronized validator
   clocks are an explicit assumption; historical blocks replay through the same
   rule. Median-past-time and an agreed deterministic clock source remain absent.
7. **Consensus break:** Version 2 body binding, mandatory authorization, network
   binding and stricter state checks require an explicit reset/migration policy.
   Prior permissive histories are rejected, not silently upgraded.

## Additional fresh evidence

Under Go 1.27.3, `go test -race -p 2 ./v2/chain -count=1` exited 0
(87.691s), before the final added fault/parity/timestamp cases.
`go vet -p 2 ./v2/chain` exited 0.
`TestSecurityBadgerOversizeTransactionRollback` forces Badger's actual transaction
size failure with 40,000 distinct output records and confirms unchanged full state.
An initial 16MiB single value did not trigger that limit because Badger stores
large values outside the memtable; the final test uses many moderate values.
`TestSecurityShorterHeavierForkWins` passed (23.312s): a 100-block steady-time
chain is replaced by a fully mined and validated 91-block fast fork whose last
block has difficulty 120. This distinguishes accumulated work from height.
Both backends pass parity and nested signature-slice alias checks. Missing Badger
tip metadata now fails closed rather than reinitializing a nonempty database.
`TestSecurityFutureTimestampCannotFreezeChain` passed (0.676s), rejecting both
now+7201 seconds and MaxInt64 specifically for future drift, accepting now+7200.

## Final chain additions and scope distinctions

- Historical commitments and unsigned kernel IDs are indexed on the active
  canonical chain (memory maps and Badger `o`/`k` keys). Output uniqueness includes
  spent outputs. Reorg/undo reconstruct those indices atomically; orphan history
  does not permanently reserve identifiers. This prevents a balance-valid
  `A -> B -> A` recreation from making an old signed transfer replayable.
  The mature native pipeline test demonstrates former admission by wrapping the
  same real validator with only the historical lookups disabled, then checks
  rejection through both `ValidateTransaction` and `AddBlock` with indexes active.
  A valid zero-value range proof and previously signed excess also reproduce
  historical kernel replay without its index; the new index rejects it.
- Full retained UTXO commitments in the 61-block native spend scenario are
  algebraically checked against independently counted authorized issuance using
  fixture-known blindings, both after consumption/replacement of the first
  coinbase and after undo. This checks value in actual unspent state, not just
  block heights or helper arithmetic.
- `TestSecuritySyntheticScheduleEdgesThroughAddBlock` passed (0.639s). It supplies
  an explicitly synthetic bounded tip/difficulty-window Store, then calls the
  real `AddBlock` path at heights 209999, 210000, 210001, 2309999, 2310000 and
  2310001. Correct scheduled issuance succeeds; a fully signed extra unit or
  post-issuance coinbase fails; a signed MaxUint64 ordinary fee fails overflow
  checks before any write. This is not evidence that 2.31 million blocks were
  mined or replayed. Independent full-schedule arithmetic is covered by lead
  types tests.
- The mature real-chain proof mutation tests distinguish rejection reasons:
  changed body without changed roots fails body binding; updated roots with
  invalid Borromean proof or 33-byte version-1 placeholder fail `ErrBadOutput`;
  forged ordinary signature fails kernel authorization; changed input feature
  fails stored metadata matching. Legacy theft fails specifically because the
  ownership procedure is unavailable.
- Fresh pre-historical-index full suite: Go1.27.3
  `go test -p 2 ./v2/chain -count=1` exited 0 (55.653s),
  `go test -race -p 2 ./v2/chain -count=1` exited 0 (156.969s), and
  `go vet -p 2 ./v2/chain` exited 0. Lead runs final repository verification after
  the last historical-index additions and mechanical module-path change.
- Economic documentation contradiction: `GVTBaseValue=70_000_000_000` base units
  is **700 NOSO** at 100,000,000 units/NOSO, while comments call it 70. The
  historical constant is preserved; changing it requires an explicit economic
  decision. Genesis pins the trusted supplied allocation rather than claiming
  to prove a historical migration snapshot independently.

## Storage-contract second pass

The raw exported Store is a trusted persistence boundary, not a second complete
consensus validator: trusted callers must still pass blocks through Chain for
PoW, signatures, proofs, subsidy, fees, feature policy and legacy authorization.
However, an erroneous raw write must not corrupt canonical state or its indices.

Before the second-pass fix, `go test -p 2 ./v2/chain -run
'^TestSecurityStoreRejectsImpossibleDeltas' -count=1` exited 1: both backends
accepted missing and duplicate inputs, mismatched stored input feature/address/
amount, duplicate outputs, outputs already unspent or spent historically, a
commitment present as both input and output, and duplicate or historical kernels.
Height/parent guard cases already rejected correctly.

A shared cheap delta preflight now checks those conditions before mutation.
The memory store preflights before modifying maps. Badger checks the existing
tip, parent, target block indices, every input's actual decoded stored record,
and output/kernel history within the same update transaction and its read set.
It distinguishes missing keys from decode/backend errors and reuses the exact
preflight spent records to remove legacy indices; no nested database View is used
for the transition. Full-history replacement uses the same preflight when building
its staged state, preserving identical rejection semantics on both backends.

The direct-store test fixtures explicitly distinguish storage validity from
consensus validity: the trusted initial legacy allocation is retained, while raw
follow-up deltas deliberately omit cryptographic authorization to test only the
storage contract. No consensus/genesis fixture is relaxed. Each impossible write
and complete-chain replacement must fail with byte-identical canonical derived
state. Additional Badger tests corrupt UTXO encoding and tip encoding, assert a
failed raw write, and compare every raw durable key/value before and after.

Fresh Go1.27.3 results after this fix:

- Direct-store red/green test: fixed targeted run exited 0 (1.490s).
- `go test -race -p 2 ./v2/chain -run '^TestSecurityStore' -count=1`
  exited 0 (5.171s), including direct replacement and decode-failure cases.
- `go vet -p 2 ./v2/chain` and `git diff --check -- v2/chain` exited 0.
- Final complete chain suite after raw-store preflight:
  `go test -p 2 ./v2/chain -count=1` exited 0 (59.979s).
