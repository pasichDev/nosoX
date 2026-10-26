# Independent defensive second pass

Reviewed 2026-10-26 against `audit/CONSENSUS_INVARIANTS.md` after the initial
boundary work was frozen. Scope was read-only inspection of current
`v2/chain/validation.go`, `v2/chain/chain.go`,
`v2/chain/badger_store.go`, `v2/types/commitments.go`, and
`v2/miner/miner.go`, plus relevant existing tests. No production files or tests
were modified, no exploit was constructed, and no network actions were taken.
No new test executions were performed for this pass: test references below
mean inspected coverage, not fresh passing results or a security guarantee.
The lead was notified immediately of actionable findings. Source line numbers
refer to the worktree as read and may move during remediation.

## Findings requiring resolution or explicit acceptance

### SP-1 — High: deterministic fee outputs conflict with historical uniqueness

`validation.go:231` rejects every output whose commitment has appeared anywhere
in the active history, including outputs already spent. That is a necessary
replay defense for ordinary outputs, and the new history tests demonstrate why
it cannot simply be removed. However, `miner.go:299-304` constructs the
transparent fee output using `ExpectedDevFundCommit(totalFee)` alone. The
existing `TestExpectedDevFundCommitDeterministic` explicitly asserts identical
fees produce identical commitments. A later fee-paying block with the same
aggregate fee therefore necessarily selects an already-seen output commitment
and is rejected before `validateDevFund` runs. Spending the first output cannot
fix this because `HasOutput` is a historical index.

This can stall a miner repeatedly selecting an otherwise valid fee-paying
transaction: revalidating the transaction succeeds because the fee output is
constructed separately, but the completed candidate fails application.
Zero-fee blocks may still advance, so this is fee-payment/miner liveness rather
than an assertion that every chain immediately stops.

Existing dev-fund tests call the isolated destination validator and test
within-block duplicates. They do not cover two fully validated fee-paying
blocks with the same aggregate fee and historical indexes enabled. Resolution
requires an explicitly reviewed unique fee-output identity/commitment design
or another accounting design preserving value conservation and destination
ownership; bypassing historical uniqueness for arbitrary outputs is unsafe.

Status when this document was written: reported to lead; not patched by this
reviewer. Required regression: same positive aggregate fee in two sequential
real signed/proven blocks on both memory and Badger, including restart/reorg.

### SP-2 — High: reorg resource consumption grows with all historical blocks

`chain.go:255-264` rebuilds a new memory store from genesis through the common
ancestor while holding the chain-wide mutex. Only afterward, at `:274-280`,
are incoming block structures, roots, authorization and proofs validated.
The incoming suffix and removed suffix are bounded to 1,024 blocks, but the
copied prefix is not bounded by either limit. Each stored block and its dynamic
proof/signature slices are copied, and full derived historical indexes are
retained in the staged state.

Consequently a malformed candidate with a known recent ancestor can trigger
O(total chain history) memory/CPU and block unrelated chain/RPC operations
before even the first candidate's cheap structural rejection. A structural
preflight of the complete suffix would remove the easiest avoidable work, but
would not make staging a structurally valid, later-invalid suffix bounded.
Snapshot/delta staging with explicit budgets is needed for long-lived chains.

The same whole-history reconstruction occurs in Badger `stateEntries`, and
`ReplaceChain` iterates the complete database. This is a resource/liveness gap
against invariant 8, not evidence that the final transactional replacement
partially commits. Existing small-chain reorg rollback tests do not bound
cost as historical chain length increases.

Status: reported to lead; no changes by this reviewer. Required evidence:
reorg preflight rejection before historical copying and bounded staging cost
on a large synthetic history with a small recent suffix.

### SP-3 — High assurance gap: backend transaction capacity is not a consensus bound

`BadgerStore.ReplaceChain` deliberately uses one transaction and propagates
transaction-size errors. That preserves old state on failure. However,
consensus permits up to 1,024 incoming blocks, each with up to an approximately
8 MiB body, while the Badger transaction capacity is finite. A valid suffix can
therefore require far more atomic writes than the configured storage
transaction supports; the memory backend has no equivalent capacity error.
The append path also persists both the complete block and new UTXO encodings,
so the 8 MiB body estimate is not itself a bound on storage transaction bytes.

`TestSecurityBadgerOversizeTransactionRollback` intentionally bypasses consensus
with 40,000 outputs; it establishes rollback for oversized backend work, not
that every consensus-legal append/reorg fits the backend. No maximum-legal-body
append and maximum-legal-delta reorg parity test was found. I did not measure
the exact Badger transaction threshold or construct a valid oversized suffix,
so this is an identified design/test gap rather than a claimed tested
acceptance divergence for a specific block.

Status: reported to lead. Required evidence is an explicit relationship between
all legal consensus deltas and the atomic persistence design, or a documented
production blocker with a snapshot/version-switch storage strategy. Splitting
one reorg into visible partial commits would violate invariant 6.

### SP-4 — Medium: miner does not abandon work when the canonical tip advances

`miner.run` comments that `grindBlock` can return because a new tip arrived, but
`grindBlock` observes only its mining context and its own nonce results. It
never checks or subscribes to the canonical tip. After a peer extends the chain,
a high-difficulty worker may keep hashing the obsolete parent until it finds
a nonce or mining is explicitly canceled. `AddBlock` then safely rejects the
stale result, so this is lost availability/work, not invalid-block acceptance.

Existing miner tests use difficulty one and do not exercise external tip
advancement during a long grind. A cancellation-aware tip refresh and a test
using controlled work are needed. Candidate-build retries also use a fixed
uncancellable two-second sleep; this bounds extra stop latency but does not
provide immediate cancellation.

### SP-5 — Medium hardening gap: storage lookup errors lose their cause

In `badger_store.go`, `hasSeen`, `HasUTXO`, `HeightOf`, and `Tip` reduce backend
errors to false/missing values. Input lookup failures normally reject a spend,
which is fail-closed. In contrast, an output/kernel historical-index read error
is indistinguishable from absence at `validation.go:231` and `:267`. Runtime
storage read failures could therefore skip a historical uniqueness check if a
subsequent write succeeds. Startup replay plus exact `verifyState` protects
against persisted inconsistency found at boot, but does not replace propagating
runtime errors through validation.

No fault-injection test for historical-index read errors followed by a successful
write was found; no such failure was induced during this review. Consider
error-returning Store lookups, distinguishing an absent key from an unavailable
or corrupt store, before making fail-closed storage claims.

## Checks that appear resolved in the inspected paths

- Every candidate is structurally bounded and its independently recomputed
  ordered body roots must match before normal extension PoW/proof work.
  `commitments.go` length-delimits variable fields and list elements, includes
  counts, and incorporates inputs and kernel signatures. Output completeness
  additionally depends on `EncodeOutput`, which was outside this pass's source
  scope; existing output/body mutation tests exercise that dependency.
- Unknown output/kernel features and unsupported offsets fail closed. Existing
  tests mutate versions, features, offsets and network magic.
- Non-genesis positive issuance requires exactly one matching coinbase output
  and kernel, zero coinbase fee, exact maturity lock, valid point and a valid
  signature checked against the scheduled amount. After issuance ends, any
  coinbase output/kernel is rejected. The schedule-edge tests use a disclosed
  bounded synthetic Store rather than claiming a multi-million-block replay.
- Inputs are unique, checked against stored feature/ownership metadata and the
  current UTXO set; legacy spends remain disabled. Coinbase maturity checks
  stored history rather than trusting the input feature supplied by the caller.
  Native kernels verify signatures and plain outputs verify range proofs before
  the final balance check. Cryptographic implementation correctness and native
  cross-network signing-domain design were not independently reviewed here.
- Output and kernel historical indexes survive ordinary appends and are
  reconstructed for the selected active history on replacement/undo. Existing
  tests cover spent-commitment recreation, historical kernel reuse, removal of
  orphan history identities and restoration of complete spent-output metadata.
- Reorg validation occurs in an isolated Store, compares strictly greater
  accumulated target-derived work with `big.Int`, and only then replaces live
  state. Old and candidate suffixes share the same trusted prefix. Tests cover
  later-invalid suffixes, equal-work rejection, old hash-index removal, injected
  replacement failure and a shorter-but-heavier fork.
- Memory replacement constructs a complete new Store before assignment.
  Badger replacement writes/deletes in a single database transaction; synchronous
  writes are enabled. Startup replay pins trusted genesis and compares the
  complete expected Badger keyspace, including derived indexes/metadata. Existing
  tests include abrupt-process exit, missing persisted tip, persistence, mutation
  isolation and backend comparison. Capacity/resource limits remain SP-2/SP-3.
- Parent/height progression, network consistency and strictly increasing
  timestamps are enforced. Difficulty history deltas use `big.Int` subtraction,
  clamp non-int64 results and fail with difficulty zero when history is missing.
  Reorg work uses the actual PoW target rather than height. The correctness of
  `pow.LWMA3` and `pow.Target` internals was outside this restricted pass.
- Future timestamp subtraction is overflow-safe and enforces the stated two-hour
  clock-relative drift limit. Existing tests exercise `MaxInt64`, rejection one
  second beyond the limit and acceptance at the limit.
- The miner persists reward secrets before constructing signed coinbase outputs,
  refuses to proceed when no reward keystore exists, advances parent time without
  int64 overflow, caps transaction aggregation, revalidates pending transactions
  and commits the complete body roots. AddBlock remains the final independent
  acceptance gate even if the tip changes during candidate construction.

## Test interpretation and remaining assurance limits

`v2/miner/integration_test.go` still calls its empty-pool coinbase test an
"end-to-end gate for production launch" and says it covers plain-output range
proof verification. The test mines coinbase-only blocks and never constructs a
plain output, so that particular proof-verification branch is not exercised.
The chain native-spend tests and separate P2P mature-native-transaction test do
exercise real proofs. The miner comment should be narrowed to its actual
coverage; no single inspected test establishes launch readiness.

The wall-clock future-drift check necessarily assumes appropriately synchronized
validator clocks. Identical history presented while different local clocks
straddle that boundary can receive temporary different acceptance results, and
clock rollback can prevent reopening a previously accepted recent history until
time catches up. This is not arithmetic overflow, but invariant 9's determinism
wording needs to state the environmental clock assumption explicitly.

The tests inspected here are useful checks of specific behaviors. They do not
establish maximum-size backend parity, long-history bounded reorg resources,
complete valid repeated-fee operation, interrupted writes at every instruction,
a cryptographic audit, or consensus safety under arbitrary concurrency/faults.
SP-1 through SP-3 should be resolved or retained as explicit deployment blockers;
this review does not certify the code as secure or production-ready.

## Lead verification disposition (subsequent changes; original review preserved)

See VERIFICATION_SUMMARY.md and TEST_REPORT.md for exact executed results on
Go1.27.3 and source manifests. This addendum does not replace the independent
reviewer's original observations with a blanket approval.

- SP1 remains an explicit High blocker. The existing deterministic-fee test
  passes and the formula/identity collision is unchanged. No full sequential
  fee-block scenario was added in the later verification-only pass.
- SP2 has cheap whole-suffix structural preflight before retained-prefix reads.
  Its existing regression passed0.09s. Full-history staging remains O(history),
  so the High resource blocker is unresolved.
- SP3 remains a High capacity/parity assurance blocker. The existing backend
  fault test was strengthened to require specifically badger.ErrTxnTooBig and
  passed under race (test3.36s, package4.473s), retaining the old full state.
  It deliberately uses a non-consensus-sized fixture and does not prove every
  valid suffix fits one transaction or both backends converge at those limits.
- SP4 has parent-change abandonment and an existing miner regression; full
  current race verification passed. The stale readiness/proof-coverage comment
  in the miner test was corrected. Two-second retry latency remains bounded.
- SP5 is reduced at commit by error-returning delta checks inside the same Badger
  transaction; corrupted UTXO/tip reads fail unchanged in direct-store tests.
  Boolean read APIs outside that commit boundary still warrant redesign.

The verification pass introduced no new discovery campaign or attack simulation.
No deployment, publication, merge or repository-setting change occurred.

## Later remediation of SP1/SP2/SP3

After the verification-only pass, the user authorized fixes. The current
version3 implementation, integrated executed results and remaining limits are
in SP123_COMPLETION.md. SP123_SECOND_PASS.md records a new independent internal
review of the combined suffix/fence implementation. The original SP1/SP2/SP3
observations above remain historical evidence, not the latest code disposition.
No publication or deployment occurred.

## Version4 follow-up

The later user-authorized blocker remediation is recorded in BLOCKERS_V4.md.
SP1 context-bound fee outputs, SP2 suffix-only staging and SP3 fenced persistence
remain in force, with new native resource limits, safe MVCC lifecycle and
streaming startup verification. REMAINING_BLOCKERS_SECOND_PASS.md records a
separate scoped internal review of these fixes and the legacy claim integration.
External crypto/economic evidence and remaining capacity/durability gates are
still explicit; the earlier independent internal findings above remain intact.
