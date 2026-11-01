# Consensus invariants

These are the properties the validation code is required to uphold, with the
place each one is enforced. They are requirements and evidence pointers, not a
proof of security. Cryptographic soundness is a separate, open question (see
[RELEASE_READINESS.md](RELEASE_READINESS.md)).

Rules and encodings are specified in the
[protocol documentation](https://github.com/pasichDev/nosoX/blob/main/docs/protocol.md).

## Invariants

1. **Supply.** Issued supply at height `h` equals the sum of
   `BlockReward(i)` for `i = 1..h`, and equally the sum of all unspent
   values: **Σ unspent = Σ rewards**. Genesis allocates nothing. A spend
   destroys its fee and the block's coinbase re-creates it for the miner, so
   fees are moved, never minted or burned. There is no founder allocation and
   no protocol fee. Tests: `TestSupplyEqualsRewardsWithFeesAndReorg` (both
   stores, with a reorg).
2. **Coinbase.** The coinbase value is `BlockReward(height) + F` (`F` = total
   fee of the plain kernels, from the one helper `PlainKernelFees` that the
   balance equation also uses), overflow-checked in int64 and enforced by the kernel signature
   (`VerifyCoinbase` is called with exactly that amount), so a miner can claim
   neither more nor less. A block with `reward + F > 0` has exactly one
   coinbase output and one coinbase kernel, also after emission ends at height
   2,310,000, where fees are the only payment; a block with `reward + F == 0`
   has neither. The coinbase output must commit to the same point as the
   coinbase kernel's excess. The coinbase kernel has fee 0 and lock height
   `height + 60`; a coinbase kernel fee is also never counted in `F`, so the
   fee-0 rule is defense in depth rather than the only guard. Output feature 2
   (once a dev-fund draft) is unassigned and rejected. Tests:
   `TestCoinbaseMustClaimExactlyRewardPlusFees`,
   `TestPostEmissionCoinbaseIsFeesOnly`, `TestOutputFeatureTwoIsRejected`,
   `TestCandidateCoinbasePaysRewardPlusFees`, and one test per guard (each was
   shown to fail when its guard is removed; see the table below).
3. **Inputs.** Each input matches exactly one unspent output, appears once in
   the block, and carries the stored feature flag. A coinbase output cannot be
   spent until 60 blocks after its creation, exactly (a spend one block early
   is refused, at 60 accepted), also when the coinbase carries fees.
4. **Native transfers.** `sum(plain outputs) - sum(inputs) + fees*H` equals the
   sum of ordinary kernel excesses. Each ordinary kernel carries a valid
   Schnorr signature under its excess. Each plain output carries a verified
   range proof. The coinbase output is constrained separately (invariant 2). The
   header offset field must be zero.
5. **Binding.** The header commits to every input, output, proof, kernel and
   kernel signature through two ordered roots. Encodings are domain separated
   and length delimited. Validators recompute the roots. Unknown versions and
   feature flags are rejected.
6. **Atomicity.** A failed validation or storage error leaves the tip, indexes
   and unspent set unchanged. A reorganization replaces a whole suffix or
   nothing, and only when the incoming suffix has strictly greater accumulated
   work.
7. **Determinism.** The same genesis and the same history produce the same
   state in both storage backends.
8. **Bounded work.** Untrusted decoding and validation have explicit bounds.
   Cheap structural checks run before curve and Argon2id operations.
9. **Arithmetic.** Difficulty uses exact integer arithmetic with saturation.
   Timestamps cannot overflow the validator.
10. **Uniqueness.** An output commitment or kernel ID that ever appeared on the
    active chain cannot appear again.

## Where each invariant is enforced

| Invariant | Code | Representative tests |
|---|---|---|
| 1, 2 | `types.BlockReward`, `chain.validateBody`, `wallet.VerifyCoinbase` | `TestIssuanceScheduleIndependentSum` (`v2/types`), `TestSecurityBlockAuthorizationMutations` (`v2/chain`) |
| 3 | `chain.validateBody` | `TestSecurityNativeAuthorizationMaturityAndUndo`, `TestFeeCarryingCoinbaseMaturityBoundary` |
| 4 | `chain.validateBalance`, `crypto.PedersenSumZero`, `crypto.SchnorrVerify`, `crypto.VerifyRange` | `v2/chain/balance_test.go`, `v2/crypto` tests |
| 5 | `types.BlockRoots`, `chain.validateStructure` | `v2/types/hardening_test.go` |
| 6 | `Chain.ReorgTo`, `Store.ReplaceSuffix` | `TestSecurityShorterHeavierForkWins`, `v2/chain/badger_fence_test.go` |
| 7 | both stores, genesis pin on reopen | `v2/chain/store_contract_test.go`, `TestSecurityReopenPinsGenesis` |
| 8 | `chain.BodyResourceBytes`, `CheckReorgResourceBudget`, bounded P2P and RPC codecs | `v2/chain/resource_budget_test.go`, `v2/p2p/security_test.go` |
| 9 | `pow.LWMA3`, `Chain.validate` | `v2/pow/hardening_test.go`, `TestSecurityFutureTimestampCannotFreezeChain` |
| 10 | `Store.HasOutput`, `Store.HasKernel` | `v2/chain/hardening_test.go` |

### Guards on the coinbase and fee rules, and the test that fails without each

Each test below was run against a copy of the tree with the named guard
disabled and failed there. "Helper test" means the guard lives in a shared
function and the table-driven test of that function is what fails; the call
sites are covered by the second test named.

| Guard | Code | Test that fails without it |
|---|---|---|
| Coinbase output commit equals kernel excess | `validateBody` | `TestCoinbaseOutputMustCommitToKernelExcess` |
| Coinbase forbidden when reward + F is 0 | `validateBody` | `TestCoinbaseForbiddenWhenBlockPaysNothing` |
| Coinbase kernel fee is 0 | `validateBody` | `TestCoinbaseKernelFeeIsRejected`, `TestSecurityBlockAuthorizationMutations` (cases "coinbase fee", "coinbase lock" check the rule's own error) |
| Same fee total in balance and coinbase amount | `PlainKernelFees` | `TestFeeTotalsIgnoreCoinbaseKernels` (helper test), `TestCoinbaseKernelFeeIsRejected` |
| Coinbase maturity, exact boundary | `validateBody` | `TestFeeCarryingCoinbaseMaturityBoundary` |
| Capacity kept for the coinbase, mempool | `checkTransactionCheap`, `CoinbaseReserve` | `TestTransactionLeavesRoomForCoinbase`, `TestCoinbaseReserveTable` (helper test) |
| Capacity kept for the coinbase, miner | `selectTransactions`, `CoinbaseReserve` | `TestSelectionReservesCoinbaseCapacity`, `TestCoinbaseReserveTable` (helper test) |
| Supply equals rewards, including fee-carrying coinbase spends and after emission | whole `validateBody` | `TestSupplyEqualsRewardsWithFeesAndReorg`, `TestFeeCarryingCoinbaseMaturityBoundary`, `TestPostEmissionRunConservesSupply` |
| A mined transaction stays restorable after a reorg | `Pool.Confirmed`, `Miner.confirmMined` | `TestConfirmedKeepsMinedTransactionsForReorg`, `TestMinedTransactionsAreStashedForReorg` |

Limits of this evidence: the post-emission cases run through a synthetic schedule
store (the difficulty window and tip are synthetic; UTXO, output and kernel
indexes are real), not through 2.31 million mined blocks. The miner's
post-emission selection is tested through `selectTransactions` at the schedule
heights, not through a running miner. Wallet, RPC and P2P packages were not run
against mutants.

## Known exceptions to unqualified claims

- **Clocks.** The 540 s future-timestamp rule uses the validator's clock and
  applies to new blocks only (replay of stored blocks does not re-check it).
  Validators near the bound can briefly disagree. There is no median-past-time
  rule by decision: strictly increasing timestamps are retained (simulation in
  `v2/pow/timewarp_sim_test.go`).
- **Cryptographic conditionality.** The no-inflation argument holds only if the
  custom Schnorr signature and range proof are sound, the second generator `H`
  has no known discrete log relative to `G`, and the discrete-log problem is
  hard. None of this has been independently reviewed.
- **Memory backend.** The in-memory store writes a snapshot only on explicit
  `Save` or `Close`. The daemon uses the Badger backend. Durability of Badger
  depends on the operating system and storage hardware.
- **Capacity.** Atomic failure tests do not prove that every legal transition
  can be applied under all memory and disk conditions. Startup replay is linear
  in history in time and scratch disk. See [limits](https://github.com/pasichDev/nosoX/blob/main/docs/limits.md).
- **Network.** Decoder bounds do not establish resistance to Sybil or eclipse
  attacks or a bound on total resource use by many peers.
