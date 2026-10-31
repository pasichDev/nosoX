# Security findings

This is a summary of the problems found during internal hardening of this
codebase, and how each stands today. It is self-contained. It comes from the
maintainers' own review and is not an independent audit. The review round of
2026-10-31 (below) was done by AI-assisted internal review of the working
tree; it is not an independent audit either, and nobody outside the project has
checked its conclusions.

A finding marked "fixed" has a code change and regression tests. That is
evidence for the specific condition, not a proof that the area is secure. Tests
are finite.

IDs are stable labels. Some findings concerned migration and import code from an
earlier design. That code was removed in protocol version 5, so those findings
are closed by removal.

## Status overview

| ID | Severity | Area | Status |
|---|---|---|---|
| NX-001 | Critical | Ordinary kernel signatures not enforced | Fixed |
| NX-002 | Critical | Coinbase not authorized; unaccounted issuance | Fixed |
| NX-003 | Critical | Migration claims had no ownership check | Closed by removal |
| NX-004 | Critical | Range proof accepted on shape alone | Fixed |
| NX-005 | Critical | Header did not bind the full body | Fixed |
| NX-006 | Critical | Failed reorg could partly rewrite state | Fixed for covered cases |
| NX-007 | Critical | Duplicate spends, feature and maturity bypasses | Fixed |
| NX-008 | High | Genesis and stored history could change unchecked | Fixed for covered cases |
| NX-009 | Critical | Identity points allowed universal signatures | Fixed |
| NX-010 | High | Non-canonical points, scalars and proofs | Fixed |
| NX-011 | High | Unsafe wallet, slate and secret-file handling | Fixed for covered cases; residual risks below |
| NX-012 | High | Remote input panics, allocation, missing auth | Fixed for covered cases; residual risks below |
| NX-013 | High | Difficulty arithmetic wrapped; zero difficulty verified | Fixed |
| NX-014 | High | Spent commitments and kernels could be replayed | Fixed |
| NX-015 | High | Far-future timestamp could freeze the chain | Fixed |
| NX-016 | High | Order signer not bound to account in old network code | Closed by removal |
| NX-017 | High | Equal fee totals produced identical fee outputs | Fixed |
| NX-018 | High | Custom proof construction has no independent review | **Open** |
| NX-019 | High | Secret operations are not constant time | **Open** |
| NX-020 | High | Provenance of initial supply unverified | Closed by removal |
| NX-021 | High | Reorg cost and capacity | Mitigated; limits remain |
| NX-022 | High | Storage version retention and failed-retry growth | Mitigated; limits remain |
| NX-023 | High | Legal block and undo sizes were impractically large | Mitigated; limits remain |
| SP-4 | Medium | Miner kept working on a stale parent | Fixed |
| SP-5 | Medium | Storage read errors indistinguishable from absence | Reduced; interface limit remains |

## Fixed findings

**NX-001 Kernel signatures (Critical).** Block validation checked commitment
balance but never required proof of knowledge of the excess secret, so a block
producer could submit a balanced spend without authorization. Now every ordinary
kernel signature is verified over `types.KernelSigningMessage` (domain, network magic and kernel ID) under a
canonical, non-identity excess point, and lock heights are enforced.
Code: `chain.validateBody`. Tests: `TestSecurityNativeAuthorizationMaturityAndUndo`,
`TestSecurityBlockAuthorizationMutations`.

**NX-002 Coinbase authorization (Critical).** A missing or unsigned coinbase
allowed unaccounted issuance. Now, while the reward is positive, a block needs
exactly one coinbase output and kernel with matching commitment, fee 0, lock
height `height + 60` and a valid signature. After issuance ends neither may
appear. Fee sums are checked against `int64` overflow.
Tests: `TestSecurityMissingCoinbaseRejected`, `TestSecuritySyntheticScheduleEdgesThroughAddBlock`.

**NX-004 Range proof shape bypass (Critical).** An earlier proof format was
accepted when it had the right length, without verifying anything. That format
is removed. Only the current encoding is accepted, and it is cryptographically
verified. Whether the construction itself is sound is NX-018.

**NX-005 Body binding (Critical).** The header committed to an incomplete view of
the body. Now two roots commit to the ordered outputs and to the ordered inputs
and signed kernels, including proofs and signatures, with list counts and
length-delimited fields. Validators recompute them. The header offset field must
be zero, because offsets have no defined semantics.
Code: `types.BlockRoots`, `chain.validateStructure`.

**NX-006 Atomic reorganization (Critical).** A failed reorganization could leave
state half rewritten. Now a candidate suffix is validated against an isolated
overlay and committed in one atomic replacement. Fork choice compares accumulated
work, not height.
Tests: `TestSecurityReorgRollbackAndStrictWork`, `TestSecurityReorgCommitFailureUnchanged`,
`TestSecurityShorterHeavierForkWins`, `TestSecurityBadgerAbruptExit`.

**NX-007 Spend rules (Critical).** Inputs must now be unique, match an unspent
output and its stored features, and coinbase outputs must be 60 blocks old.
Body item counts are bounded.

**NX-008 Genesis and history (High).** The node now pins the supplied genesis,
requires it to be empty, replays stored non-genesis blocks on reopen, and
compares the derived state with the database. Accepted blocks are deep-copied.
Tests: `TestSecurityReopenPinsGenesis`, `TestSecurityGenesisMustBeEmpty`,
`TestSecurityStoredBlocksAreImmutable`. A hostile local database file remains
unsupported input.

**NX-009 Identity points (Critical).** The identity point as a public key or
nonce made any signature verify. Identity points, non-canonical scalars and
non-canonical encodings are now rejected. Internal arithmetic still uses a
canonical identity representation.

**NX-010 Canonical encodings (High).** Point, scalar and proof parsing is now
strict, with exact proof length, bounded challenge and response values and an
opening-consistency check before heavy work.

**NX-011 Wallet and secret files (High).** Wallet files are size-bounded and
validated before expensive derivation. Writes use an exclusive temporary file
with restrictive permissions, `fsync`, and an atomic rename. Slate decoding is
size-bounded and field-validated; signature verification rejects empty,
duplicate and malformed entries. Residual risks: the miner's reward blinding
factors are plaintext in `coinbases.json` (mode 0600 in a 0700 data directory, unencrypted); secret copies can persist in Go
strings and garbage-collected memory; memory locking is best effort and a
no-op on some platforms. The wallet key derivation is Argon2id with 3 passes,
256 MiB and 4 lanes, stored and authenticated in the file (`envelope.go`,
`TestProductionDefaultsAreStrong`); version 1 files (1 pass, 64 MiB) are read only to
be migrated, and the migration keeps the old file as `<wallet>.v1.bak` under the old
weak encryption until the user deletes it.

**NX-012 Remote boundaries (High).** Gossip, hello and sync messages use a bounded,
versioned binary format (wire protocol v6) with deadlines and queue limits, whose
size limits derive from the consensus limits. Sync ranges are at most 64
blocks. A per-peer limiter and a global byte budget throttle sync serving.
The mempool validates before admission. RPC bodies are limited to 128 KiB. The
daemon binds to loopback by default and requires a token for a non-loopback RPC
bind. HTTPS seed lists reject plain HTTP and downgrade redirects.
The client caps a peer-supplied sync error string at 1 KiB. Residual: no Sybil
or eclipse analysis and no budget for outbound dials and gossip across peers.

**NX-013 Difficulty arithmetic (High).** The weighted-window formula now uses
exact big integers with `uint64` saturation. Zero difficulty is invalid.
Missing history stops validation. Whether the formula matches any published
LWMA-3 variant is unverified.

**NX-014 Replay (High).** All output commitments and kernel IDs that ever
appeared on the active chain are tracked in both stores and rolled back on
reorg. Reuse is rejected.

**NX-015 Timestamps (High).** Timestamps must be non-negative, strictly increase,
and be at most 540 s ahead of the validator's clock (new blocks only). Comparisons
use big integers. There is no median-past-time rule by decision (simulation in
`v2/pow/timewarp_sim_test.go`) and the clock is a trust assumption.
Test: `TestSecurityFutureTimestampCannotFreezeChain`.

**NX-017 Fee output collisions (High).** The fee output used to be a dev-fund commitment `F*H + P_dev`, identical whenever two blocks had the same fee total, which collided with the uniqueness rule. The dev fund has since been removed (see IR-W-H3, IR-C-F7): fees go to the miner in the coinbase, whose blinding is the miner's own fresh random key, so equal fee totals no longer repeat a commitment. Test: `TestSP1ConsecutiveEqualFees`.

**SP-4 Stale mining work (Medium).** The miner now checks the tip on every hash
attempt and abandons a candidate whose parent is no longer the tip.

**SP-5 Storage read errors (Medium).** Store read methods return booleans, so an
I/O failure and an absent key look the same. Commit-time checks inside the
storage transaction now return errors, which reduces the effect. The interface
itself still has the limitation.

## Mitigated, with remaining limits

**NX-021 Reorg cost (High).** Reorganization used to copy the whole retained
history. Now it stages only the removed suffix over a read-through overlay and
publishes only changed keys. Routine reorg cost no longer grows with chain
length. Startup replay, in-memory snapshots and imports still read the whole
history. A maximum-size valid suffix has not been measured.

**NX-022 Storage version retention (High, operational).** The Badger discard
cutoff was zero, so obsolete versions were never reclaimed, and failed
candidates could grow dirty-key metadata. Now reader pins set a safe cutoff,
maintenance runs one bounded attempt per interval, failed stages restore the
canonical state before a different candidate is staged, and recovery visits at
most 65,536 distinct keys. Persistent startup verification streams blocks through
a disk-backed store instead of a history-sized map. Limits: startup time and
scratch disk are linear in history, long readers pin versions, and repeated
persistent write failures can grow disk until a write succeeds. There is no
disk quota.

**NX-023 Block and undo size (High, operational).** Earlier bodies could be
very large, so a legal 1024-block suffix needed gigabytes. Consensus now limits
a block to 4 inputs, 4 outputs, 4 kernels, a 64 KiB charged body and 14,529-byte
range proofs. Undo records are checked before they are decoded, and the aggregate
suffix body envelope is 64 MiB. Peak resident memory observed on the previous protocol revision, which had the
same block limits, for synthetic
1024-block replacement fixtures was about 370 MiB (memory backend) and 790 MiB
(Badger); those fixtures use invalid synthetic proofs through the raw store
interface. These numbers support a working target of at least 2 GiB of RAM for
experiments. They are not a ceiling, and not a measurement of a fully valid
maximum fork.

## Open findings

**NX-018 Custom proof construction.** The range proof is a custom
bit-decomposition scheme with 64 per-bit OR proofs, and the Schnorr signature is
custom. Verification is real, and tests cover valid, mutated and malformed
inputs, but there is no independent review of soundness, zero-knowledge,
transcript binding or composition. Review scope: [EXTERNAL_CRYPTO_REVIEW_PACKET.md](EXTERNAL_CRYPTO_REVIEW_PACKET.md).

**NX-019 Variable-time secrets.** The Decred call used for public-key derivation
in signing, `big.Int` arithmetic in commitments, and bit-dependent branches in
the prover are not constant time. Function names that include `ConstantTime`
are historical. Do not use this code where timing leakage matters.

## Closed by removal in protocol version 5

NX-003 (migration claims without an ownership check), NX-016 (order signer not
bound to the account in earlier network code) and NX-020 (unverified supply from
an imported snapshot) concerned code that carried balances from an earlier
chain. Protocol version 5 has no such code. Genesis is empty and all supply is
mined. Nothing carries over.

## Other limits recorded during review

- No median-past-time rule; difficulty formula equivalence unverified.
- Ordinary kernel signatures cover `types.KernelSigningMessage` (network magic and
  kernel ID); the coinbase signing hash binds network magic and height too.
- Compact block filters exist as a library type with high false-positive rates.
  They are not served over RPC or P2P and are not authenticated.
- Forks are found with a block locator down to the 1024-block reorg limit; a fork
  deeper than that is rejected by design and needs an operator-assisted resync.
- Mining and cryptographic routines do not take request contexts, so a timeout
  cannot interrupt a computation already running.

## Internal review round, 2026-10-31

Four AI-assisted internal reviews of the working tree on branch
`security/consensus-hardening`: consensus (`v2/types`, `v2/chain`,
`v2/genesis`, `v2/pow`), networking (`v2/p2p`, `v2/miner`, `v2/mempool`,
`cmd/nosoxd`), cryptography and wallet (`v2/crypto`, `v2/wallet`,
`cmd/nosox-cli`), and RPC with the surrounding attack surface including the
release pipeline. They are reading reviews with targeted reproduction tests in
scratch copies. They are not an independent audit, they do not cover the
soundness of the custom proofs (NX-018), and impact sizes marked "not measured"
in the reports were not measured. Several reproductions rely on timings from one
arm64 laptop.

Status rule for this table: **Open** means the report stands and a fix has not
been verified in the tree. A finding is moved only after the change is in the
tree with a regression test and the test has been run. "Changed, unproven"
means the repository change is made but has not run in the real environment
(GitHub Actions).

| ID | Severity | Area | Summary | Status |
|---|---|---|---|---|
| IR-N1 | Critical | p2p sync | First-seen fork wins; forks deeper than 4 blocks never heal, although `ReorgTo` allows 1024. Hello compares height, not work | Fixed. Tests: `TestHelloAdvertisesCumulativeWork`, `TestSyncChoosesByWorkNotHeight`, `TestConvergePartitionedPairDeepFork`, `TestConvergeForkLongerThanOneBatch` |
| IR-N2 | Critical | mempool | Blocks and reorgs never update the mempool; pool fills and stays full | Fixed. Tests: `TestAttachedPoolFollowsRealChain` (real chain and pool: confirm, reorg out, conflict), `TestApplyChangeRemovesConfirmedAndConflicting`, `TestApplyChangeReadmitsOrphanedAndRevalidates` |
| IR-N3 | High | p2p sync | One fetcher slot, no retry, 5 minute cap; a node more than ~60 blocks behind cannot recover | Fixed. Tests: `TestFarBehindNodeRecoversFromGossip`, `TestFetcherCannotBePinned` |
| IR-N4 | High | chain, p2p | Bad-PoW blocks hold the global chain lock during Argon2; shared validation queue | Fixed. Tests: `TestBlockPoWRunsOutsideChainLock`, `TestAcceptedBlockHashedOnceAndCheapChecksFirst` |
| IR-N5 | High | p2p | No peer scoring; gossipsub peer exchange lets any peer steer dials | Fixed. Tests: `TestLyingPeerIsScoredAndDropped`, `TestGarbagePeerIsDroppedAndBanned`, `TestPeerExchangeCannotSteerDials` |
| IR-N6 | High | p2p | Subscription flood retains memory per peer | Fixed. Test: `TestSubscriptionFloodIsBounded` |
| IR-N7 | High | p2p | 16 MiB wire limit against 64 KiB blocks; JSON decode amplification | Fixed (binary wire format, protocol v6). Tests: `TestDecodeAmplificationIsBounded`, `TestWireLimitsDerivedFromProtocol` |
| IR-N8 | High | p2p | Old blocks and pooled transactions are re-forwarded without limit; message ID is peer plus seqno | Fixed. Tests: `TestReplayedBlockIsNotForwarded`, `TestGossipMessageIDIsContentHash`, `TestTxFloodDoesNotStarveBlocks` |
| IR-N9 | High | p2p sync | Idle streams exhaust the global sync slots | Fixed. Tests: `TestIdleStreamsDoNotExhaustSyncSlots`, `TestOneSyncStreamPerPeer` |
| IR-N10 / IR-W-H2 | High | miner, wallet | Miner stops silently after 10,000 coinbase candidates | Fixed. Tests: `TestCandidatesDoNotConsumeKeyRecords`, `TestFullKeyFileRecoversOnRestart`, `TestKeyPersistFailureIsSurfacedAndBlockWithheld`, `TestMinerStatsReportsFailures`, `TestImportCoinbaseReadsArchivedRotations` |
| IR-N11 | High | p2p | Ephemeral peer identity, no reconnect, no discovery | Fixed for covered cases (stable identity, reconnect); no public seed nodes exist. Tests: `TestIdentityPersistsWith0600`, `TestSeedAddressSurvivesRestartAndNodeReconnects`, `TestKnownPeersPersistAndAreRedialed` |
| IR-N12 to N15 | Medium | chain, mempool, p2p | Unfunded transaction verified before balance check; no mempool eviction or minimum fee; low-work forks validated before the work check; no global sync budget | Fixed for covered cases. Tests: `TestAcceptedBlockHashedOnceAndCheapChecksFirst`, `TestMinimumRelayFee`, `TestFullPoolEvictsLowestFeeRate`, `TestReorgChecksWorkBeforeValidationAndRemembersFailures`, `TestByteBudgetBoundsGlobalServing`, `TestOneSyncStreamPerPeer` |
| IR-C-F1 | High | consensus | 2 hour future limit lets a small miner slow the chain (simulation: up to 3.6x); a 540 s limit neutralised it in the model | Fixed: future limit is 540 s (decision taken; median-time-past rejected after simulation). Tests: `TestSecurityFutureTimestampCannotFreezeChain`, `TestTimeWarpFutureLimit`, `TestFutureLimitSweep` |
| IR-C-F2 | High | p2p, chain | Same root cause as IR-N1 | Fixed (same root cause as IR-N1) |
| IR-C-F3 | Medium | chain | A checkpoint above the tip blocks all reorgs (dormant: no checkpoints) | Fixed. Test: `TestCheckpointAboveTipDoesNotFreezeReorg` |
| IR-C-F4 | Medium | chain | Same root cause as IR-N4 | Fixed (same root cause as IR-N4) |
| IR-C-F5 | Medium | chain | Startup replay applies the wall-clock rule; a clock step stops a valid node | Fixed. Test: `TestReplayDoesNotApplyWallClockRule` |
| IR-C-F6 | Medium | chain | Full Argon2 replay on every start; orphaned scratch directories | Fixed (verified-history marker). Tests: `TestVerifiedMarkerSkipsReplay`, `TestVerifiedMarkerReplaysTail`, `TestFailedLoadNeverWritesMarker` |
| IR-C-F7 | Medium | design | Miners earn no fees and nothing after height 2,310,000 | **Resolved by decision**: all fees go to the miner (coinbase = subsidy + fees, also after emission ends, where fees are the only payment). Tests: `TestCoinbaseMustClaimExactlyRewardPlusFees`, `TestPostEmissionCoinbaseIsFeesOnly`, `TestSupplyEqualsRewardsWithFeesAndReorg`, `TestOutputFeatureTwoIsRejected`, `TestCandidateCoinbasePaysRewardPlusFees` |
| IR-C-F8 | Low | consensus | Plain kernel signatures carry no network domain | Fixed. Tests: `TestKernelSignatureIsBoundToNetwork`, `TestKernelSignatureIsBoundToTheNetwork` |
| IR-C-F9, F10 | Low | chain | Work compared last in `ReorgTo`; coinbase maturity scans block bodies | Fixed. Tests: `TestReorgChecksWorkBeforeValidationAndRemembersFailures`, `TestCoinbaseMaturityDoesNotDecodeBlocks` |
| IR-W-H1 | High | wallet | `pay` past the 10,000 record cap makes the wallet unreadable | Fixed: the file cannot be bricked (`TestPayAtHardBoundFailsCleanlyAndNeverBricks`, `TestOversizedStateFromOlderBuildOpensAndIsPruned`). The lock-up this fix introduced (a full wallet could never pay) is PR4-W1 below; the byte bound that the counts did not respect is PR4-W6 |
| IR-W-H3 | High (trust) | dev fund | No proof of knowledge for `P_dev`; hidden inflation possible through the dev-fund point | **Resolved by removal**: the dev fund, `DevFundPoint`, the fee output and output feature 2 are gone; there is no recipient point left to hide a component in. The invariant is now checkable by anyone: the unspent set sums to the cumulative subsidy. Tests: `TestCoinbaseMustClaimExactlyRewardPlusFees`, `TestPostEmissionCoinbaseIsFeesOnly`, `TestSupplyEqualsRewardsWithFeesAndReorg`, `TestOutputFeatureTwoIsRejected`, `TestCandidateCoinbasePaysRewardPlusFees` |
| IR-W-H4 | High | wallet | Slates are unauthenticated and unencrypted: whoever answers an offer receives the payment | Open; documented as a limit |
| IR-W-H5 | High | wallet (Windows) | Directory fsync fails and there is no file lock on Windows (read of Go source, not run on Windows) | Changed, unproven: `fsync_windows.go` (write-through rename, `syncDir` a no-op) and `flock_windows.go` (`LockFileEx`) exist and `GOOS=windows go vet` passes; nothing has run on Windows. The coinbase file rotation used a raw directory sync and is fixed (PR4-W5) |
| IR-W-M1 | Medium | wallet | Reorg releases an input held by a live payment | Fixed. Test: `TestReorgKeepsAnInputReservedByALivePayment` |
| IR-W-M2 | Medium | cli | `wallet new` overwrites an existing keystore | Fixed. Tests: `TestWalletCreateNeverOverwrites`, `TestWalletNewRefusesOverwriteAndWeakPassphrase` |
| IR-W-M3 | Medium | wallet | State rollback reuses the nonce and can leak `x_s` | Mitigated: a generation sidecar marks live nonces suspect after a restored backup; an attacker who restores the sidecar as well defeats it. Tests: `TestRestoredBackupCannotSignASecondTransactionWithTheSameNonce` (also asserts the change key survives `cancel`), `TestMissingOrForgedMarkerMakesLiveContextsSuspect` |
| IR-W-M5 to M8 | Medium | wallet | Weak KDF parameters not stored in the file; plaintext `coinbases.json`; depth 1 treated as confirmed; no kernel offsets | Partly fixed: KDF parameters are stored and authenticated (`TestEnvelopeStoresAndAuthenticatesKDFParameters`, `TestProductionKDFIsStrong`) and depth is required (`TestConfirmationDepthIsRequired`, `TestShallowOutputsAreNotSpent`). **Open**: plaintext `coinbases.json`, no kernel offsets |
| IR-A-H2 | High | p2p, rpc | One valid transaction can force repeated network-wide proof verification | Open |
| IR-A-M1 | Medium | rpc, wallet | Same root cause as IR-N10 | Fixed (same root cause as IR-N10) |
| IR-A-M2 to M8 | Medium | rpc, cli | No-token mode gives every local process full control; token on argv; token over plain HTTP on a public bind; no RPC resource budget; `hasutxo` rebuild without cancellation; `wallet sync` reveals the output set to the node; `wallet new` overwrite | Split. Fixed in code: token on argv (`cmd/nosoxd/main.go` refuses `-rpc-token`; the CLI reads the environment only), token over plain HTTP (`cmd/nosoxd/rpcconfig.go` requires TLS on a non-loopback bind; the client refuses cleartext to a remote host, `TestRPCNodeRefusesTokenOverCleartextToRemoteHosts`), `wallet new` overwrite (IR-W-M2), `hasutxo` (one indexed lookup, `v2/rpc/wallet_methods.go`). **Open**: no-token mode on loopback, the RPC resource budget (concurrency cap only), and `wallet sync` revealing the output set (inherent, documented in `docs/wallet.md`) |
| IR-A-M9 | Medium | p2p | Seed list is an unsigned file from a mutable branch | Mitigated: the list is fetched over HTTPS from a pinned tag, not a branch (`TestSeedFetchIsPinnedAndRedirectsAreRestricted`). It is still unsigned, and the tag `seeds-v1` does not exist yet, so `-http-seeds` finds nothing until it is created |
| IR-A-M11 | Medium | wallet (Windows) | Same root cause as IR-W-H5 | Changed, unproven (same as IR-W-H5) |
| IR-A-L1 to L9, L11 | Low | rpc, cli, wallet | See the reports: CORS wildcard, token compare, error strings, bind failure only logged, terminal escapes, client trust gaps, `startmining` input handling, KDF format, `coinbases.json` rewrite, secret file permissions | Open |
| IR-A-H1 | High | release pipeline | Release workflow could ship tampered binaries and users could not detect it | Changed, unproven: least-privilege jobs, SHA-pinned actions, no cache, combined `SHA256SUMS`, provenance attestation. Not yet run on GitHub. See `docs/reproducible-builds.md` |
| IR-A-M10 | Medium | docs build | Docs build ran unhashed installs with deploy rights | Changed, unproven: hash-locked requirements, build job without Pages or OIDC permissions. `mkdocs build --strict` passes locally |
| IR-A-L10 | Low | repo | `.gitignore` missed `coinbases.json`, `*.outputs`, wallet files, binaries | Fixed in the tree |
| IR-A-L12 | Low | dependencies | Dependencies behind current; five advisories in imported packages with no reachable symbol | Mitigated: the upgrade is applied (x/crypto 0.58, x/net 0.62; libp2p and quic-go not moved, see `RELEASE_READINESS.md`); `govulncheck` reports no reachable vulnerability. One advisory remains in a required module (GO-2026-5932, x/crypto `openpgp`, not imported, no fix upstream) |
| IR-A-L13 | Low | publication | Personal email in 15 commits; history will publish deleted audit documents | Open (decision before making the repository public) |
| IR-X-W1 | High | wallet | Fund loss: `sync` deleted the blinding factor of an unconfirmed receive after 30 days, so a genuine payment finalized and mined later was unspendable | Fixed: expired receives move to an encrypted archive (2048 entries) that `sync` keeps matching and `receive` still counts as a used session. Tests: `TestExpiredPendingReceivesAreArchivedNotDeleted` (including replay of an archived session), `TestReceiveMinedAfterExpiryStaysSpendable`, `TestArchiveFullRefusesReceiveButNeverEvicts`, `TestPruneDepthCoversMaxReorg` |
| PR4-W1 | High | wallet | A lying node destroyed keys: `sync` trusted the reported tip without bound, two comparisons overflowed, and a node answering "absent" with tip 2^64-1 made one sync delete every unspent blinding factor and imported coinbase key | Fixed. No key is deleted on a node's word: finished records move to the encrypted archive and a correct node restores them; the tip is also bounded (plausible, consistent, no unconfirmed rise, lowest answer used); a poisoned tip from an older build is cleared on open. Tests: `TestLyingNodeHugeTipDestroysNoKeys`, `TestSlowLiarWithinBoundsDestroysNoKeys`, `TestArchivedSpentKeyComesBackWhenACorrectNodeReturns`, `TestImplausibleTipIsRefusedEvenOnTheFirstSync`, `TestTipJumpNeedsExplicitConfirmationAndFallingIsAccepted`, `TestInconsistentTipsInOneSyncAreRefused`, `TestStateWithAnAbsurdTipFromAnOlderBuildRecovers`, `TestRetiredArchiveEvictsOnlyByLocalAgeAndNeverRefusesPay`. Residual: a node can still lie about status and confirmations (documented) |
| PR4-W2 | High | wallet | A wallet at 10,000 records could never pay (`roomFor(1)` before selection), import-coinbase filled to exactly that | Fixed: payments are not subject to the soft limit, spends are archived under pressure, `wallet consolidate` merges small outputs. Tests: `TestPayWorksAtTheRecordCap`, `TestConsolidateMergesSmallOutputsEvenWhenTheWalletIsFull`, `TestImportCoinbaseFillsToTheCapAndPaymentsStillWork`. Residual: payments fail cleanly if 16,384 live records are all still in flight |
| PR4-W3 | High | wallet | `cancel` after a restored backup zeroized the change of a transaction that may have been signed and mined | Fixed: the change key is archived and revives when the transaction is on chain; `ErrRolledBack` and the docs say to sync first. Tests: `TestCancelAfterRestoreKeepsChangeForAMinedTx`, `TestCancelAfterRestoreChangeIsArchivedAndRevivesOnChain` |
| PR4-W4 | Medium | wallet, cli | Automatic keystore upgrade silently dropped `legacy` keys | Fixed: the old file is kept as `<wallet>.v1.bak` (0600, fsynced, never overwritten) and the CLI says so. Tests: `TestUpgradeKeepsABackupOfTheOldKeystore`, `TestUpgradeBackupIsNeverOverwritten`. Residual: the backup keeps the weak v1 encryption |
| PR4-W5 | Medium | wallet, miner | Coinbase rotation synced the directory directly (fails on Windows) and left the in-memory set full after a transient error, so the miner withheld blocks until restart | Fixed: durable rename helper, set emptied once the rename succeeded, directory sync retried by the next `Persist`. Test: `TestCoinbaseRotateRecoversAfterATransientDirectoryFailure` (POSIX only; nothing ran on Windows) |
| PR4-W6 | Low-Medium | wallet | The 4 MiB plaintext bound was reached long before the record limits | Fixed: bound derived from the worst case at every limit (20 MiB plaintext, 32 MiB file). Test: `TestWorstCaseStateFitsTheByteBound` |
| PR4-W7 | Low-Medium | wallet, cli | The pending-quota error advised a cancel that did not exist for receives | Fixed: `wallet cancel-receive` (archives, key kept). Test: `TestCancelReceiveArchivesFreesTheQuotaAndTheKeyRevives`. Residual: a full receive archive (2048) still refuses `receive` and nothing evicts it |
| PR4-W8 | Low | wallet | The resubmit path skipped the durability gate | Fixed: state is re-committed before a stored transaction is resubmitted. Test: `TestResubmitWaitsForADurableState` |
| PR4-W9 | Low | wallet | Permanently pending change and reorged-out coinbases; a failed reload was silent; a vanished `.outputs` opened as an empty wallet | Fixed: change is archived after 30 days, a coinbase keeps its claimed height, a store that cannot reload refuses to write, a missing state with its marker present refuses to open. Tests: `TestStuckChangeAndReorgedCandidatesAreArchivedNotKeptForever`, `TestAStoreThatCannotReloadRefusesToWriteOnStaleMemory`, `TestStateMissingWithMarkerPresentIsNotAnEmptyWallet` |
| PR4-W10 | Low | cli | Misleading messages (a new passphrase "can be chosen", lock height, fee warning only for one input), unbounded slate file | Fixed in messages; slate files are bounded (`TestSlateFileIsBounded`). Not changed: `-y` is still stripped from anywhere in the arguments |
| PR4-L10 | Low | rpc, wallet | Policy refusals (conflict, replacement fee) reached the wallet as final rejections and the wallet advised `cancel --force` | Fixed: separate code `-32013`; the wallet reports it as retryable and advises against cancelling. Tests: `TestPolicyConflictsAreNotFinalRejections`, `TestRPCNodeSeparatesPolicyRefusalFromRejection`, `TestPolicyRefusalMessageDoesNotAdviseForceCancel` |
| PR4-W-doc | Low | wallet | Fake confirmations from a node not under the user's control | Documented limit kept; every sync now prints the trust notice and warns for non-loopback nodes (`TestSyncReportCarriesTheTrustNotice`) |
| PR4-V1 | High | p2p, chain | Honest peers were banned for the local node's state: any `AddBlock`/`ReorgTo` error except a few was -100 plus a bad-tip mark (stale after a race, low work, future timestamp, resource and disk errors), a busy server's rate limit scored as non-delivery, a sibling stream was reset, and a node behind the tip rejected relayed transactions as invalid | Fixed: `chain.IsPeerFault` is an allowlist (`ErrInvalidBlock`, wrapped around rejections provable from the block and its named parent); ErrStale, ErrLowWork, ErrFutureTimestamp, ErrResourceBudget, ErrTooDeep, ErrCheckpoint, store errors (detected by comparing the store's read-fault counter around a validation) never penalize. State-dependent transaction rejects (`ErrTxState`, `ErrDoubleSpend`) are Ignore. Rate-limited answers only set a retry time; a second stream gets "busy". Tests: `TestIsPeerFaultIsAnAllowlist`, `TestStoreFaultIsNeverAPeerFault`, `TestBlameOnlyProvableInvalidity`, `TestBusyServerIsNotPenalized`, `TestSecondStreamGetsBusyNotReset`, `TestBehindNodeDoesNotPenalizeStateDependentTx`. Residual: peer reorg between batches costs -10 (`penaltyMoved`), not zero |
| PR4-S1/S2 | High | p2p | Claimed tip hashes were remembered globally, so one free identity made every honest peer advertising the same tip unusable for 10 minutes; `Synced` ignored them, was satisfied by any low-work peer and was a one-shot wait; stalling high-claim IDs starved the single sync loop | Fixed: marks are keyed per (peer, hash) and only set for the peer's own failure; peers that delivered blocks outrank unproven claims; `Synced` needs every connected peer past its handshake, none heavier, and a recent tip or a peer at our work; the miner re-checks a gate before every block (`Miner.SetSyncGate`, which also covers RPC `startmining` with no change to `v2/rpc`); locator deadline 5 s. Tests: `TestPoisonedClaimDoesNotBlockHonestPeers`, `TestProvenPeerOutranksStallingClaims`, `TestSyncedNeedsConfirmationNotJustAnyPeer`, `TestSyncGateIsRecheckedBeforeEveryBlock`, `TestMinerGateFollowsPeersAndSync` |
| PR4-H1 | High | p2p, chain | Forks 520-1024 blocks deep were refused (the sparse locator's ancestor was up to 512 blocks too old) | Fixed: the ancestor is refined with follow-up locators of up to 64 evenly spread heights; the answer is validated against the heights of that request. Tests: `TestAncestorSearchIsExact`, `TestSpreadHeights`, `TestDeepForkBeyondTheSparseLocatorConverges` (520 blocks above the fork, tip 1032) |
| PR4-H2 | Medium | chain | Every reorg made the next `TotalWork` walk the whole chain under the state lock | Fixed: `ReorgTo` updates the cache from the work `stageFork` computed. Test: `TestReorgUpdatesWorkCacheWithoutWalkingTheChain` |
| PR4-C1/M3 | Medium | chain | The verified marker skipped checkpoints, was not bound to the rules, and skipped the derived-state comparison; the checkpoint guard pinned a non-matching block | Fixed: the marker carries the consensus-rules version and a hash of the checkpoint set (a change forces a full replay), the marker pass checks checkpoints and compares the unspent/output/kernel key sets (count and additive digest) with what the stored blocks imply; the guard compares hashes; a failed marker write no longer discards a verified replay. Tests: `TestMarkerPathEnforcesCheckpoints`, `TestMarkerBoundToCheckpointSetAndRules`, `TestMarkerPathDetectsDamagedDerivedState`, `TestCheckpointGuardComparesHashes`, `TestMarkerWriteFailureDoesNotFailLoad` |
| PR4-G1 | High | p2p | A throttled or ignored copy burned the gossip content ID (pubsub marks messages seen before validators run), so honest copies were dropped | Fixed: budgets are enforced in an RPC inspector before pubsub sees the message and the sender is queried for its status. Verified by reading go-libp2p-pubsub v0.16.0 `validation.go` (`markSeen` precedes the validators) and tested at the inspector: `TestInspectorTrimsOverBudgetBeforePubsubSeesIt`. Not run: a multi-hop race |
| PR4-E1 | High | p2p | Eight idle inbound connections stopped all redialing; the address book was first come first served and unfiltered; dead seeds consumed every dial | Fixed: only outbound peers count toward the target, inbound limited per /24 (/48) and in total (loopback and private exempt), the book admits dialed or block-delivering peers, filters advertised addresses of public peers and holds two entries per network, seeds back off and the tick budget is shared between seeds and known peers. Tests: `TestInboundSybilsDoNotStopRedialingHonestPeers`, `TestDeadSeedsCannotExhaustDials`, `TestInboundLimitPerNetworkAndLoopbackExempt`, `TestAddressBookAdmission` |
| PR4-Win | High | p2p | The Windows build refused its own identity key on the second start (Go reports 0666) | Fixed: the mode check is skipped on Windows (access is the inherited ACL); `cmd/nosoxd` data-dir chmods skipped too. Test: `TestLooseModeIgnoresWindowsPseudoPermissions` (the decision is parameterised by GOOS; nothing ran on Windows; `GOOS=windows go vet` passes) |
| PR4-R1 | Medium | mempool | Reorg re-admission was one aggregate per block, so a partial inclusion lost the rest | Fixed: originals are kept by kernel and restored one by one; unseen leftovers are tried as an aggregate and as balancing subsets. Test: `TestReorgPartialInclusionRestoresTheRest` (both cases) |
| PR4-M | Medium/Low | chain, mempool, nosoxd | Fake fork validated before PoW under the state lock; a refused admission still evicted; validate-to-insert window; rejected cache held `ErrLowWork`; `AddBlock(nil)` panicked with the lock held; RPC failure exited 0; no `AllowedHosts` flag | Fixed: PoW for every fork block, head first, before staging, and staging no longer holds `mu`; evictions are planned first; the pool revalidates when a chain change ran meanwhile; `ErrLowWork` and storage faults are not remembered; nil is an error; RPC failure exits 1 after the clean shutdown; `-rpc-allowed-hosts`. Tests: `TestForkPoWIsCheckedBeforeStaging`, `TestRefusedAdmissionEvictsNothing`, `TestAdmissionRevalidatesWhenTheChainMoved`, `TestRPCAllowedHostsFlag`. Not tested: the exit status (needs a failing listener) and N1 (needs responses above the 256 KiB yamux window; the slot is now released before the write) |
| PR4-clock | Low | p2p | Future-stamped honest blocks banned relays; no hint that the local clock was off | Fixed: no penalty; a warning when two peers serve blocks beyond the drift. Test: `TestClockSkewWarnsOnlyWhenPeersAgree` |
| IR-X-W2 | High | wallet, cli | `import-coinbase` read only the live key file; keys in archived `coinbases.json.<ts>.<n>` files were never imported | Fixed. Test: `TestImportCoinbaseReadsArchivedRotations` |
| IR-X-N1 | Medium | mempool, rpc, p2p | A fee below the relay minimum was reported without the minimum, the wallet had no fee that cleared it, and gossip matched errors by string prefix | Fixed. Tests: `TestTransactionFeeTooLowIsAPolicyRejection`, `TestGossipTxAdmissionClassification`, `TestEstimatedSizeMatchesPoolAccounting`, `TestMinimumRelayFee` |

Source reports (kept outside the repository by the reviewers):
`review-consensus.md`, `review-network.md`, `review-crypto-wallet.md`,
`security-audit.md`. Severities are the reviewers' own and were not
cross-checked by a second reviewer. Findings that appear in two reports are
listed once per reporter and share a root cause. Not in scope of this round:
remote repository settings (branch protection, tag rules, Actions policy).

Documentation that contradicted the code was corrected in this round: the
claims that mined coins cannot be spent, that the CLI cannot send an RPC token,
and the RPC body limit (128 KiB).

## Test evidence

Run the full suite with `go test ./...` and the race detector with
`go test -race ./...`. Fuzz targets (`go test ./v2/crypto -run '^$' -fuzz
FuzzVerifyRangeBorromean`, and the others listed in the review packet) provide
finite robustness evidence only.
