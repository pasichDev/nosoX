# Release readiness

**Decision: not ready for mainnet. Do not hold value.**

No independent audit has taken place. The review round of 2026-10-31 was done
by internal reviews, not by an outside party; its findings are in
[SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) and most are still open. `nosoxd` refuses to start with
`-network mainnet`. The table below is the current gate list. A gate is only
"met" where it can be checked in the repository. "Covered locally" means
tests exist; it does not mean the property is proven.

| Gate | Status | Detail |
|---|---|---|
| NX-018: independent review of the custom Schnorr signature and range proof | **Open** | No reviewer engaged. See [EXTERNAL_CRYPTO_REVIEW_PACKET.md](EXTERNAL_CRYPTO_REVIEW_PACKET.md). |
| NX-019: constant-time secret arithmetic | **Open** | Signing, commitment and proving use variable-time code on secrets. Names containing `ConstantTime` are historical and do not describe behavior. |
| NX-020: provenance of initial supply | **Closed by removal** | Protocol version 5 has no migration of any earlier chain. Genesis is empty and every coin is mined. |
| Wallet spending | Covered locally; open findings | Two-party payments (`pay`, `receive`, `finalize`) with encrypted output tracking. Tests: a real miner on the memory and Badger stores, payment through the mempool into a block accepted by `AddBlock`, onward spend, node restart and reorg with resubmission; adversarial slate and nonce tests; a test driving the real `nosoxd` and `nosox-cli` binaries. Secret arithmetic is still variable-time (NX-019), and reward keys stay plaintext on the node. Limits: at most 4 inputs per payment, no seed-based recovery, unauthenticated slates (IR-W-H4), no payment proofs. The file can no longer be bricked at the record cap (IR-W-H1) and a full wallet can pay and consolidate (PR4-W2); a lying node can no longer make the wallet delete a key (PR4-W1: finished records move to the encrypted archive); the 30-day loss of late receives (IR-X-W1) is fixed with tests; nonce reuse on state rollback (IR-W-M3) is mitigated, not closed, and `cancel` after a restore keeps the change key (PR4-W3); Windows durability (IR-W-H5) is changed in code and unproven on Windows. See [wallet](../docs/wallet.md). |
| Dev-fund point provenance | **Closed by removal** | The dev fund no longer exists (IR-W-H3). Fees go to the miner; there is no founder allocation or protocol fee, and the unspent set sums to the cumulative subsidy. Tests: `TestCoinbaseMustClaimExactlyRewardPlusFees`, `TestPostEmissionCoinbaseIsFeesOnly`, `TestSupplyEqualsRewardsWithFeesAndReorg`, `TestOutputFeatureTwoIsRejected`, `TestCandidateCoinbasePaysRewardPlusFees`. |
| Internal review round 2026-10-31 | Partly closed | Most findings now have a fix in the tree with a named regression test (fork convergence IR-N1, mempool following blocks IR-N2, 540 s future limit IR-C-F1, miner failures IR-N10, wallet fund loss IR-X-W1); see [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md). Still open: unauthenticated slates (IR-W-H4), the rows marked Open there. Windows durability (IR-W-H5) is changed in code but has not run on Windows. |
| Subsidy and kernel authorization | Covered locally | Missing or forged signatures and subsidy rejected through `AddBlock` on both stores. |
| Complete body binding and history uniqueness | Covered locally | Roots over all body fields; replay of spent commitments and kernels rejected. |
| Atomic reorganization and fork choice | Covered locally | Strictly greater accumulated work required; injected commit failure leaves state unchanged. |
| Fee routing and repeated equal fees | Covered locally | Coinbase = subsidy + fees, exactly, on both stores and after emission ends; repeated equal fees give distinct commitments. Tests: `TestSP1ConsecutiveEqualFees`, `TestCoinbaseMustClaimExactlyRewardPlusFees`, `TestPostEmissionCoinbaseIsFeesOnly`, `TestSupplyEqualsRewardsWithFeesAndReorg`, `TestOutputFeatureTwoIsRejected`, `TestCandidateCoinbasePaysRewardPlusFees`. |
| Capacity and durability | **Open** | Consensus bounds are in place (4 inputs, 4 outputs, 4 kernels, 64 KiB body, 1024-block reorg depth). A maximum-size, cryptographically valid fork has not been measured. There is no power-loss test matrix. Startup replay is linear in history. |
| Safe public P2P and RPC operation | **Open** | Message and range bounds exist. There is no global resource budget and no eclipse or Sybil analysis. The CLI sends an RPC bearer token from `NOSOX_RPC_TOKEN`; the RPC rate-limits per client address. The HTTP seed list needs the `seeds-v1` tag, which does not exist yet; until it is created `-http-seeds` finds no peers. |
| Difficulty and timestamps | Partial | Arithmetic is overflow-safe. Equivalence to a published LWMA-3 is not established. Timestamps strictly increase and may be at most 540 s ahead of the validator clock (new blocks only). No median-past-time rule, by decision: a simulation (`v2/pow/timewarp_sim_test.go`) showed it is worse than strict increase plus a short future limit. |
| Checkpoints | **Open** | The daemon verifies the baked set and launcher signature at startup and pins the list. The set is empty and no launcher key exists, so nothing is pinned yet. |
| Miner key storage | **Open** | Reward blinding factors are kept in plaintext in `coinbases.json` and its archives `coinbases.json.<ts>.<n>` (files `0600`, data directory `0700`, not encrypted). Keys are written only for solved blocks, before the block is added. `wallet import-coinbase` reads the archives too. |
| Genesis and launch parameters | **Open** | Mainnet genesis parameters (timestamp, initial difficulty) are defaults in code. No launch procedure has been exercised and no seed nodes exist. |
| Reproducible builds | Not verified | The build script and flags are designed for reproducibility. Independent rebuilds have not been compared. |
| Release integrity | Changed, not exercised | The release workflow now uses per-job least privilege, SHA-pinned actions, no cache, a combined `SHA256SUMS` that `scripts/verify-release.sh` consumes and a build-provenance attestation. It has not run on GitHub. Attestations need a public repository (or a plan that supports them). No offline signature is produced; `--sign` in `scripts/build-release.sh` is manual. Repository settings (branch and tag protection, reviewers on the `release` environment) are not checked here. |
| Continuous integration | Not demonstrated | The workflows in `.github/workflows` have not yet run on the public repository. |
| Dependencies | Mitigated | The upgrade is applied (x/crypto 0.58, x/net 0.62, x/text, x/sys, x/term, klauspost/compress, pion/stun, OpenTelemetry). `govulncheck ./...` reports no reachable vulnerability; one advisory remains in a required module (GO-2026-5932, x/crypto `openpgp`, not imported, no fix upstream). libp2p stays at 0.48 and quic-go at 0.60: libp2p 0.51 and quic-go 0.64 build and pass the p2p tests, but they pull `decred/secp256k1` 4.4.1, which deprecates the `elliptic.Curve` calls in `v2/crypto` (9 staticcheck SA1019 findings), and libp2p-pubsub 0.19 changes the protobuf API a test uses. Moving them needs the crypto code ported to the new curve API first. Re-run `govulncheck` on every release candidate. |
| History secret scan | Run once | `scripts/check-publication.sh` with gitleaks 8.30.1 scanned 32 commits and the working tree. One false positive (prose in a deleted document) is recorded in `.gitleaksignore`; no other findings. Re-run on every release candidate. |

## Publication checklist for maintainers

Before changing repository visibility:

1. Fetch all refs and tags. Confirm the clone is not shallow.
2. Run `scripts/check-publication.sh` with `gitleaks` installed. It scans
   reachable history and the working tree and exits non-zero on any finding or
   on a scan that cannot finish.
3. Review flagged content by hand, including deleted files. A file deleted
   from the tree is still in history. Rotate any real credential regardless of
   history rewriting.
4. Check documentation, author metadata and logs for personal information that
   scanners cannot find.
5. Enable GitHub private vulnerability reporting (see `SECURITY.md`).
6. Keep the status notice in `README.md` and `docs/index.md` until the open
   gates above are closed.

The script cannot prove that GitHub holds no unreachable objects, other refs
or forks. A zero-finding run still needs a human review.
