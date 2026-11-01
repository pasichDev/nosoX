# Changelog

All notable changes are listed here, newest first. There are no tagged releases
yet.

## Unreleased: protocol version 5

### Changed (consensus): the dev fund is removed

- The coinbase is worth `BlockReward(height) + F`, where `F` is the block's
  total kernel fee, with overflow-checked 64-bit arithmetic. A miner can claim
  neither more nor less (the coinbase signature is verified against exactly
  that amount). A coinbase is required whenever `reward + F > 0`, including
  after emission ends at height 2,310,000, and forbidden when it is 0. The
  invariant "sum of unspent values = sum of rewards" now holds on the chain.
- Removed: `OutputFeaturesDevFund` (value 2 stays unassigned and is rejected),
  `types.DevFundPoint`, `chain.DevFundBlindingTweak`,
  `chain.ExpectedDevFundCommit`, `validateDevFund`, `docs/devfund.md`, the
  `NosoX/devfund-blind/v5` domain, the miner's fee output and the mempool's
  reserve for it. The miner builds the coinbase after selecting transactions;
  its key record stores the full amount.
- After emission ends, miners are paid by fees alone. There is no founder
  allocation and no protocol fee. Block version stays 5: the protocol has not
  launched. Markers written by earlier builds force one full replay.
- Findings IR-W-H3 and IR-C-F7 are resolved by this change.

### Changed (convergence hardening)

- A peer is penalized only for provably invalid data; ErrStale, low work, clock,
  resource and disk conditions never cost a peer anything. Claimed tips are
  remembered per peer, never globally. Fork ancestors are found exactly (forks up
  to 1024 deep sync). `Synced` is re-checked before every block by the miner.
  Rate limits run before gossip deduplication. Address-book and inbound
  admission, reconnection, reorg work cache, verified-history marker coverage
  (checkpoints, rules version, derived state), mempool reorg re-admission and
  several smaller items: see `audit/SECURITY_FINDINGS.md`.

Breaking. Databases and peers from earlier protocol versions are rejected.

### Changed

- Block version is 5. Every hash domain and the proof-of-work salt use one
  `NosoX/<name>/v5` family. The libp2p wire protocol is version 6 (compact binary
  format instead of JSON): stream IDs `/NosoX/hello/v6`, `/NosoX/sync/v6` and
  gossip topics `NosoX/<magic>/blocks/v6`, `.../txs/v6`.
  This renames the Schnorr, Borromean, Pedersen `H`, and
  checkpoint domains, so the generator `H`, signatures and test vectors changed.
  `v2/crypto/testdata` and `audit/reference_vectors.py` were regenerated.
- The coinbase kernel signature digest is domain tagged and binds the network
  magic and height. `wallet.SignCoinbase`, `wallet.VerifyCoinbase` and
  `wallet.CoinbaseKernelSignHash` take the magic as their first argument.
- `nosoxd` verifies the baked checkpoint set and its launcher signature before
  opening any state and refuses to start on a bad or unsigned set. An empty set
  starts. A non-empty set without a launcher key is refused.
- `nosoxd` creates the data directory `0700` (and tightens an existing one) and
  keeps `coinbases.json` at `0600`. The file still holds blinding factors in
  plaintext; see `docs/mining.md`.
- `ReplaceChain` propagates staging errors, and Badger open paths report a
  failed close instead of dropping it.
- Genesis is empty: no outputs, no kernels. Every coin is issued through mined
  coinbase outputs. Genesis can no longer carry allocations, and an incoming
  non-empty genesis is rejected.
- The module is `github.com/pasichDev/nosoX`.

### Consensus and node hardening (review round 2026-10-31)

Consensus rules (still protocol version 5, as the network is not launched):

- Block timestamps may be at most 540 s ahead of the validator's clock (was
  7200 s). A simulation with the real difficulty algorithm (`v2/pow`,
  `TestTimeWarpFutureLimit`) shows the 2 h limit lets a 5-20% miner slow the
  chain to 2.8-3.6x the target; at 540 s the mean interval stays within 3%.
  Timestamps must still strictly exceed the parent's. A median-time-past rule
  *instead of* that was simulated and is worse (it lets an attacker speed the
  chain up), so it was not adopted.
- The wall-clock rule applies to new blocks only. Startup replay of stored
  blocks no longer fails after the clock steps back.
- Plain kernel signatures cover
  `SHA256("NosoX/kernel-sig/v5\0" || BE32(magic) || KernelID)`
  (`types.KernelSigningMessage`) instead of the bare kernel ID, so a signature
  is valid on one network only. Wallet signers must use it.
- The output-seen marker in the Badger store now records the creation height
  (8 bytes). Coinbase maturity reads it instead of decoding up to 59 blocks.
  Existing development databases must be recreated.

Node behaviour:

- Proof-of-work, signatures and range proofs run without the chain lock; only
  short bounded sections hold it, so `Tip`, `Height` and RPC no longer wait on
  Argon2. Cheap header checks run first, concurrent Argon2 evaluations are
  limited to two, and an accepted block is hashed once.
- Transactions are checked cheapest first: state and balance before range
  proofs.
- A reorg is rejected on declared work before any validation, the head's
  proof-of-work is checked first, blocks identical to the canonical chain are
  trimmed, and failed forks are remembered by head hash. A checkpoint constrains
  reorgs only once the node holds it.
- A verified-history marker (`chain/verified.json`) replaces the full replay at
  every start: stored blocks are checked structurally, only blocks after the
  marker are fully re-validated. `-verify-full` forces the complete replay.
  Abandoned `.nosox-replay-*` directories are removed at start.
- `Chain` gains `Subscribe`, `UTXOByCommit` (with creation height),
  `TotalWork`, `BlockLocator`, `CommonAncestor`, `BlockHash`, `BlocksFrom`.
- The mempool drops confirmed and conflicting transactions on every block,
  re-admits valid transactions of disconnected blocks, enforces a minimum fee
  rate, evicts the lowest fee rate when full, replaces conflicts only for a
  strictly higher fee rate and absolute fee, and expires entries after 24 h.
- The miner keeps the coinbase key in memory while grinding and persists it
  only for a solved block, before the block is added or gossiped. A full key
  file is archived and a new one started. Failures are logged and reported in
  `minerstats` instead of stopping the miner silently.
- `nosoxd`: the RPC token is read from `NOSOX_RPC_TOKEN` (at least 32 bytes);
  the `-rpc-token` flag is removed. A non-loopback RPC bind requires a token and
  TLS. A failed RPC bind or unusable TLS certificate is fatal. `-testnet-difficulty`
  sets the testnet genesis difficulty. A bad `-threads` value is fatal.
- `genesis.Build` returns an error for network magic 0.

### Removed

- All migration code for earlier chains: balance import, claim transactions,
  special-purpose token outputs, wallet key import, and archive tooling.
- The `internal/` packages, the `nosod` and `nosocli` commands, and old test
  fixtures.
- RPC methods tied to the removed code.
- Documentation and audit logs describing earlier protocol versions.

### Retained

- Subsidy schedule: 50 coins, halving every 210,000 blocks, 2,310,000 block end.
- Fees: paid to the miner in the coinbase (see the first entry above).
- Consensus limits: 4 inputs, 4 outputs, 4 kernels, 64 KiB body, 1024-block
  reorganization depth.

### Added

- Documentation site sources in `docs/` built with MkDocs.
- CI: formatting, module tidiness, lint, vulnerability scan, secret scan.
- `SECURITY.md`, issue and pull request templates, Dependabot configuration.

### Release pipeline, CI and documentation (review round 2026-10-31)

- Release workflow: build jobs have read-only permissions; only the final
  `release` job (in a `release` environment) can write. No setup-go cache on
  tag builds. Archives are packaged with fixed order, owner and timestamps.
  A combined `SHA256SUMS` is published, which `scripts/verify-release.sh`
  consumes, together with a keyless build-provenance attestation for every
  archive (`actions/attest-build-provenance`). The per-archive `.sha256` files
  are gone. The workflow has not yet run on GitHub.
- Every action in every workflow is pinned to a full commit SHA with a version
  comment.
- Pages workflow: the build job has read access only and installs from a
  hash-locked `docs/requirements.txt` with `--require-hashes --only-binary :all:`
  (source: `docs/requirements.in`). Only the deploy job has `pages` and
  `id-token` permissions. `actions/configure-pages` was dropped; MkDocs does
  not need it.
- CI: checkouts do not persist credentials; a `GOOS=windows` build is checked.
- `.gitignore` covers `coinbases.json`, `*.outputs`, wallet and key files, data
  directories and built binaries.
- `scripts/verify-release.sh` falls back to `shasum -a 256` when `sha256sum` is
  missing.
- Documentation no longer says that mined coins cannot be spent or that the
  CLI cannot send an RPC token. It states the payment limits: at most 4 inputs,
  no seed-based recovery, unauthenticated slates, no payment proofs.
- `audit/SECURITY_FINDINGS.md` and `audit/RELEASE_READINESS.md` record the
  internal review round of 2026-10-31. These are not an
  independent audit. Almost all findings are listed as open until a fix is
  verified in the tree.
- Dependencies upgraded (x/crypto 0.58, x/net 0.62, x/text, x/sys, x/term,
  klauspost/compress, pion/stun, OpenTelemetry); `govulncheck` reports no
  reachable vulnerability. libp2p and quic-go stay (see `audit/RELEASE_READINESS.md`).

### Wallet, mempool and miner (follow-up)

- **Fund-loss fix.** An unconfirmed incoming output used to be deleted by
  `wallet sync` after 30 days. A sender who finalizes and mines later would then
  have paid coins whose blinding factor the receiver had destroyed. Expired
  receives now move to an encrypted archive (not counted against the live quota
  of 64, bounded at 2048 entries), are still asked about on every sync and come
  back as live records when they appear on chain. `Receive` refuses new offers
  when the archive is full; nothing is evicted. Pruning of spent records and
  never-landed coinbase candidates is bounded by `pruneDepth` (1024) which is
  tested to cover `MaxReorgBlocks`.
- `wallet import-coinbase` also reads the archived `coinbases.json.<ts>.<n>`
  files beside the given path, and works when only archives exist.
- Relay minimum fee: the rejection is `mempool.ErrFeeTooLow` with the fee paid
  and the minimum; over RPC it is the definitive code `-32010` marked as a policy
  rejection (retrying cannot succeed), gossip ignores it (`mempool.IsPolicy`)
  rather than punishing the sender (`classifyTxAdmission`; a malformed
  transaction is now rejected and penalized instead of ignored). `wallet pay` accepts `default` for the fee
  (enough for any payment the wallet builds) and prints the minimum in its usage.
- `minerstats` returns `blocks_found`, `errors`, `last_error`, `last_error_at`.
