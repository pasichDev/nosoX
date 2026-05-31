# Security audit memo

This is my honest assessment after writing the v2 code. It's intended
for the launcher, anyone considering forking the chain, and any future
auditor. I'd rather flag potential issues now than have them surface
in production.

**TL;DR.** The code is structurally sound for a testnet. It is NOT
ready for high-value mainnet deployment without (a) an independent
professional audit and (b) closing the items in § 4 below.

## 1. What's solid

### Cryptographic primitives

- **secp256k1** via btcec (Bitcoin's vetted curve).
- **Schnorr signatures** with proper Fiat-Shamir transcript and
  domain separation (`"Noso-v2-Schnorr"` || R || P || len(msg) || msg).
- **Pedersen commitments** computed as `v·H + r·G`, with H derived
  deterministically from `SHA-256("Noso v2 Pedersen H point")` via
  try-and-increment — standard NUMS construction.
- **Borromean bit-decomposition range proofs**: each of 64 bits has
  a Schnorr-OR proof showing the bit-commitment opens to (0, r) or
  (1, r); verifier checks both the OR-proof and Σ_i C_i·2^i == C.
  Mathematically equivalent to what Monero shipped 2016–2018.
- **Argon2id PoW** at 64 MiB, t=1, lane=1. Well-reviewed
  primitive; memory-hard against GPU/FPGA per Argon2 paper.
- **Ed25519** master keys for wallets (deterministic, fast on ARM,
  small signatures).
- **Argon2id + XChaCha20-Poly1305** for wallet encryption at rest.

### Defensive engineering

- All file writes are atomic: `tmp → fsync → rename → fsync(parent)`.
- TCP line buffers capped at 8 KiB (v1 used `MaxInt` — DoS vector).
- Explicit read/write/idle deadlines on every connection.
- BadgerDB transactional UTXO updates (write + delete atomic).
- Reorg depth hard-capped at 5 400 blocks (~7.5 days at 120 s).
- Checkpoint pinning closes the early-chain 51 % window.
- libp2p Noise handshake — IP impersonation impossible at the
  transport layer.

### Test discipline

- 15 packages, all tests green including an end-to-end mine + validate
  integration test that runs the entire PoW → coinbase Schnorr →
  range proof → BadgerDB write path.
- Two fixture-driven tests parse real v1 data (`sumary_59238.psk`,
  `gvts.psk`) to verify byte-exact compat with the Pascal node.
- Crypto tests cover round-trip, tampering, wrong-key, wrong-amount,
  wrong-commit cases.

## 2. Real concerns the launcher must close before mainnet

These are not theoretical — they would let a sophisticated attacker
do something we don't want.

### 2.1 No independent audit

This codebase was written quickly. Even careful single-author crypto
code has bugs that show up only under adversarial review. Before any
real-value mainnet, retain a firm with ECC + Mimblewimble experience
(e.g. NCC Group, Trail of Bits, Cure53) for a 4–6 week pass.
Budget $50–150 k.

**Status:** OPEN. No audit performed.

### 2.2 Variable-time ECC operations

`crypto/elliptic` operations on `btcec.S256()` are **not**
constant-time. `ScalarMult`, `Add`, and the `big.Int` arithmetic
throughout `v2/crypto` leak timing information correlated with
secret values.

Worst-case impact: an observer with precise timing measurements
during Schnorr signing or Borromean range-proof generation could
recover blinding factors or bit values. The cost of mounting such an
attack on a remote miner is high (network jitter), but co-located or
side-channel-capable attackers are real.

**Mitigation path:** replace `btcec.S256()` calls with
`decred/dcrd/dcrec/secp256k1/v4`, which provides constant-time
scalar operations. Affects `v2/crypto/pedersen.go`,
`v2/crypto/schnorr.go`, `v2/crypto/borromean.go`.

**Estimated effort:** 1–2 days.

**Status:** OPEN.

### 2.3 No checkpoint-list signing

`MainnetCheckpoints` is a Go slice. Anyone shipping an unofficial
binary can rewrite it. Without signature verification at startup, a
fork with malicious checkpoints can be made to look authoritative.

**Mitigation path:** launcher publishes a `checkpoints.sig` file —
detached Ed25519 signature over the canonical checkpoint list —
alongside each binary release. Daemon verifies on startup against a
launcher pubkey baked into the source.

**Estimated effort:** half a day.

**Status:** OPEN.

### 2.4 No DNSSEC validation client-side

`net.Resolver.LookupTXT` returns whatever the local resolver hands
back. A malicious resolver (or MITM between node and resolver) can
substitute seed entries.

**Mitigation paths** (pick one):
- Sign the seed-list TXT body with launcher Ed25519, verify in
  `parseSeedTXT`.
- Use a DNSSEC-validating resolver library
  (`github.com/miekg/dns` + DNSKEY chain validation).

**Estimated effort:** 1–2 days.

**Status:** OPEN.

### 2.5 RPC has zero authentication

`v2/rpc` accepts `startmining`, `stopmining`, `submitorder` from any
HTTP POST. A node exposing 7780 to the internet allows arbitrary
actions on behalf of the operator.

**Mitigation paths:**
- Document loudly: "bind 127.0.0.1 only" in `LAUNCH.md`.
- Add token-auth: shared secret in HTTP header, configurable via
  `-rpc-token` flag.

**Status:** Documentation says "no auth"; binary still accepts. Token
auth is ~50 lines of middleware.

### 2.6 No fuzz harnesses

Every parser and verifier is a candidate for malformed-input bugs.
Go's `testing.F` makes this cheap.

Priority targets:
- `Wallet.Slate.Decode` (Base58 + JSON)
- `p2p.decodeBlockMsg` / `decodeTxMsg` (gob)
- `crypto.VerifyRangeBorromean` (33-byte point parsing)
- `chain.Chain.AddBlock` (full block validation)

**Estimated effort:** 1 day to scaffold; ongoing.

**Status:** OPEN.

### 2.7 Mempool / DoS limits

- `Pool.maxSize` is 2048 transactions. With 100 outputs per tx and
  14 KB Borromean proofs each, the pool ceiling is ~2.8 GB of RAM.
- `/noso/sync/1` accepts batch size up to 256 blocks. A peer
  requesting maximum batches from height 0 forces the responder to
  serialize ~256 × (header + N orders + Schnorr + Borromean) bytes.
  No rate limit.

**Mitigation paths:**
- Bound mempool by total weight (sum of output counts × proof sizes)
  not just tx count.
- Per-peer rate limit on `/noso/sync/1` (e.g. one batch per peer per
  10 seconds).

**Estimated effort:** half a day.

**Status:** OPEN.

### 2.8 libp2p peer scoring not wired up

Misbehaving peers (sending invalid blocks, oversized payloads, slow
streams) keep eating resources. libp2p-pubsub exposes a
`PeerScoreParams` hook; we don't use it.

**Mitigation path:** define a score function that penalizes invalid
blocks, slow streams, repeated decode failures.

**Estimated effort:** 1 day.

**Status:** OPEN.

### 2.9 Wallet keys not mlock'd

`v2/wallet.Load` decrypts the master seed into a regular `[]byte` and
keeps the Ed25519 `PrivateKey` in heap memory. On a swap-enabled
system the secret could land on disk.

**Mitigation path:** call `syscall.Mlock` on the seed and the
`ed25519.PrivateKey` slice. Zeroize on close.

**Estimated effort:** half a day.

**Status:** OPEN.

### 2.10 Argon2id @ 64 MiB is not RandomX-strong

NosoX picks a Pi-friendly memory size. A motivated FPGA designer
spending ~$50–100 k can outperform CPUs at the same wattage. Argon2
is provably memory-hard in the random-oracle model, but constants
matter.

This is an **accepted tradeoff** — the locked spec prioritizes Pi
mineability over absolute ASIC resistance. Document it loudly so
miners don't think Argon2id @ 64 MiB is a moat.

**Status:** ACCEPTED, document in `MINING.md`.

## 3. Risks the design has but the threat model accepts

These are NOT bugs — they're trade-offs called out in the design.

| Risk | Mitigation in design | Accepted because |
| --- | --- | --- |
| Lost v1 key = unrecoverable v2 balance | none | Trustless airdrop has no central authority |
| Checkpoint trust → launcher | launcher signs checkpoint list (§ 2.3) | Hardrate too low for natural finality early |
| MW interactivity hurts UX | Slatepack over QR / chat | Real privacy needs it |
| Borromean range proofs are 14 KB | Bulletproofs upgrade later | Real ZK now > smaller-proof-later |
| Reward halving in 10 years not 100 | matches v1 emission curve | Holder continuity |

## 4. Pre-mainnet release blockers (ordered)

If I were operating the launch I'd refuse to ship `MainnetCheckpoints`
until each of these is closed.

1. **Third-party audit pass** (4–6 weeks).
2. **Constant-time ECC swap** to `decred/dcrd/dcrec/secp256k1/v4`.
3. **Checkpoint signature verification** with launcher pubkey baked
   in source.
4. **RPC token-auth middleware** + LAUNCH.md updated to require it.
5. **Fuzz harnesses** for Slatepack, gob block decoder, range-proof
   verifier — let them run for 24 h on CI.
6. **Per-peer rate limits** on `/noso/sync/1`.
7. **mlock** of decrypted wallet secrets.
8. **Reproducible-build** instructions and a published manifest of
   release binary hashes signed by the launcher key.

Items 2-8 are mechanical and total roughly 1 working week.

## 5. Cryptographic claims I make and what they mean

To make the threat model crisp:

| Claim | What it really means |
| --- | --- |
| "Pedersen kernels prevent over-issuance" | If `Σ output_commits − Σ input_commits − Σ kernel_excess − fee·H = 0`, no value was created from nothing **assuming discrete log over secp256k1 is hard**. |
| "Borromean range proofs prove `v ∈ [0, 2⁶⁴)`" | An honest verifier rejects any range proof whose Σ_i C_i · 2^i differs from the input commit OR whose per-bit OR-proof fails. Assumes secure RNG and unforgeability of Schnorr-OR under random oracle. |
| "Schnorr signatures bind coinbase ownership" | Verifier reconstructs `r·G = C − amount·H` and checks Schnorr. Forging requires DLog secret. |
| "MW transactions hide sender and amount" | An observer learns commitments and proofs, nothing more, **assuming Pedersen hiding holds**. Statistical hiding is information-theoretic; binding requires DLog. |
| "libp2p peer-id binds connection" | Noise handshake refuses anyone whose pubkey hash ≠ announced peer-id. Forging requires the seed's private key. |
| "Checkpoints prevent deep rewrites" | Validator refuses any block at pinned height with non-matching hash AND any reorg ancestor below highest checkpoint. Only as strong as the launcher's checkpoint-publication discipline. |

## 6. What an auditor should review first

If hiring an auditor and they ask "where to start":

1. `v2/crypto/borromean.go` — the OR-proof construction. Verify
   challenge-response soundness, simulator hiding, no transcript bugs.
2. `v2/crypto/schnorr.go` — challenge hashing, nonce generation,
   verification equation.
3. `v2/crypto/pedersen.go` — `PedersenSumZero` arithmetic correctness,
   identity-point handling, compression/decompression edge cases.
4. `v2/chain/chain.go::validate` and `::ReorgTo` — invariant
   maintenance under partial failure, checkpoint enforcement.
5. `v2/wallet/coinbase_glue.go::pubFromCoinbase` — the math that
   recovers the kernel pubkey from `(commit, amount)`. This was where
   the first audit pass found a real bug; another set of eyes is
   warranted.
6. `v2/wallet/slatepack.go::CheckBalance` — interactive transaction
   conservation.

## 7. Final word

If I had to grade this for production-readiness today: **B-**. The
cryptography is real, the math is correct, the engineering is careful,
and the test suite covers the happy paths. But "real and correct" is
not "audited and hardened." I would run a public testnet on this code
tomorrow; I would not put a billion-dollar bridge on it without
closing § 2 and § 4.

The audit-and-close pass is roughly a one-week ticket for a
moderately senior crypto engineer + a 4–6 week external audit. After
that I'd grade it **B+** — competitive with mid-tier privacy coins
shipped after similar effort.
