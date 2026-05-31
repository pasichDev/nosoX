# Noso v2: privacy money, formalized

**Version:** v0.2 · **Status:** pre-mainnet · **License:** MIT

## Abstract

Noso v2 is a Mimblewimble-based cryptocurrency that inherits every
balance from the original Pascal Noso chain (v1, 2018–2024) and replaces
its cryptography, networking, storage, and wallet UX with primitives
suited to long-term operation. Transactions reveal Pedersen commitments
and zero-knowledge range proofs but never amounts or addresses; mining
runs on a memory-hard Argon2id construction targeted at low-power
CPUs; a libp2p mesh handles peering, NAT traversal, and gossip. The
v1 ledger snapshot is bundled into the v2 genesis block as a set of
*legacy outputs* spendable by the original secp256k1 keys, providing
1:1 inheritance without an interactive claim. This document specifies
the protocol and is the canonical reference for implementers.

## 1. Introduction

The original Noso chain shipped a transparent ledger over hand-rolled
cryptography (SHA-256/RIPEMD-160 addresses, ECDSA-SHA1 signatures, MD5
consensus hashes) and a hand-rolled TCP wire protocol. After the
network died in 2024 the ledger persisted on disk in tens of thousands
of wallets. Two facts motivated v2:

1. **The existing balance distribution is community history.** Erasing
   it for a new launch is a political and ethical cost. A 1:1
   inheritance preserves it.
2. **The original primitives are not what modern designers would pick.**
   SHA-1 + ECDSA, MD5 in consensus, and transparent amounts are
   liabilities, not features.

v2 changes everything below the application layer and keeps the parts
users observe — the supply schedule, the Σ NOSO ticker, the existing
NosoSova Flutter wallet — intact.

## 2. Design goals

- **Privacy by default.** No optional shielding. Every native v2
  transaction is a Mimblewimble transaction.
- **Solo-mineable on commodity hardware.** A Raspberry Pi 4 must
  produce blocks at a meaningful rate at network launch.
- **Forkable.** Anyone holding the v1 `sumary.psk` can deterministically
  generate the genesis block; anyone running the source can fork.
- **No premine, no team allocation, no dev fund.** The legacy carry-over
  is the only pre-genesis state.

## 3. Notation

| Symbol | Meaning |
| --- | --- |
| `G` | secp256k1 generator (canonical) |
| `H` | NUMS point on secp256k1, `H = lift_x(SHA-256("Noso v2 Pedersen H point") mod p)` |
| `n` | secp256k1 group order |
| `‖` | byte concatenation |
| `C(v, r)` | Pedersen commitment `v·H + r·G` |

## 4. Transactions

### 4.1 Outputs

Every output is one of three kinds:

| Feature | Meaning |
| --- | --- |
| `Plain` | Standard MW output; commitment + range proof |
| `Coinbase` | Miner reward; one per block, no range proof but constrained by chain rules |
| `Legacy` | Genesis-only; carries `(address, balance)` from v1 |

A plain output is

```
Output = (Features, Commit, RangeProof)
Commit = v·H + r·G       with v >= 0
RangeProof: Borromean ZK proof that v ∈ [0, 2⁶⁴)
```

A legacy output is

```
LegacyOutput = (Features = Legacy, Commit, LegacyAddress, LegacyAmount)
Commit       = LegacyAmount·H + b_addr·G
b_addr       = SHA-256("NosoX legacy blind " ‖ LegacyAddress)
```

The blinding factor `b_addr` is publicly recoverable from the address,
so every validator can independently verify the commitment without any
secret data. Legacy outputs are NOT private; they become private on
first spend.

### 4.2 Inputs

```
Input = (Features, Commit, ...)
```

For `Plain`/`Coinbase` inputs, the commitment must currently be in the
UTXO set. For `Legacy` inputs, the input additionally carries
`(LegacyAddr, LegacyAmount, LegacySig)`; the signature is an ECDSA
signature by the original secp256k1 key over the canonical claim
string

```
"NOSOX-LEGACY-SPEND " ‖ LegacyAddr ‖ hex(Commit) ‖ blockHeight
```

The chain validator checks that `LegacySig` verifies under the public
key derived from `LegacyAddr` via the v1 address-derivation rules
(SHA-256 → RIPEMD-160 over Base64 string of pubkey → Base58 + checksum).

### 4.3 Kernels

A kernel binds inputs and outputs together and certifies the value
conservation of the transaction:

```
Kernel = (Features, Fee, LockHeight, Excess, ExcessSig)
Excess: 33-byte Pedersen commitment to the excess blinding factor
ExcessSig: Schnorr signature over KernelID by the secret r corresponding to Excess
KernelID = SHA-256(Features ‖ Fee ‖ LockHeight ‖ Excess)
```

Kernels come in three variants:

- `Plain` — typical transfer.
- `Coinbase` — block reward; one per block.
- `LegacyClaim` — transitioning a legacy output to native MW.

### 4.4 Conservation

A block is value-valid iff

```
Σ_outputs Commit − Σ_inputs Commit − Σ_kernels Excess − total_offset
  =  fee · H
```

Because `H` and `G` are independent generators (`H` is NUMS) this
identity holds iff (a) the algebraic sum of values is zero modulo `n`
and (b) the prover knew the discrete-log decomposition of the excess.
Under the discrete-log assumption, no transaction can create value.

### 4.5 Coinbase

A coinbase output has the form

```
Output_cb = (Coinbase, C_cb, ⊥)         (no range proof; amount fixed by chain rules)
C_cb      = reward(h)·H + r_cb·G
```

with `r_cb` chosen randomly by the miner and persisted to its
`CoinbaseStore`. The matching coinbase kernel signs the canonical
preimage

```
msg = SHA-256( BigEndian(h) ‖ BigEndian(reward(h)) ‖ C_cb )
```

with the Schnorr secret key `r_cb`. The verifier recovers the kernel
public key as `C_cb − reward(h)·H = r_cb·G` and checks the signature
under that key. This binds the coinbase to whoever generated `r_cb`;
spending it later requires knowing `r_cb`.

### 4.6 Borromean range proof

For a plain output with value `v ∈ [0, 2⁶⁴)` the prover:

1. Decomposes `v = Σ_{i=0..63} b_i · 2^i` with `b_i ∈ {0, 1}`.
2. Picks blindings `r_0, …, r_62` uniformly at random and computes
   `r_63 = (r − Σ_{i<63} r_i · 2^i) · (2⁶³)^{-1} mod n` so that
   `Σ_i r_i · 2^i ≡ r (mod n)`.
3. Forms per-bit commits `C_i = b_i·H + r_i·G`.
4. For each `i`, produces a Schnorr OR-proof showing `C_i` opens to
   either `(0, r_i)` or `(1, r_i)`. The OR is non-interactive via
   Fiat-Shamir with domain separator `"Noso-v2-Borromean"`.

The verifier checks `Σ_i C_i · 2^i = C(v, r)` and that every per-bit
OR-proof verifies. Wire size: `1 + 64·(33 + 194) = 14 529 B` per output.
The construction is replaceable by Bulletproofs without altering the
public `ProveRange`/`VerifyRange` API.

## 5. Proof of Work — NosoX

### 5.1 Hash function

```
NosoX(header) = Argon2id(
    password = canonical_encode(header),
    salt     = "NosoX-v1-PoW-salt-32B-deterministic",
    memory   = 64 MiB,
    time     = 1,
    lanes    = 1,
    keyLen   = 32 bytes
)
```

The header encoding is the concatenation, in big-endian order, of
`Version, Height, Timestamp, PrevHash, OutputRoot, KernelRoot,
TotalKernelOffset, Difficulty, Nonce`.

### 5.2 Target & verification

```
MaxTarget = 2²⁵⁶ − 1
Target(d) = MaxTarget / d
Verify(h) ↔ NosoX(h) ≤ Target(h.Difficulty)
```

### 5.3 Difficulty adjustment — LWMA-3

For tip `H` with `H ≥ 90` predecessors:

```
T = TargetBlockTime = 120 s
N = 90
solveTime_i ∈ [1, 6·T]              (clamped)
nextD = (Σ D_i · T · (N+1)) / (2 · Σ i · solveTime_i)
nextD ≥ MinDifficulty (= 1)
```

The linear weights on `solveTime_i` suppress timestamp manipulation
relative to a simple moving average; the algorithm is Zawy's LWMA-3,
well-studied for low-hashrate chains.

## 6. Network

### 6.1 Transport

All P2P traffic uses libp2p over TCP with Noise encryption and yamux
multiplexing. The host advertises one or more multi-addresses of the
form `/ip4/IP/tcp/PORT/p2p/PEERID` where `PEERID = SHA-256(host pub
key)`. The Noise handshake verifies the dialed peer's public key
matches its announced peer ID, making IP-level impersonation
infeasible.

### 6.2 Topics

Two gossipsub topics, namespaced by network magic:

```
noso-v2/<magic-hex>/blocks   — gob-encoded *Block
noso-v2/<magic-hex>/txs      — gob-encoded *Transaction
```

Mainnet magic = `0x4e4f5832`, testnet = `0x4e4f5854`.

### 6.3 Streams

Two per-stream protocols supplement gossipsub:

- `/noso/hello/1` — application-level status exchange:
  `(Version, NetworkMagic, Height, TipHash)`. On every new peer
  connect, both sides open this stream; if the peer's tip is higher,
  the local node starts cold-sync.
- `/noso/sync/1` — request/response for a range of blocks. Used both
  for cold-sync (`from = local_height + 1`) and reorg fetch (`from =
  local_height − 3`). Response contains full blocks; the requester
  validates each via `Chain.AddBlock` or `Chain.ReorgTo`.

### 6.4 Peer discovery

Three layers:

1. **Hardcoded.** `MainnetBootstrap` is a slice of multi-addrs baked
   into the binary release.
2. **DNS.** TXT records under `seed.noso-v2.{network}.example.com`
   in the form `v=nosox1;addr=<multiaddr>` are resolved at startup.
3. **User-supplied.** `-seed` CLI flag, `nosocfg.psk` overrides.

Layer 1 is reviewable in source; layer 2 lets operators rotate
without binary rebuilds; layer 3 lets distrustful operators choose
their own bootstrap entirely.

## 7. Consensus

### 7.1 Block validation

A block is consensus-valid iff:

1. `PrevHash` equals the current tip's `HeaderID`.
2. `Height = tip.Height + 1`.
3. `Difficulty = LWMA3(last_window, target=120 s)`.
4. `Verify(header)` succeeds (PoW).
5. For every input: `Commit ∈ UTXO`.
6. No `Checkpoint{Height, Hash}` exists with `Height == block.Height`
   and `Hash ≠ HeaderID(block.Header)`.
7. The coinbase Schnorr signature verifies (if present).
8. Every plain output's range proof verifies.
9. The Pedersen kernel-sum identity holds (transaction-level).

### 7.2 Reorg

A node receives a block whose `PrevHash` is not the current tip and
initiates a reorg fetch from the publishing peer. After fetching the
fork's blocks, `Chain.ReorgTo` walks back to the common ancestor,
verifies each incoming block under the same rules as above, and
applies it. A reorg is refused if:

- the common ancestor is below the highest `MainnetCheckpoint`
  (`ErrCheckpoint`), or
- depth > `CoinbaseLock · DifficultyWindow = 60 · 90 = 5400` blocks
  (`ErrTooDeep`).

### 7.3 Checkpoints

`MainnetCheckpoints` is a slice of `(Height, Hash)` pairs published by
the launcher. The validator refuses any block at a pinned height with
a different hash and any reorg whose ancestor is below the highest
pin. Checkpoints close the 51 % attack window at network birth; they
become unnecessary once natural hashrate is high enough.

## 8. Genesis — inheritance from v1

`genesis.Build(cfg)` computes a deterministic genesis block from a v1
`sumary.psk` snapshot:

```
for each (Hash, Balance) ∈ sumary.psk with Balance > 0:
    add LegacyOutput{
        Commit = Balance·H + SHA-256("NosoX legacy blind " ‖ Hash)·G,
        LegacyAddress = Hash,
        LegacyAmount  = Balance,
    } to genesis.Outputs
```

The genesis header has `Height = 0`, `PrevHash = 0`, `Difficulty =
InitialDifficulty (256)`, `Timestamp = cfg.Timestamp`. Anyone running
`genesis.Build()` with the same inputs gets the same `HeaderID`
(verified across nodes by the cold-sync handshake).

At the time of writing the canonical v1 snapshot at block 59 238
yields:

```
3 561 legacy outputs
2 971 803.9073 NOSO carried
genesis hash 3a59a5392e8e7f9ee8ad1a02c9db684a56808c786a36e519dcab5b0ab4f22f07
```

## 9. Economic schedule

| Parameter | Value |
| --- | --- |
| Block time | 120 s |
| Halving interval | 210 000 blocks (≈ 292 days) |
| Halving steps | 10 |
| Initial reward | 50 NOSO (5×10⁹ base units) |
| Total supply | ≈ 24 M NOSO (≈ 3 M legacy + ≈ 20.98 M emission) |
| Premine | 0 |
| Dev fund | 0 |
| Min fee | `max(amount / 10 000, 1 000 000)` base units |
| Coinbase maturity | 60 blocks (≈ 2 h) |

Reward at height `h`:

```
reward(0)                = 0   (no coinbase at genesis)
reward(h), 0 < h < 210k·(steps+1) = InitialReward >> (h / 210k)
reward(h) otherwise        = 0
```

## 10. Wallet

A wallet holds two key kinds:

- **Master Ed25519 key** — used to sign partial slates and Slatepack
  envelopes. One per wallet, encrypted at rest with Argon2id-derived
  XChaCha20-Poly1305.
- **Imported legacy secp256k1 keys** — used only to sign legacy claim
  inputs.

Transactions are built interactively via **Slatepacks**:

1. Sender constructs a stage-1 slate carrying `(amount, fee,
   lockHeight, sender's contributed inputs and change output)`, signs
   the partial under the kernel's challenge-hash.
2. Receiver decodes the slate, adds an output for the gross amount,
   signs their share, returns a stage-2 slate.
3. Sender verifies, signs the final aggregate, broadcasts via the
   node's RPC.

Slates are base58-wrapped CBOR-like JSON. The CLI exposes
`nosox-cli wallet pay|receive|finalize`.

## 11. Security model

The chain's correctness rests on the following assumptions:

| Assumption | Consequence if broken |
| --- | --- |
| Discrete log over secp256k1 is hard | All Pedersen commitments could be opened; conservation broken. |
| `H` is a NUMS point | A clever attacker could create commitments with two openings, breaking binding. |
| SHA-256, SHA-1 are collision-resistant in our usage | Hash collisions could let attackers forge IDs / signatures. |
| Argon2id is memory-hard | An attacker with custom silicon could outpace honest miners. |
| Schnorr soundness in the ROM | Forged signatures possible. |
| `crypto/rand` provides cryptographic randomness | Nonces could be predictable, leaking secrets. |

Layered defenses:

- **Checkpoints** close the 51 % window during low hashrate.
- **Reorg-depth ceiling** prevents week-long rewrites under any
  circumstance.
- **Range proofs** prove `v ∈ [0, 2⁶⁴)` without leaking `v`.
- **Conservation check** rejects any unbalanced transaction.

The full open-issue list is in [`AUDIT.md`](./AUDIT.md). Items the
launcher must close before mainnet include constant-time ECC,
checkpoint signature verification, RPC token-auth, and a third-party
audit.

## 12. Roadmap

Post-launch upgrades on the table, none breaking the wire format:

- **Bulletproofs** replace Borromean for ~20× smaller range proofs.
- **Compact-block filters** with a light-client wallet mode.
- **DNSSEC client-side validation** for the seed TXT records.
- **Per-peer rate limits** on `/noso/sync/1`.
- **`mlock`-ing decrypted wallet secrets**.

## 13. Conclusion

Noso v2 is a clean re-implementation that preserves the supply
schedule and balance ledger of a community cryptocurrency while
swapping its primitives for ones whose security and performance
properties are documented. The cryptography is real (Pedersen,
Borromean, Schnorr, Argon2id), the engineering is conservative
(atomic writes, bounded buffers, explicit timeouts), and the
deployment is forkable (anyone with the snapshot can launch).

The same balance of conservatism applies to claims: this paper does
not promise mainnet-grade safety until an independent audit completes
the open items in `AUDIT.md`. For a public testnet today, it is
sufficient. For higher stakes, it is a structurally complete starting
point.

## References

1. Andrew Poelstra. *Mimblewimble.* 2016.
2. Greg Maxwell. *Confidential Transactions.* 2015.
3. Tom Elvis Jedusor. *Mimblewimble whitepaper.* 2016.
4. *Argon2: the memory-hard function for password hashing and other
   applications.* Biryukov, Dinu, Khovratovich. 2015.
5. Zawy. *LWMA Difficulty Algorithm.* 2017.
6. Protocol Labs. *libp2p specification.* https://libp2p.io
7. Noso Project. *NosoNode v0.5.0 source.* 2024 (final v1 release).
