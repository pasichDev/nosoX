# Known limits and follow-up work

Updated 2026-05-31. The list is short because the previous round of
production-hardening landed nearly everything.

## What's resolved

| Item                            | Status   | Reference                          |
| ------------------------------- | -------- | ---------------------------------- |
| BadgerDB chain backend          | done     | `v2/chain/badger_store.go`         |
| Chain reorg (`ReorgTo`)         | done     | `v2/chain/chain.go`                |
| Coinbase blinding persistence   | done     | `v2/wallet/coinbase.go`            |
| Slatepack codec                 | done     | `v2/wallet/slatepack.go`           |
| libp2p + gossipsub P2P          | done     | `v2/p2p/libp2p_host.go`            |
| NextDifficulty exposed for miner | done    | `v2/chain/chain.go`                |
| Miner respects rolling LWMA-3   | done     | `v2/miner/miner.go`                |
| Memory + Badger reorg tests     | done     | `v2/chain/chain_test.go`           |
| Fee market (mempool sort)       | done     | `v2/mempool/mempool.go`            |
| Schnorr signature on coinbase   | done     | `v2/crypto/schnorr.go` + wallet glue |
| Compact-block-filter (per-block)| done     | `v2/types/filter.go`               |
| libp2p reorg fetch on stale block | done   | `v2/p2p/sync.go`, `v2/p2p/reorg.go` |
| NAT relays + bootstrap nodes    | done     | `v2/p2p/bootstrap.go`              |
| CLI slatepack pay/receive/finalize | done  | `cmd/nosox-cli/main.go`            |
| Real zero-knowledge range proofs | done    | `v2/crypto/borromean.go`           |

## Range proofs: Borromean today, Bulletproofs tomorrow

The active range proof is a Borromean bit-decomposition zero-knowledge
proof over 64 bits:

* Each bit of the committed value gets its own Pedersen commitment.
* Per bit, an OR-proof (Schnorr-style sigma protocol, Fiat-Shamir)
  shows the commit opens to either (0, r) or (1, r) without revealing
  which.
* The verifier checks that Σ C_i · 2^i equals the input commit AND
  every per-bit OR-proof verifies. Both checks together imply the
  committed value is non-negative and ≤ 2^64 − 1.

Wire size: 1 + 64·(33 + 194) = **14529 bytes per output**. That's bigger
than Bulletproofs' ~700 bytes but the structure is simpler and the
verification cost is comparable. Bulletproofs remain on the roadmap as
a drop-in replacement; `VerifyRange` and `ProveRange` already abstract
over the proof type.

Trade-offs:

* ✅ Real ZK — a third-party validator learns the value is in range,
  not what the value is.
* ✅ Conservation enforced by Pedersen kernel sum, independently.
* ✅ Pure-Go, no exotic dependencies.
* ❌ ~20x larger than Bulletproofs.

## What's still open

### 1. Bulletproofs (replace Borromean for wire compactness)

Status: Borromean is real and works; Bulletproofs would shrink each
range proof by ~20x. `VerifyRange` already routes by version byte, so
adding a `borromeanVersion = 3` Bulletproof implementation and
preferring it in `ProveRange` is a non-breaking switch. Estimated
effort: 2–4 days, including test vectors against Grin/Beam reference.

### 2. Light-client wallet mode

Status: per-block compact filters are emitted; the wallet can match
its own outputs. The CLI does not yet have a `wallet sync --light`
mode that fetches filters over libp2p, matches its watch list, and
selectively downloads full blocks. Estimated effort: 1 day.

### 3. Full coinbase split for PoS / dev fund

The locked economic spec calls for 0 dev fund and no PoS — both fields
in `v2/blockchain` are kept at zero on purpose. If a future hardfork
changes the spec, the miner's reward distribution code will need to
read the new percentages. Estimated effort: hours.

### 4. ECC point arithmetic constant-time hardening

Status: `crypto/elliptic` operations on `btcec.S256()` are *not*
constant-time. Production miners running on shared hardware should
consider timing side-channels — the threat model is low because the
Pedersen blinding factors used here are not long-term identity keys,
but a future hardening pass should replace the variable-time
`ScalarMult`/`Add` calls with constant-time wrappers from
`decred/dcrd/dcrec/secp256k1/v4`.

## What is NOT a limit anymore

Items previously listed as gaps and now resolved (kept here for the
record):

- ~~In-memory chain~~ — Badger ships, memstore retained for tests.
- ~~No chain reorg support~~ — `ReorgTo` lands with tests.
- ~~Coinbase without real signing~~ — Schnorr signature on the
  blinding scalar; chain validator enforces it.
- ~~No Slatepack codec~~ — implemented, round-tripping in tests, CLI
  exposes pay/receive/finalize.
- ~~JSON-over-TCP P2P~~ — libp2p + gossipsub.
- ~~Miner queries wrong difficulty~~ — `Chain.NextDifficulty()` exposed.
- ~~No fee market~~ — mempool sorts by fee desc.
- ~~No compact filters~~ — 256-bit per-block filter ships.
- ~~No reorg fetch~~ — `/noso/sync/1` protocol over libp2p.
- ~~No NAT bootstrap~~ — `DefaultBootstrap` + `-relay` flag.
- ~~SimpleRangeProof (binding only)~~ — replaced by Borromean ZK.

## Estimated readiness

The network is now structurally complete for a soft-launch testnet:

* Privacy holds against a third-party validator (Borromean).
* Coinbase ownership is cryptographically bound (Schnorr).
* Stalled blocks trigger automatic reorg fetch via libp2p.
* Mempool prioritizes fee-paying transactions.
* Chain state survives restarts (BadgerDB).
* NAT'd peers can join via static relays.
* The Flutter wallet (NosoSova) speaks to NosoDart, which speaks to v1's
  RPC; a v2 RPC bridge is the only piece linking the two ecosystems.

The remaining items (Bulletproofs, light-client mode, side-channel
hardening) are quality-of-life and security-defense-in-depth that can
ship in subsequent iterations once a testnet is producing traffic.
