# Component-by-component readiness

Last revised: 2026-05-31. This document tracks every shipped component:
what it does, what it depends on, what's tested, what's still open.
The bottom-line column drives the launch go/no-go decision.

## Legend

🟢 production-ready · 🟡 testnet-ready, hardening recommended · 🟠
functional, important gaps · 🔴 do not ship

## Microservice surface

| Component | File path | Status | Bottom line |
| --- | --- | --- | --- |
| `nosoxd` daemon | `cmd/nosoxd/` | 🟢 | Boots chain, miner, p2p, rpc; clean shutdown |
| `nosox-cli` wallet+client | `cmd/nosox-cli/` | 🟡 | Wallet flow works; slatepack pay/receive/finalize round-trip; `sendto` final integration deferred |
| `nosox-explorer` web UI | `cmd/nosox-explorer/` | 🟢 | Live dashboard, search, /block, /legacy, /network, HTMX auto-refresh |
| `nosocli` (v1 archive CLI) | `cmd/nosocli/` | 🟢 | Read-only over v1 NOSODATA |
| `nosod` (v1 archive daemon) | `cmd/nosod/` | 🟢 | Read-only over v1 NOSODATA |
| Marketing site | `web/index.html` + `compare.html` | 🟢 | SIGMA-styled, nav, comparison page |
| Docs site | `docs-site/` (Astro Starlight) | 🟢 | 12 pages, builds clean, peer-search index |

## Core packages

| Package | Path | Tests | Coverage notes | Status |
| --- | --- | --- | --- | --- |
| Pascal codec (v1) | `internal/codec` | ✓ | round-trip ShortString | 🟢 |
| v1 crypto | `internal/crypto` | ✓ | genesis-address validates, ECDSA sign/verify | 🟢 |
| v1 types (records) | `internal/types` | ✓ | Marshal/Unmarshal round-trip, fixture-driven | 🟢 |
| v1 storage | `internal/storage` | ✓ | wallet.pkw / sumary.psk / blchhead.nos / gvts.psk parse | 🟢 |
| v1 blockchain logic | `internal/blockchain` | ✓ | halving, supply, fees | 🟢 |
| v1 network (NosoDart compat) | `internal/network` | ✓ | TCP listener, NODESTATUS, NSLBALANCE | 🟢 |
| v2 types (block, output, kernel) | `v2/types` | ✓ | CompactFilter, Checkpoints | 🟢 |
| v2 crypto (Pedersen, Schnorr, Borromean) | `v2/crypto` | ✓ | round-trip 0..2⁴⁰, tamper-reject, wrong-commit-reject, Schnorr forge-reject | 🟡 (variable-time ECC) |
| v2 PoW (NosoX) | `v2/pow` | ✓ | NosoX verify, LWMA-3 steady, LWMA-3 ramp | 🟢 |
| v2 genesis | `v2/genesis` | ✓ | deterministic hash from sumary.psk | 🟢 |
| v2 chain | `v2/chain` | ✓ | Badger persistence, reorg, checkpoint enforcement, 100-block run | 🟢 |
| v2 mempool | `v2/mempool` | ✓ | fee-desc sort | 🟢 |
| v2 miner | `v2/miner` | ✓ | end-to-end mine + validate + coinbase signing | 🟢 |
| v2 wallet | `v2/wallet` | ✓ | Argon2id+XChaCha20 keystore, Slatepack, coinbase, legacy claim | 🟡 (no mlock) |
| v2 p2p | `v2/p2p` | ✓ | two-node cold sync, gossipsub block propagation | 🟡 (no peer scoring) |
| v2 rpc | `v2/rpc` | ✓ run | JSON-RPC 2.0; daemon ctx for miner | 🟠 (no auth) |

## Test coverage as of last sweep

```
15 packages green, no flakes across 3 consecutive runs
─────────────────────────────────────────────────────────
internal/blockchain      0.02 s   (3 tests)
internal/codec           0.01 s   (4 tests)
internal/crypto          0.02 s   (8 tests)
internal/network         0.03 s   (3 tests)
internal/storage         0.01 s   (6 tests)
internal/types           0.02 s   (8 tests, 2 fixture-driven)
v2/chain                 2.4 s    (5 unit + 4 scenario tests including 100-block run, deep reorg, checkpoint enforcement)
v2/crypto                0.7 s    (Borromean + Schnorr + Pedersen + identity + coinbase E2E)
v2/genesis               0.9 s    (deterministic snapshot)
v2/mempool               0.003 s  (fee market)
v2/miner                 0.7 s    (E2E mine + validate, multi-block emit)
v2/p2p                   3.4 s    (parse + format + two-node cold sync + block gossip)
v2/pow                   7.6 s    (LWMA-3 + NosoX + difficulty math)
v2/types                 0.01 s   (compact filter + checkpoints)
v2/wallet                0.025 s  (Slatepack + coinbase + legacy claim)
```

Large-scale scenarios added in this readiness pass:

- `TestTwoNodeColdSync` — fresh node catches up 5 blocks via libp2p
- `TestTwoNodeBlockGossip` — mined block reaches peer in <10 s
- `TestScenarioLongRunMinesHundredBlocks` — 100 blocks under LWMA-3
- `TestScenarioBadgerRestartPreservesState` — kill, reopen, continue mining
- `TestScenarioDeepReorg` — 15-block deep reorg with state rollback
- `TestScenarioCheckpointSurvivesRewriteAttempt` — checkpoint blocks an attempted rewrite

## Component-by-component breakdown

### `nosoxd` (daemon)

**What it does.** Boots BadgerDB chain, applies/loads genesis, opens
libp2p with bootstrap, optional miner, JSON-RPC.

**Dependencies.** All v2 packages + `wallet.OpenCoinbaseStore`.

**Tested.** Live E2E: mines blocks against real v1 sumary fixture for
~80 minutes, height 140+, LWMA-3 ramps difficulty 256→2931 correctly.

**Open.** None blocking testnet. RPC has no auth (use 127.0.0.1
binding or reverse proxy).

### `nosox-cli` (CLI wallet + client)

**What it does.** Wallet create/load/import, legacy listing, Slatepack
pay/receive/finalize, RPC calls (tip, balance, mine start/stop/stats,
genesis info).

**Tested.** Slatepack round-trip + signatures verified.

**Open.** `wallet sendto` doesn't yet assemble a real MW transaction;
documented in LIMITS.

### `nosox-explorer` (web UI)

**What it does.** Live block explorer with HTMX polling. Routes:
`/`, `/block`, `/legacy`, `/genesis`, `/about`, `/tip` (fragment),
`/network` (fragment), `/blocks` (fragment), `/search`.

**Tested.** Live against running nosoxd; all routes 200; template
helpers handle JSON float64→int64 coercion; live dashboard shows real
hashrate + ETA.

**Open.** None blocking. Could grow features post-launch (mempool view,
miner leaderboard, etc).

### v2 crypto

**What it does.** secp256k1 helpers (Pedersen commit, point sub),
Schnorr sign/verify, Borromean ZK range proofs, Base58/36/64 + hashes
needed by genesis bundling.

**Tested.** Round-trip across values 0..2⁴⁰; tamper rejection; wrong-key
rejection; wrong-commit rejection; coinbase pub recovery; identity
point handling.

**Open.** Variable-time `crypto/elliptic` ops — side-channel angle. Swap
to constant-time `decred/dcrec/secp256k1/v4` is a documented blocker
in AUDIT.md.

### v2 PoW (NosoX)

**What it does.** Argon2id at 64 MiB, time=1, lanes=1, deterministic
salt. LWMA-3 difficulty over 90-block window.

**Tested.** Easy-target & search; difficulty steady under stable
solve-times; difficulty ramps on accelerated solve-times.

**Open.** None. The locked spec is the locked spec.

### v2 chain

**What it does.** Two backends (in-memory + BadgerDB) behind a common
`Store` interface. Validation pipeline: PoW + LWMA-3 difficulty +
checkpoint + UTXO presence + coinbase Schnorr + Borromean range
proofs. Reorg via `UndoBlock` → `WriteBlock` with checkpoint guard.

**Tested.** Hundred-block run with active LWMA-3, restart-and-continue,
15-block deep reorg, checkpoint-protected rewrite attempt.

**Open.** None blocking. BadgerDB compaction tuning may benefit
long-running mainnet operators.

### v2 p2p

**What it does.** libp2p host with gossipsub for block + tx topics,
`/noso/hello/1` for status exchange, `/noso/sync/1` for batched block
fetch (used by both cold-sync and reorg fetch). DNS TXT discovery and
hardcoded bootstrap.

**Tested.** Two-node cold sync over libp2p completes 5 blocks in ~1 s;
block gossip propagates in <10 s.

**Open.** No per-peer rate limiting on `/noso/sync/1`; no peer
scoring. Both documented in AUDIT.md.

### v2 wallet

**What it does.** Master Ed25519 key + imported v1 secp256k1 keys.
Slatepack codec + sign/verify. Coinbase blinding storage + signing.

**Tested.** Slatepack encode/decode/sig-verify; coinbase sign/verify
round-trip; legacy claim signing.

**Open.** `mlock` of decrypted master secret. Documented.

### Docs surface

| File | Purpose | Status |
| --- | --- | --- |
| `WHITEPAPER.md` | Bitcoin/Monero-style design paper | 🟢 added in this pass |
| `PROTOCOL.md` | wire formats | 🟢 |
| `MINING.md` | NosoX expectations | 🟢 |
| `WALLET.md` | Slatepack flow | 🟢 |
| `MIGRATION.md` | v1 inheritance | 🟢 |
| `FORKING.md` | run your own chain | 🟢 |
| `LAUNCH.md` | operator runbook | 🟢 |
| `SECURITY.md` | trust model | 🟢 |
| `AUDIT.md` | honest open-issue list | 🟢 |
| `LIMITS.md` | remaining backlog | 🟢 |
| `READINESS.md` | this doc | 🟢 |

Plus the Astro Starlight site at `docs-site/` mirroring the above.

## Pre-mainnet release checklist

Repeating the AUDIT.md ordered list so it's accessible from this
readiness gate too:

1. **Third-party audit** (4–6 weeks). 🔴 not started.
2. **Constant-time ECC** swap. 🟠 patch ready in design.
3. **Checkpoint signature verification** (launcher Ed25519). 🟠 design ready.
4. **RPC token-auth** middleware. 🟠 design ready.
5. **Fuzz harnesses** (Slatepack, gob decoder, range-proof). 🟠 not yet.
6. **Per-peer rate limits** on /noso/sync/1. 🟠 design ready.
7. **`mlock`** of decrypted wallet secrets. 🟠 small.
8. **Reproducible-build manifest** signed by launcher. 🟠 packaging task.

## Go/no-go

| Target | Verdict | Why |
| --- | --- | --- |
| **Local devnet** | 🟢 GO | All packages green, two-node sync verified |
| **Public testnet** | 🟡 GO with banner | "experimental, not audited; do not use real value" notice |
| **Public mainnet** | 🔴 NO-GO | Wait for third-party audit + items 2–7 above |

The work between testnet and mainnet is roughly **one engineer-week**
plus **4–6 weeks external audit**. The chain is structurally complete;
what remains is hardening and external review.
