# noso-go — NosoX implementation

> [!WARNING]
> **Archived research prototype. Not maintained. Consensus is NOT safe.**
> The node accepts blocks it must reject: kernel signatures on transactions are never
> verified (anyone can spend anyone's output), the coinbase amount is not enforced when the
> coinbase kernel is missing (unlimited minting), legacy v1 claims are not signature-checked,
> a placeholder "v1" range proof is accepted, and block contents are not bound to the header.
> There is also no fork choice by total work and no pinned genesis. The status tables in
> `docs/` (READINESS, LAUNCH, AUDIT) describe intent, not the code. Do not run a network or
> hold value on this software. The code stays available for study under the MIT license.

## What NosoX is

NosoX is a memory-hard, privacy-by-default cryptocurrency designed for
**personal devices** — Raspberry Pi, old laptops, modern phones — to
participate as first-class miners. The mission is to keep mining
democratic:

- **NOT ASIC.** Argon2id memory-hard PoW raises the silicon-design
  cost beyond economic viability for a project this size.
- **NOT GPU.** Memory bandwidth dominates, not arithmetic throughput.
  GPUs lose their advantage.
- **YES Pi, phone, laptop, old desktop.** Anything with 256 MB of free
  RAM and a CPU can find blocks.

The chain inherits every balance from the dead Noso v1 Pascal chain
(2018–2024) at genesis. Original v1 keys remain valid for one-time
claim of inherited balances. After claim, normal operation runs on
modern primitives: Ed25519 wallet keys, Pedersen-commitment outputs,
Borromean zero-knowledge range proofs, libp2p networking.

## Project layout

```
noso-go/
├── cmd/
│   ├── nosoxd/         # NosoX node daemon (mining + p2p + JSON-RPC)
│   ├── nosox-cli/      # Wallet + client tool
│   ├── nosox-explorer/ # HTMX-based block explorer
│   ├── nosod/          # (legacy) v1 archive node — read-only
│   └── nosocli/        # (legacy) v1 archive client — read-only
├── v2/                 # NosoX implementation
│   ├── crypto/         # Pedersen, Schnorr (constant-time), Borromean ZK
│   ├── types/          # Block, transaction, kernel, output
│   ├── pow/            # NosoX = Argon2id, LWMA-3 difficulty
│   ├── chain/          # BadgerDB store + validation + reorg + checkpoints
│   ├── genesis/        # Deterministic genesis bundler from v1 sumary.psk
│   ├── miner/          # CPU multi-thread mining loop
│   ├── mempool/        # Fee-prioritized transaction queue
│   ├── wallet/         # Argon2id+XChaCha20 keystore, Slatepack, mlock
│   ├── p2p/            # libp2p + gossipsub + Noise + NAT + DNS seeds
│   └── rpc/            # JSON-RPC 2.0 + Bearer auth
├── internal/           # v1 archive reader (Pascal-compat byte-for-byte)
├── docs/v2/            # Whitepaper, audit, security, launch, migration, …
├── scripts/            # build-release.sh, verify-release.sh
└── testdata/           # Real v1 snapshot fixtures
```

## Quick start (testnet, local)

```bash
go build -o ./bin/nosoxd        ./cmd/nosoxd
go build -o ./bin/nosox-cli     ./cmd/nosox-cli
go build -o ./bin/nosox-explorer ./cmd/nosox-explorer

# Boot a local testnet node (mining enabled, no peers)
./bin/nosoxd \
    -data ./testdata-local \
    -rpc 127.0.0.1:7780 \
    -p2p 127.0.0.1:7781 \
    -network testnet \
    -mine -threads 2 -reward me

# In another terminal: live explorer
./bin/nosox-explorer -listen 127.0.0.1:7782 -node http://127.0.0.1:7780
# open http://127.0.0.1:7782/
```

Within ~30 seconds you'll see blocks rolling in on the explorer
dashboard.

## Migration test (BYO blockchain)

If you have the v1 Noso archive on hand and want to **test the
genesis-bundling pipeline locally**, here's the procedure:

```bash
# 1. Locate your v1 snapshot:
#       sumary.psk  — balances at the height you snapshotted
#       gvts.psk    — 100 GVT slots with their v1 owners

# 2. Boot nosoxd against it, on testnet, in a scratch directory:
./bin/nosoxd \
    -data ./migration-test \
    -rpc 127.0.0.1:7780 \
    -p2p 127.0.0.1:7781 \
    -network testnet \
    -genesis-summary /path/to/sumary.psk \
    -genesis-gvts    /path/to/gvts.psk

# 3. Query the genesis-info RPC:
curl -sS -X POST http://127.0.0.1:7780/ \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"genesisinfo","params":[],"id":1}' | jq .

# Expected: deterministic hash, the same number of legacy accounts
# you had non-zero balances for, and 100 GVTs (one per slot).
```

**The migration is performed entirely locally with the operator's own
v1 archive.** This repo ships zero v1 mainnet data; the only test
fixture is the public 59238-block snapshot already in `testdata/` for
unit tests.

## Wallet test

```bash
# Create a fresh NosoX wallet (encrypted with your passphrase)
./bin/nosox-cli wallet new ~/.nosox/wallet.json

# Import legacy v1 keys (so you can claim airdropped balances)
./bin/nosox-cli wallet import ~/.nosox/wallet.json /path/to/wallet.pkw

# See what's claimable
./bin/nosox-cli wallet legacy ~/.nosox/wallet.json

# Build a claim transaction (does NOT submit to mainnet)
./bin/nosox-cli wallet claim ~/.nosox/wallet.json http://127.0.0.1:7780 N4PeJyqj…

# List GVT slots and owners
./bin/nosox-cli wallet gvt list ~/.nosox/wallet.json http://127.0.0.1:7780

# Redeem a GVT for 70 NOSO
./bin/nosox-cli wallet gvt redeem ~/.nosox/wallet.json http://127.0.0.1:7780 47
```

The CLI prints the constructed transaction but does **not** broadcast
it. Direct RPC submission is wired in but disabled by default until
the audit completes. Treat the wallet as a **transaction-builder
sandbox** today.

## Locked spec

| Parameter | Value |
| --- | --- |
| Block time | 120 s |
| Halving interval | 210 000 blocks (≈ 292 days) |
| Halving steps | 10 |
| Initial reward | 50 NOSO |
| Max supply | ≈ 24 M NOSO (legacy carry + emission) |
| Premine | 0 |
| Dev fund | 0 |
| Legacy carry | 1:1 from v1 sumary.psk + 100 GVTs (70 NOSO each) |
| PoW | NosoX = Argon2id, 64 MiB memory, 1 lane |
| Privacy | Mimblewimble + Borromean ZK range proofs |
| Difficulty algo | LWMA-3 over 90-block window |
| Reorg cap | 5 400 blocks (≈ 7.5 days) |
| Wallet at rest | Argon2id + XChaCha20-Poly1305 + mlock |
| RPC auth | Bearer token (off by default on 127.0.0.1) |

## Roadmap — what NosoX enables beyond money

The cryptographic primitives in this repo (`v2/crypto`) are
deliberately reusable. Once the chain is stable, planned extensions:

- **Encrypted messenger.** Pedersen commitments + Ed25519 signing +
  the same libp2p transport already power a private store-and-forward
  messaging protocol. Wallets become messaging endpoints; no
  centralized server, no plaintext metadata.
- **Identity attestations.** Holders sign claims about themselves
  (e.g. "this Ed25519 key controls GVT slot 47") that other apps
  consume.
- **Payment-channel-style tooling.** Two-party commitments on the
  chain settle, micropayments off-chain.
- **Light-client wallet for mobile.** Compact filters already shipped
  in `v2/types/filter.go`; need the mobile sync mode (one engineering
  week).

These are **not** consensus features and don't require a hard fork.
They reuse the same crypto primitives the chain already exposes.

## Documentation

| File | Audience |
| --- | --- |
| [`docs/v2/WHITEPAPER.md`](docs/v2/WHITEPAPER.md) | Design paper, formal notation |
| [`docs/v2/PROTOCOL.md`](docs/v2/PROTOCOL.md) | Wire format and validation |
| [`docs/v2/MIGRATION.md`](docs/v2/MIGRATION.md) | v1 → NosoX inheritance mechanics |
| [`docs/v2/MINING.md`](docs/v2/MINING.md) | NosoX expectations on Pi / phone / laptop |
| [`docs/v2/WALLET.md`](docs/v2/WALLET.md) | Slatepack flow |
| [`docs/v2/SECURITY.md`](docs/v2/SECURITY.md) | Trust model, seeds, 51% defense |
| [`docs/v2/AUDIT.md`](docs/v2/AUDIT.md) | Honest open-issue list |
| [`docs/v2/READINESS.md`](docs/v2/READINESS.md) | Component-by-component status |
| [`docs/v2/EXCHANGES.md`](docs/v2/EXCHANGES.md) | Listing strategy (honest) |
| [`docs/v2/REPRODUCIBLE.md`](docs/v2/REPRODUCIBLE.md) | How to verify binaries |
| [`docs/v2/LAUNCH.md`](docs/v2/LAUNCH.md) | Operator runbook |
| [`docs/v2/FORKING.md`](docs/v2/FORKING.md) | Run your own chain |
| [`docs/v2/LIMITS.md`](docs/v2/LIMITS.md) | Post-launch backlog |
| [`docs/v2/PITCH.md`](docs/v2/PITCH.md) | Short pitch for technical reviewers |

The marketing landing + comparison site is a separate repo:
[noso/nosox-site](https://github.com/pasichDev/nosox-site).

## Status as of last commit

```
13 200+ LOC Go        16 packages, all tests green (×3 runs)
102 test functions    5 fuzz harnesses, 0 crashes in 25s runs
5 binaries            constant-time Schnorr + Borromean prover
                      reproducible builds, mlock'd wallet,
                      checkpoint Ed25519 verification, fee market,
                      libp2p gossipsub, multi-node sync verified
```

Mainnet readiness gate: **independent external audit** (4–6 weeks,
$50–150 k budget). Recommended firms: NCC Group, Trail of Bits,
Cure53. Everything else mechanical is closed in the source.

## License

MIT. Anyone can fork, rebrand, run their own NosoX-compatible chain.
The genesis bundler is parameter-driven; bring your own v1 snapshot.

## Contributing

Issues and PRs welcome. Priority categories:
1. **Audit feedback** when the external review starts.
2. **Light-client mobile wallet** mode.
3. **Encrypted-messenger protocol** on top of v2/crypto + v2/p2p.
4. **Documentation translations** (UK Ukrainian, ES, JA, DE).

For coordination, open a GitHub issue.
