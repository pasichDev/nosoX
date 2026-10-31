# NosoX

[![ci](https://github.com/pasichDev/noso-go/actions/workflows/ci.yml/badge.svg)](https://github.com/pasichDev/noso-go/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

NosoX is a Mimblewimble-style chain written in Go. Outputs are Pedersen
commitments with range proofs, blocks are mined with memory-hard Argon2id, and
nodes communicate over libp2p. Documentation: <https://pasichdev.github.io/noso-go/>.

NosoX started as a rewrite of the Noso protocol; it is a new chain, no balances
carry over. Genesis is empty and every coin is mined.

## Status

Experimental. No independent cryptographic audit has taken place. The custom
Schnorr signature and range proof are unreviewed, and secret-dependent code is
not constant time. `nosoxd` refuses to start on mainnet. Do not hold value in
this software.

The wallet spends mined coins with two-party Mimblewimble payments:
`wallet pay`, `receive` and `finalize` exchange two slates, aggregate the
kernel signature and submit the transaction with the `submittransaction` RPC.
Outputs are tracked in an encrypted `<wallet>.outputs` file. Slates are text
starting `SLATEPACK3.`; `wallet new` needs a passphrase of at least 12
characters; `wallet receive <wallet> <slate|@file> [node-rpc]` takes the node so
the wallet can pin its network; an output counts as confirmed after
`NOSOX_CONFIRMATIONS` blocks (default 10); `wallet pay` takes `<fee|default>`
and prints the relay minimum fee; `wallet import-coinbase` also reads the
archived `coinbases.json.<ts>.<n>` key files. See [Wallet](docs/wallet.md) for
the protocol, nonce safety and the variable-time code that remains.

## Features

- Protocol version 5: Pedersen commitments on secp256k1, Schnorr kernel
  signatures, 64-bit range proofs, ordered body roots in the header.
- Argon2id proof of work (64 MiB), weighted-window difficulty, 120 s target.
- Fixed emission: 50 coins per block, halving every 210,000 blocks, about
  20.99 million coins in total. No premine.
- Block fees go to the miner, in the coinbase. After emission ends (height
  2,310,000) fees are the only payment. No founder allocation, no protocol fee.
- Fork choice by accumulated work, atomic reorganization up to 1024 blocks.
- Badger storage with restart replay and verification.
- libp2p gossip and sync over TCP and QUIC (wire protocol v6, compact binary).
- JSON-RPC API with bearer-token access control (token from `NOSOX_RPC_TOKEN`,
  never a flag) for mining controls and wallet calls; no CORS headers unless
  `-rpc-cors-origin` is set.
- Encrypted wallet and output store; two-party payment slates.

## Quick start

Requires Go 1.27.3 or newer.

```bash
git clone https://github.com/pasichDev/noso-go
cd noso-go
go build -o bin/nosoxd ./cmd/nosoxd
go build -o bin/nosox-cli ./cmd/nosox-cli

# isolated testnet node that mines (loopback only, no seeds)
bin/nosoxd -data ./nosox-data -mine -solo-mine -threads 2
```

In another terminal:

```bash
bin/nosox-cli tip 127.0.0.1:7780
bin/nosox-cli mine stats 127.0.0.1:7780   # needs NOSOX_RPC_TOKEN if the node has one
```

Run the tests:

```bash
go vet ./...
go test ./...
go test -race ./...
```

## Repository layout

| Path | Contents |
|---|---|
| `cmd/nosoxd` | Node, miner and RPC daemon. |
| `cmd/nosox-cli` | Wallet and RPC client. |
| `v2/` | Library packages: `types`, `crypto`, `pow`, `chain`, `genesis`, `mempool`, `miner`, `wallet`, `p2p`, `rpc`. |
| `docs/` | Documentation source for the site. |
| `audit/` | Threat model, consensus invariants, findings, release gates. |
| `scripts/` | Release build and verification, publication scan. |
| `seeds/` | Seed list files (currently empty). |

## Documentation

- [Getting started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Protocol](docs/protocol.md)
- [Cryptography](docs/crypto.md)
- [Wallet](docs/wallet.md), [Mining](docs/mining.md), [Running a node](docs/running-a-node.md)
- [RPC](docs/rpc.md), [Limits](docs/limits.md)
- [Security](docs/security.md), [Roadmap](docs/roadmap.md)

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). The internal
review is summarized in [audit/SECURITY_FINDINGS.md](audit/SECURITY_FINDINGS.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
