# Noso v2 — protocol documentation

Noso v2 is a privacy-by-default cryptocurrency designed for solo mining
on low-power devices. It evolves the dead Noso v1 chain by:

- Inheriting every old balance into genesis via a 1:1 airdrop.
- Replacing SHA-1+ECDSA address-based transactions with Mimblewimble
  Pedersen commitments + range proofs.
- Replacing the unspecified Pascal PoW with **NosoX** = Argon2id at
  64 MiB memory, time=1, threads=1. Pi-friendly, ASIC-hostile.
- Replacing line-based TCP P2P with JSON-over-TCP gossip (libp2p is a
  stretch goal).
- Reusing the v1 halving schedule (5 NOSO initial, halving every
  210k blocks) for emission continuity.

| Topic                                  | File                          |
| -------------------------------------- | ----------------------------- |
| Block/transaction/kernel structures    | [PROTOCOL.md](PROTOCOL.md)    |
| Running NosoX on a Pi                  | [MINING.md](MINING.md)        |
| Slatepack send/receive flow            | [WALLET.md](WALLET.md)        |
| 1:1 airdrop + legacy claim mechanics   | [MIGRATION.md](MIGRATION.md)  |
| Forking your own Noso v2 chain         | [FORKING.md](FORKING.md)      |
| Known limits & follow-up work          | [LIMITS.md](LIMITS.md)        |

## Binaries

* `nosoxd` — v2 archive + mining + RPC daemon
* `nosox-cli` — wallet management + client commands
* `nosox-explorer` — HTMX-based block explorer

The v1 binaries (`nosod`, `nosocli`) remain in the repo for legacy
archive access; they don't talk to v2 nodes.
