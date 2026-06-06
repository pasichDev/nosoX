# Launching a Noso v2 network — operator runbook

This document describes how to spin up Noso v2 from scratch and bring
it to a stable, peered network. It's intended for the launch operator
and anyone forking the chain.

## Prerequisites

* Go ≥ 1.23 installed on every node
* A public IPv4/IPv6 address (or a relay if you're behind NAT)
* The v1 `sumary.psk` file if you want to carry forward legacy
  balances (the canonical Noso v2 mainnet does; private forks do not
  have to)
* Inbound + outbound **TCP and UDP** allowed on the chosen p2p port —
  the node listens on both TCP and **QUIC-v1 (UDP)**. QUIC (the
  transport Google/HTTP3 use) keeps peers connected on lossy/mobile
  networks where TCP stalls; no extra flags, just open UDP too.

> **Launch plan: 3 seed nodes** are enough to bootstrap the mesh; the
> DHT + HTTPS/DNS seed discovery take over from there.

## Step 1 — pick network parameters

Edit `v2/types/types.go` only if you're forking. For the canonical
network:

```
NetworkMagicMainnet  = 0x4e4f5832  ("NOX2")
TargetBlockTimeSeconds = 120
BlockHalvingInterval  = 210_000
InitialReward         = 5_000_000_000   (= 50 NOSO)
DifficultyWindow      = 90
```

The locked spec is in `docs/v2/MINING.md` and
[../analysis/README.md](../analysis/README.md). Don't change values
without a fork rename.

## Step 2 — build the binaries

```bash
git clone https://github.com/Noso-Project/noso-go
cd noso-go
go build -o bin/nosoxd ./cmd/nosoxd
go build -o bin/nosox-cli ./cmd/nosox-cli
```

Two binaries:

* `nosoxd` — full node + miner + RPC + libp2p host
* `nosox-cli` — wallet + client tools

The block explorer is a separate static repo (`nosox-explorer`, GitHub Pages) —
see Step 7.

## Step 3 — bootstrap a fresh chain

Operators carrying v1 balances pass `-genesis-summary`:

```bash
mkdir -p /var/nosox
bin/nosoxd \
    -data /var/nosox \
    -genesis-summary /path/to/v1/sumary.psk \
    -rpc 0.0.0.0:7780 \
    -p2p 0.0.0.0:7781 \
    -network mainnet
```

For a true from-scratch fork (no legacy balances) just omit
`-genesis-summary`.

On first start `nosoxd` prints the genesis hash, the libp2p multi-addr
list (one per network interface), and the RPC URL. Capture the
multi-addr — that's what other operators will use to dial your node.

Example output:

```
nosoxd chain ready: height=0 hash=3a59a5392e8e7f9ee… difficulty=256
nosoxd p2p listening on /ip4/203.0.113.5/tcp/7781/p2p/12D3KooWFD1qH…
nosoxd JSON-RPC on http://0.0.0.0:7780
```

## Step 4 — publish bootstrap multi-addrs

Edit `v2/p2p/bootstrap.go`:

```go
var MainnetBootstrap = []string{
    "/ip4/203.0.113.5/tcp/7781/p2p/12D3KooW…",
    "/dns4/seed1.example.com/tcp/7781/p2p/12D3KooW…",
    // …
}
```

Tag a release commit with the official seed list so every new
node bootstraps without manual configuration. Operators behind
NAT add their entries to `MainnetRelays` instead and run a relay node.

### Recommended: publish seeds over HTTPS at your domain (no rebuild)

Hard-coding seeds in `bootstrap.go` means a binary upgrade every time the
set changes. Instead, keep the live list in the repo at
[`seeds/mainnet.txt`](../../seeds/mainnet.txt) and **serve it from your
domain**:

```
https://pasichdev.xyz/seeds/mainnet.txt
```

Point `pasichdev.xyz` (CNAME) at a static host (GitHub Pages / Cloudflare
Pages) that serves the repo's `seeds/` directory. Every node fetches this URL
on startup (`v2/p2p/httpseeds.go` → `HTTPSeedURLs`) and merges it with `-seed`,
DNS seeds and the DHT. Rotate seeds by editing the file and redeploying — no
new binary. Per-node opt-out: `-http-seeds=false`. Format: one libp2p
multi-address per line; `#` comments and blank lines ignored. Testnet uses
`seeds/testnet.txt` → `https://pasichdev.xyz/seeds/testnet.txt`.

## Step 5 — start mining

A miner needs:

1. A long-running `nosoxd` process (above).
2. A `-reward` label baked into coinbase kernels. Pick any string
   — it doesn't bind funds, it's just a tag.
3. Threads count matching physical cores (Argon2id is memory-bound;
   hyperthreads don't help).

```bash
bin/nosoxd \
    -data /var/nosox \
    -genesis-summary /path/to/v1/sumary.psk \
    -rpc 0.0.0.0:7780 \
    -p2p 0.0.0.0:7781 \
    -mine \
    -threads 2 \
    -reward my-launch-node
```

Or start mining on a running node via RPC:

```bash
bin/nosox-cli mine start http://127.0.0.1:7780 2 my-launch-node
bin/nosox-cli mine stats http://127.0.0.1:7780
```

Stats should show `hashesps` rising within a minute. Expected on a
Pi 4: 5–15 H/s per core.

## Step 6 — connect peers

A second node dials the first using the multi-addr from step 3:

```bash
bin/nosoxd \
    -data /var/nosox2 \
    -genesis-summary /path/to/v1/sumary.psk \
    -rpc 127.0.0.1:8780 \
    -p2p 127.0.0.1:8781 \
    -seed "/ip4/203.0.113.5/tcp/7781/p2p/12D3KooW…"
```

For NAT'd nodes, also pass `-relay` with a list of public relay
multi-addrs. The libp2p AutoRelay subsystem will register and accept
inbound dials via the relay.

## Step 7 — the explorer (separate, serverless)

The block explorer is now its own **static** repo (`nosox-explorer`),
deployed to GitHub Pages at `explorer.pasichdev.xyz`. It talks to node RPC
directly from the browser — there is nothing to run here. Just make sure your
node's RPC is reachable over HTTPS with CORS (it is by default) and listed in
`seeds/rpc-mainnet.txt` (served at `https://pasichdev.xyz/seeds/rpc-mainnet.txt`).

## Step 8 — expose the RPC externally (remote wallets / explorers)

To let wallets, explorers and clients connect **from outside** over JSON-RPC:

```bash
bin/nosoxd -data /var/nosox -network mainnet \
    -rpc 0.0.0.0:7780 \
    -rpc-token "$(openssl rand -hex 32)"   # REQUIRED on a public bind
```

- **Bind:** `-rpc 0.0.0.0:7780` listens on all interfaces; open TCP 7780 in the
  firewall. (Loopback-only? use `127.0.0.1:7780`.)
- **Auth:** on a non-loopback bind always set `-rpc-token`. Read-only methods
  (`tip`, `getblock`, `legacybalance`, `genesisinfo`, `minerstats`, …) stay
  public so an explorer needs no token; mutating methods (`startmining`,
  `stopmining`, …) require `Authorization: Bearer <token>`.
- **Browser clients:** CORS is enabled (`Access-Control-Allow-Origin: *`,
  `Allow-Headers: Content-Type, Authorization`), so a web wallet on another
  origin can call a remote node with a Bearer token — the preflight passes.
- **TLS:** the RPC server is plain HTTP. For public deployments terminate TLS
  at a reverse proxy (Caddy/nginx) — e.g. `https://rpc.pasichdev.xyz` → 7780 —
  so tokens aren't sent in clear.

Quick remote check:

```bash
curl -s https://rpc.pasichdev.xyz -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tip","id":1}'
```

## Verification checklist

Run through this list before announcing the network is live.

| Check | Command | Expected |
| --- | --- | --- |
| Genesis hash matches across nodes | `nosox-cli tip http://node:7780` | Same `hash` on every node |
| Legacy balance lookup works | `nosox-cli balance http://node:7780 N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd` | `1042008032156` for the canonical premine address |
| Mining produces blocks | `nosox-cli mine stats …` after ~5 min | `hashes > 0`, `state = 1` |
| Validators accept mined blocks | `nosox-cli tip` returns increasing height | `height` grows |
| Two-node sync | second node's tip catches up | matches first node within ~1 block |
| RPC port is reachable | `curl -X POST http://node:7780/health` | `ok` |
| libp2p peer count > 0 | (log message at startup) | reachable on `/ip4/…/p2p/…` |

## Wallet onboarding for end-users

```bash
# Create a fresh wallet (master Ed25519 key)
bin/nosox-cli wallet new ~/.nosox/wallet.json

# Import legacy v1 keys to claim airdropped balances
bin/nosox-cli wallet import ~/.nosox/wallet.json /path/to/v1/wallet.pkw

# See what's claimable
bin/nosox-cli wallet legacy ~/.nosox/wallet.json
```

## What's intentionally NOT in this release

These are documented in `LIMITS.md`. None are launch blockers:

* Bulletproofs (Borromean ZK ships; Bulletproofs trims wire size 20×).
* Light-client sync mode (compact filters ship; wallet flag pending).
* Constant-time ECC (`btcec` variable-time ops; threat model is low
  because miners' blinding factors are not long-term identity keys).

## Operational notes

* **Backups.** `state.gob` (memory store) or the `chain/` BadgerDB
  directory is the canonical chain state. Snapshot it before any
  upgrade. The genesis is deterministic, so a corrupted chain can be
  rebuilt by replaying gossip from peers.
* **Wallet recovery.** Lost passphrase = lost wallet. There is no
  recovery service. Keep an off-site encrypted backup of
  `~/.nosox/wallet.json`.
* **NAT.** A node behind symmetric NAT cannot accept inbound. Either
  open the p2p port, use the libp2p AutoRelay flag (`-relay`), or run
  outbound-only and miss broadcast-fan-in opportunities.
* **Resource use.** Each Argon2id hash allocates 64 MiB transiently.
  A miner with 4 threads holds ~256 MiB of working set during PoW.
  Block validation and RPC are negligible.

## When something goes wrong

* `chain ready: height=0 hash=…` with the WRONG hash → check that
  `-genesis-summary` points at the v1 mainnet `sumary.psk`; the
  canonical hash is `3a59a5392e…`.
* `chain: bad coinbase Schnorr signature` in logs → the node's wallet
  store is mis-allocating blindings. Stop the node, delete
  `coinbases.json` and restart (only safe if you haven't already
  earned coinbases).
* `p2p: reject block: chain: stale block` → the reorg fetcher is
  already trying. Wait one block time; check tip via `nosox-cli tip`.
* libp2p shows zero peers → confirm the p2p port is open
  (`ss -tlnp | grep 7781`), verify the seed multi-addr you passed.

## Production hardening checklist (post-launch)

* Pin a TLS-terminating proxy in front of `:7780` RPC if exposing to
  the internet. The RPC layer has no auth.
* Run the daemon under systemd with `Restart=always` and a dedicated
  user.
* Mount `/var/nosox` on a fast SSD; BadgerDB performance depends on
  random reads.
* Forward port 7781/tcp on the upstream firewall for inbound libp2p
  dials.
* Monitor `nosox-cli tip` from a separate watchdog; alert if the tip
  hash stops advancing for > 10 minutes.
