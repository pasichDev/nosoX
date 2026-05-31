# Security model & trust assumptions

This document answers the three questions every potential operator and
miner asks: where do the seed nodes come from, what protects the chain
from a 51 % attack at launch, and how does a fresh node trust what it
syncs?

## 1. Seed nodes — who runs them, how they're trusted

### Cold-start problem

A brand-new node has no peers. Without seeds it cannot discover the
network. Whoever provides the first seeds has temporary disproportionate
influence on what the new node accepts as "the chain".

### Three layers of seeds

Noso v2 ships with a layered fallback:

| Layer | Where it lives | When it updates | Trust property |
| --- | --- | --- | --- |
| **Hardcoded** | `v2/p2p/bootstrap.go::MainnetBootstrap` | binary release | reviewed-in-source-code |
| **DNS TXT** | `seed.noso-v2.example.com` TXT records | DNS TTL (1 hour typical) | DNSSEC-signed by the launcher |
| **User-supplied** | `-seed` CLI flag, `nosocfg.psk` | runtime | operator's own judgment |

A node tries all three at startup and uses every reachable address.

### Initial seed-operator selection (launcher's job)

For the first 6 months, the launcher runs **3 dedicated public seed
nodes** in different jurisdictions/networks:

- One in EU (e.g. Hetzner Falkenstein)
- One in North America (e.g. Vultr Chicago)
- One in Asia (e.g. Vultr Singapore)

Each is published in `MainnetBootstrap` with its libp2p peer ID —
peer IDs are derived from Ed25519 keys, so impersonation requires
private-key compromise, not just an IP.

After 6 months the launcher invites community operators by tagging
their multi-addrs in a signed `seedlist.txt` file in the repository.

### How a user verifies "this seed is who it claims to be"

libp2p uses `/p2p/<peer-id>` segments in every multi-address. The peer
ID is the SHA-256 of the host's public key. When a node dials, libp2p
performs a Noise handshake and refuses any connection where the
remote's public key doesn't match the announced peer ID. So **a typo'd
or hostile IP cannot impersonate a real seed** — only a seed whose
private key has leaked.

To rotate compromised seeds, the launcher:
1. Removes the entry from `MainnetBootstrap` and DNS.
2. Tags a binary release with the new list.
3. Posts the rotation rationale in a signed `SECURITY-ROTATION-N.txt`.

### What about a malicious seed?

A malicious seed CAN:
- Drop your traffic (you'll connect to none — annoying but not fatal).
- Refuse to gossip blocks (you'll lag).
- Try to keep you on a stale chain (defeated by the cold-sync flow —
  another peer's HELLO height beats the stale seed's).

A malicious seed CANNOT:
- Forge blocks (PoW + Schnorr + range proofs reject invalid blocks).
- Roll back history past a checkpoint (see § 2).
- Steal funds (signatures are cryptographically bound).

### Why this is acceptable

The trust placed in seeds is **bootstrap-only**. Once a node has dialed
even one honest peer it discovers others via libp2p's peer routing.
After 100 blocks of sync it has its own copy of the chain and is
seed-independent.

## 2. 51 % attack and checkpoints

### The early-chain problem

For the first ~30 days after launch, total network hashrate is small.
A single well-funded miner can outrun the network and rewrite recent
history. Confirmations are correspondingly less final.

### Mitigation: published checkpoints

Every 1000 blocks for the first 100 days the launcher tags a release
with a new `Checkpoint{Height, Hash}` entry in
`v2/types/checkpoints.go::MainnetCheckpoints`. Nodes running that
release **refuse**:

- Any block at the pinned height with a different hash.
- Any reorg whose common ancestor is below the highest checkpoint —
  even one block deeper.

This means a rewrite attack can at most rewrite ~1000 blocks (12 hours
at 120 s blocks) before being shut out.

### What checkpoints are NOT

- **Not a substitute for hashrate.** Between checkpoints the chain is
  still just PoW. The pinned heights are the only fixed points.
- **Not centralization in the long run.** After year one the launcher
  stops publishing new checkpoints; by then the chain's hashrate is
  enough that natural finality (~100 confirmations) covers everything.
- **Not signed by an oracle.** Each operator chooses whether to update
  their binary. If you don't trust the launcher you can run an older
  binary without the new checkpoints and miss the protection.

### Reorg-depth ceiling

Beyond checkpoints, `Chain.ReorgTo` refuses any reorg deeper than
`CoinbaseLock × DifficultyWindow = 60 × 90 = 5400` blocks (~7.5 days),
hardcoded. This is the final fence: even a 51 % attacker can't rewrite
a week of history.

### Recommended confirmation counts

| Use case | Confirmations | Rationale |
| --- | --- | --- |
| Casual receive | 6 | Catches most accidental orphans |
| Merchant payment | 30 | Beats any small-hashrate rewrite |
| Exchange deposit | 100 | Matches `SecurityBlocks` ceiling |
| Large settlement | next checkpoint | Below this, no PoW rewrite is possible |

## 3. How a fresh node syncs the chain

### Cold-sync flow (built in)

1. Node starts. Loads or initializes its chain at genesis.
2. libp2p host comes up; it dials seed multi-addrs from
   `MainnetBootstrap` and DNS TXT records.
3. For each peer that connects, the local node opens a
   `/noso/hello/1` stream and reads the peer's tip height.
4. If the peer is ahead, the node opens a `/noso/sync/1` stream and
   requests blocks in 64-block batches starting from
   `local_height + 1`.
5. Each fetched block is validated (PoW, difficulty, checkpoint,
   coinbase signature, range proofs, double-spend) and applied via
   `Chain.AddBlock`.
6. The loop continues until the local tip ≥ the peer's tip.

A node typically syncs from one peer at a time; libp2p's connection
manager keeps several peers around so the cold-sync survives the loss
of any one.

### Catch-up after disconnection

If a node goes offline for a while and reconnects, the same
`/noso/hello/1` exchange triggers another `CatchUp` call. The reorg
path (`/noso/sync/1` with arbitrary `from`) handles the case where the
network forked while the node was offline — the reorg fetcher pulls
blocks from common-ancestor + 1 and `Chain.ReorgTo` either applies
them (if heavier and not crossing a checkpoint) or rejects them.

### What the new node trusts

A fresh node trusts:
1. The **binary** it runs (provenance: signed release from the
   launcher).
2. The **checkpoints baked into the binary** (the launcher's curation).
3. The **PoW** of every block it accepts (independent re-verification).
4. The **range proofs and Schnorr signatures** in every block
   (independent re-verification).

A fresh node does NOT trust:
- Any single peer (sync from any one peer is verified bit-for-bit).
- The seed IP (peer-ID handshake protects against IP-level
  impersonation).
- The genesis hash claimed by a peer (a fresh node computes its own
  via `genesis.Build()` from the canonical v1 `sumary.psk`).

### Failure modes a fresh node detects

| Scenario | Detection | Resolution |
| --- | --- | --- |
| Seed gives stale tip | another peer's HELLO has higher height | switch to that peer |
| Seed gives invalid blocks | `Chain.AddBlock` rejects with PoW / Schnorr / range-proof error | drop the connection; libp2p picks another |
| Peer impersonates the seed | libp2p peer-ID handshake fails | dial terminates |
| Two peers disagree on chain history | each peer's blocks are validated independently; the heavier chain wins under reorg rules | natural |
| Chain crosses a checkpoint | `ErrCheckpoint` returned, all blocks past divergence rejected | requires the binary's checkpoints to be updated |

## Summary in three sentences

1. Seed nodes are reviewable code + DNS records signed by the launcher,
   peer-ID-bound so impersonation is impossible.
2. Hardcoded checkpoints in the binary stop 51 % attacks past ~1000
   recent blocks; the wider `Chain.ReorgTo` ceiling shuts down anything
   beyond a week.
3. A fresh node verifies every byte of every block it accepts; trust in
   peers is purely bootstrap and shrinks to zero after ~100 sync'd
   blocks.
