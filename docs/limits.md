# Limits

Facts about what this software does and does not bound. The consensus numbers
are in [Protocol](protocol.md).

## Consensus limits

| Limit | Value |
|---|---|
| Inputs, outputs, kernels per block | 4 each |
| Charged body size | at most 60,168 bytes in practice (ceiling 64 KiB, never reached) |
| Range proof size | 14,529 bytes |
| Reorganization depth | 1024 blocks |
| Aggregate body of a maximum suffix | 64 MiB |
| Future timestamp | 540 s (new blocks only) |

## Throughput

A block holds at most four outputs. The coinbase takes one. That leaves three
outputs for transactions (the wallet builds payments with at most two: one
payment and its change), about one payment per 120 seconds. Each plain output carries a 14.5 KB proof. The
64 KiB body ceiling does not bind: four inputs, four outputs with maximum-size
proofs and four kernels charge 60,168 bytes, so the item limits above are the
operative bound (the byte check stays as a ceiling; `MaxReorgBodyBytes` derives
from it). There is no way to raise these numbers without a consensus
change.

## Resource use

- Each Argon2id hash needs 64 MiB. Mining with `n` threads holds about `n x 64
  MiB`. Block validation computes one hash.
- Startup replays the full stored chain. Time and scratch disk grow with chain
  length. Memory use during replay does not.
- Badger keeps old versions while a reader is open. Long-running readers delay
  reclamation. If writes keep failing, disk use can grow until one succeeds.
- Experiments on synthetic fork fixtures stayed under 1 GiB of resident memory.
  Use at least 2 GiB as a planning figure. A maximum-size, valid fork has not
  been measured.
- The mempool holds up to 2048 transactions.

## Network

- Sync serves at most 64 blocks per request, a per-peer limiter allows roughly
  one batch every 5 seconds after a burst of 3, and a global byte budget bounds
  what one node serves in total.
- Forks are located with a block locator and followed down to the 1024-block
  reorg limit; a deeper fork is rejected by design and needs a manual resync.
- There is no analysis of Sybil or eclipse resistance and no global budget for
  gossip or dials across peers.

## Cryptographic

- The range proof is large and slow compared with Bulletproofs.
- Secret-dependent arithmetic is variable time.
- Compact block filters exist as a library type with a high false-positive rate.
  They are not served by any interface.

## Timing and difficulty

- Timestamps must strictly exceed the parent's and be at most 540 s ahead of
  the validator's clock, so the rule depends on that clock. There is no
  median-past-time rule by decision: a simulation (`v2/pow/timewarp_sim_test.go`)
  showed it is worse than strictly increasing timestamps with a short future
  limit (it lets an attacker speed the chain up).
- The relay floor is 1000 base units per 1000 bytes of accounted size, roughly
  29,700 to 30,300 units for a wallet payment (a policy of each node, not
  consensus).
- Difficulty holds at 256 for the first 90 blocks, then follows the
  weighted-window formula.
