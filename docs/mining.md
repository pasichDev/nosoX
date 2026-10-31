# Mining

NosoX uses Argon2id with 64 MiB of memory, one pass and one lane. Each hash
allocates 64 MiB. Mining is CPU work and is memory-bound, so extra threads
beyond the number of physical cores add little. No ASIC or GPU resistance is
established; this is a design intention, not a verified property.

## Run a miner

```bash
bin/nosoxd -data ./nosox-data -mine -threads 2 -reward my-label
```

The thread limit is 16. You can also start and stop mining on a running node:

```bash
bin/nosox-cli mine start 127.0.0.1:7780 2 my-label
bin/nosox-cli mine stats 127.0.0.1:7780
bin/nosox-cli mine stop  127.0.0.1:7780
```

`mine stats` returns `state` (1 while mining), `hashes`, `elapsed` seconds,
`hashesps`, `blocks_found` (solved blocks the chain accepted), `errors` (failures
of the mining loop since start), `last_error` and, once one happened,
`last_error_at`. A miner that cannot build a candidate or save a reward key
keeps retrying and shows up there instead of stopping silently.

`mine start`, `mine stop` **and `mine stats`** are restricted methods: when the
node runs with a token (`NOSOX_RPC_TOKEN` in the node's environment), set the
same variable in the environment of `nosox-cli`. Without a token they work from
non-browser callers on loopback only.

On a fresh single-node network `-mine` alone waits for a synced peer; add
`-solo-mine` to start at once.

## What a miner earns

- The block subsidy: 50 coins per block at the start, halving every 210,000
  blocks (about 291.7 days at the target rate), ending at height 2,310,000.
- All fees of the transactions in the block. The coinbase is worth the subsidy
  plus the total kernel fee `F`, exactly; a miner cannot claim more or less.
  After emission ends (height 2,310,000) the subsidy is 0 and fees are the
  **only** payment: a block with fees still carries a coinbase worth `F`, and
  a block without fees carries none.
- There is no founder allocation, no premine and no protocol fee: every fee a
  sender pays reaches the miner of the block that includes it.

The coinbase output matures after 60 blocks. The blinding factor needed to
spend it is in `<data>/coinbases.json`. To spend it, copy the records into a
wallet with `nosox-cli wallet import-coinbase` (it also reads the archived
`coinbases.json.<ts>.<n>` files beside the live one; see below), run `wallet sync`, and pay with
`wallet pay`, `receive` and `finalize` (see [Wallet](wallet.md)). Limits: one
payment uses at most 4 inputs, `wallet consolidate` merges small outputs, the wallet
has no seed-based recovery (back up the wallet and `.outputs` files), and the
payment slates are not authenticated, so confirm out of band who answers an
offer.

!!! warning "coinbases.json holds spending keys in plaintext"
    Each record contains the blinding factor of a coinbase output, which is the
    only secret needed to spend it. The file is not encrypted. Anyone who can
    read it can take every unspent reward, and losing it loses the reward. The
    daemon creates the data directory with mode `0700` (it tightens an existing
    one) and writes the file with mode `0600`, but that does not protect
    against backups, disk images, other processes of the same user or a
    compromised host. Keep the data directory on an encrypted volume, exclude
    it from unencrypted backups and keep a copy of the file somewhere safe.

The node writes a key only for a block it solved, and only before that block is
added or gossiped, so a crash cannot leave a mined block without its key. When
the file reaches 5,000 records it is renamed to `coinbases.json.<unixnano>.<n>`
and a new file is started; no key is deleted. Keep and import every file: a
wallet that imports only the live file misses the rewards whose keys were
archived.

The `-reward` label (and the `my-label` argument of `mine start`) is a free-form
name for the miner. It appears in the log only and is not part of any block,
kernel or signature. The reward is always paid to a fresh key in
`coinbases.json`.

## Block production

The miner builds a candidate from the tip and the mempool, adds the coinbase
output and kernel (after it has chosen the transactions, because the coinbase
amount includes their fees), and searches nonces. It checks the tip on every attempt and abandons the candidate if the tip
changes. It refreshes the timestamp periodically while searching.

Because a block is limited to 4 outputs, and one is the coinbase, a block carries
at most three transaction outputs.

## Difficulty

The network starts at difficulty 256 and holds it until the chain is 90 blocks
long. After that, difficulty follows the weighted-window formula described in
[Protocol](protocol.md). Hash rates depend on your hardware; measure with
`mine stats`. On one laptop run, two threads reached about 41 hashes per second.

## Memory

Each thread holds about 64 MiB while hashing. Avoid swap on mining machines.

## Pools

There is no pool protocol.
