# Wallet

The v2 wallet (`nosox-cli wallet`) stores two kinds of keys:

1. An **Ed25519 master key** that signs native v2 transactions.
2. Zero or more **secp256k1 legacy keys** imported from v1 `wallet.pkw`
   files, used only to claim legacy outputs.

The on-disk file is JSON, encrypted with Argon2id-derived key +
XChaCha20-Poly1305. The passphrase is requested interactively (stdin,
hidden).

## Create a wallet

```bash
nosox-cli wallet new ~/.nosox/wallet.json
```

Set a strong passphrase. Argon2id will protect it against brute-force.

## Import legacy keys from v1

```bash
nosox-cli wallet import ~/.nosox/wallet.json /path/to/wallet.pkw
```

Every record in `wallet.pkw` is added as a claim-capable legacy entry.
Only records whose stored address matches the derived address are
accepted (catches corrupt files).

## List claimable balances

```bash
nosox-cli wallet legacy ~/.nosox/wallet.json
```

Then for each address, check the live balance:

```bash
nosox-cli balance http://node:7780 N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd
```

## Native send/receive (Slatepack)

Mimblewimble transactions are interactive: sender and receiver each
contribute outputs and signature shares. The v2 wallet wraps this in
**Slatepack** strings — base58-encoded JSON containers you exchange
over any channel (chat, email, QR).

The flow:

1. Sender runs `wallet pay`, gets a slate-1 string.
2. Receiver runs `wallet receive slate-1`, gets a slate-2 string.
3. Sender runs `wallet finalize slate-2`, broadcasts to the network.

This roundtrip is in the implementation backlog — the wallet structure
and key plumbing are in place; the Slatepack codec is a follow-up.
