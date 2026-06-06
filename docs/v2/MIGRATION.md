# Migration from Noso v1 to NosoX

NosoX inherits **two** things from the original Noso v1 Pascal chain:

1. **Every non-zero account balance** in v1's `sumary.psk` becomes a
   *Legacy UTXO* in the NosoX genesis block. Original v1 secp256k1
   keys remain valid to claim them.
2. **Every one of the 100 GVT tokens** in v1's `gvts.psk` becomes a
   *LegacyGVT* output, preserving slot identity (00..99) and
   transferable / redeemable by the v1 owner.

## Short version for v1 holders

If you held NOSO at the time of the v1 snapshot:

```bash
# 1. Create a NosoX wallet
nosox-cli wallet new ~/.nosox/wallet.json

# 2. Import your v1 keys (read-only — only for claim signing)
nosox-cli wallet import ~/.nosox/wallet.json /path/to/v1/wallet.pkw

# 3. See what's claimable on a NosoX node
nosox-cli wallet legacy ~/.nosox/wallet.json

# 4. Claim balances (each call builds one claim transaction)
nosox-cli wallet claim ~/.nosox/wallet.json http://nosox-node:7780 N4PeJyqj…
```

After every claim, that legacy UTXO converts to a private MW
commitment owned by your Ed25519 master key. The v1 key is never
needed again for that balance.

## GVT inheritance (new in NosoX)

The 100 v1 GVT slots are preserved 1:1 in NosoX genesis. Each becomes
a `LegacyGVT` output with three operational modes for its owner:

| Action | What happens | Use case |
| --- | --- | --- |
| **Redeem** | Spend the GVT for 70 NOSO base units (the v1 `GVTBaseValue`). The slot disappears from the UTXO set. | "I want the value as ordinary NOSO." |
| **Transfer** | Spend → mint a new `LegacyGVT` output with the same slot number under a new owner's blinding factor. Identity preserved. | "I'm gifting/selling slot 47 to someone else." |
| **Hold** | Do nothing. The output sits in the UTXO set indefinitely under the v1 owner address. | "I'll decide later." |

```bash
# List all 100 GVT slots and their owners
nosox-cli wallet gvt list ~/.nosox/wallet.json http://node:7780

# Redeem slot 47 for 70 NOSO (only if you're the slot 47 owner)
nosox-cli wallet gvt redeem ~/.nosox/wallet.json http://node:7780 47

# Transfer slot 47 to another wallet's blinding factor
nosox-cli wallet gvt send ~/.nosox/wallet.json http://node:7780 47 <receiver-blind-hex>
```

NosoX assigns **no special protocol role** to GVTs. They are
historical collectibles with a fixed redeem value (70 NOSO). They do
NOT vote, do NOT confer governance power, do NOT pay yield. The whole
purpose is to honor v1 ownership without inventing new mechanics.

## Mechanics in detail

### Genesis bundling

`v2/genesis/genesis.go` reads both files at bundle time:

```go
cfg := genesis.Default()
cfg.SummaryPath = "/path/to/v1/sumary.psk"
cfg.GVTsPath    = "/path/to/v1/gvts.psk"
block, accounts, gvts, err := genesis.Build(cfg)
```

For each non-zero `sumary.psk` record:

```
LegacyOutput {
  Commit        = PedersenCommit(balance, SHA256("NosoX legacy blind " + addr))
  LegacyAddress = addr
  LegacyAmount  = balance
}
```

For each of the 100 `gvts.psk` records with an owner:

```
LegacyGVTOutput {
  Features      = OutputFeaturesLegacyGVT
  Commit        = PedersenCommit(GVTBaseValue, SHA256("NosoX legacy GVT blind <slot> <owner>"))
  LegacyAddress = owner       // v1 secp256k1-derived address that can spend it
  LegacyAmount  = GVTBaseValue = 70_000_000_000 base units = 70 NOSO
  GVTNumber     = slot        // 00..99, preserved on transfer
}
```

The blinding factor is **deterministic** and publicly derivable from
the address (and slot, for GVTs). This means every node and every
wallet can independently reconstruct each commitment without sharing
secrets. Legacy outputs are NOT privacy-protected — privacy starts
when the original owner first spends them into a regular MW output.

### Claim signature

To spend either output type, the owner constructs an `Input` with:

```
Input {
  Features     = Legacy or LegacyGVT
  Commit       = the genesis commit
  LegacySig    = ECDSA-SHA1(v1 private key, claim_message)
  LegacyAddr   = original "N…" address
  LegacyAmount = balance / GVTBaseValue
}
```

The claim message is

```
"NOSOX-LEGACY-SPEND " ‖ legacy_address ‖ hex(commit) ‖ block_height
```

The chain validator derives the v1 public key from the address using
the v1 derivation rules (SHA-256 over Base64 pubkey → RIPEMD-160 →
Base58 + sum checksum) and verifies the signature. Same code path for
balance claims and GVT spends.

### Determinism

Two independent runs of `genesis.Build()` over the same v1 snapshot
files produce the same `Block.HeaderID`. The integration test
`v2/genesis/gvt_test.go` asserts this with the public
`testdata/sumary_59238.psk` + `testdata/gvts.psk` fixtures:

```
16,207 accounts (9,011,854 NOSO at block 180031) + 100 GVTs (7,000 NOSO)
   → genesis hash 3e7c5bcae0765b0f6e7b203d9c4261cde84e30ec8f3014ab2f7f1b4bf7ffe3ed
```

If another implementation produces a different hash from the same
inputs, it has diverged from the canonical bundler.

## Lost keys

A 1:1 inheritance does NOT save lost keys. If the original v1
`wallet.pkw` is gone, the carried balance (or GVT) is unrecoverable.
There is no central recovery service and no quorum override. This is
deliberate for trust-minimization.

## For non-holders

You don't need to do anything. The chain still works for you —
balances and GVTs you don't own simply sit in the UTXO set
indefinitely under their original owner addresses. They don't
inflate supply, they don't move on their own.

## Forking your own chain

If you want a clean NosoX-shaped chain WITHOUT carrying v1 balances:

```bash
nosoxd -data ./mychain -network testnet
# Omit both -genesis-summary and -genesis-gvts → empty genesis
```

The chain otherwise behaves identically. Your community can launch
its own NosoX-compatible network with different seed nodes and
checkpoints.
