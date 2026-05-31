# Noso v2 protocol

Authoritative for the wire format and validation rules. The Go
implementation under `v2/` MUST match this doc; if it doesn't, the doc
or the code is a bug.

## Constants

| Constant                     | Value                              |
| ---------------------------- | ---------------------------------- |
| `BlockVersion`               | 1                                  |
| `TargetBlockTimeSeconds`     | 120                                |
| `CoinbaseLock`               | 60 blocks                          |
| `DifficultyWindow` (LWMA-3)  | 90                                 |
| `MinDifficulty`              | 1                                  |
| `CoinUnits`                  | 100_000_000 (8 decimals)           |
| `InitialReward`              | 5_000_000_000 base units           |
| `BlockHalvingInterval`       | 210_000                            |
| `HalvingSteps`               | 10                                 |
| `NetworkMagicMainnet`        | 0x4e4f5832 ("NOX2")                |
| `NetworkMagicTestnet`        | 0x4e4f5854 ("NOXT")                |

## Block header

Canonical encoding (big-endian, no padding):

```
[4]  version
[8]  height
[8]  timestamp     (unix seconds)
[32] prev_hash     SHA-256
[32] output_root   Merkle SHA-256 of OutputID per Output
[32] kernel_root   Merkle SHA-256 of KernelID per Kernel
[33] total_kernel_offset   Pedersen commitment
[8]  difficulty
[8]  nonce
```

The block hash is `SHA-256(encoded_header)`. PoW validity:

```
Argon2id(encoded_header) <= MaxTarget / difficulty
```

with `MaxTarget = 2^256 - 1` and parameters memory=64 MiB, time=1,
threads=1, salt=`"NosoX-v1-PoW-salt-32B-deterministic"`.

## Output

```go
Output {
  Features      uint8   // 0 = Plain, 1 = Coinbase, 2 = Legacy
  Commit        [33]    // Pedersen commitment (compressed point)
  RangeProof    bytes   // present only when Features == Plain
  LegacyAddress string  // present only when Features == Legacy
  LegacyAmount  int64   // present only when Features == Legacy
}
```

`OutputID` is `SHA-256` of the canonical preimage:

```
[1] features
[33] commit
(if Legacy:)
[utf-8 of LegacyAddress]
[8] big-endian LegacyAmount
```

Note the range proof is NOT in the OutputID preimage, so cut-through can
rewrite proofs without altering identities.

## Kernel

```go
Kernel {
  Features    uint8  // 0 = Plain, 1 = Coinbase, 2 = LegacyClaim
  Fee         uint64
  LockHeight  uint64
  Excess      [33]   // Pedersen commitment to the excess blinding factor
  ExcessSig   bytes  // Schnorr-style sig (on KernelID) by Excess
}
```

`KernelID` is `SHA-256` of `[features || fee || lock_height || excess]`.

A block is **conservation-valid** iff:

```
Σ output_commits − Σ input_commits − Σ kernel_excess − total_kernel_offset
   == fee · H
```

where H is the deterministic NUMS point derived from
`SHA-256("Noso v2 Pedersen H point")`.

For legacy outputs whose amount is explicit, the commitment uses a
public blinding factor `SHA-256("NosoX legacy blind " + legacy_address)`,
so any node can verify legacy commitments without secret data.

## Legacy claim

To spend a legacy output, the spender includes an `Input` with:

```
Features      = Legacy
Commit        = the legacy commit
LegacySig     = Base64 DER ECDSA(SHA-1) signature by the original
                  secp256k1 key over the canonical claim message
LegacyAddr    = original "N…" address
LegacyAmount  = the carried balance
```

Canonical claim message:

```
NOSOX-LEGACY-SPEND <legacy_address> <hex(commit)> <block_height>
```

## Difficulty

Standard LWMA-3 (Zawy) over the last 90 blocks. For the first 90 blocks
the difficulty stays pinned to the genesis value. Floor: `MinDifficulty`.

## Reward schedule

```
height = 0   → no coinbase (legacy outputs only)
0 < h < 210_000 * (HalvingSteps + 1)
             → InitialReward >> (h / 210_000)
otherwise    → 0
```

## P2P

Line-delimited JSON over TCP. Each message is one `Envelope`:

```json
{"type": "HELLO|NEWBLOCK|NEWTX", "body": {...}}
```

Bound max line size: 1 MiB. Connections idle out at 30 seconds without
a read.
