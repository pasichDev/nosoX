# Protocol

This page describes protocol version 5 as implemented in `v2/`. The code is
authoritative. The hash domains and encodings listed here are consensus rules.

## Constants

| Name | Value |
|---|---|
| Block version | 5 |
| Network magic, mainnet | `0x4e4f5832` |
| Network magic, testnet | `0x4e4f5854` |
| Target block time | 120 s |
| Difficulty window | 90 blocks |
| Initial difficulty (genesis) | 256 |
| Minimum difficulty | 1 |
| Coinbase maturity | 60 blocks |
| Base units per coin | 100,000,000 |
| Maximum reorganization depth | 1024 blocks |
| Maximum future timestamp | 540 s ahead of the validator clock (new blocks only) |
| Minimum relay fee (policy, not consensus) | 1000 base units per 1000 bytes of accounted size |

## Header

All integers are big-endian. The header is 169 bytes:

| Field | Size |
|---|---|
| Version | 4 |
| NetworkMagic | 4 |
| Height | 8 |
| Timestamp (Unix seconds, signed) | 8 |
| PrevHash | 32 |
| OutputRoot | 32 |
| KernelRoot | 32 |
| TotalKernelOffset | 33 (must be all zero) |
| Difficulty | 8 |
| Nonce | 8 |

The block hash is SHA-256 of this encoding. The proof of work hashes the same
bytes with Argon2id (see below).

## Body

A block has lists of inputs, outputs and kernels.

- **Input**: feature flag (1 byte) and the 33-byte commitment of the output
  being spent.
- **Output**: feature flag, 33-byte commitment, range proof. Flags: `0` plain,
  `1` coinbase. `2` is unassigned (an earlier draft used it for a dev-fund
  output that was removed before launch) and is rejected. Coinbase outputs
  carry no proof.
- **Kernel**: feature flag (`0` plain, `1` coinbase), fee (8 bytes), lock height
  (8 bytes), 33-byte excess, 65-byte Schnorr signature.

### Hash domains

Every domain is an ASCII string. A trailing `\0` is part of the string where
shown.

| Purpose | Preimage |
|---|---|
| Kernel ID | `"NosoX/kernel/v5\0"` + feature + fee + lock height + excess (signature excluded) |
| Kernel signing message | `types.KernelSigningMessage`: SHA-256 of `"NosoX/kernel-sig/v5\0"` + `BE32(network magic)` + kernel ID. A plain kernel's signature covers this, so it is valid on one network only |
| Output ID | `"NosoX/output/v5\0"` + feature + commitment + length-prefixed proof |
| OutputRoot | SHA-256 of `"NosoX/block/outputs/v5\0"` + output count + each output preimage, length-prefixed |
| KernelRoot | SHA-256 of `"NosoX/block/inputs-kernels/v5\0"` + input count and inputs, then kernel count and each kernel preimage and signature, length-prefixed |
| Transaction ID | SHA-256 of `"NosoX/transaction/v5\0"` + length-prefixed inputs-and-kernels encoding + length-prefixed outputs encoding |

Counts and length prefixes are 8-byte big-endian integers. The roots commit to
the complete ordered body, including proofs and signatures.

The Schnorr, range-proof, generator and slate domains are listed in
[Cryptography](crypto.md).

## Consensus rules

A block at height `h` is valid when all of the following hold.

**Header**

1. Version is 5, the offset field is zero, difficulty is non-zero, the
   timestamp is non-negative.
2. The body is within the limits below and both roots match the body.
3. `PrevHash` is the current tip, the height is `tip + 1`, and the network magic
   equals the parent's.
4. The timestamp is strictly greater than the parent's and at most 540 s ahead
   of the validator's clock. The clock rule applies to new blocks only; replay of
   stored blocks does not re-check it. A median-time-past rule was simulated
   (`v2/pow/timewarp_sim_test.go`) and rejected: used instead of the strict rule
   it lets an attacker speed the chain up, so strictly increasing timestamps are
   retained and the future limit was cut from two hours to 540 s.
5. Difficulty equals the value computed from the previous blocks.
6. If a checkpoint is configured for the height, the hash matches it. The
   daemon configures none.
7. The Argon2id hash meets the difficulty target.

**Inputs**

8. Each input is a valid point, appears once, and matches an unspent output with
   the same feature flag.
9. A coinbase output cannot be spent until 60 blocks after the block that
   created it.

**Outputs**

10. Each output is a valid, non-identity point that has not appeared before on
    the active chain, even if spent.
11. Plain outputs carry a range proof that verifies. Coinbase outputs
    carry none and appear only in blocks, never in standalone transactions.
    Output feature 2 is rejected.

**Kernels**

12. Each excess is a valid point and each kernel ID is new to the active chain.
13. Plain kernels have a lock height not above `h` and a signature that verifies
    over `KernelSigningMessage(network magic, kernel)` under the excess. Fees must sum to at most 2^63 - 1.
14. The coinbase kernel has fee 0 and lock height `h + 60`.

**Coinbase**

15. Let `R = BlockReward(h)` and `F` the total kernel fee. The coinbase amount
    is `R + F`, computed with overflow-checked 64-bit arithmetic. If
    `R + F > 0` the block has exactly one coinbase output and one coinbase
    kernel, including after emission ends; the output commitment equals the
    kernel excess; and the kernel signature verifies under
    `commitment - (R + F)*H` over the digest of network magic, height, amount
    and commitment (see [Cryptography](crypto.md)). A commitment to any other
    value fails. If `R + F == 0` the block has neither. A block with fees and no
    coinbase is invalid.

**Fees**

16. Fees are not minted: a spend destroys `F` (its outputs plus fee equal its
    inputs) and the coinbase collects it, so the unspent set always sums to the
    cumulative subsidy. After height 2,310,000 miners are paid by fees alone.
    There is no founder allocation and no protocol fee.

**Balance**

17. `sum(plain outputs) - sum(inputs) + F*H = sum(plain kernel excesses)`.
    The coinbase value is known and checked by rule 15, so it is excluded.

**Limits**

18. At most 4 inputs, 4 outputs and 4 kernels. Charged body size at most
    64 KiB: 192 bytes per input, 128 plus proof length per output, 128 plus
    signature length per kernel. A proof is at most 14,529 bytes. The item
    limits already keep the charged body at or below 60,168 bytes, so the
    64 KiB ceiling is never the deciding limit.

The genesis block has height 0, a zero parent, and no inputs, outputs or
kernels.

## Emission

`BlockReward(h)` is 0 at height 0. For `0 < h < 2,310,000` it is
`5,000,000,000 >> floor(h / 210,000)` base units: 50 coins, halving every
210,000 blocks, rounding down. From height 2,310,000 it is 0.

Total issuance is 2,098,969,609,270,000 base units (20,989,696.0927 coins),
reached at height 2,309,999. One halving period is about 291.7 days at the
120-second target. Fees are not subsidy; they go to the miner in the coinbase (rule 15).

## Proof of work

Argon2id over the 169-byte header: 64 MiB memory, 1 pass, 1 lane, 32-byte
output, fixed salt `NosoX/pow-salt/v5\0`. The hash, read as a
big-endian integer, must be at most `(2^256 - 1) / difficulty`.

## Difficulty

While the tip height is below 90, difficulty stays at the tip's value (the
genesis value, 256). After that it is computed from the last 90 blocks with a
weighted-window formula (`pow.LWMA3`). Solve times are clamped to between 1 and
6 times the target and weighted linearly by position. The result is
`sum(difficulties) * target * (n + 1) / (2 * sum(weighted solve times))` in exact
integers, saturating at the `uint64` maximum. The function name is historical.
Equivalence to a published LWMA-3 is not established.

## Fork choice

A candidate suffix replaces the current chain only if its common ancestor is at
most 1024 blocks back, every block validates against an isolated copy of the
state, and its summed work is strictly greater. Work per block is
`floor(2^256 / (target + 1))`.

## Wire formats

Wire protocol version 6. Gossip and streams carry a compact binary format
(`v2/p2p/wire.go`); every length and count is checked against a limit derived
from the consensus limits before anything is allocated. JSON was dropped. A
gossip message is limited to a block's wire size; sync requests cover at most 64
blocks. Stream protocol IDs are `/NosoX/hello/v6` and `/NosoX/sync/v6`. Gossip
topics are `NosoX/<network magic, 8 hex digits>/blocks/v6` and `.../txs/v6`. A
peer on an older wire version does not match these IDs and is not served.
