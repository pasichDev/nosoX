# Noso Block / Order / Consensus Spec

## 1. BlockHeaderData (`nosoblock.pas:25-40`)

```
Number         Int64       (8)
TimeStart      Int64       (8)
TimeEnd        Int64       (8)
TimeTotal      Int32       (4)
TimeLast20     Int32       (4)
TrxTotales     Int32       (4)
Difficult      Int32       (4)
TargetHash     String[32]  (33)  // length-prefix + ASCII, zero-pad
Solution       String[200] (201)
LastBlockHash  String[32]  (33)
NxtBlkDiff     Int32       (4)
AccountMiner   String[40]  (41)
MinerFee       Int64       (8)
Reward         Int64       (8)
                          ----
                          378 B
```

(The original analyst noted 370 B — recount gives **378 B** when ShortStrings
are length-prefix + capacity bytes. Implement first, then validate against a
real `.blk` from `NosoNode-main/`.)

Genesis (block 0) special: `Solution` empty, `LastBlockHash = "NOSO GENESYS BLOCK"`,
`TimeStart = 1531896783`, `Difficult = InitialBlockDiff = 60`.

## 2. TOrderData (`nosogeneral.pas:26-41`)

```
Block       Int32       (4)
OrderID     String[64]  (65)
OrderLines  Int32       (4)
OrderType   String[6]   (7)   // 'TRFR' | 'CUSTOM' | 'SNDGVT' | 'PROJCT'
TimeStamp   Int64       (8)
Reference   String[64]  (65)
TrxLine     Int32       (4)
Sender      String[120] (121)
Address     String[40]  (41)
Receiver    String[40]  (41)
AmmountFee  Int64       (8)
AmmountTrf  Int64       (8)
Signature   String[120] (121)
TrfrID      String[64]  (65)
                       -----
                       562 B  // verify against sample, prior estimate said 619/630
```

## 3. Block file layout (`NOSODATA/BLOCKS/{N}.blk`)

```
[ BlockHeaderData ]
[ TOrderData × TrxTotales ]
[ PoS data ]            (only for blocks ≥ PoSBlockStart=8425)
[ MN data  ]            (only for blocks ≥ MNBlockStart=48010)
```

PoS and MN data formats: TBD from `mpblock.pas`. Port read first; write later.

## 4. Block validation rules (`mpblock.pas:136-231`)

- `TimeStart` ≥ previous `TimeEnd + 1`.
- `TimeStart` ≤ current UTC + 5 s tolerance.
- Per transaction:
  - `OrderTime ≥ LastBlockData.TimeStart && OrderTime + 600 ≤ BlockTime`.
  - Not already in last block (`TrxExistsInLastBlock(TrfrID)`).
  - `GetAddressBalanceIndexed(Address) - PendingPays(Address) ≥ Fee + Amount`.
  - For TRFR, signature valid.
- Max 2000 transactions per block.

`ValidateTrfr` return codes (`mpprotocol.pas:779-800`):
0=valid, 1=insufficient balance, 2=already pending, 3=too old, 4=too new,
5=in last block, 6=bad signature, 7+=bad amount.

## 5. Reward distribution (`mpblock.pas:260-352`)

```
total = BlockReward + MinerFee
share into:
  PoSReward  (blocks 8424..88399, percent from GetPoSPercentage)
  MNsReward  (blocks 48010+,      percent from GetMNsPercentage)
  DevReward  (blocks 88400+,      10%, to AdminHash 'NpryectdevepmentfundsGE')
  PoWReward  = total - PoS - MN - Dev → to BlockHeader.AccountMiner
```

## 6. Halving (`mpblock.pas:489-500`)

```
reward(0)  = PremineAmount = 1_030_390_730_000
reward(n>0, n < BlockHalvingInterval*(HalvingSteps+1)) =
  InitialReward / 2^(n div BlockHalvingInterval)
reward(n)  = 0     otherwise
InitialReward = 5_000_000_000
BlockHalvingInterval = 210_000
HalvingSteps = 10
```

## 7. TSummaryData (`nosounit.pas:18-24`)

```
Hash    String[40]  (41)
Custom  String[40]  (41)
Balance Int64       (8)
Score   Int64       (8)
LastOP  Int64       (8)
                  ----
                  106 B
```

Stored in `NOSODATA/sumary.psk`, indexed in memory by `MD5(hash) → B58 → mod N`.
The genesis record is `N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd` with balance 1_030_390_730_000
at block 0.

## 8. ResumenData (`nosoheaders.pas:18-22`)

```
block      Int32       (4)
blockhash  String[32]  (33)   // MD5(file contents) of {N}.blk
SumHash    String[32]  (33)   // MD5(file contents) of sumary.psk at that height
                            ----
                            70 B
```

Stored in `NOSODATA/blchhead.nos`, append-only, one record per finalized block.

## 9. Consensus fingerprint (`nosoconsensus.pas:215-221`)

```
ConHash = MD5(
    LastBlock
  + Headers[:5]    + MNsHash[:5]
  + LBHash[:5]     + Summary[:5]
  + GVTs[:5]       + NosoCFG[:5]
)
```

Network: query peers with `NODESTATUS`; tally hash votes; majority wins.
Reorg via `UndoneLastBlock()` up to `SecurityBlocks=100` deep.

## 10. Known issues to document, not fix

- MD5 collision vulnerability is baked into the consensus hash → keep.
- The fingerprint uses **only the first 5 chars** of several component hashes,
  giving 58⁵ ≈ 6.6e8 buckets per slot — collisions possible but extremely rare.
- `Difficult = 0` for all blocks in 1..52_999 — no PoW work required for those,
  intentional during the PoS rollout.
- Several integer fields are still 32-bit on 64-bit timestamps → 2038 risk
  (preserved for compat; flag in BUGS.md).
