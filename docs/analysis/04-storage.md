# Noso Storage / Disk Layer Spec

## Directory tree (`NOSODATA/` rooted at CWD)

```
NOSODATA/
├── BLOCKS/{N}.blk
│   └── DB/blocks_db.nos             (TDBRecord, 16 B each)
├── LOGS/{console,eventlog,deepdeb,exceptlog,nodeftp,report}.txt
├── UPDATES/
├── SUMMARKS/
│   ├── {N}.bak                       (sumary snapshot every 1000 blocks)
│   ├── RPC/                          (auto-saved RPC-generated wallets)
│   └── GVTS/
├── wallet.pkw          + .bak
├── sumary.psk          + sumary.zip (for distribution)
├── blchhead.nos        + blchhead.zip
├── psos.dat
├── gvts.psk
├── masternodes.txt
├── nosocfg.psk         (text, space-separated)
└── advopt.txt          (text, key value)
```

## Packed-record sizes (Pascal `String[N]` = 1 length byte + N capacity bytes)

| File                        | Record                  | Size (B) |
| --------------------------- | ----------------------- | -------- |
| `wallet.pkw`                | WalletData              | 626      |
| `sumary.psk`                | TSummaryData            | 106      |
| `blchhead.nos`              | ResumenData             | 70       |
| `BLOCKS/{N}.blk` header     | BlockHeaderData         | 378      |
| `BLOCKS/{N}.blk` tx         | TOrderData              | 562 *    |
| `gvts.psk`                  | TGVT                    | 105      |
| `BLOCKS/DB/blocks_db.nos`   | TDBRecord (4×Int32)     | 16       |

\* Pending live verification against sample `.blk`; earlier estimates said 619/630.

## Pascal ShortString → Go encoding

```
[1 byte len][len ASCII chars][(N-len) zero bytes]   total = N+1 bytes
```

Read: `len = b[0]; s = string(b[1:1+len])`.
Write: `b[0] = byte(len(s)); copy(b[1:], s); zero rest of capacity`.

Little-endian everywhere (Pascal on x86).

## Atomic write rules (improvement, no compat impact)

Pascal uses `Reset / Seek / Write / Closefile` without any atomic guarantee.
Sole safety net is a `.bak` copy on the wallet file. Go port should use:

```
write -> tmp file -> fsync -> rename(tmp, target) -> fsync(parent dir)
```

This produces identical file *contents* and is invisible to other Noso
nodes. Wallet should keep the `.bak` copy too for users who run mixed
Pascal+Go binaries.

## Summary snapshot schedule

- `SumMarkInterval = 100` blocks: full snapshot under `SUMMARKS/{N}.bak`.
- Every block: in-place updates to `sumary.psk`. Hash index is rebuilt in
  RAM on start.

## ZIP distribution

`sumary.zip` and `blchhead.zip` are created on demand and served via
`$GETSUMARY` / `$GETRESUMEN`. Standard deflate. Block batches via
`$LASTBLOCK` are zipped on-the-fly in memory (100 blocks max).

## Migration constraints

Files that MUST stay byte-exact:
- `wallet.pkw`, `sumary.psk`, `blchhead.nos`, all `BLOCKS/{N}.blk`, `gvts.psk`, `psos.dat`.

Files that MAY differ (text formats, we only need to parse them and stay
within the existing schema):
- `nosocfg.psk`, `masternodes.txt`, `advopt.txt`, all `LOGS/*.txt`.
