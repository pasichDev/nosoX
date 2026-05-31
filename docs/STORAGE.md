# Storage formats

Every Noso file is one of two shapes:

1. **Packed binary records** — back-to-back, no file header, no padding
   between fields, no padding between records. Pascal `String[N]` fields
   on disk are `length_byte || N capacity bytes of ASCII`, zero-padded
   after the actual content. Integers are little-endian.

2. **Plain text** — space-separated tokens on a single line, or
   key/value pairs one per line.

The `internal/codec` and `internal/types` packages handle (1); ad-hoc
parsers in `internal/storage` handle (2).

## Binary records

| File              | Record         | Size | Source                                  |
| ----------------- | -------------- | ---- | --------------------------------------- |
| `wallet.pkw`      | `WalletData`   | 626  | `nosowallcon.pas:18-27`                 |
| `sumary.psk`      | `SummaryRecord`| 106  | `nosounit.pas:18-24`                    |
| `blchhead.nos`    | `ResumenData`  | 70   | `nosoheaders.pas:18-22`                 |
| `BLOCKS/{N}.blk`  | header + N×Order | 368 + N×562 | `nosoblock.pas` / `nosogeneral.pas` |
| `gvts.psk`        | `TGVT`         | 105  | `nosogvts.pas:11-16`                    |

Sizes are derived from field arithmetic; the Go test suite asserts them
and exercises round-trips against the real `sumary_59238.psk` and
`gvts.psk` shipped in the original NosoNode-main repo.

## Block file layout

```
[ BlockHeaderData ]   368 bytes
[ TOrderData × TrxTotales ]
[ trailing bytes ]     optional — PoS section and MN section for
                       blocks ≥ 8425 and ≥ 48010
```

The trailing PoS/MN sections are preserved as opaque `Trail` bytes by
the Go reader, since their exact layout was not in the analysis spec.
Round-tripping a block (read → write) preserves the bytes exactly.

## Text formats

### `nosocfg.psk`

Single-line, space-separated sections:

```
NORMAL <seeds> <ntp_servers> <deprecated> <deprecated> <frozen_addrs>
```

Items inside a section are colon-separated. `null:` is a placeholder
for "empty". Example:

```
NORMAL 1.2.3.4;8080:5.6.7.8;8080: pool.ntp.org:time.google.com: null: null: addr1:addr2:
```

### `seednodes.txt` / `defseeds.nos`

```
DefNodes 1.1.1.1 2.2.2.2 3.3.3.3 … 10.10.10.10
```

Leading `DefNodes` is a label; rest are IPs (default port 8080).

### `masternodes.txt`

Pascal writes this as `<block> <ip>;<port>:<fund_addr>:<age> …` per
line. The Go port reads it as opaque text; archive usage doesn't need
the parsed form.

### `advopt.txt`

Key/value lines, one per option:

```
HideEmpty true
MultiSend true
Language en
RPCPort 8078
```

The Go daemon doesn't honor these yet; CLI flags supersede them.

## Pascal ShortString gotchas

Pascal does not zero-pad the unused capacity bytes of a ShortString when
writing — the bytes retain whatever was there before (often previous
record data). Round-trip tests must compare on the **logical content**
of each ShortString, not the raw bytes after the content, or accept
mismatches in the padding region. `internal/types/fixtures_test.go`
illustrates the pattern.

## Atomic writes

The Go port writes every file via `write → tmp → fsync → rename` and
also fsyncs the parent directory. The file content is byte-identical to
what Pascal would produce, so a Pascal node can read what Go writes.
