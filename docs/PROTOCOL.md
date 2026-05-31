# Wire protocol

The Go daemon speaks a **subset** of the Pascal Noso network protocol —
specifically, the commands that NosoDart (and through it NosoSova) sends.
Live-peer commands are out of scope (see [SCOPE.md](SCOPE.md)).

## Framing

* TCP, line-based, terminator `\n` (LF only).
* Default port: 8080.
* Max line length: 8 KiB (enforced; over-long lines close the connection).
* Idle timeout: 60 s. Read/write timeout: 15 s.
* No TLS.

## Commands

### `NODESTATUS\n`

Returns one space-separated line of 18 fields. NosoDart's
`parseDataNode` (`utils/data_parser.dart:84-111`) reads:

| Index | Meaning                            |
| ----- | ---------------------------------- |
| 1     | connections (always 0 — archive)   |
| 2     | last block number                  |
| 3     | pending pool size                  |
| 4     | delta (0)                          |
| 5     | branch name ("archive")            |
| 6     | node version string                |
| 7     | UTC time, Unix seconds             |
| 10    | last block hash, first 5 chars     |
| 15    | headers hash, first 5 chars        |
| 17    | summary hash, first 5 chars        |

Other indices are kept to maintain field positions but filled with
placeholders.

### `NSLMNS\n`

Replies with a space-separated seed list:
`seed1 ip;port:address ip;port:address …`

Parsed by NosoDart's `parseDataSeeds`. Element 0 is a label that the Dart
parser skips. The Go daemon emits seeds from `nosocfg.psk` with a `:null`
suffix in place of the per-seed address.

### `NSLPENDFULL\n`

One space-separated line, where each item is CSV:

```
orderId,0,orderType,sender,receiver,amount,fee,0
```

Maps to NosoDart's `Pending` model.

### `GETZIPSUMARY\n`

Replies with a freshly-built ZIP of `sumary.psk` (deflate, contains a
single entry named `sumary.psk`). NosoDart locates the inner ZIP via a
`PK\x03\x04` magic scan and unzips from there, so the daemon does not
need to prefix any bytes.

### `NSLCFG\n`

Replies with the raw `nosocfg.psk` content on a single line.

### `NSLGVT\n`

Replies with 20 zero bytes (the Pascal-side ZIP-header artifact NosoDart
strips) followed by the raw `gvts.psk` file (100 × 105 bytes).

### `NSLBALANCE <hash>\n`

Replies with a single integer line — the address's confirmed balance in
base units (8 decimals). `0` if the address is unknown.

### `NSLORDER …\n` and `NSLCUSTOM …\n`

Accepts a transaction order from NosoDart. The accepted line layout
(stripped of the leading command word):

```
<proto> <appVersion> <utcTime> ORDER <trxLine> $ <orderType>
  <orderID> <orderLines> <orderType> <timeStamp> <message>
  <trxLine> <sender> <address> <receiver> <amountFee> <amountTrf>
  <signature> <trfrID> $
```

`<orderType>` appears twice (a section marker followed by the order body)
because that's what NosoDart emits.

Reply: `OK <orderID>` on success, `DUPLICATE` if the TrfrID is already
in the pool, or `ERROR <reason>` on parse/signature failure.

## Unknown commands

The server replies `ERROR unknown command <name>\n` and leaves the
connection open for the next request.
