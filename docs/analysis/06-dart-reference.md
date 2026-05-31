# NosoDart Client Reference (authoritative for protocol shape)

NosoDart is the lib the user (project owner) wrote for NosoSova. It's the
cleanest, most up-to-date reference for what bytes go on the wire. If Pascal
disagrees with Dart, Dart wins for client-facing behavior (Pascal is what
existing nodes do, so it wins for node-side decisions).

## Client commands (`node_request.dart`)

All requests end with `\n`.

| Command                | Wire string              |
| ---------------------- | ------------------------ |
| Node status            | `NODESTATUS\n`           |
| Active seed list       | `NSLMNS\n`               |
| Pending pool dump      | `NSLPENDFULL\n`          |
| Zipped summary         | `GETZIPSUMARY\n`         |
| Network config         | `NSLCFG\n`               |
| GVT list (binary)      | `NSLGVT\n`               |
| Balance for one addr   | `NSLBALANCE <hash>\n`    |
| Submit transfer order  | begins `NSLORDER ...`    |
| Submit custom (alias)  | begins `NSLCUSTOM ...`   |

Note the Dart command names (`NSLMNS`, `NSLPENDFULL`, `NSLBALANCE`, `NSLORDER`,
`NSLCUSTOM`, `NSLCFG`, `NSLGVT`, `GETZIPSUMARY`) overlap but are not identical to
the Pascal codes in `mpprotocol.pas`. The Go server must accept BOTH variants.

## Response parsing (`utils/data_parser.dart`)

- `NODESTATUS` reply: space-separated; field map is in
  [03-network.md](./03-network.md) §3. Dart picks fields 1,2,3,4,5,6,7,10,15,17.
- `NSLMNS` reply: `"seed1 ip;port:address ip;port:address ..."`. Skip element 0.
- `NSLPENDFULL`: space-separated CSV lines:
  `orderId,?,orderType,sender,receiver,amount,fee,?`.
- `GETZIPSUMARY`: skip header until ZIP magic `50 4B 03 04`, deflate,
  parse 106-byte `TSummaryData` records.
- `NSLGVT`: skip first 20 bytes, then 105-byte records (note Dart uses
  custom offsets `[0:2]`, `[3:33]`, `[34:100]` — verify against Pascal
  `TGVT` field layout before committing).

## Order construction (Dart)

For TRFR:

```
sign_input = currentTime + senderHash + receiverHash
           + amount + commission + trxLine
trfrID = "tr" + B58(SHA256(currentTime + senderHash + receiverHash
                          + amount + currentBlock)) + B58(checksum)
orderID = "OR" + B36(SHA256("1" + currentTime + trfrID))
wireLine = headRequest + orderType + " " + orderID + " " + orderLines
         + " " + orderType + " " + currentTime + " " + message + " "
         + trxLine + " " + senderPubKey + " " + senderHash + " "
         + receiverHash + " " + amountFee + " " + amountTrf + " "
         + signatureBase64 + " " + trfrID + " $"
send = wireLine[:-2] + "\n"
```

For CUSTOM:

```
sign_input = "Customize this " + senderHash + " " + alias
commission = 25_000
trfrID = "tr" + B58(SHA256(currentTime + senderHash + receiverHash)) + B58(chk)
```

## Math (`utils/noso_math.dart`)

- `getFee(amount) = max(amount // 10_000, 1_000_000)`
- Fixed-point: every int64 amount is in base units = NOSO × 10⁸.
- `bigIntToDouble(fromPsk = 8 bytes little-endian)` reads the int64 balance.

## Wallet file (`handlers/files_handler.dart`)

NOTE: Dart uses a **625-byte stride incremented by 626** when iterating a
wallet file. The Pascal `wallet.pkw` record is 626 bytes total. The Dart
parser appears to off-by-one some balance bytes; the Go port should
implement against the Pascal record (`nosowallcon.pas:18-27`) and validate
that NosoDart can still read what we write. If a mismatch is found, file an
issue against NosoDart — do not mirror the bug in Go.

## Constants

| Constant         | Value                                                                  |
| ---------------- | ---------------------------------------------------------------------- |
| `coinChar`       | `N`                                                                    |
| `coinName`       | `NOSO`                                                                 |
| `customizationFee` | 25_000                                                               |
| `comissiontrfr`  | 10_000                                                                 |
| `minimumFee`     | 1_000_000                                                              |
| `b58Alphabet`    | `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`            |
| `b36Alphabet`    | `0123456789abcdefghijklmnopqrstuvwxyz`                                 |
| `b64Alphabet`    | standard RFC 4648                                                      |
| MN stake req.    | 10_500 NOSO (= 1_050_000_000_000 base units)                           |
| Block time       | 600 s                                                                  |
