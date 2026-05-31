# Migration guide

This project supports the **archived** Noso chain. The original Pascal
node (`NosoNode-main`) and lite wallet (`NosoLite-main`) still load and
write the same files; you can run either, or swap between them, against
the same `NOSODATA` folder.

## Migrating a NOSODATA folder

There is no migration. Point `nosod` at the existing folder:

```bash
./bin/nosod -data /path/to/NOSODATA -listen 0.0.0.0:8080
```

`nosod` reads `sumary.psk`, `blchhead.nos`, `BLOCKS/*.blk`, `gvts.psk`,
and `nosocfg.psk` in their native binary/text formats. It writes back in
the same formats so a Pascal node can be started later against the same
folder if needed.

Files that are touched on every run:
- `sumary.psk` — only if you set a balance via internal APIs (the
  archive use-case is read-only by default).
- Logs under `LOGS/` are not implemented; the daemon logs to stderr.

Files that are read-only in the archive workflow:
- `wallet.pkw` — read by `nosocli` when it needs to sign transactions.
  Use the Pascal node, NosoSova, or `nosocli newaddress` to create new
  wallets.
- `blchhead.nos`, `BLOCKS/*.blk`, `gvts.psk`, `nosocfg.psk` —
  read at startup; not modified.

## Migrating NosoSova (Flutter wallet)

NosoSova talks to a node via NosoDart's TCP commands. Point its node
list at `127.0.0.1;8080` (or wherever `nosod` is listening). The
following commands are implemented and tested:

| Command          | Status |
| ---------------- | ------ |
| `NODESTATUS`     | ✅      |
| `NSLMNS`         | ✅      |
| `NSLPENDFULL`    | ✅      |
| `GETZIPSUMARY`   | ✅      |
| `NSLCFG`         | ✅      |
| `NSLGVT`         | ✅      |
| `NSLBALANCE`     | ✅      |
| `NSLORDER`       | ✅ (signature verified, pending pool kept locally) |
| `NSLCUSTOM`      | ✅      |

Commands NOT implemented (live-network specific, deferred per `SCOPE.md`):

- `$PING`/`$PONG` field-by-field parity
- `$LASTBLOCK` zip-stream
- `$MNREPO`/`$MNCHECK`
- `GETHEADUPDATE`
- `ADMINMSG`

NosoSova does not send those; they are Pascal-node ↔ Pascal-node only.

## What about importing an old wallet.pkw?

`internal/storage.LoadWallet(path)` reads it as-is. The 626-byte record
layout, the ShortString format, and the 32-byte LE int64 balance are all
preserved. Signature verification on transactions you submit will pass
on a Pascal node too (we use the same SHA-1+ECDSA+DER pipeline).

## What if I migrate back to Pascal later?

You can. `noso-go` does not introduce any new files or formats — every
write reproduces the byte layout the Pascal node expects. The only
visible difference is that `noso-go`'s atomic writes are crash-safer
(the Pascal version overwrites in place).
