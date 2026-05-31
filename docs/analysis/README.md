# Analysis Reports — Spec for the Go Port

These six documents are the byte-exact specification used to drive the Go
reimplementation. They were produced by deep, parallel reverse-engineering
of the Pascal NosoNode and NosoLite codebases plus the Dart NosoDart client
library written by the project owner.

The Go code under `internal/` MUST be consistent with these documents. If
the code disagrees with a doc, fix the doc (it's the spec) or fix the code
(it's a bug) — and write a test that pins the agreed behavior.

| #  | Doc                                          | Covers                                                                  |
| -- | -------------------------------------------- | ----------------------------------------------------------------------- |
| 01 | [Cryptography](01-crypto.md)                 | secp256k1, SHA-1+ECDSA, address derivation, Base58/36/64, signing IDs   |
| 02 | [Blocks & consensus](02-blocks.md)           | BlockHeader, TOrderData, validation, rewards, halving, consensus hash   |
| 03 | [Network protocol](03-network.md)            | TCP framing, PSK header, every wire command, peer discovery             |
| 04 | [Storage / disk](04-storage.md)              | Directory tree, all packed-record file formats, atomic-write strategy   |
| 05 | [RPC + console parser](05-rpc-parser.md)     | JSON-RPC 2.0 methods, CLI commands, economic constants                  |
| 06 | [NosoDart client reference](06-dart-reference.md) | Authoritative client commands the Flutter wallet sends today        |

When in conflict:
- For node-side behavior (consensus, storage) → Pascal node wins.
- For client-facing wire format → NosoDart wins (it's what the live wallet
  uses today).

## Cross-cutting rules

1. **Migration is byte-exact.** See `MIGRATION.md` (TBD).
2. **Pascal bugs are documented, not silently fixed.** See `BUGS.md` (TBD).
3. **Improvements that don't change bytes on the wire/disk are encouraged**:
   atomic file writes, bounded buffers, explicit timeouts, context-cancellable
   goroutines, structured logging, opt-in RPC auth, per-IP rate limiting.

## Open questions / pending verification

These need to be confirmed against real sample data in `NosoNode-main/`:

- Exact size of `TOrderData` record (estimates between 562 B and 630 B).
- Layout of PoS and MN sections appended after transactions in a `.blk`.
- The 20-byte header skip in `NSLGVT` reply that Dart performs.
- The `wallet.pkw` 625-stride-vs-626-record off-by-one in Dart.

These get verified during the cross-check pass (task #14).
