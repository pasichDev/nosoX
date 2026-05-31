# Architecture

`noso-go` is a single-process archive node + companion CLI. The whole
thing is six internal packages and two binaries. No external services, no
config server, no embedded database.

## Module map

```
cmd/nosocli  ─┐
              ├─> internal/storage  ──> internal/types  ──> internal/codec
cmd/nosod   ─┤                          │
              └─> internal/network     ─┤
                  └─> internal/blockchain ──> internal/crypto
```

* **`internal/codec`** — Pascal `ShortString[N]` encode/decode + LE int
  helpers. Owns one quirk: ShortString = length byte + capacity bytes of
  ASCII, zero-padded after the actual content. Everything above it works
  in Go strings/ints.

* **`internal/crypto`** — Base58 with the Noso alphabet, Base36, SHA256/
  RIPEMD160/MD5 over UTF-8 strings, secp256k1 + SHA-1 + ECDSA + DER-Base64
  signatures. Implements `AddressFromPublicKey` and `IsValidAddress` with
  the byte-exact quirks documented in [analysis/01-crypto.md].

* **`internal/types`** — pure-data structs for every on-disk record
  (`WalletData`, `SummaryRecord`, `BlockHeader`, `Order`, `ResumenData`,
  `GVT`) with `Marshal()` / `Unmarshal()` methods that produce byte
  layouts identical to Pascal's packed records. Sizes:
  626/106/368/562/70/105.

* **`internal/storage`** — file-backed stores. Atomic writes (write→tmp→
  fsync→rename). Hash-indexed `SummaryStore` for O(1) balance lookups.
  Append-only `HeadersStore`. Block reader. CFG and seednodes parsers.

* **`internal/blockchain`** — pure economic functions: `BlockReward`,
  `GetSupply`, `MinimumTransferFee`, `CustomizationFeeFor`, plus order
  construction (`NewTransferOrder`, `NewCustomOrder`) and signature
  verification (`VerifyOrder`). All Pascal constants live here.

* **`internal/network`** — line-based TCP server (port 8080 by default,
  bounded line length to prevent DoS) plus NosoDart-compatible
  `Service` that registers handlers for every command NosoSova sends.
  Includes a thread-safe `PendingPool`.

## Binaries

* **`cmd/nosod`** opens NOSODATA, builds a `network.Service`, starts the
  TCP listener, blocks on SIGINT/SIGTERM. Single process, no workers
  besides what the TCP server spawns per connection.

* **`cmd/nosocli`** is a multi-mode tool:
  * Offline (default): reads NOSODATA directly — no network needed.
  * Online (`-node host:port`): forwards relevant commands over TCP.

## Concurrency model

* Each TCP connection runs on one goroutine. Idle connections are
  reaped via `SetReadDeadline`. The accept loop and per-connection
  goroutines are tracked in a `sync.WaitGroup` for clean shutdown.
* `SummaryStore` and `HeadersStore` use `sync.RWMutex`. Reads are
  parallel; writes are serialized.
* `PendingPool` uses a `sync.Mutex` and re-sorts on every `Add`.
  The pool is small (≤ a few hundred entries in practice), so the
  sort is cheap.

## Improvements vs. the Pascal node (no compat impact)

* **Atomic file writes** — `write → tmp → fsync → rename` everywhere
  instead of Pascal's in-place `Reset/Seek/Write/Close`. Prevents
  partial-write corruption on crash.
* **Bounded line buffer** — 8 KiB cap instead of Pascal's `MaxInt`.
  Closes a DoS angle where a peer could exhaust RAM with one long line.
* **Explicit timeouts** — read/write/idle deadlines on every TCP
  connection. Pascal kept idle connections forever.
* **Context-cancellable shutdown** — `srv.Shutdown(ctx)` drains
  in-flight handlers; Pascal `Halt`'d the process.
* **Hash-indexed summary** — O(1) balance lookups; Pascal does a linear
  scan and caches a per-startup index in RAM.

None of these change the bytes a Pascal client sees on the wire or on
disk.

[analysis/01-crypto.md]: ./analysis/01-crypto.md
