# Known weaknesses in the original Noso codebase

These were surfaced during the reverse-engineering pass that fed the Go
port. They are documented here rather than silently "fixed" in the port,
because most of them require either a hard fork or a wire-format change.

Group by severity, then by whether the Go port preserves them or not.

## Preserved (compat-blocking if changed)

### MD5 in the consensus fingerprint

Source: `nosoconsensus.pas:215-221`.

```
ConHash = MD5(LastBlock || Headers[:5] || MNsHash[:5] || LBHash[:5]
            || Summary[:5] || GVTs[:5] || NosoCFG[:5])
```

MD5 is cryptographically broken. Combined with the use of only the first
5 chars of each component hash (`58⁵ ≈ 6.6e8` buckets), the fingerprint
is theoretically attackable. In practice the live network is dead, so
this is academic now.

**Why not fix?** Changing the hash changes every node's `NODESTATUS`
reply, breaking the few clients that depend on hash equality. Would
require coordinated upgrade.

### SHA-1 in ECDSA

Source: `mpsignerutils.pas:54`.

```
Signing algorithm: SHA-1withECDSA on secp256k1
```

SHA-1 is collision-vulnerable; ECDSA over SHA-1 is dated. Every existing
signature on the chain was produced this way, so swapping the hash
invalidates all existing wallets.

**Why not fix?** Would invalidate every wallet.pkw on the planet.

### Base58 checksum is sum-of-indices

Source: `nosocrypto.pas:679-689`.

```
total = Σ index_in_b58_alphabet(c) for c in body
```

Detects single-character typos and most random corruption, but is not
cryptographically binding. Bitcoin's Base58Check uses a double-SHA256
checksum for a reason.

**Why not fix?** Address scheme is baked into every wallet. Change
breaks them all.

### Hash-over-Base64-string of pubkey

Source: `nosocrypto.pas:245-258`, mirrored in `noso_core.dart:79-88`.

Address derivation hashes the UTF-8 bytes of the Base64-encoded public
key, not the raw EC point. This is unusual and produces a different
address than the standard pubkey → SHA256 → RIPEMD160 → Base58Check
pipeline. The Go port preserves the quirk; switching would break every
address.

### XOR-with-SHA256("noso") for certificates

Source: `nosocrypto.pas:362`.

`UPPERCASE(XorEncode(SHA256("noso"), payload))` produces a trivially
reversible "encryption" of ownership certificates. Useful for
obfuscation only; relied on for nothing security-critical.

**Why not fix?** Certificates are accepted by other Noso software with
this exact encoding.

## Fixed in this port (no compat impact)

### No atomic writes

Pascal uses `Reset/Seek/Write/Closefile`. A crash mid-write corrupts the
file. The wallet has a `.bak` copy on the side, but summary and
block files do not.

`noso-go` writes everything via `write → tmp → fsync → rename`, with
`fsync` on the parent directory. The resulting file bytes are identical
to what the Pascal node would produce. A `.bak` copy is still made for
`wallet.pkw` to preserve compat with the Pascal mode of recovery.

### Unbounded ReadLn buffer

Source: `nosonetwork.pas:1144`.

```
CanalCliente[Slot].IOHandler.MaxLineLength := MaxInt;
```

A single peer can OOM the node by sending one very long line.
`noso-go` caps a line at 8 KiB.

### Unauthenticated RPC

Source: `mprpc.pas`.

`RPCPass` exists but is never checked. `noso-go` doesn't ship the legacy
HTTP RPC, but if/when it lands it will gate on a token (off by default
for parity, but easy to turn on).

### No fsync on directory

Per-file `Sync()` is not enough on Linux to make a rename durable;
parent directory needs an fsync too. `noso-go` does this; Pascal does
not.

### Sloppy version comparison

Source: `mpparser.pas:1070`.

```pascal
if (Tversion = MainnetVersion + NodeRelease) and (not overRule)
```

String equality on dotted versions: `"0.5.10" < "0.5.2"` ASCII-wise.
The Go port reports version as a fixed string and does not gate
features on a version comparison.

## Catalogued but not addressed

### Integer-32 timestamps in some block fields

`BlockHeaderData.TimeTotal`, `TimeLast20`, `NxtBlkDiff` are 32-bit ints
in Pascal. Unix timestamps overflow Int32 in 2038. The Go structs are
typed `int32` for byte-compat, so the same overflow looms there. Not a
problem for the archived chain; would be a problem for a revived one.

### MD5File returns the empty-string digest on read error

Source: `nosocrypto.pas:195-202`. Silent failure mode. The Go port
treats file read errors as errors; it doesn't try to mirror this.

### No transaction ordering guarantee inside a block

Source: `mpblock.pas:170-231`. Orders are included in pending-pool order.
Allows MEV-style ordering attacks during live mining; moot for the
archive use case.

### Hardcoded `AdminPubKey` for ADMINMSG

Source: `mpprotocol.pas:975`. Single point of failure for admin
control. Live-network problem; archive doesn't accept ADMINMSG.

## Backlog

If a community ever revives Noso, the right shopping list for a v2 is:

- SHA-256 (or Blake3) consensus hash, full digest, not prefix-5.
- Ed25519 signatures.
- Bitcoin-style Base58Check with proper checksum.
- Length-prefixed binary wire protocol replacing the line-based one.
- mTLS or noise-protocol peering.
- Bounded RPC auth tokens with rotation.
- Slot leadership instead of MD5 voting.

That's all out of scope for this port.
