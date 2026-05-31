# Cryptography

The `internal/crypto` package implements Noso's primitives byte-for-byte
compatible with Pascal `nosocrypto.pas`, `mpsignerutils.pas`, and the Dart
mirror in `NosoDart/lib/crypto/`. The full reverse-engineered spec is in
[analysis/01-crypto.md](analysis/01-crypto.md). This page is the
short user-facing summary.

## Curve and signing

* Curve: **secp256k1** (the Bitcoin curve).
* Signing algorithm: **SHA-1 + ECDSA**. The digest fed into ECDSA is
  SHA-1 of the message bytes — *not* SHA-256.
* Signature wire format: ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`,
  Base64-encoded.

## Key encoding

* Private key on disk and wire: `Base64(32-byte big-endian unsigned scalar)`
  → exactly 44 characters.
* Public key on disk and wire: `Base64(uncompressed EC point, 0x04 || X || Y,
  65 bytes total)` → exactly 88 characters.
* `KeyPair.IsValid()` checks the lengths.

## Hashing

Important footgun: Noso hashes the **UTF-8 string representation** of its
input, not the raw decoded bytes. In particular:

```
sha256_hex = SHA256( utf8_bytes_of( pubkey_base64_string ) )      // hex, uppercase
md160_hex  = RIPEMD160( utf8_bytes_of( sha256_hex_string ) )      // hex, uppercase
```

A naive port that decodes Base64 first will produce *different* addresses.
The Go implementation keeps the quirk.

## Address derivation

```
sha   = SHA256String(pubkey_base64)                  // 64-char hex
md160 = RIPEMD160String(sha)                          // 40-char hex
body  = HexToB58(md160)                               // ~28 chars
chk   = DecToB58(B58Checksum(body))                   // 1–3 chars, usually 2
addr  = "N" + body + chk                              // "N" for regular, "M" for multisig
```

## Address validation

`IsValidAddress` is the structural check from `IsValidHashAddress`
(`nosocrypto.pas:327-342`). It strips the first char and the last 2 chars,
recomputes the checksum, and compares the rebuilt string to the input.

This works for ~99.99 % of derived addresses, since the typical checksum
is 2 chars long. The rare 1- or 3-char checksum case rejects on both the
Pascal node and the Go port (preserved bug).

## Order IDs

* **TransferID**: `"tR" + B58(SHA256(text)) + B58(checksum)`.
* **OrderID**:    `"OR" + B36(SHA256(text))` (note Base36, lowercase).

The canonical sign-input strings for TRFR and CUSTOM are in
[analysis/06-dart-reference.md](analysis/06-dart-reference.md) and
implemented in `internal/blockchain/orders.go`.

## What's *not* used

* MD5 is used for the consensus fingerprint (see BUGS.md), but never as
  part of address derivation or signatures.
* No HMAC, no Argon2, no PBKDF2 — the wallet file is plain binary;
  encrypting it is the user's responsibility.
