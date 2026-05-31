# Noso Cryptography Spec (Pascal → Go reference)

Source-of-truth reverse engineering of `nosocrypto.pas`, `mpsignerutils.pas`, and
the Dart equivalents in `NosoDart-main/lib/crypto/`. This document is the spec
the Go `internal/crypto` package must implement byte-exact.

## 1. Curve & signing

- **Curve:** secp256k1 (Bitcoin curve, not P-256). `mpsignerutils.pas:44`,
  `noso_core.dart:59`.
- **Signing algorithm:** `SHA-1withECDSA`. The message digest fed into ECDSA is
  SHA-1, not SHA-256. `mpsignerutils.pas:54`, `noso_signer.dart:37-40`.
- **Signature wire format:** ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`, then
  Base64-encoded. `noso_signer.dart:74-80`.
- **Private key wire format:** Base64 of the 32-byte big-endian unsigned scalar
  → 44 chars. `mpsignerutils.pas:176-177`.
- **Public key wire format:** Base64 of the uncompressed EC point
  (`0x04 || X || Y`, 65 bytes total) → 88 chars. `mpsignerutils.pas:175`,
  `noso_core.dart:73`. `KeyPair.isValid()` checks `pub==88 && priv==44`
  (`keys_pair.dart:25-27`).

## 2. Hashing (all over UTF-8 strings, not bytes)

Critical: most Noso "hash X" calls accept the *string* (Base64-encoded or hex)
and feed its UTF-8 byte representation into the hash. **Do not pre-decode.**

```pascal
// nosocrypto.pas:177
function HashSha256String(s: string): string;
begin Result := THashFactory.TCrypto.CreateSHA2_256()
  .ComputeString(s, TEncoding.UTF8).ToString(); end;
```

Functions used downstream:
- `HashSha256String(s)` → hex string (uppercase 64 chars).
- `HashMD160String(s)` → hex string (uppercase 40 chars), `nosocrypto.pas:182`.
- `HashMD5String(s)` → uppercase hex 32 chars.
- `HashMD5File(path)` → uppercase hex; returns MD5 of empty string on error
  (bug: silently shares the same default with all missing files).

## 3. Address derivation

```
addr = "N" + B16toB58( RIPEMD160( SHA256( pubkey_base64_string ) ) )
           + B58( sum(b58_alphabet_index(c)) for c in that B58 string )
```

Implemented in `GetAddressFromPublicKey` (`nosocrypto.pas:245-258`) and
`getAddressFromPublicKey` (`noso_core.dart:79-88`).

Validation (`IsValidHashAddress`, `nosocrypto.pas:327-342`):
1. First char ∈ {`N`, `M`} (`M` = multisig type 1, type 0 = `N`).
2. `len(addr) > 20`.
3. Strip last 3 chars → body. `IsValid58(body)`.
4. Recompute checksum: `B10toB58( BMB58resumen(body) )` and compare.

## 4. Base58 / Base36 alphabets

```
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B36 = "0123456789abcdefghijklmnopqrstuvwxyz"  // lowercase only
HEX = "0123456789ABCDEF"                      // uppercase only
```

Source: `nosocrypto.pas:80-82`, `noso_core.dart` / `const.dart`.

`BMB58resumen` checksum (sum of 1-based positions minus 1 — equivalent to
sum of 0-based alphabet indexes, ignoring chars not in the alphabet):

```pascal
total := 0;
for c in s do total += Pos(c, B58Alphabet) - 1;
return IntToStr(total);
```

For Go: `idx := strings.IndexByte(B58, c); if idx >= 0 { total += idx }`.

## 5. Hashes used as IDs

| Purpose      | Encoding                                                                 | Source                |
| ------------ | ------------------------------------------------------------------------ | --------------------- |
| TransferID   | `"tR" + B58(SHA256(msg)) + B58(checksum)`                                | `nosocrypto.pas:345`  |
| OrderID      | `"OR" + B36(SHA256(msg))`                                                | `nosocrypto.pas:355`  |
| Certificate  | XOR(`SHA256("noso")`, payload) → uppercase → B58 + checksum (see source) | `nosocrypto.pas:362`  |

The transfer/order text that gets SHA256'd is described in
[02-blocks.md](./02-blocks.md) and [06-dart-reference.md](./06-dart-reference.md).

## 6. Key generation

```pascal
GenerateECKeyPair(SECP256K1) →
  privKey.D.ToByteArrayUnsigned  // raw scalar bytes
  pubKey.Q.GetEncoded(false)     // uncompressed point 0x04|X|Y
→ Base64-encode both
```

Caller signs an "OWN" certificate when importing/owning an address —
see `GetCertificate` at `nosocrypto.pas:362`.

## 7. Migration footguns (preserve these quirks)

These are weird-but-required:

1. **Hash inputs are strings, not bytes.** SHA256 is called on the *Base64
   ASCII text* of the pubkey. A naive Go port that decodes Base64 first will
   produce a different address.
2. **RIPEMD160 input is the *uppercase hex* of the SHA256 result**, not the
   raw 32-byte digest. The Pascal `HashSha256String` returns a hex string;
   the next `HashMD160String` call hashes that hex string. Same applies.
3. **Address checksum uses B58 alphabet index sum,** not a hash. Weak by
   modern standards but required for compat.
4. **DER signatures may have leading zeros on `r`/`s`** to keep them positive
   (per ASN.1 INTEGER spec). Go's `encoding/asn1` handles this correctly via
   `big.Int`; just use `asn1.Marshal(struct{R,S *big.Int}{...})`.
5. **SHA-1 in ECDSA is intentional.** Don't substitute SHA-256. `mpsignerutils.pas:54`.
6. **Public key on disk is uncompressed (65 bytes)**, not compressed (33 bytes).

## 8. Known weaknesses (documented for BUGS.md, do not "fix" in port)

- **SHA-1 in ECDSA** — outdated; replacement breaks compat.
- **MD5 used in consensus** — collision-vulnerable but baked into the
  consensus fingerprint; replacement breaks compat.
- **XOR-with-SHA256("noso") "encryption" for certificates** — trivially
  reversible; useful for obfuscation only.
- **Checksum is a sum of indexes**, not a hash — catches typos but not
  malicious manipulation.
- **`HashMD5File` returns MD5 of empty string on read error** — silent
  failure mode.
