# Cryptography

!!! warning "Unreviewed"
    The Schnorr signature and the range proof are custom constructions. They
    have not been independently reviewed. Secret-dependent operations are not
    constant time. See [Security](security.md).

All curve operations use secp256k1.

## Commitments

A commitment to value `v` with blinding factor `r` is `C = v*H + r*G`,
serialized as a 33-byte compressed point. `G` is the standard generator. `H`
is derived by taking `SHA-256("NosoX/pedersen-h/v5\0")`, treating it as an x
coordinate and incrementing until it lies on the curve, with even y. The
assumption that nobody knows the discrete log of `H` relative to `G` is
unreviewed. The all-zero encoding is the identity and is rejected as a public
point everywhere.

## Schnorr signature

A signature is 65 bytes: `R` (33 bytes) then `s` (32 bytes).

- `R = k*G` with a random nonce `k` from the operating system.
- `e = SHA-256("NosoX/schnorr/v5\0" || R || P || len(msg) as 4 bytes || msg) mod n`.
- `s = k + e*x mod n`.
- Verification checks `s*G == R + e*P`, rejects the identity, non-canonical
  points and out-of-range `s`.

It is not compatible with BIP340. The function `SchnorrSignConstantTime` is
named for history only. It computes public keys with a non-constant-time
routine.

Kernel signatures sign `SHA-256("NosoX/kernel-sig/v5\0" || BE32(network_magic) || kernel ID)`
(`types.KernelSigningMessage`) under the excess point, so a signature is valid on one network only. The coinbase kernel
signs `SHA-256("NosoX/coinbase-kernel/v5\0" || BE32(network_magic) || BE64(height) || BE64(amount) || commitment)`
under `commitment - reward*H`, using the output's blinding factor as the secret
key. The network magic and height make the signature valid on one network at
one height only.

## Range proof

Each plain output carries a proof that its value lies in `[0, 2^64)`.

- The value is split into 64 bits. Each bit gets its own commitment
  `C_i = b_i*H + r_i*G`, with blindings chosen so that `sum(2^i * C_i)` equals
  the output commitment.
- Each bit has a Fiat-Shamir OR proof that `C_i` opens to 0 or to 1. The challenge
  uses the domain `NosoX/borromean/v5\0`.
- Encoding: one version byte (`2`), then 64 times (33-byte bit commitment plus
  a 194-byte OR proof). Total 14,529 bytes per output.

This is roughly 20 times larger than a Bulletproof. It is a design choice for
simplicity, and also a limit on throughput (see [Limits](limits.md)).

## Other primitives

| Use | Primitive |
|---|---|
| Proof of work | Argon2id, 64 MiB, 1 pass, 1 lane |
| Block, kernel, output and transaction IDs | SHA-256 with the domains in [Protocol](protocol.md) |
| Wallet identity (binds the output state file to the wallet; signs nothing) | Ed25519 key. Slates carry no signatures: payments are authorized by the Schnorr kernel signature |
| Wallet file encryption | Argon2id (64 MiB, 1 pass, 1 lane) deriving an XChaCha20-Poly1305 key |
| Checkpoint list hash | SHA-256 with prefix `NosoX/checkpoints/v5\0`; the daemon verifies the baked signature at startup and refuses to start if it does not verify |

## Domain separators

Every hash domain is `NosoX/<name>/v5` followed by a NUL byte, as a plain
prefix of the hashed input. The proof-of-work salt, the libp2p stream IDs and
the gossip topics use the same name family. Changing any of them changes
consensus or wire compatibility.

| Domain | Used for |
|---|---|
| `NosoX/schnorr/v5\0` | Schnorr challenge |
| `NosoX/borromean/v5\0` | Range-proof OR challenge |
| `NosoX/pedersen-h/v5\0` | Derivation of the generator `H` |
| `NosoX/coinbase-kernel/v5\0` | Coinbase kernel signature digest |
| `NosoX/kernel-sig/v5\0` | Plain kernel signature digest (network magic and kernel ID) |
| `NosoX/kernel/v5\0`, `NosoX/output/v5\0`, `NosoX/transaction/v5\0`, `NosoX/block/outputs/v5\0`, `NosoX/block/inputs-kernels/v5\0` | IDs and roots, see [Protocol](protocol.md) |
| `NosoX/checkpoints/v5\0` | Checkpoint list hash |
| `NosoX/pow-salt/v5\0` | Argon2id salt of the proof of work |

Ed25519 wallet identities are separate from output spending scalars. An
Ed25519 key does not control any output.

## Test vectors

`v2/crypto/reference_test.go` checks a Pedersen commitment, the generator `H`
and a Schnorr signature against constants computed by
[`audit/reference_vectors.py`](https://github.com/pasichDev/nosoX/blob/main/audit/reference_vectors.py),
which uses plain affine integer arithmetic. These are consistency checks, not
proofs of security.
