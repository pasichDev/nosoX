# External cryptographic review packet

Status: **not started.** No reviewer has been contacted or commissioned. This
document scopes the work. It is not an assessment and not an approval.

The reviewed revision must be a specific commit named by the maintainer when a
review is commissioned. Dependencies relevant to the cryptography are pinned in
`go.mod`: `github.com/btcsuite/btcd/btcec/v2`,
`github.com/decred/dcrd/dcrec/secp256k1/v4` and `golang.org/x/crypto`.

## Scope

1. **Primitives** in `v2/crypto/`: `pedersen.go`, `schnorr.go`, `schnorr_ct.go`,
   `ops.go`, `rangeproof.go`, `borromean.go`, `borromean_ct.go`.
   - Derivation of the second generator `H` and the assumption that its
     discrete log relative to `G` is unknown.
   - Identity rejection, canonical scalar and point parsing, commitment algebra.
   - The exact Schnorr challenge transcript, nonce handling, domain separation,
     and signature malleability. The signature is not BIP340 compatible and
     must not be assumed to be.
2. **The range proof.** It is a custom bit-decomposition proof: 64 per-bit
   Pedersen commitments, each with a Fiat-Shamir OR proof. Review questions:
   correspondence to a published construction, transcript binding, soundness
   and zero-knowledge, bit commitments, boundary values, composition across
   multiple proofs, and the permitted amount range. Shape and round-trip tests
   are not sufficient. Decide whether to keep the construction or replace it
   with an established, reviewed one.
3. **Secret-dependent paths.** Signing, proving, key and blinding generation,
   and the wallet. The Schnorr signing function is named `SchnorrSignConstantTime`
   for historical reasons. It is not constant time: the Decred
   `PrivateKey.PubKey` call it relies on uses a non-constant-time base
   multiplication. Finding NX-019 stays open until a reviewed implementation
   exists.
4. **Domains and transcripts** across the protocol: header, body roots, output,
   kernel and transaction IDs, the coinbase signing transcript and
   the slate signing hashes. In particular:
   - the coinbase signing hash is `SHA-256("NosoX/coinbase-kernel/v5\0" ||
     BE32(network magic) || BE64(height) || BE64(amount) || commitment)`;
   - the Schnorr challenge domain is `NosoX/schnorr/v5\0`, a plain prefix of
     `R || P || len(msg) || msg`;
   - plain kernel signatures sign `types.KernelSigningMessage`:
     `SHA-256("NosoX/kernel-sig/v5\0" || BE32(network magic) || kernel ID)`.
   Assess whether signing intent can be replayed across network contexts. Do not
   infer intent guarantees from the header network field alone.
5. **Conservation** across complete chain validation: the balance equation,
   the coinbase check (value = subsidy plus the block's fees, also after
   emission ends).

## Existing evidence and its limits

- `v2/crypto/reference_test.go` checks Pedersen, generator and Schnorr values
  against independently computed constants. `audit/reference_vectors.py`
  reproduces them with plain affine integer arithmetic.
- Tests cover strict encodings, mutated proofs and signatures, and rejection
  at chain entry through `AddBlock`.
- Fuzz targets: `FuzzVerifyRangeBorromean` and `FuzzSchnorrVerify`
  (`v2/crypto`), `FuzzTransactionEncoding` (`v2/types`), `FuzzSlatepackDecode`
  (`v2/wallet`), `FuzzBlockDecode` and `FuzzTxDecode` (`v2/p2p`).

This is behavioral evidence from finite runs. There is no interoperability
suite against a reference implementation, no formal soundness argument and no
timing analysis.

## What would close the gate

A named, independent reviewer delivers a dated report for a precise commit,
covering assumptions, construction references, test vectors, findings with
severity, review of remediations, and residual limits. Every High or Critical
finding returns to remediation with regression tests. A replacement primitive
requires an explicit protocol version change; swapping an algorithm under an
existing name would silently split consensus.
