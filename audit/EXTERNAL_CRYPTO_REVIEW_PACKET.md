# Independent cryptographic review packet

Status: **REQUIRED EXTERNAL EVIDENCE, NOT COMPLETED**. This packet scopes work;
it does not constitute an independent assessment or an approval. No auditor has
been contacted or commissioned, and no code or findings were published.

Review source on `security/consensus-hardening`, manifest
`BLOCKERS_V4_SOURCE.sha256`, together with exact results under
`logs/blockers-v4-final/`. The commit containing that source can be obtained from
local Git history. There are no new cryptographic dependencies in this revision:
the claim verifier uses the already pinned Decred secp256k1/ECDSA implementation.

## Required review scope

1. `v2/crypto/{pedersen,schnorr,schnorr_ct,rangeproof,borromean}.go` and associated
   scalar/point encoding and `borromean_ct.go` helpers: generator derivation and unknown-log
   assumption, identity rejection, canonical scalar/point parsing, complete
   commitment algebra, exact Schnorr challenge transcript, nonce handling,
   domain separation and signature malleability. Do not assume BIP340 compatibility.
2. Custom bit-decomposition OR range proofs: published mathematical construction
   correspondence, Fiat–Shamir transcript binding, statement soundness, bit
   commitments, boundary values, proof composition and amount range. Shape and
   round-trip tests are insufficient. Decide whether to retain the construction
   after review or migrate explicitly to an established reviewed implementation.
3. All secret-dependent paths, including Decred public-key derivation calls,
   `big.Int`, wallet blinding/key generation, imported keys and kernel signing.
   Constant-time function names do not establish constant-time execution.
   NX-019 remains open; signing/proving must not be represented as side-channel
   hardened. Functional tests cannot close this gate.
4. `v2/legacyclaim`, `v2/chain/legacy_claim.go` and
   `v2/wallet/legacy_claim_v4.go`: exact new SHA256/strict-DER/low-S procedure,
   historical text-address derivation, trusted source selection, claim-leg
   context, aggregation/replay and cross-network/genesis binding. Historical
   SHA1 transaction signatures are not accepted by this new procedure.
5. Header/body/ID domains, coinbase transcript, version3 fee tweak, unsupported
   offsets and conservation across complete chain validation. Assess native
   kernel signing intent/reuse across network contexts separately from block
   network binding. Do not infer intent guarantees from header magic alone.

## Existing evidence and its limits

The crypto tests contain independently constructed arithmetic vectors, strict
encoding negatives, modified proof/signature transcripts and actual chain-entry
rejection tests. `legacyclaim/claim_test.go` pins synthetic key/address/digest/DER
vectors; chain tests exercise both backends, restart and reorg with real proofs.
The complete test/race runs are finite behavioral evidence. No independent
proof-system interoperability suite, formal soundness proof, timing assurance
or external cryptographic conclusion is supplied here.

## Evidence required to close the external gate

An identifiable independent reviewer must deliver a dated report for a precise
source revision, with assumptions, construction references, test vectors,
findings/severity, remediation review and explicit residual limits. All High or
Critical findings must return to remediation and executed regression testing.
Any replacement primitive requires an explicit protocol/serialization/version
decision; copying a different signature/proof algorithm under the existing name
would silently break consensus. Mainnet remains disabled pending this and the
separate economic migration, capacity and durability release gates.
