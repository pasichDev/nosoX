# Bulletproofs — design & status

**Status: NOT IMPLEMENTED.** This is a design/tracking doc, not shipped code.
The current range proofs are Borromean ring CT (`v2/crypto/borromean_ct.go`,
`rangeproof.go`) — correct but ~10× larger and variable-time. Do **not**
advertise Bulletproofs anywhere until the code below exists, is constant-time,
and has passed the external audit.

## Why
- **Size:** a Bulletproof range proof is ~675 bytes vs several KB for Borromean,
  and aggregates: N proofs in one ~`675 + 64·log2(N)` bytes. Big chain-size win.
- **No trusted setup**, unlike SNARK alternatives.

## Scope to replace Borromean
1. Inner-product argument over secp256k1 (reuse btcec field/scalar ops).
2. Single-value range proof (prove `v ∈ [0, 2^64)` for a Pedersen commit).
3. Aggregated multi-output proof for a transaction's outputs.
4. Constant-time scalar/point ops throughout (audit § 2.2).
5. Consensus switch: new tx version that carries Bulletproofs; keep Borromean
   verification for historical blocks (or hard-fork at a height).
6. Fuzz `FuzzVerifyRangeBulletproof`; KATs against a reference vector set.

## Risk / effort
Security-critical, consensus-affecting. Estimate: ~2–3 weeks for a careful
implementation + tests, then it MUST go through the external audit before it
touches mainnet. Shipping a half-finished range proof would let an attacker
mint coins (inflation) — strictly gated behind the audit.

## Migration
Until shipped, transactions use Borromean CT. The roadmap line "Bulletproofs
replacing Borromean (20× smaller proofs)" stays under **Up next**.
