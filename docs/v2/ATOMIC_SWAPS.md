# Atomic swaps (Bisq / Haveno) — design & status

**Status: NOT IMPLEMENTED.** Design/tracking doc only. No HTLC, adaptor-
signature, or swap-protocol code exists in the tree yet. The roadmap line
"Bisq / Haveno / atomic-swap integrations" stays under **Up next**.

## Goal
Trustless BTC/XMR ↔ NosoX swaps so the coin is tradeable without a custodial
exchange listing (which a privacy coin rarely gets early).

## Approach (Mimblewimble-aware)
Classic HTLCs are awkward in pure MW (no script, no addresses). The realistic
path is **adaptor signatures** on the Schnorr signatures NosoX already uses:

1. **Schnorr adaptor signatures** — a pre-signature that completes only when a
   secret `t` is revealed; revealing the on-chain signature leaks `t`. We
   already have Schnorr (`v2/crypto/schnorr.go`) — extend with
   `encsign`/`decsig`/`recover`.
2. **Cross-chain coordination:**
   - **XMR (Haveno):** Monero↔NosoX both Schnorr-friendly → adaptor-signature
     swap, no on-chain scripts. Closest fit.
   - **BTC (Bisq-style):** BTC side uses a Taproot/HTLC; NosoX side uses the
     adaptor signature. More moving parts.
3. **Swap protocol + timeouts:** refund path via kernel lock-height; a
   `nosox-cli swap {offer,accept,refund}` flow over Slatepack.

## Scope / effort
- `v2/crypto`: adaptor signatures + tests (~1 week).
- `v2/swap`: protocol state machine, timeouts, refund (~2–3 weeks).
- Integration with Bisq/Haveno trade protocols (external, coordination-heavy).

Estimate: ~4–6 weeks for a working XMR adaptor-swap MVP; Bisq/BTC after.
Security-sensitive (a refund/timeout bug = lost funds) → audit before mainnet.
