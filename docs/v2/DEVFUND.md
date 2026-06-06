# Dev fund — transparent, fee-funded

## Decision (2026-06-06)
Development is funded by **network transaction fees**, openly:

- Every block's total kernel fees are paid to **one public, immutable dev
  address** (`types.DevFundPubKeyHex` = `099f0f0f…0a97`). The **miner keeps the
  block subsidy** (50 NOSO, halving). 
- **No premine** (genesis allocation to the dev fund = 0).
- The address is hard-coded so the destination can't be redirected, and fully
  public so every coin reaching it is auditable on-chain. This is the opposite
  of a hidden dev wallet.
- A future on-chain messenger fee (deferred) would route here too, with a
  **dynamic, difficulty-scaled** price (see MESSENGER.md).

Private spending key: off-repo in `repo/noso/dev-wallet/` (gitignored).

## Honesty / spec note
This replaces the earlier "Dev fund: 0 / no devtax" wording. A fee-funded dev
address IS a (transparent) dev fee — docs and the site must say so plainly. What
stays true: **no premine, no team allocation, no hidden allocation.**

## Implementation status — IMPLEMENTED (testnet-grade; audit pending)
Done in `v2/chain/devfund.go` + miner + consensus, with tests
(`v2/chain/devfund_test.go`):

1. `TotalKernelFee(b)` = Σ kernel.Fee over the block.
2. Consensus (`validateDevFund`, wired into `Chain.validate`): if F>0 the block
   MUST carry exactly one `OutputFeaturesDevFund` output whose commit ==
   `F·H + DevFundPoint` (value-known, recomputable by anyone). If F==0, no
   dev-fund output is allowed.
3. The miner adds this output automatically when assembling fee-bearing blocks.
4. Tests cover: deterministic commit, zero-fee (with/without output),
   fee-requires-output, correct accepted, wrong-value rejected, duplicate
   rejected.

REMAINING (gated behind external audit, same bar as Bulletproofs):
- Full MW sum-balance enforcement (Σ outputs − Σ inputs = Σ excess + fee·H) is
  a separate, pre-existing gap in this codebase — the dev-fee rule is consistent
  with the current value-known coinbase model but does not by itself close it.
- The dev spends the output with the off-repo scalar r_dev (P_dev = r_dev·G).
