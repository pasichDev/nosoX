---
title: Exchanges & liquidity
description: Honest strategy for getting a privacy coin onto exchanges in 2026.
---

# Exchanges & liquidity

This document is the honest answer to "how do we get listed?" — a
question every new privacy coin's community asks within the first
month after launch. The short version: **list expectations conservatively,
build user demand first, and route the path through DEX + atomic
swaps rather than chasing tier-1 CEX listings**.

## 1. The regulatory landscape in 2026

Privacy coins have been delisted by **most regulated exchanges**
over the past five years. This is not a problem unique to Noso v2 —
it's the environment every new privacy coin enters.

### Why privacy coins get delisted

| Driver | What it requires | Effect on privacy coins |
| --- | --- | --- |
| FATF Travel Rule | Sender + receiver KYC for txs > USD 1 000 | Untraceable by design = non-compliant |
| EU MiCA (effective Dec 2024) | Regulated CASPs cannot list "anonymity-enhanced" tokens | Outright ban for EU CEXes |
| US enforcement | Coinbase, Kraken, Bittrex pressured by FinCEN / SEC | Voluntary delistings of XMR, ZEC, DASH |
| Japan FSA (since 2018) | Privacy coin ban | XMR delisted from Japanese CEXes |
| South Korea | Privacy coin ban (2021) | XMR, ZEC, DASH off domestic exchanges |
| Australia (2023) | Privacy coin ban | Same |
| UK (FCA) | "Anonymity-enhanced" coins flagged | Heightened scrutiny |

### Where Monero, Grin, Beam currently trade

| Coin | Tier-1 CEX presence (2026) | Decentralized exchanges |
| --- | --- | --- |
| Monero (XMR) | Kraken (limited regions), MEXC, KuCoin, OKX (some regions). Delisted from Binance, Coinbase, Bittrex. | Bisq, Haveno, Serai, atomic-swap pairs with BTC. Strong DEX presence. |
| Grin (GRIN) | None in tier-1. Some tier-2 (TradeOgre, XT). | Marginal. |
| Beam (BEAM) | MEXC, KuCoin. Largely off tier-1. | Marginal. |

**The takeaway:** even Monero, the strongest privacy coin, mostly
trades on tier-2 CEXes and DEX-style atomic swaps. A new privacy
coin in 2026 should plan for that landscape, not yesterday's.

## 2. What we will NOT do

These are common mistakes for new-coin teams. Doing any of them
damages credibility and sometimes invites enforcement action.

- **Pay listing fees to tier-1 CEXes**. Even if Binance accepts, it
  delists privacy coins within 12 months. The fee is wasted.
- **Hire "market makers" who promise liquidity**. They wash-trade
  to inflate volume, regulators investigate, the coin tanks.
- **Promise listings in marketing**. We don't control exchange
  decisions; saying "Binance listing coming" is fraud-adjacent.
- **Apply for compliant listings by adding optional auditability**.
  This breaks the privacy design (see Beam's auditable txs — usage
  is near zero because users don't trust the opt-in).
- **Sell premine to a "VC round"**. There is no premine. There is no
  founder allocation. The whitepaper says so; we mean it.

## 3. What we will do — staged plan

### Stage 0 — Pre-launch (now → mainnet day)

- Build user demand via solo mining. The Raspberry Pi narrative
  reaches a real audience (r/raspberry_pi, hackerspaces, makerfaire,
  university labs).
- Ship a usable wallet (NosoSova via NosoDart) and a usable explorer.
- Publish whitepaper, audit memo, READINESS.md so technical reviewers
  can evaluate the project without us asking.
- Encourage Noso v1 holders to claim their inherited balances.
- Get **at least 100 active wallets and ~10 active miners** before
  approaching any exchange.

### Stage 1 — DEX-first listing (mainnet + 1 month)

| Venue | What it is | Why first |
| --- | --- | --- |
| Bisq | P2P decentralized exchange, fiat ↔ crypto | No listing fee, no KYC, treats Monero as standard. Track record. |
| BasicSwap (Particl) | Atomic-swap DEX | No counterparty, peer-to-peer. |
| Haveno | Monero-style P2P DEX | Active development, growing user base. |

Implementing **atomic swaps with XMR and BTC** is a one-month
engineering task. Once shipped, the coin trades 24/7 against the
most-liquid privacy coin and the most-liquid asset. No permission
required.

### Stage 2 — Tier-2 CEX (mainnet + 3–6 months)

Approach when monthly DEX volume is consistently > USD 50 k. Target
exchanges:

| CEX | Why approach | Caveats |
| --- | --- | --- |
| TradeOgre | Listed Grin, Beam, other small-cap privacy | Low volume, low fees, no KYC |
| MEXC | Lists XMR, BEAM | Tier-2, lower visibility |
| KuCoin | Lists XMR | Heightened compliance pressure |
| XT.com | Lists various privacy | Mixed reputation |

**Application process**: submit project info, demonstrate volume,
demonstrate community size, pay listing fee (typically 0.5–3 BTC
equivalent for tier-2). Do NOT pay for "marketing packages" —
they're worthless.

### Stage 3 — Bridge to other ecosystems (mainnet + 6–12 months)

Once a liquidity baseline exists, consider wrapped representations:

- **wNOSO on Ethereum**: locks NOSO on the v2 chain, mints wNOSO on
  ETH. Users get DeFi access without the privacy coin getting listed
  on regulated CEXes directly.
- **Lightning-style payment channel** between NOSO and BTC for fast
  swaps without on-chain settlement.

Bridges add **regulatory complexity** because the bridge custodian
can be pressured to KYC its users. Only do this if the community
sees real demand.

### Stage 4 — Resilience without exchanges

Realistic possibility: **no tier-1 CEX ever lists Noso v2**. That is
not failure. Bitcoin had no exchanges for its first two years; users
mined, paid each other, settled debts. The project survives if:

- **Real-world payments work.** Merchants accept NOSO for goods.
- **Mining is profitable.** Solo miners cover their electricity and
  bandwidth.
- **The chain keeps producing blocks.** Decentralization persists
  even at low fiat valuation.

Privacy coins that succeed economically without exchanges are rare
but exist (early Monero before Kraken listed it).

## 4. Liquidity recommendations for early holders

If you are a v1 inheritor or early miner asking "what do I do with
my balance?":

| Holding | Recommended action |
| --- | --- |
| < 100 NOSO | Hold, use for testing, donate to dev fund (none exists, so this is rhetorical), use for in-network payments. |
| 100–1 000 NOSO | DEX trade via Bisq when listing lands; otherwise hold. |
| > 1 000 NOSO | OTC peer-to-peer trades. Never use unverified mixers — they're scams or honeypots. |

## 5. Compliance posture

We do not require contributors to KYC. We do not collect user data.
We do not have a registered foundation. We are unincorporated open
source.

If a jurisdiction regulates Noso v2 in a way that affects local
users, we comply by **publishing the requirements** so users can
self-determine compliance. We do not act as compliance gatekeeper —
that's the user's responsibility under local law.

If you are a CASP considering listing: yes, MiCA / FATF make this
hard for you. We understand. The project's listing strategy is not
built around your participation. If you can list, great; if you
can't, the project still functions.

## 6. Communicating exchange status to the community

Templates for community channels:

> **"Will it be listed on Binance?"**  
> Probably not. Binance has delisted Monero, Zcash, and other privacy
> coins. Our listing strategy is DEX-first via Bisq + atomic swaps with
> BTC and XMR. See `docs/v2/EXCHANGES.md` for the full plan.

> **"When can I sell?"**  
> Atomic swaps to BTC will be available approximately one month after
> mainnet launch. Sooner via OTC peer-to-peer. We do not promise CEX
> listings.

> **"How do I avoid scams while trading?"**  
> Use Bisq or BasicSwap for trustless trades. If someone DMs you
> offering an "OTC desk" or "early listing", they are scamming you.
> The project has no official OTC desk.

## 7. Summary

- Privacy coins in 2026 list mostly on DEXes and a few tier-2 CEXes.
- Plan DEX-first via Bisq + atomic swaps with BTC and XMR.
- Approach tier-2 CEXes only after sustained DEX volume.
- Do NOT promise tier-1 listings. Do NOT pay for "market makers".
- Resilience without exchanges is a valid end state for a payment
  network.

The project succeeds if people **mine, pay, and accept** the coin —
not if it gets listed. The listings, when they come, follow demand.
