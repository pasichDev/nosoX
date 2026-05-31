# NosoX — Project Paper

> **Privacy-by-default money. Mineable on a Raspberry Pi, a phone, or
> an old laptop. Inherits the entire 2018–2024 Noso ledger 1:1.
> Zero premine, zero dev fund, zero founder allocation.**

A pure-Go Mimblewimble cryptocurrency that picks up the original Noso
chain where it stopped — preserves every balance and every
collectible, throws out the broken cryptography, and runs on hardware
that ordinary people already own.

---

## One-paragraph summary

NosoX is a memory-hard, Mimblewimble-based cryptocurrency written
from scratch in Go. It boots from a snapshot of the original 2018
Pascal Noso chain — every non-zero balance and all 100 governance
tokens (GVTs) ship in genesis under their original owner addresses,
spendable by the original keys. Privacy is not a toggle: every native
transaction hides amounts behind Pedersen commitments and proves
non-negativity with Borromean zero-knowledge range proofs. Mining
uses Argon2id with 64 MiB memory per attempt — this kills ASIC and
GPU advantage and levels the field for phones, laptops, and a $35
Raspberry Pi. There is no premine, no dev fund, no marketing
allocation, no governance token, and no founder address. The only
pre-genesis state is the inherited v1 ledger.

---

## The pitch in three bullets

- **Privacy by default.** Mimblewimble transactions hide amounts and
  addresses on every transfer. No opt-in shielding, no public memo
  field, no surveillance surface to leak through. Borromean range
  proofs prove "this output is non-negative" without revealing the
  amount.

- **Mining for humans.** Argon2id at 64 MiB closes the door on
  specialized hardware. A Raspberry Pi, an Android phone, or a
  five-year-old laptop all participate. No GPU farms, no warehouse
  ASICs. The chain is mined by the people who run it.

- **Trust-minimal inheritance.** Every v1 account and every v1 GVT
  ships in the NosoX genesis block, deterministically reconstructible
  by anyone with the original `sumary.psk` and `gvts.psk` files. Old
  keys spend old balances directly. No centralized claim portal, no
  KYC, no rent.

---

## What problem does this solve

Noso v1 (2018–2024) was a community Pascal project with a real user
base, a working Flutter wallet (NosoSova), and a working chain — but
it ran on cryptography from a different era: MD5 consensus hashes,
SHA-1 ECDSA signatures, plaintext peer-to-peer networking, raw binary
storage, and amounts public on chain. When the original maintainer
stopped releasing updates, the chain quietly stalled.

NosoX restores forward motion **without throwing away its users**:

| Lost in v1 | Inherited into NosoX |
| --- | --- |
| Maintainer attention | Active Go reimplementation |
| Forward compatibility | Built on modern primitives, audited toolchain |
| Privacy | Mimblewimble, hidden amounts on every tx |
| Hardware accessibility | Mineable on $35 boards and phones |
| Trust in the binary | Reproducible builds, signed checkpoints |
| | |
| **Preserved** | |
| Every non-zero balance | Carried into genesis under original v1 address |
| All 100 GVT collectibles | Preserved 1:1 with slot identity (00..99) |
| Original wallet keys | Still spend, via legacy secp256k1 signature path |
| NosoSova UX | Migration path through the new wallet CLI |
| 50 NOSO block reward | Same emission curve, same halving cadence |

---

## What's locked (economic spec)

| Parameter | Value | Why |
| --- | --- | --- |
| Block time | 120 s | Mobile-friendly confirmations |
| Halving | every 210 000 blocks (≈292 days) | Matches v1 emission |
| Halving steps | 10 | Tail emission ends after ≈10 years |
| Initial reward | 50 NOSO | v1 continuity |
| Max supply | ~24 M NOSO | ~3 M legacy + ~21 M emission |
| Premine | **0** | No founder allocation, no insider supply |
| Dev fund | **0** | No tax on miners or holders |
| Treasury | **0** | No multisig sitting on community funds |
| PoW algorithm | Argon2id, 64 MiB memory per nonce | ASIC-hostile, Pi-friendly |
| Privacy | Mimblewimble + Borromean range proofs | Always on, no toggle |
| Difficulty | LWMA-3, 90-block window | Stable on low hashrate |
| Signing | Ed25519 (wallet) + Schnorr (kernel) + secp256k1 (legacy claim) | Modern + legacy compat |

---

## What's been built (status today)

**Shipped and running:**

- 3 binaries: `nosoxd` (full node), `nosox-cli` (wallet + RPC client),
  `nosox-explorer` (read-only block/mempool/GVT browser)
- Full Mimblewimble protocol — Pedersen commitments, Borromean range
  proofs (constant-time prover), Schnorr signatures on secp256k1
  (constant-time)
- Argon2id PoW at 64 MiB with multi-threaded miner
- LWMA-3 difficulty adjustment, deep-reorg protection,
  checkpoint-signed binaries
- libp2p networking with gossipsub, Noise transport, NAT traversal
- BadgerDB persistent storage with atomic writes
- Wallet encryption: Argon2id KDF + XChaCha20-Poly1305, mlock'd,
  zeroized on close
- RPC bearer-token authentication with constant-time compare
- Slatepack interactive transaction protocol (pay / receive /
  finalize)
- v1 ledger import: full balance carry-over + 100 GVTs
- Reproducible builds: two independent rebuilds produce identical
  SHA-256
- 99 test functions across 16 packages + 5 fuzz harnesses
- Multi-node sync verified: cold sync < 1 s for 5 blocks, gossip
  propagation < 10 s
- 15-block deep-reorg under load test, checkpoint-guarded reorg
  rejection
- Astro Starlight documentation site (16 pages, search-indexed)
- Marketing site with v1↔NosoX comparison and live roadmap

**Closed this sprint:**

- Constant-time crypto across signing and range-proof prover paths
- GVT inheritance (Redeem / Transfer / Hold semantics)
- Wallet builder for all claim/redeem/transfer flows
- Honest audit document with open-issue tracking

**Mandatory for mainnet:**

- External cryptographic audit (4–6 weeks, recommended firms: NCC
  Group, Trail of Bits, Cure53)
- Seed-node infrastructure (3 nodes minimum, geographically
  distributed)

Everything else is operational: pick a domain, publish DNS TXT
seeds, tag a release with checkpoints. Roughly one week of
launcher-side work after the audit signs off.

---

## v1 → NosoX inheritance (the unique part)

NosoX is the only Mimblewimble chain that starts from a non-empty
state. The bridge is deterministic and audit-friendly.

### Balances

Every non-zero `sumary.psk` record becomes a *Legacy UTXO* in genesis:

```
LegacyOutput {
  Commit        = PedersenCommit(balance, SHA256("NosoX legacy blind " + addr))
  LegacyAddress = original v1 "N…" address
  LegacyAmount  = v1 balance
}
```

To spend, the holder signs a claim message with their original v1
secp256k1 key. The chain verifies under the legacy SHA-1 ECDSA path,
then converts the legacy output into a private MW output owned by
the holder's new Ed25519 master key. The v1 key is never needed
again for that balance.

### GVTs (Governance and Voting Tokens) — the collectibles

The v1 chain shipped 100 GVT slots numbered 00..99, each redeemable
for a fixed 70 NOSO. NosoX preserves all 100 with three operational
modes:

| Action | What happens | Use case |
| --- | --- | --- |
| **Redeem ↻** | Spend GVT → 70 NOSO. Slot disappears. | "I want the value." |
| **Transfer →** | Mint new `LegacyGVT` output, same slot, new owner. Identity preserved on chain. | "I'm gifting / selling slot 47." |
| **Hold ⊙** | Do nothing. Output sits in UTXO set under v1 owner address. | "I'll decide later." |

GVTs in NosoX have **no special protocol role**. They don't vote,
they don't pay yield, they don't confer governance. The whole point
is to honor v1 ownership without inventing new mechanics — a clean
collectible registry inherited 1:1.

### Lost keys

If your v1 `wallet.pkw` is gone, the inherited balance is
unrecoverable. There is no quorum override, no recovery service, no
discretionary admin key. This is deliberate trust-minimization.

---

## Mining: NOT ASIC, NOT GPU, YES everything else

Argon2id at 64 MiB per nonce attempt means a single mining attempt
needs 64 MiB of fast memory bandwidth. This is exactly the regime
where general-purpose CPUs and SoCs are at their best, and where
ASICs and GPUs are at their worst:

| Hardware | Approximate hashrate | Notes |
| --- | --- | --- |
| Raspberry Pi 4 (4 GB) | 8–15 H/s | Reference baseline — block ≈1× per day at launch |
| Android phone | 30–80 H/s | Mid-range 2023+ device |
| 5-year-old laptop | 40–90 H/s | Even an old CPU has the memory bandwidth |
| Modern desktop CPU | 200–500 H/s | 8-core mid-range builds |
| GPU (RTX 4090) | 100–200 H/s | Wasted silicon — VRAM access patterns mismatch |
| ASIC | — | Negative ROI. No memory bandwidth advantage to exploit. |

The result: a chain that's mined by the people who run it, on the
hardware they already own.

---

## What we're building on top

The crypto primitives that protect NosoX transactions — constant-time
Schnorr, Argon2id key derivation, XChaCha20-Poly1305 envelope
encryption, libp2p Noise transport — are not limited to money. The
NosoX roadmap uses them as the foundation for an ecosystem of
sovereign-by-default tools:

- **Encrypted messenger.** End-to-end encrypted messaging using
  Ed25519 device keys and libp2p relay. No central server, no phone
  number, no metadata leakage. Bridged to NosoX wallet identities so
  payments and messages share a key.
- **Mobile light-client.** SPV-mode wallet for Android and iOS that
  verifies headers against checkpointed roots without downloading
  the chain.
- **Identity attestations.** Provable claims (proof-of-membership,
  proof-of-uniqueness) backed by cryptographic commitments without
  revealing identity itself.
- **Payment channels.** Off-chain micropayment lanes for
  high-frequency transfers (donations, streaming, in-game value).

Each layer strengthens the network's significance beyond "just
another privacy coin" — the same cryptography makes the same wallet
useful for messaging, identity, and routine payments.

---

## Roadmap

**Done (12 milestones):**

- Mimblewimble protocol — commitments, kernels, range proofs
- Borromean ZK range-proof prover (constant-time)
- Constant-time Schnorr signing on secp256k1
- Argon2id 64 MiB PoW + LWMA-3 difficulty
- libp2p + gossipsub network transport
- BadgerDB chain store with reorg guard
- v1 ledger import (balances + GVTs)
- Wallet encryption (Argon2id + XChaCha20-Poly1305)
- Slatepack tx protocol (pay/receive/finalize)
- Reproducible build manifest + verify
- 5 fuzz harnesses + 99 test functions
- Documentation site + marketing site

**In progress:**

- External cryptographic audit (engagement scoping)
- Seed-node + checkpoint validator coordination

**Up next:**

- Encrypted messenger over libp2p
- Mobile light-client (Android + iOS)
- Identity attestations layer
- Payment channels
- Bulletproofs upgrade (smaller range proofs, ~700 B vs 14 KB)
- Multilingual documentation (Ukrainian, Russian, Spanish)

---

## What this means for someone evaluating the project

**If you're a developer:**

- The code is 12k LOC pure Go, written with extensive test coverage
  and documentation. Onboarding is hours, not weeks.
- The cryptography is real (Pedersen, Borromean, Schnorr, Argon2id)
  but has not had an external audit. Anyone joining as a crypto
  engineer can verify against the whitepaper or scope the audit.
- The economic model is conservative: no founder allocations, no
  optional shielding, no governance token, no admin keys.

**If you're an operator:**

- Reproducible builds let you verify the binary you run matches the
  source repository.
- The runbook (`docs/v2/LAUNCH.md`) is step-by-step and tested
  end-to-end.
- The seed-node + checkpoint trust model is documented in
  `SECURITY.md` and is honest about its centralization at launch.

**If you're a former Noso community member:**

- Your old balance is preserved. Genesis contains every non-zero
  account from `sumary.psk`.
- Your old key still spends. The legacy claim path verifies under the
  original secp256k1 + SHA-1 ECDSA scheme.
- If you held a GVT slot, your slot is preserved with the same number
  in genesis. You can redeem (70 NOSO), transfer, or hold.

**If you're an exchange or wallet operator:**

- Read-only JSON-RPC integration via `nosox-cli rpc`.
- Deposit detection through the `mempool` and `block` RPC endpoints.
- No proprietary SDK — speak JSON-RPC over HTTPS with a bearer token.
- Reorg-safe confirmation: 12 confirmations recommended at launch
  while checkpoints anchor the chain.

---

## What this does NOT promise

- **No lost-key recovery.** Trustless inheritance has no central
  authority. If you lost your v1 wallet, the balance is gone.
- **No mainnet-grade safety today.** The external audit is a real
  prerequisite, not a nice-to-have. The current testnet is for
  exercising the protocol, not securing real value.
- **No economic upside guarantee.** There is no marketing team, no
  listing campaign, no influencer outreach budget. The token
  economics are a fair-launch baseline; whatever price discovery
  happens, happens.
- **No founder kickbacks.** There is no founder reward, no premine,
  no developer tax. The maintainer mines on the same terms as every
  other participant.

---

## Where to read more

| Document | What it is |
| --- | --- |
| `WHITEPAPER.md` | Formal design paper, Bitcoin-style |
| `PROTOCOL.md` | Wire format and validation rules |
| `AUDIT.md` | Honest open-issue list and threat model |
| `READINESS.md` | Component-by-component go/no-go matrix |
| `LAUNCH.md` | Operator runbook |
| `SECURITY.md` | Trust model (seeds, checkpoints, 51%) |
| `MIGRATION.md` | v1 inheritance mechanics, GVTs included |
| `MINING.md` | Argon2id, Pi/phone/laptop tuning |
| `WALLET.md` | Slatepack pay/receive/finalize |
| `FORKING.md` | Run your own NosoX-compatible chain |
| `REPRODUCIBLE.md` | How users verify the binary |
| `EXCHANGES.md` | Integration guide for listings |
| `LIMITS.md` | Backlog of post-launch improvements |

All also rendered as a searchable static site under
[`nosox-site/docs/`](../../nosox-site/).

---

## Contact / next step

- **Source:** https://github.com/pasichDev/noso-go
- **Audit scoping & technical questions:** open a GitHub issue.
- **Operational coordination** (seed nodes, relays, checkpoint
  validators): reach the maintainer via the contact channel listed
  on the GitHub README.

NosoX is in active development on testnet. Mainnet is gated on the
external audit. Everything is open source, MIT licensed, and
reproducible from the source tree.
