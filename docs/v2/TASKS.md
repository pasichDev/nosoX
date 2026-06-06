# NosoX — task register

Single source of truth for everything assigned. Statuses: ✅ done · 🟡 in
progress · ⬜ backlog · ❓ needs a decision. Last updated 2026-06-06.

Locked decision: **transparent dev fund** — the dev address is a public,
immutable protocol constant; message fees + any genesis allocation go to it
openly and are documented on the site (no hidden dev wallet, ever).

---

## A. Done this session

### Legacy v1 chain analysis (NosoData-Go)
- ✅ Solved the 137,780,000 delta (empty-receiver TRFR → premine slot 0).
- ✅ Explained the 40e9 "burn" (8 uncommitted tip blocks of the 59238 checkpoint — not a real burn; airdrop unaffected).
- ✅ Garbage-address blocklist (`androidx…`) + protocol-address detection.
- ✅ Migration policy: keyless protocol addrs consolidate to one keyed v2 address.
- ✅ Exported tip snapshot `balances.json` (16,207 accounts, block 180031, ~9.01M NOSO).
- ⚠️ Finding: real legacy carry ≈ **9.0M NOSO**, not 3M (3M was the 59238-era figure). Economics/site need reconciling.

### Website (nosox-site)
- ✅ Audit page: analysis story + searchable balances + Top-100 + alias subtitles + MEGA blocks download.
- ✅ Unified header across pages; removed run/launch instructions (pre-public); mobile fixes; status badge placement.

### Node (noso-go) — branch `feat/launch-rpc-quic-seeds`
- ✅ QUIC-v1 transport (TCP+UDP) for lossy/mobile networks.
- ✅ HTTPS seed discovery from the domain (`seeds/*.txt` + `httpseeds.go`).
- ✅ External RPC: CORS `Authorization` fix + docs (remote wallet/explorer connect).
- ✅ CI: `ci.yml` + reproducible `release.yml` (node/cli/explorer × linux amd64/arm64/arm, darwin, windows).
- ✅ Docs: LAUNCH refresh, AUDIT refresh, BULLETPROOFS + ATOMIC_SWAPS design docs.
- ✅ Verified roadmap "Done" list against code; all 16 packages green, 102 tests + 5 fuzz.

---

## B. Backlog assigned (the big build)

> Each step ships with tests; security-critical items (crypto, swaps, money
> routing) go through the external audit before mainnet. "100% / done" is only
> claimed when code exists, tests pass, and it's verified — never faked.

### Task 1 — Bulletproofs  ⬜  (sub-agent C)
- Inner-product argument over secp256k1; single-value range proof; aggregated multi-output.
- Constant-time ops; consensus tx-version switch; keep Borromean verify for history.
- Fuzz `FuzzVerifyRangeBulletproof` + KAT vectors. Target ~100 focused tests.
- Est. 2–3 weeks + audit. Spec: `BULLETPROOFS.md`.

### Task 2 — Atomic swaps (Bisq/Haveno)  ⬜  (sub-agent C)
- Schnorr adaptor signatures (encsign/decsig/recover) + tests.
- `v2/swap` protocol state machine, timeouts, refund via kernel lock-height.
- XMR (Haveno) adaptor swap first; BTC (Bisq) after. `nosox-cli swap {offer,accept,refund}`.
- Est. 4–6 weeks + audit. Spec: `ATOMIC_SWAPS.md`.

### Task 3 — Messenger protocol + auth SDK + site  ⬜  (sub-agent B)
- On-chain limited-data messages with **TTL ≈ 1 week** (auto-expire/prune).
- **Compression**: ultra — ❓ custom algo vs vetted (zstd/brotli) + our framing.
- **Encryption**: e2e — only sender OR named recipient can decrypt.
- **Fee**: fixed price per message → dev fund (transparent); **daily limit** per address.
- Messages **signed on the site**.
- **Wallet-auth SDK**: "Sign in with NosoX wallet" for third-party sites.
- Separate demo **site**.

### Task 4 — Explorer extraction  ⬜  (sub-agent A)
- Move explorer to ❓ separate repo vs `nosox-site/explorer` (static HTML/JS for GitHub Pages).
- Runs on a domain → reads seeds → pulls data via RPC. **Maximize metrics.**
- **Remove** explorer from the main code repo (`cmd/nosox-explorer`).
- Seeds unavailable → friendly message ("such is life, wait").

### Task 5 — Dev wallet + genesis allocation  ⬜  (foundation; I do first)
- Generate dev keypair; **private keys stored in `repo/noso/` outside git**.
- Embed only the **public** dev address as an immutable protocol constant.
- Message fees + agreed genesis allocation route here, **openly documented**.
- Generate block 0; dev wallet receives the agreed funds.

### Task 6 — Economics reconciliation  ⬜
- Update site/spec from "0 dev fund / no devtax" → honest "fixed message fee funds dev (address X)".
- Reconcile legacy carry ≈9M (not 3M) and max-supply numbers.

---

## C. Open decisions before sub-agents launch  ❓
1. **Order** of Tasks 1–4 (I run sequentially; sub-agents can parallelize A/B/C).
2. **Explorer**: new standalone repo vs subfolder; remove `cmd/nosox-explorer` fully or keep RPC endpoints it consumes.
3. **Messenger economics**: fixed price (NOSO)? daily limit (msgs/addr/day)? TTL exactly 7d? compression = custom or vetted?
4. **Dev genesis amount**: exact figure the dev wallet receives at block 0.
5. **Sub-agent parallelism**: confirm OK to spawn multiple sub-agents (higher token cost).

---

## Hard rules (standing)
- No hidden/obfuscated dev monetization — transparent only.
- No faked "done"; security-critical code gated behind the external audit.
- Existing v1 wallets/data stay byte-exact compatible.
- Commits local, **no Claude/Anthropic co-author trailer**.
