# Contributing to NosoX

> Before you start: this is currently a **testnet/research repo**.
> Mainnet launch waits on the external audit. Treat the code as a
> design vehicle, not as production money infrastructure.

## How to set up

```bash
git clone https://github.com/<you>/noso-go
cd noso-go
go build ./...
go test ./...
```

Go 1.23 or newer required. No CGO. All dependencies are pinned via
`go.mod` / `go.sum`.

## What's most welcome

In order of where help is most needed:

1. **Audit feedback.** When the external review starts, public
   reproduction of findings is critical. Please file issues with
   minimal reproducers.
2. **Mobile light-client.** Compact filters ship; we need a wallet
   mode that syncs filters instead of full blocks. Reference:
   `v2/types/filter.go`, BIP-157/158-style protocol.
3. **Encrypted messenger protocol** on top of `v2/crypto` and
   `v2/p2p`. Design doc PR appreciated before implementation.
4. **Translations.** Documentation in Ukrainian, Spanish, Japanese,
   German is sorely missing. Open a PR with `docs/v2/<file>.<lang>.md`.
5. **Repro test cases for AUDIT.md items** as they get closed.

## What's NOT welcome

- Premine / founder allocation requests. Locked at 0 by spec.
- "Quick exchange listing" pitches. Read `docs/v2/EXCHANGES.md`.
- Marketing copy that promises mainnet-grade safety. We're honest:
  pre-audit, testnet-only.
- Adding `v2/types` fields without a corresponding hard-fork plan.
  Consensus rules are stable.

## Coding standards

- `gofmt -s` everything before committing.
- Tests for new public functions. The bar is "round-trip + tamper +
  wrong-input" coverage at minimum.
- Constant-time primitives for any new code that touches secrets
  (private keys, blinding factors). Use `decred/dcrd/dcrec/secp256k1/v4`
  `ModNScalar` / `PrivateKey.PubKey()` patterns from `v2/crypto/schnorr_ct.go`
  and `v2/crypto/borromean_ct.go`.
- No new dependencies without justification.
- Don't add emojis to source files.

## Commit messages

Format: `<area>: <short imperative>` — example:

```
v2/wallet: claim builder produces real signed Transaction
docs/v2: README documents migration test procedure
v2/p2p: drop the old JSON-TCP gossip (superseded by libp2p)
```

## License

Contributing implies you license your contribution under the
project's MIT license.

## Security disclosure

For security issues, please **do not open a public issue**. Email
the maintainer (contact info on the project's GitHub profile) or
use GitHub's private-issue feature.

We will not run a bug-bounty program until after the external audit
and mainnet launch.
