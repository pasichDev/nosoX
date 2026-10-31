# Contributing

Read [audit/CONSENSUS_INVARIANTS.md](audit/CONSENSUS_INVARIANTS.md) before
changing validation. This project is experimental and has not been
independently audited.

## Setup

Use the Go version in `go.mod`. Fork the repository, create a branch, and
run before opening a pull request:

```bash
gofmt -l .            # must print nothing
go mod tidy -diff     # must print nothing
go vet ./...
go build ./...
go test ./... -count=1
go test -race ./... -count=1
golangci-lint run     # configuration in .golangci.yml
```

Use `-p 2` on small machines. Fuzz targets run with `go test -fuzz`; see the
list in [audit/EXTERNAL_CRYPTO_REVIEW_PACKET.md](audit/EXTERNAL_CRYPTO_REVIEW_PACKET.md).

## Rules for consensus changes

- Add a negative test that goes through `AddBlock`, `ValidateTransaction` or
  `ReorgTo`, a valid control case, and an assertion that state is unchanged on
  both stores.
- Check that the test fails for the intended reason. An earlier guard can hide a
  missing check.
- Do not weaken a monetary rule to make a fixture pass.
- A consensus change needs a protocol version bump and an entry in the
  changelog.
- Do not change the subsidy, the coinbase amount (subsidy plus fees) or the fee rule as a side
  effect of another change.
- Do not describe code as constant time unless a reviewer has confirmed it.
- A new cryptographic dependency or construction needs a written justification
  and independent review.

## Pull requests

Keep commits focused and use imperative messages. Update the documentation in
`docs/` when behavior changes. The documentation site builds in strict mode:

```bash
pip install -r docs/requirements.txt
mkdocs build --strict -d /tmp/site
```

## Reporting vulnerabilities

Do not use public issues. See [SECURITY.md](SECURITY.md).

## License

Contributions are licensed under the MIT license in [LICENSE](LICENSE).
