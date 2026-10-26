# Contributing to unsafe NosoX research

Read [release blockers](audit/RELEASE_READINESS.md) and
[consensus invariants](audit/CONSENSUS_INVARIANTS.md) before editing validation.
This is not production money infrastructure or an independently audited project.

Use Go 1.27.3 (`go.mod` is authoritative). Clone `pasichDev/noso-go` into a private
working checkout, use a feature branch, then run:

```bash
go fmt ./...
go build ./...
go vet ./...
go test ./... -count=1
go test -race ./... -count=1
```

Bound package parallelism with `-p 2` on constrained machines. Cache paths must
be writable. See [TEST_REPORT.md](audit/TEST_REPORT.md) for fuzz commands, scanner
versions, local integration and measured limits. Never connect test fixtures or
adversarial tests to public hosts or cryptocurrency networks.

For validation changes, add a negative test through AddBlock/ValidateTransaction/
ReorgTo, a valid control and state-unchanged assertion on both stores. Preserve
historical fixture bytes and explicitly document rejection/compatibility changes.
Tests must exercise intended rejection reasons; earlier guard failures can hide
missing checks. Never weaken monetary or ownership rules to satisfy a fixture.

Do not assert constant-time behavior from an API name: current secret operations
have unresolved timing risks. Any new cryptographic dependency or construction
requires justification and independent review. Do not change subsidy, GVT value,
premine or fee destination as an incidental fix.

Use focused imperative commits. Do not publish vulnerabilities or secrets in
public issues; use an established private maintainer contact. No public disclosure
SLA, private GitHub reporting facility or bounty is assumed. MIT license applies.
