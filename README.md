# NosoX — unsafe research implementation

> **RESEARCH ONLY. MAINNET BLOCKED. Not independently audited.**
> This branch contains defensive hardening of an archived prototype. Passing
> tests do not establish cryptographic soundness or monetary legitimacy.
> Legacy claims are disabled. Custom cryptography, legacy migration and
> storage lifecycle/resource assurance remain release blockers. Do not hold value,
> expose this software publicly, or connect it to a public cryptocurrency network.

The Go module is `github.com/pasichDev/noso-go`, aligned with the repository
relocation. Go **1.27.3** is required, as selected from the official
[stable downloads](https://go.dev/dl/). CI reads the version from `go.mod`.

The implemented model uses secp256k1 Pedersen commitments, custom Schnorr and
bit-decomposition OR range proofs, Argon2id PoW, Badger storage and libp2p.
Ed25519 wallet identities are distinct from output spending scalars. No ASIC,
GPU, privacy, constant-time or production-readiness guarantee is established.

SP-1/2/3 follow-up implementation and exact current results are in
[audit/SP123_COMPLETION.md](audit/SP123_COMPLETION.md). It adds context-bound fee
outputs, suffix-only state staging and durable MVCC publication fences. This
does not establish independent cryptographic or production resource assurance.

The current internal assessment and exact evidence are in:

- [Security findings](audit/SECURITY_AUDIT.md)
- [Consensus invariants](audit/CONSENSUS_INVARIANTS.md)
- [Executed tests and limitations](audit/TEST_REPORT.md)
- [Breaking protocol changes](audit/PROTOCOL_CHANGES.md)
- [Release gates](audit/RELEASE_READINESS.md)
- [Migration trust](audit/MIGRATION_TRUST.md)
- [Threat model and scope](audit/THREAT_MODEL.md)

## Reproduce checks locally

```bash
go version
go build ./...
go vet ./...
go test ./...
go test -race ./...
```

The review used `-p 2` to bound concurrent package execution. If your environment
points Go caches at a read-only directory, set `GOMODCACHE` and `GOCACHE` to
writable directories; this does not alter module verification.

For isolated experiments, use temporary data, loopback listeners, testnet and
`-http-seeds=false`. The daemon defaults to these restrictions and refuses
mainnet startup. Automated local multi-node tests are safer starting points:

```bash
go test ./v2/p2p -run 'TestThreeNode|TestPreAdmittedNativeTransactionGossips' -count=1
```

## Compatibility and migration

Version **3** adds context-bound fee commitments and a new atomic storage schema
to the earlier header/body-binding changes. Old unfenced databases and earlier
protocol histories are rejected. Create a
new disposable local data directory; there is no trusted automatic upgrade.
No reward, allocation, fee destination or GVT value constant was changed.

The original snapshot fixture is preserved, but genesis generation rejects its
malformed account records. A valid binary parser does not authenticate historical
supply. There is no approved mainnet genesis or authenticated migration manifest.
The `GVTBaseValue` constant is **700 NOSO**, despite old documents claiming 70;
that discrepancy requires an explicit protocol decision, not a silent patch.

## Layout

`v2/` contains chain, crypto, genesis, wallet, miner, mempool, PoW, types, P2P and
RPC. `internal/` and `cmd/nosod`, `cmd/nosocli` contain legacy archive tooling;
it is not a complete historical consensus verifier. `scripts/` builds local
artifacts. The previously documented explorer executable is absent.

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup and private disclosure.
MIT licensed. Repository visibility and archive settings are unchanged.
