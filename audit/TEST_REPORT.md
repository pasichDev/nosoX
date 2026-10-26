# Executed validation and limitations

Current version3 SP1/SP2/SP3 follow-up results are in [SP123_COMPLETION.md](SP123_COMPLETION.md)
and logs/sp123/. The prior measurements below remain preserved historical evidence.

Baseline:6179eb56d53768a19950f07e9c806fd384572c5d, clean main before branch creation.
Branch:security/consensus-hardening. Verified code commit:ed5c2eb. Original module:noso-project/noso-go;
current module:pasichDev/noso-go. No publish/deploy/merge/settings change.

## Baseline before production edits

With Go1.25.7 and writable caches, all four commands returned0:
`go build ./...`, `go vet ./...`, `go test ./...`, `go test -race ./...`.
Raw logs:logs/baseline-{build,vet,test,race}.log. The initial default-cache
invocation failed because /mnt/yocto/gomod/cache is read-only; explicit writable
cache selection resolved that environment issue. Passing baseline tests failed
to expose critical consensus omissions and do not establish safety.

## Current verification-only pass

All entries below were actually executed, not inferred from earlier agent results.
Environment for every row: `GOTOOLCHAIN=go1.27.3`,
`GOMODCACHE=/home/pasich/go/pkg/mod`, `GOCACHE=/home/pasich/.cache/go-build`,
`GOPROXY=off`. Platform:linux/amd64. Exact UTC starts, command argument arrays,
exit status, wall times and log hashes are in logs/verification-*-results.json.
No new vulnerability discovery, fuzz campaign, network scan or attack simulation
was started in this pass. Existing local regression/integration/fault tests run.

| Command | Exit | Wall seconds | Log |
|---|---:|---:|---|
| `go version` | 0 | 0.009 | [version](logs/verification-version.log) |
| `go fmt ./...` | 0 | 0.134 | [format](logs/verification-format.log) |
| `go build -p 2 ./...` | 0 | 2.115 | [build](logs/verification-build.log) |
| `go vet -p 2 ./...` | 0 | 0.621 | [vet](logs/verification-vet.log) |
| `go mod verify` | 0 | 0.736 | [modverify](logs/verification-modverify.log) |
| `go test -p 2 ./... -count=1` | 0 | 100.567 | [regression](logs/verification-regression.log) |
| `go test -race -p 2 ./... -count=1` | 0 | 190.019 | [race](logs/verification-race.log) |
| `go test -p 2 ./v2/chain -run ^TestSecurity -count=1 -v` | 0 | 56.927 | [storage](logs/verification-storage.log) |
| `go test -p 2 -coverprofile=audit/coverage.out ./... -count=1` | 0 | 77.603 | [coverage](logs/verification-coverage.log) |
| `go tool cover -func=audit/coverage.out` | 0 | 0.215 | [coverage-summary](logs/verification-coverage-summary.log) |

Full regression and race logs contain17 passing test packages and3 command
packages without tests. Coverage:62.9% overall statements. Coverage is execution
measurement, not an invariant or security proof. Concurrent independent package
runs affect wall times; they are not benchmark numbers.

A final test-only strengthening made the existing backend-size fault assert
`errors.Is(err,badger.ErrTxnTooBig)` instead of accepting any error. The actual
specific failure and unchanged state were then verified with:

```
go test -race -p 2 ./v2/chain -run '^TestSecurityBadgerOversizeTransactionRollback$' -count=1 -v
```

Exit0; test3.36s, package4.473s. See logs/verification-sp3-error-class.log.
No production source changed after full-suite/race verification. Exact pre-
assertion manifest:FULL_SUITE_SOURCE.sha256; final manifest:VERIFIED_SOURCE.sha256.
The only differing source file is the stated test. All final production bytes
match the full-suite manifest. Source fixtures and original testdata are retained.

## Failures retained and ordinary regressions fixed

- Earlier integrated race run failed in Miner.grindBlock: worker read shared
  candidate header while winner replaced it. Fixed using an immutable worker
  template and draining workers; failed log:final-race-before-miner-fix.log.
  Targeted miner race tests subsequently passed3 runs (5.722s), and the current
  full race run passed including miner2.646s.
- First verification build/vet/regression failed because v2/p2p/sync.go retained
  unused fmt after a previous bounded-error change. Removed that import only.
  Attempt1 logs and metadata remain under verification-*-attempt1.*. Current
  rerun rows above are all0. The existing Sync regression also passed0.315s.
- Supplementary offline `go list -m -json all` returned1 (`module lookup disabled
  by GOPROXY=off`): not all graph metadata is cached. No fetch was made in this
  pass. DEPENDENCIES.json explicitly lists declared go.mod requirements, not a
  complete post-update transitive graph; PRE_UPDATE_DEPENDENCIES.json preserves
  the earlier inventory. `go mod verify` returned0 for cached module integrity.

## Security invariant regression mapping

All names below are existing tests executed in the current pass. Chain test
seconds are the verbose storage-run totals, often including both backend subtests.

| Invariant / files | Real entry-point regression | Observed result |
|---|---|---|
| Ordinary kernel ownership, maturity, duplicates; chain/validation.go | TestSecurityNativeAuthorizationMaturityAndUndo | PASS13.08s |
| Exact signed subsidy; chain/validation.go | TestSecurityBlockAuthorizationMutations; TestSecuritySyntheticScheduleEdgesThroughAddBlock | PASS2.32s /0.59s |
| Legacy ownership fails closed; chain/validation.go | TestSecurityLegacyClaimFailsClosed | PASS0.29s |
| Reject fake v1 or mutated range proof; crypto/rangeproof.go, chain/validation.go | NativeAuthorizationMaturityAndUndo (specific proof error assertions) | PASS13.08s |
| Bind full body; types/commitments.go, chain/validation.go | NativeAuthorizationMaturityAndUndo (roots mismatch then proof failure); types body mutation/KAT tests in full suite | PASS; types package0.009s |
| Rollback all derived state; chain/chain.go,badger_store.go | ReorgRollbackAndStrictWork; ReorgCommitFailureUnchanged | PASS2.09s /0.32s |
| Persistence and backend parity | BadgerAbruptExit; BackendParityAndNestedSlices | PASS0.96s /0.83s |
| Direct store delta consistency; chain/store_delta.go | StoreRejectsImpossibleDeltas; StoreBadgerDecodeFailureUnchanged | PASS1.54s /0.12s |
| Actual transaction-limit refusal leaves state intact | BadgerOversizeTransactionRollback | PASS0.43s; stronger error-class race test also PASS4.473s/package |
| Shorter but higher valid work wins | ShorterHeavierForkWins | PASS32.78s |
| Timestamp overflow/future bound | FutureTimestampCannotFreezeChain | PASS0.57s |
| Cheap malformed-suffix rejection before prefix reads | ReorgRejectsMalformedBeforePrefixRead | PASS0.09s |

Schedule-edge tests use an explicitly disclosed synthetic bounded tip/window,
not a2.31-million-block replay. Separate types test enumerates BlockReward over
all scheduled heights against an independent era-sum formula. UTXO aggregate
commitments are checked after a mature spend and undo. These are conditional on
cryptographic soundness, not independent economic reconstruction.

Existing P2P tests in the full suite/race run include three loopback nodes,
propagation, persisted memory restart, competing suffix convergence and invalid
block forwarding rejection with a valid control. A real mature native spend
with a range proof and ordinary signature propagates after local admission.
They do not establish internet-scale consensus, maximum legal backend capacity,
complete interactive wallet payments or Sybil/eclipse resistance.

## Earlier bounded fuzzing (before the verification-only instruction)

The lead executed these with Go1.27.3, -p2, -run '^$', -parallel2:

- `go test -p 2 ./v2/types -run '^$' -fuzz '^FuzzTransactionEncoding$' -fuzztime=5s -parallel=2`:
  exit0, package5.084s,306358 executions, initial1 seed,5 new interesting inputs.
- `go test -p 2 ./v2/crypto -run '^$' -fuzz '^FuzzVerifyRangeBorromean$' -fuzztime=5s -parallel=2`:
  exit0, package6.066s,4832 executions, initial3 seeds,0 new interesting inputs.

Exact logs:fuzz-types.log/fuzz-range.log. The Go mutator did not print its PRNG
seed; the exact random mutation sequence is not recoverable. The then-current
range seed included a freshly randomized proof. Initial proof/signature seed
bytes were subsequently fixed in v2/crypto/testdata for reproducible normal
regression corpus execution; those new fixed seeds were covered by the current
ordinary/race tests, not a new fuzz campaign. Types seeds are the literal x/yz
case in FuzzTransactionEncoding. Finite runs do not prove absence of defects.
Earlier agent-run crypto/wallet/P2P fuzz results and limitations are preserved
in crypto-wallet-review.md and network-review.md; not re-executed in this pass.

## Earlier tools and remaining checks

Before verification-only scope, govulncheck1.9.0 required an explicit
GOTOOLCHAIN=go1.27.3 (automatic tool module selection had chosen1.26.10 and failed
on1.27 sources). It initially reported3 called-module advisories; transport
updates yielded exit0,0 called advisories,5 imported-package and10 required-
module alerts classified not called. See govulncheck-patched.log and failed logs.
That scan preceded final storage/miner changes and was not rerun here.

staticcheck, gosec, gitleaks and trufflehog were not installed. No successful
result is claimed. Dedicated secret/history scan, reproducible binary comparison,
cross-OS/architecture compilation, production-scale resource tests and exhaustive
power-loss testing were not completed. Release scripts had bash syntax checking,
not full signed-release/reproducibility validation. No public crypto network was
contacted. All these limitations remain explicit gates where relevant.

SP1/2/3 dispositions and next safe steps are in VERIFICATION_SUMMARY.md.

## Preserved raw-log whitespace diagnostics

`git diff --check 6179eb56d53768a19950f07e9c806fd384572c5d HEAD`
returned2 solely for two captured scanner-log formatting diagnostics:
audit/logs/govulncheck-version.log has a final blank line, and
audit/logs/govulncheck.log preserves the scanner's trailing space. Raw evidence
was intentionally not rewritten. The same check with
`-- . ':!audit/logs'` returned0 for source, tests and documentation. These are
log-format diagnostics, not passing code checks or new security findings.
