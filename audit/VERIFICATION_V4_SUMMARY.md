# Version4 final local verification

Date:2026-10-26. Branch:`security/consensus-hardening`; base:`1f4b2d2`.
Source:`BLOCKERS_V4_SOURCE.sha256` (155 Go/module files). The final source was
frozen before the executed checks below and hash-checked again afterwards.
No deploy, merge, public-network test, publication or setting change occurred.

Environment for all Go commands:
```text
GOTOOLCHAIN=go1.27.3
GOMODCACHE=/home/pasich/go/pkg/mod
GOCACHE=/home/pasich/.cache/go-build
GOPROXY=off
```

| Exact executed command | Exit | Wall seconds | Log |
|---|---:|---:|---|
| `go version` | 0 | 0.008 | `audit/logs/blockers-v4-final/verification-version.log` |
| `go fmt ./...` | 0 | 0.139 | `audit/logs/blockers-v4-final/verification-format.log` |
| `go build -p 2 ./...` | 0 | 1.989 | `audit/logs/blockers-v4-final/verification-build.log` |
| `go vet -p 2 ./...` | 0 | 0.513 | `audit/logs/blockers-v4-final/verification-vet.log` |
| `go mod verify` | 0 | 0.472 | `audit/logs/blockers-v4-final/verification-modverify.log` |
| `go test -p 2 ./... -count=1` | 0 | 118.666 | `audit/logs/blockers-v4-final/verification-regression.log` |
| `go test -race -p 2 ./... -count=1` | 0 | 294.124 | `audit/logs/blockers-v4-final/verification-race.log` |
| Storage selection (command below) | 0 | 95.616 | `audit/logs/blockers-v4-final/verification-storage.log` |

```bash
go test -p 2 ./v2/chain -run '^(TestSecurity|TestSP1|TestBadgerFence|TestBadgerLifecycle|TestBadgerRecovery|TestStreamingReplay|TestResource|TestLegacyClaimV4)' -count=1 -v
```

Ordinary tests:18 packages passed,3 packages have no tests. Full race:18
packages passed, no race report in the final run. Storage subset:48 passing
top-level tests /191 including subtests; the opt-in1024-shape test was skipped
there and subsequently executed explicitly on both backends below.

## Selected complete-entry/lifecycle regressions

| Test | Observed test seconds |
|---|---:|
| `TestBadgerLifecyclePinnedReaders` | 0.04 |
| `TestBadgerLifecycleFailedStageRecovery` | 0.08 |
| `TestBadgerLifecycleCompactionReclaimsVersions` | 0.07 |
| `TestBadgerLifecycleMaintenanceLimits` | 0.01 |
| `TestBadgerLifecycleConcurrentViewPublish` | 0.01 |
| `TestBadgerLifecycleRepeatedFailuresBoundDirtyKeys` | 0.17 |
| `TestBadgerRecoveryDistinctKeyBudgetAndSeek` | 0.03 |
| `TestBadgerRecoveryEmptyZeroBudget` | 0.01 |
| `TestLegacyClaimV4BothBackends` | 4.92 |
| `TestLegacyClaimV4DurableRestart` | 0.60 |
| `TestStreamingReplayMatchesAndRejectsCorruptState` | 3.50 |
| `TestStreamingReplayPinsTrustedGenesis` | 0.08 |
| `TestResourceV4ShapeBoundaries` | 0.00 |
| `TestResourceMaximumEncodedUndoBoundAndIsolation` | 0.00 |
| `TestResourceBadgerUndoPredecodeGuard` | 0.03 |
| `TestResourceStoresRejectOversizedUndoAtomic` | 0.07 |
| `TestResourceV4MaximumShapeStoreParity` | 0.06 |
| `TestResourceV4NativePaymentFullPipeline` | 12.69 |
| `TestSP1ConsecutiveEqualFees` | 20.07 |
| `TestSP1TweakedRecipientSpendability` | 0.05 |

These tests exercise real Chain.AddBlock/ValidateTransaction/reorg/restart
where named; raw storage capacity fixtures are explicitly separate. Actual
cryptographic legacy/native full-entry tests retain signatures, range proofs
and conservation; no shape-only acceptance was introduced.

## Finite maximum-shape storage checks

Exact build and execution commands/environment/exit/timings:
`logs/blockers-v4-final/capacity-results.json`. The standalone package test
binary was built from the same frozen source. Both1024-block replacement runs
passed with complete undo readback, GOMEMLIMIT512MiB, zero swaps:

| Backend | Test seconds | Wall seconds | Peak RSS KiB | Exit |
|---|---:|---:|---:|---:|
| memory | 0.41 | 0.479 | 380748 | 0 |
| badger | 6.09 | 6.147 | 810512 | 0 |

These fixtures use synthetic INVALID proof bytes and raw Store APIs. They do
not claim1024 fully cryptographically valid blocks, full Chain.ReorgTo peak
memory, a universal RSS ceiling or a latency bound. Experimental target>=2GiB;
Go memory limits are soft. No larger public or destructive load test ran.

## Preserved initial failures and correction

The initial integration attempt in `logs/blockers-v4/` is preserved:
ordinary test exit1 (129.005s), storage exit1 (101.611s), race exit1
(350.911s). All failed only TestResourceV4ShapeBoundaries:
`maximum shape:63240, want62984` after64 new ID bytes/input were charged.
The expectation still described the old input schema. The corrected maximum
fixture now also fills88 public-key bytes, giving63592 bytes, and asserts+1
rejection. No consensus bound, signature/proof check or monetary rule was
weakened. Final successful runs are separate files, not overwritten failures.

The independent integration review also required native P2P bounds to use the
canonical chain accounting. This was corrected before the final source freeze;
decoder and pool claim-charge/removal regressions passed in the full runs.

## Migration diagnostic

Executed locally, read-only:
`python3 audit/tools/scan_legacy_headers.py /home/pasich/repo/noso/BLOCKS --output audit/LEGACY_ARCHIVE_V4_HEADER_DIAGNOSTIC.json`.
Exit0;4.261s;180032 files/1424238 declared orders inventoried. JSON pins the
script hash. This checks headers and declared sizes only, not signatures,
MD5 links, PoS/MN economics, canonical provenance or authorized balances.

## Outstanding release blockers and next safe steps

- NX-018/NX-019 remain High: independent cryptographic soundness and reviewed
  secret arithmetic. Use EXTERNAL_CRYPTO_REVIEW_PACKET.md; no external report
  has been supplied or fabricated.
- NX-020 remains High: authenticate historical archive/rules and independently
  reconcile per-owner balances/issuance, malformed accounts,400NOSO discrepancy
  and GVT policy before approving any migration genesis.
- Exercise a maximum cryptographically valid fork and long-history replay
  capacity, actual eligible value-log rewrite, restoration-specific crashes
  and storage I/O/power-loss scenarios. Permanent faults can retain versions
  until durable progress; long readers intentionally pin versions.
- Prior wallet, global P2P/Sybil, LWMA equivalence and history secret-scan gates
  are not closed by this pass. No new fuzz campaign, coverage, staticcheck,
  govulncheck, gosec, cross-platform or reproducible-build run is claimed here.
  Earlier results remain historical evidence in TEST_REPORT.md.

SP1 repeated-fee collisions remain fixed; SP2 retained-prefix RAM copying and
SP3 aggregate single-transaction capacity are addressed by suffix/fenced design.
Version4 adds explicit limits/lifecycle/replay safeguards; broader production
capacity is still a gate. See BLOCKERS_V4.md for per-file invariant mapping.

**RESEARCH ONLY / MAINNET BLOCKED.** Suitable for targeted independent review
of an unsafe research protocol, not a final external release sign-off. Source
publication requires maintainer disclosure/secret review; no publication occurred.

Verified implementation commit: `f4169f5f25853be6031fe39fc9bf9e15c20acabb` (local only).
