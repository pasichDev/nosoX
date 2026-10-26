# Version 4 resource envelope remediation

This is an explicit research-protocol hard fork. It changes block acceptance,
not rewards, GVT allocation, developer fees, proof verification or signatures.
The supported experimental target is a **2 GiB process working set**, subject to
measurement. No 256 MiB claim is made; Go's memory limit is a soft GC target,
not an RSS limit. This document does not establish a production capacity SLA.

## Plan and implementation

- [x] Replace native block item limits with four inputs, four outputs and four
  kernels, with a 64 KiB structural body envelope and current 14529-byte proof
  encoding ceiling. Keep depth 1024.
- [x] Preserve the separate trusted-genesis allocation envelope (10000 items,
  8 MiB), including all 100 GVT slots. Genesis cannot be an incoming reorg block.
- [x] Check native body bounds before raw backend/overlay allocation; check
  incoming aggregate before rollback staging. All consensus-legal native
  1024-block suffixes fit, so there is no smaller local fork-admission ceiling.
- [x] Add `Store.UndoAtBudget` with memory charge checks before proof cloning and
  Badger raw-record bounds before gob decoding, followed by decoded checks.
- [x] Transfer isolated undo ownership instead of copying proofs a second time
  during rollback and overlay writes.
- [x] Exercise deterministic boundaries, the former v3 maximum's rejection,
  both backends, real signed/proven native payments, and finite 1024-block raw
  maximum-shape storage transitions.

Canonical constants live in the source; `BodyResourceBytes` uses the original
128-byte/item structural accounting unit plus 64 bytes per input for the two
claim-leg IDs (and the bounded public-key text). It is not Go heap usage or a JSON
wire-size estimate. A native payment fits: one or up to four inputs, two plain
payment/change outputs, coinbase and developer-fee outputs use all four slots.
Validation still verifies every actual signature and plain-output proof.

## Equations and comparison

The previous structural rules permitted a spent-output undo record approaching
`10000 * (128 + 65536 + 256) = 659200000` charged bytes, about 629 MiB for one
record. Even accepted 14529-byte proofs allowed roughly 143 MiB per 10000-input
record and approximately 140 GiB across depth 1024. A native incoming suffix
alone could contain `1024 * 8 MiB = 8 GiB` of charged body bytes. No such
previous maximum was asserted to fit a small device.

For version 4:

- Maximum structural shape (all field ceilings together):
  `4*(192+256+256+88) + 4*(128+14529+256) + 4*193 = 63592` bytes, below 64 KiB.
- Incoming-body aggregate: `B <= 1024*65536 = 64 MiB`.
- One undo: `4*(128+14529+256) = 59652` charged bytes.
- Aggregate incoming undo: `U <= 59652*1024 = 58.254 MiB`.
- Aggregate restored rollback outputs: `R <= U`.
- Maximum gob undo guard: `2*59652+4096 = 123400` encoded bytes. The actual
  maximum-field four-output fixture encodes to 59490 bytes. The loose encoded
  cap covers type descriptors and field/length prefixes of this fixed schema;
  post-decode count/field/charge checks are still required.
- Candidate validation and backend publication can retain two overlays. Each
  charges no more than `B+U+R` in principal body/proof payload, or about
  180.51 MiB. Counting both overlays, caller body and serialized block/undo/UTXO
  payload at one charge per byte gives `5B+3U+3R < 670 MiB`.
  Even allowing twice the structural charge for serialization brings the
  principal payload estimate below 1 GiB. **This excludes Go objects/maps,
  allocator slack, gob buffers, GC-retained garbage, Badger caches, write-batch
  bookkeeping and all canonical in-memory history. It is not an RSS bound.**
- At most four range proofs and four kernel signatures per block: depth 1024
  entails at most 4096 proofs, or 262144 bit OR-proof verifications, and 4096
  kernel signatures. Coinbase maturity checking can additionally read up to
  `4*59*1024` historical blocks. These are finite work bounds, not latency claims.

Trusted genesis remains a separate, trusted and non-rollbackable allocation
input. Full-history startup replay, trusted import, in-memory canonical history
and Save are history-sized operations; this change does not call them bounded
routine reorgs.

## Verification actually run

Environment: Go 1.27.3, `GOMODCACHE=/home/pasich/go/pkg/mod`,
`GOCACHE=/home/pasich/.cache/go-build`, `GOPROXY=off`, `-p 2`.

`go test -p 2 ./v2/chain -run '^(TestResource|TestBadgerFencePrevious)' -count=1 -v`
passed before adding the opt-in 1024-block fixture. It exercised exact item,
field and proof boundaries and +1, aggregate depth 1024 and +1, maximum encoded
undo, budget boundary and -1, ownership isolation, malformed oversized raw gob
rejection before decode, both raw stores and native Chain.AddBlock acceptance.
The real full pipeline passed on memory (5.41 s) and Badger (5.54 s), total
10.95 s. It spends four genuinely matured coinbases and constructs two actual
range proofs, an authorized native kernel, fee destination and coinbase, then
checks atomic rejection of an additional input. These timings are observations,
not benchmark guarantees.

Finite maximum-shape runs used a prebuilt standalone package test binary and
`/usr/bin/time -v`, with `GOMEMLIMIT=512MiB`:

```
go test -p 2 -c -o /tmp/noso-resource-chain.test ./v2/chain
NOSO_RESOURCE_MAX_SUFFIX=1 GOMEMLIMIT=512MiB /usr/bin/time -v \
  /tmp/noso-resource-chain.test \
  -test.run '^TestResourceMaximumSuffixSynthetic1024$' -test.count=1 -test.v
NOSO_RESOURCE_MAX_SUFFIX=1 NOSO_RESOURCE_MAX_BACKEND=badger \
  GOMEMLIMIT=512MiB /usr/bin/time -v /tmp/noso-resource-chain.test \
  -test.run '^TestResourceMaximumSuffixSynthetic1024$' -test.count=1 -test.v
```

Both ran 1024 canonical blocks and 1024 replacement blocks, each with four
outputs carrying full-size synthetic proof bytes, four inputs except genesis,
four kernels and maximum metadata fields. Each replacement published and all
1024 complete undo records remained readable within the budget.

| Backend | Test time | Maximum RSS | Swaps | Exit |
|---|---:|---:|---:|---:|
| Memory | 0.29 s | 387720 KiB (378.6 MiB) | 0 | 0 |
| Badger | 5.99 s | 780568 KiB (762.3 MiB) | 0 | 0 |

The fixture deliberately uses synthetic invalid proof bytes and raw Store APIs;
it is a retention/serialization test, not a cryptographically valid maximum
fork. It does not run Chain.ReorgTo's extra authorization overlay. These results
cannot be extrapolated into a whole-process worst-case RSS guarantee.

## Remaining assurance limits

A full 1024-block cryptographically valid maximum-work fork has not been
constructed and timed. Maximum-shape tests do not cover every arrangement of
independently retained rollback outputs or every Go/Badger configuration. The
2 GiB experimental target therefore remains a test target rather than a proved
universal working-set ceiling. There is no operationally smaller per-call
reorg cap, so a legal suffix is not deliberately stranded by a local RAM policy.
The protocol's existing 1024-block finality/depth policy itself is unchanged.

Badger now publishes abandoned-write restoration as a standalone same-state
fence before staging any new candidate. Failed restoration cannot add candidate
keys, so dirty key identities remain bounded by one stage. Restoration and an
already computed new candidate can nevertheless coexist in memory. The clean
stage equations above do not include that additional restoration buffer.
Repeated failed restorations can still add physical MVCC versions above active;
recovery scan time and disk reclamation depend on eventually publishing a
successful restoration. See REMAINING_BLOCKERS_SECOND_PASS.md and the lifecycle
report for the reviewed guarantees and remaining capacity-test gaps.

Independent cryptographic review and legacy ownership/supply trust remain
separate gates. **RESEARCH ONLY / MAINNET BLOCKED** remains the conclusion.

## Final integrated source rerun

After adding the two32-byte claim-leg IDs (64bytes total/input) and88-byte
public-key ceiling, the maximum charged shape is63592bytes. The corrected
fixture was recompiled and run again; exact command/environment/exit metadata
is in logs/blockers-v4-final/capacity-results.json. Memory test0.41s,
peak380748KiB; Badger test6.09s, peak810512KiB; both exit0 with zero swaps.
The limitations of synthetic raw proof fixtures above remain unchanged.
