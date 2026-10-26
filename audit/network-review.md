# Remote boundary review

Scope: every production file under `v2/p2p`, `v2/rpc`, `v2/mempool`,
`internal/network`, and `cmd/nosoxd/main.go`; maintained tests were inspected.
Baseline is 6179eb56d53768a19950f07e9c806fd384572c5d. Production changes began
only after the lead reported all original build/test/vet/race commands exit 0.
All sockets exercised here were numeric loopback sockets or `net.Pipe`; no public
seed/bootstrap hosts were contacted by this review.

## Reproduced findings and remediation

1. **High: legacy remote process panic and unbounded line allocation.** A line
   containing spaces/tabs caused `strings.Fields(line)[0]` to panic. An attacker
   could also send unlimited data without newline because `ReadString` collected
   the entire line before enforcing the 8 KiB limit. The two new regression tests
   failed on the original code: `index out of range` and connection still open
   after sending an overlong unterminated line. Fixed with bounded `ReadSlice`,
   an empty-fields check, 128 concurrent-connection slots, close-on-context-cancel,
   and active-connection shutdown. Regression tests pass.
2. **High: legacy signer/address confusion.** An attacker generated a key,
   replaced the order address with another generated address, signed the
   victim-address message with the attacker's own key, and received `OK` from
   `handleSubmitOrder`. The handler now derives the sender address and requires
   equality before signature verification. The missing general check in
   `internal/blockchain.VerifyOrder` was reported to the lead. Parsing also
   rejects int32 truncation, invalid line counts, extra fields, negative amounts,
   and zero-value transfers. No fee/reward schedule was changed.
3. **High: unauthenticated wildcard RPC administration.** The daemon defaulted
   to `:7780`, warned but continued without a token, and had no HTTP server
   timeouts. Default is now `127.0.0.1:7780`. Explicit non-loopback or hostname
   binds require a token; numeric IPv4/IPv6 loopback is recognized with
   `net.ParseIP`, rather than vulnerable string prefix checks. Partial TLS
   configuration and unknown network names fail startup. Browser-origin requests
   cannot invoke unauthenticated administrative methods on a local node. Remote
   authenticated HTTP remains an explicit operator option; TLS is not silently
   configured or assumed.
4. **Medium: unbounded and ambiguous RPC input.** Before the fix, >1 MiB request
   bodies and trailing second JSON values were accepted. Negative/fractional/
   out-of-range float heights silently converted, and uint64 heights lost
   precision through float64. Negative tests demonstrated each. RPC now limits
   bodies to 64 KiB, requires exactly one JSON-RPC 2.0 object, uses `json.Number`,
   parses exact uint64 heights, validates thread counts against available CPUs,
   and refuses mining when no daemon-owned context exists. HTTP header/read/
   write/idle deadlines are configured. `genesisinfo` now uses the captured
   genesis configuration rather than a different default.
5. **High: unvalidated transaction admission and mutable ownership.** `Pool.Add`
   accepted arbitrary kernel-only data, panicked on nil, and retained caller
   pointers; `Snapshot` exposed the same pointers. IDs omitted every input,
   output, range proof and signature. Negative tests reproduced the nil panic,
   acceptance without validation, and identical IDs for different bodies. Pool
   construction now requires a real validator to admit transactions; bare `New`
   deliberately fails closed. The daemon wires `Chain.ValidateTransaction`.
   IDs use canonical `types.TransactionID`. Admission enforces cheap bounds before copying or hashing; admission and
   snapshots deep-copy nested slices. The canonical duplicate error is typed;
   gossiping a locally pre-admitted transaction rechecks real current chain
   validation before accepting the duplicate for publication. Input and kernel indexes reject conflicting/overlapping
   transactions in linear time; entry count, field sizes and a 64 MiB aggregate
   body budget bound retention. Test-only validators exist solely in pool unit
   tests, explicitly labeled. Consensus remains independently enforced at block
   application, including when the chain changes after pool admission.
6. **Medium/high: unbounded peer bookkeeping and unsafe application decoding.**
   The sync-rate-limit map never called its GC; 10,000 distinct identities
   produced 10,000 entries. A concatenated second gob object was silently
   accepted. These two regression tests were run against exact baseline P2P
   production files copied into `/tmp/noso-boundary-repro` and both failed.
   The map now caps at 4,096 records and opportunistically expires old peers.
   Wire serialization migrated from gob to size-bounded JSON. Slice allocation
   follows consumed bytes rather than trusting gob element counts. Exactly one
   value, known fields, counts and per-field lengths are enforced. Full gossip
   payloads and sync responses cap at 16 MiB; requests and HELLO cap at 1 KiB.
   Block count/field limits match consensus limits. HELLO and sync protocol IDs
   are `/noso/hello/2` and `/noso/sync/2`; gossip topics end in `blocks-v2` and
   `txs-v2`. Original gob fuzz fixture bytes remain rejected migration seeds.
7. **High: hostile sync responses and uncancellable reads.** A peer could supply
   nil blocks and cause a dereference panic in catch-up; range responses were
   not required to match the requested sequence. The client now rejects nil,
   excess, out-of-range and noncontiguous blocks before use. Stream reads reset
   immediately on context cancellation, rather than waiting 15 seconds. Tests
   exercise malicious local libp2p responders and a stalled read. Range arithmetic
   rejects overflow-sized ranges; an inclusive loop explicitly terminates at the
   requested endpoint. Catch-up arithmetic avoids uint64 wrap. Rate-limit errors
   are classified and retried after five seconds with cancellable backoff, so
   legitimate cold sync can exceed the original three-batch burst.
8. **Medium: unbounded background work and incorrect bind behavior.** Cold sync
   and reorg now share one in-flight fetch lock. Incoming sync handlers cap at
   eight. Background tasks register atomically with shutdown and are joined;
   inbound/outbound sync streams reset on cancellation. Pubsub validates with
   two workers, two concurrent validations and eight queued messages. Transaction
   validation/admission and full next-tip block validation happen before
   forwarding. Fork announcements trigger bounded fetch and are ignored for
   relay until validated against their complete competing suffix. Seed records/dials and relays
   have finite caps. The legacy pending pool caps at 2,048 entries and no longer
   mutates an optional service pointer during concurrent requests. Archive ZIP
   and GVT handlers stream files rather than allocating complete file copies.
   The daemon preserves a requested P2P numeric bind IP; previously it discarded
   the host part and always exposed wildcard interfaces.

The pinned libp2p implementation was inspected locally: its default resource
manager installs a fixed autoscaled limiter (memory between 128 MiB and 1 GiB,
1/8 physical memory), and default connection manager uses 160/192 low/high water
marks. Those protections remain enabled; application limits above supplement
rather than bypass them. Connection-manager watermarks are trimming thresholds,
not a claim of a hard concurrent-connection ceiling.

## Verification evidence

Environment: Go 1.27.3 linux/amd64, GOMODCACHE=/home/pasich/go/pkg/mod,
GOCACHE=/home/pasich/.cache/go-build, package build parallelism `-p 2`.

- `go test -p 2 ./internal/network ./v2/mempool ./v2/rpc ./v2/p2p ./cmd/nosoxd`
  exited 0 after fixes (P2P 6.699s).
- Fresh full owned-package `go test -race -p 2 ... -count=1` exited 0
  (network 1.177s, mempool 1.016s, RPC 1.034s, P2P 18.037s, daemon 1.030s).
  This includes block pre-forward rejection, stalled-stream cancellation and
  backoff cancellation. The final canonical-duplicate publication regression
  was subsequently reproduced and fixed; final P2P/mempool race result follows.
- `go vet -p 2` over all five owned packages exited 0.
- `git diff --check` over owned paths exited 0.
- Bounded `FuzzBlockDecode` run, 3 seconds/two workers: exit 0, 632 executions.
- Bounded `FuzzTxDecode` run, 3 seconds/two workers: exit 0, 12,427 executions.
  These are short smoke runs, not exhaustive fuzz assurance.
- `TestThreeNodePropagationRestartAndFork` creates three isolated loopback
  libp2p hosts, propagates a signed-coinbase block across two gossip edges,
  stops C, saves its chain, reopens a fresh chain object from the actual saved
  directory, creates a fresh C host and catches up. A longer valid competing
  suffix is then fetched over sync and independently applied via `ReorgTo` on
  both receivers; exact tip hashes must converge. This is a same-process
  transport/storage restart scenario, not a three-container/process deployment.
  `TestThreeNodeInvalidBlockIsNotForwarded` also sends a corrupted signed
  coinbase through an intentionally malicious source to a validating middle
  peer; a downstream observer sees zero invalid blocks. A valid control block
  must subsequently reach that same observer, avoiding a vacuous mesh test.
  It does not establish eclipse/Sybil resistance or deep-fork discovery.

## Limits and migration implications

- Protocol v2 is intentionally incompatible with old gob peers. Coordinated
  migration and the lead's chain-state/genesis trust procedure are required.
- A node does not relay an economically unvalidated fork announcement. A peer
  that only hears that announcement through a validating intermediary may
  need a later valid head or reconnect/HELLO exchange to discover the fork.
- The reorg fetch discovery window still walks only a small recent suffix;
  very deep forks may need an operator-assisted full resync. Accumulated-work
  choice and atomic validation belong to chain, not peer height claims.
- Public read RPC methods can still consume resources within their body/server
  limits. Internet-scale authenticated TLS termination and IP-based request
  throttling are operational concerns not established by these local tests.
- Mining and cryptographic routines do not universally accept request contexts;
  body/count bounds and admission concurrency bound work, but a timeout cannot
  forcibly interrupt arbitrary ongoing CPU code.
- `TestPreAdmittedNativeTransactionGossips` creates 60 valid signed-coinbase
  blocks on each of two nodes, generates a real range-proven native output,
  signs the ordinary excess for the mature spend, admits it through
  `Chain.ValidateTransaction`, and publishes it to the peer. It first failed
  after local admission with `validation failed` (9.98s): the newly added
  pre-forward validator mistook the exact local duplicate for an invalid tx.
  After the typed duplicate/fresh-validation fix it passed (9.456s). No
  permissive validator or fabricated UTXO is used in this integration. This
  does not establish a complete interactive wallet payment flow or economic/
  cryptographic production readiness.
- No public network, deployment, balance migration, or issuance policy was
  changed or tested by this scope.

Final owned-scope verification after the pre-admitted native publish fix:
`go test -race -p 2 ./v2/mempool ./v2/p2p -count=1` exited 0,
with mempool 1.013s and P2P 42.029s. The latter includes the real mature
coinbase/native-proof transaction propagation regression and both three-node
scenarios. The final legacy read-deadline adjustment separately passed
`go test -race -p 2 ./internal/network -count=1` (exit 0, 1.186s).

Post-freeze second-pass note sent to the lead: a peer-controlled sync `Err`
string should be capped at 1 KiB before interpolation into error/log text;
otherwise the 16 MiB response-frame limit still allows log amplification.
This note must be resolved or retained as an explicit remaining limitation in
the integrated report. No further production changes were made by this agent
following the freeze signal.
