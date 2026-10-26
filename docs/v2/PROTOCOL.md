# Experimental version-4 validation rules

**Unsafe research specification. Mainnet blocked.** This describes this branch,
not the prior version-1 wire format or an independently reviewed protocol.
[Breaking changes and open decisions](../../audit/PROTOCOL_CHANGES.md) are normative
for compatibility. Existing histories are not silently grandfathered.

## Header and body binding

`types.EncodeHeader` serializes big-endian Version(uint32), NetworkMagic(uint32),
Height(uint64), Timestamp(int64), PrevHash(32), OutputRoot(32), KernelRoot(32),
TotalKernelOffset(33), Difficulty(uint64), Nonce(uint64). HeaderID is SHA-256.
Version must equal 4, network must match the parent's, offset must be all zero.
Offsets have no supported algebra and are rejected.

`types.BlockRoots` independently hashes complete ordered body lists. OutputRoot
is SHA-256 of domain `NosoX/block/outputs/v4\0` plus output count and length-
delimited encoded outputs. KernelRoot uses `NosoX/block/inputs-kernels/v4\0`
plus the input list and signed kernel list. Every list count and variable field
length uses big-endian uint64. See `types/commitments.go` for exact field order.
These are ordered list commitments, not the old duplicate-last Merkle trees.
Proofs, input ownership fields, signatures and otherwise-unused metadata are bound.

KernelID hashes `NosoX/kernel/v2\0`, feature, fee, lock height and excess, excluding
its own signature. OutputID includes all fields and the proof. TransactionID uses
`NosoX/transaction/v4\0` and both complete lists. Canonical nil and empty
slices have the same zero-length encoding. Unsupported nonempty metadata fails
validation. Cut-through/proof rewriting is not supported by these commitments.

## Authorization and supply

Each input must match an unspent stored commitment and its feature/metadata;
inputs are unique, and coinbase spends require at least 60 blocks of maturity.
New output commitments and kernel IDs must also be unique over active-chain
history, preventing reuse after spending. Reorg removes orphaned identities.
Legacy/GVT outputs are genesis-only. Version4 legacy spends name exactly one
Plain output and one zero-fee, zero-lock LegacyClaim kernel using their IDs.
The trusted active source tuple, canonical genesis, network and exact destination
leg are signed with canonical uncompressed historical key text and strict DER,
low-S ECDSA-SHA256. The key text must derive the stored owner address. Each leg
satisfies `destinationCommit-sourceCommit=kernelExcess` with a valid Schnorr
signature; shared/missing/unreferenced legs fail. Native inputs forbid all claim
fields. See [exact ownership procedure](../../audit/legacy-ownership-procedure.md).
This authorizes only operator-trusted source state, not historical issuance.

Every ordinary kernel verifies the custom 65-byte Schnorr signature over KernelID
with its canonical nonidentity excess point as public key; lock height must not
exceed block height. Coinbase has exactly one output and matching kernel while
BlockReward(height)>0; both are absent afterwards. Coinbase fee=0 and kernel
lock=height+60. Its signature is mandatory under `commit-reward*H`, with the
wallet's height/amount/commit transcript. No claim of cross-network signing
intent guarantees beyond the enforced header domain is made.

The transfer equation is `sum(plain outputs)-sum(inputs)+fee*H=sum(tx excesses)`.
Coinbase is separately constrained to the existing subsidy. Fees go to a transparent dev-fund output
`fee*H+DevFundPoint+t*G`, with the version3 public scalar from DEVFUND.md. The
amount and recipient are unchanged. Every fee sum must fit int64. Equal fees
in distinct block contexts no longer force duplicate commitments; historical
uniqueness remains enforced. There is no burn feature. Issued supply includes all
locked/unclaimed outputs and the explicitly trusted genesis allocation.

Plain outputs require the version-2 bit-decomposition OR proof, exact shape plus
real cryptographic verification. The old version-1 shape-only branch is gone.
This custom proof system and secret-dependent arithmetic need external review.

## Headers, work and state

A non-genesis block must extend the active tip at height+1, advance timestamp,
be no more than two hours ahead of validator UTC time, match expected difficulty
and checkpoints, and satisfy Argon2id PoW. Clocks are an explicit trust assumption.
PoW remains 64MiB, one pass/lane with the original fixed salt and encoded header.
Zero difficulty is invalid. Difficulty uses the existing weighted-window formula
with exact big integers and uint64 saturation. Equivalence to a published LWMA-3
variant has not been established. Missing history fails closed.

Forks must have strictly greater sum(floor(2^256/(target+1))) over the divergent
suffix; equal work does not replace the tip. The effective suffix/depth cap is
1024, not the previously advertised 5400. Candidates validate against a suffix overlay using complete persisted undo
records. Retained history is read through rather than copied. Memory publishes
only the prepared touched-key delta under the Chain mutex. Badger stages chunks
at a fresh managed timestamp and synchronously publishes one active-state fence;
readers cannot see partial chunks. Interrupted future writes are restored or
tombstoned before a later fence publishes. Memory snapshots require explicit
Save/Close. Badger tracks pinned snapshots and advances discard to the minimum
active/read timestamp; old readers retain versions they need. Abandoned-key
restoration publishes separately before a different candidate. Recovery records
at most 65536 distinct future keys and skips older same-key versions, failing
closed above the cap. Periodic maintenance makes one GC attempt per interval;
persistent I/O failure can still grow disk until durable progress succeeds.

The operator-supplied genesis is a local trust anchor. Reopen checks its hash and
replays all non-genesis history into a disposable bounded-cache disk-backed
store, then compares persistent state with ordered streaming iterators. Full
replay time and scratch disk remain O(history); startup can fail on insufficient
space, without accepting inconsistent state. This is
not a canonical mainnet genesis or proof of historical economic correctness.

## Bounds and wire

Native consensus bodies: at most 4 inputs/outputs/kernels each and 64KiB
accounted body; proof<=14529 bytes, address/signature text<=256 bytes each,
legacy public-key text<=88 bytes, kernel signature<=65 bytes. Body charge is
128 per item plus variable bytes plus 64 per input for the two claim IDs.
Depth remains1024; the aggregate native body envelope is64MiB. Undo is bounded
before cloning/decoding. Trusted genesis retains10000 records/8MiB, has no
inputs/kernels and permits only separately validated allocations. It cannot be
an incoming reorg block. These rules change consensus; use fresh disposable data.
The experimental process target is at least2GiB; no whole-process RSS ceiling,
256MiB support or maximum cryptographically valid fork timing is established.
Mempool/network admission may be stricter. Version-2 topics and `/noso/*/2`
streams use bounded JSON instead of gob; sync ranges<=64 blocks, framed response
<=16MiB. These limits are not a proof against all resource exhaustion or Sybils.
