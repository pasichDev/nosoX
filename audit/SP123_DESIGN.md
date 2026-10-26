# Follow-up design: SP1/SP2/SP3 remediation

Base:34f0d0d, branch security/consensus-hardening. Prior commits, reports and raw
logs remain historical evidence. Latest user instruction authorizes fixing the
remaining issues. No public cryptocurrency network, deployment, publishing or
repository setting changes. Existing economic constants and recipient unchanged.

## SP1: context-bound public blinding tweak

For positive fee F and fixed recipient public point P=dG, define a canonical
public scalar t from a distinct v3 hash domain and network, height, parent hash,
F. The output is F*H+P+tG; spending scalar is (d+t) mod n. This uses existing
Pedersen/curve operations. Fee amount and recipient ownership do not change.
Roots, timestamp and nonce are excluded from the tweak to avoid a circular block
template or changing rewards during nonce search. No historical uniqueness
exception, forged signature, output overwrite or new cryptographic primitive.
Canonical nonidentity output is required. Public-key addition does not establish
soundness of the custom proof system or constant-time secret handling.

BlockVersion3 explicitly rejects former rules. The v2 body encoding remains the
same; this is not a live-network upgrade or silent database migration. Tests must
exercise sequential equal positive fees through real AddBlock on both stores,
wrong-context rejection, restart and fork handling, plus independent algebra.

## SP2: suffix-only isolated state

Store.UndoAt(height) supplies exact original spent output records. Store appends
persist these alongside block deltas. A fork overlay rolls back only the old
suffix (<=1024) and applies incoming blocks against a read-through canonical
prefix. Changes/tombstones cover blocks, undo, hash indices, UTXOs, historical
commitment/kernel identities, legacy indices and tip. All incoming blocks pass
the same validator and accumulated-work rules before atomic ReplaceSuffix.
Memory history uses a height map, avoiding prefix copying on slice growth.
Full-history work remains permitted for explicit snapshot Save/startup verification,
not routine reorg/undo. Tests count prefix accesses even for a later-invalid
candidate, compare complete metadata and ensure failures do not mutate state.

## SP3: staged MVCC state and one publication fence

Badger managed transactions stage a delta at a fresh, never reused timestamp.
Write batches may flush chunks larger in total than a single transaction limit.
Readers only see the committed active timestamp; a small durable marker publishes
the complete staged state after every chunk is durable. Ordinary appends use the
same design, because block+UTXO encoding can exceed one transaction too.
Read operations capture a coherent timestamp. Old un-fenced schema is rejected.

Aborted future versions MUST NOT become visible when a later timestamp publishes.
Dirty keys are restored from the active snapshot at a new timestamp before the
next publication; restart recovers unpublished versions, including tombstones.
Discard/GC policy must retain the active snapshot and uncommitted recovery data.
Crash before fence exposes old complete state, after fence exposes new complete
state. Every validation/error boundary keeps live state unchanged before publish.
A failed commit at the OS durability boundary can have uncertain outcome; no
claim exceeding Badger/OS durability guarantees is permitted.

Tests must include multiple batches, errors/crashes before publication, reopen,
retry after an abandoned stage, deleted keys, subsequent valid appends/reorgs and
maximum consensus-size delta representative checks. Previous expected-ErrTxnTooBig
regression is explicitly migrated to successful large atomic publication plus
injected prepublication failure tests, not deleted or weakened to hide a failure.

## Integration and remaining gates

Lead independently reviews diffs and fault paths, runs build/vet/full tests/race
on frozen integrated source, preserves failed attempts and updates current docs.
Custom proof-system review, side channels, historical migration trust and broader
resource/crash assurance remain separate release gates regardless of these fixes.
