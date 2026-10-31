# Wallet

The wallet builds real two-party Mimblewimble payments. Mined coins can be
spent: the sender and receiver exchange two slates, the sender aggregates the
kernel signature and submits the transaction to a node with `submittransaction`.

Verified by tests: a real miner on both the in-memory and Badger chain stores
mines past coinbase maturity, a payment is built with `wallet pay`, `receive`
and `finalize`, admitted to the mempool, mined and accepted by `AddBlock`; the
receiver spends the output onward to a third wallet; the node restarts; a reorg
removes the payment and the stored transaction is resubmitted with the same
signature. A second test drives the real `nosoxd` and `nosox-cli` binaries.

## Commands

```
nosox-cli wallet new <wallet>
nosox-cli wallet pay <wallet> <node-rpc> <amount> <fee|default> [memo]
nosox-cli wallet receive <wallet> <slate|@file> [node-rpc]
nosox-cli wallet finalize <wallet> <slate|@file> <node-rpc>
nosox-cli wallet outputs <wallet>
nosox-cli wallet balance <wallet>
nosox-cli wallet sync <wallet> <node-rpc>
nosox-cli wallet cancel <wallet> <txid> [--force]
nosox-cli wallet import-coinbase <wallet> <coinbases.json>
```

Amounts and fees are integers in base units (1 coin is 100,000,000 units).
Nodes refuse to relay a transaction whose fee is below the relay minimum, 1000
units per 1000 bytes of accounted size: about 29,700 for a payment with one
input and about 30,300 for four. `wallet pay` prints these numbers in its usage,
and `default` pays the four-input figure, which clears the minimum whatever
inputs are selected. A signed transaction with too low a fee stays stored; the
node answers `-32010` ("fee too low for relay (policy)"), so `cancel --force` it
and pay again with a higher fee.

> **Slates are not authenticated or encrypted, and there is no payment proof.**
> Whoever receives a payment offer can answer it, and the sender pays whoever
> answers first; nothing in the slate names the intended recipient, and afterwards
> neither side can prove who was paid. An attacker who can read the channel the
> offer travels over (chat, mail, a relay) can answer it with their own wallet and
> return the response. Send offers only over a channel you trust, check the
> recipient out of band, and treat a large payment like cash handed to whoever
> says "that's me". The CLI repeats this warning every time it prints a slate.
> A receiver address with a signed response and a payment-proof signature would
> close this; it is not implemented.

Before it signs or answers, the CLI prints the amount, **fee, lock height and
memo** (and the node) and, on a terminal, asks for confirmation; `--yes` skips the
question, and it is skipped when stdin is not a terminal. Text from a node or a
memo is stripped of terminal control sequences before it is printed.

- The passphrase is read from the terminal. When stdin is not a terminal the CLI
  reads one line from stdin instead (for scripts and tests). It is never read
  from arguments or the environment.
- `wallet new` takes a passphrase of at least 12 characters (asked twice on a
  terminal) and **never overwrites**: it fails if the wallet file or its
  `.outputs` file already exists, so use a new path.
- `NOSOX_CONFIRMATIONS` sets how many blocks deep an output must be to count as
  confirmed and to be spent (default 10, range 1 to 10000; below 10 prints a warning).
- The RPC bearer token is read from the environment variable `NOSOX_RPC_TOKEN`.
  There is no command-line option for it. The client accepts only `https` or a
  loopback address (plain `http` to any other host is refused, token or not: a network
  attacker could otherwise forge the answers the wallet treats as chain state), and
  does not follow redirects. A node that rate-limits the client is retried.
- `pay` and `receive` print the slate alone on stdout (instructions go to
  stderr). A slate is about 1 KB to 40 KB of text; pass `@file` to read it from a
  file.

### Typical flow

```
# Miner: bring in the reward keys, then ask the node what is on chain.
nosox-cli wallet import-coinbase miner.json /var/nosox/coinbases.json
nosox-cli wallet sync miner.json 127.0.0.1:7780
nosox-cli wallet balance miner.json

# Sender: round 1. Locks the inputs and prints the offer slate.
nosox-cli wallet pay miner.json 127.0.0.1:7780 1500000000 100000 "rent" > offer.txt
# Receiver: round 2. The node address pins the wallet's network on first use
# (a wallet that has synced before can omit it). Prints the response slate.
nosox-cli wallet receive friend.json @offer.txt 127.0.0.1:7780 > response.txt
# Sender: round 3. Signs, stores the transaction, submits it.
nosox-cli wallet finalize miner.json @response.txt 127.0.0.1:7780

# Later, both sides:
nosox-cli wallet sync <wallet> 127.0.0.1:7780
```

Re-running `finalize` with the same response slate resubmits the stored
transaction; it never signs again.

## Protocol

All points are secp256k1, all scalars are modulo n. A transaction is valid when
`sum(plain outputs) - sum(inputs) + fee*H == kernel excess E` and the kernel
carries a Schnorr signature `(R, s)` with `s*G = R + e*E`,
`e = H("Noso-v2-Schnorr" || R || E || len(msg) || msg)` and `msg =
types.KernelSigningMessage(magic, kernel)`: SHA-256 of a domain label, the network
magic and the kernel id (features, fee, lock height, excess). The magic comes from the
node at `pay` (`genesisinfo`), travels in the slate, and is enforced: `receive`
rejects a slate for another network than the wallet's, `finalize` rejects a response
whose magic differs from the node's, and a wallet is pinned to the first network it
sees. A signature made for one network does not verify on another, so a transaction
cannot be replayed across a chain split or between networks sharing outputs. Both parties contribute to `E` and `R`.

1. Sender (`pay`). Select unspent, mature outputs; the node is asked about each
   candidate (`hasutxo`), so a spent or immature output is never used. Build a
   change output with a range proof (omitted when the change is zero). Compute
   `x_s = r_change - sum(r_in)`, `P_s = x_s*G`, derive a nonce `k_s`
   (see Nonce safety), `R_s = k_s*G`. The slate carries the network magic, amount, fee,
   lock height, inputs, change output, `P_s`, `R_s` and a random 16-byte session id.
   The wallet first moves finished records to the archive to make room and fails
   with a clear error, before locking anything, only if the hard record limit is
   reached by records still in flight (see State file); inputs must be buried at
   least the confirmation depth. The
   secrets `x_s` and `k_s` and the input locks are written to disk,
   encrypted, before the slate is returned. If that write fails, no slate is
   returned.
2. Receiver (`receive`). Check bounds, the network, the change output's range proof
   and that the session id is new. The receiver cannot see the chain, so the offer's
   inputs are not checked: a made-up offer costs its author nothing. That is why
   unconfirmed incoming outputs are rationed: at most 64 pending receives, and a
   receive the node never shows is moved by `sync` to an archive after 30 days
   (never deleted; see `sync`). Create the output `a*H + r_r*G` with a range
   proof; `x_r = r_r`, `P_r`, a fresh `k_r` and `R_r`. Form `E = P_s + P_r`,
   `R = R_s + R_r`, `e`, and `s_r = k_r + e*x_r`. The receiver also checks
   that the whole commitment equation already balances against `E` (otherwise the
   sender could not build a valid transaction), verifies its own partial
   signature, and records the new output as pending before returning the
   response. `k_r` is never stored and is zeroed.
3. Sender (`finalize`). Load the context by session id and require the slate's
   amount, fee, lock height, inputs, change output (commitment and proof),
   `P_s`, `R_s` and memo to be identical to what was offered. Verify the receiver's
   range proof and that its commitment is unique, that `s_r*G = R_r + e*P_r`,
   and that `sum(out) - sum(in) + fee*H` equals `E` exactly. Compute
   `s_s = k_s + e*x_s` and `s = s_s + s_r`; reject `s = 0`; encode `R || s`
   with the compressed (parity-carrying) sum point; require `SchnorrVerify`
   to pass. Only then build the transaction.

### Nonce safety

`k_s` exists on disk only from `pay` until one atomic write during `finalize`.
That single write erases the nonce context, stores the final signed
transaction, marks the inputs spent and keeps the change pending. Only after it
is durable is anything submitted. Consequences:

- A failed verification, a tampered slate or a failed state write leaves the
  context intact and signs nothing, so nothing was exposed.
- A retry after a crash or a network failure finds the stored transaction and
  resubmits the same bytes. A different response slate for the same session is
  rejected (`slate does not match`). The sender can never produce a second `s`
  under the same `k_s`.
- `cancel` destroys the context and unlocks the inputs, dropping the change
  output; the old response can no longer be finalized. A new payment draws a new
  nonce and session id. One exception: on a payment marked suspect (below) the
  change key is **kept** in the archive instead of dropped, because that payment may
  have been signed and mined in the timeline the restore rolled back.

How `k_s` is derived: `k_s = HMAC-SHA256(state key, label || x_s || slate context ||
fresh 32 random bytes || counter)`, reduced to a non-zero scalar. It mixes a secret,
the slate's public data and fresh randomness, so a broken or repeating random source
alone cannot repeat a nonce, and two slates never share one.

What this does **not** do, and what does: `R_s = k_s*G` is published in the offer,
before the receiver has said anything, so `k_s` cannot depend on the response, and the
Schnorr challenge `e` depends on the receiver's nonce, which the receiver picks. If an
attacker could restore an old copy of the state file (a backup, a VM snapshot) after
`finalize` signed, and then feed `finalize` a different response, the same `k_s` would
sign two different challenges and leak `x_s` (with one input and no change, `x_s` is
that input's spending key). No derivation prevents that. The defence is a generation
check:

- Every state write increments a counter stored inside the encrypted state. After
  each write the wallet also writes `<wallet>.outputs.gen`, the counter with an HMAC
  under a key derived from the state key.
- On open, a state whose counter is lower than the marker's, or a state that has been
  written before but has no valid marker, is treated as restored. Every nonce context
  alive in it is marked suspect: `finalize` refuses it (`ErrRolledBack`). Run `sync`
  first: the payment may already have been signed and mined before the restore. Then
  `cancel` it (the change key stays in the archive and comes back by itself if the
  transaction is on chain), and pay again only if the money did not leave. A state
  newer than its marker (a crash between the two writes) is normal and not flagged.
  If the `.outputs` file is missing while its `.gen` marker exists, the wallet refuses
  to open instead of starting empty.
- Guarantee: restoring only `<wallet>.outputs` from a backup cannot lead to a second
  signature with a saved nonce. Limit: an attacker who restores the state file and the
  `.gen` marker together from the same old snapshot defeats the check, because the
  check cannot tell a consistent old snapshot from the present. If you restore a backup
  yourself, `sync` and then `cancel` every payment that shows as in flight. Copying a
  wallet to a new machine without its marker file gets the same treatment.

After signing, `cancel <txid> --force` releases the inputs but keeps the change
output tracked as pending, because the transaction may still be mined from
some node's mempool.

## State file

Output tracking lives in one encrypted file, `<wallet>.outputs`, next to the
keystore. It holds, per output: commitment, value, blinding factor, status
(`pending`, `unspent`, `locked`, `spent`), origin (`coinbase`, `change`,
`receive`), height, maturity and the locking transaction; plus the live nonce
contexts and the signed-but-unconfirmed transactions.

Why a separate file and not a section of the keystore: the keystore holds the
master key and must stay small, stable and unchanged by routine activity; the
output state is rewritten on every payment. Why one file and not one per kind of
record: the transitions that must be atomic together (lock inputs and persist the
nonce; erase the nonce, store the transaction and mark inputs spent) are a single
rename, so no crash can leave one half written.

- Encryption is the keystore scheme (envelope version 2): Argon2id with 3 passes,
  256 MiB and 4 lanes into XChaCha20-Poly1305 with a fresh random nonce per write, its
  own random salt, and additional data that covers a distinct label, the version, the
  salt and the Argon2 parameters, so the two files cannot be exchanged and the stored
  parameters cannot be altered. The parameters are in the file; a reader refuses
  parameters weaker than 3 passes / 256 MiB or heavier than 1 GiB. The key is
  derived once per command, not per write. The state records the wallet's public
  key and is refused for any other wallet.
- Measured cost (Apple M2, 8 cores): 0.18 s per derivation at these parameters
  (0.56 s with a single lane, which is what a one-core attacker pays per guess
  per 256 MiB). The CLI derives twice per command (keystore, then state). The old
  setting (1 pass, 64 MiB, 1 lane) took 0.05 s.
- **Migration:** version 1 files (old parameters, no additional data on the keystore)
  are still read. The CLI rewrites the keystore as version 2 the first time the wallet
  is opened, and the state file is re-keyed with a fresh salt on open. A short
  passphrase on an old wallet keeps working. There is no command to change the
  passphrase of an existing wallet (re-keying must rewrite the keystore and the state
  together); a new passphrase means a new wallet and a payment of the funds into it.
  Before the keystore is rewritten the old file is copied to `<wallet>.v1.bak` (mode
  0600, fsynced, never overwritten). The v2 keystore holds only the master seed:
  anything else an old keystore carried, such as imported legacy `v1.pkw` keys in a
  `legacy` section, exists only in that backup, still under the **old weak
  encryption**. Check that you do not need it, then delete it yourself.
- Writes go to a random temporary file in the same directory, are fsynced and
  renamed; the directory is then fsynced (on Windows the rename is made with
  `MOVEFILE_WRITE_THROUGH` instead, because a directory cannot be opened for sync
  there). File mode is 0600 (on Windows this has no effect: the file inherits the
  directory's ACL, so keep wallets in a user-private directory). If a write fails
  before the rename the in-memory state is reloaded from disk so memory never runs
  ahead of what is durable. A failure after the rename means the file **is** written
  but its durability is unconfirmed; the messages say so and never claim "not
  written".
- The state is bounded: the writer enforces the same limits the reader does before it
  touches the disk, so a state that was written can always be reopened. The real bound
  is bytes, not counts: the plaintext may not exceed 20 MiB, and the counts below are
  chosen so that every list at its limit, with every record at its widest, still fits
  (`TestWorstCaseStateFitsTheByteBound`; the worst case is about 16.5 MiB). Imports and receives stop at
  10,000 records that can still change (pending, unspent, locked); the hard limit on
  live records is 16,384, and the room between the two is for the change and the spent
  inputs of payments. **A payment is never refused by the 10,000 limit**: it consumes
  at least one input, and when the hard limit is near, spends already seen on chain are
  moved to the archive to make room. Only if 16,384 live records are all still in
  flight does a payment fail, cleanly, before anything is locked.
  **No key is deleted on a node's word.** Records of outputs seen spent on chain for 1024
  blocks, never-landed coinbase candidates 1024 blocks old and the change of payments
  that never reached a block (30 days) move to the encrypted archive; signed transactions
  whose inputs are all that deep are forgotten (they hold no secrets). 1024 is the
  maximum reorganization depth, but "spent" is only what a node said, so the key stays.
  A state written by an older build with more records opens and is pruned the same way.
- A lock on `<wallet>.outputs.lock` makes a second wallet process fail instead of
  interleaving: `flock` on Linux, macOS and BSD, `LockFileEx` on Windows. A platform
  with neither refuses to open the store.
- `outputs` and `balance` never print blinding factors.

### `sync`

`sync` asks the node about the tracked outputs that can still change and is not
monotonic, because chains reorganize. Outputs seen spent on chain for 1024 blocks are
final and are neither queried nor kept, so the node is asked about pending, unspent,
locked and recently spent outputs only. Pending becomes unspent only when the output is
at least the confirmation depth (default 10 blocks) deep; one block deep is reported
as `Shallow`. An unspent output no longer on chain becomes spent, unless the block
that created it left the chain (checked by block hash), in which case it goes back to
pending; an input reserved by a payment in progress stays reserved when its block is
reorganized away and back; a spent output that is back on chain returns to unspent,
including when the signed transaction that spent it has since been pruned; a signed transaction whose inputs reappear is reported
under `ReorgedTxs`, and running `finalize` again with the same response slate
resubmits it unchanged. A sync that cannot reach the node writes nothing.

**Tip checks.** The height a node reports decides which records count as buried, so it
is bounded before it is believed: the answers of one sync must agree within 64 blocks
and the lowest is used; the height cannot exceed what the elapsed time since 2025-01-01
allows at one block per 10 s, plus about a million blocks of margin; it cannot rise since the last sync by more than the
elapsed time allows at that rate (plus 64 blocks). A refused sync writes nothing and
says so. If your own node really is that far ahead, repeat with
`wallet sync <wallet> <node> --accept-tip <height>` (the height must be what the node
reports). A tip that falls is accepted: a correct node returning after a bad one must
work. These checks are a second line; the first is that no key is deleted.

**Trust.** Confirmations, balances and spent/unspent status are the answers of the node
you sync with. A node you do not control can report a payment as confirmed that is not
(or hide one that is) and so get goods from you without paying; use your own node over
loopback or https before handing over anything of value. Every sync prints this, and
warns when the node is not on this machine.

**The archive.** Two kinds of entry live in a compact list inside the same encrypted
state (commitment, value, blinding factor, session id, origin):

- *Receives*: an incoming output the node has not shown within 30 days, or one you
  abandoned with `wallet cancel-receive`. The sender may still hold the finished
  transaction and mine it later, and without the blinding factor those coins could
  never be spent. At most 2048; a full list makes `receive` refuse new offers and
  nothing is evicted.
- *Retired keys*: spent outputs, coinbase candidates and abandoned change moved out of
  the live set. At most 16,384 and separate from the receive limit, so they can never
  fill it. Only when this part is full is an entry evicted, oldest first, and only if the
  local clock says it was archived more than 180 days ago; nothing a node says evicts
  anything.

Neither counts against the 64 pending receives or the 10,000 records. Every `sync` asks
the node about the archive (at most 1024 entries per sync, taken round-robin). When one
appears on chain it becomes a live pending record and then confirms and spends like any
other output, so after a lying node a correct one restores everything.

### `consolidate`

`wallet consolidate <wallet> <node> [fee|default] [rounds]` merges up to 4 of the smallest
spendable outputs into one, paying the wallet itself (offer, answer and finalize in one
call). It exists for wallets full of small outputs, such as a miner's coinbases, whose
payments would otherwise need more than 4 inputs. It is not subject to the receive
limits. Run it, wait for the confirmation depth, `sync`, repeat (`rounds` does several
in a row; the outputs of one round are not spendable in the next).

### `cancel-receive`

`wallet cancel-receive <wallet> <txid>` abandons an unconfirmed incoming payment: the
record moves to the archive (key kept) and stops counting against the 64 pending
receives. The offer cannot be answered again. Fake offers that fill the quota are
cleared this way.

### `import-coinbase`

Reads the miner's `coinbases.json` **and every archived rotation beside it**
(`coinbases.json.<ts>.<n>`, written when the live file reaches 5,000 records),
recomputes each record's commitment from
(amount, blinding factor) and imports only those that match, as pending
coinbase outputs. The miner keeps a record for every block it solved, including blocks
that later lost a fork and never landed, so some imported records stay pending; they
are not counted as spendable, and `sync` moves the ones still absent 1024 blocks after
their height to the archive (key kept). When the wallet holds 10,000 unfinished outputs,
the rest is reported as `Skipped` and stays in the file you imported from (keep it): run
`consolidate`, `sync`, then import again. A full wallet can still pay. `sync` promotes the ones that are on chain, and a
coinbase is selected only when the node reports it mature for the next block
(a coinbase created at height `b` is spendable in a block at height `b + 60`).

## Slate format

`SLATEPACK3.` followed by unpadded base64url of a fixed binary layout; the layout
starts with the format version and carries the network magic after the session id.
Slates of earlier formats (`SLATEPACK1.`, Ed25519 intent signatures; `SLATEPACK2.`,
without the magic) are rejected. Decoding is bounded and strict: at most 64 KiB of text, at most 4 inputs,
at most one change output, memo at most 256 bytes of valid UTF-8 without ASCII control characters (the CLI replaces
every control and bidirectional-format character when it prints one), every point
must be a valid non-identity curve point, every scalar canonical and non-zero, no
trailing bytes, no whitespace inside the text, and the stage byte must match the
body. There is no third slate: the final transaction goes to the node.

A transaction built by the wallet has at most 4 inputs and 2 outputs, which leaves
room for the coinbase within the block limits.

## Wallet file

`wallet new` creates an Ed25519 master key and writes it as a JSON file (envelope
version 2, Argon2id 3 passes / 256 MiB / 4 lanes, parameters stored and authenticated).
The file is created atomically and exclusively (hard link; an existing file is never
replaced) with mode 0600. The passphrase must have at least 12 characters. A lost
passphrase cannot be recovered. The master key
no longer signs slates; it identifies the wallet and binds the state file to it.
Outputs are Pedersen commitments with their own random blinding factors, stored
in the state file, not derived from the seed. Losing the state file loses the
ability to spend those outputs; the wallet has no seed-based recovery. Back up
`<wallet>` and `<wallet>.outputs` together.

## Where secrets touch disk

| Where | What | Protection |
|---|---|---|
| `<wallet>` | Ed25519 master seed | Argon2id (3 passes, 256 MiB) + XChaCha20-Poly1305 with AAD, 0600 |
| `<wallet>.outputs` | Blinding factor of every tracked output; `x_s` and `k_s` of in-flight payments | Argon2id + XChaCha20-Poly1305 with AAD (label, version, salt, parameters), 0600, atomic and fsynced |
| `<wallet>.outputs.gen` | State generation counter (public) with an HMAC | Detects a restored old state; see Nonce safety |
| `<wallet>.v1.bak` | The keystore as it was before the upgrade to version 2, including any legacy keys | The **old weak** encryption (Argon2id 1 pass, 64 MiB), 0600. Delete it once you have checked you do not need it. |
| `<data>/coinbases.json` (node) | Blinding factor of every coinbase the miner created | **Plaintext**, file 0600, directory 0700. `import-coinbase` copies these into the encrypted state; the file stays on the node and should be protected. Remove it only when `import-coinbase` reported `Skipped: 0`; skipped keys exist nowhere else. |
| Slates | Public data only (commitments, proofs, points, the receiver's partial `s_r`) | None needed; contain no blinding factors or nonces |
| Terminal / stdin | Passphrase | Read without echo; not kept after the command, but Go strings cannot be zeroed |
| Swap, core dumps | Secrets in process memory | Keys are `mlock`ed best-effort and buffers zeroed after use; strings and GC copies may remain |

The RPC token never touches disk in the wallet; it is read from the environment.

## Variable-time code

Honest list of places where secret-dependent timing exists:

- Every scalar multiplication of a base point by a secret is variable-time:
  `P = x*G` and `R = k*G` (`PublicFromScalar`), Pedersen commitments
  `v*H + r*G`, and the range-proof prover (all in `v2/crypto`, using
  `big.Int` or `ScalarBaseMultNonConst`). They run on the blinding factors, `x_s`,
  `x_r`, `k_s` and `k_r`.
- Partial and full signature verification (`VerifyPartialSchnorr`,
  `SchnorrVerify`) are variable-time, but only on public values.
- Scalar addition, subtraction and multiplication modulo n on secrets
  (`x_s`, `s_s`, `s_r`) use `secp256k1.ModNScalar`, which is constant-time.
- The final nonce and scalar sampling is rejection sampling from `crypto/rand`; the
  retry count depends only on random bytes that are discarded.
- Secrets are serialized with `encoding/json`, whose base64 encoder and decoder
  index lookup tables with secret bytes, and whose encoder and decoder keep
  internal and pooled buffers holding the plaintext state. The buffer the wallet owns
  is zeroed after use; the library's internal copies are not reachable and are not.
- Selection, sorting and comparisons of commitments and amounts are on public data.
- The requests that `sync` and `pay` make reveal your outputs to the node you ask
  (spent ones are not asked about again after 1024 blocks; archived commitments are
  asked about on every sync). There is no privacy from the node you connect to; use
  your own node, reached over loopback or https.

Constant-time secret arithmetic remains an open gate (NX-019).

## Known limits

- **Upgrading from an earlier build:** payments in flight when you upgrade cannot be
  finished. Stored offers use the old slate layout and signed transactions carry
  kernel signatures over the old message, which nodes no longer accept. Finish or cancel
  every payment first (`wallet cancel <txid>`, and `--force` for ones already signed)
  before installing the new version.
- No seed-based recovery of outputs; keep backups of the state file.
- A receiver that crashes after saving its pending output but before showing the
  response leaves a dead session: the slate is refused as a replay and the nonce
  `k_r` is gone. The sender must `cancel`; the receiver can `wallet cancel-receive` the
  pending output (it is not counted as spendable either way, and sync archives it
  after 30 days).
- A transaction that is signed and submitted but never mined stays locked as spent
  until you run `cancel --force` (and then the original may still be mined).
- Amounts must be covered by at most 4 inputs; `wallet consolidate` merges small outputs.
- **No payment proofs and no authenticated slates** (see the warning above): whoever
  answers an offer is paid. No sending to an address (both parties must pass the slates
  by hand), no multi-kernel aggregation.
- The wallet trusts the node it talks to for chain state; confirmations are counted
  from the node's answers. A node you do not control can fake them (see `sync`, Trust).
  Its tip is sanity-checked, never proven, and it cannot make the wallet delete a key.
- A relay-policy refusal (a conflicting transaction already pending) is reported
  differently from an invalid transaction: it may still be mined, so `finalize` says not
  to cancel it. Only an explicit rejection suggests `cancel --force`, and even then a
  transaction that is later mined pays twice.
- A receiver who accepts an offer cannot check that its inputs exist. Fake offers are
  limited by the pending quota (64) and, after 30 days (or `cancel-receive`), move to the
  bounded archive (2048). A genuine payment finalized and mined later than that is still
  matched by `sync` and restored; a wallet whose receive archive is full refuses new
  offers, and there is no command that deletes archived receives.
- **Windows:** the release is built for `windows/amd64` and the code compiles and
  vets for it (`GOOS=windows go vet`), but it has not been run on Windows. File
  protections differ: file modes do nothing, so wallets and `coinbases.json` inherit
  directory ACLs; memory is not locked against swapping; the directory-sync step is
  replaced by a write-through rename (the coinbase file rotation uses the same
  durable rename); the state lock uses `LockFileEx`.
