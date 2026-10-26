# Crypto and wallet review

Scope: every production file in `v2/crypto` and `v2/wallet`, associated tests,
original baseline 6179eb56d53768a19950f07e9c806fd384572c5d. This is defensive
source review and local regression testing, not an independent cryptographic
security assessment or a proof of soundness. No node/network was contacted.

## Confirmed defects and changes

* **Critical: unverifiable range proofs.** `VerifyRange` accepted any 33-byte
  string beginning with 1 without even examining the commitment. A fresh
  arbitrary proof reproduced acceptance. Removed this development-version
  fallback entirely. Only exact version-2 length (14,529 bytes) reaches curve
  work. Existing version-1 history is incompatible and requires explicit
  migration/trust handling; shape acceptance must never be restored.
* **Critical: identity-key signature forgery.** The all-zero point decoded to
  the identity and `SchnorrVerify(identity, msg, G||1)` accepted every message.
  The verifier now requires canonical nonidentity compressed public key and
  nonce, exact signature length, and response in (0,n). A dedicated regression
  constructs the forgery. The historical Schnorr scheme remains custom and is
  not BIP340 (its 65-byte encoding/challenge differ).
* **High: noncanonical points/scalars.** Any prefix-zero point was interpreted
  as identity, field coordinates were reduced through modular arithmetic,
  and public-key scalars were silently reduced. Parsing now uses dependency
  SEC point parsing, permits only the exact all-zero internal identity, and
  rejects public zero/order-or-larger scalars and commitment order-or-larger
  blinds. `ValidPublicPoint` exposes strict nonidentity validation for chain
  boundaries. Internal zero-value/zero-blind commitment remains the canonical
  all-zero mathematical identity. Cancellation from public add/subtract
  returns an error instead of an invalid compressed (0,0). Negative fees fail.
* **High: OR proof scalar malleability.** e0,e1,s0,s1 were not constrained to
  [0,n), although curve operations reduced them. Verification now rejects
  these encodings and malformed/identity bit commitments and nonces. A
  controlled OR proof uses e1=0 then replaces it by n to test this precise
  equivalence attack. Both provers check that the supplied commitment equals
  the opening before randomness/curve work. Scalar sampling rejects overflow;
  the signing sampler now explicitly fails after exhausted retries rather
  than using a reduced overflow sample.
* **High: hostile wallet envelope panic/work amplification.** Invalid base64,
  unsupported versions and invalid nonce sizes reached Argon2 and AEAD.Open;
  the latter panicked on malformed nonce. Load now bounds regular-file bytes
  to 8 MiB, checks version/base64/salt(16)/nonce(24)/ciphertext minimum before
  Argon2, and validates decrypted seed and legacy key pairs. No attacker
  supplied KDF parameters exist: Argon2id is fixed at 64 MiB, t=1, p=1.
  Legacy import reads through the same bounded descriptor, caps records at
  10,000 and verifies secret scalar, public point, derived public key and
  address. Direct legacy signing rejects invalid secret scalars too.
* **High: predictable secret temporary file.** Wallet and coinbase writes used
  `path.tmp`, followed existing symlinks, did not correct existing temp modes,
  and omitted fsync. They now exclusively create a random mode-0600 temporary
  in the destination directory, write, sync, close, rename, and sync the
  directory. A symlink regression verifies the old static temp victim stays
  untouched; successful save/load and 0600 mode are checked. Coinbase failed
  persistence no longer appends to in-memory state; loading verifies every
  record's opening and unique commitment, and bounds record count.
* **High: slate intent signature confusion/DoS.** Empty signature lists were
  accepted; malformed Ed25519 public key length panicked. Signatures omitted
  version/stage/role, features, proof bytes, metadata, memo, and list framing;
  participant labels could be changed. Signatures now bind domain-separated
  canonical Go JSON of every slate field excluding signature list, plus the
  participant role in a second domain. Verify rejects empty/duplicate/unknown
  roles and malformed key/signature sizes before Ed25519 work. Decode caps
  encoded input at 128 KiB before quadratic Base58 arithmetic, then validates
  version/stage/header agreement/role/amount/fee/list bounds. Encode caps JSON
  at 90 KiB. Fee conversion above MaxInt64 fails. This changes slate signing
  interoperability and must be version-migrated with consumers.

## Cryptographic assessment and external blockers

The custom proof is 64 weighted bit commitments with individual Fiat-Shamir
Schnorr OR proofs. Each verification checks the weighted sum against the
parent commitment and both response equations plus challenge splitting.
Code tests cover valid witnesses, wrong commitments, inconsistent prover
openings, malformed length/version, mutations and scalar malleability. These
checks do **not** establish knowledge soundness, zero knowledge, transcript
security, multi-proof composition or constant-time execution. Independent
specialist review, published construction mapping and interoperable vectors
remain a release blocker. A reviewed production range-proof implementation
is preferable to treating this audit as validation of a novel scheme.

**The existing constant-time claims were false.** The pinned Decred v4.4.0
`PrivateKey.PubKey` explicitly calls `ScalarBaseMultNonConst`. PedersenCommit
uses big.Int and variable-time curve arithmetic on secrets, and the CT-named
prover branches on secret bits. Historical exported names are retained for API
compatibility, but production comments now state the limitation. Scalar-only
fixed-width operations do not establish constant-time signing/proving. A
reviewed implementation with an explicit side-channel contract and independent
analysis is required; timing tests cannot prove this guarantee.

The NUMS H derives from the fixed literal SHA256 seed plus try-and-increment,
not a standard hash-to-curve suite. No known discrete logarithm is introduced
by this code, but its provenance/security is not independently certified.

Slate partials are self-asserted Ed25519 acknowledgments. They do not implement
secure interactive aggregate Schnorr signing, prove input ownership, authenticate
a trusted recipient, or establish a complete payment negotiation protocol.
Full body binding fixes mutation bugs; a reviewed interactive MW protocol
remains absent. Legacy builders still produce historical claims, while chain
migration authorization must fail closed pending a reviewed network-bound
ownership proof. A public deterministic legacy blinding never proves ownership.

## Wallet limits and residual risks

* Argon2id t=1 is retained for existing version-1 keystore compatibility; it
  is below RFC 9106's memory-constrained recommendation (64 MiB,t=3,p=4).
  Introduce a versioned KDF migration and benchmark target devices before
  recommending this keystore for real assets. Valid-size envelopes can still
  each incur the fixed 64 MiB derivation cost; invocation concurrency must be
  controlled at the application boundary.
* The coinbase store remains a plaintext secret-key file. Mode 0600 is not
  encryption; local account compromise, backups and disk exposure reveal
  blindings. It loads/replaces complete snapshots, capped at 10,000 records;
  production miners need a transactional encrypted key store and backup plan.
* Atomic replacement assumes an exclusively owned destination directory and
  a filesystem supporting file and directory fsync. Cross-process writers
  are not serialized; last rename wins. A directory fsync failure after rename
  reports uncertain durability (the file may have changed despite error).
  Windows filesystem behavior and actual power-failure durability were not
  exercised. These tests do not emulate sudden power loss.
* mlock is best effort on supported Unix and a no-op elsewhere; Load ignores
  lock failures. Go strings/JSON/GC can retain secret copies. Close now accurately
  documents that immutable legacy strings cannot be scrubbed; mutable master
  bytes are cleared and legacy references removed. There is no complete memory
  erasure or swap-exclusion guarantee. `Plain` export-view references are cleared.
* The public Wallet fields are mutable by callers. Invalid master signing/save
  calls must be checked at each API boundary; concurrent access is not promised.
  MasterPublic now returns nil for invalid/inconsistent master bytes; Save
  returns an error. Concurrent caller mutation remains unsupported.

## References (primary)

* Decred pinned implementation: https://github.com/decred/dcrd/blob/dcrec/secp256k1/v4.4.0/dcrec/secp256k1/privkey.go
  (`PubKey` calls ScalarBaseMultNonConst); local module source confirms this.
* SEC 1 v2 point encodings and elliptic-curve public-key validation:
  https://www.secg.org/sec1-v2.pdf
* BIP340, comparison only; this project is not compatible:
  https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
* Argon2id parameters and recommendations: https://www.rfc-editor.org/rfc/rfc9106.html
* Original Borromean ring-signature construction (the project implements
  independent OR proofs rather than a direct reviewed integration):
  https://github.com/Blockstream/borromean_paper/blob/master/borromean_draft_0.01_9ade1e49.pdf

## Verification evidence

Negative tests were added before production changes after baseline completion.
`go test -p 2 ./v2/crypto ./v2/wallet -run 'TestReject|TestPointCancellationCanonicalIdentity|TestLoadRejectsMalformed|TestSlateRejects|TestSlateSignatureBinds' -count=1`
exited 1 on original production code: confirmed range fallback acceptance,
identity forgery, scalar/identity/cancellation acceptance, two AEAD nonce
panics, empty-partial acceptance, malformed Ed25519 panic, and memo mutation.

All commands below use `GOMODCACHE=/home/pasich/go/pkg/mod` and
`GOCACHE=/home/pasich/.cache/go-build` (default cache path is read-only).
Intermediate full package tests exited 0 twice, including added OR proof,
proof mutation, persistence symlink/mode, size, rollback, slate-bound tests.
Final verification results are appended below when complete.

Final local verification on Go 1.27.3 linux/amd64:

* `go test -p 2 ./v2/crypto ./v2/wallet -count=1`: exit 0;
  crypto 0.915s, wallet 0.395s (before final master consistency check).
* `go test -race -p 2 ./v2/crypto ./v2/wallet -count=1`: exit 0 after
  final production changes; crypto 22.644s, wallet 3.477s.
* `go vet -p 2 ./v2/crypto ./v2/wallet`: exit 0.
* `go test -p 2 ./v2/crypto -run '^$' -fuzz '^FuzzVerifyRangeBorromean$' -fuzztime=5s -parallel=2`:
  exit 0, 6,143 executions. Corrected the harness so valid seed proofs are
  paired with their real parent commitment instead of an invalid constant.
* Same bounded command with `-fuzz '^FuzzSchnorrVerify$'`: exit 0,
  157,774 executions. Wallet `FuzzSlatepackDecode`: exit 0, 145,121 executions.
* `git diff --check -- v2/crypto v2/wallet`: exit 0.

These short fuzz campaigns provide limited local robustness evidence, not
exhaustive adversarial coverage or cryptographic validation. Full repository,
chain/backend and dependency/toolchain verification is coordinated separately.

`go test -p 2 ./v2/crypto ./v2/wallet -cover -count=1` after final changes:
exit 0; crypto 83.4% statement coverage (0.958s), wallet 70.4% (0.447s).
Coverage percentages are observed execution, not proof of security.
