# Internal security hardening audit

**RESEARCH ONLY — MAINNET BLOCKED. Not independently audited.**
Baseline6179eb56d53768a19950f07e9c806fd384572c5d, initially clean main;
work preserved on security/consensus-hardening. Current-source line ranges below
refer to this branch; original vulnerable behavior refers to the baseline SHA.
Tests are evidence of selected invariants, never proof of absence of defects.

Scope/trust/inventory: THREAT_MODEL.md and BASELINE_TREE.tsv. Exact test commands,
results, tool failures and limits: TEST_REPORT.md and logs/. Independent second
pass: SECOND_PASS.md. Evidence confidence is high for reproduced/code-visible
validation defects; residual cryptographic/economic assurance is explicitly
unresolved. No operational exploit or public-network test was required.

## NX-001: Ordinary kernel signatures were not enforced

- Severity: **Critical**. Classification: CWE-862.
- Affected current source: `v2/chain/validation.go:182-317` (`func (c *Chain) validateBody`).
- Root cause: Block validation checked commitments without proving knowledge of excess secret.
- Threat model / impact: Untrusted block producer could submit a balanced spend without ownership authorization.
- Evidence: Baseline source omitted SchnorrVerify entirely in Chain.validate. Mature native pipeline tests distinguish valid signed control from modified excess signature.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Verify every ordinary kernel signature over domain-separated KernelID under a canonical nonidentity excess, enforce locks and supported features.
- Regression evidence: TestSecurityNativeAuthorizationMaturityAndUndo; TestSecurityBlockAuthorizationMutations
- Verification status: Fixed boundary; cryptographic construction assurance remains NX-018/NX-019. Final executed status is recorded in TEST_REPORT.md.

## NX-002: Missing coinbase authorization permitted unaccounted issuance

- Severity: **Critical**. Classification: CWE-20.
- Affected current source: `v2/chain/validation.go:182-317` (`func (c *Chain) validateBody`).
- Root cause: Coinbase output/kernel count and required signature were optional; reward constraints could be skipped.
- Threat model / impact: Untrusted producer could introduce value outside the schedule.
- Evidence: TestSecurityMissingCoinbaseRejected failed on original code accepting a subsidy-less block; explicit signed wrong-value/extra-output mutations exercise AddBlock on both stores.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Require exactly one signed matching subsidy output/kernel while reward positive, zero afterwards, exact lock/zero fee, canonical excess and overflow-safe fees.
- Regression evidence: TestSecurityMissingCoinbaseRejected; TestSecurityBlockAuthorizationMutations; TestSecuritySyntheticScheduleEdgesThroughAddBlock
- Verification status: Fixed validation; schedule boundary tests use explicitly synthetic tip history, not millions of mined blocks. Final executed status is recorded in TEST_REPORT.md.

## NX-003: Legacy claims had no verifiable ownership boundary

- Severity: **Critical**. Classification: CWE-862.
- Affected current source: `v2/chain/validation.go:182-317` (`func (c *Chain) validateBody`).
- Root cause: Legacy commitments use publicly derivable blindings; input existence and balance do not authenticate historical owner.
- Threat model / impact: Any party knowing public snapshot data could construct a claim unless historical authorization is separately verified.
- Evidence: Baseline validation has no legacy signature verification; claim format lacks supplied historical key and reviewed context binding.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Reject all Legacy/LegacyGVT spends and legacy-claim kernels; do not invent address-to-public-key recovery.
- Regression evidence: TestSecurityLegacyClaimFailsClosed
- Verification status: Fail-closed mitigation verified. Legitimate migration remains unavailable and release-blocking. Final executed status is recorded in TEST_REPORT.md.

## NX-004: Shape-only legacy range proof accepted

- Severity: **Critical**. Classification: CWE-345.
- Affected current source: `v2/crypto/rangeproof.go:11-13` (`func VerifyRange`).
- Root cause: Version1 branch accepted exact length without verifying a cryptographic witness.
- Threat model / impact: Untrusted output could bypass the nonnegative-value condition needed for commitment conservation.
- Evidence: TestRejectLegacyShapeOnlyRangeProof failed prepatch; full mature-spend AddBlock regression now supplies the same fake version1 shape.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Remove legacy acceptance entirely; accept only exact supported proof encoding plus actual transcript/curve verification.
- Regression evidence: TestRejectLegacyShapeOnlyRangeProof; TestRangeProofOpeningAndEncodingBounds; TestSecurityNativeAuthorizationMaturityAndUndo
- Verification status: Bypass removed. Custom proof-system soundness remains unverified. Final executed status is recorded in TEST_REPORT.md.

## NX-005: Headers and IDs did not bind complete bodies

- Severity: **Critical**. Classification: CWE-345.
- Affected current source: `v2/types/commitments.go:47-52` (`func BlockRoots`).
- Root cause: Validator did not recompute body roots; IDs omitted proofs, inputs and signature-bearing data.
- Threat model / impact: Producer/relay could mutate consensus-relevant body without changing advertised header identity.
- Evidence: Original TestOutputIdentityBindsProof/AllMetadata failed; full pipeline distinguishes stale roots from recomputed roots with invalid proof.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Version2 ordered domain/count/length-delimited complete body roots, canonical transaction ID, independent root checks, zero unsupported offsets.
- Regression evidence: TestBodyCommitmentsBindEveryField; TestOutputIdentityBindsProof; TestSecurityNativeAuthorizationMaturityAndUndo; FuzzTransactionEncoding
- Verification status: Fixed binding rules, consensus-breaking; no cut-through compatibility claim. Final executed status is recorded in TEST_REPORT.md.

## NX-006: Failed reorganization could partially rewrite state

- Severity: **Critical**. Classification: CWE-362 / CWE-841.
- Affected current source: `v2/chain/chain.go:230-302` (`func (c *Chain) ReorgTo`).
- Root cause: Old blocks were replayed before removing applied incoming suffix and recovery errors were ignored.
- Threat model / impact: Peer-supplied invalid suffix or storage failure could corrupt canonical tip and UTXO/index state.
- Evidence: Baseline ReorgTo ordering inspected; regression validates multiple incoming blocks then rejects a later invalid block and compares all derived state on both stores.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Validate isolated candidate then commit one atomic replacement; synchronous Badger writes and complete history-derived undo.
- Regression evidence: TestSecurityReorgRollbackAndStrictWork; TestSecurityReorgCommitFailureUnchanged; TestSecurityBadgerOversizeTransactionRollback; TestSecurityBadgerAbruptExit
- Verification status: Small tested transitions/faults fixed; production-scale capacity and full power-loss coverage remain blocked. Final executed status is recorded in TEST_REPORT.md.

## NX-007: Duplicate spends and feature/maturity bypasses

- Severity: **Critical**. Classification: CWE-20 / CWE-841.
- Affected current source: `v2/chain/validation.go:182-317` (`func (c *Chain) validateBody`).
- Root cause: Checking only HasUTXO neither reserved inputs within a block nor authenticated input metadata/maturity.
- Threat model / impact: Producer could duplicate a spend or disguise a locked coinbase as another feature.
- Evidence: Mature/immature real spends, duplicate input and changed feature tests run through AddBlock against both backends.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Unique inputs; stored metadata match; actual creation-height maturity; bounded output/kernel structure and commitment balance.
- Regression evidence: TestSecurityNativeAuthorizationMaturityAndUndo; TestSecurityBlockAuthorizationMutations
- Verification status: Fixed tested validation boundary; raw storage preconditions are separately tested. Final executed status is recorded in TEST_REPORT.md.

## NX-008: Genesis and accepted history could change outside validation

- Severity: **High**. Classification: CWE-345 / CWE-367.
- Affected current source: `v2/chain/chain.go:80-131` (`func (c *Chain) LoadOrInit`).
- Root cause: Reopen trusted stored tip without genesis pin/replay; memory stored and returned caller-owned pointers.
- Threat model / impact: Operator mistake/corruption or in-process caller could silently replace trusted history or mutate accepted state.
- Evidence: Original genesis-pin and mutation tests failed; nested slice and backend parity tests inspect full state.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Pin supplied genesis, structurally validate it, replay non-genesis blocks on reopen, compare derived Badger state, deep-copy accepted/getter bodies.
- Regression evidence: TestSecurityReopenPinsGenesis; TestSecurityStoredBlocksAreImmutable; TestSecurityBackendParityAndNestedSlices; TestSecurityBadgerMissingTipFailsClosed
- Verification status: Fixed covered cases; untrusted local gob/resource limits remain a blocker. Final executed status is recorded in TEST_REPORT.md.

## NX-009: Identity public keys allowed universal signature acceptance

- Severity: **Critical**. Classification: CWE-347.
- Affected current source: `v2/crypto/schnorr.go:89-124` (`func SchnorrVerify`).
- Root cause: Identity point was valid as a public key even though it removes the secret-dependent term from verification.
- Threat model / impact: Untrusted signer could satisfy verification under identity rather than prove a secret.
- Evidence: TestRejectIdentityPublicKeyForgery failed before strict parsing and succeeds as rejection afterwards.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Reject identity public keys/nonces/excesses and noncanonical scalars; preserve only canonical internal arithmetic identity.
- Regression evidence: TestRejectIdentityPublicKeyForgery; TestRejectNoncanonicalPointAndScalar; TestIndependentArithmeticVectors
- Verification status: Fixed encoding/identity boundary; custom Schnorr is not asserted BIP340 or independently reviewed. Final executed status is recorded in TEST_REPORT.md.

## NX-010: Proof/point/scalar noncanonical encodings

- Severity: **High**. Classification: CWE-20.
- Affected current source: `v2/crypto/borromean.go:264-321` (`func bitOrVerify`).
- Root cause: Proof scalar reductions and lax point decoding admitted alternate encodings and malformed public objects.
- Threat model / impact: Peer could create malleable transcripts or inconsistent invalid-point handling.
- Evidence: Independent OR-equation test changes a zero challenge to group order while retaining old modular equations; malformed coordinate/identity tests.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Strict curve parsing, challenge/response bounds, opening consistency and exact proof length; reject unsupported public identity.
- Regression evidence: TestORProofRejectsNoncanonicalResponseAndChallenge; TestRejectNoncanonicalPointAndScalar; TestRangeProofOpeningAndEncodingBounds
- Verification status: Fixed canonical boundaries; independent proof security review still required. Final executed status is recorded in TEST_REPORT.md.

## NX-011: Malformed wallet/slate and unsafe secret-file updates

- Severity: **High**. Classification: CWE-20 / CWE-377.
- Affected current source: `v2/wallet/wallet.go:170-243` (`func Load`).
- Root cause: Envelope lengths were not checked before AEAD/KDF; predictable temporary names and incomplete record/import validation.
- Threat model / impact: Malicious local wallet/slate or another local user could cause panic, excessive work or interfere with secret writes.
- Evidence: Prepatch malformed nonce panic, bad partial/memo binding and static temporary-file tests failed; recorded crypto-wallet-review.md.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Bound secret files, validate envelopes/keys/imports before expensive work, use exclusive0600 fsynced temporary files and validate reward records.
- Regression evidence: TestLoadRejectsMalformedEnvelopeWithoutPanic; TestSaveIgnoresAttackerStaticTempAndProtectsMode; TestSlateSignatureBindsBodyFields; TestCoinbaseFailedPersistenceDoesNotPublishRecord
- Verification status: Covered cases fixed; Go secret copies, plaintext coinbase store and incomplete interactive payments remain documented. Final executed status is recorded in TEST_REPORT.md.

## NX-012: Remote boundaries had panic, allocation and authentication gaps

- Severity: **High**. Classification: CWE-400 / CWE-20 / CWE-306.
- Affected current source: `v2/p2p/sync.go:146-217` (`func (n *Libp2pNode) GetBlocks`).
- Root cause: Unbounded legacy line reading, permissive wire decode/sync response handling, unbounded peer records and weak RPC binding defaults.
- Threat model / impact: Untrusted local-test peer/request could exhaust resources or trigger panic; exposed unauthenticated RPC controls could mutate miner state.
- Evidence: Negative baseline TCP whitespace/read, decode/mempool/RPC tests reproduced; real3node invalid-block forwarding test has valid control.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Bounded versioned JSON, response/range/field checks, deadlines/cancellation/queues, limiter cap, validated mempool, loopback defaults and nonloopback token requirement.
- Regression evidence: internal/network/security_test.go; v2/p2p/security_test.go; v2/rpc/security_test.go; TestThreeNodePropagationRestartAndFork; TestPreAdmittedNativeTransactionGossips
- Verification status: Covered boundaries fixed; Sybil/eclipsing/global budgets and hostile long-history costs are not solved. Final executed status is recorded in TEST_REPORT.md.

## NX-013: Difficulty arithmetic wrapped and zero difficulty verified

- Severity: **High**. Classification: CWE-190.
- Affected current source: `v2/pow/difficulty.go:11-41` (`func LWMA3`).
- Root cause: uint64 difficulties converted/summed/multiplied in int64; Target(0) silently became minimum difficulty.
- Threat model / impact: Untrusted header/history could exploit incorrect target transitions or zero work declaration.
- Evidence: Prepatch maximum steady difficulty collapsed to1 and zero-difficulty header verified.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Exact big-integer evaluation of existing formula, uint64 saturation, explicit zero-difficulty rejection, missing-history fail-closed.
- Regression evidence: TestLWMAMaxDifficultySteady; TestLWMASaturates; TestVerifyZeroDifficulty; TestSecurityShorterHeavierForkWins
- Verification status: Arithmetic fixed; published-LWMA equivalence and timestamp manipulation analysis remain unverified. Final executed status is recorded in TEST_REPORT.md.

## NX-014: Spent commitments and kernels could be replayed

- Severity: **High**. Classification: CWE-294.
- Affected current source: `v2/chain/validation.go:182-317` (`func (c *Chain) validateBody`).
- Root cause: Uniqueness was checked only within block/live UTXO set, not active history.
- Threat model / impact: Recreated previously spent commitments permitted repeated old signed transaction contexts.
- Evidence: Second pass identified and full mature-spend tests reproduce missing historical checks using a test-only historical-read wrapper, then assert rejection with real indexes.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Track all output commitments and KernelIDs on active chain in both stores; rebuild/verify/remove orphan indexes atomically on reorg.
- Regression evidence: TestSecurityNativeAuthorizationMaturityAndUndo; TestSecurityBackendParityAndNestedSlices
- Verification status: Fixed historical replay boundary; deterministic fee output conflict is deliberately not bypassed. Final executed status is recorded in TEST_REPORT.md.

## NX-015: Unbounded future timestamp could freeze advancement

- Severity: **High**. Classification: CWE-20.
- Affected current source: `v2/chain/chain.go:311-358` (`func (c *Chain) validate`).
- Root cause: TimestampMaxInt64 could be accepted while next timestamp had to advance.
- Threat model / impact: Untrusted producer could make no representable child timestamp available.
- Evidence: Deterministic both-backend tests rejectMaxInt64 and now+7201 for the exact drift reason; accept+7200 control.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Enforce advancing nonnegative timestamp and overflow-safe2h future UTC drift, with explicit synchronized-clock assumption; miner advances parent time.
- Regression evidence: TestSecurityFutureTimestampCannotFreezeChain; TestCandidateAdvancesTimeAndBindsBody
- Verification status: Fixed tested freeze path; temporal/network clock design still needs review. Final executed status is recorded in TEST_REPORT.md.

## NX-016: Legacy order signer was not bound to claimed account

- Severity: **High**. Classification: CWE-862.
- Affected current source: `internal/blockchain/orders.go:131-154` (`func VerifyOrder`).
- Root cause: Signature verification trusted o.Sender while debit address came independently from o.Address.
- Threat model / impact: An unrelated historical key could sign an order naming another account.
- Evidence: TestOrderBindsOwnerKey failed on original code; separate network handler regression confirms rejection boundary.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Derive and match signer address, reject invalid private scalar/DER trailing data, strict handler integer/count parsing.
- Regression evidence: TestOrderBindsOwnerKey; TestLegacyPrivateScalarBounds; TestLegacyDERStrict; internal/network/security_test.go
- Verification status: Selected archive/tooling boundaries fixed; complete historical ledger validation remains unavailable. Final executed status is recorded in TEST_REPORT.md.

## NX-017: Deterministic fee outputs collide — OPEN BLOCKER

- Severity: **High**. Classification: CWE-682 / CWE-841.
- Affected current source: `v2/chain/devfund.go:37-55` (`func ExpectedDevFundCommit`).
- Root cause: Fee output equals F*H+fixed public point with no per-block uniqueness domain.
- Threat model / impact: Equal fee totals reuse commitment; prior code overwrote value, hardened history uniqueness rejects repeat forever, even after spending.
- Evidence: Independent second pass/SP1 and deterministic ExpectedDevFundCommit source; current rules intentionally reject collision.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Do not relax uniqueness or change recipient. Requires separately reviewed height/network commitment or accumulator design and spending semantics.
- Regression evidence: Existing TestExpectedDevFundCommitDeterministic; SP1; repeated-fee full pipeline remains a test gap.
- Verification status: UNRESOLVED HIGH, blocks public testnet/final audit/mainnet. Final executed status is recorded in TEST_REPORT.md.

## NX-018: Custom proof construction lacks independent justification — OPEN BLOCKER

- Severity: **High**. Classification: CWE-327 (assurance risk).
- Affected current source: `v2/crypto/borromean.go:114-169` (`func VerifyRangeBorromean`).
- Root cause: Bit OR proofs are custom code, not a reviewed drop-in production proof system.
- Threat model / impact: Failure of soundness/Fiat-Shamir/generator assumptions would invalidate no-inflation reasoning.
- Evidence: Negative proofs and independent arithmetic vectors cover selected equations only; no published interoperability proof-system vectors or external review completed.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Retain real verification, remove bypass, document limitation; commission independent review or select established reviewed implementation with explicit migration.
- Regression evidence: crypto hardening/proof/fuzz tests are partial evidence, not a proof.
- Verification status: UNRESOLVED HIGH assurance blocker. Final executed status is recorded in TEST_REPORT.md.

## NX-019: Secret operations lack constant-time guarantees — OPEN BLOCKER

- Severity: **High**. Classification: CWE-208.
- Affected current source: `v2/crypto/schnorr_ct.go:16-75` (`func SchnorrSignConstantTime`).
- Root cause: Function names/comments implied CT despite big.Int/variable-time point operations and dependency PubKey calling ScalarBaseMultNonConst.
- Threat model / impact: Local timing/cache observation may leak wallet secrets; remote applicability is not established.
- Evidence: Dependency source inspection in crypto-wallet-review.md; no side-channel experiment or formal CT proof performed.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Remove misleading guarantees; require reviewed secret arithmetic implementation, audit secret lifetime and dependency behavior.
- Regression evidence: Functional/race tests cannot verify constant-time behavior.
- Verification status: UNRESOLVED HIGH, blocks production wallet use. Final executed status is recorded in TEST_REPORT.md.

## NX-020: Historical supply and ownership are unverified — OPEN BLOCKER

- Severity: **High**. Classification: CWE-345.
- Affected current source: `v2/genesis/genesis.go:66-188` (`func Build`).
- Root cause: Byte parsing was conflated with trusted economic issuance and historical ownership.
- Threat model / impact: An unverified allocation manifest could permanently legitimize corrupted balances.
- Evidence: 4956 records/3561 positive;11 invalid addresses;400NOSO discrepancy against repository simple formula. Original fixture remains unchanged.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Reject invalid/duplicate/negative snapshots and missing requested files, preserve evidence, disable mainnet and legacy claims. Require independent reconciliation.
- Regression evidence: TestRejectOriginalMalformedSnapshot; TestRejectNegativeAndDuplicateSnapshot; TestDefaultTimestampPreservesSnapshotAndNetwork
- Verification status: UNRESOLVED HIGH migration trust; parser hardening verified separately. Final executed status is recorded in TEST_REPORT.md.

## NX-021: Atomic reorg resource/capacity bounds remain unproven — OPEN BLOCKER

- Severity: **High**. Classification: CWE-400 / CWE-703.
- Affected current source: `v2/chain/chain.go:230-302` (`func (c *Chain) ReorgTo`).
- Root cause: Reorg stages full retained history in RAM; Badger one-transaction cap can reject valid suffixes accepted by memory backend.
- Threat model / impact: Long-history peer events or large valid suffix may cause resource exhaustion or backend convergence failure.
- Evidence: Independent SP2/SP3; real oversized Badger fault proves unchanged failure state but not capacity for every consensus-legal transition.
- Confidence: high in stated code behavior; unverified assurance explicitly noted.
- Fix / disposition: Cheap whole-suffix structural preflight added. Keep atomic failure; redesign state snapshot/delta staging and prove bounded backend capacity instead of splitting nonatomically.
- Regression evidence: TestSecurityReorgRejectsMalformedBeforePrefixRead; TestSecurityBadgerOversizeTransactionRollback; maximum valid suffix/long-history resource tests still missing.
- Verification status: UNRESOLVED HIGH, blocks deployment. Final executed status is recorded in TEST_REPORT.md.

## Additional remediation and limits

- Go1.25.7 baseline build/test/vet/race all returned0, despite critical omissions.
  Go upgraded to1.27.3 from official stable releases; CI follows go.mod.
- govulncheck1.9.0 initially reported GO-2026-6165(dtls), GO-2026-6099
  (webtransport), GO-2026-5676(quic). Updated dtls3.1.4, webtransport0.11.1,
  quic0.60.0 (required by webtransport), transitive x/net0.55.0. The earlier post-dependency-update scan reports
  zero called vulnerabilities, but5 imported-package/10 required-module alerts
  not considered called. Static traces are overapproximations, not remote proof.
  See official pkg.go.dev/vuln entries and exact scanner logs.
- Miner fails if reward keys cannot persist, caps selected candidate bodies/fees,
  revalidates stale pending transactions, preserves actual solved headers and
  drains workers on Stop. A full race run exposed a newly introduced shared-header
  race; corrected by immutable worker templates, with failed log retained and
  fresh reruns. Parent changes now abandon stale work (SP4).
- Secret scanning was not completed. Dedicated scanners were unavailable; the
  later verification-only pass did not start new scanning. This remains a gate.
- Storage read booleans conflate I/O failure and absence (SP5). Startup replay and
  transactional writes help, but an error-returning full Store read API is still
  needed. Corruption/power-loss/resource coverage remains incomplete.
- CLI Slatepack intent signatures are not a complete MW interactive payment
  protocol. No production wallet, anonymity, seed-governance or mainnet guarantee.

No known Critical/High risk is silently declared closed. Open blockers require
protocol/cryptographic/storage work beyond the tested patches. See strict release
gates before any deployment or final external release audit.
