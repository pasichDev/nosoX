# SP1: unique transparent developer fee commitments (protocol version 3)

Scope: authorized local defensive regression on `security/consensus-hardening`, starting at `34f0d0d`. No network nodes, publication, production recipient secret, recipient replacement, or historical uniqueness exception is involved.

## Cause and mathematical invariant

The old output `C = F H + P_dev` repeated whenever different blocks paid equal fees. The historical output uniqueness rule correctly rejected the second output, stopping normal fee-bearing progression. Removing that index check would introduce replay ambiguity and is not the remediation.

Version 3 derives the public scalar below, interpreting every integer as unsigned big-endian and the digest as a 256-bit unsigned integer:

```
t = SHA256(ASCII("NosoX/devfund-blind/v3") || BE32(header.NetworkMagic)
           || BE64(header.Height) || header.PrevHash[32] || BE64(totalFee)) mod n
C = F H + P_dev + t G
```

`n` is the existing secp256k1 group order. The domain string has no terminator. `PrevHash` is the raw canonical hash bytes. `chain.DevFundBlindingTweak` exposes the exact canonical 32-byte big-endian scalar for wallet recovery. `chain.ExpectedDevFundCommit(&header, totalFee)` fixes the recipient internally; callers cannot substitute it. It rejects nil/noncurrent-version headers, fee overflow, and a noncanonical/identity adjusted recipient `P_dev+tG` or final commitment. Only canonical internal identity addends produced by the existing Pedersen primitive are accepted by existing `PointAdd` semantics (for t=0 or F=0); a resulting identity recipient or final commitment is explicitly rejected. No input-validation identity exception is introduced.

For `P_dev = d_dev G`, the commitment equals `F H + (d_dev+t mod n) G`. The holder spends using `d_dev+t mod n`; the value remains F and no other party learns d_dev. Block reward, developer destination, genesis allocation, GVT rules and ordinary balance checks remain unchanged. Coinbase and developer outputs are checked independently as value-known outputs; the transaction equation remains `sum(plain_outputs) - sum(inputs) + F H = sum(tx_excesses)`.

The context includes network magic and parent ancestry, binding the genesis domain even for two networks sharing a magic value. Different block heights/parents yield different public blindings except with negligible hash/group collision probability. Existing historical uniqueness still fails closed if a collision occurs. Nonce, timestamp, difficulty and body roots are excluded to avoid circular roots or output changes during PoW grinding. Validation uses the actual candidate header; miner construction initializes that stable header context before appending the fee output and propagates any derivation error.

## Standard comparison and limits

The additive group transformation and corresponding secret transformation were checked against the primary [BIP 341 public and secret tweak algorithms](https://bips.dev/341/): Q=P+tG and q=d+t modulo n. This protocol uses compressed full keys, its own domain string and mod-n hash reduction; it does not implement or claim compatibility with Taproot's x-only normalization, tagged hash or overflow rules.

`TestSP1TweakedRecipientSpendability` additionally computes P+tG using the pinned `github.com/decred/dcrd/dcrec/secp256k1/v4@v4.4.0` Jacobian APIs (`ScalarBaseMultNonConst`, `AddNonConst`, `ModNScalar.SetByteSlice`) and compares it with the production Pedersen/point arithmetic. These independent API paths check the algebra, not the security of the project's custom proof or signature constructions. No new primitive or dependency was added. Public tweak calculation may use variable-time arithmetic because every operand is public.

## Compatibility

`types.BlockVersion` changes from 2 to 3: this is an explicit consensus hard fork, not a silent reinterpretation of version-2 blocks. Existing supported serialization layouts and the v2 kernel/output/body-root hash domains are deliberately retained; only the fee-output construction gets a new v3 domain. Existing byte fixtures are not rewritten. Tests derive current headers with version 3 and explicitly reject a version-2 derivation context. Existing stored version-2 histories require a separately designed migration or relaunch policy; automatic migration is not introduced here.

## Red / green evidence

Runtime red was captured before the fix by archiving HEAD into `/tmp/nosox-sp1-red` and copying only the new regression there. An archive was necessary because concurrent SP2 changes temporarily made the shared Store interface uncompilable; no active work was reverted.

```
GOTOOLCHAIN=go1.27.3 GOMODCACHE=/home/pasich/go/pkg/mod GOCACHE=/home/pasich/.cache/go-build \
  go test -C /tmp/nosox-sp1-red -p 2 ./v2/chain -run '^TestSP1ConsecutiveEqualFees$' -count=1
```

Both memory and Badger failed at the second real fee block with `chain: duplicate or existing output` (10.602 seconds total).

After remediation:

```
GOTOOLCHAIN=go1.27.3 GOMODCACHE=/home/pasich/go/pkg/mod GOCACHE=/home/pasich/.cache/go-build \
  go test -p 2 ./v2/chain -run 'TestSP1|TestDevFund|TestExpectedDevFund' -count=1
```

Passed (17.937 seconds); fresh rerun after the backend-selection test cleanup passed (20.458 seconds), and the subsequent explicit adjusted-recipient identity check passed the same suite (18.583 seconds). `go test -p 2 ./v2/types ./v2/miner -count=1` also passed (0.007 / 0.653 seconds respectively).

- `TestSP1ConsecutiveEqualFees`: full AddBlock path on memory and Badger; 61 local subsidy blocks mature two real source outputs; successive blocks contain genuine signatures and range proofs and each pay fee 100. Both are accepted and commitments differ. Re-rooted wrong-parent, wrong-height, wrong-network and wrong-fee commitments are rejected by full AddBlock. Both historical indices and UTXOs are present; Save/close/reopen/replay preserves the complete snapshot. A heavier fork removes both orphan fee outputs and their historical indices.
- `TestDevFundContextBinding`: independent SHA256/BE-encoding vector; parent/network/height binding; mining nonce/timestamp/root invariance; old version, nil header and fee overflow rejected. Existing tests continue checking exact fee amount, deterministic same-context derivation, missing/duplicate/zero-fee outputs.
- `TestSP1TweakedRecipientSpendability`: separate public test recipient, private/public tweak agreement, independent Jacobian differential, real signed/proven zero-fee spend conservation and +1 inflation rejection. The production fixed-recipient equation is also checked without its secret. No fake production developer key, state injection or trust bypass is used.

## Open risks

The production developer secret intentionally stays off-repo, so an end-to-end production-recipient AddBlock spend is not performed. Its spendability is established by the differential group equation and a separate test-recipient signed/proven spend. The existing developer wallet must adopt the exact exported tweak and new spending scalar before version-3 deployment; this patch does not modify an off-repo wallet. General custom cryptographic construction security and secret-operation side channels remain outside this local remediation and require independent expert review. Hard-fork activation/history migration and deployment are not authorized or implemented by this change.
