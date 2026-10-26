# Transparent fees — experimental protocol version 3

**Unsafe research implementation. Mainnet remains blocked.** This revision fixes
SP-1 without changing the fee amount, destination point, subsidy or allocation.
The previous version's `F*H+P_dev` repeated whenever equal fee totals recurred;
removing historical uniqueness or overwriting UTXOs is not a permitted fix.

For total public kernel fee F>0, exactly one output must equal:

```
t = SHA256("NosoX/devfund-blind/v3" || BE32(network_magic) ||
           BE64(height) || prev_hash[32] || BE64(F)) mod n
P_adjusted = P_dev + t*G
C_fee = F*H + P_adjusted
```

`chain.DevFundBlindingTweak(header,F)` and
`chain.ExpectedDevFundCommit(header,F)` are canonical. The header must have
version3. The recipient point and final commitment must be canonical and
nonidentity. Roots, nonce and timestamp are excluded from the tweak so a miner
can form its body before computing roots and can search nonces without changing
fee ownership. Parent ancestry binds the trusted genesis and network domain.
When F=0 there is no fee output. F and all summed fees must fit int64.

The fixed public recipient remains `types.DevFundPoint()`; its private scalar d
is not part of this repository. The spending scalar for a particular output is
`(d+t) mod n`. An off-repository signer must derive t from the exact creation
header and fee total, use reviewed secret-scalar handling and verify the resulting
public key/commitment. No production private key was inspected, forged, changed
or printed. Existing in-repository primitives perform the public derivation;
this is not a claim of BIP341 compatibility or a complete production wallet.

Every native transfer still checks
`sum(plain outputs)-sum(inputs)+F*H=sum(transaction excesses)`.
The fee output is independently constrained to the known amount F. Public
blinding addition changes no value and creates no extra subsidy. The adjusted
recipient retains the original secret ownership under the curve/hash assumptions.
Those assumptions and the custom range/signature systems need independent audit.

`TestSP1ConsecutiveEqualFees` checks real signed/proven consecutive fee blocks,
wrong-context/inflation rejection, restart and reorg on both stores.
`TestSP1TweakedRecipientSpendability` checks independent Jacobian arithmetic and a
synthetic recipient's signed/proven spend; it does not use the production secret.
See [remediation](../../audit/sp1-remediation.md),
[combined verification](../../audit/SP123_COMPLETION.md) and
[protocol changes](../../audit/PROTOCOL_CHANGES.md).
