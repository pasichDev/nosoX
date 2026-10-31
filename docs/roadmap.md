# Roadmap and known limitations

This list contains work that is missing. It has no dates and no commitments.

## Blocking any real use

| Item | State |
|---|---|
| Independent cryptographic review | Open (NX-018, NX-019). |
| Mainnet launch | Not defined. The node refuses mainnet, no seeds exist, and no checkpoints are installed. |

## Known gaps

- No block-body query in the RPC, and no per-client RPC rate limiting, which is why `submittransaction` and `hasutxo` need the token.
- Payments work end to end, with limits: at most 4 inputs per payment, slates are
  unauthenticated and unencrypted (whoever answers an offer receives the
  payment), and there are no payment proofs.
- The wallet has no seed-based recovery of outputs, and cannot cancel a signed transaction that is still in some mempool without `--force`.
- The RPC keeps its own in-memory UTXO index because `chain.Chain` exposes no commitment lookup.
- Reward keys must be copied from `coinbases.json` into a wallet with `wallet import-coinbase`; the plaintext file stays on the node.
- No checkpoints are baked in. The daemon verifies the baked set and its
  launcher signature at startup (an empty set starts, a bad set refuses) and
  pins the list for the running network, but there is nothing to pin yet.
- Miner reward keys are stored unencrypted.
- No light-client mode. Compact filters exist only as a type.
- No pool protocol.
- Cut-through and transaction offsets are not supported.
- No median-past-time rule: a decision, not an omission. Strictly increasing timestamps and a 540 s future limit were kept after simulation (`v2/pow/timewarp_sim_test.go`).
- A maximum-size valid fork and power-loss behavior have not been tested.
- No packaged documentation for operators of a public network, because none
  exists.

## Under consideration

- Replacing the range proof with a smaller, reviewed construction. This needs a
  new protocol version.
- A reviewed constant-time implementation of secret arithmetic.
- An encrypted store for reward keys.
