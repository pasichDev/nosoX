# Threat model

Scope: the current tree, protocol version 5. This is an internal assessment by
the maintainers. It is not an independent audit or a certification. See
[RELEASE_READINESS.md](RELEASE_READINESS.md) for what is still open and
[SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) for past findings.

## Attacker model

Block producers, transaction submitters and network peers are untrusted. They
may send any body field, any curve encoding, any timestamp, any fork suffix,
malformed JSON, and sync requests with arbitrary timing.

The security goals are:

- no spend and no issuance without authorization;
- no inconsistent or partially applied state;
- bounded remote work per message.

Tests use synthetic data and loopback peers only. No test touches a public
network.

## Trusted inputs

The following are assumed correct. A failure in any of them is outside what the
consensus code can detect.

| Input | Notes |
|---|---|
| Genesis block | Derived from network parameters in `v2/genesis`. Empty: no outputs, no kernels. The node pins it on every reopen. |
| Checkpoints | `nosoxd` verifies the baked checkpoint set and its launcher signature at startup and refuses to start on a bad or unsigned set. The set is empty, so no checkpoint protection is active. |
| Validator clock | Used for the 540 s future-timestamp rule (new blocks only). |
| Operating system | Randomness, filesystem durability, process isolation. |
| Toolchain and dependencies | Go, Badger, libp2p, btcec, Decred secp256k1, `x/crypto`. |
| Local data directory | A node trusts its own database. A hostile local database is not a supported input. |

## Cryptographic assumptions

These need independent review. They are not established by tests.

- Discrete-log hardness on secp256k1 and independence of the second generator
  `H`, derived by try-and-increment from a fixed seed string.
- Soundness of the custom Schnorr signature and the custom bit-decomposition
  OR range proof (finding NX-018).
- Absence of useful timing leakage. Secret-dependent code is variable time
  (finding NX-019).
- Fiat-Shamir transcript binding of both constructions.

## Boundaries and entry points

| Boundary | Entry points | Untrusted input |
|---|---|---|
| Consensus | `Chain.AddBlock`, `ValidateBlock`, `ValidateTransaction`, `ReorgTo` | Blocks, transactions, fork suffixes. All spending, subsidy, fee routing and fork choice. |
| Initialization | `genesis.Build`, `Chain.LoadOrInit` | Operator data directory. Replays persisted history on startup. |
| Persistence | `Store.WriteBlock`, `ReplaceSuffix`, `UndoBlock`, `ReplaceChain`, `Save` | Canonical blocks, unspent set, height and hash indexes, tip metadata. |
| Verification | `SchnorrVerify`, `VerifyRange`, `VerifyCoinbase`, `PedersenSumZero` | Curve points, signatures, proof transcripts. |
| Network | `Libp2pNode` gossip topics, hello stream, sync stream, HTTPS seed list | Bounded binary frames, peer addresses, claimed heights, seed lists. |
| RPC | `rpc.Service.HTTPHandler`, daemon bind options | HTTP JSON, bearer token, mining controls. |
| Wallet | `wallet.Load`, `Save`, `Decode`, `VerifyPartials`, `CoinbaseStore` | Encrypted wallet files, slate strings, plaintext reward blinding factors. |
| Release | `scripts/`, `.github/workflows` | Toolchain and dependency trust, checksums. |

## Value paths

There are three, and no others:

1. The scheduled block subsidy, as one coinbase output per block. That output
   also carries the block's transaction fees (value = subsidy + fees), so after
   emission ends miners are paid by fees alone.
2. Native Mimblewimble spends of existing outputs. A spend destroys its fee;
   the coinbase re-creates it exactly once.

Genesis allocates nothing. There is no burn feature. A rule change to any of
these paths is a consensus change.

## Residual risks

These are the assumptions and gaps that remain. Each is also listed in
[RELEASE_READINESS.md](RELEASE_READINESS.md).

- Custom proof system and signatures are unreviewed (NX-018).
- Secret arithmetic is variable time (NX-019).
- Wallet spending works end to end (`pay`, `receive`, `finalize`, `submittransaction`),
  so the wallet is part of the threat surface. Known limits: at most 4 inputs per
  payment, no seed-based recovery, slates are unauthenticated and unencrypted
  (a party that can answer an offer receives the payment), no payment proofs,
  the wallet trusts the node for chain state, and the state file needs
  protection against rollback (see `audit/SECURITY_FINDINGS.md`).
- Miner reward blinding factors are stored in plaintext in `coinbases.json`.
- Public P2P and RPC operation has no global resource budget and no eclipse or
  Sybil analysis.
- Capacity under a maximum-size valid fork and durability under power loss are
  not measured. Startup replay costs time and scratch disk linear in history.
- Difficulty adjustment is a weighted-window formula whose equivalence to a
  published LWMA-3 is not established. There is no median-past-time rule by decision (strictly increasing timestamps kept; see `v2/pow/timewarp_sim_test.go`).
- Compromise of the host exposes keys. Go strings and garbage collection can
  retain secret copies despite best-effort memory locking.
