# Threat model and assessed scope

This is an internal defensive hardening assessment of baseline
`6179eb56d53768a19950f07e9c806fd384572c5d` (clean main), on branch
`security/consensus-hardening`. It is not an independent audit or certification.
The original module was github.com/noso-project/noso-go; source imports and module
now match github.com/pasichDev/noso-go. Original fixture bytes are preserved.
Go baseline1.25.7 was run before production changes; final toolchain1.27.3.

## Attacker and trust boundaries

Untrusted block producers, transaction submitters and peers may supply arbitrary
body fields, curve encodings, timestamps, fork suffixes, JSON, sync ranges and
stream timing. The goals are preventing unauthorized spend/issuance, inconsistent
state and partial transitions, and bounding remote work. Adversarial tests use
only synthetic local data and loopback libp2p/TCP/HTTP peers. No public crypto
network interaction, load attack, deployment, merge or repository-setting change.

Trusted inputs include the operator-selected genesis, compiled fee destination
and checkpoints, OS randomness, synchronized validator clock (future-drift rule),
Go/compiler/dependencies, and filesystem access controls. Local chain database
corruption is detected on restart where covered; malicious local gob files are
not a safely bounded hostile codec. Read failures represented as booleans are a
remaining storage-interface weakness. Compromised OS/process can expose secrets.

Curve discrete-log hardness, generator independence, Fiat-Shamir soundness and
side-channel resistance are assumptions requiring independent review. Ed25519
identity signatures are not Pedersen-output ownership. Legacy public blindings
confer no ownership. Checkpoints, DNS/HTTPS seeds, Noise and finite tests do not
prove economic legitimacy, Sybil resistance, privacy or consensus security.

## Inventory and depth

Every tracked path at baseline is indexed by blob hash in BASELINE_TREE.tsv.
All twenty source package directories were inventoried and their source reviewed
within assigned boundaries. Relevant maintained tests, protocol documents,
configuration and two release scripts were inspected. Review depth is unequal:
chain/crypto/wallet/remote boundaries received implementation changes and negative
regressions; legacy archive formats and CLI received source inspection/selected
fixes, not complete historical consensus reconstruction. No full formal proof,
external cryptographic audit, OS power-cut campaign, production-scale long-chain
soak, or independent economic reconciliation was completed. Treat unverified
requirements as open, not silently satisfied.

| Boundary | Entry points | Inputs / mutations |
|---|---|---|
| Consensus | Chain.AddBlock, ValidateBlock, ValidateTransaction, ReorgTo | Untrusted blocks/transactions; all spending, subsidy, fee routing and chain selection |
| Initialization | genesis.Build, Chain.LoadOrInit | Operator snapshots/config; initial allocations and persisted history replay |
| Persistence | Store.WriteBlock, UndoBlock, ReplaceChain, Save | Canonical blocks, UTXOs, height/hash/legacy/history indices, tip metadata |
| Proof verification | SchnorrVerify, VerifyRange, VerifyCoinbase, PedersenSumZero | Untrusted curve points, signatures, proof transcripts and balances |
| Networking | Libp2pNode.Start/GetBlocks/hello/cold-sync, legacy TCP handlers | Framed JSON, peer addresses, heights, bootstrap discovery, legacy orders |
| RPC | Service.HTTPHandler/jsonRPC, daemon bind configuration | HTTP JSON, token/public-method policy, mining controls and queries |
| Wallet | Load/Save/ImportLegacyFile, Slate.Decode/VerifyPartials, CoinbaseStore | Encrypted files, historical keys, intent envelopes, plaintext reward blinds |
| Release | scripts/build-release.sh, verify-release.sh, .github/workflows | Toolchain/dependency trust, checksums, optional publisher signature |

Value paths: trusted genesis legacy/GVT allocation; scheduled coinbase; native
commitment spends; fees to fixed dev point; legacy claims/redeem/transfer disabled
at consensus. There is no enabled burn. No supply/fee/GVT constant was changed.
The historical archive's incomplete PoS/MN/administrative handling is not accepted
as proof of valid issuance. Constants/version rules are in v2/types/types.go and
PROTOCOL_CHANGES.md; they are not authenticated merely by being documented.

## Residual release-blocking assumptions

Unreviewed custom range proofs and variable-time secrets; unverified migration
supply/claim format; deterministic fee-output collisions; full-history reorg RAM
and storage transaction capacity/parity; insufficient power-loss/resource/long-
chain testing; cross-network transaction signing intent and checkpoint governance
need explicit protocol review. Mainnet is disabled in the daemon.
