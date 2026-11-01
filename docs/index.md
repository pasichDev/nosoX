# NosoX

NosoX is a Mimblewimble-style chain written in Go. Outputs are Pedersen
commitments with range proofs, blocks are mined with Argon2id, and nodes talk
over libp2p. The repository contains the node (`nosoxd`), a command-line
client (`nosox-cli`) and the Go packages under `v2/`.

NosoX started as a rewrite of the Noso protocol. It is a new chain: no
balances carry over, genesis is empty and every coin is mined.

!!! warning "Status"
    This is experimental software. No independent cryptographic audit has
    taken place. The custom Schnorr signature and the custom range proof are
    unreviewed, and secret-dependent code is not constant time. `nosoxd`
    refuses to start on mainnet. Do not hold value in it.

    The wallet can pay: `wallet pay`, `receive` and `finalize` build a
    two-party Mimblewimble transaction that the node accepts and mines. Limits:
    at most 4 inputs per payment, no seed-based recovery, unauthenticated
    slates (whoever answers an offer receives the payment), no payment proofs,
    and reward keys stay in plaintext on the node. See [Wallet](wallet.md) and
    [Roadmap](roadmap.md).

## Where to start

| I want to | Page |
|---|---|
| Build and run a local test node | [Getting started](getting-started.md) |
| Understand the design | [Architecture](architecture.md) |
| Read block and transaction formats and consensus rules | [Protocol](protocol.md) |
| See who is paid fees | [Mining](mining.md#what-a-miner-earns) |
| Read about the cryptography | [Cryptography](crypto.md) |
| Use the wallet | [Wallet](wallet.md) |
| Mine | [Mining](mining.md) |
| Operate a node | [Running a node](running-a-node.md) |
| Call the JSON-RPC API | [RPC](rpc.md) |
| Know the limits | [Limits](limits.md) |
| Report a vulnerability | [Security](security.md) |
| See what is missing | [Roadmap](roadmap.md) |

Source: [github.com/pasichDev/nosoX](https://github.com/pasichDev/nosoX).
Licensed under MIT.
