# Architecture

## Packages

| Package | Role |
|---|---|
| `v2/types` | Block, header, transaction, output and kernel types; canonical encodings; emission schedule; consensus limits. |
| `v2/crypto` | secp256k1 Pedersen commitments, Schnorr signatures, range proofs. |
| `v2/pow` | Argon2id proof of work, target arithmetic, difficulty adjustment. |
| `v2/chain` | State machine: validation, unspent set, reorganization, two storage backends. |
| `v2/genesis` | Builds the empty genesis block. |
| `v2/mempool` | Pool of validated unconfirmed transactions. |
| `v2/miner` | Builds block candidates and searches for a nonce. |
| `v2/wallet` | Encrypted wallet file, reward-key store, slate encoding. |
| `v2/p2p` | libp2p host, gossip, hello and sync streams, seed discovery. |
| `v2/rpc` | JSON-RPC over HTTP. |
| `cmd/nosoxd` | Node, miner and RPC daemon. |
| `cmd/nosox-cli` | Wallet and RPC client. |

## Data flow

1. A transaction enters the mempool from gossip. The mempool calls
   `Chain.ValidateTransaction` before admitting it.
2. The miner takes transactions from the pool, then adds one coinbase output
   worth the subsidy plus the fees of the selected transactions, then searches
   for a nonce.
3. `Chain.AddBlock` validates the block against the tip and writes it.
4. The node broadcasts the block on a gossip topic. Peers validate it before
   forwarding.
5. If a peer announces a block whose parent is not the tip, the node fetches
   a short window of blocks and calls `Chain.ReorgTo`. A fork wins only with
   strictly greater accumulated work.

## Storage

`Store` is the persistence interface. Two implementations exist:

- Badger (`badger_store.go`) is used by `nosoxd`. State changes are published
  through a durable fence so readers never see a partial write.
- An in-memory store is used by tests. It writes a snapshot only on `Save`
  or `Close`.

On restart the node checks that the stored genesis equals the one it derives,
replays every stored block through validation, and compares the resulting state
with the database. Replay streams through a disk-backed scratch store. Its time
and scratch disk grow with the length of the chain.

## Networking

- Transports: TCP and QUIC on the same port. libp2p default security and stream multiplexing.
- Gossip: two topics, one for blocks and one for transactions, namespaced by
  network magic.
- Streams: a hello stream exchanging height and tip hash, and a sync stream
  serving block ranges of at most 64 blocks.
- Peer discovery: seeds from `-seed`, an HTTPS seed list (opt-in with
  `-http-seeds`), DNS TXT seeds (no domains are configured), and static relays
  from `-relay`. There is no DHT and no local-network discovery.
- The seed lists in `seeds/` are empty. No public seed nodes exist.

## Not implemented

Cut-through, transaction offsets, light-client sync, seed-based wallet
recovery, payment proofs and authenticated slates. Transaction submission over
RPC and the two-party wallet spend path exist; see [Wallet](wallet.md) and
[Roadmap](roadmap.md).
