# Running a node

`nosoxd` refuses `-network mainnet`. Every network option below applies to
`testnet` or to private experiments.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-data` | `./nosox-data` | Data directory (`chain/`, `coinbases.json` and its archives, `p2p_identity.key`, `peers.json`). |
| `-network` | `testnet` | `testnet`, or `mainnet` which is refused. |
| `-rpc` | `127.0.0.1:7780` | JSON-RPC listen address. |
| `-p2p` | `127.0.0.1:7781` | P2P listen address, TCP and QUIC. Numeric IP required. |
| `-seed` | empty | Comma-separated libp2p multiaddresses to dial. |
| `-relay` | empty | Comma-separated relay multiaddresses, dialed once at startup. No AutoRelay reservation is made. |
| `-http-seeds` | `false` | Fetch a seed list over HTTPS at startup. Needs the `seeds-v1` tag to exist in the repository; until it is published the fetch gets a 404 and the node has no HTTP seeds (see Peer discovery). |
| `-allow-private-seeds` | `false` | Keep loopback, private, link-local and CGNAT addresses that come from DNS or HTTPS seed lists (private test networks). Addresses given with `-seed` are never filtered. |
| `-nat-portmap` | `false` | Ask the router for a UPnP / NAT-PMP port mapping. Off by default. |
| `-mine` | `false` | Start mining. Mining waits until at least one peer is connected and none has more work. |
| `-solo-mine` | `false` | Mine without waiting for a synced peer, also when mining is started over RPC (a fresh single-node network). Otherwise the miner idles, and re-checks before every block, until a peer is connected and none has more work. |
| `-threads` | `1` | Mining threads. |
| `-reward` | `nosox-default` | Label only. |
| `-rpc-cors-origin` | empty | One browser origin allowed to call the RPC (exact origin, or `*`). Empty sends no CORS headers, so no web page can read a response. |
| `-rpc-tls-cert`, `-rpc-tls-key` | empty | Serve RPC over HTTPS. Both required together. |
| `-testnet-difficulty` | built-in | Testnet only: initial difficulty of the testnet genesis. It changes the genesis hash, so every node of that testnet must use the same value. |
| `-verify-full` | `false` | Replay and fully verify the whole chain at start even when a `chain/verified.json` marker exists. Use it after restoring a data directory from an untrusted source. |
| `-storage-maintenance` | `10m` | Interval of one bounded storage GC attempt; `0` disables. |

The RPC bearer token is **not** a flag. The old `-rpc-token` flag was removed
because a command line is readable by every local user; the daemon exits if it
is given. Export the token instead (at least 32 printable ASCII bytes):

```bash
export NOSOX_RPC_TOKEN="$(openssl rand -hex 32)"
```

A non-loopback `-rpc` address requires `NOSOX_RPC_TOKEN` **and** TLS
(`-rpc-tls-cert` / `-rpc-tls-key`); the daemon exits otherwise.

## Two nodes on one machine

```bash
bin/nosoxd -data ./a -rpc 127.0.0.1:7780 -p2p 127.0.0.1:7781 -mine
```

The first node prints its address, for example
`/ip4/127.0.0.1/tcp/7781/p2p/12D3Koo...`. Start the second with that address:

```bash
bin/nosoxd -data ./b -rpc 127.0.0.1:8780 -p2p 127.0.0.1:8781 \
    -seed /ip4/127.0.0.1/tcp/7781/p2p/<peer-id>
```

Compare `nosox-cli tip` on both. The hashes converge once the second node has
synced.

## Peer discovery

There are no public seed nodes. The files in `seeds/` contain no addresses.
Peers come from `-seed`, `-relay`, DNS TXT seeds (no domains are configured), the
optional HTTPS seed list, and peers this node met before. There is no DHT: with a
handful of seeds and an address book it adds a large dependency and an eclipse
surface for no benefit at this network size. A node started with no seed and no
known peer logs a warning, because a miner in that state builds a chain alone.

- **Stable address.** The node key lives in `<data>/p2p_identity.key` (mode 0600,
  created on first start; a key readable by others is refused). The peer ID, and
  so every published `/p2p/<id>` seed address, survives a restart. Back the file
  up if the address is published.
- **Reconnect.** Every 30 s, while below 8 peers, the node redials its seeds and
  the peers it has met (kept in `<data>/peers.json`). A seed that was down at
  start, or a dropped connection, heals by itself.
- **HTTPS seed list** (`-http-seeds`, off by default). Fetched only over HTTPS,
  from a pinned tag (`SeedsRef` in `v2/p2p/httpseeds.go`, currently `seeds-v1`),
  never from a branch; redirects must stay on the same HTTPS host. **The tag
  `seeds-v1` must be created in the repository before `-http-seeds` can work**:
  until it exists the fetch gets a 404 and the node simply has no HTTP seeds.
  Rotating seeds means editing `seeds/*.txt`, tagging that commit with a new ref
  (`seeds-v2`, ...) and shipping a release that bumps `SeedsRef`. The list is unsigned. Loopback,
  private, link-local and CGNAT addresses in HTTP and DNS seed lists are dropped,
  so a list cannot make the node probe its own network. Addresses given with
  `-seed` are never filtered.
- **NAT.** UPnP / NAT-PMP port mapping is off unless enabled explicitly (`-nat-portmap`). Open both
  TCP and UDP on the P2P port if you want inbound connections.

### Sync and fork choice

Nodes follow the chain with the most accumulated work, never the tallest. Hello
carries cumulative work; the node picks the peer with the most work above its own,
finds the common ancestor with a block locator (any fork up to the 1024-block
reorg limit), fetches in 64-block batches and reorganises once the fork is
provably heavier. A peer that stalls, advertises work it cannot deliver or sends
invalid data is scored, backed off and, if it keeps failing, disconnected and
banned for 10 minutes; the next best peer is tried at once. Gossip uses
content-hash message IDs, so replays are not revalidated, with separate block and
transaction budgets, gossipsub peer scoring, peer exchange off, and only the
block and transaction topics allowed. Wire messages use a compact binary format
whose size limits are derived from `MaxBlockBodyBytes`; the sync service serves
one stream per peer and has global request and byte budgets.

## Exposing the RPC

```bash
export NOSOX_RPC_TOKEN="$(openssl rand -hex 32)"
bin/nosoxd -rpc 0.0.0.0:7780 -rpc-tls-cert cert.pem -rpc-tls-key key.pem
```

With a token set, the read-only methods in [RPC](rpc.md) stay public and the
others (including `minerstats`) need `Authorization: Bearer <token>`; set the
same `NOSOX_RPC_TOKEN` in the environment of `nosox-cli`. No CORS headers are
sent by default, so a web page cannot read responses; `-rpc-cors-origin` allows
exactly one origin (or `*` if you pass it explicitly).

## Data and backups

The `chain/` directory is a Badger database. It can be rebuilt by syncing from
peers. `coinbases.json` holds miner reward keys and cannot be rebuilt; back it up
privately.

**Key-file archives.** The miner writes a reward key only for a block it solved.
When `coinbases.json` reaches 5,000 records the node renames it to
`coinbases.json.<unixnano>.<n>` (an intact, importable file) and starts a new
one; no key is ever deleted. Back up and import **all** of them. A wallet that
imports only the live `coinbases.json` misses every reward whose key sits in an
archive. `nosox-cli wallet import-coinbase <wallet> <data>/coinbases.json` reads
the live file and every `coinbases.json.<ts>.<n>` beside it, and also works when
the live file is missing (a crash right after a rotation).

On start the node checks the stored chain against `chain/verified.json`, a
marker recording the verified genesis, height and tip hash. Stored blocks up to
the marker are checked structurally and only blocks after it are fully
re-validated, so a restart no longer replays every proof of work. Without a
marker, or with `-verify-full`, the whole chain is replayed through validation,
which takes time and scratch disk space proportional to the chain length. Plan
for at least 2 GiB of RAM; this is a working target from tests, not a guarantee.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `mainnet disabled` | Expected. Use `testnet`. |
| `non-loopback RPC requires a token` / `requires TLS` | Export `NOSOX_RPC_TOKEN` and pass `-rpc-tls-cert` / `-rpc-tls-key`, or bind to loopback. |
| `-rpc-token was removed` | Use the `NOSOX_RPC_TOKEN` environment variable. |
| `mining waits for a synced peer` | Connect a peer with `-seed`, or pass `-solo-mine` on a single-node network. |
| Genesis hash differs between nodes | Different network, or a data directory from another protocol version. |
| No peers | Nothing to dial. Pass `-seed`, check firewall for TCP and UDP. `-http-seeds` finds nothing until the `seeds-v1` tag exists. |
| `chain: stale block` in logs | A block arrived for an old parent; the node may fetch a fork window. |
