# Getting started

These steps run an isolated test node on your machine. They need Go 1.27.3 or
newer (the version in `go.mod`).

## Build

```bash
git clone https://github.com/pasichDev/noso-go
cd noso-go
go build -o bin/nosoxd ./cmd/nosoxd
go build -o bin/nosox-cli ./cmd/nosox-cli
```

## Run a node and mine

```bash
bin/nosoxd -data ./nosox-data -mine -solo-mine -threads 2 -reward demo
```

Defaults: network `testnet`, RPC on `127.0.0.1:7780`, P2P on
`127.0.0.1:7781`, no seed discovery. The node does not connect to anything
unless you pass `-seed`. `-solo-mine` lets a lone node mine: without it mining
waits for a synced peer.

The first start prints the genesis block hash and the node's libp2p address.
With the initial difficulty of 256, blocks arrive within seconds on a laptop.

## Check progress

In another terminal:

```bash
bin/nosox-cli tip 127.0.0.1:7780
bin/nosox-cli mine stats 127.0.0.1:7780
```

`tip` prints the height, hash and difficulty. `mine stats` prints the hash
count and rate, the blocks found and the miner's error counters. If the node
runs with `NOSOX_RPC_TOKEN`, export the same variable for `nosox-cli`
(`mine stats` is a restricted method).

## Mined coins

Coinbase outputs are created and recorded in `./nosox-data/coinbases.json`.
To spend them, import the records with `nosox-cli wallet import-coinbase`
(it reads the live file and its `coinbases.json.<ts>.<n>` archives) and pay with
`wallet pay`, `receive` and `finalize`. See [Wallet](wallet.md) for the details:

- `wallet new` needs a passphrase of at least 12 characters.
- Payments are exchanged as `SLATEPACK3.` slates. `wallet receive <wallet>
  <slate|@file> [node-rpc]` takes the node address so the wallet can pin its
  network the first time.
- An output counts as confirmed after `NOSOX_CONFIRMATIONS` blocks (default 10).
- `wallet pay ... <fee|default>`: nodes refuse a fee below the relay minimum;
  `default` pays enough for any payment the wallet builds.

## Run the tests

```bash
go vet ./...
go test ./...
go test -race ./...
```

Use `-p 2` on small machines to limit parallel packages. A multi-node test on
loopback:

```bash
go test ./v2/p2p -run 'TestThreeNode|TestPreAdmittedNativeTransactionGossips' -count=1
```

## Wipe state

The chain lives in the directory given to `-data`. Delete that directory to
start over. The protocol version changes between releases, and databases from
earlier protocol versions are rejected.
