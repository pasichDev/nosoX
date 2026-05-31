# Forking your own Noso v2 chain

The v2 codebase is parameter-driven: switch the network magic, the
genesis-summary path, and the initial difficulty and you have your own
chain.

## Minimal fork

```bash
git clone https://github.com/Noso-Project/noso-go
cd noso-go
go build -o bin/nosoxd ./cmd/nosoxd

bin/nosoxd \
    -data ./mychain \
    -network testnet \
    -rpc :9780 \
    -p2p :9781
```

This bootstraps a chain whose genesis contains zero legacy outputs and
whose network magic is `0x4e4f5854` ("NOXT"). Nodes with `mainnet` magic
will refuse to peer.

## Fork that carries v1 balances

```bash
bin/nosoxd \
    -data ./mychain \
    -genesis-summary path/to/sumary.psk \
    -network mainnet
```

You'll get the same canonical genesis hash everyone else gets — so all
forks that supply the same `sumary.psk` are commensurate at block 0.
They diverge from block 1 onward via independent PoW.

## Custom parameters

Edit `v2/types/types.go` constants for things like:

- `TargetBlockTimeSeconds` — change block cadence
- `InitialReward` / `BlockHalvingInterval` — change emission schedule
- `CoinbaseLock` — change maturity
- `NetworkMagicMainnet` — change network ID (must do this for an
  independent network!)

Then rebuild and distribute the binary.

## Genesis nonce

The first node to launch a network must grind the genesis nonce to meet
`InitialDifficulty`. At difficulty 256 this takes about a second on a
Pi. Hardcode the resulting nonce in your published binary so every node
agrees on the same genesis bytes.

## Seed nodes

Distribute a small list of public seed IPs in `-seed=1.2.3.4:7781,...`.
The address book file under `-data/p2p-addrs.txt` extends from seeds at
runtime.
