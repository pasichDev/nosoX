# Noso RPC + Console Parser Spec

## RPC server (`mprpc.pas`)

- Transport: HTTP, JSON-RPC 2.0.
- Default port: **8078**.
- Auth: `RPCPass` exists but is NOT enforced in the Pascal code. The Go
  port should still read the same setting and add an opt-in token check at
  the proxy/middleware layer (off by default to preserve current behavior;
  configurable on).

### Error codes
`400` bad request · `401` invalid JSON · `402` invalid method · `407` send
funds failed · `498` not authorized · `499` unexpected error.

### Methods

| Method                  | Params                                   | Notes                                  |
| ----------------------- | ---------------------------------------- | -------------------------------------- |
| `test`                  | —                                        | `"testok"`                             |
| `banned`                | —                                        | name-of-banned-method check            |
| `restart`               | —                                        | trigger restart                        |
| `getaddressbalance`     | `addr [addr...]`                         | per-addr object                        |
| `getorderinfo`          | `orderid`                                |                                        |
| `getblocksinfo`         | `blockN [blockN...]`                     |                                        |
| `getmainnetinfo`        | —                                        | tip status                             |
| `getpendingorders`      | —                                        | CSV-encoded                            |
| `lockedmns`             | —                                        |                                        |
| `getpeers`              | —                                        | `["ip:port", ...]`                     |
| `getblockorders`        | `blockN`                                 |                                        |
| `getblockmns`           | `blockN`                                 | only for blocks ≥ 48010                |
| `getmasternodes`        | —                                        |                                        |
| `getwalletbalance`      | —                                        |                                        |
| `getnewaddress`         | `[count]` (1, max 100)                   |                                        |
| `getnewaddressfull`     | —                                        | `{hash, public, private}`              |
| `islocaladdress`        | `addr`                                   |                                        |
| `setdefault`            | `addr`                                   |                                        |
| `getgvtinfo`            | —                                        |                                        |
| `sendfunds`             | `dest amount [ref]`                      |                                        |
| `checkcertificate`      | `cert`                                   |                                        |
| `submitorder`           | `orderString`                            |                                        |
| `submitorderwr`         | `orderString`                            | wait-for-response variant              |

## Console parser (`mpparser.pas`)

Commands worth porting to `cmd/nosocli`:

- Node: `VER STATUS RESTART SERVERON SERVEROFF FORCESERVER SETPORT OFFSET TIMESTAMP`
- Wallet: `NEWADDRESS SHOWWALLET BALANCE IMPWALLET EXPWALLET SETDEFAULT SHOWKEYS EXPKEYS NEWFROMKEYS ADDRESS HISTORY`
- Tx: `SENDTO CUSTOMIZE SENDGVT PENDING ORDER`
- Chain: `BLOCK LBINFO HALVING SUPPLY GETPOS GETMNS TESTHEAD HEADSIZE BLOCKPOS BLOCKMNS`
- RPC: `SETRPCPORT RPCON RPCOFF`
- Network: `NODES BOTS PEERS CONNECTTO MYIP`
- Crypto helpers (debug/cross-check parity): `SHA256 MD5 MD160 BASE58SUM GETCERT CHECKCERT TESTHASH COMPARE ADDFROMPUB`
- Export: `EXPORTADDRESS SUMARY REBUILDSUM ZIPSUMARY`
- Config: `NOSOCFG SETMODE ADDNODE DELNODE ADDPOOL DELPOOL RESTORECFG ADDNOSOPAY DELNOSOPAY`
- Consensus/PSO: `CONSENSUS CONSTATS NEWPSO LISTPSOS CLEARPSOS SHOWPSOS MNSCHECKS`
- System: `OSVERSION SYSTEM FUNDS TOTALFEES GMTS CLEAR`

## Coin economics

- 8 decimal places. 1 base unit = 0.00000001 NOSO.
- Reward formula and halving in `02-blocks.md`.
- Min fee: `max(amount / 10_000, 1_000_000)`. Customization fee:
  25_000 base units (or 1_000_000 after block 162_000 — see `mpprotocol.pas`).

## Time sync (`nosotime.pas`)

- NTP servers parsed from `nosocfg.psk` section 2 (colon-delimited).
- Timeout per server: 500 ms.
- Block is "open" when `BlockAge ∈ [10, 585]` seconds (block period = 600 s).

## RPCBanned list

A semicolon-separated list of method names that always return `"banned"`.
Treat it as a denylist applied before dispatch.
