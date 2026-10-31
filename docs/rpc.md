# RPC

JSON-RPC 2.0 over HTTP `POST` to the RPC address (default
`http://127.0.0.1:7780`). Method names are case-insensitive. Request bodies are
limited to 128 KiB (a transaction can be 64 KiB, base64 encoded inside the JSON). `GET /health` returns `ok`.

```bash
curl -s http://127.0.0.1:7780 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tip","params":[],"id":1}'
```

## Methods

| Method | Params | Result | Access |
|---|---|---|---|
| `version` | none | Version string. | public |
| `tip` | none | `valid`, `height`, `hash`, `difficulty`, `timestamp`, `pending`. | public |
| `getmainnetinfo` | none | Same as `tip`. | public |
| `getblock` | `[height]` | `height`, `hash`, `prev`, `timestamp`, `difficulty`, `nonce`. | public |
| `pending` | none | Number of transactions in the mempool. | public |
| `minerstats` | none | `state`, `hashes`, `elapsed`, `hashesps`, `blocks_found`, `errors`, `last_error`, `last_error_at` (only after a failure); `null` if no miner. | restricted |
| `genesisinfo` | none | `genesis_hash`, `difficulty`, `network` (the network magic of the chain this node serves, read from its genesis block; wallets bind to it). | public |
| `startmining` | `[threads]` or `[threads, rewardLabel]` | `"mining"`. Threads: an integer from 1 to the CPU count, **at most 16**. Label: 1-64 characters of `A-Z a-z 0-9 . _ -`. Extra or mistyped parameters are rejected (-32602). Already running: -32012. | restricted |
| `stopmining` | none | `"stopped"`. | restricted |
| `hasutxo` | `[commitHex]` | `present`, `tip`; when present also `features` (0 plain, 1 coinbase; 2 is unassigned and rejected), `height`, `block_hash` of the creating block, `mature`, `matures_at`. | restricted |
| `submittransaction` | `[base64Tx]` | `accepted`, `duplicate`, `txid`, `broadcast` (and `broadcast_error`). | restricted |

There is no method to read a full block body.

### `hasutxo`

`commitHex` is a 33-byte compressed commitment as 66 hex characters. The node
answers with one indexed lookup in the chain's own unspent set
(`Chain.UTXOByCommit`): no separate index, no scan, and it follows reorgs because
it reads the canonical state. For a coinbase output, `matures_at` is the first
block height that may spend it (`height + 60`) and `mature` says whether the next
block (`tip + 1`) is allowed to. `height` is the creating block; wallets count
confirmations as `tip - height + 1`.

### `submittransaction`

The parameter is the canonical binary transaction encoding of `v2/wallet`
(`EncodeTx`), base64 (standard alphabet, padded, strict). Decoding is bounded: at most
4 inputs, 4 outputs and 4 kernels, range proofs within the consensus bound, valid
curve points, 65-byte kernel signatures, no trailing bytes. The transaction then
goes through the mempool's chain validation (`ValidateTransaction`: inputs exist and
are mature, signatures, range proofs, balance, block capacity). If it is admitted
the node gossips it through the same libp2p path as relayed transactions
(`Service.BroadcastTx`, wired to the p2p node by the daemon). The call is idempotent:
submitting a transaction already in the pool re-validates it, re-gossips it and
returns `"duplicate": true`. A failed gossip does not fail the call; it is reported
as `broadcast_error` (a generic text; details go to the node log). A definitive rejection is error `-32010` with the validation message (at most 200 characters). A fee below the relay minimum is also `-32010`, with the text `fee too low for relay (policy): ...` giving the fee paid and the minimum: it is a node policy, not a transient condition, so retrying the same transaction cannot succeed; sign a new payment with a higher fee (`wallet pay ... default`). A transient refusal (pool full, resource budget) is `-32011` with HTTP 503: the transaction may still be valid, retry it. A conflict with a pending transaction is `-32013`: also not final, and the wallet advises against cancelling.

Why these are restricted: `submittransaction` mutates the mempool and triggers
gossip and expensive proof verification; `hasutxo` answers per-commitment queries
that reveal which outputs a wallet owns; `minerstats` reveals whether and how fast
the node mines. With a token set they need the bearer token; with no token
(loopback only) they are available to non-browser callers, and a request with an
`Origin` header is refused.

## Access control

- No token set: requests without an `Origin` header may call any method. A
  request carrying an `Origin` header (a browser) may call only the methods in
  `DefaultPublicMethods`. A custom `PublicMethods` list is ignored in this mode on
  purpose, so it can never widen what a web page reaches. The `Host` header must be
  `localhost` or an IP literal (DNS-rebinding defence); anything else gets 403.
  Only bind to loopback in this mode.
- Token set: public methods need no token. Restricted methods need
  `Authorization: Bearer <token>`. Tokens are compared as SHA-256 digests in
  constant time, so neither content nor length leaks. The `Host` allowlist is
  enforced in this mode only when `AllowedHosts` is configured.
- `POST` requests must have `Content-Type: application/json` (415 otherwise), which
  also closes the "simple request" cross-site route.
- CORS: no `Access-Control-*` header is sent by default, so no web page can read a
  response. `CORSOrigin` allows exactly one configured origin (or `*` only when set
  explicitly).
- Limits (all methods, `/health` included): 64 requests in flight (503, code -32020),
  200 requests per second with burst 400 per client address (429, code -32021, with
  `Retry-After`), and 16 concurrent HTTP/2 streams per connection when the daemon
  uses `Service.NewServer`. The wallet client retries throttled calls. `tip` answers
  are cached for 250 ms.
- Internal errors are logged on the node and answered with the text `internal error`.
- `nosox-cli` reads the token from `NOSOX_RPC_TOKEN` (never from arguments).

## Errors

Errors use the shape `{"error": {"code": N, "message": "..."}}` with standard
JSON-RPC 2.0 codes. Transport-level failures carry an HTTP status; errors in a
well-formed call return HTTP 200 unless noted.

| Code | HTTP | Meaning |
|---|---|---|
| -32700 | 400 | Parse error: the body is not valid JSON, or has trailing data. |
| -32600 | 400 | Invalid request: wrong shape, `jsonrpc` is not `"2.0"`, no method. 405 for a non-POST request, 413 for a body over the limit, 415 for a wrong `Content-Type`. |
| -32601 | 200 | Method not found. |
| -32602 | 400 | Invalid or missing parameters. |
| -32603 | 500 | Internal error. |
| -32000 | 503 | Component not configured (miner, chain, mempool). |
| -32001 | 401 | Not authorized. |
| -32004 | 200 | Not found (block). |
| -32010 | 200 | Transaction rejected by validation or relay policy such as the minimum fee (definitive). |
| -32011 | 503 | Transaction not admitted for a transient reason; retry. |
| -32012 | 409 | Conflict (miner already running). |
| -32013 | 200 | Transaction not admitted by relay policy because a competing transaction is pending (conflicting input, duplicate kernel, replacement fee too low). It is not a statement that the transaction is invalid and it may still be mined: do not cancel it, retry later. |
| -32020 | 503 | Too many requests in flight. |
| -32021 | 429 | Rate limit exceeded for this client address. |
| -32022 | 403 | `Host` header not allowed. |

Earlier versions returned a parse failure as HTTP 200 with code 401, and used the
codes 400, 402, 404, 498 and 500; those are gone.
