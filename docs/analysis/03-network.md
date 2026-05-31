# Noso Wire Protocol Spec

## 1. Transport

- **TCP**, line-based, terminator `\n` (LF only — not CRLF).
- **Default P2P port:** 8080.
- **No TLS.** Mainnet runs cleartext (preserve for compat; document in BUGS.md).
- **Indy `MaxLineLength = MaxInt`** in the Pascal node — DoS vector. The Go
  port should cap line length (e.g. 64 KiB) and reject longer lines with a
  hard error. This is safe to fix; it does not change wire semantics.

## 2. PSK header

Every text command begins with:

```
PSK <proto-version> <node-version> <utc-time-string> <command> [args...]\n
```

Currently:
- `proto-version = 2`
- `node-version = 0.4.3` (or whatever the local node reports)

The first `$PING` authenticates the peer.

## 3. Commands

### `$PING` / `$PONG` (codes 3/4)

Args are 15 space-separated fields:

```
connCount lastBlockN lastBlockHashFull sumHashFull pendingCount resumeHash[:5]
connStatus listenPort mnsHash[:5] mnsCount bestDiff(="null") mnChecksCount
gvtsHash cfgHash[:5] psoHash[:5]
```

### `$GETPENDING` (5)

Server replies with one PSK line per pending entry:
- TRFR are batched into `ORDER <n> $<line1> $<line2> ...`
- CUSTOM/SNDGVT as `$<orderString>`

### `$GETSUMARY` (6) — binary stream after `SUMARYFILE` ASCII marker.
### `$GETRESUMEN` (7) — binary stream after `RESUMENFILE` ASCII marker.

### `$LASTBLOCK <N>` (8)

Reply: text marker `BLOCKZIP` then a ZIP stream containing up to 100
consecutive `.blk` files named `<n>.blk` (paths in zip use `/`).

### `$CUSTOM` (9), `ORDER` (5-variant)

Submit pending. Rate-limited to ~100 per IP per scan window (`ArrCont` /
`BotsList`). Validation in `mpprotocol.pas:744-770` / `779-811`.

Single ORDER line layout (space-separated, in this order):

```
orderID orderLines orderType timeStamp reference trxLine sender
address receiver amountFee amountTrf signature trfrID
```

Max 30 transfers per ORDER batch.

### `$GETMNS` (11) → many `$MNREPO` lines.

### `$MNREPO` (13)

```
$MNREPO <ip> <port> <signAddr> <fundAddr> <firstBlock> <lastBlock>
        <total> <validations> <hash>
hash = MD5(ip + port + signAddr + fundAddr)
```

### `$MNCHECK` (14)

```
$MNCHECK <validatorIp> <block> <signAddr> <pubkey>
         <validatedList> <signature>
validatedList = ip;port:ip;port:...   (colon-delimited)
signature signs validatedList
```

### `$GETCHECKS` (15) — replay of recent checks.
### `GETMNSFILE` / `MNFILE` (16/17) — full MN file.
### `GETHEADUPDATE <fromBlock>` / `HEADUPDATE $<colon-delimited triples>` (18/19).

Triples: `block:blockhash:sumhash` separated by spaces. Used for ≤144-block
delta sync; bigger gaps trigger full `$GETRESUMEN`.

### `$GETGVTS` (20), `$SNDGVT` (21)
- Reply for GETGVTS: text `GVTSFILE` then binary stream.
- SNDGVT must be signed by `AdminPubKey`.

### `GETCFGDATA` (30) / `SETCFGDATA $<payload>` (31).
### `$GETPSOS` (32) → `PSOSFILE` then binary stream.

### `ADMINMSG <time> <message> <signature> <hash>`

`hash = MD5(time + message + signature)`. Signed with `AdminPubKey`.
Subcommands: `UPDATE RESTART SETMODE ADDNODE DELNODE ADDNTP DELNTP
ADDLOCKED DELLOCKED ADDNOSOPAY DELNOSOPAY CLEARCFG RESTORECFG`.

### Special replies
- `DUPLICATED` → server tells us we're already connected; close.
- `OLDVERSION` → version too old; close.

## 4. Peer discovery

- `seednodes.txt` first line: `DefNodes <ip1> <ip2> ... <ip10>` — fallback list.
- `nosocfg.psk` section 1 holds the user-configured node list. Format:
  colon-delimited `ip;port:ip;port:...`.
- Default port 8080 if no `;port` specified.

## 5. Pending pool semantics

- Memory array sorted by `TimeStamp ASC, OrderID ASC, TrxLine ASC`.
- Dedup by `TrfrID`.
- Cleared on sync to a new block.

## 6. Improvements safe to ship in the Go port (no wire-format change)

- **Bounded line length** — cap `bufio.Scanner` buffer.
- **Per-connection read deadline** — Pascal uses static `ReadTimeout`; in Go,
  set `conn.SetReadDeadline()` per `ReadLn`.
- **Context-cancellable goroutines** instead of unbounded per-peer threads.
- **Outgoing back-pressure**: bounded channel instead of unbounded `ArrayOutgoing`.
- **Per-IP rate limiter** abstraction in front of `$CUSTOM` / `ORDER` (still
  enforces the same numeric thresholds).
- **Explicit max payload size on ORDER batches** (already 30 transfers; cap
  total bytes too).

None of these change the bytes a Pascal peer sees on the wire.
