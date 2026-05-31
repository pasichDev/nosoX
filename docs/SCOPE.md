# Scope

Noso is a dead project (network died after scandals). This Go port is a
**revival/archive** effort, not a live-fork. Goals follow from that.

## In scope

- Read existing Pascal blockchain data byte-exact (block files, `sumary.psk`,
  `blchhead.nos`, `wallet.pkw`, `gvts.psk`, `psos.dat`).
- Validate the historical chain end-to-end using the original rules.
- Preserve cryptography exactly (secp256k1, SHA-1+ECDSA, Base58/Noso alphabet,
  hash-over-Base64-string-of-pubkey), so existing wallets and addresses stay
  valid. Users can still sign messages and submit transactions.
- Serve an RPC interface compatible with the Flutter wallet
  (NosoSova → NosoDart), so users can connect their existing wallets and read
  balances, history, and pending state from the archived chain.
- CLI parity with `mpparser.pas` for the operationally useful commands
  (balance, send, history, block lookup, summary tools).

## Out of scope (deferred / "future improvements")

- Live P2P peering with other Pascal nodes — there are none.
- Wire-byte exact `$PING`/`$PONG`, `$LASTBLOCK` zip-stream, `$MNREPO`, `$MNCHECK`,
  `GETHEADUPDATE`, `ADMINMSG` and other live-network commands. Stubbed only.
- Masternode validation network protocol.
- Cross-peer consensus voting (no peers to vote with — the on-disk chain *is*
  the chain).
- NTP time sync (no live block production to coordinate).
- New features beyond what the Pascal node does.

## Will be in BUGS.md

A catalog of weaknesses the analysis found (MD5 in consensus, SHA-1 in ECDSA,
no atomic writes, weak Base58 checksum, etc.) — documented for a future
hard-fork conversation, not silently fixed in this port.

This SCOPE.md was added after the user clarified on 2026-05-31: "проект
мертвий, тому міграції між нодами не треба, лише підтримка старого
блокчейну".
