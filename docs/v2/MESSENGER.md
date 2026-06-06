# On-chain messenger — design & status

**Status: DEFERRED (not being built now).** Captured here so the requirements
aren't lost.

## Idea
A separate site + protocol to send a small amount of data on-chain that:
- lives ~1 week then expires/prunes (TTL),
- is heavily compressed,
- is end-to-end encrypted (only sender or the named recipient can read),
- carries a fee, with a per-address daily limit,
- funds development via the transparent dev fund (`types.DevFundPubKeyHex`).
Plus a wallet-auth SDK ("Sign in with NosoX wallet") and a demo site.

## Key open design point (why it's deferred)
**The message fee must be DYNAMIC — scaled to network difficulty/complexity,
not a fixed price.** A flat 0.01 NOSO is wrong: as difficulty/load rises the fee
should rise (and vice-versa) so messaging can't cheaply spam the chain and the
cost tracks real network cost. Needs a fee formula (e.g. f(difficulty, size,
recent load)) designed before implementation.

## Consequence for the dev fund
The dev fund was to be funded by these message fees. With the messenger
deferred, the dev fund (`types.DevFundPubKeyHex`, genesis allocation 0) has **no
income source yet** — in practice the chain is back to "0 dev fund" until a
funding mechanism is decided. Keep the published address constant for future
use, or drop it — owner's call.

## When resumed, rough scope
1. On-chain message record format + consensus rules (TTL prune, dynamic fee → dev fund, daily limit) + tests.
2. Compression + e2e encryption in wallet/CLI.
3. Wallet-auth SDK.
4. Demo site.
