# Migration is blocked

The original claims of verified 1:1 inheritance and public-key derivation from a
hashed address were incorrect. The current validator rejects **all** Legacy and
LegacyGVT spends. A reviewed claim format must supply a historical public key,
verify canonical historical address derivation, and bind ownership to destination,
network/genesis and transaction context. No such consensus procedure is approved.

[Migration trust evidence](../../audit/MIGRATION_TRUST.md) describes the unchanged
fixture, malformed accounts and missing historical issuance reconciliation.
Genesis parsing now rejects malformed/duplicate/negative allocations and missing
explicit snapshot files; this does not prove the remaining economic history.

Version-2 genesis includes network magic in its header and complete body roots.
There is no accepted mainnet snapshot, signed allocation manifest or automatic
version-1 database migration. Use fresh disposable local test data. Never silently
sanitize malformed accounts into a supposedly trusted mainnet genesis.

`GVTBaseValue=70_000_000_000` base units equals **700**, not 70 NOSO at 1e8 units.
The constant was preserved. Changing it requires an explicit economic decision.
