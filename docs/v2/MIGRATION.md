# Migration is blocked

The original claims of verified 1:1 inheritance and public-key derivation from a
hashed address were incorrect. Version4 implements an experimental explicit
claim leg with historical public-key TEXT, ECDSA-SHA256 ownership and native
Schnorr/range-proof/conservation checks. Source state, network and canonical
genesis are chosen by the verifier. See the exact
[ownership procedure](../../audit/legacy-ownership-procedure.md). Old SHA1
transaction signatures and the old context-free wallet builders are not accepted.
A correct signature does not prove that the original balance was authorized.

[Migration trust evidence](../../audit/MIGRATION_TRUST.md) describes the unchanged
fixture, malformed accounts and missing historical issuance reconciliation.
Genesis parsing now rejects malformed/duplicate/negative allocations and missing
explicit snapshot files; this does not prove the remaining economic history.

Version4 genesis includes network magic in its header and complete body roots.
There is no accepted mainnet snapshot, signed allocation manifest or automatic
version-1 database migration. Use fresh disposable local test data. Never silently
sanitize malformed accounts into a supposedly trusted mainnet genesis.

`GVTBaseValue=70_000_000_000` base units equals **700**, not 70 NOSO at 1e8 units.
The constant was preserved. Changing it requires an explicit economic decision.

A local candidate archive of180032 blocks is available and has undergone a
read-only header/body-size diagnostic. It is not independently authenticated,
and signatures, MD5 chain linkage, deployed reward-sharing rules and balances
have not been fully replayed/reconciled. See the latest evidence in
[audit/MIGRATION_TRUST.md](../../audit/MIGRATION_TRUST.md). Mainnet remains blocked.
