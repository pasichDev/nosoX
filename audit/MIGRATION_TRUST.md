# Migration trust assessment — BLOCKED

The local fixture `testdata/sumary_59238.psk` is retained byte-for-byte.
SHA256: `dc4a7aa23a6fead6fc951ce13f8405215b6dda8f5f04963694d855a60df9631b`.
It has 4956 fixed106-byte records, 3561 positive balances, no negative balances,
and total297180390730000 base units (2,971,803.9073 NOSO).

Eleven records (indices4749,4750,4755,4756,4760,4762,4764,4765,4767,4768,4769)
contain Android MutableLiveData object strings in place of valid historical
addresses. The raw fixture and record-level validation provide the evidence; no economic
legitimacy is inferred from a total. The bundler rejects the entire input
at the first malformed record. It does not silently discard, redistribute or
repair those balances. TestRejectOriginalMalformedSnapshot pins that behavior;
synthetic valid input tests are explicitly renamed and separate.

The repository's simple legacy arithmetic predicts
`1030390730000 + 59238*5000000000 = 297220390730000` base units at that height.
The fixture is40000000000 units (400 NOSO) lower. That is a discrepancy to
investigate, not evidence of either authorized burns, theft or proven inflation.
The legacy GetSupply helper and reward-sharing implementation are themselves
incomplete approximations. A matching aggregate would still not authenticate
ownership or issuance history. Previous documents also inconsistently describe
59238 versus180031 and different allocation counts/hashes.

A local candidate v1 archive is available at `/home/pasich/repo/noso/BLOCKS`:
180032 continuous files0..180031,2684282134 bytes. Earlier absence claims were
inaccurate. The version4 header diagnostic ran over every file (see
LEGACY_ARCHIVE_V4_HEADER_DIAGNOSTIC.json):1424238 declared orders, no negative
header rewards/fees/counts, short declared bodies or filename/header mismatch.
Header rewards sum901185390730000; fees361337942285 base units. Untyped PoS/MN
trail bytes total1817608602 in171607 files. These untrusted headers do not prove
chain linkage, signatures, canonical provenance or economic legitimacy.
No independently authenticated canonical archive identity, signed snapshot,
complete deployed reward/fee/burn replay or independent balance reconciliation
has been verified. Fixtures cannot prove historical balances
were protocol-authorized. No snapshot is approved for trusted mainnet genesis.

The existing GVT constant70000000000 at1e8 base units is700 NOSO, not70. At100
occupied slots this would carry70000 NOSO, not the7000 previously claimed. The
constant was intentionally preserved; maintainer/protocol review must choose the
economics explicitly. No premine, developer allocation or fee destination changed.

Version4 requires canonical historical public-key TEXT and a new ECDSA-SHA256
signature bound to source/network/genesis/exact destination leg. Native kernel,
range proof and individual/global conservation checks remain mandatory. Old
context-free builders fail explicitly. Tests demonstrate regular/GVT claims only
from synthetic operator-trusted genesis, not an authenticated historical snapshot.
See legacy-ownership-procedure.md for the complete encoding. This does not resolve
malformed accounts, economic authenticity, GVT policy approval or provenance;
mainnet mode remains disabled.

Release gate: independently reconstruct and reconcile historical supply and
ownership, publish a reviewed allocation manifest only under explicit separate
authorization, and obtain cryptographic/protocol review before approving any mainnet migration.
