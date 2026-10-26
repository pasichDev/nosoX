# Experimental legacy ownership procedure

Status: version 4 has an explicit claim-leg verifier and wallet builder for
**explicitly trusted genesis deployments**. It cannot authenticate historical
issuance or approve a mainnet snapshot. Mainnet/economic migration trust remains
blocked under `MIGRATION_TRUST.md`; no genesis allocation or GVT value changed.

## Primary-source inspection

Only public implementation source under `/home/pasich/repo/noso` was inspected;
no wallet/private-key file, public node, or external wallet was used.

* `NosoNode-main/nosocrypto.pas:245-258` hashes the public-key **text** with
  SHA256, hashes the uppercase hexadecimal result with RIPEMD160, then applies
  the historical Base58/checksum algorithm. It does not hash the decoded point.
* `NosoDart-main/lib/crypto/noso_core.dart:54-88` explicitly exports an
  uncompressed point and pads the scalar to 32 bytes, and derives the same
  text-based address. `internal/crypto.AddressFromPublicKey` preserves this
  derivation and is reused; elliptic arithmetic is not reimplemented here.
* `NosoNode-main/mpsignerutils.pas:54,160-177` specifies SHA-1withECDSA and exports
  an unsigned scalar. That Pascal scalar export is not proof that all historical
  secret encodings were exactly 32 bytes. Dart explicitly pads them.
* `NosoDart-main/lib/crypto/noso_signer.dart:30-95` signs/validates decoded message
  bytes with SHA1 and serializes ASN.1 R/S. These routines are historical
  evidence, not an interoperability test of the new procedure.

Local source SHA256, for reproducible review (these hashes are observations,
not independent authentication of upstream code/history):

| File | SHA256 |
| --- | --- |
| nosocrypto.pas | fc91227f32d475613a17ba90a79c6f8a3bad7a645ae8cb42b99ec62fb80cbf80 |
| mpsignerutils.pas | e6b35ae270c436794f4260e95999b0e9f6999c34838fe7a317e8156db9497e4a |
| noso_core.dart | b443e3abd97f784dc90def54bce4490cadc1f0041c89c1109a6972ee9ea3c909 |
| noso_signer.dart | e7da49626c5e54aa36d111bf79139b378d18f5700797576324a87eb5b3030ee2 |

## New procedure version 1

The caller supplies a verifier-chosen network, genesis digest, exact v4
destination-leg digest, and a **trusted** source containing address,
positive int64 amount in base units, and a canonical compressed 33-byte Pedersen
source commitment. The source point identifies the active allocation; its address
and amount must be loaded from authenticated state. An arbitrary claimant-provided
commitment has no authority.
The helper does not reconstruct a source commitment from untrusted metadata.

`Digest` hashes the following exact bytes once with SHA256:

```
ASCII("NosoX/legacy-ownership/SHA256/v1") || 00
|| uint32be(network)
|| genesis[32] || sourceCommitment[33]
|| uint32be(len(address)) || address
|| uint64be(amount)
|| destinationTransactionDigest[32]
```

The network is a nonzero uint32 identifier; digests must be nonzero and the source
point must be valid compressed secp256k1. Only valid historical regular `N`
addresses of at most 64 bytes are supported. A single key
is not sufficient evidence for an `M` multisignature address or GVT policy.
`DestinationDigest` computes SHA256 of ASCII(`NosoX/legacy-claim-leg/v4`) || 00
|| OutputID[32] || KernelID[32]. OutputID binds the complete Plain destination
output including its range proof; KernelID binds the LegacyClaim kernel fields
and excludes the Schnorr signature. This avoids ownership-signature cycles.
The block format is flat and has no transaction boundaries: each legacy input
therefore explicitly names exactly one output and one kernel. There are no height,
timestamp or nonce fields. Source/network/genesis/destination binding rejects
cross-context replays; duplicate use within the identical context remains a
state-machine concern, as explained below.

`Verify` requires standard padded canonical Base64 with strict pad bits and exact
round-trip equality. The supplied public-key text decodes to exactly 65 bytes,
starting `04`, and a valid secp256k1 point. Its exact text must derive the trusted
source address. No attempt is made to recover a public key from an address.
DER must be strict and R/S must be in [1,n). **This new procedure rejects high-S**;
it does not assert that historical Pascal/Dart rejected high-S. Signers must
normalize S to min(S,n-S) before DER serialization. Verification uses the already
pinned `github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0` ECDSA implementation;
its strict parser checks minimal DER, range, sign and trailing bytes. No custom
elliptic-curve verifier or historical SHA1 signing API is used.

The new ECDSA digest is SHA256, not SHA1. Historical ownership keys can sign this
new message through a deliberately implemented signer; existing historical
transaction signatures are **not** valid claim evidence. No historical-client
interoperability or production deployment is claimed. `wallet.BuildLegacyClaimV4` and `BuildGVTRedeemV4` sign with the actual imported
legacy secret after canonical 32-byte scalar/keypair/address checks. Decred
ECDSA-SHA256 produces low-S DER; the wallet verifies it through the same helper.
Tests use only synthetic keys including public scalar 1 encoded as exactly 32
bytes with scalar range validation. That test key must never hold funds.

## Required integration and external evidence

The stateless helper intentionally can verify the same proof more than once.
The v4 chain transition loads each active source from trusted state, takes network
from the canonical tip and genesis identity from stored block zero, matches
metadata and verifies the explicit ownership leg. The named Plain output and
zero-fee, zero-lock LegacyClaim kernel must occur exactly once; claims cannot
share them, and unreferenced LegacyClaim kernels are forbidden. Each leg enforces
OutputCommit minus SourceCommit equals KernelExcess and verifies its Schnorr
signature. Atomic store application consumes the source with destination creation;
ordinary inputs forbid all legacy authorization fields. Mempool/reorg/restart
use the same checks. Signature hashes do not serve as source identity. This
closes an authorization mechanism only for explicitly trusted genesis: claimant
metadata and arbitrary genesis UTXOs still prove neither issuance nor provenance.

Remaining required external inputs are a complete independently sourced v1 block
archive and its authenticated canonical chain identity; the exact deployed
protocol/reward/fee/burn rules with version/height boundaries; independently
reconciled per-address balances and total issuance at an agreed migration height;
an authenticated reviewed allocation manifest and its canonical commitment;
an explicit resolution of malformed summary addresses and the observed 400 NOSO
discrepancy; an approved GVT ownership/economic policy; and reviewed target
network/genesis and the v4 claim-leg/source encodings. Public
keys and fresh claim signatures must be supplied by the respective owners;
private keys must stay with them. No available local fixture authenticates these
inputs. Mainnet migration remains fail-closed until those gates are met.

## Local archive discovery

A read-only filename/stat inventory on 2026-10-26 found
`/home/pasich/repo/noso/BLOCKS` contains 180032 numeric `.blk` files, continuously
numbered 0..180031 with no filename gaps, totaling 2684282134 bytes. The only
additional directory entry is `DB`. Thus a local candidate block archive **is
available**; earlier claims that no archive was available require correction.
Filename continuity and local bytes do not establish canonical chain identity,
upstream provenance, deployed-version rules or valid historical issuance.

`python3 audit/tools/scan_legacy_headers.py /home/pasich/repo/noso/BLOCKS`
reproduces the inventory and header/body-size diagnostic; `--max-height` bounds
header reads for a quick smoke check while retaining the full inventory.

An exhaustive read-only header/body-size diagnostic over those 180032 files
found no header-number/filename mismatch, short header, truncated declared order
body, negative header reward, negative header fee or negative order count. It
counted 1424238 declared orders; 171607 files contain trailing bytes totaling
1817608602 bytes. Header rewards sum to 901185390730000 base units: the genesis
header records 1030390730000 once, and all 180031 subsequent headers record
5000000000. Header fees sum to 361337942285. These are observations of untrusted
local headers, not proof of correctness or a reconciled ledger. This scan did
not verify MD5 file linkage, PoW, order signatures, spendable balances or supply.

The current `internal/storage/blocks.go` reads a 368-byte header and declared
562-byte orders, leaving PoS/MN bytes as untyped `Trail`. Pascal
`mpblock.pas:503-544` writes the PoS section as int64 payment, int32 recipient
count, then `TArrayPos` records at/after PoSBlockStart; MN uses the same structure
at/after MNBlockStart. A reviewed replay needs the exact packed `TArrayPos`
layout and all historical rule/config boundaries. `mpblock.pas:262,296-301,
333-340,352` distributes developer, PoS, MN and miner shares; MN percentage also
depends on the historical configuration mode through `GetCFGDataStr(0)`.
`Header.Reward` stores the base reward (`mpblock.pas:384`), so summing those
headers cannot establish per-owner balances or authenticate authorized issuance.
Existing `blockchain.VerifyOrder` checks historical SHA1 signature and public-key
text owner binding for TRFR/CUSTOM only; SNDGVT/PROJCT require separately reviewed
procedures. Those are diagnostic limits, not permission to discard other orders.
`masterpaskalform.pas:186-188` defines `TArrayPos` as a packed record containing
`string[32]` (33 bytes). Its PoSBlockStart is 8425 (line 606), MNBlockStart 48010
(line 608). `nosogeneral.pas:293-322` contains percentage ramps omitted by the
simple Go economics helper: PoS rises after 40000 up to 20%, MN rises every 4000
blocks up to 60%, and MNSONLY mode uses 90%. A replay must verify which rules
actually applied at each historical height, rather than assume current source
or the simplified Go implementation is sufficient.

## Tests

`v2/legacyclaim` pins a deterministic synthetic address/key/digest/signature
vector and rejects changed owners, networks, genesis, source commitments,
destination digests and amounts; missing contexts; malformed/off-curve/compressed
keys; multisig sources; noncanonical Base64/pad bits; malformed/trailing/nonminimal
DER; zero, negative and out-of-range R/S; high-S and incorrect signatures.
Both backends also test full AddBlock acceptance of synthetic trusted regular/GVT
claims, rejection of altered/missing ownership/context/destination, duplicate or
shared legs, fees, locks, inflation and replay, plus restart verification and
reorg restoration. Wallet tests preserve output/range-proof/kernel/conservation
assertions under mandatory v4 context; old ambiguous APIs explicitly reject, and
GVT identity transfer stays unsupported. These tests are not evidence about
historical allocations.

### Final diagnostic source and limits

The final command was:
`python3 audit/tools/scan_legacy_headers.py /home/pasich/repo/noso/BLOCKS --output audit/LEGACY_ARCHIVE_V4_HEADER_DIAGNOSTIC.json`.
It completed successfully in4.261s. The JSON pins the script SHA256 and all
observed totals/limitations. The scanner rejects symlink numeric entries,
duplicate numeric heights and inventories beyond height1000000, reads only
368header bytes per selected file and performs no network or wallet access.
Earlier LEGACY_ARCHIVE_HEADER_DIAGNOSTIC.json is retained as historical evidence;
the version4 result corresponds to the final checked-in scanner source.
