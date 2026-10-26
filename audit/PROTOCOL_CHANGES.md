# Protocol and compatibility changes

Baseline:6179eb56d53768a19950f07e9c806fd384572c5d. This is a breaking experimental
protocol revision, not a compatible security release for a live network.
No public network was contacted or upgraded. No economic constants changed.

1. BlockVersion1→2; header adds uint32 NetworkMagic immediately after Version.
   HeaderID/PoW encoding changes. Genesis now binds network magic instead of
   silently ignoring its config. Subsequent headers must match network domain.
2. Complete ordered domain-separated OutputRoot/KernelRoot replace incomplete
   duplicate-last trees; inputs, proofs, signatures and all metadata are bound.
   OutputID includes proofs/all fields. KernelID adds a version2 signing domain;
   TransactionID includes the entire body with uint64 counts/length delimiters.
   Existing signatures, block hashes and genesis hashes consequently change.
3. Require ordinary kernel Schnorr checks; exact coinbase count/value/signature/
   fee/lock rules; maturity, supported features, stored metadata, duplicate input
   prevention, bounded fields and int64 fee sums. Historical commitment and
   KernelID uniqueness now persists/reorgs with canonical state. Formerly
   accepted unsafe blocks/transactions are invalid, not grandfathered.
4. Legacy/GVT ownership remains unspecified and is rejected entirely. Old
   version1 shape-only range proofs are rejected. Point/scalar/proof encodings
   are canonical, and public identity keys/excesses/nonces are invalid. Internal
   mathematical zero has one encoding. No custom substitute proof was invented.
5. TotalKernelOffset must be zero: no unimplemented offset semantics accepted.
6. Nonnegative timestamps must strictly advance and be no more than7200 seconds
   ahead of local validator UTC time, using overflow-safe arithmetic. This adds
   an explicit synchronized-clock assumption. A large future timestamp cannot
   be used to exhaust the int64 timeline. Median-past-time design remains open.
7. Keep the existing weighted-window difficulty formula but evaluate exact
   integers and saturate at uint64; reject zero difficulty and missing history.
   Most-work uses sum(floor(2^256/(target+1))) over divergent suffix, strict wins.
   Effective existing depth cap1024 is documented instead of advertised5400.
8. Reorg validates a staged candidate then commits atomically; no replay-before-
   undo recovery. New historical identity keys accompany backend state; startup
   pins trusted genesis and verifies replay/derived indexes. Old databases fail
   validation; no implicit replay of permissive histories or schema migration.
9. P2P topic suffixes and /noso/hello/2,/noso/sync/2 use bounded JSON instead of
   gob. This intentionally breaks old gossip/stream interoperability. Per-frame,
   per-field, queue/concurrency, limiter and sync-range bounds apply.
10. Wallet envelope writes/import checks and slate intent-signature binding are
    stricter; old incomplete slate signatures may reject. Intent signatures do
    not implement a complete confidential interactive payment protocol.
11. Go1.27.3, relocated module github.com/pasichDev/noso-go and patched transport
    dependencies change build/import compatibility. CI takes version from go.mod.
    Daemon defaults to loopback testnet/no HTTP seeds and refuses mainnet.

Subsidy, halving interval, fee destination, dev allocation, GVT value and premine
were preserved. In particular GVTBaseValue actually means700NOSO, and all fees
still route to the fixed existing point. Same fee totals repeat the fee output
commitment; this unresolved design now fails closed under historical uniqueness.
Changing the recipient or weakening uniqueness is not an acceptable incidental fix.

Migration policy: use a new disposable isolated devnet data directory. Original
fixtures are retained; the malformed summary fixture now explicitly fails genesis
validation. A trusted public genesis needs independent economic reconciliation,
canonical ownership proof, reviewed allocation decisions and separate release
approval. No production network compatibility or mainnet migration is claimed.

## Subsequent version3 revision (base34f0d0d)

SP1/SP2/SP3 are implemented in this follow-up; the earlier version2 inventory
above remains historical. See SP123_DESIGN.md and SP123_COMPLETION.md.

- BlockVersion is3. Fees now use `F*H+P_dev+t*G`, with public scalar from the
  exact network/height/parent/fee context in DEVFUND.md. The spending scalar is
  `(d_dev+t) mod n`. Both adjusted recipient and final commitment must be valid
  nonidentity points. Fee amount, recipient, subsidy and allocation constants
  are unchanged. Historical uniqueness is not bypassed. Off-repo signers must
  adopt the canonical helper before spending the revised outputs.
- KernelID/OutputID/body serialization domains retain their v2 format; header
  version and fee outputs/genesis hash change. JSON transport v2 is retained.
  This is not compatibility with old consensus, nor a live-network upgrade.
- Stores persist exact undo records. Routine reorg/undo uses read-through suffix
  overlays and touched-key publication rather than rebuilding retained history.
- Badger now uses managed timestamps, chunked staged writes and a durable active
  fence. Interrupted writes cannot become visible merely when a later timestamp
  publishes; dirty-key recovery restores the old committed values/tombstones.
  An empty schema fence precedes genesis staging. Old unfenced DBs are rejected,
  with no silent migration. Use a separate disposable local data directory.
- Old MVCC versions are retained (discard timestamp0). Safe reclamation, startup
  scan cost, large-delta RAM budgets and hardware power-loss behavior remain
  explicit operational limits. Removing the single-transaction cap is not a
  claim of unlimited storage or production resource assurance.
