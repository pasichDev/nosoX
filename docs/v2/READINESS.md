# Readiness

**RESEARCH ONLY. MAINNET BLOCKED.** No independent audit has occurred.

The evidence-based gates are in
[RELEASE_READINESS.md](../../audit/RELEASE_READINESS.md).
Local tests include actual signatures/proofs, both stores, faults/crashes and
multiple loopback peers; finite tests do not establish network or crypto safety.

The SP1 fee collision and SP2/SP3 full-prefix/single-transaction designs have
follow-up fixes with new regression evidence in audit/SP123_COMPLETION.md.
The latest [version4 remediation](../../audit/BLOCKERS_V4.md) implements trusted-
genesis claim authorization, reader-safe MVCC reclamation, streaming restart
verification and explicit consensus resource envelopes. Remaining gates include
independent cryptographic review, authenticated historical migration/supply,
maximum valid-fork capacity and deeper durability testing. This is not yet an external final-audit
candidate or a public-testnet candidate. It can be shared as explicitly unsafe
research source after maintainer review; this task does not publish it.
