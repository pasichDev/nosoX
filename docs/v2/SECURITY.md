# Security and disclosure

**Unsafe research prototype. Do not hold value or operate a public network.**
No independent security audit or cryptographic assurance is claimed.

Read [threat model](../../audit/THREAT_MODEL.md),
[findings](../../audit/SECURITY_AUDIT.md) and
[release gates](../../audit/RELEASE_READINESS.md).

Report findings privately to the maintainer through an already established
private channel. Check that any GitHub private reporting facility actually exists
before relying on it. Do not publish secrets, working attack tools or unreviewed
vulnerability details in public issues. There is no promised response SLA or
bug-bounty program. Tests and reproductions must use isolated local fixtures and
loopback peers, never public cryptocurrency networks.

The hardened daemon defaults to loopback RPC/P2P, testnet, no HTTPS seed discovery,
and refuses mainnet mode. Non-loopback RPC requires a token. Public read methods
remain an explicit allow-list. TLS, network isolation and host permissions remain
operator responsibilities; authentication does not establish consensus safety.

Version4 technical remediation and residual High gates are summarized in
[BLOCKERS_V4.md](../../audit/BLOCKERS_V4.md). Legacy signatures authorize only
explicitly trusted allocations; they do not authenticate historical supply.
Reader-safe reclamation and explicit consensus limits do not guarantee bounded
disk growth under permanent I/O failures or universal whole-process RSS.
