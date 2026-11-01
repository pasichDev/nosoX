# Security

## Status

No independent security audit or cryptographic review has taken place. The
custom Schnorr signature and range proof are unreviewed. Signing, proving and
commitment code on secrets is not constant time. `nosoxd` refuses to start on
mainnet. Do not hold value in this software.

## What has been done

The maintainers reviewed the code internally and fixed the problems they found.
The summary, with severity and status for each, is in
[SECURITY_FINDINGS.md](https://github.com/pasichDev/nosoX/blob/main/audit/SECURITY_FINDINGS.md).
Other documents:

- [Threat model](https://github.com/pasichDev/nosoX/blob/main/audit/THREAT_MODEL.md)
- [Consensus invariants](https://github.com/pasichDev/nosoX/blob/main/audit/CONSENSUS_INVARIANTS.md)
- [Release readiness](https://github.com/pasichDev/nosoX/blob/main/audit/RELEASE_READINESS.md)
- [External review packet](https://github.com/pasichDev/nosoX/blob/main/audit/EXTERNAL_CRYPTO_REVIEW_PACKET.md)

## Open findings

- NX-018: custom proof construction without independent review.
- NX-019: secret operations are not constant time.
- A further round of internal reviews (2026-10-31) reported
  findings in consensus, networking, the wallet and the RPC. Their status is
  tracked in SECURITY_FINDINGS.md. None of them is an independent audit.

## Daemon defaults

- Network `testnet`; `mainnet` is refused.
- RPC and P2P bind to loopback. A non-loopback RPC address requires a token.
- Seed discovery over HTTPS is off by default.
- When no token is set, browser requests (with an `Origin` header) reach only
  read-only methods.

TLS, firewalls and host permissions are the operator's job.

## Reporting a vulnerability

Use GitHub private vulnerability reporting on the repository's Security tab.
Do not open a public issue for a vulnerability. See
[SECURITY.md](https://github.com/pasichDev/nosoX/blob/main/SECURITY.md) for scope.
There is no response-time guarantee and no bounty.
