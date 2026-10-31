# Security policy

## Status

NosoX is experimental. It has not been independently audited, and `nosoxd`
refuses to start on mainnet. Do not hold value in it. Known open issues are
listed in [audit/SECURITY_FINDINGS.md](audit/SECURITY_FINDINGS.md) and
[audit/RELEASE_READINESS.md](audit/RELEASE_READINESS.md).

## Supported versions

There are no tagged releases yet. Only the `main` branch is supported.

## Reporting a vulnerability

Use GitHub private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**. Do not open a public issue or pull
request for a vulnerability, and do not post exploit details publicly.

Include the affected commit, a description, and a reproduction using local data
and loopback peers only. Do not test against any network you do not own.

There is no response-time guarantee and no bounty program. The maintainers will
try to acknowledge reports and to credit reporters who want credit.

## Scope

In scope: consensus validation, signature and proof verification, storage,
P2P and RPC handling, wallet file handling, and the release scripts and
workflows in this repository.

Already known, so reports add little: the custom Schnorr and range-proof
constructions are unreviewed (NX-018); secret arithmetic is not constant time
(NX-019); payment slates are unauthenticated and the wallet has no payment
proofs or seed recovery (see the roadmap); reward keys are plaintext in
`coinbases.json`. The internal review findings still open are listed in
`audit/SECURITY_FINDINGS.md`.

Out of scope: third-party dependencies (report upstream), and attacks that need
control of the victim's host.
