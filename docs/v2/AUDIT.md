# Internal hardening status

**Not independently audited. RESEARCH ONLY; MAINNET BLOCKED.**

The prior checklist and readiness claims were inaccurate. The current evidence,
confirmed fixes and unresolved blockers are maintained in
[SECURITY_AUDIT.md](../../audit/SECURITY_AUDIT.md),
[TEST_REPORT.md](../../audit/TEST_REPORT.md), and
[RELEASE_READINESS.md](../../audit/RELEASE_READINESS.md).

Kernel/coinbase signatures, historical uniqueness, proof verification, header
body binding, maturity and atomic reorg handling now have negative regressions.
These checks do not validate the custom proof construction, private-key side
channels, migration economics, or production-scale reorganization behavior.
