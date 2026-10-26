# Security hardening execution plan

Scope: user's full ten-phase mission, local execution only; no repository settings
or visibility changes. Findings remain in this branch/one review PR.

1. Record clean baseline, original Go 1.25.7 build/test/vet/race outputs before edits.
2. Partition chain/storage, cryptography/wallet, and remote boundaries for independent
   review. Lead reviews types, miner, genesis, legacy, scripts, dependencies and docs.
3. Reproduce suspected defects with negative tests before patching. Enforce the
   separately written CONSENSUS_INVARIANTS.md. Reject unsupported ownership and
   offset semantics rather than inventing cryptography.
4. Add canonical full-body commitments and update producers and maintained test
   fixtures explicitly for breaking validation rules. Preserve old fixture bytes.
5. Add fault, mutation, fuzz, property, local integration and backend parity tests.
6. Run fresh build/vet/tests/race/coverage plus available scanners, bounded fuzzing,
   cross-compilation and reproducibility checks; log actual exit statuses.
7. Conduct independent adversarial second pass and remediate new high findings.
8. Write five required reports, migration trust, threat model and contributor steps;
   replace unsupported readiness claims. Commit focused changes and prepare one PR
   if repository write/archive settings allow; otherwise preserve local branch.

Each report distinguishes tested fixes from unverified requirements and blockers.
