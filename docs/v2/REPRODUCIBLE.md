# Reproducible builds

Every Noso v2 binary released by the launcher must be reproducible:
two operators starting from the same source commit and the same Go
toolchain version produce byte-identical artefacts. That property
lets users verify the launcher hasn't slipped a back-door into the
binary they downloaded.

## How the build pipeline achieves it

1. **No CGO.** `CGO_ENABLED=0` so we never link to platform-specific
   C libraries whose ABI varies.
2. **`-trimpath`.** Strips local file paths from the binary so a build
   at `/home/alice/noso-go` produces the same hash as `/home/bob/noso-go`.
3. **`-buildvcs=false`.** Strips git revision / dirty-state from the
   binary header.
4. **`-ldflags="-s -w -buildid="`.** Strips debug symbols and the random
   build ID Go adds by default.
5. **Pinned Go version.** Whoever cuts the release publishes the exact
   toolchain version (e.g. `go1.23.4`) — different toolchains produce
   different output.

The actual script lives at `scripts/build-release.sh`.

## How an operator verifies

After downloading a release directory:

```bash
scripts/verify-release.sh release/v0.2.0/                 # hash check only
scripts/verify-release.sh release/v0.2.0/ launcher.pub    # also check signature
```

The first form recomputes SHA-256 of each artefact and compares it
against `SHA256SUMS`. The second form additionally verifies that the
launcher signed `SHA256SUMS` with the key whose public component the
operator already trusts.

If both checks pass, the operator has cryptographic evidence that:

- The binary they hold is bit-identical to the one the launcher built.
- The launcher (or someone with the launcher's key) endorses that
  bit pattern.

## Cross-verification: rebuild from source

If you don't trust either the launcher OR the prebuilt binary, you
can independently rebuild from source and compare:

```bash
git clone https://github.com/Noso-Project/noso-go
cd noso-go
git checkout v0.2.0                # the tagged release commit
scripts/build-release.sh v0.2.0    # produces release/v0.2.0/
diff release/v0.2.0/SHA256SUMS path/to/downloaded/SHA256SUMS
```

If the diff is empty, every byte of the binary matches what the
launcher published — independent of whether you trust the launcher.

## Cross-platform builds

`scripts/build-release.sh v0.2.0 --all` builds five binaries for each
of {linux/amd64, linux/arm64, darwin/amd64, darwin/arm64}. ARM64 is
the Raspberry Pi target. A single launcher run produces every release
artefact.

## Launcher signing setup

The launcher generates a minisign key pair once:

```bash
minisign -G -p launcher.pub -s launcher.key
```

Distributes `launcher.pub` via the official website, GitHub repo,
multiple social channels (blog, IRC, Twitter, etc) — anywhere a
user can independently confirm the key the launcher controls.

When cutting a release:

```bash
LAUNCHER_MINISIGN_KEY=launcher.key \
  scripts/build-release.sh v0.2.0 --all --sign
```

The script produces `SHA256SUMS.minisig` alongside `SHA256SUMS`.

## Trust escalation

| Risk you want to defend against | Tool |
| --- | --- |
| Mirror site swapped binary for malware | `verify-release.sh` (SHA256SUMS) |
| GitHub release tampered without launcher knowing | `verify-release.sh launcher.pub` |
| Launcher themselves slipping in a back-door | Rebuild from source + diff |
| Source repository compromise | Audit the diff between releases, run tests |

Reproducible builds close everything down to (3); only (4) requires
human review of code changes.
