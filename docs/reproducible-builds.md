# Reproducible builds

The release build is designed so that two builds from the same commit with the
same Go toolchain produce identical binaries. Independent rebuilds have not yet
been compared, so treat this as intent until someone verifies it.

## Build flags

- `CGO_ENABLED=0`: no platform C libraries.
- `-trimpath`: no local paths in the binary.
- `-buildvcs=false`: no Git state in the binary.
- `-ldflags="-s -w -buildid="`: no symbols and no build ID.
- The Go version in `go.mod` pins the toolchain. Use the same Go release.

## Build locally

```bash
scripts/build-release.sh v0.0.0-test            # linux/amd64
scripts/build-release.sh v0.0.0-test --all      # adds linux/arm64 and darwin
```

The script writes `nosoxd` and `nosox-cli` per platform and a `SHA256SUMS` file to
`release/<version>/`. With `--sign` and `LAUNCHER_MINISIGN_KEY` set it also
produces a minisign signature. It needs `sha256sum` on the path.

## Verify a download

A GitHub release contains the archives, `SHA256SUMS` (one line per archive) and
`SHA256SUMS.sigstore.json` (the attestation bundle). Put them in one directory.

```bash
scripts/verify-release.sh release-dir/                  # checksums only
scripts/verify-release.sh release-dir/ publisher.pub    # also a minisign signature
```

Checksums show that the files match the list. They do not show who made the
list, because the list comes from the same place as the files. Use the
attestation for that:

```bash
gh attestation verify noso-go_<tag>_linux_amd64.tar.gz \
  --repo pasichDev/noso-go \
  --signer-workflow pasichDev/noso-go/.github/workflows/release.yml \
  --source-ref refs/tags/<tag>
```

The attestation is keyless: a Sigstore certificate bound to the workflow run,
repository and tag signs a statement that lists the SHA-256 of every archive.
Verification shows that the archive was produced by that workflow from that tag
of that repository. It does not show that the source is free of bugs or that
the repository owner is trustworthy, and it does not replace a rebuild. To
verify offline, add `--bundle SHA256SUMS.sigstore.json`. The minisign check
applies only if a maintainer signs `SHA256SUMS` by hand with `--sign`; the
workflow does not do that.

## Rebuild and compare

```bash
git clone https://github.com/pasichDev/noso-go
cd noso-go
git checkout <tag>
scripts/build-release.sh <tag>
diff release/<tag>/SHA256SUMS /path/to/downloaded/SHA256SUMS
```

## GitHub releases

Pushing a tag that starts with `v` runs `.github/workflows/release.yml`. The
workflow cannot be started by hand.

1. `build` (read-only token, no cache) builds `nosoxd` and `nosox-cli` for linux
   (amd64, arm64, arm), darwin (amd64, arm64) and windows (amd64). Each archive
   holds the two binaries, `README.md`, `LICENSE` and `docs/running-a-node.md`,
   with fixed file order, owner and timestamps.
2. `attest` (the only job with `id-token` and `attestations` permissions)
   refuses to continue unless all six archives exist, writes one combined
   `SHA256SUMS`, and creates a build-provenance attestation for every archive
   with `actions/attest-build-provenance`.
3. `release` (the only job with `contents: write`, in the `release` environment)
   re-checks `SHA256SUMS` and attaches archives, `SHA256SUMS` and the
   attestation bundle to a GitHub release.

Every action is pinned to a full commit SHA; Dependabot proposes updates.

Limits to know about:

- Attestations need a public repository, or a GitHub plan that supports them
  for private ones. The workflow fails at the `attest` job otherwise: make the
  repository public BEFORE pushing the first release tag.
- The workflow was changed but has not yet run on GitHub.
- Required reviewers for the `release` environment, tag protection and branch
  protection are repository settings and are not enforced by this file.
- Provenance proves where an archive came from. It does not prove that two
  builds are byte-identical; that has not been compared (see the top of this
  page).
