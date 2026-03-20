# Release Process

This document describes how to publish a new `lokeys` GitHub release using the
Makefile automation.

## What the release targets do

- build Linux binaries for each architecture in `RELEASE_LINUX_ARCHES`
- package each build as `lokeys_<tag>_linux_<arch>.tar.gz`
- generate a `SHA256SUMS` file for uploaded tarballs
- create a GitHub release for the specified tag
- upload tarballs and checksums as release assets

## Prerequisites

- clean git working tree
- release tag already exists locally and points at `HEAD`
- `gh` authenticated (`gh auth login`)
- required tools installed: `tar`, `sha256sum`, Go toolchain

## Safe GitHub credential handling

Prefer `gh auth login` with OS credential storage instead of copying tokens into
shell history.

Recommended options:

1. Local interactive use
   - Run `gh auth login`
   - Use the keychain-backed credential helper prompted by `gh`

2. CI or headless use
   - Use a short-lived token in `GH_TOKEN`
   - Store it in your CI secret manager
   - Scope it minimally to release creation/upload permissions

Security notes:

- never commit tokens or write them into repository files
- never print token values in logs
- avoid broad long-lived personal tokens when fine-grained tokens are available

## Release commands

Use semantic version tags in `vMAJOR.MINOR.PATCH` format.

### 1) Create and push the release tag

```bash
git tag v0.1.0
git push origin v0.1.0
```

### 2) Optional dry run (build/package/checksums only)

```bash
make release-dry-run RELEASE_TAG=v0.1.0
```

`release-dry-run` does not require a local git tag, but still requires a
semver-formatted `RELEASE_TAG` value for artifact naming.

Artifacts will be created under:

`dist/release/v0.1.0`

### 3) Publish the release

```bash
make release RELEASE_TAG=v0.1.0
```

This runs:

- `release-check`
- `release-build-linux`
- `release-checksums`
- `release-create`
- `release-upload`

## Customizing Linux targets

Default architectures are `amd64 arm64`.

To override:

```bash
make release RELEASE_TAG=v0.1.0 RELEASE_LINUX_ARCHES="amd64 arm64 386"
```

## Troubleshooting

- `RELEASE_TAG is required`
  - set `RELEASE_TAG=vX.Y.Z`
- `HEAD does not match tag`
  - check out the tagged commit before releasing
- `gh auth status` fails
  - run `gh auth login` and retry
- release already exists
  - either delete the GitHub release manually or publish a new version tag
