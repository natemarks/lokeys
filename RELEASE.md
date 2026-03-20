# Release Process

This document explains the exact steps to publish a `lokeys` GitHub release
using the Makefile targets in this repository.

## Overview

`make release` will:

- validate release prerequisites
- build Linux binaries for each architecture
- package tarballs as `lokeys_<tag>_linux_<arch>.tar.gz`
- generate `SHA256SUMS`
- create a GitHub release for the tag
- upload tarballs and checksums as assets

## Quick start

If you are releasing a brand new version from `main`:

```bash
make release-all RELEASE_TAG=v0.1.0
```

If tag already exists and you only want to publish assets:

```bash
make release RELEASE_TAG=v0.1.0
```

## Prerequisites

- clean git working tree
- Go toolchain installed
- tools available: `gh`, `tar`, `sha256sum`
- GitHub CLI authenticated: `gh auth login`
- release tag exists locally and points to `HEAD`

The release target accepts both lightweight and annotated tags.

## Safe GitHub credential handling

Prefer `gh auth login` locally so credentials are stored in your OS keychain.

For CI/headless runs:

- provide `GH_TOKEN` from a secret manager
- use short-lived or fine-grained tokens where possible
- scope token permissions minimally (release creation/upload)

Never:

- commit tokens
- print token values in logs
- store credentials in repo files

## Standard release flow

Use semantic versions like `v0.1.0`.

### 1) Prepare branch and commit

```bash
git checkout main
git pull --ff-only
# make any final release fixes
git add .
git commit -m "<release prep message>"
git push origin main
```

### 2) Create and push tag (automated)

```bash
make release-tag RELEASE_TAG=v0.1.0
make release-tag-push RELEASE_TAG=v0.1.0
```

`release-tag` creates an annotated tag at `HEAD`.

### 3) Optional dry run (no publish)

```bash
make release-dry-run RELEASE_TAG=v0.1.0
```

Dry run still requires semver `RELEASE_TAG`, but does not require a local tag.
Artifacts are placed in `dist/release/v0.1.0`.

### 4) Publish release

```bash
make release RELEASE_TAG=v0.1.0
```

### 5) One-command flow (tag + push + release)

```bash
make release-all RELEASE_TAG=v0.1.0
```

## If you changed code after creating the tag

`make release` enforces `HEAD == tag commit` for safety.

If you made a new commit after tagging, choose one:

1. Create a new version tag (recommended)
2. Retag the existing version only if it has not been published/consumed

Retag example (only when safe):

```bash
git tag -d v0.1.0
git tag v0.1.0
git push origin :refs/tags/v0.1.0
git push origin v0.1.0
```

Then re-run:

```bash
make release RELEASE_TAG=v0.1.0
```

Or allow automated retagging (dangerous; use only before public consumption):

```bash
make release-tag RELEASE_TAG=v0.1.0 RELEASE_ALLOW_RETAG=1 CONFIRM=1
make release-tag-push RELEASE_TAG=v0.1.0 RELEASE_ALLOW_RETAG=1 CONFIRM=1
```

With those flags, local/remote tag replacement is allowed explicitly.

## Customizing Linux architecture matrix

Default:

- `amd64 arm64`

Override example:

```bash
make release RELEASE_TAG=v0.1.0 RELEASE_LINUX_ARCHES="amd64 arm64 386"
```

## Make targets

- `release-tag-check` - validate semver tag input, clean tree, branch safety, and optional static checks
- `release-tag` - create annotated release tag at `HEAD`
- `release-tag-push` - push tag to `origin` (optionally replace remote tag with explicit flags)
- `release-check` - validate tools, auth, working tree, and tag/HEAD alignment
- `release-build-linux` - cross-build and package tarballs
- `release-checksums` - generate `SHA256SUMS`
- `release-create` - create GitHub release
- `release-upload` - upload assets to existing release
- `release-dry-run` - build/package/checksum only
- `release` - full publish pipeline
- `release-all` - run `release-tag`, `release-tag-push`, and `release`

## Safety flags

- `RELEASE_ALLOW_NON_MAIN=1` - allow tagging/releasing outside `main`
- `RELEASE_SKIP_STATIC=1` - skip `make static` inside `release-tag-check`
- `RELEASE_ALLOW_RETAG=1 CONFIRM=1` - allow destructive tag replacement

## Troubleshooting

- `RELEASE_TAG is required`
  - set `RELEASE_TAG=vX.Y.Z`
- `RELEASE_TAG must match vMAJOR.MINOR.PATCH`
  - fix tag format
- `Tag <tag> does not exist locally`
  - run `make release-tag RELEASE_TAG=<tag>`
- `HEAD (...) does not match tag ...`
  - check out tagged commit or retag/create a new version
- `Tag <tag> already exists locally`
  - use a new version tag, or explicitly retag with `RELEASE_ALLOW_RETAG=1 CONFIRM=1`
- `gh auth status` fails
  - run `gh auth login`
- `Release <tag> already exists`
  - publish a new version tag or delete the existing release intentionally
