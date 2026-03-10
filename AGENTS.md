# AGENTS.md

Purpose
- This file guides agentic coding assistants working in this repo.
- Project intent: Go + Bash tools for mounting a local RAM disk and
  encrypting/decrypting small sensitive files to/from that RAM disk.

Repo state
- This repository was empty when this file was drafted.
- Update commands and conventions once real tooling/configs are added.

Cursor/Copilot rules
- No `.cursor/rules/`, `.cursorrules`, or `.github/copilot-instructions.md`
  were present when authored. If added later, merge here.

Core workflows
- Always prioritize security, correctness, and safe defaults.
- Prefer small, testable changes with clear rollback paths.
- Preserve established patterns once they exist.

Personas for review (required)
- Security Specialist: review cryptography, permissions, secrets handling,
  threat model assumptions, and cleanup on failure.
- Command Line Usability Specialist: review ergonomics, help text, error
  messages, exit codes, and predictable flags.

Suggested command map (update to real tools when present)
- Build: `go build ./...`
- Run binary: `go run ./cmd/lokeys` (or actual entrypoint)
- Lint (Go): `golangci-lint run` (preferred), `go vet ./...`
- Format (Go): `gofmt -w .` or `goimports -w .`
- Format (Bash): `shfmt -w .`
- Lint (Bash): `shellcheck scripts/*.sh` (adjust paths)
- Test all: `go test ./...`
- Single test (package): `go test ./path/to/pkg -run '^TestName$' -count=1`
- Single test (all): `go test ./... -run '^TestName$' -count=1`
- Coverage: `go test ./... -coverprofile=coverage.out`

Single-test guidance
- Use `-run` with an anchored regex for exact test selection.
- Use `-count=1` to avoid cached results when changing crypto or filesystem.

Go style conventions
- Formatting: always `gofmt`; prefer `goimports` to manage imports.
- Imports: standard lib first, blank line, third-party, blank line, local.
- Naming: `CamelCase` for exported, `camelCase` for unexported.
- Files: snake_case or lower-case with dashes avoided (Go convention is
  lower-case with underscores acceptable).
- Package names: short, lower-case, no underscores, no plurals when possible.
- Types: avoid unnecessary interfaces; accept interfaces at boundaries.
- Errors: return errors, never panic for expected failures.
- Error wrapping: `fmt.Errorf("context: %w", err)`.
- Sentinel errors: `var ErrX = errors.New("...")` in package scope.
- Context: pass `context.Context` as first parameter when needed.
- Logging: structured, consistent; never log secrets or plaintext payloads.

Bash style conventions
- Use `#!/usr/bin/env bash` and `set -euo pipefail` at top.
- Prefer `printf` over `echo` for portability.
- Quote all variables and paths; avoid globbing surprises.
- Use functions for reusable steps; keep scripts small and focused.
- Return proper exit codes; non-zero for failure conditions.
- Use `trap` to ensure cleanup (unmount, temp file removal).

Security conventions (critical)
- Never log keys, plaintext, or derived secrets.
- Default file permissions: directories `0700`, files `0600`.
- Use least-privilege mount flags (e.g., `noexec`, `nodev`, `nosuid`).
- Validate mount points and ensure they are within user-controlled paths.
- Always unmount and wipe temporary data on error paths.
- Avoid shelling out with user-provided inputs unless safely validated.
- Use constant-time comparisons for secret material if applicable.

Crypto guidelines
- Prefer modern, authenticated encryption modes (e.g., AES-GCM, ChaCha20-Poly1305).
- Enforce unique nonces per encryption operation.
- Store metadata needed for decryption (nonce, version) alongside ciphertext.
- Validate input sizes; protect against truncation and format confusion.

RAM disk guidelines
- Use platform-appropriate mount commands and document them.
- Explicitly size the RAM disk and fail if size is unreasonable.
- Use idempotent mount/unmount behavior when possible.

Command-line UX guidelines
- Provide `--help` and clear usage examples.
- Use consistent flag names (`--mount`, `--unmount`, `--encrypt`, `--decrypt`).
- Support `--dry-run` where safe.
- Error messages should be actionable, include next steps.
- Exit codes: `0` success, `1` generic failure, `2` usage error.

Testing guidelines
- Unit tests for crypto and path validation logic.
- Integration tests for mount/unmount with a temp mount path.
- Avoid tests that require root or system-specific tools unless gated.
- Use golden files for encrypted payload formats when stable.

Review checklist (agent self-review)
- Security Specialist: confirm no secret leakage in logs or errors.
- Security Specialist: confirm permissions and cleanup on error paths.
- CLI Usability Specialist: confirm helpful usage output and flags.
- CLI Usability Specialist: confirm exit codes and errors are consistent.
- Ensure scripts work in non-interactive environments (CI-friendly).

When repo becomes non-empty
- Replace placeholder commands with actual build/lint/test scripts.
- Reflect any existing architectural conventions.
- Expand sections based on real tools (Makefile, Taskfile, Mage, etc.).
