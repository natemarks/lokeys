# SKILL.md

Project skill profile
- Domain: local RAM disk mount + file encryption/decryption.
- Languages: Go for core logic, Bash for orchestration.
- Security posture: high; treat all data as sensitive by default.

Expected capabilities
- Implement AES-GCM or ChaCha20-Poly1305 with safe nonce handling.
- Validate inputs and paths; prevent directory traversal.
- Use safe temp file handling and atomic writes.
- Provide clear, consistent CLI options and errors.

Specialist agent capability
- AWS Cloud Security + KMS Specialist
  - Designs and reviews AWS KMS implementations against least-privilege and defense-in-depth.
  - Ensures correct key policy + IAM interaction and avoids accidental privilege escalation.
  - Applies best practices for envelope encryption, grants, rotation, aliases, and key deletion windows.
  - Validates cross-account KMS access patterns, multi-Region key usage, and service-integrated encryption.
  - Emphasizes observability via CloudTrail and actionable audit controls for KMS operations.
- Go Testing Specialist
  - Designs robust unit/integration tests for Go CLI and filesystem-heavy workflows.
  - Improves determinism via stubs/fakes for prompts, mount calls, and environment dependencies.
  - Strengthens negative-path coverage for security and rollback behavior.
  - Recommends efficient test execution strategy for local dev and CI.

Trigger list for AWS Cloud Security + KMS Specialist
- Any code or config change that calls AWS KMS APIs directly.
- Any change to KMS key policy, IAM permissions, grants, or cross-account access.
- Any change to envelope encryption flow, data key handling, or key rotation/deletion settings.
- Any change to encryption configuration for AWS-managed services using KMS keys.
- Any change to logging/audit controls relevant to KMS usage (CloudTrail, alerts, detections).

Trigger list for Go Testing Specialist
- Any change to command behavior or internal business logic.
- Any change to crypto, key lifecycle, filesystem permissions, backup, or rotation logic.
- Any addition of new subcommands, flags, or error/exit-code semantics.
- Any test suite instability, flaky tests, or low-confidence coverage areas.

Recommended tools
- Go: `gofmt`, `goimports`, `golangci-lint`, `go vet`, `go test`.
- Bash: `shfmt`, `shellcheck`.

Verification habits
- Run unit tests for crypto and path validation logic.
- Use integration tests with a temporary mount point if feasible.
- Verify permissions and mount flags match security requirements.

Required reviews
- Security Specialist persona review.
- Command Line Usability Specialist persona review.
- AWS Cloud Security + KMS Specialist review for any AWS/KMS-related change.
- Go Testing Specialist review for substantial Go logic or test changes.
