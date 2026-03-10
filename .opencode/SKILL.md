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
