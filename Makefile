.DEFAULT_GOAL := help

# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
SHELL := $(shell which bash)
DEFAULT_BRANCH := main
VERSION := 0.0.0
COMMIT := $(shell git rev-parse HEAD)
CURRENT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
RELEASE_TAG ?=
RELEASE_LINUX_ARCHES ?=amd64 arm64
RELEASE_ENFORCE_TAG ?=1
DIST_DIR := dist
RELEASE_ROOT := $(DIST_DIR)/release
RELEASE_DIR := $(RELEASE_ROOT)/$(RELEASE_TAG)

help: ## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

GO_FILES := $(shell find . -name "*.go" -not -path "./vendor/*")
SH_FILES := $(shell ls scripts/*.sh 2>/dev/null)
INTEGRATION_SH_FILES := $(shell find scripts -type f -name "*.sh" 2>/dev/null)
ifneq ($(strip $(INTEGRATION_SH_FILES)),)
SH_FILES := $(INTEGRATION_SH_FILES)
endif

.PHONY: static go-static bash-static gofmt-check go-vet golint go-deadcode go-test shfmt-check shellcheck build git-clean integration-workflows integration-workflows-local integration-workflows-kms release release-dry-run release-check release-clean release-build-linux release-checksums release-create release-upload

static: go-static bash-static ## Run all static checks.

build: git-clean ## Build lokeys with version.
	go build -ldflags "-X main.version=$(COMMIT)" -o bin/lokeys ./cmd/lokeys

go-static: gofmt-check go-vet golint go-deadcode go-test ## Run Go checks.

bash-static: shfmt-check shellcheck ## Run Bash checks.

gofmt-check: ## Check Go formatting with gofmt.
	@if [ -n "$(GO_FILES)" ]; then \
		unformatted=$$(gofmt -l $(GO_FILES)); \
		if [ -n "$$unformatted" ]; then \
			printf "gofmt needed for:\n%s\n" "$$unformatted"; \
			exit 1; \
		fi; \
	else \
		printf "No Go files found.\n"; \
	fi

go-vet: ## Run go vet on all packages.
	go install ./...
	go vet ./...

golint: ## Run golint.
	go install golang.org/x/lint/golint@latest
	golint ./...

go-deadcode: ## Run deadcode analysis.
	go install golang.org/x/tools/cmd/deadcode@latest
	deadcode ./...

go-test: ## Run Go tests.
	go test ./...

shfmt-check: ## Check Bash formatting with shfmt.
	@if [ -n "$(SH_FILES)" ]; then \
		shfmt -d $(SH_FILES); \
	else \
		printf "No Bash scripts found.\n"; \
	fi

shellcheck: ## Run shellcheck on scripts.
	@if [ -n "$(SH_FILES)" ]; then \
		shellcheck -x $(SH_FILES); \
	else \
		printf "No Bash scripts found.\n"; \
	fi

git-clean: ## Fail if git status is dirty.
	@if [ -n "$(shell git status --porcelain)" ]; then \
		printf "Git working tree is dirty. Commit or stash changes.\n"; \
		exit 1; \
	fi

clean_config: ## Clean up generated config files.
	bash scripts/clean_config.sh

reset_data: ## Reset data directory.
	bash scripts/reset_data.sh

integration-workflows-local: ## Run local integration workflow test.
	go build -o bin/lokeys ./cmd/lokeys
	LOKEYS_BIN=./bin/lokeys bash scripts/integration/local_workflow.sh

integration-workflows-kms: ## Run KMS integration workflow test (requires AWS_PROFILE).
	go build -o bin/lokeys ./cmd/lokeys
	LOKEYS_BIN=./bin/lokeys bash scripts/integration/kms_workflow.sh

integration-workflows: integration-workflows-local integration-workflows-kms ## Run all integration workflow tests.

release-check: ## Validate release prerequisites (tag/tools/auth/clean tree).
	@if [ -z "$(RELEASE_TAG)" ]; then \
		printf "RELEASE_TAG is required (example: make release RELEASE_TAG=v0.1.0)\n"; \
		exit 1; \
	fi
	@if ! printf "%s" "$(RELEASE_TAG)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		printf "RELEASE_TAG must match vMAJOR.MINOR.PATCH (got %s)\n" "$(RELEASE_TAG)"; \
		exit 1; \
	fi
	@if [ -n "$(shell git status --porcelain)" ]; then \
		printf "Git working tree is dirty. Commit or stash changes before releasing.\n"; \
		exit 1; \
	fi
	@command -v gh >/dev/null 2>&1 || { printf "gh CLI is required\n"; exit 1; }
	@command -v tar >/dev/null 2>&1 || { printf "tar is required\n"; exit 1; }
	@command -v sha256sum >/dev/null 2>&1 || { printf "sha256sum is required\n"; exit 1; }
	@gh auth status >/dev/null
	@if [ "$(RELEASE_ENFORCE_TAG)" = "1" ]; then \
		git rev-parse "$(RELEASE_TAG)^{tag}" >/dev/null 2>&1 || { printf "Tag %s does not exist locally\n" "$(RELEASE_TAG)"; exit 1; }; \
		if [ "$(shell git rev-parse HEAD)" != "$(shell git rev-list -n 1 $(RELEASE_TAG))" ]; then \
			printf "HEAD (%s) does not match tag %s (%s)\n" "$(shell git rev-parse --short HEAD)" "$(RELEASE_TAG)" "$(shell git rev-parse --short $(RELEASE_TAG))"; \
			exit 1; \
		fi; \
	fi

release-clean: ## Remove release build artifacts for current tag.
	@if [ -n "$(RELEASE_TAG)" ]; then \
		rm -rf "$(RELEASE_DIR)"; \
	fi

release-build-linux: release-check release-clean ## Build and package Linux release tarballs.
	@mkdir -p "$(RELEASE_DIR)"
	@for arch in $(RELEASE_LINUX_ARCHES); do \
		stage_dir="$(RELEASE_DIR)/lokeys_$(RELEASE_TAG)_linux_$${arch}"; \
		mkdir -p "$$stage_dir"; \
		CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" go build -trimpath -ldflags "-s -w -X main.version=$(RELEASE_TAG)" -o "$$stage_dir/lokeys" ./cmd/lokeys; \
		cp README.md "$$stage_dir/"; \
		tar -C "$(RELEASE_DIR)" -czf "$(RELEASE_DIR)/lokeys_$(RELEASE_TAG)_linux_$${arch}.tar.gz" "lokeys_$(RELEASE_TAG)_linux_$${arch}"; \
		rm -rf "$$stage_dir"; \
	done

release-checksums: release-build-linux ## Generate SHA256 checksums for release assets.
	@(cd "$(RELEASE_DIR)" && sha256sum ./*.tar.gz > SHA256SUMS)

release-create: release-check ## Create GitHub release for tag.
	@gh release view "$(RELEASE_TAG)" >/dev/null 2>&1 && { printf "Release %s already exists\n" "$(RELEASE_TAG)"; exit 1; } || true
	@gh release create "$(RELEASE_TAG)" --title "lokeys $(RELEASE_TAG)" --generate-notes

release-upload: release-checksums release-create ## Upload tarballs and checksums to GitHub release.
	@gh release upload "$(RELEASE_TAG)" "$(RELEASE_DIR)"/*.tar.gz "$(RELEASE_DIR)/SHA256SUMS"

release-dry-run: ## Build artifacts/checksums without requiring a local tag.
	@$(MAKE) RELEASE_TAG="$(RELEASE_TAG)" RELEASE_LINUX_ARCHES="$(RELEASE_LINUX_ARCHES)" RELEASE_ENFORCE_TAG=0 release-checksums
	@printf "Dry run complete. Artifacts are in %s\n" "$(RELEASE_DIR)"

release: release-upload ## Publish GitHub release assets for current tag.
	@printf "Release %s published with assets from %s\n" "$(RELEASE_TAG)" "$(RELEASE_DIR)"
