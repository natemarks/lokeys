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
RELEASE_ALLOW_NON_MAIN ?=0
RELEASE_ALLOW_RETAG ?=0
RELEASE_SKIP_STATIC ?=0
CONFIRM ?=0
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

.PHONY: static go-static bash-static gofmt-check go-vet golint go-deadcode go-test shfmt-check shellcheck build git-clean integration-preflight-local integration-preflight-kms test-integration-local test-integration-kms test-integration integration-workflows integration-workflows-local integration-workflows-kms release release-dry-run release-check release-clean release-build-linux release-checksums release-create release-upload release-tag-check release-tag release-tag-push release-all

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

integration-preflight-local: ## Validate local integration workflow prerequisites.
	@command -v bash >/dev/null 2>&1 || { printf "bash is required\n"; exit 1; }
	@command -v go >/dev/null 2>&1 || { printf "go is required\n"; exit 1; }
	@command -v readlink >/dev/null 2>&1 || { printf "readlink is required\n"; exit 1; }
	@command -v rm >/dev/null 2>&1 || { printf "rm is required\n"; exit 1; }
	@command -v openssl >/dev/null 2>&1 || { printf "openssl is required\n"; exit 1; }
	@command -v mountpoint >/dev/null 2>&1 || { printf "mountpoint is required\n"; exit 1; }
	@command -v umount >/dev/null 2>&1 || { printf "umount is required\n"; exit 1; }
	@command -v sudo >/dev/null 2>&1 || { printf "sudo is required for integration mount cleanup\n"; exit 1; }
	@[ -t 0 ] || { printf "integration workflows require an interactive terminal (TTY)\n"; exit 1; }
	@sudo -n true >/dev/null 2>&1 || { printf "sudo non-interactive access is required; run 'sudo -v' first\n"; exit 1; }

integration-preflight-kms: integration-preflight-local ## Validate KMS integration prerequisites.
	@command -v aws >/dev/null 2>&1 || { printf "aws CLI is required for KMS integration workflow\n"; exit 1; }
	@[ -n "$(AWS_PROFILE)" ] || { printf "AWS_PROFILE is required for KMS integration workflow\n"; exit 1; }
	@aws sts get-caller-identity --profile "$(AWS_PROFILE)" >/dev/null || { printf "unable to call sts:GetCallerIdentity with AWS_PROFILE=%s\n" "$(AWS_PROFILE)"; exit 1; }
	@region_value="$${AWS_REGION:-$${AWS_DEFAULT_REGION:-$$(aws configure get region --profile "$(AWS_PROFILE)" 2>/dev/null)}}"; \
	if [ -z "$$region_value" ]; then \
		printf "set AWS_REGION/AWS_DEFAULT_REGION or configure a profile region for AWS_PROFILE=%s\n" "$(AWS_PROFILE)"; \
		exit 1; \
	fi

test-integration-local: integration-preflight-local integration-workflows-local ## Run local integration workflow with preflight checks.

test-integration-kms: integration-preflight-kms integration-workflows-kms ## Run KMS integration workflow with preflight checks.

test-integration: integration-preflight-kms integration-workflows ## Run all integration workflows with preflight checks.

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
	@if [ "$(RELEASE_ALLOW_NON_MAIN)" != "1" ] && [ "$(CURRENT_BRANCH)" != "$(DEFAULT_BRANCH)" ]; then \
		printf "Releases must run from %s (current: %s). Set RELEASE_ALLOW_NON_MAIN=1 to override.\n" "$(DEFAULT_BRANCH)" "$(CURRENT_BRANCH)"; \
		exit 1; \
	fi
	@command -v gh >/dev/null 2>&1 || { printf "gh CLI is required\n"; exit 1; }
	@command -v tar >/dev/null 2>&1 || { printf "tar is required\n"; exit 1; }
	@command -v sha256sum >/dev/null 2>&1 || { printf "sha256sum is required\n"; exit 1; }
	@gh auth status >/dev/null
	@if [ "$(RELEASE_ENFORCE_TAG)" = "1" ]; then \
		git rev-parse --verify --quiet "refs/tags/$(RELEASE_TAG)" >/dev/null || { printf "Tag %s does not exist locally\n" "$(RELEASE_TAG)"; exit 1; }; \
		if [ "$(shell git rev-parse HEAD)" != "$(shell git rev-list -n 1 $(RELEASE_TAG))" ]; then \
			printf "HEAD (%s) does not match tag %s (%s)\n" "$(shell git rev-parse --short HEAD)" "$(RELEASE_TAG)" "$(shell git rev-parse --short $(RELEASE_TAG))"; \
			exit 1; \
		fi; \
	fi

release-tag-check: ## Validate prerequisites for creating/pushing a release tag.
	@if [ -z "$(RELEASE_TAG)" ]; then \
		printf "RELEASE_TAG is required (example: make release-tag RELEASE_TAG=v0.1.0)\n"; \
		exit 1; \
	fi
	@if ! printf "%s" "$(RELEASE_TAG)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		printf "RELEASE_TAG must match vMAJOR.MINOR.PATCH (got %s)\n" "$(RELEASE_TAG)"; \
		exit 1; \
	fi
	@if [ -n "$(shell git status --porcelain)" ]; then \
		printf "Git working tree is dirty. Commit or stash changes before tagging.\n"; \
		exit 1; \
	fi
	@if [ "$(RELEASE_ALLOW_NON_MAIN)" != "1" ] && [ "$(CURRENT_BRANCH)" != "$(DEFAULT_BRANCH)" ]; then \
		printf "Tagging must run from %s (current: %s). Set RELEASE_ALLOW_NON_MAIN=1 to override.\n" "$(DEFAULT_BRANCH)" "$(CURRENT_BRANCH)"; \
		exit 1; \
	fi
	@if [ "$(RELEASE_SKIP_STATIC)" != "1" ]; then \
		$(MAKE) static; \
	fi

release-tag: release-tag-check ## Create annotated release tag at HEAD.
	@if git rev-parse --verify --quiet "refs/tags/$(RELEASE_TAG)" >/dev/null; then \
		if [ "$(RELEASE_ALLOW_RETAG)" = "1" ] && [ "$(CONFIRM)" = "1" ]; then \
			printf "Recreating existing local tag %s\n" "$(RELEASE_TAG)"; \
			git tag -d "$(RELEASE_TAG)"; \
		else \
			printf "Tag %s already exists locally. Use RELEASE_ALLOW_RETAG=1 CONFIRM=1 to recreate.\n" "$(RELEASE_TAG)"; \
			exit 1; \
		fi; \
	fi
	@git tag -a "$(RELEASE_TAG)" -m "lokeys $(RELEASE_TAG)"
	@printf "Created local tag %s at %s\n" "$(RELEASE_TAG)" "$(shell git rev-parse --short HEAD)"

release-tag-push: release-tag-check ## Push release tag to origin.
	@if ! git rev-parse --verify --quiet "refs/tags/$(RELEASE_TAG)" >/dev/null; then \
		printf "Tag %s does not exist locally. Run make release-tag RELEASE_TAG=%s first.\n" "$(RELEASE_TAG)" "$(RELEASE_TAG)"; \
		exit 1; \
	fi
	@if [ "$(RELEASE_ALLOW_RETAG)" = "1" ] && [ "$(CONFIRM)" = "1" ]; then \
		printf "Deleting remote tag %s before push\n" "$(RELEASE_TAG)"; \
		git push origin ":refs/tags/$(RELEASE_TAG)"; \
	fi
	@git push origin "refs/tags/$(RELEASE_TAG)"
	@printf "Pushed tag %s to origin\n" "$(RELEASE_TAG)"

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

release-all: release-tag release-tag-push release ## Create tag, push tag, and publish release.
