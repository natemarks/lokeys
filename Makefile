.DEFAULT_GOAL := help

# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
SHELL := $(shell which bash)
DEFAULT_BRANCH := main
VERSION := 0.0.0
COMMIT := $(shell git rev-parse HEAD)
CURRENT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

help: ## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

GO_FILES := $(shell find . -name "*.go" -not -path "./vendor/*")
SH_FILES := $(shell ls scripts/*.sh 2>/dev/null)
INTEGRATION_SH_FILES := $(shell find scripts -type f -name "*.sh" 2>/dev/null)
ifneq ($(strip $(INTEGRATION_SH_FILES)),)
SH_FILES := $(INTEGRATION_SH_FILES)
endif

.PHONY: static go-static bash-static gofmt-check go-vet golint go-deadcode go-test shfmt-check shellcheck build git-clean integration-workflows integration-workflows-local integration-workflows-kms

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
