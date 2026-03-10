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

.PHONY: static go-static bash-static gofmt-check go-vet golint go-test shfmt-check shellcheck build git-clean

static: go-static bash-static ## Run all static checks.

build: git-clean ## Build lokeys with version.
	go build -ldflags "-X main.version=$(COMMIT)" -o bin/lokeys ./cmd/lokeys

go-static: gofmt-check go-vet golint go-test ## Run Go checks.

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
	go vet ${GO_FILES}

golint: ## Run golint.
	go install golang.org/x/lint/golint@latest
	golint ./...

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
		shellcheck $(SH_FILES); \
	else \
		printf "No Bash scripts found.\n"; \
	fi

git-clean: ## Fail if git status is dirty.
	@if [ -n "$(shell git status --porcelain)" ]; then \
		printf "Git working tree is dirty. Commit or stash changes.\n"; \
		exit 1; \
	fi
