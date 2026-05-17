# O.W.A.S.A.K.A. SIEM - Build Automation
# Air-gapped SIEM with surgical precision

.PHONY: help build clean test lint deps run dev install docker-down release

# Variables
BINARY_NAME=oswaka
BINARY_PATH=./bin/$(BINARY_NAME)
CMD_PATH=./cmd/oswaka
MAIN_FILE=$(CMD_PATH)/main.go
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-s -w"
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S_UTC')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Colors for output
CYAN=\033[0;36m
GREEN=\033[0;32m
RED=\033[0;31m
YELLOW=\033[0;33m
NC=\033[0m # No Color

##@ General

help: ## Display this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\n$(CYAN)O.W.A.S.A.K.A. SIEM - Make Targets$(NC)\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

deps: ## Install Go dependencies
	@echo "$(CYAN)Installing dependencies...$(NC)"
	$(GO) mod download
	$(GO) mod tidy
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

build: deps ## Build the binary
	@echo "$(CYAN)Building $(BINARY_NAME)...$(NC)"
	@mkdir -p bin
	$(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BINARY_PATH) \
		$(CMD_PATH)
	@echo "$(GREEN)✓ Build complete: $(BINARY_PATH)$(NC)"
	@echo "$(YELLOW)  Version: $(VERSION)$(NC)"
	@echo "$(YELLOW)  Commit:  $(GIT_COMMIT)$(NC)"
	@echo "$(YELLOW)  Built:   $(BUILD_TIME)$(NC)"

build-release: deps ## Build optimized release binary
	@echo "$(CYAN)Building release binary...$(NC)"
	@mkdir -p bin
	CGO_ENABLED=1 $(GO) build \
		-a \
		-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.buildTime=$(BUILD_TIME)" \
		-o $(BINARY_PATH) \
		$(CMD_PATH)
	@echo "$(GREEN)✓ Release build complete$(NC)"

release: check build-release ## Full release: check + optimized build
	@echo "$(CYAN)Release artifact ready:$(NC)"
	@ls -lh $(BINARY_PATH)
	@echo "$(GREEN)  Version: $(VERSION)$(NC)"
	@echo "$(GREEN)  Commit:  $(GIT_COMMIT)$(NC)"
	@echo "$(GREEN)  Built:   $(BUILD_TIME)$(NC)"

run: build ## Build and run the application
	@echo "$(CYAN)Starting O.W.A.S.A.K.A. SIEM...$(NC)"
	$(BINARY_PATH) --config configs/examples/default.yaml

dev: ## Run in development mode with hot reload (requires air)
	@echo "$(CYAN)Starting development mode...$(NC)"
	@command -v air >/dev/null 2>&1 || { \
		echo "$(YELLOW)Installing air for hot reload...$(NC)"; \
		go install github.com/cosmtrek/air@latest; \
	}
	air

##@ Testing

test: ## Run tests
	@echo "$(CYAN)Running tests...$(NC)"
	$(GO) test -v -race -coverprofile=coverage.out ./...
	@echo "$(GREEN)✓ Tests complete$(NC)"

test-coverage: test ## Run tests with coverage report
	@echo "$(CYAN)Generating coverage report...$(NC)"
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✓ Coverage report: coverage.html$(NC)"

test-integration: ## Run integration tests
	@echo "$(CYAN)Running integration tests...$(NC)"
	$(GO) test -v -tags=integration ./...

demo-sprint1: ## Run the Sprint 1 authentication end-to-end demo (asciinema-friendly)
	@echo "$(CYAN)Running Sprint 1 auth demo...$(NC)"
	$(GO) test -tags=demo -v -count=1 ./internal/identity/demo/...

benchmark: ## Run benchmarks
	@echo "$(CYAN)Running benchmarks...$(NC)"
	$(GO) test -bench=. -benchmem ./...

##@ Code Quality

lint: ## Run linters
	@echo "$(CYAN)Running linters...$(NC)"
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "$(YELLOW)Installing golangci-lint...$(NC)"; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	}
	golangci-lint run --timeout=5m
	@echo "$(GREEN)✓ Linting complete$(NC)"

fmt: ## Format code
	@echo "$(CYAN)Formatting code...$(NC)"
	$(GO) fmt ./...
	@echo "$(GREEN)✓ Code formatted$(NC)"

vet: ## Run go vet
	@echo "$(CYAN)Running go vet...$(NC)"
	$(GO) vet ./...
	@echo "$(GREEN)✓ Vet complete$(NC)"

check: fmt vet lint test ## Run all checks (fmt, vet, lint, test)
	@echo "$(GREEN)✓ All checks passed$(NC)"

##@ Documentation

docs: ## Generate documentation
	@echo "$(CYAN)Generating documentation...$(NC)"
	@command -v godoc >/dev/null 2>&1 || { \
		echo "$(YELLOW)Installing godoc...$(NC)"; \
		go install golang.org/x/tools/cmd/godoc@latest; \
	}
	@echo "$(GREEN)✓ Run 'godoc -http=:6060' to view docs$(NC)"

docs-serve: ## Serve documentation locally
	@echo "$(CYAN)Serving documentation at http://localhost:6060$(NC)"
	godoc -http=:6060

##@ Cleanup

clean: ## Remove build artifacts
	@echo "$(CYAN)Cleaning build artifacts...$(NC)"
	rm -rf bin/
	rm -f coverage.out coverage.html
	$(GO) clean -cache -testcache -modcache
	@echo "$(GREEN)✓ Clean complete$(NC)"

clean-all: clean ## Remove all generated files including dependencies
	@echo "$(CYAN)Deep cleaning...$(NC)"
	rm -rf vendor/
	@echo "$(GREEN)✓ Deep clean complete$(NC)"

##@ Installation

install: build ## Install binary to $GOPATH/bin
	@echo "$(CYAN)Installing $(BINARY_NAME)...$(NC)"
	$(GO) install $(CMD_PATH)
	@echo "$(GREEN)✓ Installed to $(GOPATH)/bin/$(BINARY_NAME)$(NC)"

uninstall: ## Uninstall binary from $GOPATH/bin
	@echo "$(CYAN)Uninstalling $(BINARY_NAME)...$(NC)"
	rm -f $(GOPATH)/bin/$(BINARY_NAME)
	@echo "$(GREEN)✓ Uninstalled$(NC)"

##@ Docker (Legacy - for reference)

docker-down: ## Stop and remove legacy Wazuh containers
	@echo "$(CYAN)Stopping legacy Wazuh containers...$(NC)"
	@if [ -f docker-compose.yml ]; then \
		docker compose down -v; \
		echo "$(GREEN)✓ Legacy containers stopped$(NC)"; \
	else \
		echo "$(YELLOW)No docker-compose.yml found$(NC)"; \
	fi

##@ Git

git-status: ## Show git status
	@git status

git-log: ## Show recent commits
	@git log --oneline -10 --decorate --graph

##@ Information

info: ## Show project information
	@echo ""
	@echo "$(CYAN)╔═══════════════════════════════════════════════════════╗$(NC)"
	@echo "$(CYAN)║         O.W.A.S.A.K.A. SIEM - Project Info           ║$(NC)"
	@echo "$(CYAN)╚═══════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "  $(YELLOW)Version:$(NC)        $(VERSION)"
	@echo "  $(YELLOW)Commit:$(NC)         $(GIT_COMMIT)"
	@echo "  $(YELLOW)Go Version:$(NC)     $(shell go version | cut -d' ' -f3-)"
	@echo "  $(YELLOW)Platform:$(NC)       $(shell go env GOOS)/$(shell go env GOARCH)"
	@echo "  $(YELLOW)Module:$(NC)         github.com/marcosfpina/O.W.A.S.A.K.A"
	@echo "  $(YELLOW)Binary:$(NC)         $(BINARY_PATH)"
	@echo ""
	@echo "  $(YELLOW)Phase:$(NC)          Pre-Production"
	@echo "  $(YELLOW)Status:$(NC)         $(GREEN)Core Modules Integrated$(NC)"
	@echo ""

.DEFAULT_GOAL := help
