# CELScanner Plugin Makefile

BINARY_NAME=celscanner-plugin
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-s -w"

# Default target
all: build

# Build the plugin
build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME) .

# Run unit tests
test:
	@echo "Running unit tests..."
	$(GO) test $(GOFLAGS) ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test $(GOFLAGS) -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Run integration tests against live Kubernetes cluster
test-k8s:
	@echo "Running Kubernetes integration tests..."
	@echo "Using kubeconfig: $${KUBECONFIG:-$$HOME/.kube/config}"
	$(GO) test $(GOFLAGS) -tags=integration -timeout=60s ./...

# Run all tests (unit + integration)
test-all: test test-k8s

# Run tests with specific kubeconfig
test-k8s-config:
	@echo "Running Kubernetes integration tests with specific kubeconfig..."
	KUBECONFIG=/home/vincent/.kube/config $(GO) test $(GOFLAGS) -tags=integration -timeout=60s ./...

# Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

# Run linters
lint:
	@echo "Running linters..."
	golangci-lint run

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

# Install the plugin
install: build
	@echo "Installing $(BINARY_NAME)..."
	mkdir -p ~/.complyctl/plugins
	cp $(BINARY_NAME) ~/.complyctl/plugins/

# Generate mocks for testing
generate-mocks:
	@echo "Generating mocks..."
	mockgen -source=server/server.go -destination=server/server_mock.go -package=server

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	$(GO) test $(GOFLAGS) -tags=integration ./...

# Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 .
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe .

# Development target - build and install
dev: fmt build install

# Check dependencies
deps:
	@echo "Checking dependencies..."
	$(GO) mod tidy
	$(GO) mod verify

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Build the plugin (default)"
	@echo "  build         - Build the plugin binary"
	@echo "  test          - Run unit tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Run linters"
	@echo "  clean         - Remove build artifacts"
	@echo "  install       - Install plugin to ~/.complyctl/plugins"
	@echo "  deps          - Check and tidy dependencies"
	@echo "  dev           - Format, build, and install"
	@echo "  help          - Show this help message"

.PHONY: all build test test-coverage fmt lint clean install generate-mocks test-integration build-all dev deps help