.PHONY: test test-unit test-integration test-coverage test-coverage-full test-race test-bench clean build help deps verify vet lint docker-build

# Default target
.DEFAULT_GOAL := help

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	@go mod download

# Verify dependencies
verify:
	@echo "Verifying dependencies..."
	@go mod verify

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...

# Run golangci-lint
lint:
	@echo "Running golangci-lint..."
	@golangci-lint run --timeout=5m

# Build the application
build:
	@echo "Building geoip-server..."
	@go build -o geoip-server .

# Run unit tests only (internal packages)
test-unit:
	@echo "Running unit tests (internal packages only)..."
	@go test -v ./internal/...

# Run all tests excluding integration (default go test behavior)
test:
	@echo "Running all tests (excluding integration)..."
	@go test -v ./...

# Run integration tests only
test-integration:
	@echo "Running integration tests..."
	@go test -v . -run ".*Integration.*" -test.short=false

# Run ALL tests including integration
test-all:
	@echo "Running ALL tests (including integration)..."
	@go test -v -test.short=false ./...

# Run ALL tests with race detection
test-race:
	@echo "Running ALL tests with race detection..."
	@go test -race -v -test.short=false ./...

# Generate test coverage report (excluding integration)
test-coverage:
	@echo "Generating test coverage report (excluding integration)..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1
	@echo "Coverage report generated: coverage.html"

# Generate FULL test coverage report (including integration)
test-coverage-full:
	@echo "Generating FULL test coverage report (including integration)..."
	@go test -race -coverprofile=coverage_full.out -test.short=false ./...
	@go tool cover -html=coverage_full.out -o coverage_full.html
	@go tool cover -func=coverage_full.out | tail -1
	@echo "Full coverage report generated: coverage_full.html"

# Run benchmarks
test-bench:
	@echo "Running benchmarks..."
	@go test -bench=. -test.short=false ./...

# Build Docker image (for local development)
docker-build:
	@echo "Building Docker image..."
	@docker build --build-arg DATE="$(shell date -u +%Y%m%d-%H%M%S)" -t geoip-server:latest .

# CI pipeline - full check sequence
ci: deps verify vet lint test-race
	@echo "All CI checks passed!"

# Clean build artifacts and coverage files
clean:
	@echo "Cleaning up..."
	@rm -f geoip-server coverage*.out coverage*.html

# Show help
help:
	@echo ""
	@echo "Available targets:"
	@echo "  deps               Download dependencies"
	@echo "  verify             Verify dependencies"
	@echo "  vet                Run go vet"
	@echo "  lint               Run golangci-lint"
	@echo "  build              Build the application"
	@echo "  test-unit          Run unit tests only (internal packages)"
	@echo "  test               Run all tests (excluding integration)"
	@echo "  test-integration   Run integration tests only"
	@echo "  test-all           Run ALL tests (including integration)"
	@echo "  test-race          Run ALL tests with race detection"
	@echo "  test-coverage      Generate coverage report (excluding integration)"
	@echo "  test-coverage-full Generate coverage report (including integration)"
	@echo "  test-bench         Run benchmarks"
	@echo "  docker-build       Build Docker image"
	@echo "  ci                 Run full CI pipeline (deps+verify+vet+lint+test-race)"
	@echo "  clean              Clean build artifacts"
	@echo "  help               Show this help message"
	@echo ""
	@echo "Quick commands:"
	@echo "  make ci                 # Full CI pipeline"
	@echo "  make test-coverage-full # Full coverage with integration tests"
	@echo "  make test-race          # All tests with race detection"
	@echo "  make test               # Fast tests without integration"
