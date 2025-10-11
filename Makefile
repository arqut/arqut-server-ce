.PHONY: build run dev test coverage coverage-html clean install-deps tidy apikey-generate apikey-rotate apikey-status help

# Binary name
BINARY_NAME=arqut-server
BUILD_DIR=./build

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GORUN=$(GOCMD) run
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOCLEAN=$(GOCMD) clean

# Build flags
LDFLAGS=-ldflags "-s -w"

# Default target
all: build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

# Run the server (development mode - no build)
dev:
	$(GORUN) ./cmd/server -c config.yaml

# Run the built server
run: build
	@echo "Starting server..."
	$(BUILD_DIR)/$(BINARY_NAME) -c config.yaml

# Install dependencies
install-deps:
	@echo "Installing dependencies..."
	$(GOGET) github.com/knadh/koanf/v2
	$(GOGET) github.com/knadh/koanf/parsers/yaml
	$(GOGET) github.com/knadh/koanf/providers/file
	$(GOGET) github.com/pion/turn/v4
	$(GOGET) github.com/go-acme/lego/v4
	$(GOGET) github.com/gorilla/websocket
	$(GOGET) github.com/gofiber/fiber/v2
	$(GOGET) github.com/stretchr/testify
	$(GOMOD) tidy

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race ./...

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -func=coverage.out

# Generate HTML coverage report
coverage-html: coverage
	@echo "Generating HTML coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# API Key management targets
apikey-generate: build
	@echo "Generating API key..."
	$(BUILD_DIR)/$(BINARY_NAME) apikey generate -c config.yaml

apikey-rotate: build
	@echo "Rotating API key..."
	$(BUILD_DIR)/$(BINARY_NAME) apikey rotate -c config.yaml

apikey-status: build
	@echo "Checking API key status..."
	$(BUILD_DIR)/$(BINARY_NAME) apikey status -c config.yaml

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build the server binary to ./build/"
	@echo "  run            - Build and run the server"
	@echo "  dev            - Run server without building (go run)"
	@echo "  test           - Run all tests"
	@echo "  coverage       - Run tests with coverage report"
	@echo "  coverage-html  - Generate HTML coverage report"
	@echo "  install-deps   - Install project dependencies"
	@echo "  tidy           - Tidy go.mod and go.sum"
	@echo "  clean          - Remove build artifacts"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "API Key Management:"
	@echo "  apikey-generate - Generate new API key"
	@echo "  apikey-rotate   - Rotate existing API key"
	@echo "  apikey-status   - Show API key status"
