# Makefile for the Go Sudo I/O Log Server

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOMOD=$(GOCMD) mod

# Protoc variables
PROTOC=protoc
PROTO_SRC_DIR=pkg/sudosrv_proto
PROTO_SRC_FILE=$(PROTO_SRC_DIR)/sudo_logsrv.proto
PROTO_GO_OUT_DIR=$(PROTO_SRC_DIR)/

# Binary variables
BINARY_NAME=sudosrv
CMD_PATH=./cmd/sudosrv

# Build flags for stripped release binary
LDFLAGS_STRIP = -ldflags="-s -w"

# Default target executed when you just run `make`
.DEFAULT_GOAL := help

# Phony targets do not represent files
.PHONY: all build build-release build-linux-amd64 build-linux-arm64 release-all build-static-linux-amd64 build-static-linux-arm64 release-static-all proto test deps run clean help

# Build the application for local architecture
all: build

build: proto deps
	@echo "Building the application for local architecture..."
	$(GOBUILD) -o $(BINARY_NAME) $(CMD_PATH)
	@echo "Build complete: ./$(BINARY_NAME)"

# Build a stripped release binary for the local architecture
build-release: proto deps
	@echo "Building stripped release binary for local architecture..."
	$(GOBUILD) $(LDFLAGS_STRIP) -o $(BINARY_NAME) $(CMD_PATH)
	@echo "Stripped build complete: ./$(BINARY_NAME)"

# Build stripped release binaries for specific architectures
build-linux-amd64: proto deps
	@echo "Building for Linux (x86_64)..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS_STRIP) -o $(BINARY_NAME)-linux-amd64 $(CMD_PATH)
	@echo "Build complete: ./$(BINARY_NAME)-linux-amd64"

build-linux-arm64: proto deps
	@echo "Building for Linux (ARM64)..."
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS_STRIP) -o $(BINARY_NAME)-linux-arm64 $(CMD_PATH)
	@echo "Build complete: ./$(BINARY_NAME)-linux-arm64"

# Build all release binaries
release-all: build-linux-amd64 build-linux-arm64
	@echo "All release binaries built."

# Build stripped, statically linked release binaries for specific architectures
build-static-linux-amd64: proto deps
	@echo "Building statically linked binary for Linux (x86_64)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS_STRIP) -o $(BINARY_NAME)-linux-amd64-static $(CMD_PATH)
	@echo "Build complete: ./$(BINARY_NAME)-linux-amd64-static"

build-static-linux-arm64: proto deps
	@echo "Building statically linked binary for Linux (ARM64)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS_STRIP) -o $(BINARY_NAME)-linux-arm64-static $(CMD_PATH)
	@echo "Build complete: ./$(BINARY_NAME)-linux-arm64-static"

# Build all static release binaries
release-static-all: build-static-linux-amd64 build-static-linux-arm64
	@echo "All static release binaries built."


# Generate Go code from the .proto file
proto:
	@echo "Generating protobuf Go code from $(PROTO_SRC_FILE)..."
	$(PROTOC) --proto_path=$(PROTO_SRC_DIR) --go_out=$(PROTO_GO_OUT_DIR) --go_opt=paths=source_relative $(PROTO_SRC_FILE)

# Run all unit tests verbosely
test:
	@echo "Running tests..."
	$(GOTEST) -timeout 30s -v ./...

# Tidy Go module dependencies
deps:
	@echo "Tidying module dependencies..."
	$(GOMOD) tidy

# Build and run the application with a default config file path
# Example: make run CONFIG=./config.yaml
CONFIG ?= config.yaml
run: build
	@echo "Running the server with config: $(CONFIG)..."
	./$(BINARY_NAME) -config=$(CONFIG)

# Clean up all build artifacts
clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME) $(BINARY_NAME)-linux-amd64 $(BINARY_NAME)-linux-arm64 $(BINARY_NAME)-linux-amd64-static $(BINARY_NAME)-linux-arm64-static
	$(GOCLEAN)

# Display help information
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all                      Build the application binary for the local architecture (default)."
	@echo "  build                    Compile the application for the local architecture."
	@echo "  build-release            Build a smaller, stripped binary for the local architecture."
	@echo "  build-linux-amd64        Cross-compile a stripped binary for Linux (x86_64)."
	@echo "  build-linux-arm64        Cross-compile a stripped binary for Linux (ARM64)."
	@echo "  release-all              Build all release binaries (linux-amd64, linux-arm64)."
	@echo "  build-static-linux-amd64 Cross-compile a statically linked binary for Linux (x86_64)."
	@echo "  build-static-linux-arm64 Cross-compile a statically linked binary for Linux (ARM64)."
	@echo "  release-static-all       Build all static release binaries."
	@echo "  proto                    Generate Go code from the protobuf definition."
	@echo "  test                     Run all unit tests."
	@echo "  deps                     Ensure all Go module dependencies are correct."
	@echo "  run                      Build and run the server. Use 'make run CONFIG=path/to/config.yaml' to specify a config file."
	@echo "  clean                    Remove all compiled binaries and build cache."
	@echo "  help                     Display this help message."
