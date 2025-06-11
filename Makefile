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

# Binary name
BINARY_NAME=sudosrv
CMD_PATH=./cmd/sudosrv

# Default target executed when you just run `make`
.DEFAULT_GOAL := help

# Phony targets do not represent files
.PHONY: all build proto test deps run clean help

# Build the application
# Depends on `proto` to ensure Go code is generated before building.
# Depends on `deps` to ensure all dependencies are fetched.
all: build

build: proto deps
	@echo "Building the application..."
	$(GOBUILD) -o $(BINARY_NAME) $(CMD_PATH)
	@echo "Build complete: ./$(BINARY_NAME)"

# Generate Go code from the .proto file
proto:
	@echo "Generating protobuf Go code from $(PROTO_SRC_FILE)..."
	$(PROTOC) --proto_path=$(PROTO_SRC_DIR) --go_out=$(PROTO_GO_OUT_DIR) --go_opt=paths=source_relative $(PROTO_SRC_FILE)

# Run all unit tests verbosely
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

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

# Clean up build artifacts
clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)
	$(GOCLEAN)

# Display help information
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all        Build the application binary (same as 'build')."
	@echo "  build      Compile the application."
	@echo "  proto      Generate Go code from the protobuf definition."
	@echo "  test       Run all unit tests."
	@echo "  deps       Ensure all Go module dependencies are correct."
	@echo "  run        Build and run the server. Use 'make run CONFIG=path/to/config.yaml' to specify a config file."
	@echo "  clean      Remove the compiled binary and build cache."
	@echo "  help       Display this help message."

