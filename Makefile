# Makefile for the Go Sudo I/O Log Server

# RPM package version
PKG_VERSION=0.1.0

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOMOD=$(GOCMD) mod

# Protoc variables
PROTOC=protoc
# The protoc-gen-go plugin is pinned by the `tool` directive in go.mod (Go 1.24+)
# rather than taken from PATH, so the generator version always matches the
# google.golang.org/protobuf runtime this module compiles against. Resolved
# lazily (=, not :=) so non-proto targets never pay for building the plugin.
PROTOC_GEN_GO=$(shell $(GOCMD) tool -n protoc-gen-go)
PROTO_SRC_DIR=pkg/sudosrv_proto
PROTO_SRC_FILE=$(PROTO_SRC_DIR)/sudo_logsrv.proto
PROTO_GO_OUT_DIR=$(PROTO_SRC_DIR)/

# Binary variables
BINARY_NAME=sudosrv
CMD_PATH=./cmd/sudosrv

# logsh, the recording login shell. Built with CGO_ENABLED=0 ALWAYS, not just
# for release: logsh is set as an account's shell in /etc/passwd, so a dynamic
# linker that cannot resolve it does not degrade the login, it prevents the login
# entirely. A static binary removes that whole failure mode. The cost is that
# os/user can no longer consult NSS, which is why record_users accepts numeric
# uids -- see Config.ShouldRecord.
LOGSH_BINARY_NAME=logsh
LOGSH_CMD_PATH=./cmd/logsh
LOGSH_ENV=CGO_ENABLED=0

# Build flags for stripped release binary
LDFLAGS_STRIP = -ldflags="-s -w"

# Default target executed when you just run `make`
.DEFAULT_GOAL := help

# Phony targets do not represent files
.PHONY: lint all build build-logsh install-logsh build-release build-linux-amd64 build-linux-arm64 release-all build-static-linux-amd64 build-static-linux-arm64 release-static-all proto test deps run clean help rpm deb arch

# Build the application for local architecture
all: build

build: proto deps build-logsh
	@echo "Building the application for local architecture..."
	$(GOBUILD) -o $(BINARY_NAME) $(CMD_PATH)
	@echo "Build complete: ./$(BINARY_NAME)"

# Build logsh, the recording login shell. See LOGSH_ENV for why this is always
# a static build.
build-logsh:
	@echo "Building logsh (static) for local architecture..."
	$(LOGSH_ENV) $(GOBUILD) -o $(LOGSH_BINARY_NAME) $(LOGSH_CMD_PATH)
	@echo "Build complete: ./$(LOGSH_BINARY_NAME)"

# Install logsh on THIS host: binary, symlinks, /etc/shells, then verify.
# Switches no account -- see docs/logsh-deployment.md for the rollout sequence
# and the mandatory break-glass drill.
install-logsh: build-logsh
	install -D -m 0755 $(LOGSH_BINARY_NAME) $(DESTDIR)/usr/sbin/$(LOGSH_BINARY_NAME)
	install -d -m 0755 $(DESTDIR)/etc/logsh
	@if [ ! -f $(DESTDIR)/etc/logsh/logsh.yaml ]; then \
		install -m 0644 examples/logsh.yaml $(DESTDIR)/etc/logsh/logsh.yaml; \
		echo "Installed a starter config at /etc/logsh/logsh.yaml -- review it before enabling."; \
	fi
	ROOT=$(DESTDIR) ./packaging/logsh/logsh-install.sh install
	@echo
	@echo "Installed. NO account has been switched."
	@echo "Next: logsh-install.sh verify, then read docs/logsh-deployment.md."

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
	$(PROTOC) --plugin=protoc-gen-go=$(PROTOC_GEN_GO) --proto_path=$(PROTO_SRC_DIR) --go_out=$(PROTO_GO_OUT_DIR) --go_opt=paths=source_relative $(PROTO_SRC_FILE)

# Run all unit tests verbosely with race detection
test:
	@echo "Running tests..."
	$(GOTEST) -race -timeout 60s -v ./...

# Run the linter. This is the ONLY place the version is pinned: the CI lint job
# runs `make lint` rather than the golangci-lint action, so there is no second
# copy of the version to drift out of step with this one.
# `go run pkg@version` resolves in an isolated module, so the version is pinned
# WITHOUT adding golangci-lint's dependency graph to go.mod/go.sum -- a tool
# directive here would add ~900 lines of go.sum for a binary that never ships.
GOLANGCI_LINT_VERSION = v2.12.2

lint:
	@echo "Running golangci-lint $(GOLANGCI_LINT_VERSION)..."
	$(GOCMD) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

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
#	rm -rf deb/
	$(GOCLEAN)

# Build RPM package
rpm:
	@echo "Building RPM package..."
	./rpm/build-rpm.sh "$(PKG_VERSION)"

# Build Debian package
deb:
	@echo "Building Debian package for $(BINARY_NAME) version $(PKG_VERSION)"
	@# Check if required tools are installed
	@if ! command -v dpkg-buildpackage >/dev/null 2>&1; then \
		echo "Error: dpkg-buildpackage not found. Please install devscripts package:"; \
		echo "  sudo apt-get install devscripts"; \
		exit 1; \
	fi
	@if ! command -v protoc >/dev/null 2>&1; then \
		echo "Error: protoc not found. Please install protobuf-compiler:"; \
		echo "  sudo apt-get install protobuf-compiler"; \
		exit 1; \
	fi
	@if ! command -v go >/dev/null 2>&1; then \
		echo "Error: go not found. Please install golang:"; \
		echo "  sudo apt-get install golang-go"; \
		exit 1; \
	fi
	@# Update changelog with current version if different
	@if ! grep -q "^$(BINARY_NAME) ($(PKG_VERSION)-1)" debian/changelog; then \
		echo "Updating changelog for version $(PKG_VERSION)"; \
		sed -i "1s/^$(BINARY_NAME) ([^)]*-1)/$(BINARY_NAME) ($(PKG_VERSION)-1)/" debian/changelog; \
	fi
	@# Clean any previous builds
	@echo "Cleaning previous builds..."
	@$(MAKE) clean || true
	@rm -rf deb/* || true
	@# Build the package
	@# Create deb output directory
	@pwd
	@mkdir -p deb
	@echo "Building package..."
	@dpkg-buildpackage -us -uc -b
	@# Move artifacts to deb folder
	@echo "Moving build artifacts to deb/ folder..."
	@mv ../$(BINARY_NAME)_*.deb deb/ 2>/dev/null || true
	@mv ../$(BINARY_NAME)_*.tar.xz deb/ 2>/dev/null || true
	@mv ../$(BINARY_NAME)_*.dsc deb/ 2>/dev/null || true
	@mv ../$(BINARY_NAME)_*.changes deb/ 2>/dev/null || true
	@mv ../$(BINARY_NAME)_*.buildinfo deb/ 2>/dev/null || true
	@echo "Package build completed successfully!"
	@# Show package info if deb file exists
	@if ls deb/$(BINARY_NAME)_*.deb >/dev/null 2>&1; then \
		DEB_FILE=$$(ls deb/$(BINARY_NAME)_*.deb | head -1); \
		echo "Debian package created: $$DEB_FILE"; \
		echo ""; \
		echo "Package information:"; \
		dpkg-deb -I "$$DEB_FILE"; \
	else \
		echo "Warning: No .deb files found in deb/ directory"; \
		echo "Check if dpkg-buildpackage completed successfully"; \
	fi

# Build Arch Linux package
arch:
	@echo "Building Arch Linux package for $(BINARY_NAME) version $(PKG_VERSION)"
	@if ! command -v makepkg >/dev/null 2>&1; then \
		echo "Error: makepkg not found. This must be run on Arch Linux."; \
		echo "  sudo pacman -S base-devel"; \
		exit 1; \
	fi
	./archlinux/build-arch.sh "$(PKG_VERSION)"

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
	@echo "  lint                     Run golangci-lint (version pinned in go.mod)."
	@echo "  deps                     Ensure all Go module dependencies are correct."
	@echo "  run                      Build and run the server. Use 'make run CONFIG=path/to/config.yaml' to specify a config file."
	@echo "  clean                    Remove all compiled binaries and build cache."
	@echo "  rpm                      Build RPM package for distribution."
	@echo "  deb                      Build Debian package for distribution."
	@echo "  arch                     Build Arch Linux package for distribution."
	@echo "  help                     Display this help message."
