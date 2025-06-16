#!/bin/bash
set -e

# Script to build RPM package for sudosrv
# Usage: ./rpm/build-rpm.sh [version] [architecture]
# Architecture can be: x86_64, aarch64, or all (default: all)

VERSION=${1:-1.0.0}
ARCH=${2:-all}
PACKAGE_NAME="sudosrv"
SPEC_FILE="rpm/SPECS/${PACKAGE_NAME}.spec"
BUILD_ROOT="$PWD"
RPM_BUILD_DIR="$BUILD_ROOT/rpm"

echo "Building RPM package for $PACKAGE_NAME version $VERSION"

# Check if rpmbuild is available
if ! command -v rpmbuild &> /dev/null; then
    echo "Error: rpmbuild not found. Please install rpm-build package."
    echo "On RHEL/CentOS/Fedora: sudo dnf install rpm-build rpmdevtools"
    echo "On Ubuntu/Debian: sudo apt install rpm"
    exit 1
fi

# Create source tarball
echo "Creating source tarball..."
TARBALL_NAME="${PACKAGE_NAME}-${VERSION}.tar.gz"
TEMP_DIR=$(mktemp -d)
SOURCE_DIR="$TEMP_DIR/${PACKAGE_NAME}-${VERSION}"

# Copy source files excluding build artifacts and rpm directory
mkdir -p "$SOURCE_DIR"
rsync -av cmd internal pkg Makefile go.mod go.sum "$SOURCE_DIR/"

# Copy rpm sources to the source directory for the build
cp -r "$BUILD_ROOT/rpm/SOURCES" "$SOURCE_DIR/rpm/"

# Create tarball
cd "$TEMP_DIR"
tar -czf "$RPM_BUILD_DIR/SOURCES/$TARBALL_NAME" "${PACKAGE_NAME}-${VERSION}/"
cd "$BUILD_ROOT"

# Clean up temp directory
rm -rf "$TEMP_DIR"

echo "Source tarball created: $RPM_BUILD_DIR/SOURCES/$TARBALL_NAME"

# Function to build RPM for specific architecture
build_rpm_for_arch() {
    local target_arch=$1
    echo "Building RPM for architecture: $target_arch"

    rpmbuild --define "_topdir $RPM_BUILD_DIR" \
             --define "_version $VERSION" \
             --target "$target_arch" \
             -ba "$SPEC_FILE"
}

# Build RPMs based on architecture parameter
if [ "$ARCH" = "all" ]; then
    echo "Building RPMs for all supported architectures..."
    build_rpm_for_arch "x86_64"
    build_rpm_for_arch "aarch64"
elif [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "aarch64" ]; then
    build_rpm_for_arch "$ARCH"
else
    echo "Error: Unsupported architecture '$ARCH'. Supported: x86_64, aarch64, all"
    exit 1
fi

echo "RPM build completed!"
echo "Binary RPMs: $RPM_BUILD_DIR/RPMS/"
echo "Source RPM: $RPM_BUILD_DIR/SRPMS/"

# List the generated packages
echo
echo "Generated packages:"
find "$RPM_BUILD_DIR/RPMS" -name "*.rpm" -exec basename {} \; 2>/dev/null || true
find "$RPM_BUILD_DIR/SRPMS" -name "*.rpm" -exec basename {} \; 2>/dev/null || true