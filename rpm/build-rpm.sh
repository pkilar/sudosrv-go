#!/bin/bash
set -e

# Script to build RPM package for sudosrv
# Usage: ./rpm/build-rpm.sh [version]

VERSION=${1:-1.0.0}
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
rsync -av --exclude='rpm/' --exclude='sudosrv*' --exclude='.git/' \
    --exclude='*.log' --exclude='*.tmp' "$BUILD_ROOT/" "$SOURCE_DIR/"

# Copy rpm sources to the source directory for the build
cp -r "$BUILD_ROOT/rpm/SOURCES" "$SOURCE_DIR/rpm/"

# Create tarball
cd "$TEMP_DIR"
tar -czf "$RPM_BUILD_DIR/SOURCES/$TARBALL_NAME" "${PACKAGE_NAME}-${VERSION}/"
cd "$BUILD_ROOT"

# Clean up temp directory
rm -rf "$TEMP_DIR"

echo "Source tarball created: $RPM_BUILD_DIR/SOURCES/$TARBALL_NAME"

# Build the RPM
echo "Building RPM package..."
rpmbuild --define "_topdir $RPM_BUILD_DIR" \
         --define "_version $VERSION" \
         -ba "$SPEC_FILE"

echo "RPM build completed!"
echo "Binary RPMs: $RPM_BUILD_DIR/RPMS/"
echo "Source RPM: $RPM_BUILD_DIR/SRPMS/"

# List the generated packages
echo
echo "Generated packages:"
find "$RPM_BUILD_DIR/RPMS" -name "*.rpm" -exec basename {} \; 2>/dev/null || true
find "$RPM_BUILD_DIR/SRPMS" -name "*.rpm" -exec basename {} \; 2>/dev/null || true