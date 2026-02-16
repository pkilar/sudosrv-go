#!/bin/bash
set -e

# Build Arch Linux package for sudosrv
# Usage: ./archlinux/build-arch.sh [version]

VERSION=${1:-0.1.0}
PACKAGE_NAME="sudosrv"
BUILD_ROOT="$PWD"
ARCH_DIR="$BUILD_ROOT/archlinux"
WORK_DIR=$(mktemp -d)

echo "Building Arch Linux package for $PACKAGE_NAME version $VERSION"

# Check for makepkg
if ! command -v makepkg &> /dev/null; then
    echo "Error: makepkg not found. This must be run on Arch Linux."
    echo "Install base-devel: sudo pacman -S base-devel"
    exit 1
fi

# Create source tarball
echo "Creating source tarball..."
SOURCE_DIR="$WORK_DIR/${PACKAGE_NAME}-${VERSION}"
mkdir -p "$SOURCE_DIR"

rsync -a \
    --exclude='/.git' \
    --exclude='/deb' \
    --exclude='/debian' \
    --exclude='/rpm' \
    --exclude='/sudosrv' \
    --exclude='/sudosrv-linux-*' \
    "$BUILD_ROOT/" "$SOURCE_DIR/"

cd "$WORK_DIR"
tar -czf "${PACKAGE_NAME}-${VERSION}.tar.gz" "${PACKAGE_NAME}-${VERSION}/"

# Set up makepkg build directory
BUILD_DIR="$WORK_DIR/build"
mkdir -p "$BUILD_DIR"

# Copy PKGBUILD and install script
cp "$ARCH_DIR/PKGBUILD" "$BUILD_DIR/"
cp "$ARCH_DIR/sudosrv.install" "$BUILD_DIR/"

# Update version in PKGBUILD
sed -i "s/^pkgver=.*/pkgver=${VERSION}/" "$BUILD_DIR/PKGBUILD"

# Move source tarball next to PKGBUILD
mv "$WORK_DIR/${PACKAGE_NAME}-${VERSION}.tar.gz" "$BUILD_DIR/"

# Generate checksums
cd "$BUILD_DIR"
SHA256=$(sha256sum "${PACKAGE_NAME}-${VERSION}.tar.gz" | awk '{print $1}')
sed -i "s/sha256sums=('SKIP')/sha256sums=('${SHA256}')/" PKGBUILD

# Build the package
echo "Running makepkg..."
makepkg -sf --noconfirm

# Copy resulting package back to project
mkdir -p "$BUILD_ROOT/archlinux/pkg"
cp "$BUILD_DIR"/${PACKAGE_NAME}-*.pkg.tar.* "$BUILD_ROOT/archlinux/pkg/" 2>/dev/null || true

echo ""
echo "Build complete!"
if ls "$BUILD_ROOT/archlinux/pkg/"${PACKAGE_NAME}-*.pkg.tar.* &>/dev/null; then
    echo "Package(s):"
    ls -lh "$BUILD_ROOT/archlinux/pkg/"${PACKAGE_NAME}-*.pkg.tar.*
    echo ""
    echo "Install with: sudo pacman -U archlinux/pkg/${PACKAGE_NAME}-${VERSION}-1-*.pkg.tar.*"
else
    echo "Warning: No package files found. Check makepkg output above."
fi

# Clean up
rm -rf "$WORK_DIR"
