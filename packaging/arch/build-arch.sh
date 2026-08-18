#!/bin/bash
#
# Build the sudosrv and logsh Arch packages.
#
# Usage: packaging/arch/build-arch.sh
#
# Requires: makepkg (base-devel), git, tar. Must NOT be run as root -- makepkg
# refuses; use an unprivileged user with sudo rights for dependency install.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd -- "${SCRIPT_DIR}/../.." && pwd)
# shellcheck source=../stage-source.sh
. "${PROJECT_ROOT}/packaging/stage-source.sh"

VERSION=$(read_version)
NAME=sudosrv
BUILDDIR="${PROJECT_ROOT}/archbuild"

command -v makepkg >/dev/null || {
	echo "error: makepkg not found. This must run on Arch (pacman -S base-devel)." >&2
	exit 1
}

echo ":: sudosrv ${VERSION} -> pkg.tar.zst"
rm -rf "${BUILDDIR}"
mkdir -p "${BUILDDIR}"

stage_source "${BUILDDIR}/staging/${NAME}-${VERSION}"
tar -czf "${BUILDDIR}/${NAME}-${VERSION}.tar.gz" \
	-C "${BUILDDIR}/staging" "${NAME}-${VERSION}"
rm -rf "${BUILDDIR}/staging"

# Every .install referenced by the PKGBUILD has to sit beside it. Copying only
# sudosrv.install is what the previous script did, so makepkg failed on the
# logsh subpackage from the day the split landed.
cp "${SCRIPT_DIR}/PKGBUILD" "${BUILDDIR}/"
cp "${SCRIPT_DIR}"/*.install "${BUILDDIR}/"

cd "${BUILDDIR}"
sed -i "s/^pkgver=.*/pkgver=${VERSION}/" PKGBUILD
sed -i "s/^sha256sums=.*/sha256sums=('$(sha256sum "${NAME}-${VERSION}.tar.gz" | cut -d' ' -f1)')/" PKGBUILD

makepkg -sf --noconfirm

echo
echo ":: built"
find "${BUILDDIR}" -maxdepth 1 -name '*.pkg.tar.*' | sed 's/^/   /'
