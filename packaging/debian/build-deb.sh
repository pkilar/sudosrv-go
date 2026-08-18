#!/bin/bash
#
# Build the sudosrv and logsh .debs.
#
# Usage: packaging/debian/build-deb.sh
#
# Requires: dpkg-buildpackage (dpkg-dev), debhelper, git, tar, and a Go
# toolchain with network access -- see the Build-Depends comment in control.
#
# debian/ lives under packaging/debian/ in this repo, but dpkg-buildpackage
# insists on finding it at the root of the source tree, so it is copied into the
# staged snapshot rather than kept at the repo root.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd -- "${SCRIPT_DIR}/../.." && pwd)
# shellcheck source=../stage-source.sh
. "${PROJECT_ROOT}/packaging/stage-source.sh"

VERSION=$(read_version)
NAME=sudosrv
BUILDDIR="${PROJECT_ROOT}/debbuild"
STAGING="${BUILDDIR}/${NAME}-${VERSION}"

command -v dpkg-buildpackage >/dev/null || {
	echo "error: dpkg-buildpackage not found. Install dpkg-dev and debhelper." >&2
	exit 1
}

echo ":: sudosrv ${VERSION} -> deb"
rm -rf "${BUILDDIR}"
mkdir -p "${BUILDDIR}"

stage_source "${STAGING}"
mkdir -p "${STAGING}/debian"
cp -a "${SCRIPT_DIR}/." "${STAGING}/debian/"
rm -f "${STAGING}/debian/build-deb.sh"

# The shared sysusers and tmpfiles files, under the names debhelper looks for.
# This is done here rather than from a debian/rules hook because dh plans its
# sequence -- including which commands to skip -- before rules runs, so a hook
# that creates them is always too late. See the comment in debian/rules.
install -m 0644 "${PROJECT_ROOT}/packaging/sysusers/sudosrv.conf" "${STAGING}/debian/sudosrv.sysusers"
install -m 0644 "${PROJECT_ROOT}/packaging/tmpfiles/sudosrv.conf" "${STAGING}/debian/sudosrv.tmpfiles"

# Rewrite, do not cross-check. The changelog is authoritative to dpkg and so
# CAN disagree with VERSION; a build that merely warns still lets a wrong
# version ship. Rewriting the staged copy makes disagreement impossible and
# leaves the committed changelog obviously not hand-maintained for the version.
sed -i "1s/^${NAME} ([^)]*)/${NAME} (${VERSION}-1)/" "${STAGING}/debian/changelog"

cd "${STAGING}"
dpkg-buildpackage -us -uc -b

echo
echo ":: built"
find "${BUILDDIR}" -maxdepth 1 -name '*.deb' | sed 's/^/   /'
