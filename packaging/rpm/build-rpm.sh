#!/bin/bash
#
# Build the sudosrv and logsh RPMs.
#
# Usage: packaging/rpm/build-rpm.sh
#
# Requires: rpmbuild (rpm-build), git, tar, and a Go toolchain with network
# access -- see the BuildRequires comment in sudosrv.spec.
#
# The version comes from the top-level VERSION file and is injected as
# %{rpm_version}; it is never typed into the spec.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd -- "${SCRIPT_DIR}/../.." && pwd)
# shellcheck source=../stage-source.sh
. "${PROJECT_ROOT}/packaging/stage-source.sh"

VERSION=$(read_version)
NAME=sudosrv
TOPDIR="${PROJECT_ROOT}/rpmbuild"

command -v rpmbuild >/dev/null || {
	echo "error: rpmbuild not found. Install rpm-build (dnf install rpm-build rpmdevtools)." >&2
	exit 1
}

echo ":: sudosrv ${VERSION} -> RPM"
rm -rf "${TOPDIR}"
mkdir -p "${TOPDIR}"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}

stage_source "${TOPDIR}/staging/${NAME}-${VERSION}"
tar -czf "${TOPDIR}/SOURCES/${NAME}-${VERSION}.tar.gz" \
	-C "${TOPDIR}/staging" "${NAME}-${VERSION}"

# Source1/Source2: the shared sysusers and tmpfiles files. The spec takes them
# as Sources rather than from inside the tarball because %sysusers_create_compat
# embeds their content at spec-parse time.
install -m 0644 "${PROJECT_ROOT}/packaging/sysusers/sudosrv.conf" "${TOPDIR}/SOURCES/sudosrv.sysusers"
install -m 0644 "${PROJECT_ROOT}/packaging/tmpfiles/sudosrv.conf" "${TOPDIR}/SOURCES/sudosrv.tmpfiles"

# Host architecture only. The previous script looped over x86_64 and aarch64
# passing --target, but %build runs `make build` with no GOARCH, so the
# "aarch64" package contained an x86_64 binary under an aarch64 tag -- a package
# that installs and then cannot execute. Build on the target architecture, or
# use the Makefile's cross-compile targets and a pipeline that plumbs GOARCH
# through %build.
rpmbuild --define "_topdir ${TOPDIR}" \
	--define "rpm_version ${VERSION}" \
	-ba "${SCRIPT_DIR}/${NAME}.spec"

echo
echo ":: built"
find "${TOPDIR}/RPMS" "${TOPDIR}/SRPMS" -name '*.rpm' | sed 's/^/   /'
