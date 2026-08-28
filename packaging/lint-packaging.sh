#!/bin/sh
# Build one package format in a clean container and lint the BUILT package.
#
# Linting the recipe catches syntax; linting the built package catches what the
# recipe actually produced -- unowned files, wrong permissions, missing runtime
# dependencies, scriptlets that reference paths which do not exist on a target
# host. Three real defects were found this way and none of them were visible in
# the recipe: a logrotate config nothing depended on, a %post that ran
# systemd-tmpfiles against the builder's own SOURCES directory, and a log
# directory logrotate would have processed as root.
#
# The build runs from `git archive HEAD`, so it lints COMMITTED state. Commit
# before running this locally or you will lint the previous revision.
#
# usage: packaging/lint-packaging.sh <rpm|deb|arch>
set -eu

FORMAT="${1:-}"
case "$FORMAT" in
rpm | deb | arch) ;;
*)
	echo "usage: $0 <rpm|deb|arch>" >&2
	exit 2
	;;
esac

if command -v podman >/dev/null 2>&1; then
	ENGINE=podman
elif command -v docker >/dev/null 2>&1; then
	ENGINE=docker
else
	echo "error: neither podman nor docker is available" >&2
	exit 2
fi

REPO=$(cd -- "$(dirname -- "$0")/.." && pwd)

# Error-level lines differ per linter but the gate is the same: any error fails
# the job, warnings are printed for information. Findings that genuinely do not
# apply belong in that format's justified filter file (sudosrv.rpmlintrc,
# debian/*.lintian-overrides), not in a widened gate here.
case "$FORMAT" in
rpm)
	IMAGE=fedora:latest
	SCRIPT='
	set -e
	dnf install -y -q rpm-build golang protobuf-compiler systemd-rpm-macros \
	    make git rpmlint >/dev/null
	mkdir -p /work && cp -a /src/. /work/ && cd /work
	git config --global --add safe.directory /work
	./packaging/rpm/build-rpm.sh >/dev/null
	rc=0
	for f in rpmbuild/RPMS/*/*.rpm rpmbuild/SRPMS/*.rpm; do
		echo "===== $(basename "$f") ====="
		rpmlint -f packaging/rpm/sudosrv.rpmlintrc "$f" 2>&1 | tee /tmp/out || true
		if grep -qE ": E: " /tmp/out; then rc=1; fi
	done
	exit $rc
	'
	;;
deb)
	IMAGE=debian:stable
	SCRIPT='
	set -e
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq build-essential debhelper golang-go protobuf-compiler \
	    git ca-certificates lintian >/dev/null
	mkdir -p /work && cp -a /src/. /work/ && cd /work
	git config --global --add safe.directory /work
	./packaging/debian/build-deb.sh >/dev/null
	rc=0
	for f in debbuild/*.deb; do
		echo "===== $(basename "$f") ====="
		lintian -i --tag-display-limit 0 --fail-on error "$f" || rc=1
	done
	exit $rc
	'
	;;
arch)
	IMAGE=archlinux:latest
	# makepkg refuses to run as root, so the build runs as a throwaway account
	# that owns the copied tree.
	SCRIPT='
	set -e
	pacman -Sy --noconfirm --needed base-devel go protobuf git namcap >/dev/null 2>&1
	useradd -m builder
	mkdir -p /work && cp -a /src/. /work/ && chown -R builder /work
	cd /work
	git config --global --add safe.directory /work
	su builder -c "git config --global --add safe.directory /work"
	su builder -c "./packaging/arch/build-arch.sh" >/dev/null
	rc=0
	for f in archbuild/*.pkg.tar.*; do
		echo "===== $(basename "$f") ====="
		namcap "$f" 2>&1 | tee /tmp/out || true
		if grep -qE " E: " /tmp/out; then rc=1; fi
	done
	exit $rc
	'
	;;
esac

echo ":: linting $FORMAT packages in $IMAGE via $ENGINE"
exec "$ENGINE" run --rm -v "$REPO:/src:ro" "$IMAGE" sh -c "$SCRIPT"
