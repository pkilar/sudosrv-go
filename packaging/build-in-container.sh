#!/bin/sh
# Build one target's packages in a clean container, and optionally lint them.
#
# The container supplies the DISTRIBUTION; this machine supplies the
# ARCHITECTURE. Nothing here passes an architecture to the container engine:
# no platform flag, no cross toolchain, no emulation. A package is built on
# hardware of the architecture it targets, which is what keeps cgo, glibc
# linkage and shared-library dependency generation correct.
#
# Build dependencies come from the recipe's own declarations rather than a list
# maintained here, so a distribution nobody anticipated works without editing
# this file.
#
# The build stages from `git archive HEAD`, so it builds COMMITTED state.
# Commit before running this locally or you will build your previous revision.
#
# Behind a firewall, see --site below: internal package repositories, a proxy,
# and a corporate CA are supplied from a directory outside this repo, because
# they are site-specific and their hostnames are usually not public.
#
# usage: build-in-container.sh <target-id> [--lint] [--out DIR] [--dry-run]
#                              [--site DIR]
set -eu

DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO=$(cd -- "$DIR/.." && pwd)
TARGETS="$DIR/targets.sh"

TARGET="" LINT=0 OUT="$REPO/dist" DRYRUN=0 SITE="${PKG_SITE_DIR:-}"
while [ $# -gt 0 ]; do
	case "$1" in
	--lint) LINT=1; shift ;;
	--out) OUT="$2"; shift 2 ;;
	--dry-run) DRYRUN=1; shift ;;
	--site) SITE="$2"; shift 2 ;;
	-h|--help) sed -n '2,17p' "$0"; exit 0 ;;
	-*) echo "error: unknown option $1" >&2; exit 2 ;;
	*)
		[ -z "$TARGET" ] || { echo "error: one target at a time" >&2; exit 2; }
		TARGET="$1"; shift ;;
	esac
done
[ -n "$TARGET" ] || { echo "usage: build-in-container.sh <target-id> [--lint]" >&2; exit 2; }

ROW=$("$TARGETS" get "$TARGET") || exit 2
FORMAT=$(printf '%s' "$ROW" | cut -f1)
IMAGE=$(printf '%s' "$ROW" | cut -f2)
ARCHES=$(printf '%s' "$ROW" | cut -f3)

# Normalise to the manifest's vocabulary. uname reports the machine name; the
# manifest and the CI runner labels use Go/OCI names.
case "$(uname -m)" in
x86_64) HOST_ARCH=amd64 ;;
aarch64 | arm64) HOST_ARCH=arm64 ;;
*) echo "error: unsupported host architecture $(uname -m)" >&2; exit 2 ;;
esac

if ! "$TARGETS" supports "$TARGET" "$HOST_ARCH"; then
	echo "error: target '$TARGET' does not support $HOST_ARCH (supports: $ARCHES)." >&2
	echo "       Build it on $ARCHES hardware. This tool does not emulate or" >&2
	echo "       cross-compile, deliberately -- see docs/building-packages.md." >&2
	exit 2
fi

if command -v podman >/dev/null 2>&1; then ENGINE=podman
elif command -v docker >/dev/null 2>&1; then ENGINE=docker
else ENGINE=none
fi

# --dry-run resolves the target and reports; it starts no container, so it must
# not require an engine. It runs where one cannot exist -- notably inside a
# package build, since the Debian recipe and the PKGBUILD both run the test
# suite, and the tests exercise this path.
if [ -n "$SITE" ]; then
	[ -d "$SITE" ] || { echo "error: --site '$SITE' is not a directory" >&2; exit 2; }
	SITE=$(cd -- "$SITE" && pwd)
fi

if [ "$DRYRUN" = 1 ]; then
	echo "target=$TARGET format=$FORMAT image=$IMAGE arch=$HOST_ARCH engine=$ENGINE site=${SITE:-none}"
	exit 0
fi

if [ "$ENGINE" = none ]; then
	echo "error: neither podman nor docker is available" >&2
	exit 2
fi

case "$FORMAT" in
rpm)
	# rpmlint is installed separately and tolerated as missing: UBI 10 ships no
	# rpmlint in its repositories at all. A distribution's tooling gap must not
	# make the target unbuildable -- but it must not read as a clean lint
	# either, which is what the LINT UNAVAILABLE notice below is for.
	BOOTSTRAP='dnf install -y -q rpm-build make git "dnf-command(builddep)" && { dnf install -y -q rpmlint || echo "note: rpmlint unavailable"; }'
	BUILDDEP='dnf builddep -y -q packaging/rpm/sudosrv.spec'
	BUILDCMD='./packaging/rpm/build-rpm.sh'
	GLOB='rpmbuild/RPMS/*/*.rpm rpmbuild/SRPMS/*.rpm'
	# rpmlint 1.x (RHEL 9) and 2.x (Fedora) disagree about the flag for a
	# config file: 1.x spells it -f and has no unused-filter check to disable,
	# 2.x spells it -r and reports unused filters as errors. Both understand the
	# addFilter() rpmlintrc, so only the invocation differs. Probing beats
	# pinning a version here -- the whole point is that a target's own toolchain
	# is what gets exercised.
	LINTPRE='rpmlint_compat() {
	if rpmlint --help 2>&1 | grep -q -- --ignore-unused-rpmlintrc; then
		rpmlint --ignore-unused-rpmlintrc -r packaging/rpm/sudosrv.rpmlintrc "$1"
	else
		rpmlint -f packaging/rpm/sudosrv.rpmlintrc "$1"
	fi
}'
	SITE_REPO_DIR='/etc/yum.repos.d'
	SITE_REPO_EXT='repo'
	SITE_REPO_DEST=''
	SITE_CA_DIR='/etc/pki/ca-trust/source/anchors'
	SITE_CA_UPDATE='update-ca-trust'
	LINTER='rpmlint'
	LINTCMD='rpmlint_compat'
	ERRPAT=': E: '
	;;
deb)
	BOOTSTRAP='export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends build-essential debhelper devscripts equivs lintian git ca-certificates'
	BUILDDEP='mk-build-deps -ri -t "apt-get -y --no-install-recommends" packaging/debian/control'
	BUILDCMD='./packaging/debian/build-deb.sh'
	GLOB='debbuild/*.deb'
	LINTPRE=''
	SITE_REPO_DIR='/etc/apt/sources.list.d'
	SITE_REPO_EXT='list sources'
	SITE_REPO_DEST=''
	SITE_CA_DIR='/usr/local/share/ca-certificates'
	SITE_CA_UPDATE='update-ca-certificates'
	LINTER='lintian'
	LINTCMD='lintian -i --tag-display-limit 0 --fail-on error'
	ERRPAT='^E: '
	;;
arch)
	# makepkg refuses to run as root, and makepkg -s resolves makedepends
	# itself, so there is no separate build-dep step.
	BOOTSTRAP='pacman -Sy --noconfirm --needed base-devel go git namcap >/dev/null 2>&1; useradd -m builder'
	BUILDDEP=':'
	BUILDCMD='chown -R builder /work && su builder -c "./packaging/arch/build-arch.sh"'
	GLOB='archbuild/*.pkg.tar.*'
	LINTPRE=''
	# pacman takes a mirrorlist rather than repo fragments; a site file named
	# mirrorlist lands where pacman.conf already includes it from.
	SITE_REPO_DIR='/etc/pacman.d'
	# pacman.conf includes this path by exact name, so the destination is fixed
	# however the source file is named.
	SITE_REPO_EXT='mirrorlist'
	SITE_REPO_DEST='mirrorlist'
	SITE_CA_DIR='/etc/ca-certificates/trust-source/anchors'
	SITE_CA_UPDATE='trust extract-compat'
	LINTER='namcap'
	LINTCMD='namcap'
	ERRPAT=' E: '
	;;
*) echo "error: unknown format '$FORMAT'" >&2; exit 2 ;;
esac

DEST="$OUT/$TARGET/$HOST_ARCH"
# Start from empty. The lint loop inspects everything in this directory, and it
# is what CI uploads, so a leftover artifact from an earlier version would be
# linted as if current and shipped as if fresh.
rm -rf "$DEST"
mkdir -p "$DEST"

echo ":: building $TARGET ($FORMAT, $IMAGE) on $HOST_ARCH via $ENGINE"

# HOST_ARCH is passed in so the container can prove it is not emulating. With
# binfmt registered, or an arch-specific image reference, a leg could silently
# run under emulation and produce a correct-looking package very slowly -- the
# exact failure this design exists to avoid.
SCRIPT=$(cat <<EOF
set -eu
case "\$(uname -m)" in
x86_64) IN_ARCH=amd64 ;;
aarch64 | arm64) IN_ARCH=arm64 ;;
*) echo "container reports unsupported arch \$(uname -m)" >&2; exit 1 ;;
esac
if [ "\$IN_ARCH" != "$HOST_ARCH" ]; then
	echo "REFUSING: container is \$IN_ARCH but host is $HOST_ARCH -- this build" >&2
	echo "would be emulated. Builds must run natively." >&2
	exit 1
fi

# Site configuration, applied before anything touches the network. Order
# matters: the CA has to be trusted before an HTTPS mirror is contacted, and the
# mirrors have to be in place before the first install.
if [ -d /site ]; then
	# env is sourced, not passed on a command line: a proxy URL may carry
	# credentials, and a command line is visible in ps and in build logs.
	if [ -f /site/env ]; then
		echo ":: site: sourcing /site/env"
		. /site/env
		export \$(sed -n 's/^[[:space:]]*\\([A-Za-z_][A-Za-z0-9_]*\\)=.*/\\1/p' /site/env) 2>/dev/null || true
	fi
	if [ -d /site/ca ] && ls /site/ca/*.crt >/dev/null 2>&1; then
		echo ":: site: installing CA anchors into $SITE_CA_DIR"
		mkdir -p "$SITE_CA_DIR" && cp /site/ca/*.crt "$SITE_CA_DIR/"
		$SITE_CA_UPDATE >/dev/null 2>&1 || echo "note: $SITE_CA_UPDATE failed or is unavailable" >&2
	fi
	# Exactly one repository file, chosen by target id -- rhel9.repo for the
	# rhel9 target, fedora.repo for fedora -- so ONE site directory can carry
	# configuration for every distribution without them colliding. default.<ext>
	# is the fallback where several targets share a mirror (an RPM baseurl using
	# \$releasever usually serves rhel9 and rhel10 from one file).
	_installed=
	for _name in $TARGET default; do
		[ -n "\$_installed" ] && break
		for _ext in $SITE_REPO_EXT; do
			_src="/site/$FORMAT/\$_name.\$_ext"
			[ -f "\$_src" ] || continue
			# Prefixed, never the bare source name: a target id is often the
			# distribution's own repo filename -- fedora.repo, rocky.repo,
			# ubi.repo all ship in /etc/yum.repos.d -- and copying over one of
			# those deletes the base repository, after which nothing installs
			# and the error names a missing package rather than the cause.
			# Arch is the exception: its destination is fixed, because
			# pacman.conf includes that exact path.
			_dest="${SITE_REPO_DEST:-00-site-\$_name.\$_ext}"
			mkdir -p "$SITE_REPO_DIR"
			cp "\$_src" "$SITE_REPO_DIR/\$_dest"
			echo ":: site: \$_name.\$_ext -> $SITE_REPO_DIR/\$_dest"
			_installed=1
			break
		done
	done
	# A directory with files but no match is a naming mistake, and silence would
	# let the build proceed against unreachable default mirrors and fail later
	# for a reason that looks unrelated.
	if [ -z "\$_installed" ] && [ -d /site/$FORMAT ] && [ -n "\$(ls -A /site/$FORMAT 2>/dev/null)" ]; then
		echo "!! site: /site/$FORMAT has files but none named '$TARGET.<ext>' or 'default.<ext>'" >&2
		echo "!! site: looked for extensions: $SITE_REPO_EXT" >&2
		echo "!! site: found: \$(ls /site/$FORMAT | tr '\\n' ' ')" >&2
	fi
	# The escape hatch, run last so it can override anything above -- disabling
	# the distribution's own unreachable mirrors is the usual reason.
	if [ -x /site/setup.sh ]; then
		echo ":: site: running setup.sh"
		/site/setup.sh || { echo "SITE SETUP FAILED" >&2; exit 1; }
	fi
fi

{ $BOOTSTRAP ; } >/tmp/bootstrap.log 2>&1 || { cat /tmp/bootstrap.log 2>/dev/null; echo "BOOTSTRAP FAILED" >&2; exit 1; }
mkdir -p /work && cp -a /src/. /work/ && cd /work
git config --global --add safe.directory /work 2>/dev/null || true

{ $BUILDDEP ; } >/tmp/builddep.log 2>&1 || { cat /tmp/builddep.log 2>/dev/null; echo "BUILD-DEP RESOLUTION FAILED" >&2; exit 1; }
{ $BUILDCMD ; } >/tmp/build.log 2>&1 || { cat /tmp/build.log 2>/dev/null; echo "BUILD FAILED" >&2; exit 1; }

n=0
for f in $GLOB; do
	[ -e "\$f" ] || continue
	n=\$((n + 1))
	cp "\$f" /out/
done
[ "\$n" -gt 0 ] || { echo "NO ARTIFACTS matched: $GLOB" >&2; exit 1; }
echo ":: produced \$n artifact(s)"

if [ "$LINT" = 1 ]; then
$LINTPRE
	# A linter this distribution does not ship is a coverage gap, not a build
	# failure -- but it must be stated, never implied by a silent pass.
	if ! command -v $LINTER >/dev/null 2>&1; then
		echo "!! LINT UNAVAILABLE: $LINTER is not packaged for this distribution." >&2
		echo "!! The packages were BUILT but NOT LINTED." >&2
		exit 0
	fi
	rc=0
	for f in /out/*; do
		[ -e "\$f" ] || continue
		echo "--- \$(basename "\$f")"
		if $LINTCMD "\$f" >/tmp/lint.out 2>&1; then :; else rc=1; fi
		cat /tmp/lint.out
		if grep -qE '$ERRPAT' /tmp/lint.out; then rc=1; fi
	done
	exit \$rc
fi
EOF
)

# Proxy variables are forwarded by NAME, never by value: `-e VAR` takes the
# value from this process's environment, so a proxy URL carrying credentials
# never appears in a command line, in ps output, or in a build log.
ENV_ARGS=""
for v in http_proxy https_proxy ftp_proxy no_proxy \
         HTTP_PROXY HTTPS_PROXY FTP_PROXY NO_PROXY \
         GOPROXY GOSUMDB GONOSUMDB GOPRIVATE GOFLAGS; do
	eval "val=\${$v:-}"
	[ -n "$val" ] && ENV_ARGS="$ENV_ARGS -e $v"
done

SITE_ARGS=""
[ -n "$SITE" ] && SITE_ARGS="-v $SITE:/site:ro"

# Unquoted on purpose: both are lists of separate arguments, not single words.
# shellcheck disable=SC2086
"$ENGINE" run --rm $ENV_ARGS $SITE_ARGS \
	-v "$REPO":/src:ro -v "$DEST":/out "$IMAGE" sh -c "$SCRIPT"
echo ":: artifacts in $DEST"
ls -1 "$DEST" | sed 's/^/   /'
