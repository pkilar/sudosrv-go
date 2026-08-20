%define debug_package %{nil}

Name:           sudosrv
# Injected by build-rpm.sh from the top-level VERSION file. The fallback
# keeps a bare `rpmbuild -bs` parsable; it is deliberately an obviously
# wrong number rather than a plausible one, so a package built without the
# script cannot be mistaken for a release.
Version:        %{?rpm_version}%{!?rpm_version:0.0.0}
Release:        1%{?dist}
Summary:        Go-based sudo I/O log server

License:        Apache-2.0
URL:            https://github.com/example/sudosrv
Source0:        %{name}-%{version}.tar.gz
# The shared sysusers and tmpfiles files, staged into SOURCES by build-rpm.sh.
# They are separate Sources rather than paths inside the tarball because
# %%sysusers_create_compat embeds the file's CONTENT at build time and needs a
# path that resolves while the spec is being parsed.
Source1:        sudosrv.sysusers
Source2:        sudosrv.tmpfiles

# The module needs Go 1.27, which no current Fedora ships -- F43 has
# 1.25.12. Declaring >= 1.26 made the package unbuildable there rather than
# merely inconvenient. The floor below is the version that understands
# GOTOOLCHAIN, and %%build sets GOTOOLCHAIN=auto so the distro's Go fetches
# the required toolchain. That needs network access at build time: a sealed
# builder (mock without --enable-network, koji) must vendor a toolchain.
BuildRequires:  golang >= 1.21
BuildRequires:  make
BuildRequires:  protobuf-compiler
BuildRequires:  systemd-rpm-macros
Requires:       sudo >= 1.9.0
# /bin/kill, used by the unit's ExecReload. Not present in every minimal
# image, and without it `systemctl reload sudosrv` -- the documented way to
# apply a new TLS certificate without dropping connections -- fails.
Requires:       util-linux
# Fedora's RPM generates "Requires: user(sudosrv)" and "group(sudosrv)" from the
# %%attr(...,sudosrv,sudosrv) entries in %%files. Nothing provided them, so the
# package could not be installed at all -- dnf refused the transaction with
# "nothing provides user(sudosrv)". Shipping the sysusers.d file is what
# generates the matching Provides, as well as being how the account gets made.
%{?sysusers_requires_compat}
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
A high-performance, standalone I/O log server for sudo, written in Go. 
It is designed to be a fully compatible alternative to sudo's native 
sudo_logsrvd, capable of receiving and processing detailed I/O logs 
from any sudo client (version 1.9.0 and newer).

%package -n logsh
Summary:        Recording login shell for sudo I/O log servers
# logsh-install.sh drives every install and removal step, so what IT needs is a
# hard runtime requirement of this package: awk and grep as well as coreutils.
# coreutils alone was wrong -- on a minimal image without gawk the %%post would
# fail and the symlinks would never be created.
Requires:       coreutils
Requires:       gawk
Requires:       grep
Requires:       /bin/sh
Recommends:     sudosrv

%description -n logsh
logsh is a multi-call login shell that records a user's terminal session to a
sudosrv log server, in the same sudoreplay-compatible format sudo produces.
/usr/sbin/lbash and /usr/sbin/lzsh are symlinks to it; the name it is invoked
under selects the real shell to run.

It belongs on every managed host, whereas the sudosrv daemon usually does not,
which is why it is a separate package. Installing it switches no account: see
%{_docdir}/logsh/logsh-deployment.md for the rollout and the mandatory
break-glass drill before deploying anywhere you cannot walk up to.

%prep
%setup -q

%build
# See the BuildRequires comment: the distro toolchain bootstraps the one this
# module actually needs.
export GOTOOLCHAIN=auto

# Generate protobuf code and resolve dependencies
make deps

# Built with the same flags as the other two formats rather than via `make
# build`, which leaves the binary unstripped (rpmlint: unstripped-binary-or-object)
# and diverges from what debian/rules and the PKGBUILD produce. CGO stays off
# throughout; see the logsh comment below.
export CGO_ENABLED=0
# -X stamps the version this package is being built as, so `-version` and
# `rpm -q` cannot disagree.
go build -ldflags="-s -w -X main.appVersion=%{version}" -o sudosrv ./cmd/sudosrv
go build -trimpath -ldflags="-s -w -X main.appVersion=%{version}" -o logsh ./cmd/logsh

%install
# Install the binary
install -d %{buildroot}%{_bindir}
install -m 0755 sudosrv %{buildroot}%{_bindir}/sudosrv

# Install configuration file
install -d %{buildroot}%{_sysconfdir}/sudosrv
install -m 0644 packaging/config/sudosrv.yaml %{buildroot}%{_sysconfdir}/sudosrv/config.yaml

# Install systemd service file
install -d %{buildroot}%{_unitdir}
install -m 0644 packaging/systemd/sudosrv.service %{buildroot}%{_unitdir}/sudosrv.service

# Install logrotate configuration
install -d %{buildroot}%{_sysconfdir}/logrotate.d
install -m 0644 packaging/logrotate/sudosrv.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/sudosrv

# Create directories for logs and cache
install -d %{buildroot}%{_localstatedir}/log/sudosrv
install -d %{buildroot}%{_localstatedir}/spool/sudosrv-cache

# Manual pages. The unit has always carried Documentation=man:sudosrv(8);
# until now nothing shipped one, so `systemd-analyze verify` reported the
# reference as broken and rpmlint reported no-manual-page.
install -D -m 0644 packaging/man/sudosrv.8 %{buildroot}%{_mandir}/man8/sudosrv.8

# Service account and state directories, from the same shared files Debian and
# Arch install. This replaces a hand-written groupadd/useradd in %%pre.
install -D -m 0644 %{SOURCE1} %{buildroot}%{_sysusersdir}/sudosrv.conf
install -D -m 0644 %{SOURCE2} %{buildroot}%{_tmpfilesdir}/sudosrv.conf

# --- logsh ------------------------------------------------------------------
# logsh is a login shell, so a dynamic linker that cannot resolve it prevents
# login rather than degrading it -- hence CGO_ENABLED=0 above.
install -D -m 0755 logsh %{buildroot}%{_sbindir}/logsh
install -D -m 0755 packaging/logsh/logsh-install.sh \
    %{buildroot}%{_libexecdir}/logsh/logsh-install.sh
# 0644, not 0600: logsh runs as the logging-in user and must be able to read it.
install -D -m 0644 examples/logsh.yaml %{buildroot}%{_sysconfdir}/logsh/logsh.yaml
install -D -m 0644 docs/logsh-deployment.md \
    %{buildroot}%{_docdir}/logsh/logsh-deployment.md
install -D -m 0644 packaging/man/logsh.8 %{buildroot}%{_mandir}/man8/logsh.8

%pre
# Creates the account from the shared sysusers file, falling back to useradd on
# systems without systemd-sysusers. The hand-written groupadd/useradd this
# replaces produced the same account but generated no Provides, which is what
# made the package uninstallable.
%sysusers_create_compat %{SOURCE1}

%post
# Enable and start the service
%systemd_post sudosrv.service
# %%tmpfiles_create, not %%tmpfiles_create_compat -- the latter does not exist.
# An undefined RPM macro is left verbatim, so the scriptlet ran "%%tmpfiles_..."
# as a shell job spec and died with "fg: no job control", failing the whole
# transaction after the files were already unpacked.
%tmpfiles_create %{SOURCE2}

%preun
# Stop and disable the service
%systemd_preun sudosrv.service

%postun
# Clean up after service removal
%systemd_postun_with_restart sudosrv.service

%post -n logsh
# Put the machinery in place and switch NOBODY. A package that enabled itself
# would turn the first bad config into a fleet-wide lockout at upgrade time.
# Runs on install ($1 == 1) and upgrade ($1 == 2) alike; both are idempotent.
%{_libexecdir}/logsh/logsh-install.sh install
if ! %{_libexecdir}/logsh/logsh-install.sh verify; then
    echo "logsh: verification FAILED -- do not enable any account until this is fixed." >&2
fi
exit 0

%preun -n logsh
# $1 == 0 is the final removal; 1 means an upgrade is replacing this version.
#
# Restoring accounts on upgrade would silently disable recording on every
# package update, so it is guarded. And this must be %%preun, not %%postun: by
# postun the binary and symlinks are gone, and any account still pointing at
# /usr/sbin/lbash has a login shell that does not exist.
if [ "$1" = 0 ]; then
    if ! %{_libexecdir}/logsh/logsh-install.sh uninstall; then
        echo "logsh: FAILED to restore account shells; check /etc/passwd for" >&2
        echo "logsh: accounts still pointing at %{_sbindir}/l*" >&2
        exit 1
    fi
fi
exit 0

%files -n logsh
%{_sbindir}/logsh
%dir %{_libexecdir}/logsh
%{_libexecdir}/logsh/logsh-install.sh
%dir %{_sysconfdir}/logsh
%config(noreplace) %{_sysconfdir}/logsh/logsh.yaml
%dir %{_docdir}/logsh
%doc %{_docdir}/logsh/logsh-deployment.md
%{_mandir}/man8/logsh.8*

%files
%{_bindir}/sudosrv
%config(noreplace) %{_sysconfdir}/sudosrv/config.yaml
%{_unitdir}/sudosrv.service
%{_sysusersdir}/sudosrv.conf
%{_tmpfilesdir}/sudosrv.conf
%{_mandir}/man8/sudosrv.8*
%config(noreplace) %{_sysconfdir}/logrotate.d/sudosrv
%dir %attr(0700,sudosrv,sudosrv) %{_localstatedir}/log/sudosrv
%dir %attr(0700,sudosrv,sudosrv) %{_localstatedir}/spool/sudosrv-cache

%changelog
* Tue Aug 19 2026 Paul Kilar <pkilar@gmail.com> - 0.2.0-1
- logsh records standalone with -record, writing a sudoreplay-compatible I/O
  log locally and contacting no server; -wire additionally keeps the raw stream
- New wiredump command for decoding a journal or relay cache file
- Fix: terminal I/O was throttled to 100 messages/sec, which distorted recorded
  timings and delayed logout
- Fix: the legacy log file dropped the command's arguments and left lines and
  columns empty for a tty-less client
- Fix: a session from a terminal reporting no size recorded as 0x0, which
  sudoreplay refuses silently
- Sessions now carry source, runenv and submitenv, matching what C writes
- Both binaries report the version they were built as; it is no longer a
  literal in the source that drifts from the VERSION file
- The ldash multi-call name is retired; accounts already using it are restored
  on removal

* Mon Aug 17 2026 Paul Kilar <pkilar@gmail.com> - 0.1.0-1
- Install shared assets from packaging/ rather than per-format copies
- Ship manual pages for sudosrv(8) and logsh(8)
- Require util-linux for the unit's ExecReload
- Derive Version from the top-level VERSION file

* Sun Jun 15 2025 Paul Kilar <pkilar@gmail.com> - 0.1.0-1
- Initial RPM package for sudosrv
- Added systemd service integration
- Added logrotate configuration
- Created dedicated user account for service
