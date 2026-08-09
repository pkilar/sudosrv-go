%define debug_package %{nil}

Name:           sudosrv
Version:        %{_version}
Release:        1%{?dist}
Summary:        Go-based sudo I/O log server

License:        MIT
URL:            https://github.com/example/sudosrv
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.26
BuildRequires:  make
BuildRequires:  protobuf-compiler
BuildRequires:  systemd-rpm-macros
Requires:       sudo >= 1.9.0
Requires(pre):  shadow-utils
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
Requires:       coreutils
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
# Generate protobuf code and build dependencies
make deps

# Build the binary for the target architecture
make build

%install
# Install the binary
install -d %{buildroot}%{_bindir}
install -m 0755 sudosrv %{buildroot}%{_bindir}/sudosrv

# Install configuration file
install -d %{buildroot}%{_sysconfdir}/sudosrv
install -m 0644 rpm/sudosrv.conf %{buildroot}%{_sysconfdir}/sudosrv/config.yaml

# Install systemd service file
install -d %{buildroot}%{_unitdir}
install -m 0644 rpm/sudosrv.service %{buildroot}%{_unitdir}/sudosrv.service

# Install logrotate configuration
install -d %{buildroot}%{_sysconfdir}/logrotate.d
install -m 0644 rpm/sudosrv.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/sudosrv

# Create directories for logs and cache
install -d %{buildroot}%{_localstatedir}/log/sudosrv
install -d %{buildroot}%{_localstatedir}/spool/sudosrv-cache

# Create man page directory (placeholder for future documentation)
install -d %{buildroot}%{_mandir}/man8

# --- logsh ------------------------------------------------------------------
# Always CGO-free: logsh is a login shell, so a dynamic linker that cannot
# resolve it prevents login rather than degrading it.
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o logsh ./cmd/logsh
install -D -m 0755 logsh %{buildroot}%{_sbindir}/logsh
install -D -m 0755 packaging/logsh/logsh-install.sh \
    %{buildroot}%{_libexecdir}/logsh/logsh-install.sh
# 0644, not 0600: logsh runs as the logging-in user and must be able to read it.
install -D -m 0644 examples/logsh.yaml %{buildroot}%{_sysconfdir}/logsh/logsh.yaml
install -D -m 0644 docs/logsh-deployment.md \
    %{buildroot}%{_docdir}/logsh/logsh-deployment.md

%pre
# Create sudosrv user and group
getent group sudosrv >/dev/null || groupadd -r sudosrv
getent passwd sudosrv >/dev/null || \
    useradd -r -g sudosrv -d %{_localstatedir}/lib/sudosrv -s /sbin/nologin \
    -c "sudo I/O log server" sudosrv
exit 0

%post
# Enable and start the service
%systemd_post sudosrv.service

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
# package update, so it is guarded. And this must be %preun, not %postun: by
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

%files
%{_bindir}/sudosrv
%config(noreplace) %{_sysconfdir}/sudosrv/config.yaml
%{_unitdir}/sudosrv.service
%config(noreplace) %{_sysconfdir}/logrotate.d/sudosrv
%dir %attr(0700,sudosrv,sudosrv) %{_localstatedir}/log/sudosrv
%dir %attr(0700,sudosrv,sudosrv) %{_localstatedir}/spool/sudosrv-cache

%changelog
* Sun Jun 15 2025 Paul Kilar <pkilar@gmail.com> - 0.1.0-1
- Initial RPM package for sudosrv
- Added systemd service integration
- Added logrotate configuration
- Created dedicated user account for service
