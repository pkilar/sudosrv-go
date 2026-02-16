%define debug_package %{nil}

Name:           sudosrv
Version:        %{_version}
Release:        1%{?dist}
Summary:        Go-based sudo I/O log server

License:        MIT
URL:            https://github.com/example/sudosrv
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.25
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
