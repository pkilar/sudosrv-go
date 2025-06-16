# RPM Package for sudosrv

This directory contains all the necessary files to build an RPM package for the sudosrv Go sudo I/O log server.

## Quick Start

```bash
# Build the RPM package
make rpm

# Or run the build script directly
./rpm/build-rpm.sh [version]
```

## Package Contents

- **Binary**: `/usr/bin/sudosrv`
- **Configuration**: `/etc/sudosrv/config.yaml`
- **Systemd Service**: `/usr/lib/systemd/system/sudosrv.service`
- **Log Directory**: `/var/log/sudosrv/` (owned by sudosrv user)
- **Cache Directory**: `/var/spool/sudosrv-cache/` (for relay mode)
- **Logrotate Config**: `/etc/logrotate.d/sudosrv`

## Directory Structure

```
rpm/
├── SPECS/
│   └── sudosrv.spec          # RPM specification file
├── SOURCES/
│   ├── sudosrv.service       # Systemd service file
│   ├── sudosrv.conf          # Default configuration file
│   └── sudosrv.logrotate     # Logrotate configuration
├── BUILD/                    # Build workspace (created during build)
├── RPMS/                     # Generated binary RPMs
├── SRPMS/                    # Generated source RPMs
├── build-rpm.sh              # Build script
└── README.md                 # This file
```

## Building the RPM

### Prerequisites

- `rpmbuild` and `rpmdevtools` packages
- Go 1.22 or newer
- `protoc` (Protocol Buffer compiler)
- `make`

### Installation on RHEL/CentOS/Fedora:
```bash
sudo dnf install rpm-build rpmdevtools golang protobuf-compiler make
```

### Installation on Ubuntu/Debian:
```bash
sudo apt install rpm golang-go protobuf-compiler make
```

### Build Process

1. Run the build script:
   ```bash
   ./rpm/build-rpm.sh [version]
   ```

2. Or use the Makefile target:
   ```bash
   make rpm
   ```

The script will:
1. Create a source tarball
2. Build the RPM using `rpmbuild`
3. Generate both binary and source RPMs

## Installing the RPM

```bash
# Install the generated RPM
sudo rpm -ivh rpm/RPMS/x86_64/sudosrv-*.rpm

# Or using dnf/yum
sudo dnf install rpm/RPMS/x86_64/sudosrv-*.rpm
```

## Post-Installation

1. **Edit the configuration file**: `/etc/sudosrv/config.yaml`
2. **Start the service**: `sudo systemctl start sudosrv`
3. **Enable auto-start**: `sudo systemctl enable sudosrv`
4. **Check status**: `sudo systemctl status sudosrv`

## Service Management

The RPM creates a dedicated `sudosrv` user and group for running the service securely.

```bash
# Start the service
sudo systemctl start sudosrv

# Stop the service
sudo systemctl stop sudosrv

# Restart the service
sudo systemctl restart sudosrv

# Check service status
sudo systemctl status sudosrv

# View logs
sudo journalctl -u sudosrv -f
```

## Configuration

The default configuration is installed at `/etc/sudosrv/config.yaml`. This file is marked as `%config(noreplace)` in the RPM spec, so it won't be overwritten during package updates.

## Log Management

- Application logs are stored in `/var/log/sudosrv/`
- Logrotate is configured to rotate logs daily, keeping 30 days of history
- Relay cache logs (if using relay mode) are rotated weekly