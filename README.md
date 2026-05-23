# Go Sudo I/O Log Server

[![CI][ci-badge]][ci] [![Go Report Card][go-reportcard-badge]][go-reportcard] [![Go Reference][pkg.go.dev-badge]][pkg.go.dev] [![License: Apache 2.0][license-badge]][license]

A high-performance, standalone I/O log server for sudo, written in Go. It is a fully compatible alternative to sudo's native `sudo_logsrvd`, capable of receiving and processing I/O logs from any sudo client (version 1.9.0+).

The server captures complete transcripts of user sessions run via sudo, including all terminal input and output, providing a tool for security auditing, forensic analysis, and troubleshooting.

## Features

- **Protocol Compatibility**: Implements the `sudo_logsrv.proto` protocol buffer specification used by sudo for remote logging.
- **Dual-Mode Operation**:
  - **Local Storage Mode**: Saves I/O logs to the local filesystem in a format **100% compatible with `sudoreplay`**.
  - **Relay Mode**: Forwards logs to an upstream `sudo_logsrvd` or compatible server with **store-and-forward caching** and exponential backoff reconnection to handle network interruptions without data loss.
- **Full Escape Sequence Support**: Implements all standard sudoers escape sequences for log path customization (`%{user}`, `%{seq}`, `%{epoch}`, `%{command}`, etc.).
- **Password Filtering**: Automatically masks password input in captured sessions (enabled by default).
- **Secure Communication**: Supports TLS for encrypting log streams in transit. Dual TCP/TLS listeners can run simultaneously.
- **Packaging**: Debian (`.deb`), RPM, and Arch Linux packages with systemd service units included.
- **Cross-Platform Binaries**: Stripped and statically linked binaries for `linux/amd64` and `linux/arm64`.
- **Configurable**: All settings managed through a `config.yaml` file.

## Getting Started

### Prerequisites

- Go 1.26+
- Protocol Buffer Compiler (`protoc`) and `protoc-gen-go`
- `make`

### Building

```bash
# Build for local architecture (auto-runs proto generation + go mod tidy)
make build

# Build stripped release binary
make build-release

# Cross-compile release binaries (linux-amd64 + linux-arm64)
make release-all

# Build statically linked binaries (CGO_ENABLED=0)
make release-static-all
```

### Running Tests

```bash
make test
```

### Running the Server

1. Copy `config-example.yaml` to `config.yaml` and edit to suit your environment.
2. Run:

```bash
make run
```

Or specify a config file path:

```bash
make run CONFIG=/etc/sudosrv/config.yaml
```

### CLI Flags

```
-config=<path>       Path to configuration file (default: config.yaml)
-log-level=<level>   Log level: debug, info, warn, error
-version             Print version and exit
-help                Print usage and exit
-dry-run             Validate configuration and exit without starting
-validate            Validate configuration file
```

**Exit codes**: `0` success, `1` general failure, `2` configuration error, `3` server error

## Configuration

Example `config.yaml`:

```yaml
server:
  mode: "local"                    # "local" or "relay"
  listen_address: "0.0.0.0:30343"
  # listen_address_tls: "0.0.0.0:30344"
  # tls_cert_file: "server.crt"
  # tls_key_file: "server.key"
  idle_timeout: 30m
  server_operational_log_level: "info"

# Settings for when server.mode is "local"
local_storage:
  log_directory: "/var/log/gosudo-io"
  # iolog_dir: "%{LIVEDIR}/%{user}"
  # iolog_file: "%{seq}"
  # dir_permissions: 0750
  # file_permissions: 0640
  # compress: false
  # password_filter: true

# Settings for when server.mode is "relay"
relay:
  upstream_host: "127.0.0.1:30344"
  use_tls: false
  connect_timeout: 15s
  relay_cache_directory: "/var/log/gosudo-relay-cache"
  reconnect_attempts: -1           # -1 = infinite
  # max_reconnect_interval: 1m

# Optional read-only management API. Omit the block (or leave listen_address
# empty) to disable. See "Management API" below for endpoint details.
# api:
#   listen_address: "127.0.0.1:30345"
#   auth_token_file: "/etc/sudosrv/api.token"
#   # tls_cert_file: "api.crt"
#   # tls_key_file:  "api.key"
```

### Supported Escape Sequences

For `iolog_dir` and `iolog_file`:

| Category | Sequences |
|----------|-----------|
| User | `%{user}`, `%{uid}`, `%{group}`, `%{gid}` |
| RunAs | `%{runuser}`, `%{runuid}`, `%{rungroup}`, `%{rungid}` |
| Host/Command | `%{hostname}`, `%{command}`, `%{command_path}` |
| Time | `%{year}`, `%{month}`, `%{day}`, `%{hour}`, `%{minute}`, `%{second}`, `%{epoch}` |
| Generated | `%{seq}`, `%{rand}`, `%{LIVEDIR}`, `%%` |

## Management API

An optional read-only HTTP+JSON API exposes currently active sessions for
operational visibility. The API is **disabled by default** — set
`api.listen_address` to enable it.

### Configuration

```yaml
api:
  listen_address: "127.0.0.1:30345"        # empty disables the API
  auth_token_file: "/etc/sudosrv/api.token" # preferred over inline auth_token
  # auth_token: "raw-token"                 # alternative; inline (discouraged)
  # tls_cert_file: "api.crt"                # optional TLS for the listener
  # tls_key_file:  "api.key"
```

The bearer token is loaded once at startup; rotating it requires a restart.
Bind to localhost unless TLS and a strong token are in place.

### Endpoints

Both endpoints require an `Authorization: Bearer <token>` header.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/sessions` | Summary list of active sessions, newest first. |
| GET | `/api/v1/sessions/{id}` | Full metadata for one session, looked up by `session_id` (UUID) or `server_log_id` (base64). URL-escape the segment when using `server_log_id` because it may contain `/`. |

### Example

```bash
TOKEN=$(cat /etc/sudosrv/api.token)

# List active sessions
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:30345/api/v1/sessions

# Inspect one session
curl -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:30345/api/v1/sessions/fb8f1722-2cdc-45e6-967f-22e39b2b465b
```

The detail response includes a `live` block with running counters
(`messages_received`, `bytes_received`, `last_activity`) and mode-specific
fields (`session_dir` for local mode; `cache_file` and `phase` —
`writing`/`flushing` — for relay mode).

Errors are returned as `{"error": "..."}` with `401` for missing or invalid
tokens and `404` for unknown session IDs.

## Packaging

```bash
make deb    # Debian package (requires dpkg-buildpackage)
make rpm    # RPM package
make arch   # Arch Linux package (requires makepkg)
```

All packages include a systemd service unit, logrotate configuration, and sane defaults.

## Client Configuration (sudoers)

To configure a sudo client to send I/O logs to this server, edit `/etc/sudoers` using `visudo`:

```
# Enable I/O logging for all commands
Defaults log_input, log_output

# Send logs to your server instance
Defaults log_servers="your-server-hostname:30344(tls)"

# If using a self-signed or private CA for the server's TLS cert
Defaults log_server_cabundle=/etc/sudo/ca.pem
```

## Project Structure

```
cmd/sudosrv/         Entry point — flag parsing, config, signal handling
internal/
  config/            YAML configuration with defaults
  connection/        Protocol state machine & rate limiting
  protocol/          Length-prefixed protobuf message marshaling
  server/            Dual TCP/TLS listener management
  storage/           sudoreplay-compatible local log storage
  relay/             Store-and-forward relay with reconnection
  metrics/           Atomic connection/session/error counters
pkg/sudosrv_proto/   Generated protobuf definitions
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

[ci-badge]: https://github.com/pkilar/sudosrv-go/actions/workflows/makefile.yml/badge.svg
[ci]: https://github.com/pkilar/sudosrv-go/actions/workflows/makefile.yml
[go-reportcard-badge]: https://goreportcard.com/badge/github.com/pkilar/sudosrv-go
[go-reportcard]: https://goreportcard.com/report/github.com/pkilar/sudosrv-go
[pkg.go.dev-badge]: https://pkg.go.dev/badge/github.com/pkilar/sudosrv-go.svg
[pkg.go.dev]: https://pkg.go.dev/github.com/pkilar/sudosrv-go
[license-badge]: https://img.shields.io/badge/License-Apache_2.0-blue.svg
[license]: LICENSE
