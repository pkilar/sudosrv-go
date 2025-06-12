# **Go Sudo I/O Log Server**

This project is a high-performance, standalone I/O log server for sudo, written in Go. It is designed to be a fully compatible alternative to sudo's native `sudo_logsrvd`, capable of receiving and processing detailed I/O logs from any sudo client (version 1.9.0 and newer).

The server captures a complete transcript of user sessions run via sudo, including all terminal input and output, providing a powerful tool for security auditing, forensic analysis, and troubleshooting.

## **Features**

* **Protocol Compatibility**: Fully implements the `sudo_logsrv.proto` protocol buffer specification used by sudo for remote logging.
* **Advanced Local Storage**: Saves I/O logs in a format fully compatible with the standard `sudoreplay` utility. It supports highly flexible log path and filename customization through `iolog_dir` and `iolog_file` directives in its configuration, mirroring sudoers functionality.
* **Resilient Relay Mode**: Acts as a forwarding agent to an upstream log server. Includes a robust store-and-forward caching mechanism, saving logs locally if the upstream server is unavailable and automatically flushing the cache upon reconnection. This prevents data loss during network outages.
* **Full Escape Sequence Support**: Implements all standard sudoers escape sequences for log path customization, including user (`%{user}`), time (`%{year}`, `%{epoch}`), command (`%{command}`), and generated (`%{seq}`, `%{rand}`) variables.
* **Dual-Mode Operation**:
  * **Local Storage Mode**: Saves I/O logs to the local filesystem in a directory structure and format that is **100% compatible with the standard sudoreplay utility**.
  * **Relay Mode**: Acts as a forwarding agent, relaying logs to another upstream sudo\_logsrvd or compatible server. Includes a **resilient reconnect mechanism** with exponential backoff to handle temporary network interruptions with the upstream server.
* **Secure Communication**: Supports TLS for encrypting the log stream, ensuring that sensitive session data is protected in transit.
* **Cross-Platform Binaries**: The included Makefile can produce stripped and statically linked binaries for `linux/amd64` and `linux/arm64` architectures, making deployment simple and portable.
* **Configurable**: All major settings are managed through a clean `config.yaml` file.

## **Getting Started**

### **Prerequisites**

* Go (version 1.22 or newer)
* Protocol Buffer Compiler (protoc)
* make

### **Building the Server**

A comprehensive Makefile handles all common tasks.

1. **Generate Protobuf Code & Tidy Dependencies**:
```
make deps
```

2. **Build the Binary**:
   * For your local architecture:
```
make build
```

   * To build stripped, cross-compiled release binaries:
```
make release-all
```

   * To build statically linked binaries:
```
make release-static-all
```

### **Running Tests**

To run all unit tests for the project:
```
make test
```

### **Running the Server**

1. Create a config.yaml file from the example in internal/config/config.go.
2. Run the server:
```
make run
```

   Or specify a config file path:
```
make run CONFIG=/etc/sudosrv/config.yaml
```

## **Client Configuration (sudoers)**

To configure a sudo client to send its I/O logs to this server, edit /etc/sudoers using visudo:
```
# Enable I/O logging for all commands
Defaults log_input, log_output

# Send logs to your Go server instance
Defaults log_servers="your-server-hostname:30344(tls)"

# If using a self-signed or private CA for the server's TLS cert
Defaults log_server_cabundle=/etc/sudo/ca.pem
```
