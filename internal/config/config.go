// Filename: internal/config/config.go
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the application's configuration.
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Relay        RelayConfig        `yaml:"relay"`
	LocalStorage LocalStorageConfig `yaml:"local_storage"`
}

// ServerConfig holds server-specific settings.
type ServerConfig struct {
	Mode                      string        `yaml:"mode"` // "local" or "relay"
	ListenAddress             string        `yaml:"listen_address"`
	ListenAddressTLS          string        `yaml:"listen_address_tls"`
	TLSCertFile               string        `yaml:"tls_cert_file"`
	TLSKeyFile                string        `yaml:"tls_key_file"`
	ServerID                  string        `yaml:"server_id"`
	IdleTimeout               time.Duration `yaml:"idle_timeout"`
	ServerOperationalLogLevel string        `yaml:"server_operational_log_level"` // e.g., "debug", "info", "warn", "error"
}

// RelayConfig holds settings for relay mode.
type RelayConfig struct {
	UpstreamHost         string        `yaml:"upstream_host"`
	UseTLS               bool          `yaml:"use_tls"`
	TLSSkipVerify        bool          `yaml:"tls_skip_verify"`
	ConnectTimeout       time.Duration `yaml:"connect_timeout"`
	RelayCacheDirectory  string        `yaml:"relay_cache_directory"`
	ReconnectAttempts    int           `yaml:"reconnect_attempts"`
	MaxReconnectInterval time.Duration `yaml:"max_reconnect_interval"`
}

// LocalStorageConfig holds settings for local storage mode.
type LocalStorageConfig struct {
	LogDirectory string `yaml:"log_directory"` // Base directory, used if iolog_dir is not set
	IologDir     string `yaml:"iolog_dir"`     // sudoers-style I/O log directory path
	IologFile    string `yaml:"iolog_file"`    // sudoers-style I/O log session file name
}

// LoadConfig reads the configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	config := &Config{
		// Default values
		Server: ServerConfig{
			Mode:                      "local",
			ListenAddress:             "127.0.0.1:30343",
			ServerID:                  "GoSudoLogSrv/1.0",
			IdleTimeout:               10 * time.Minute,
			ServerOperationalLogLevel: "info", // Default log level
		},
		Relay: RelayConfig{
			ConnectTimeout:       5 * time.Second,
			RelayCacheDirectory:  "/var/log/gosudo-relay-cache",
			ReconnectAttempts:    -1, // Default to trying forever
			MaxReconnectInterval: 1 * time.Minute,
			TLSSkipVerify:        false, // Default to secure TLS verification
		},
		LocalStorage: LocalStorageConfig{
			LogDirectory: "/var/log/gosudo-io",
			IologDir:     "%{LIVEDIR}/%{user}", // Default sudoers-style path
			IologFile:    "%{seq}",             // Default sudoers-style file name
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Warning: Config file not found at %s. Using default values.\n", path)
			return config, nil
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config YAML: %w", err)
	}

	return config, nil
}

// Create an example config file if it doesn't exist
// Filename: config.yaml
/*
server:
  mode: "local"  # or "relay"
  listen_address: "0.0.0.0:30343"
  listen_address_tls: "0.0.0.0:30344"
  tls_cert_file: "server.crt"
  tls_key_file: "server.key"
  server_id: "GoSudoLogSrv/1.0"
  idle_timeout: 30m
  server_operational_log_level: "debug" # Supported levels: debug, info, warn, error

# Settings for when server.mode is "relay"
relay:
  upstream_host: "127.0.0.1:30343"
  use_tls: false
  tls_skip_verify: false  # Set to true only for testing with self-signed certs
  connect_timeout: 5s
  relay_cache_directory: "/var/spool/sudosrv-cache"
  reconnect_attempts: -1  # Number of retries, -1 for infinite
  max_reconnect_interval: "2m" # Maximum time to wait between retries

# Settings for when server.mode is "local"
local_storage:
  # Base directory used for the %{LIVEDIR} escape and the sequence file.
  log_directory: "/var/log/gosudo-io"

  # Directory path for session logs, with support for sudoers-style escape sequences.
  # If specified, this overrides the simpler default behavior.
  # Supported escapes:
  #   User: %{user}, %{uid}, %{group}, %{gid}
  #   RunAs User: %{runuser}, %{runuid}, %{rungroup}, %{rungid}
  #   Host/Command: %{hostname}, %{command} (basename), %{command_path} (full path)
  #   Date/Time: %{year}, %{month}, %{day}, %{hour}, %{minute}, %{second}, %{epoch}
  #   Misc: %{seq}, %{rand}, %{LIVEDIR}, %% (literal %)
  iolog_dir: "%{LIVEDIR}/%{year}-%{month}/%{user}"

  # File name for the session log directory, with support for the same escapes.
  iolog_file: "%{epoch}-%{rand}-%{command}"

*/
