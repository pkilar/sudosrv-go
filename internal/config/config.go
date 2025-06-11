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
	Server   ServerConfig   `yaml:"server"`
	Relay    RelayConfig    `yaml:"relay"`
	LocalStorage LocalStorageConfig `yaml:"local_storage"`
}

// ServerConfig holds server-specific settings.
type ServerConfig struct {
	Mode           string `yaml:"mode"` // "local" or "relay"
	ListenAddress  string `yaml:"listen_address"`
	ListenAddressTLS string `yaml:"listen_address_tls"`
	TLSCertFile    string `yaml:"tls_cert_file"`
	TLSKeyFile     string `yaml:"tls_key_file"`
	ServerID       string `yaml:"server_id"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
}

// RelayConfig holds settings for relay mode.
type RelayConfig struct {
	UpstreamHost string `yaml:"upstream_host"`
	UseTLS       bool   `yaml:"use_tls"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// LocalStorageConfig holds settings for local storage mode.
type LocalStorageConfig struct {
	LogDirectory string `yaml:"log_directory"`
}

// LoadConfig reads the configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	config := &Config{
		// Default values
		Server: ServerConfig{
			Mode:        "local",
			ListenAddress: "127.0.0.1:30343",
			ServerID:    "GoSudoLogSrv/1.0",
			IdleTimeout: 10 * time.Minute,
		},
		Relay: RelayConfig{
			ConnectTimeout: 5 * time.Second,
		},
		LocalStorage: LocalStorageConfig{
			LogDirectory: "/var/log/gosudo-io",
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// If config file not found, we can proceed with defaults.
		// For other errors, we should fail.
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
  tls_cert_file: "server.crt" # Required if listen_address_tls is set
  tls_key_file: "server.key"  # Required if listen_address_tls is set
  server_id: "GoSudoLogSrv/1.0"
  idle_timeout: 30m

# Settings for when server.mode is "relay"
relay:
  upstream_host: "10.0.0.1:30344"
  use_tls: true
  connect_timeout: 5s

# Settings for when server.mode is "local"
local_storage:
  log_directory: "/var/log/gosudo-io"

*/
