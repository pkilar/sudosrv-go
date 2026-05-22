// SPDX-License-Identifier: Apache-2.0
// Filename: internal/config/config.go
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the application's configuration.
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Relay        RelayConfig        `yaml:"relay"`
	LocalStorage LocalStorageConfig `yaml:"local_storage"`
	API          APIConfig          `yaml:"api"`
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
	MaxConnections            int           `yaml:"max_connections"`              // 0 disables the cap
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

// APIConfig holds settings for the optional management HTTP API. An empty
// ListenAddress disables the API entirely.
//
// Authentication is required when the API is enabled: AuthTokenFile (preferred)
// points at a file whose contents are the bearer token; AuthToken (discouraged
// in production) provides the token inline. If both are set, AuthTokenFile
// wins. Whitespace surrounding a file's contents is trimmed at load time.
//
// TLS is optional. When TLSCertFile and TLSKeyFile are set, the API listener
// terminates TLS using those credentials; otherwise it serves plaintext HTTP
// (intended for localhost-only deployments).
type APIConfig struct {
	ListenAddress string `yaml:"listen_address"`  // empty disables the API
	AuthToken     string `yaml:"auth_token"`      // inline (discouraged)
	AuthTokenFile string `yaml:"auth_token_file"` // path to file containing the token (preferred)
	TLSCertFile   string `yaml:"tls_cert_file"`
	TLSKeyFile    string `yaml:"tls_key_file"`
}

// LocalStorageConfig holds settings for local storage mode.
type LocalStorageConfig struct {
	LogDirectory    string `yaml:"log_directory"`    // Base directory, used if iolog_dir is not set
	IologDir        string `yaml:"iolog_dir"`        // sudoers-style I/O log directory path
	IologFile       string `yaml:"iolog_file"`       // sudoers-style I/O log session file name
	DirPermissions  uint32 `yaml:"dir_permissions"`  // Directory permissions (octal, e.g., 0750)
	FilePermissions uint32 `yaml:"file_permissions"` // File permissions (octal, e.g., 0640)
	Compress        bool   `yaml:"compress"`         // Enable gzip compression for I/O log files
	PasswordFilter  bool   `yaml:"password_filter"`  // Enable regex-based password filtering
}

// LoadConfig reads the configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	config := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("Config file not found, using defaults", "path", path)
			return config, nil
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if err := unmarshalConfig(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// LoadConfigRequired reads the configuration from a YAML file and fails if the
// file is missing. This is used for SIGHUP reloads so a transient deployment
// mistake cannot silently replace the running config with defaults.
func LoadConfigRequired(path string) (*Config, error) {
	config := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if err := unmarshalConfig(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

func defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Mode:                      "local",
			ListenAddress:             "127.0.0.1:30343",
			ServerID:                  "GoSudoLogSrv/1.0",
			IdleTimeout:               10 * time.Minute,
			MaxConnections:            10000,
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
			LogDirectory:    "/var/log/gosudo-io",
			IologDir:        "%{LIVEDIR}/%{user}", // Default sudoers-style path
			IologFile:       "%{seq}",             // Default sudoers-style file name
			DirPermissions:  0750,                 // Default directory permissions
			FilePermissions: 0640,                 // Default file permissions
			Compress:        false,                // Compression disabled by default for compatibility
			PasswordFilter:  true,                 // Password filtering enabled by default for security
		},
	}
}

func unmarshalConfig(data []byte, config *Config) error {
	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to unmarshal config YAML: %w", err)
	}

	// Re-apply defaults for zero-valued fields that yaml may have cleared
	// when a section is partially specified in the config file.
	applyZeroValueDefaults(config)

	return nil
}

// applyZeroValueDefaults restores default values for fields that yaml.Unmarshal
// may have zeroed when a section was partially specified.
func applyZeroValueDefaults(cfg *Config) {
	if cfg.Server.IdleTimeout == 0 {
		cfg.Server.IdleTimeout = 10 * time.Minute
	}
	if cfg.Server.MaxConnections < 0 {
		cfg.Server.MaxConnections = 0
	}
	if cfg.LocalStorage.DirPermissions == 0 {
		cfg.LocalStorage.DirPermissions = 0750
	}
	if cfg.LocalStorage.FilePermissions == 0 {
		cfg.LocalStorage.FilePermissions = 0640
	}
	if cfg.Relay.ConnectTimeout == 0 {
		cfg.Relay.ConnectTimeout = 5 * time.Second
	}
	if cfg.Relay.MaxReconnectInterval == 0 {
		cfg.Relay.MaxReconnectInterval = 1 * time.Minute
	}

	// YAML 1.2 (gopkg.in/yaml.v3) treats 0750 as decimal 750, not octal.
	// Auto-correct values where all digits are 0-7, which strongly indicates
	// the user intended octal (e.g., decimal 750 → octal 0750 = 488).
	cfg.LocalStorage.DirPermissions = reinterpretDecimalAsOctal(cfg.LocalStorage.DirPermissions, "dir_permissions")
	cfg.LocalStorage.FilePermissions = reinterpretDecimalAsOctal(cfg.LocalStorage.FilePermissions, "file_permissions")
}

// Validate performs structural and security validation on a loaded Config.
// Called at startup and on SIGHUP reload so an incoherent reload can be
// rejected without clobbering the running server's view of the world.
func Validate(cfg *Config) error {
	if cfg.Server.Mode != "local" && cfg.Server.Mode != "relay" {
		return fmt.Errorf("invalid server mode: %s (must be 'local' or 'relay')", cfg.Server.Mode)
	}
	if cfg.Server.ListenAddress == "" && cfg.Server.ListenAddressTLS == "" {
		return fmt.Errorf("at least one listen address must be configured")
	}
	if cfg.Server.ListenAddressTLS != "" {
		if cfg.Server.TLSCertFile == "" || cfg.Server.TLSKeyFile == "" {
			return fmt.Errorf("TLS certificate and key files must be specified for TLS listener")
		}
	}
	if cfg.Server.Mode == "relay" {
		if cfg.Relay.UpstreamHost == "" {
			return fmt.Errorf("upstream_host must be configured in relay mode")
		}
		if cfg.Relay.RelayCacheDirectory == "" {
			return fmt.Errorf("relay_cache_directory must be configured in relay mode")
		}
	}
	if cfg.Server.Mode == "local" {
		if err := ValidatePermissions(&cfg.LocalStorage); err != nil {
			return err
		}
	}
	if cfg.API.ListenAddress != "" {
		if cfg.API.AuthToken == "" && cfg.API.AuthTokenFile == "" {
			return fmt.Errorf("api.listen_address is set but neither api.auth_token nor api.auth_token_file is configured")
		}
		if (cfg.API.TLSCertFile == "") != (cfg.API.TLSKeyFile == "") {
			return fmt.Errorf("api.tls_cert_file and api.tls_key_file must both be set or both empty")
		}
	}
	return nil
}

// ValidatePermissions rejects permission combinations that would expose sudo
// session transcripts to unprivileged users. Returns an error rather than a
// warning — misconfigured permissions are a security incident waiting to
// happen and should block startup.
func ValidatePermissions(cfg *LocalStorageConfig) error {
	// World-writable (o+w, 0002) on any session artefact lets another local
	// user tamper with audit logs.
	if cfg.DirPermissions&0002 != 0 {
		return fmt.Errorf("dir_permissions 0%o is world-writable; refusing to start", cfg.DirPermissions)
	}
	if cfg.FilePermissions&0002 != 0 {
		return fmt.Errorf("file_permissions 0%o is world-writable; refusing to start", cfg.FilePermissions)
	}
	// World-readable (o+r, 0004) on file permissions exposes sudo transcripts
	// (which may contain sensitive command output) to any local user.
	if cfg.FilePermissions&0004 != 0 {
		return fmt.Errorf("file_permissions 0%o is world-readable; sudo transcripts may contain secrets — refusing to start", cfg.FilePermissions)
	}
	return nil
}

// reinterpretDecimalAsOctal detects values where YAML 1.2 parsed an intended
// octal literal (e.g., 0750) as decimal 750 and converts it to the correct
// octal value (0o750 = 488). Only converts when every decimal digit is 0-7,
// which is a strong signal the user intended octal notation. Values already
// within 0-0o777 (0-511) are returned unchanged.
func reinterpretDecimalAsOctal(val uint32, fieldName string) uint32 {
	if val <= 0o777 {
		return val // Already a valid permission value
	}
	// Check if all decimal digits are 0-7 (i.e., looks like an octal literal)
	tmp := val
	var octalVal uint32
	multiplier := uint32(1)
	for tmp > 0 {
		digit := tmp % 10
		if digit > 7 {
			// Contains 8 or 9 — not an octal literal, just a bad value
			slog.Warn(fmt.Sprintf("%s value %d exceeds maximum 0777 and contains non-octal digits; please use quoted octal (e.g., 0o750)", fieldName, val))
			return val
		}
		octalVal += digit * multiplier
		multiplier *= 8
		tmp /= 10
	}
	slog.Warn(fmt.Sprintf("%s: auto-corrected YAML 1.2 decimal %d to octal 0o%o (%d); consider using quoted 0o notation in config", fieldName, val, octalVal, octalVal))
	return octalVal
}

// ParseLogLevel converts a string log level to slog.Level with validation.
// Exported for use by main.go and server.go to avoid duplication.
func ParseLogLevel(levelStr string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %s (supported: debug, info, warn, error)", levelStr)
	}
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

  # Enable gzip compression for I/O log data files (stdin/stdout/stderr/ttyin/ttyout)
  # Disabled by default for compatibility with older tools
  compress: false

  # Enable password filtering to prevent passwords from being logged in cleartext
  # Uses regex pattern matching to detect password prompts and mask input
  # Enabled by default for security
  password_filter: true

*/
