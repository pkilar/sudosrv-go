// SPDX-License-Identifier: Apache-2.0
// Filename: internal/config/config.go
package config

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TLSVersion maps a "1.2"/"1.3" config string to the crypto/tls version
// constant. An empty string defaults to TLS 1.3 (the secure default), so
// manually-constructed configs that omit the field still resolve. Any other
// value is rejected so a typo cannot silently weaken the floor.
func TLSVersion(s string) (uint16, error) {
	switch s {
	case "", "1.3":
		return tls.VersionTLS13, nil
	case "1.2":
		return tls.VersionTLS12, nil
	default:
		return 0, fmt.Errorf("unsupported tls_min_version %q (supported: \"1.2\", \"1.3\")", s)
	}
}

// Config holds the application's configuration.
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Relay        RelayConfig        `yaml:"relay"`
	LocalStorage LocalStorageConfig `yaml:"local_storage"`
	API          APIConfig          `yaml:"api"`
}

// ServerConfig holds server-specific settings.
type ServerConfig struct {
	Mode             string        `yaml:"mode"` // "local" or "relay"
	ListenAddress    string        `yaml:"listen_address"`
	ListenAddressTLS string        `yaml:"listen_address_tls"`
	TLSCertFile      string        `yaml:"tls_cert_file"`
	TLSKeyFile       string        `yaml:"tls_key_file"`
	TLSMinVersion    string        `yaml:"tls_min_version"` // "1.2" or "1.3" (default "1.3") for the protocol TLS listener
	ServerID         string        `yaml:"server_id"`
	IdleTimeout      time.Duration `yaml:"idle_timeout"`
	// ServerTimeout bounds writes to the client and the TLS handshake, mirroring
	// C's [server] timeout (default 30s). It is NOT an idle read deadline — see
	// IdleTimeout, which is a different knob with the opposite default. 0 or
	// negative disables it, matching C's "A value of 0 will disable the timeout".
	ServerTimeout             time.Duration `yaml:"server_timeout"`
	MaxConnections            int           `yaml:"max_connections"`              // 0 disables the cap
	ServerOperationalLogLevel string        `yaml:"server_operational_log_level"` // e.g., "debug", "info", "warn", "error"
}

// RelayConfig holds settings for relay mode.
type RelayConfig struct {
	UpstreamHost        string        `yaml:"upstream_host"`
	UseTLS              bool          `yaml:"use_tls"`
	TLSSkipVerify       bool          `yaml:"tls_skip_verify"`
	TLSMinVersion       string        `yaml:"tls_min_version"` // "1.2" or "1.3" (default "1.3") for the upstream dial
	ConnectTimeout      time.Duration `yaml:"connect_timeout"`
	RelayCacheDirectory string        `yaml:"relay_cache_directory"`
	ReconnectAttempts   int           `yaml:"reconnect_attempts"`
	// RequireUpstream makes relay mode fail CLOSED: the upstream must be
	// reachable at accept time or the session is refused, which makes sudo
	// decline to run the command. Default false, i.e. fail open -- an
	// unreachable upstream spools to the local cache and delivers later, which
	// keeps privileged work running through an outage.
	//
	// C's default relay streams to the upstream and refuses the command when the
	// relay list is exhausted; its store_first mode behaves like this server's
	// default. Sites that require an auditable path to exist before privileged
	// execution set this to true and accept that an upstream outage blocks sudo.
	// Conformance: docs/logsrvd-reference/ RELAY-010.
	RequireUpstream      bool          `yaml:"require_upstream"`
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

// LoadConfig reads the configuration from a YAML file. A missing file is an
// error so a typo in -config or a missing deployment artifact cannot silently
// replace the documented secure defaults with whatever yaml.v3 leaves in a
// half-populated struct.
func LoadConfig(path string) (*Config, error) {
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

// LoadConfigRequired is retained as an alias for LoadConfig so existing SIGHUP
// reload call sites do not need to change. Both functions now have identical
// fail-fast semantics on a missing file.
func LoadConfigRequired(path string) (*Config, error) {
	return LoadConfig(path)
}

// defaultConfig returns a Config populated with all secure defaults.
//
// LoadConfig calls this first, then yaml.Unmarshal merges user values on top.
// yaml.v3 only overwrites fields that appear in the YAML, so any field the
// user omits keeps its default — including PasswordFilter, IologDir, etc.
// applyZeroValueDefaults is a defensive second pass that re-applies the few
// numeric defaults a user could accidentally zero out (e.g., idle_timeout: 0).
func defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Mode:                      "local",
			ListenAddress:             "127.0.0.1:30343",
			ServerID:                  "GoSudoLogSrv/1.0",
			IdleTimeout:               0,                // 0 = no idle read deadline. DO NOT give this a finite default; see below.
			ServerTimeout:             30 * time.Second, // C's DEFAULT_SOCKET_TIMEOUT_SEC; bounds writes + TLS handshake.
			MaxConnections:            10000,
			TLSMinVersion:             "1.3",  // Secure default; "1.2" available for legacy clients
			ServerOperationalLogLevel: "info", // Default log level
		},
		Relay: RelayConfig{
			ConnectTimeout:       5 * time.Second,
			RelayCacheDirectory:  "/var/log/gosudo-relay-cache",
			ReconnectAttempts:    -1, // Default to trying forever
			MaxReconnectInterval: 1 * time.Minute,
			TLSSkipVerify:        false, // Default to secure TLS verification
			TLSMinVersion:        "1.3", // Secure default; "1.2" available for legacy upstreams
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

// unmarshalConfig decodes the config file STRICTLY: a key that maps to no
// struct field is a fatal error, never a silent no-op.
//
// C behaves the same way. logsrvd_conf_parse() aborts the whole parse on an
// unrecognized key -- "%s:%d [%s] illegal key: %s" (logsrvd/logsrvd_conf.c:1291)
// -- and sudo_logsrvd turns that into EXIT_FAILURE at startup
// (logsrvd/logsrvd.c:2275). Plain yaml.Unmarshal ignores unknown keys, so a
// single-character typo like "listen_addres:" used to decode with err == nil and
// leave the daemon bound to the 127.0.0.1:30343 default -- reachable only from
// localhost -- while the operator's config said 0.0.0.0 and the log said nothing.
// The same silence hid typos in tls_cert_file, password_filter and auth_token_file,
// each of which fails open on a security control. Do not relax this back to
// yaml.Unmarshal. Conformance: docs/logsrvd-reference/ CONF-002.
// Guarded by TestLoadConfigRejectsUnknownKeys.
func unmarshalConfig(data []byte, config *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(config); err != nil {
		// An empty or comment-only file yields io.EOF; that is not an error,
		// it just means "use the defaults".
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to unmarshal config YAML: %w", err)
		}
	}

	// Re-apply defaults for zero-valued fields that yaml may have cleared
	// when a section is partially specified in the config file.
	applyZeroValueDefaults(config)

	return nil
}

// applyZeroValueDefaults restores default values for fields that yaml.Unmarshal
// may have zeroed when a section was partially specified.
func applyZeroValueDefaults(cfg *Config) {
	// idle_timeout is deliberately ABSENT from this function. Do not add it.
	//
	// Any value <= 0 (omitted, "0s", or the legacy "-1s" opt-out) means "no idle
	// read deadline", and that is the default. Re-defaulting a zero here to some
	// finite duration is exactly the bug this comment exists to prevent: it
	// SIGKILLs the user's command on an idle interactive session. The full chain,
	// verified in the sudo 1.9.18 sources:
	//
	//   1. C sudo_logsrvd arms its steady-state read event with a NULL timeout
	//      (logsrvd/logsrvd.c:1372, "No read timeout, client messages may happen
	//      at arbitrary times") — it never disconnects an idle client.
	//   2. sudo's def_ignore_iolog_errors defaults to false
	//      (plugins/sudoers/defaults.c:610).
	//   3. So when the log connection drops, the client calls loopbreak()
	//      (plugins/sudoers/log_client.c:1919, "Break out of sudo event loop and
	//      kill the command") and terminate_command() SIGKILLs the user's shell.
	//
	// Net effect of a finite default: `sudo -s` left at a prompt past the timeout
	// has the server hang up and the user's root shell killed under them. A
	// larger default only delays it. Operators who genuinely want a deadline set
	// a positive idle_timeout explicitly and accept that consequence.
	//
	// Conformance: docs/logsrvd-reference/ ARCH-024, ARCH-045, CONF-025 (breaking).
	// Guarded by TestIdleTimeoutDefaultsToDisabled (this package) and
	// TestIdleReadDeadlineOptOut/ShippedDefaultArmsNoReadDeadline (internal/connection).
	if cfg.Server.MaxConnections < 0 {
		cfg.Server.MaxConnections = 0
	}
	if cfg.Server.TLSMinVersion == "" {
		cfg.Server.TLSMinVersion = "1.3"
	}
	if cfg.Relay.TLSMinVersion == "" {
		cfg.Relay.TLSMinVersion = "1.3"
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
	if _, err := TLSVersion(cfg.Server.TLSMinVersion); err != nil {
		return fmt.Errorf("server.%w", err)
	}
	if _, err := TLSVersion(cfg.Relay.TLSMinVersion); err != nil {
		return fmt.Errorf("relay.%w", err)
	}
	if cfg.Server.Mode == "relay" {
		if cfg.Relay.UpstreamHost == "" {
			return fmt.Errorf("upstream_host must be configured in relay mode")
		}
		if cfg.Relay.RelayCacheDirectory == "" {
			return fmt.Errorf("relay_cache_directory must be configured in relay mode")
		}
	}
	if cfg.Server.Mode != "relay" && cfg.Relay.UpstreamHost != "" {
		// C has no mode key: a non-empty relay list is itself the switch that
		// puts sudo_logsrvd into relay mode, and every relay code path is
		// guarded by !TAILQ_EMPTY(logsrvd_conf_relay_address())
		// (logsrvd/logsrvd.c:1546,1652; logsrvd/logsrvd_conf.c:821-825). Here
		// server.mode is the switch instead, so configuring relay.upstream_host
		// and forgetting server.mode used to be accepted silently: the daemon
		// wrote every session to local_storage.log_directory while the operator
		// believed transcripts were being centralised upstream, and nothing in
		// the startup log said otherwise. Discovery typically came months later,
		// when someone went looking for a session on the central host.
		//
		// Reject rather than infer relay mode from the populated block: a
		// package upgrade that adds this check must not silently flip a daemon
		// that has been storing locally into forwarding privileged session
		// transcripts to a host the operator never intended.
		// Conformance: docs/logsrvd-reference/ CONF-038.
		// Guarded by TestValidate/relay_upstream_host_set_while_mode_is_local_rejects.
		return fmt.Errorf("relay.upstream_host is set but server.mode is %q: "+
			"set server.mode to \"relay\" to forward sessions upstream, or remove relay.upstream_host",
			cfg.Server.Mode)
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
		if err := validateAuthTokenFile(cfg.API.AuthTokenFile); err != nil {
			return err
		}
		// Plaintext HTTP is acceptable only for loopback deployments: every
		// request carries the static bearer token, so serving it on a routable
		// interface without TLS exposes the credential to the network. Warn
		// rather than refuse so existing trusted-network deployments keep
		// working, but make the exposure unmissable in the startup log.
		if cfg.API.TLSCertFile == "" && !isLoopbackListenAddress(cfg.API.ListenAddress) {
			slog.Warn("INSECURE: api.listen_address is not loopback and api TLS is not configured — "+
				"the bearer token will traverse the network in cleartext. "+
				"Configure api.tls_cert_file/api.tls_key_file or bind to 127.0.0.1.",
				"listen_address", cfg.API.ListenAddress)
		}
	}
	return nil
}

// isLoopbackListenAddress reports whether a listen address string is bound to
// a loopback interface. An empty host (":8080"), a wildcard address, or an
// unparsable host is treated as NOT loopback, so the caller errs on the side
// of warning.
func isLoopbackListenAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateAuthTokenFile enforces the security preconditions documented for the
// preferred AuthTokenFile credential path: absolute path, file exists, and the
// mode forbids group/other access. A world-readable token file accepted as
// "preferred" would be a silent regression.
func validateAuthTokenFile(path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("api.auth_token_file must be an absolute path, got %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("api.auth_token_file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("api.auth_token_file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("api.auth_token_file %s has mode 0%o; require 0600 or 0400 (no group/other access)",
			path, info.Mode().Perm())
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
	// Directories without owner-exec are not traversable; this catches the
	// classic `dir_permissions: 644` mistake (auto-octalled from decimal),
	// which would otherwise produce inscrutable runtime errors.
	if cfg.DirPermissions&0100 == 0 {
		return fmt.Errorf("dir_permissions 0%o lacks owner-exec bit; directories would not be traversable", cfg.DirPermissions)
	}
	return nil
}

// reinterpretDecimalAsOctal detects values where YAML 1.2 parsed an intended
// octal literal (e.g., 0750) as decimal 750 and converts it to the correct
// octal value (0o750 = 488). Only converts when every decimal digit is 0-7,
// which is a strong signal the user intended octal notation. Values already
// within 0-0o777 (0-511) are returned unchanged.
//
// ValidatePermissions runs after this conversion, so any resulting value that
// would be unsafe (world-writable, world-readable file, dir without owner-exec)
// still blocks startup with a clear error.
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
			slog.Warn("permission value exceeds 0777 and contains non-octal digits; use quoted octal (e.g., \"0750\")",
				"field", fieldName, "value", val)
			return val
		}
		octalVal += digit * multiplier
		multiplier *= 8
		tmp /= 10
	}
	slog.Warn("auto-corrected YAML 1.2 decimal to octal; quote the value in config to silence this warning",
		"field", fieldName, "decimal", val, "octal", fmt.Sprintf("0o%o", octalVal))
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
  # idle_timeout: off by default (C parity). Setting it kills idle interactive
  # sessions — see applyZeroValueDefaults above before enabling.
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
