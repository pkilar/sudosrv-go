// SPDX-License-Identifier: Apache-2.0
// Filename: internal/config/config_test.go
package config

import (
	"crypto/tls"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	t.Run("ValidConfigFile", func(t *testing.T) {
		// Create a temporary YAML config file
		content := `
server:
  mode: "relay"
  listen_address: "127.0.0.1:9000"
  listen_address_tls: "127.0.0.1:9001"
  tls_cert_file: "test.crt"
  tls_key_file: "test.key"
  server_id: "TestSrv/1.0"
  idle_timeout: 15m
relay:
  upstream_host: "upstream.test:9002"
  use_tls: true
  connect_timeout: 10s
local_storage:
  log_directory: "/tmp/testlogs"
`
		tmpFile := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to write temp config file: %v", err)
		}

		// Load the config
		cfg, err := LoadConfig(tmpFile)
		if err != nil {
			t.Fatalf("LoadConfig() returned an unexpected error: %v", err)
		}

		// Assert values
		if cfg.Server.Mode != "relay" {
			t.Errorf("expected server mode 'relay', got '%s'", cfg.Server.Mode)
		}
		if cfg.Server.ListenAddress != "127.0.0.1:9000" {
			t.Errorf("expected listen_address '127.0.0.1:9000', got '%s'", cfg.Server.ListenAddress)
		}
		if cfg.Server.IdleTimeout != 15*time.Minute {
			t.Errorf("expected idle_timeout '15m', got '%v'", cfg.Server.IdleTimeout)
		}
		if cfg.Relay.UpstreamHost != "upstream.test:9002" {
			t.Errorf("expected upstream_host 'upstream.test:9002', got '%s'", cfg.Relay.UpstreamHost)
		}
		if !cfg.Relay.UseTLS {
			t.Errorf("expected use_tls 'true', got 'false'")
		}
		if cfg.LocalStorage.LogDirectory != "/tmp/testlogs" {
			t.Errorf("expected log_directory '/tmp/testlogs', got '%s'", cfg.LocalStorage.LogDirectory)
		}
	})

	t.Run("NonExistentConfigFileErrors", func(t *testing.T) {
		// A missing config file is an error: silently falling back to defaults
		// would mask deployment typos and could replace a documented secure
		// config with whatever yaml.v3 leaves in a half-populated struct.
		_, err := LoadConfig("non-existent-file.yaml")
		if err == nil {
			t.Fatal("LoadConfig() with non-existent file should error, got nil")
		}
		if !strings.Contains(err.Error(), "non-existent-file.yaml") {
			t.Errorf("error should mention the missing path, got: %v", err)
		}
	})

	t.Run("MalformedConfigFile", func(t *testing.T) {
		// Create a temporary malformed YAML config file
		content := `
server:
  mode: "relay"
  listen_address:
    - "this should not be a list"
`
		tmpFile := filepath.Join(t.TempDir(), "malformed.yaml")
		if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to write temp config file: %v", err)
		}

		// Attempt to load the malformed config
		_, err := LoadConfig(tmpFile)
		if err == nil {
			t.Fatal("LoadConfig() with malformed file should have returned an error, but it did not")
		}
	})
}

func TestLoadConfigAppliesDefaultsToZeroFields(t *testing.T) {
	t.Parallel()
	// Partial YAML that explicitly sets some fields and leaves others zero;
	// applyZeroValueDefaults should fill in the zeroed ones.
	content := `
server:
  mode: "local"
  listen_address: "127.0.0.1:9999"
local_storage:
  log_directory: "/tmp/x"
`
	tmpFile := filepath.Join(t.TempDir(), "partial.yaml")
	if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		// Disabled by design — see TestIdleTimeoutDefaultsToDisabled.
		{"IdleTimeout", cfg.Server.IdleTimeout, time.Duration(0)},
		{"DirPermissions", cfg.LocalStorage.DirPermissions, uint32(0750)},
		{"FilePermissions", cfg.LocalStorage.FilePermissions, uint32(0640)},
		{"ConnectTimeout", cfg.Relay.ConnectTimeout, 5 * time.Second},
		// C's [relay] timeout default (logsrvd/logsrvd_conf.c:1639). It is a
		// separate, far larger budget than the dial: reusing ConnectTimeout for
		// the upstream's reply failed the flush of any session a busy upstream
		// took more than 5s to acknowledge, and the retry stored that session
		// upstream a second time. Conformance: docs/logsrvd-reference/ CONF-039.
		{"ResponseTimeout", cfg.Relay.ResponseTimeout, 30 * time.Second},
		{"MaxReconnectInterval", cfg.Relay.MaxReconnectInterval, 1 * time.Minute},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}

// TestPartialYAMLPreservesSecureDefaults pins yaml.v3's "leave unmentioned
// fields alone" behavior for the fields that would silently flip a server
// into an unsafe configuration if zeroed: password filter, log paths, server
// ID, listen address, relay cache dir, and reconnect retries.
//
// If you ever refactor LoadConfig's merge strategy, keep this test green.
func TestPartialYAMLPreservesSecureDefaults(t *testing.T) {
	t.Parallel()
	// Only `server.mode` is set; every other key is absent from the YAML.
	// All security-critical defaults must survive.
	content := `
server:
  mode: "local"
`
	tmpFile := filepath.Join(t.TempDir(), "minimal.yaml")
	if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"PasswordFilter", cfg.LocalStorage.PasswordFilter, true},
		{"LogDirectory", cfg.LocalStorage.LogDirectory, "/var/log/gosudo-io"},
		{"IologDir", cfg.LocalStorage.IologDir, "%{LIVEDIR}/%{user}"},
		{"IologFile", cfg.LocalStorage.IologFile, "%{seq}"},
		{"ServerID", cfg.Server.ServerID, "GoSudoLogSrv/1.0"},
		{"ListenAddress", cfg.Server.ListenAddress, "127.0.0.1:30343"},
		{"MaxConnections", cfg.Server.MaxConnections, 10000},
		{"RelayCacheDirectory", cfg.Relay.RelayCacheDirectory, "/var/log/gosudo-relay-cache"},
		{"ReconnectAttempts", cfg.Relay.ReconnectAttempts, -1},
		{"TLSSkipVerify", cfg.Relay.TLSSkipVerify, false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}

// TestPartialYAMLExplicitFalseHonored verifies that a user who explicitly
// writes `password_filter: false` can still turn it off — the defaults-merge
// must not override explicit user intent.
func TestPartialYAMLExplicitFalseHonored(t *testing.T) {
	t.Parallel()
	content := `
server:
  mode: "local"
local_storage:
  password_filter: false
  compress: true
`
	tmpFile := filepath.Join(t.TempDir(), "explicit.yaml")
	if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.LocalStorage.PasswordFilter {
		t.Error("password_filter: false in YAML should disable the filter")
	}
	if !cfg.LocalStorage.Compress {
		t.Error("compress: true in YAML should enable compression")
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	// validLocal returns a fresh, minimally-valid local-mode Config.
	validLocal := func() *Config {
		return &Config{
			Server: ServerConfig{
				Mode:          "local",
				ListenAddress: "127.0.0.1:30343",
			},
			LocalStorage: LocalStorageConfig{
				DirPermissions:  0750,
				FilePermissions: 0640,
			},
		}
	}

	tests := []struct {
		name    string
		mutate  func(t *testing.T, c *Config)
		wantErr string // substring match; "" means expect no error
	}{
		{
			name: "valid local mode",
		},
		{
			name: "valid relay mode",
			mutate: func(_ *testing.T, c *Config) {
				c.Server.Mode = "relay"
				c.Relay.UpstreamHost = "upstream:1234"
				c.Relay.RelayCacheDirectory = "/tmp/cache"
			},
		},
		{
			name: "valid TLS-only listener",
			mutate: func(_ *testing.T, c *Config) {
				c.Server.ListenAddress = ""
				c.Server.ListenAddressTLS = "127.0.0.1:30344"
				c.Server.TLSCertFile = "cert"
				c.Server.TLSKeyFile = "key"
			},
		},
		{
			name:    "invalid mode",
			mutate:  func(_ *testing.T, c *Config) { c.Server.Mode = "magic" },
			wantErr: "invalid server mode",
		},
		{
			name: "no listen address",
			mutate: func(_ *testing.T, c *Config) {
				c.Server.ListenAddress = ""
				c.Server.ListenAddressTLS = ""
			},
			wantErr: "at least one listen address",
		},
		{
			name: "TLS listener without cert",
			mutate: func(_ *testing.T, c *Config) {
				c.Server.ListenAddressTLS = "127.0.0.1:30344"
				c.Server.TLSKeyFile = "key"
			},
			wantErr: "TLS certificate and key files",
		},
		{
			name: "TLS listener without key",
			mutate: func(_ *testing.T, c *Config) {
				c.Server.ListenAddressTLS = "127.0.0.1:30344"
				c.Server.TLSCertFile = "cert"
			},
			wantErr: "TLS certificate and key files",
		},
		{
			name: "relay mode missing upstream_host",
			mutate: func(_ *testing.T, c *Config) {
				c.Server.Mode = "relay"
				c.Relay.RelayCacheDirectory = "/tmp/cache"
			},
			wantErr: "upstream_host must be configured",
		},
		{
			name: "relay mode missing relay_cache_directory",
			mutate: func(_ *testing.T, c *Config) {
				c.Server.Mode = "relay"
				c.Relay.UpstreamHost = "upstream:1234"
			},
			wantErr: "relay_cache_directory must be configured",
		},
		{
			name: "relay upstream_host set while mode is local rejects",
			mutate: func(_ *testing.T, c *Config) {
				c.Relay.UpstreamHost = "upstream:1234"
				c.Relay.RelayCacheDirectory = "/tmp/cache"
			},
			wantErr: "relay.upstream_host",
		},
		{
			name: "local mode with an empty relay block stays valid",
			mutate: func(_ *testing.T, c *Config) {
				c.Relay.RelayCacheDirectory = "/tmp/cache"
				c.Relay.ConnectTimeout = 5 * time.Second
			},
		},
		{
			name: "local mode bad permissions delegates to ValidatePermissions",
			mutate: func(_ *testing.T, c *Config) {
				c.LocalStorage.DirPermissions = 0777
			},
			wantErr: "world-writable",
		},
		{
			name: "valid API with inline token",
			mutate: func(_ *testing.T, c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthToken = "secret"
			},
		},
		{
			name: "valid API with token file (mode 0600)",
			mutate: func(t *testing.T, c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthTokenFile = writeTokenFile(t, 0600)
			},
		},
		{
			name: "valid API with TLS",
			mutate: func(_ *testing.T, c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthToken = "secret"
				c.API.TLSCertFile = "api.crt"
				c.API.TLSKeyFile = "api.key"
			},
		},
		{
			name: "API enabled without token rejects",
			mutate: func(_ *testing.T, c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
			},
			wantErr: "neither api.auth_token nor api.auth_token_file",
		},
		{
			name: "API TLS cert without key rejects",
			mutate: func(_ *testing.T, c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthToken = "secret"
				c.API.TLSCertFile = "api.crt"
			},
			wantErr: "api.tls_cert_file and api.tls_key_file",
		},
		{
			name: "API TLS key without cert rejects",
			mutate: func(_ *testing.T, c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthToken = "secret"
				c.API.TLSKeyFile = "api.key"
			},
			wantErr: "api.tls_cert_file and api.tls_key_file",
		},
		{
			name: "API disabled by default",
			// No mutation: validLocal() leaves API zero-valued. Should not error.
		},
		{
			name: "API token file with relative path rejected",
			mutate: func(_ *testing.T, c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthTokenFile = "relative/path"
			},
			wantErr: "must be an absolute path",
		},
		{
			name: "API token file missing rejected",
			mutate: func(_ *testing.T, c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthTokenFile = "/nonexistent/sudosrv/token"
			},
			wantErr: "auth_token_file",
		},
		{
			name: "API token file world-readable rejected",
			mutate: func(t *testing.T, c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthTokenFile = writeTokenFile(t, 0644)
			},
			wantErr: "no group/other access",
		},
		{
			name: "API token file group-readable rejected",
			mutate: func(t *testing.T, c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthTokenFile = writeTokenFile(t, 0640)
			},
			wantErr: "no group/other access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validLocal()
			if tt.mutate != nil {
				tt.mutate(t, cfg)
			}
			err := Validate(cfg)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("Validate(): unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("Validate(): want error containing %q, got nil", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("Validate(): want error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// writeTokenFile creates a real token file in t.TempDir() with the given mode,
// so AuthTokenFile validation (which stats the file) has something concrete
// to evaluate. Returns the absolute path.
func writeTokenFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api.token")
	if err := os.WriteFile(path, []byte("secret\n"), mode); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	// WriteFile honours mode only on creation; chmod to be sure on filesystems
	// where umask interferes.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod token file: %v", err)
	}
	return path
}

func TestValidatePermissions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		dirPerm  uint32
		filePerm uint32
		wantErr  string
	}{
		{"defaults are valid", 0750, 0640, ""},
		{"strict are valid", 0700, 0600, ""},
		{"world-writable dir", 0752, 0640, "dir_permissions"},
		{"world-writable file", 0750, 0642, "file_permissions"},
		{"world-readable file", 0750, 0644, "world-readable"},
		{"both bits bad on dir checked first", 0777, 0777, "dir_permissions"},
		{"dir without owner-exec rejected", 0640, 0640, "owner-exec"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePermissions(&LocalStorageConfig{
				DirPermissions:  tt.dirPerm,
				FilePermissions: tt.filePerm,
			})
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("ValidatePermissions(): unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("ValidatePermissions(): want error containing %q, got nil", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("ValidatePermissions(): want error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    slog.Level
		wantErr bool
	}{
		{"debug", "debug", slog.LevelDebug, false},
		{"info", "info", slog.LevelInfo, false},
		{"warn", "warn", slog.LevelWarn, false},
		{"warning", "warning", slog.LevelWarn, false},
		{"error", "error", slog.LevelError, false},
		{"uppercase", "DEBUG", slog.LevelDebug, false},
		{"mixed case", "Info", slog.LevelInfo, false},
		{"surrounding whitespace", "  warn  ", slog.LevelWarn, false},
		{"unknown level falls back to Info with error", "trace", slog.LevelInfo, true},
		{"empty string", "", slog.LevelInfo, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseLogLevel(tt.input)
			if got != tt.want {
				t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLogLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestReinterpretDecimalAsOctal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   uint32
		want uint32
	}{
		{"zero stays zero", 0, 0},
		{"in-range octal value 0o750", 0o750, 0o750},
		{"in-range octal value 0o777 (max)", 0o777, 0o777},
		{"decimal 750 -> octal 0o750", 750, 0o750},
		{"decimal 640 -> octal 0o640", 640, 0o640},
		{"decimal 700 -> octal 0o700", 700, 0o700},
		{"contains digit 8 returns unchanged", 850, 850},
		{"contains digit 9 returns unchanged", 990, 990},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := reinterpretDecimalAsOctal(tt.in, "test_field")
			if got != tt.want {
				t.Errorf("reinterpretDecimalAsOctal(%d) = %d (0o%o), want %d (0o%o)",
					tt.in, got, got, tt.want, tt.want)
			}
		})
	}
}

func TestApplyZeroValueDefaults(t *testing.T) {
	t.Parallel()

	t.Run("zero values get filled with defaults", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{} // all zero
		applyZeroValueDefaults(cfg)
		// IdleTimeout is intentionally NOT re-defaulted: zero means "no idle read
		// deadline", which is the shipped behavior. See the comment in
		// applyZeroValueDefaults and TestIdleTimeoutDefaultsToDisabled.
		if cfg.Server.IdleTimeout != 0 {
			t.Errorf("IdleTimeout: got %v, want 0 (must stay disabled)", cfg.Server.IdleTimeout)
		}
		if cfg.LocalStorage.DirPermissions != 0750 {
			t.Errorf("DirPermissions: got 0%o, want 0750", cfg.LocalStorage.DirPermissions)
		}
		if cfg.LocalStorage.FilePermissions != 0640 {
			t.Errorf("FilePermissions: got 0%o, want 0640", cfg.LocalStorage.FilePermissions)
		}
		if cfg.Relay.ConnectTimeout != 5*time.Second {
			t.Errorf("ConnectTimeout: got %v, want 5s", cfg.Relay.ConnectTimeout)
		}
		if cfg.Relay.ResponseTimeout != 30*time.Second {
			t.Errorf("ResponseTimeout: got %v, want 30s", cfg.Relay.ResponseTimeout)
		}
		if cfg.Relay.MaxReconnectInterval != 1*time.Minute {
			t.Errorf("MaxReconnectInterval: got %v, want 1m", cfg.Relay.MaxReconnectInterval)
		}
	})

	t.Run("non-zero values are preserved", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Server: ServerConfig{
				IdleTimeout:    30 * time.Minute,
				MaxConnections: 5000,
			},
			Relay: RelayConfig{
				ConnectTimeout:       2 * time.Second,
				ResponseTimeout:      45 * time.Second,
				MaxReconnectInterval: 30 * time.Second,
			},
			LocalStorage: LocalStorageConfig{
				DirPermissions:  0700,
				FilePermissions: 0600,
			},
		}
		applyZeroValueDefaults(cfg)
		if cfg.Server.IdleTimeout != 30*time.Minute {
			t.Errorf("IdleTimeout was overwritten: got %v", cfg.Server.IdleTimeout)
		}
		if cfg.Server.MaxConnections != 5000 {
			t.Errorf("MaxConnections was overwritten: got %d", cfg.Server.MaxConnections)
		}
		if cfg.LocalStorage.DirPermissions != 0700 {
			t.Errorf("DirPermissions was overwritten: got 0%o", cfg.LocalStorage.DirPermissions)
		}
		if cfg.LocalStorage.FilePermissions != 0600 {
			t.Errorf("FilePermissions was overwritten: got 0%o", cfg.LocalStorage.FilePermissions)
		}
		if cfg.Relay.ConnectTimeout != 2*time.Second {
			t.Errorf("ConnectTimeout was overwritten: got %v", cfg.Relay.ConnectTimeout)
		}
		if cfg.Relay.ResponseTimeout != 45*time.Second {
			t.Errorf("ResponseTimeout was overwritten: got %v", cfg.Relay.ResponseTimeout)
		}
	})

	t.Run("negative max_connections is normalized to 0", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{Server: ServerConfig{MaxConnections: -5}}
		applyZeroValueDefaults(cfg)
		if cfg.Server.MaxConnections != 0 {
			t.Errorf("Negative MaxConnections should be normalized to 0, got %d", cfg.Server.MaxConnections)
		}
	})

	t.Run("zero max_connections is preserved (disables cap)", func(t *testing.T) {
		t.Parallel()
		// "0 disables the cap" is documented behavior; applyZeroValueDefaults
		// must not silently rewrite it to the 10000 default.
		cfg := &Config{Server: ServerConfig{MaxConnections: 0}}
		applyZeroValueDefaults(cfg)
		if cfg.Server.MaxConnections != 0 {
			t.Errorf("MaxConnections=0 must be preserved, got %d", cfg.Server.MaxConnections)
		}
	})

	t.Run("decimal permissions get reinterpreted as octal", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			LocalStorage: LocalStorageConfig{
				DirPermissions:  750, // intended as 0o750
				FilePermissions: 640, // intended as 0o640
			},
		}
		applyZeroValueDefaults(cfg)
		if cfg.LocalStorage.DirPermissions != 0o750 {
			t.Errorf("DirPermissions: got 0%o, want 0o750", cfg.LocalStorage.DirPermissions)
		}
		if cfg.LocalStorage.FilePermissions != 0o640 {
			t.Errorf("FilePermissions: got 0%o, want 0o640", cfg.LocalStorage.FilePermissions)
		}
	})
}

// TestIdleTimeoutDefaultsToDisabled pins the idle_timeout default to "no read
// deadline". Do not "restore" a finite default here — it kills user commands.
//
// The reference C sudo_logsrvd arms its steady-state read event with an
// explicit NULL timeout and never disconnects an idle client:
//
//	logsrvd/logsrvd.c:1372  /* No read timeout, client messages may happen at
//	                           arbitrary times. */
//
// That is not a stylistic choice we may diverge from, because sudo's client
// treats a lost log connection as fatal to the *command*, not just to logging:
//
//	plugins/sudoers/defaults.c:610    def_ignore_iolog_errors = false (default)
//	plugins/sudoers/log_client.c:1919 if (!ignore_log_errors) loopbreak()
//	                                  /* "kill the command" */
//
// So any finite idle_timeout eventually SIGKILLs an interactive `sudo -s` or
// `sudo vim` sitting at a prompt — the server severs the connection and the
// client tears the user's shell down with it. A "generous" default only moves
// the goalpost (a root shell left open overnight still dies).
//
// Conformance: docs/logsrvd-reference/ ARCH-024, ARCH-045, CONF-025 (breaking).
// Operators who want a finite deadline must opt in explicitly.
// TestServerTimeoutDefault pins the write/handshake deadline, the counterpart to
// idle_timeout being disabled.
//
// C's [server] timeout (default 30s) bounds writes to the client and the TLS
// handshake — it is NOT an idle read deadline, a distinction the man page
// blurs. It is what stops an unresponsive peer holding a connection slot
// forever, so it must have a finite default; 0 disables it, matching C's "A
// value of 0 will disable the timeout."
//
// Conformance: docs/logsrvd-reference/ ARCH-032, ARCH-045, TLS-022, CONF-025.
func TestServerTimeoutDefault(t *testing.T) {
	load := func(t *testing.T, content string) *Config {
		t.Helper()
		tmpFile := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
			t.Fatalf("write temp config: %v", err)
		}
		cfg, err := LoadConfig(tmpFile)
		if err != nil {
			t.Fatalf("LoadConfig() error: %v", err)
		}
		return cfg
	}

	t.Run("OmittedGetsFiniteDefault", func(t *testing.T) {
		cfg := load(t, "server:\n  mode: \"local\"\n")
		if cfg.Server.ServerTimeout != 30*time.Second {
			t.Errorf("server_timeout: got %v, want 30s (C's DEFAULT_SOCKET_TIMEOUT_SEC). "+
				"Unlike idle_timeout this MUST be finite by default — it is the only "+
				"bound on a peer that stops reading.", cfg.Server.ServerTimeout)
		}
	})

	t.Run("ExplicitZeroDisables", func(t *testing.T) {
		cfg := load(t, "server:\n  mode: \"local\"\n  server_timeout: 0s\n")
		if cfg.Server.ServerTimeout > 0 {
			t.Errorf("server_timeout: 0s was rewritten to %v; zero must disable the "+
				"timeout, matching C", cfg.Server.ServerTimeout)
		}
	})

	t.Run("PositiveIsPreserved", func(t *testing.T) {
		cfg := load(t, "server:\n  mode: \"local\"\n  server_timeout: 5s\n")
		if cfg.Server.ServerTimeout != 5*time.Second {
			t.Errorf("server_timeout: got %v, want 5s", cfg.Server.ServerTimeout)
		}
	})
}

func TestIdleTimeoutDefaultsToDisabled(t *testing.T) {
	load := func(t *testing.T, content string) *Config {
		t.Helper()
		tmpFile := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
			t.Fatalf("write temp config: %v", err)
		}
		cfg, err := LoadConfig(tmpFile)
		if err != nil {
			t.Fatalf("LoadConfig() error: %v", err)
		}
		return cfg
	}

	// The shipped default: nothing specified at all.
	t.Run("OmittedMeansNoDeadline", func(t *testing.T) {
		cfg := load(t, "server:\n  mode: \"local\"\n")
		if cfg.Server.IdleTimeout > 0 {
			t.Errorf("idle_timeout defaulted to %v; must be non-positive so the handler "+
				"arms no read deadline (C parity: logsrvd.c:1372). A finite default "+
				"kills idle interactive sessions — see this test's doc comment.",
				cfg.Server.IdleTimeout)
		}
	})

	// An operator writing "0s" means "off", not "give me your favourite number".
	t.Run("ExplicitZeroMeansNoDeadline", func(t *testing.T) {
		cfg := load(t, "server:\n  mode: \"local\"\n  idle_timeout: 0s\n")
		if cfg.Server.IdleTimeout > 0 {
			t.Errorf("explicit idle_timeout: 0s was rewritten to %v; zero must mean "+
				"disabled, not re-defaulted", cfg.Server.IdleTimeout)
		}
	})

	// Back-compat: -1s was the documented opt-out before zero meant the same.
	t.Run("NegativeIsPreserved", func(t *testing.T) {
		cfg := load(t, "server:\n  mode: \"local\"\n  idle_timeout: -1s\n")
		if cfg.Server.IdleTimeout > 0 {
			t.Errorf("idle_timeout: -1s produced %v; negative must remain non-positive",
				cfg.Server.IdleTimeout)
		}
	})

	// Opting in must still work — this is the whole escape hatch.
	t.Run("PositiveIsPreserved", func(t *testing.T) {
		cfg := load(t, "server:\n  mode: \"local\"\n  idle_timeout: 30m\n")
		if cfg.Server.IdleTimeout != 30*time.Minute {
			t.Errorf("idle_timeout: got %v, want 30m (explicit opt-in must be honoured)",
				cfg.Server.IdleTimeout)
		}
	})
}

// TestTLSVersion verifies the "1.2"/"1.3" string maps to the right crypto/tls
// constant, that an empty string defaults to the secure 1.3 floor, and that a
// bad value is rejected (so a typo cannot silently weaken TLS).
func TestTLSVersion(t *testing.T) {
	cases := []struct {
		in      string
		want    uint16
		wantErr bool
	}{
		{"1.3", tls.VersionTLS13, false},
		{"", tls.VersionTLS13, false},
		{"1.2", tls.VersionTLS12, false},
		{"1.1", 0, true},
		{"garbage", 0, true},
	}
	for _, c := range cases {
		got, err := TLSVersion(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("TLSVersion(%q): expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("TLSVersion(%q): unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("TLSVersion(%q) = %#x, want %#x", c.in, got, c.want)
		}
	}
}

// TestTLSMinVersionConfig verifies the secure 1.3 default, the documented 1.2
// opt-in for legacy peers (server + relay), and that Validate rejects an invalid
// value.
func TestTLSMinVersionConfig(t *testing.T) {
	t.Run("DefaultIs13", func(t *testing.T) {
		cfg := defaultConfig()
		if cfg.Server.TLSMinVersion != "1.3" || cfg.Relay.TLSMinVersion != "1.3" {
			t.Fatalf("defaults: server=%q relay=%q, want 1.3/1.3", cfg.Server.TLSMinVersion, cfg.Relay.TLSMinVersion)
		}
	})

	t.Run("OptInTo12", func(t *testing.T) {
		content := "server:\n  mode: \"local\"\n  tls_min_version: \"1.2\"\nrelay:\n  tls_min_version: \"1.2\"\n"
		tmpFile := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := LoadConfig(tmpFile)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.Server.TLSMinVersion != "1.2" || cfg.Relay.TLSMinVersion != "1.2" {
			t.Fatalf("got server=%q relay=%q, want 1.2/1.2", cfg.Server.TLSMinVersion, cfg.Relay.TLSMinVersion)
		}
		if v, _ := TLSVersion(cfg.Server.TLSMinVersion); v != tls.VersionTLS12 {
			t.Errorf("resolved server min = %#x, want TLS 1.2", v)
		}
	})

	t.Run("OmittedDefaultsTo13", func(t *testing.T) {
		content := "server:\n  mode: \"local\"\n"
		tmpFile := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := LoadConfig(tmpFile)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.Server.TLSMinVersion != "1.3" {
			t.Errorf("omitted server tls_min_version = %q, want 1.3", cfg.Server.TLSMinVersion)
		}
	})

	t.Run("ValidateRejectsBadVersion", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Server.TLSMinVersion = "1.1"
		if err := Validate(cfg); err == nil {
			t.Error("expected Validate to reject tls_min_version 1.1")
		}
	})
}

func TestIsLoopbackListenAddress(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8888", true},
		{"localhost:8888", true},
		{"[::1]:8888", true},
		{"0.0.0.0:8888", false},
		{"[::]:8888", false},
		{":8888", false},
		{"10.0.0.5:8888", false},
		{"example.com:8888", false},
		{"not-an-address", false},
	}
	for _, tt := range tests {
		if got := isLoopbackListenAddress(tt.addr); got != tt.want {
			t.Errorf("isLoopbackListenAddress(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

// TestLoadConfigRejectsUnknownKeys guards CONF-002: a misspelled key must be
// fatal, not silently ignored. C's logsrvd_conf_parse() fails the whole load on
// an unrecognized key ("%s:%d [%s] illegal key: %s", logsrvd_conf.c:1292) and
// sudo_logsrvd exits EXIT_FAILURE (logsrvd.c:2275). Without this, a typo such as
// "listen_addres" leaves the daemon quietly bound to the 127.0.0.1:30343
// default while the operator believes it is listening on the configured address.
func TestLoadConfigRejectsUnknownKeys(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantIn  string
	}{
		{
			name: "MisspelledKeyInSection",
			content: `
server:
  mode: "local"
  listen_addres: "0.0.0.0:9999"
`,
			wantIn: "listen_addres",
		},
		{
			name: "UnknownTopLevelSection",
			content: `
server:
  mode: "local"
storage:
  log_directory: "/tmp/x"
`,
			wantIn: "storage",
		},
		{
			name: "UnknownKeyInNestedSection",
			content: `
local_storage:
  log_directory: "/tmp/x"
  compres: true
`,
			wantIn: "compres",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(tmpFile, []byte(tt.content), 0600); err != nil {
				t.Fatalf("failed to write temp config file: %v", err)
			}
			_, err := LoadConfig(tmpFile)
			if err == nil {
				t.Fatalf("LoadConfig() accepted an unknown key; want an error mentioning %q", tt.wantIn)
			}
			if !strings.Contains(err.Error(), tt.wantIn) {
				t.Errorf("error should name the offending key %q, got: %v", tt.wantIn, err)
			}
		})
	}
}

// TestShippedConfigsHaveNoUnknownKeys makes sure the strict decoding above does
// not reject the configs this repo ships and packages install.
func TestShippedConfigsHaveNoUnknownKeys(t *testing.T) {
	paths, err := filepath.Glob("../../*.yaml")
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	paths = append(paths, "../../debian/sudosrv/etc/sudosrv/config.yaml")
	if len(paths) < 2 {
		t.Fatal("expected to find the shipped example configs")
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		cfg, err := LoadConfig(p)
		if err != nil {
			t.Errorf("shipped config %s failed to load: %v", p, err)
			continue
		}
		// Loading is not enough: a shipped config that LoadConfig accepts but
		// Validate rejects makes the daemon exit 2 on a fresh install. It also
		// makes the example the worst possible teaching aid, which is how
		// config.yaml came to advertise a relay upstream under mode: "local".
		if err := Validate(cfg); err != nil {
			t.Errorf("shipped config %s failed validation: %v", p, err)
		}
	}
}
