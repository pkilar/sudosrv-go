// SPDX-License-Identifier: Apache-2.0
// Filename: internal/config/config_test.go
package config

import (
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

	t.Run("NonExistentConfigFile", func(t *testing.T) {
		// Attempt to load a config file that does not exist
		cfg, err := LoadConfig("non-existent-file.yaml")
		if err != nil {
			t.Fatalf("LoadConfig() with non-existent file should not error, but got: %v", err)
		}

		// Check that default values are used
		if cfg.Server.Mode != "local" {
			t.Errorf("expected default server mode 'local', got '%s'", cfg.Server.Mode)
		}
		if cfg.Server.ListenAddress != "127.0.0.1:30343" {
			t.Errorf("expected default listen_address '127.0.0.1:30343', got '%s'", cfg.Server.ListenAddress)
		}
		if cfg.LocalStorage.LogDirectory != "/var/log/gosudo-io" {
			t.Errorf("expected default log_directory '/var/log/gosudo-io', got '%s'", cfg.LocalStorage.LogDirectory)
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
		{"IdleTimeout", cfg.Server.IdleTimeout, 10 * time.Minute},
		{"DirPermissions", cfg.LocalStorage.DirPermissions, uint32(0750)},
		{"FilePermissions", cfg.LocalStorage.FilePermissions, uint32(0640)},
		{"ConnectTimeout", cfg.Relay.ConnectTimeout, 5 * time.Second},
		{"MaxReconnectInterval", cfg.Relay.MaxReconnectInterval, 1 * time.Minute},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
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
		mutate  func(*Config)
		wantErr string // substring match; "" means expect no error
	}{
		{
			name: "valid local mode",
		},
		{
			name: "valid relay mode",
			mutate: func(c *Config) {
				c.Server.Mode = "relay"
				c.Relay.UpstreamHost = "upstream:1234"
				c.Relay.RelayCacheDirectory = "/tmp/cache"
			},
		},
		{
			name: "valid TLS-only listener",
			mutate: func(c *Config) {
				c.Server.ListenAddress = ""
				c.Server.ListenAddressTLS = "127.0.0.1:30344"
				c.Server.TLSCertFile = "cert"
				c.Server.TLSKeyFile = "key"
			},
		},
		{
			name:    "invalid mode",
			mutate:  func(c *Config) { c.Server.Mode = "magic" },
			wantErr: "invalid server mode",
		},
		{
			name: "no listen address",
			mutate: func(c *Config) {
				c.Server.ListenAddress = ""
				c.Server.ListenAddressTLS = ""
			},
			wantErr: "at least one listen address",
		},
		{
			name: "TLS listener without cert",
			mutate: func(c *Config) {
				c.Server.ListenAddressTLS = "127.0.0.1:30344"
				c.Server.TLSKeyFile = "key"
			},
			wantErr: "TLS certificate and key files",
		},
		{
			name: "TLS listener without key",
			mutate: func(c *Config) {
				c.Server.ListenAddressTLS = "127.0.0.1:30344"
				c.Server.TLSCertFile = "cert"
			},
			wantErr: "TLS certificate and key files",
		},
		{
			name: "relay mode missing upstream_host",
			mutate: func(c *Config) {
				c.Server.Mode = "relay"
				c.Relay.RelayCacheDirectory = "/tmp/cache"
			},
			wantErr: "upstream_host must be configured",
		},
		{
			name: "relay mode missing relay_cache_directory",
			mutate: func(c *Config) {
				c.Server.Mode = "relay"
				c.Relay.UpstreamHost = "upstream:1234"
			},
			wantErr: "relay_cache_directory must be configured",
		},
		{
			name: "local mode bad permissions delegates to ValidatePermissions",
			mutate: func(c *Config) {
				c.LocalStorage.DirPermissions = 0777
			},
			wantErr: "world-writable",
		},
		{
			name: "valid API with inline token",
			mutate: func(c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthToken = "secret"
			},
		},
		{
			name: "valid API with token file",
			mutate: func(c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthTokenFile = "/run/sudosrv/api.token"
			},
		},
		{
			name: "valid API with TLS",
			mutate: func(c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthToken = "secret"
				c.API.TLSCertFile = "api.crt"
				c.API.TLSKeyFile = "api.key"
			},
		},
		{
			name: "API enabled without token rejects",
			mutate: func(c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
			},
			wantErr: "neither api.auth_token nor api.auth_token_file",
		},
		{
			name: "API TLS cert without key rejects",
			mutate: func(c *Config) {
				c.API.ListenAddress = "127.0.0.1:30345"
				c.API.AuthToken = "secret"
				c.API.TLSCertFile = "api.crt"
			},
			wantErr: "api.tls_cert_file and api.tls_key_file",
		},
		{
			name: "API TLS key without cert rejects",
			mutate: func(c *Config) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validLocal()
			if tt.mutate != nil {
				tt.mutate(cfg)
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
		if cfg.Server.IdleTimeout != 10*time.Minute {
			t.Errorf("IdleTimeout: got %v, want 10m", cfg.Server.IdleTimeout)
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
	})

	t.Run("negative max_connections is normalized to 0", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{Server: ServerConfig{MaxConnections: -5}}
		applyZeroValueDefaults(cfg)
		if cfg.Server.MaxConnections != 0 {
			t.Errorf("Negative MaxConnections should be normalized to 0, got %d", cfg.Server.MaxConnections)
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
