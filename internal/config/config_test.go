// Filename: internal/config/config_test.go
package config

import (
	"os"
	"path/filepath"
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
