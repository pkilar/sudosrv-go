package server

import (
	"log/slog"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"testing"
)

func TestServerReload(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	initialConfig := `server:
  mode: "local"
  listen_address: "127.0.0.1:30343"
  server_operational_log_level: "info"
local_storage:
  log_directory: "/tmp/test-logs"
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelInfo)

	srv, err := NewServer(cfg, configPath, logLevel)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	// Verify initial state
	if logLevel.Level() != slog.LevelInfo {
		t.Fatalf("Expected initial log level INFO, got %s", logLevel.Level())
	}

	t.Run("LogLevelChange", func(t *testing.T) {
		// Update config file with new log level
		updatedConfig := `server:
  mode: "local"
  listen_address: "127.0.0.1:30343"
  server_operational_log_level: "debug"
local_storage:
  log_directory: "/tmp/test-logs"
`
		if err := os.WriteFile(configPath, []byte(updatedConfig), 0644); err != nil {
			t.Fatalf("Failed to write updated config: %v", err)
		}

		srv.reload()

		if logLevel.Level() != slog.LevelDebug {
			t.Errorf("Expected log level DEBUG after reload, got %s", logLevel.Level())
		}
	})

	t.Run("InvalidLogLevel", func(t *testing.T) {
		// Set log level to something known first
		logLevel.Set(slog.LevelWarn)

		badConfig := `server:
  mode: "local"
  listen_address: "127.0.0.1:30343"
  server_operational_log_level: "invalid_level"
local_storage:
  log_directory: "/tmp/test-logs"
`
		if err := os.WriteFile(configPath, []byte(badConfig), 0644); err != nil {
			t.Fatalf("Failed to write bad config: %v", err)
		}

		srv.reload()

		// Log level should remain unchanged on invalid input
		if logLevel.Level() != slog.LevelWarn {
			t.Errorf("Expected log level to remain WARN after invalid reload, got %s", logLevel.Level())
		}
	})

	t.Run("MissingConfigFile", func(t *testing.T) {
		logLevel.Set(slog.LevelError)
		srv.configPath = filepath.Join(tmpDir, "nonexistent.yaml")

		srv.reload()

		// With the current config.LoadConfig behavior, missing file returns defaults
		// but log level should still be updated based on the default ("info")
		if logLevel.Level() != slog.LevelInfo {
			t.Errorf("Expected log level INFO from defaults after missing config reload, got %s", logLevel.Level())
		}

		// Restore path
		srv.configPath = configPath
	})

	t.Run("ConfigUpdated", func(t *testing.T) {
		// Verify that new config is picked up
		newConfig := `server:
  mode: "local"
  listen_address: "127.0.0.1:30343"
  server_operational_log_level: "error"
  server_id: "TestServer/2.0"
local_storage:
  log_directory: "/tmp/test-logs-v2"
`
		if err := os.WriteFile(configPath, []byte(newConfig), 0644); err != nil {
			t.Fatalf("Failed to write new config: %v", err)
		}

		srv.reload()

		loadedCfg := srv.config.Load()
		if loadedCfg.Server.ServerID != "TestServer/2.0" {
			t.Errorf("Expected server_id 'TestServer/2.0', got '%s'", loadedCfg.Server.ServerID)
		}
		if loadedCfg.LocalStorage.LogDirectory != "/tmp/test-logs-v2" {
			t.Errorf("Expected log_directory '/tmp/test-logs-v2', got '%s'", loadedCfg.LocalStorage.LogDirectory)
		}
		if logLevel.Level() != slog.LevelError {
			t.Errorf("Expected log level ERROR, got %s", logLevel.Level())
		}
	})
}
