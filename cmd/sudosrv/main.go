// Filename: cmd/sudosrv/main.go
package main

import (
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/config"
	"sudosrv/internal/relay"
	"sudosrv/internal/server"
)

func main() {
	// Command-line flags
	configFile := flag.String("config", "config.yaml", "Path to the configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		// Use a basic logger for this initial error since config might not be available
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// --- Setup structured logging with the configured level ---
	var logLevel slog.Level
	switch strings.ToLower(cfg.Server.ServerOperationalLogLevel) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo // Default to info if the level is unknown
	}

	handlerOpts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, handlerOpts))
	slog.SetDefault(logger)
	// --- End logging setup ---

	slog.Info("Logger initialized", "level", logLevel.String())

	// --- Flush any orphaned relay cache files from previous runs ---
	if cfg.Server.Mode == "relay" {
		go flushOrphanedRelayFiles(&cfg.Relay)
	}

	// Create and start the server
	srv, err := server.NewServer(cfg)
	if err != nil {
		slog.Error("Failed to create server", "error", err)
		os.Exit(1)
	}

	if err := srv.Start(); err != nil {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}

	srv.Wait()
	slog.Info("Server shutting down.")
}

func flushOrphanedRelayFiles(cfg *config.RelayConfig) {
	slog.Info("Scanning for orphaned relay cache files...", "directory", cfg.RelayCacheDirectory)
	files, err := filepath.Glob(filepath.Join(cfg.RelayCacheDirectory, "*.log"))
	if err != nil {
		slog.Error("Failed to scan relay cache directory", "error", err)
		return
	}

	if len(files) == 0 {
		slog.Info("No orphaned relay files found.")
		return
	}

	for _, file := range files {
		// Launch each flush operation in its own goroutine so they don't block each other.
		go relay.FlushOrphanedFile(file, cfg)
	}
}
