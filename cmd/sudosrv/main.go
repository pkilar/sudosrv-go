// Filename: cmd/sudosrv/main.go
package main

import (
	"flag"
	"log/slog"
	"os"
	"strings"
	"sudosrv/internal/config"
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
