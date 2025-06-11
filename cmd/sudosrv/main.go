// Filename: cmd/sudosrv/main.go
package main

import (
	"flag"
	"log/slog"
	"os"
	"sudosrv/internal/config"
	"sudosrv/internal/server"
)

func main() {
	// Setup structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Command-line flags
	configFile := flag.String("config", "config.yaml", "Path to the configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
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
