// Filename: cmd/sudosrv/main.go
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/config"
	"sudosrv/internal/relay"
	"sudosrv/internal/server"
	"time"
)

const (
	// Application metadata
	appName    = "sudosrv"
	appVersion = "1.0.0"

	// Exit codes following standard conventions
	exitSuccess = 0
	exitFailure = 1
	exitConfig  = 2
	exitServer  = 3

	// Timeouts
	shutdownTimeout = 30 * time.Second
)

// Error types for structured exit code classification.
// Using errors.As instead of string matching for reliable error categorization.

type configError struct{ err error }

func (e *configError) Error() string { return e.err.Error() }
func (e *configError) Unwrap() error { return e.err }

type serverError struct{ err error }

func (e *serverError) Error() string { return e.err.Error() }
func (e *serverError) Unwrap() error { return e.err }

// CommandLineFlags encapsulates all command-line arguments
type CommandLineFlags struct {
	ConfigFile *string
	Version    *bool
	Help       *bool
	LogLevel   *string
	DryRun     *bool
	Validate   *bool
}

func main() {
	// Parse command-line flags with enhanced options
	flags := parseCommandLineFlags()

	// Handle version and help flags early
	if *flags.Version {
		fmt.Printf("%s version %s\n", appName, appVersion)
		os.Exit(exitSuccess)
	}

	if *flags.Help {
		flag.Usage()
		os.Exit(exitSuccess)
	}

	// Initialize application with proper error handling
	if err := runApplication(flags); err != nil {
		handleApplicationError(err)
	}
}

// parseCommandLineFlags sets up and parses all command-line flags
func parseCommandLineFlags() *CommandLineFlags {
	flags := &CommandLineFlags{
		ConfigFile: flag.String("config", "config.yaml", "Path to the configuration file"),
		Version:    flag.Bool("version", false, "Show version information and exit"),
		Help:       flag.Bool("help", false, "Show help information and exit"),
		LogLevel:   flag.String("log-level", "", "Override log level (debug, info, warn, error)"),
		DryRun:     flag.Bool("dry-run", false, "Validate configuration and exit without starting server"),
		Validate:   flag.Bool("validate", false, "Validate configuration file and exit"),
	}

	// Customize usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", appName)
		fmt.Fprintf(os.Stderr, "%s - A sudo session logging server\n\n", appName)
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -config /etc/sudosrv/config.yaml\n", appName)
		fmt.Fprintf(os.Stderr, "  %s -validate -config config.yaml\n", appName)
		fmt.Fprintf(os.Stderr, "  %s -dry-run -log-level debug\n", appName)
	}

	flag.Parse()
	return flags
}

// runApplication contains the main application logic with proper error handling
func runApplication(flags *CommandLineFlags) error {
	// Load and validate configuration
	cfg, err := loadAndValidateConfig(*flags.ConfigFile)
	if err != nil {
		return &configError{err: fmt.Errorf("configuration error: %w", err)}
	}

	// Handle validation-only mode
	if *flags.Validate {
		fmt.Printf("Configuration file %s is valid\n", *flags.ConfigFile)
		return nil
	}

	// Setup structured logging with enhanced configuration
	logLevel, err := setupStructuredLogging(cfg, *flags.LogLevel)
	if err != nil {
		return &configError{err: fmt.Errorf("logging setup error: %w", err)}
	}

	slog.Info("Application starting",
		"app", appName,
		"version", appVersion,
		"config_file", *flags.ConfigFile,
		"mode", cfg.Server.Mode,
		"log_level", logLevel.Level().String())

	// Handle dry-run mode
	if *flags.DryRun {
		slog.Info("Dry-run mode: configuration validated successfully")
		return nil
	}

	// Initialize relay cache cleanup if in relay mode
	if err := initializeRelayMode(cfg); err != nil {
		return &configError{err: fmt.Errorf("relay initialization error: %w", err)}
	}

	// Create and start the server with proper lifecycle management
	return runServerWithGracefulShutdown(cfg, *flags.ConfigFile, logLevel)
}

// loadAndValidateConfig loads configuration with enhanced error handling
func loadAndValidateConfig(configPath string) (*config.Config, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	// Perform additional validation
	if err := validateConfiguration(cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// validateConfiguration performs comprehensive configuration validation
func validateConfiguration(cfg *config.Config) error {
	// Validate server mode
	if cfg.Server.Mode != "local" && cfg.Server.Mode != "relay" {
		return fmt.Errorf("invalid server mode: %s (must be 'local' or 'relay')", cfg.Server.Mode)
	}

	// Validate listen addresses
	if cfg.Server.ListenAddress == "" && cfg.Server.ListenAddressTLS == "" {
		return errors.New("at least one listen address must be configured")
	}

	// Validate TLS configuration
	if cfg.Server.ListenAddressTLS != "" {
		if cfg.Server.TLSCertFile == "" || cfg.Server.TLSKeyFile == "" {
			return errors.New("TLS certificate and key files must be specified for TLS listener")
		}
	}

	// Validate relay-specific configuration
	if cfg.Server.Mode == "relay" {
		if cfg.Relay.UpstreamHost == "" {
			return errors.New("upstream_host must be configured in relay mode")
		}
		if cfg.Relay.RelayCacheDirectory == "" {
			return errors.New("relay_cache_directory must be configured in relay mode")
		}
	}

	return nil
}

// setupStructuredLogging configures logging with enhanced options.
// Returns a *slog.LevelVar that can be dynamically updated (e.g., on SIGHUP).
func setupStructuredLogging(cfg *config.Config, logLevelOverride string) (*slog.LevelVar, error) {
	// Determine log level with override support
	logLevelStr := cfg.Server.ServerOperationalLogLevel
	if logLevelOverride != "" {
		logLevelStr = logLevelOverride
	}

	parsedLevel, err := parseLogLevel(logLevelStr)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	// Use LevelVar for dynamic log level changes at runtime
	logLevel := new(slog.LevelVar)
	logLevel.Set(parsedLevel)

	// Configure handler options with enhanced formatting
	handlerOpts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: parsedLevel <= slog.LevelDebug, // Add source info for debug level
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.Format(time.RFC3339))
				}
			}
			return a
		},
	}

	// Create and set the logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, handlerOpts))
	slog.SetDefault(logger)

	slog.Info("Structured logging initialized",
		"level", parsedLevel.String(),
		"source_enabled", handlerOpts.AddSource)

	return logLevel, nil
}

// parseLogLevel converts string log level to slog.Level with validation
func parseLogLevel(levelStr string) (slog.Level, error) {
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

// initializeRelayMode handles relay-specific initialization
func initializeRelayMode(cfg *config.Config) error {
	if cfg.Server.Mode != "relay" {
		return nil
	}

	slog.Info("Initializing relay mode", "cache_directory", cfg.Relay.RelayCacheDirectory)

	// Ensure cache directory exists
	if err := os.MkdirAll(cfg.Relay.RelayCacheDirectory, 0750); err != nil {
		return fmt.Errorf("failed to create relay cache directory: %w", err)
	}

	// Start orphaned file cleanup in background
	go func() {
		if err := flushOrphanedRelayFiles(&cfg.Relay); err != nil {
			slog.Error("Failed to flush orphaned relay files", "error", err)
		}
	}()

	return nil
}

// runServerWithGracefulShutdown manages server lifecycle with proper shutdown handling
func runServerWithGracefulShutdown(cfg *config.Config, configPath string, logLevel *slog.LevelVar) error {
	// Create server instance
	srv, err := server.NewServer(cfg, configPath, logLevel)
	if err != nil {
		return &serverError{err: fmt.Errorf("failed to create server: %w", err)}
	}

	// Start server
	if err := srv.Start(); err != nil {
		return &serverError{err: fmt.Errorf("failed to start server: %w", err)}
	}

	slog.Info("Server started successfully")

	// Wait for shutdown signal and handle graceful shutdown
	srv.Wait()

	slog.Info("Server shutdown completed")
	return nil
}

// handleApplicationError provides centralized error handling with appropriate exit codes
func handleApplicationError(err error) {
	var exitCode int

	// Determine appropriate exit code based on error type
	switch {
	case errors.As(err, new(*configError)):
		exitCode = exitConfig
		slog.Error("Configuration error", "error", err)
	case errors.As(err, new(*serverError)):
		exitCode = exitServer
		slog.Error("Server error", "error", err)
	default:
		exitCode = exitFailure
		slog.Error("Application error", "error", err)
	}

	os.Exit(exitCode)
}

// flushOrphanedRelayFiles cleans up orphaned relay cache files with enhanced error handling
func flushOrphanedRelayFiles(cfg *config.RelayConfig) error {
	slog.Info("Scanning for orphaned relay cache files", "directory", cfg.RelayCacheDirectory)

	// Use more specific pattern and handle potential errors
	pattern := filepath.Join(cfg.RelayCacheDirectory, "*.log")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to scan relay cache directory %s: %w", cfg.RelayCacheDirectory, err)
	}

	if len(files) == 0 {
		slog.Info("No orphaned relay files found")
		return nil
	}

	slog.Info("Found orphaned relay files", "count", len(files))

	// Process files with controlled concurrency and error tracking
	const maxConcurrentFlushes = 5
	semaphore := make(chan struct{}, maxConcurrentFlushes)
	errChan := make(chan error, len(files))

	for _, file := range files {
		go func(filename string) {
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			slog.Debug("Flushing orphaned relay file", "file", filename)
			relay.FlushOrphanedFile(filename, cfg)
			errChan <- nil
		}(file)
	}

	// Wait for all operations to complete and collect errors
	var errors []error
	for i := 0; i < len(files); i++ {
		if err := <-errChan; err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		slog.Warn("Some orphaned relay files could not be flushed", "error_count", len(errors))
		// Return first error for simplicity, but log all
		return errors[0]
	}

	slog.Info("Successfully flushed all orphaned relay files", "count", len(files))
	return nil
}
