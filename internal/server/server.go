// Filename: internal/server/server.go
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sudosrv/internal/config"
	"sudosrv/internal/connection"
	"sudosrv/internal/metrics"
	"sudosrv/internal/relay"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Server manages listeners and handles graceful shutdown.
type Server struct {
	config     atomic.Pointer[config.Config]
	configPath string
	logLevel   *slog.LevelVar
	waitGroup  sync.WaitGroup
	listeners  []net.Listener
	ctx        context.Context
	cancel     context.CancelFunc
	// connSem is a counting semaphore that caps the number of concurrent client
	// connections. nil when unbounded (MaxConnections <= 0).
	connSem chan struct{}
}

// NewServer creates a new server instance.
// configPath is the path to the config file (used for SIGHUP reload).
// logLevel is the dynamic log level that can be updated at runtime.
func NewServer(cfg *config.Config, configPath string, logLevel *slog.LevelVar) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		configPath: configPath,
		logLevel:   logLevel,
		listeners:  make([]net.Listener, 0),
		ctx:        ctx,
		cancel:     cancel,
	}
	s.config.Store(cfg)
	if max := cfg.Server.MaxConnections; max > 0 {
		s.connSem = make(chan struct{}, max)
	}
	return s, nil
}

// Start initializes listeners and begins accepting connections.
func (s *Server) Start() error {
	cfg := s.config.Load()

	// Start plaintext listener if configured
	if cfg.Server.ListenAddress != "" {
		plainListener, err := net.Listen("tcp", cfg.Server.ListenAddress)
		if err != nil {
			return fmt.Errorf("failed to start plaintext listener on %s: %w", cfg.Server.ListenAddress, err)
		}
		s.listeners = append(s.listeners, plainListener)
		s.waitGroup.Add(1)
		go s.acceptLoop(plainListener)
		slog.Info("Started plaintext listener", "address", cfg.Server.ListenAddress)
	}

	// Start TLS listener if configured
	if cfg.Server.ListenAddressTLS != "" {
		if cfg.Server.TLSCertFile == "" || cfg.Server.TLSKeyFile == "" {
			s.closeListeners()
			return fmt.Errorf("tls_cert_file and tls_key_file must be configured for TLS listener")
		}
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("failed to load TLS key pair: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}

		tlsListener, err := tls.Listen("tcp", cfg.Server.ListenAddressTLS, tlsConfig)
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("failed to start TLS listener on %s: %w", cfg.Server.ListenAddressTLS, err)
		}
		s.listeners = append(s.listeners, tlsListener)
		s.waitGroup.Add(1)
		go s.acceptLoop(tlsListener)
		slog.Info("Started TLS listener", "address", cfg.Server.ListenAddressTLS)
	}

	if len(s.listeners) == 0 {
		return fmt.Errorf("no listeners configured, server not started")
	}

	// Start metrics logging goroutine
	s.waitGroup.Add(1)
	go s.logMetricsPeriodically()

	// Kick off orphan recovery for relay mode under the server's lifecycle
	// so shutdown cancels any in-flight flush and waits for it to unwind.
	if cfg.Server.Mode == "relay" {
		s.waitGroup.Add(1)
		go func() {
			defer s.waitGroup.Done()
			if err := relay.RecoverOrphans(s.ctx, &cfg.Relay); err != nil {
				slog.Error("Orphan relay recovery reported errors", "error", err)
			}
		}()
	}

	return nil
}

// closeListeners closes all currently open listeners. Used during Start()
// cleanup if a later listener bind fails.
func (s *Server) closeListeners() {
	for _, l := range s.listeners {
		if err := l.Close(); err != nil {
			slog.Error("Failed to close listener during cleanup", "address", l.Addr(), "error", err)
		}
	}
	s.listeners = s.listeners[:0]
}

// acceptLoop continuously accepts new connections on a listener.
func (s *Server) acceptLoop(listener net.Listener) {
	defer s.waitGroup.Done()
	for {
		select {
		case <-s.ctx.Done():
			slog.Info("Stopping accept loop", "address", listener.Addr())
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			// Check if the error is due to the listener being closed.
			select {
			case <-s.ctx.Done():
				return // Context cancelled, listener was closed
			default:
				metrics.Global.IncrementFailedConnections()
				slog.Error("Failed to accept connection", "error", err, "failed_connections", metrics.Global.GetFailedConnections())
				// Brief backoff to avoid tight error loop on transient failures
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}

		// Enforce the connection cap, if configured. We attempt a non-blocking
		// acquire first so an oversubscribed server rejects the connection
		// immediately rather than queueing and tying up the peer's socket.
		if s.connSem != nil {
			select {
			case s.connSem <- struct{}{}:
			default:
				metrics.Global.IncrementFailedConnections()
				slog.Warn("Connection limit reached, rejecting new connection",
					"remote_addr", conn.RemoteAddr(),
					"limit", cap(s.connSem),
					"failed_connections", metrics.Global.GetFailedConnections())
				_ = conn.Close()
				continue
			}
		}
		metrics.Global.IncrementConnections()
		slog.Info("Accepted new connection", "remote_addr", conn.RemoteAddr(), "local_addr", conn.LocalAddr(),
			"total_connections", metrics.Global.GetTotalConnections(), "active_connections", metrics.Global.GetActiveConnections())

		s.waitGroup.Add(1)
		go func() {
			defer func() {
				if s.connSem != nil {
					<-s.connSem
				}
				s.waitGroup.Done()
				metrics.Global.DecrementActiveConnections()
			}()
			slog.Debug("Starting connection handler", "remote_addr", conn.RemoteAddr())
			handler := connection.NewHandlerWithContext(s.ctx, conn, s.config.Load())
			handler.Handle()
			slog.Debug("Connection handler finished", "remote_addr", conn.RemoteAddr())
		}()
	}
}

// Wait blocks until the server is shut down.
// SIGHUP triggers a config reload; SIGINT/SIGTERM trigger graceful shutdown.
func (s *Server) Wait() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)

	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			slog.Info("SIGHUP received, reloading configuration...")
			s.reload()
			continue
		}

		// SIGINT or SIGTERM — initiate graceful shutdown
		slog.Info("Shutdown signal received, closing listeners...", "signal", sig)
		break
	}

	// Cancel context to signal all goroutines to stop
	s.cancel()

	// Close all listeners to unblock acceptLoop
	for _, l := range s.listeners {
		if err := l.Close(); err != nil {
			slog.Error("Failed to close listener", "address", l.Addr(), "error", err)
		}
	}

	// Wait for all goroutines to finish
	s.waitGroup.Wait()
}

// reload re-reads the configuration file and applies changes that can be
// updated at runtime. New connections pick up the updated config; existing
// connections continue with the config they were created with.
func (s *Server) reload() {
	newCfg, err := config.LoadConfigRequired(s.configPath)
	if err != nil {
		slog.Error("Config reload failed: could not load config", "path", s.configPath, "error", err)
		return
	}
	if err := config.Validate(newCfg); err != nil {
		slog.Error("Config reload rejected: validation failed; keeping previous config", "path", s.configPath, "error", err)
		return
	}

	oldCfg := s.config.Load()
	if reason := restartRequiredReloadChange(oldCfg, newCfg); reason != "" {
		slog.Error("Config reload rejected: change requires restart; keeping previous config",
			"path", s.configPath,
			"reason", reason)
		return
	}

	// Update log level dynamically
	if s.logLevel != nil {
		newLevelStr := newCfg.Server.ServerOperationalLogLevel
		if newLevelStr == "" {
			newLevelStr = "info"
		}
		newLevel, err := config.ParseLogLevel(newLevelStr)
		if err != nil {
			slog.Error("Config reload: invalid log level, keeping current", "level", newLevelStr, "error", err)
		} else if s.logLevel.Level() != newLevel {
			oldLevel := s.logLevel.Level()
			s.logLevel.Set(newLevel)
			slog.Info("Config reload: log level changed", "old", oldLevel.String(), "new", newLevel.String())
		}
	}

	// Update config pointer — new connections will use the new config
	s.config.Store(newCfg)

	slog.Info("Config reload complete", "path", s.configPath)
}

func restartRequiredReloadChange(oldCfg, newCfg *config.Config) string {
	switch {
	case oldCfg.Server.Mode != newCfg.Server.Mode:
		return fmt.Sprintf("server.mode changed from %q to %q", oldCfg.Server.Mode, newCfg.Server.Mode)
	case oldCfg.Server.ListenAddress != newCfg.Server.ListenAddress:
		return fmt.Sprintf("server.listen_address changed from %q to %q", oldCfg.Server.ListenAddress, newCfg.Server.ListenAddress)
	case oldCfg.Server.ListenAddressTLS != newCfg.Server.ListenAddressTLS:
		return fmt.Sprintf("server.listen_address_tls changed from %q to %q", oldCfg.Server.ListenAddressTLS, newCfg.Server.ListenAddressTLS)
	case oldCfg.Server.TLSCertFile != newCfg.Server.TLSCertFile:
		return "server.tls_cert_file changed"
	case oldCfg.Server.TLSKeyFile != newCfg.Server.TLSKeyFile:
		return "server.tls_key_file changed"
	case oldCfg.Server.MaxConnections != newCfg.Server.MaxConnections:
		return fmt.Sprintf("server.max_connections changed from %d to %d", oldCfg.Server.MaxConnections, newCfg.Server.MaxConnections)
	default:
		return ""
	}
}

// logMetricsPeriodically logs server metrics every 5 minutes for operational visibility.
func (s *Server) logMetricsPeriodically() {
	defer s.waitGroup.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			slog.Info("Stopping metrics logging")
			return
		case <-ticker.C:
			slog.Info("Server metrics",
				"uptime", metrics.Global.GetUptime().String(),
				"total_connections", metrics.Global.GetTotalConnections(),
				"active_connections", metrics.Global.GetActiveConnections(),
				"failed_connections", metrics.Global.GetFailedConnections(),
				"total_sessions", metrics.Global.GetTotalSessions(),
				"active_sessions", metrics.Global.GetActiveSessions(),
				"local_sessions", metrics.Global.GetLocalSessions(),
				"relay_sessions", metrics.Global.GetRelaySessions(),
				"messages_processed", metrics.Global.GetMessagesProcessed(),
				"message_errors", metrics.Global.GetMessageErrors(),
			)
		}
	}
}
