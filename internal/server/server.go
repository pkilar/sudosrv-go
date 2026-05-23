// SPDX-License-Identifier: Apache-2.0
// Filename: internal/server/server.go
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sudosrv/internal/api"
	"sudosrv/internal/config"
	"sudosrv/internal/connection"
	"sudosrv/internal/metrics"
	"sudosrv/internal/relay"
	"sudosrv/internal/sessions"
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
	// registry tracks active sessions for the optional management API. Always
	// non-nil; reads from a disabled API simply never occur.
	registry *sessions.Registry
	// apiServer is the optional management HTTP server. nil when the API is
	// disabled in config.
	apiServer *api.Server
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
		registry:   sessions.NewRegistry(),
	}
	s.config.Store(cfg)
	if max := cfg.Server.MaxConnections; max > 0 {
		s.connSem = make(chan struct{}, max)
	}
	return s, nil
}

// Start initializes listeners and begins accepting connections. It is
// transactional: every listener (protocol plaintext, protocol TLS, management
// API) is bound synchronously before any accept or serve goroutine is
// spawned. A late bind failure (e.g. management API port already in use)
// therefore cannot leak side effects from a protocol accept loop that had
// already begun handing connections to the session pipeline.
func (s *Server) Start() error {
	cfg := s.config.Load()

	// Phase 1: bind every required listener.
	if cfg.Server.ListenAddress != "" {
		plainListener, err := net.Listen("tcp", cfg.Server.ListenAddress)
		if err != nil {
			return fmt.Errorf("failed to start plaintext listener on %s: %w", cfg.Server.ListenAddress, err)
		}
		s.listeners = append(s.listeners, plainListener)
	}

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
	}

	if len(s.listeners) == 0 {
		return fmt.Errorf("no listeners configured, server not started")
	}

	if cfg.API.ListenAddress != "" {
		apiSrv, err := api.NewServer(cfg.API, s.registry)
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("failed to create management API: %w", err)
		}
		if err := apiSrv.Listen(); err != nil {
			s.closeListeners()
			return fmt.Errorf("failed to start management API: %w", err)
		}
		s.apiServer = apiSrv
	}

	// Phase 2: every listener is bound — start serving.
	plaintextAddr := cfg.Server.ListenAddress
	tlsAddr := cfg.Server.ListenAddressTLS
	for _, l := range s.listeners {
		s.waitGroup.Add(1)
		go s.acceptLoop(l)
	}
	if plaintextAddr != "" {
		slog.Info("Started plaintext listener", "address", plaintextAddr)
	}
	if tlsAddr != "" {
		slog.Info("Started TLS listener", "address", tlsAddr)
	}
	if s.apiServer != nil {
		s.waitGroup.Go(func() {
			if err := s.apiServer.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("Management API server exited with error", "error", err)
			}
		})
		slog.Info("Started management API",
			"address", s.apiServer.Addr(),
			"tls", cfg.API.TLSCertFile != "")
	}

	// Phase 3: ancillary goroutines under the server's lifecycle so shutdown
	// cancels them cleanly.
	s.waitGroup.Add(1)
	go s.logMetricsPeriodically()

	if cfg.Server.Mode == "relay" {
		s.waitGroup.Go(func() {
			if err := relay.RecoverOrphans(s.ctx, &cfg.Relay); err != nil {
				slog.Error("Orphan relay recovery reported errors", "error", err)
			}
		})
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
				// Brief backoff to avoid tight error loop on transient failures.
				// Honour ctx so shutdown is not held up for 100ms per accept loop.
				select {
				case <-s.ctx.Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
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
			handler := connection.NewHandlerWithContext(s.ctx, conn, s.config.Load(), s.registry)
			handler.Handle()
			slog.Debug("Connection handler finished", "remote_addr", conn.RemoteAddr())
		}()
	}
}

// Wait blocks until the server is shut down.
// SIGHUP triggers a config reload; SIGINT/SIGTERM trigger graceful shutdown.
//
// shutdownTimeout caps the time spent waiting for goroutines after shutdown is
// signalled. A wedged handler (slow client, stuck syscall) cannot then block
// the process from exiting; the timeout fires and we return with a warning so
// the surrounding process supervisor can take over. Zero disables the cap and
// blocks indefinitely.
func (s *Server) Wait(shutdownTimeout time.Duration) {
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

	// Stop the management API first so callers see a clean refusal rather than
	// a stale snapshot of sessions that are about to tear down. http.Server.Shutdown
	// drains in-flight requests but stops accepting new ones immediately.
	if s.apiServer != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := s.apiServer.Shutdown(shutCtx); err != nil {
			slog.Error("Management API shutdown error", "error", err)
		}
		cancel()
	}

	// Close all listeners to unblock acceptLoop
	for _, l := range s.listeners {
		if err := l.Close(); err != nil {
			slog.Error("Failed to close listener", "address", l.Addr(), "error", err)
		}
	}

	// Wait for all goroutines to finish, bounded by shutdownTimeout.
	done := make(chan struct{})
	go func() {
		s.waitGroup.Wait()
		close(done)
	}()
	if shutdownTimeout <= 0 {
		<-done
		return
	}
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		slog.Warn("Shutdown timeout exceeded; some goroutines did not exit cleanly",
			"timeout", shutdownTimeout,
			"active_connections", metrics.Global.GetActiveConnections(),
			"active_sessions", metrics.Global.GetActiveSessions())
	}
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
	case oldCfg.API.ListenAddress != newCfg.API.ListenAddress:
		return fmt.Sprintf("api.listen_address changed from %q to %q", oldCfg.API.ListenAddress, newCfg.API.ListenAddress)
	case oldCfg.API.AuthToken != newCfg.API.AuthToken:
		return "api.auth_token changed"
	case oldCfg.API.AuthTokenFile != newCfg.API.AuthTokenFile:
		return "api.auth_token_file changed"
	case oldCfg.API.TLSCertFile != newCfg.API.TLSCertFile:
		return "api.tls_cert_file changed"
	case oldCfg.API.TLSKeyFile != newCfg.API.TLSKeyFile:
		return "api.tls_key_file changed"
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
