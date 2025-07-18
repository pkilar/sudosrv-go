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
	"sync"
	"syscall"
	"time"
)

// Server manages listeners and handles graceful shutdown.
type Server struct {
	config    *config.Config
	waitGroup sync.WaitGroup
	listeners []net.Listener
	quit      chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewServer creates a new server instance.
func NewServer(cfg *config.Config) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		config:    cfg,
		listeners: make([]net.Listener, 0),
		quit:      make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// Start initializes listeners and begins accepting connections.
func (s *Server) Start() error {

	// Start plaintext listener if configured
	if s.config.Server.ListenAddress != "" {
		plainListener, err := net.Listen("tcp", s.config.Server.ListenAddress)
		if err != nil {
			return fmt.Errorf("failed to start plaintext listener on %s: %w", s.config.Server.ListenAddress, err)
		}
		s.listeners = append(s.listeners, plainListener)
		s.waitGroup.Add(1)
		go s.acceptLoop(plainListener)
		slog.Info("Started plaintext listener", "address", s.config.Server.ListenAddress)
	}

	// Start TLS listener if configured
	if s.config.Server.ListenAddressTLS != "" {
		if s.config.Server.TLSCertFile == "" || s.config.Server.TLSKeyFile == "" {
			return fmt.Errorf("tls_cert_file and tls_key_file must be configured for TLS listener")
		}
		cert, err := tls.LoadX509KeyPair(s.config.Server.TLSCertFile, s.config.Server.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS key pair: %w", err)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

		tlsListener, err := tls.Listen("tcp", s.config.Server.ListenAddressTLS, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to start TLS listener on %s: %w", s.config.Server.ListenAddressTLS, err)
		}
		s.listeners = append(s.listeners, tlsListener)
		s.waitGroup.Add(1)
		go s.acceptLoop(tlsListener)
		slog.Info("Started TLS listener", "address", s.config.Server.ListenAddressTLS)
	}

	if len(s.listeners) == 0 {
		return fmt.Errorf("no listeners configured, server not started")
	}

	// Start metrics logging goroutine
	s.waitGroup.Add(1)
	go s.logMetricsPeriodically()

	return nil
}

// acceptLoop continuously accepts new connections on a listener.
func (s *Server) acceptLoop(listener net.Listener) {
	defer s.waitGroup.Done()
	for {
		select {
		case <-s.ctx.Done():
			slog.Info("Stopping accept loop due to context cancellation", "address", listener.Addr())
			return
		case <-s.quit:
			slog.Info("Stopping accept loop", "address", listener.Addr())
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			// Check if the error is due to the listener being closed.
			select {
			case <-s.ctx.Done():
				return // Context cancelled
			case <-s.quit:
				return // Normal shutdown
			default:
				metrics.Global.IncrementFailedConnections()
				slog.Error("Failed to accept connection", "error", err, "failed_connections", metrics.Global.GetFailedConnections())
			}
			continue
		}
		metrics.Global.IncrementConnections()
		slog.Info("Accepted new connection", "remote_addr", conn.RemoteAddr(), "local_addr", conn.LocalAddr(),
			"total_connections", metrics.Global.GetTotalConnections(), "active_connections", metrics.Global.GetActiveConnections())

		s.waitGroup.Add(1)
		go func() {
			defer func() {
				s.waitGroup.Done()
				metrics.Global.DecrementActiveConnections()
			}()
			slog.Debug("Starting connection handler", "remote_addr", conn.RemoteAddr())
			handler := connection.NewHandlerWithContext(s.ctx, conn, s.config)
			handler.Handle()
			slog.Debug("Connection handler finished", "remote_addr", conn.RemoteAddr())
		}()
	}
}

// Wait blocks until the server is shut down.
func (s *Server) Wait() {
	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	slog.Info("Shutdown signal received, closing listeners...")

	// Cancel context to signal all goroutines to stop
	s.cancel()

	// Signal goroutines to stop
	close(s.quit)

	// Close all listeners to unblock acceptLoop
	for _, l := range s.listeners {
		if err := l.Close(); err != nil {
			slog.Error("Failed to close listener", "address", l.Addr(), "error", err)
		}
	}

	// Wait for all goroutines to finish
	s.waitGroup.Wait()
}

// logMetricsPeriodically logs server metrics every 5 minutes for operational visibility.
func (s *Server) logMetricsPeriodically() {
	defer s.waitGroup.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			slog.Info("Stopping metrics logging due to context cancellation")
			return
		case <-s.quit:
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
