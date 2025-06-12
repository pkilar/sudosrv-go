// Filename: internal/server/server.go
package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sudosrv/internal/config"
	"sudosrv/internal/connection"
	"sync"
	"syscall"
)

// Server manages listeners and handles graceful shutdown.
type Server struct {
	config    *config.Config
	waitGroup sync.WaitGroup
	listeners []net.Listener
	quit      chan struct{}
}

// NewServer creates a new server instance.
func NewServer(cfg *config.Config) (*Server, error) {
	return &Server{
		config:    cfg,
		listeners: make([]net.Listener, 0),
		quit:      make(chan struct{}),
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

	return nil
}

// acceptLoop continuously accepts new connections on a listener.
func (s *Server) acceptLoop(listener net.Listener) {
	defer s.waitGroup.Done()
	for {
		select {
		case <-s.quit:
			slog.Info("Stopping accept loop", "address", listener.Addr())
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			// Check if the error is due to the listener being closed.
			select {
			case <-s.quit:
				return // Normal shutdown
			default:
				slog.Error("Failed to accept connection", "error", err)
			}
			continue
		}
		slog.Info("Accepted new connection", "remote_addr", conn.RemoteAddr(), "local_addr", conn.LocalAddr())

		s.waitGroup.Add(1)
		go func() {
			defer s.waitGroup.Done()
			slog.Debug("Starting connection handler", "remote_addr", conn.RemoteAddr())
			handler := connection.NewHandler(conn, s.config)
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
