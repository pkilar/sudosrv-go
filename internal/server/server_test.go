// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/config"
	"sudosrv/internal/metrics"
	"testing"
	"time"
)

// generateSelfSignedCert writes a fresh self-signed cert+key pair to t.TempDir
// and returns the file paths. Valid for one hour; SAN includes 127.0.0.1
// and localhost so dialers can verify with InsecureSkipVerify=false if desired.
func generateSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("encode cert pem: %v", err)
	}
	certFile.Close()
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encode key pem: %v", err)
	}
	keyFile.Close()
	return certPath, keyPath
}

// shutdown drives the post-signal portion of Server.Wait so tests can run
// the full lifecycle without going through signal delivery. Bounds the
// final waitGroup.Wait so a flaky test cannot hang the runner indefinitely.
func shutdown(srv *Server) {
	srv.cancel()
	if srv.apiServer != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.apiServer.Shutdown(shutCtx)
		cancel()
	}
	for _, l := range srv.listeners {
		_ = l.Close()
	}
	done := make(chan struct{})
	go func() { srv.waitGroup.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		// A regression in shutdown wiring would otherwise pin the test
		// process. Print rather than t.Fatal because shutdown is also
		// called from t.Cleanup paths where t.Fatal is a no-op.
		fmt.Fprintln(os.Stderr, "test shutdown timed out waiting for goroutines")
	}
}

func newTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelInfo)
	srv, err := NewServer(cfg, "", logLevel)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func TestNewServer_ConnSemaphoreCreation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		maxConnections int
		wantSemNil     bool
		wantSemCap     int
	}{
		{"unbounded with zero", 0, true, 0},
		{"unbounded with negative", -1, true, 0},
		{"bounded", 100, false, 100},
		{"bounded small", 1, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{
				Server: config.ServerConfig{
					Mode:           "local",
					ListenAddress:  "127.0.0.1:0",
					MaxConnections: tt.maxConnections,
				},
			}
			srv := newTestServer(t, cfg)
			t.Cleanup(srv.cancel)
			if tt.wantSemNil {
				if srv.connSem != nil {
					t.Errorf("connSem: got non-nil for MaxConnections=%d, want nil", tt.maxConnections)
				}
			} else {
				if srv.connSem == nil {
					t.Fatalf("connSem: got nil, want capacity %d", tt.wantSemCap)
				}
				if got := cap(srv.connSem); got != tt.wantSemCap {
					t.Errorf("connSem cap: got %d, want %d", got, tt.wantSemCap)
				}
			}
		})
	}
}

func TestStart_NoListeners(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{Mode: "local"},
	})
	defer shutdown(srv)

	err := srv.Start()
	if err == nil {
		t.Fatal("Start: want error, got nil")
	}
	if got := err.Error(); !strings.Contains(got,"no listeners configured") {
		t.Errorf("Start error: got %q, want contains 'no listeners configured'", got)
	}
}

func TestStart_TLSWithoutCertKey(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:             "local",
			ListenAddressTLS: "127.0.0.1:0",
		},
	})
	defer shutdown(srv)

	err := srv.Start()
	if err == nil {
		t.Fatal("Start: want error, got nil")
	}
	if got := err.Error(); !strings.Contains(got,"tls_cert_file") {
		t.Errorf("Start error: got %q, want contains 'tls_cert_file'", got)
	}
	if len(srv.listeners) != 0 {
		t.Errorf("listeners after failed Start: got %d, want 0", len(srv.listeners))
	}
}

func TestStart_TLSBadCertPath(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:             "local",
			ListenAddressTLS: "127.0.0.1:0",
			TLSCertFile:      "/nonexistent/cert.pem",
			TLSKeyFile:       "/nonexistent/key.pem",
		},
	})
	defer shutdown(srv)

	err := srv.Start()
	if err == nil {
		t.Fatal("Start: want error, got nil")
	}
	if got := err.Error(); !strings.Contains(got,"TLS key pair") {
		t.Errorf("Start error: got %q, want contains 'TLS key pair'", got)
	}
}

// TestStart_APIBindFailure asserts that a port-already-in-use on the API
// listener is reported synchronously from Start, not silently swallowed by
// the background Serve goroutine.
func TestStart_APIBindFailure(t *testing.T) {
	t.Parallel()
	// Pre-bind a port and keep it bound so the API server's Listen fails.
	pre, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind: %v", err)
	}
	defer pre.Close()

	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:          "local",
			ListenAddress: "127.0.0.1:0",
		},
		LocalStorage: config.LocalStorageConfig{
			LogDirectory:    t.TempDir(),
			DirPermissions:  0750,
			FilePermissions: 0640,
		},
		API: config.APIConfig{
			ListenAddress: pre.Addr().String(),
			AuthToken:     "secret",
		},
	})
	defer shutdown(srv)

	err = srv.Start()
	if err == nil {
		t.Fatal("Start: want error, got nil")
	}
	if got := err.Error(); !strings.Contains(got,"management API") {
		t.Errorf("Start error: got %q, want contains 'management API'", got)
	}
	if srv.apiServer != nil {
		t.Errorf("apiServer should not be set after a failed bind; got %#v", srv.apiServer)
	}
	if len(srv.listeners) != 0 {
		t.Errorf("protocol listeners should be closed after API bind failure; got %d", len(srv.listeners))
	}
}

// TestStart_APITLSFailure asserts that an invalid API TLS keypair is reported
// synchronously from Start.
func TestStart_APITLSFailure(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:          "local",
			ListenAddress: "127.0.0.1:0",
		},
		LocalStorage: config.LocalStorageConfig{
			LogDirectory:    t.TempDir(),
			DirPermissions:  0750,
			FilePermissions: 0640,
		},
		API: config.APIConfig{
			ListenAddress: "127.0.0.1:0",
			AuthToken:     "secret",
			TLSCertFile:   "/nonexistent/api.crt",
			TLSKeyFile:    "/nonexistent/api.key",
		},
	})
	defer shutdown(srv)

	err := srv.Start()
	if err == nil {
		t.Fatal("Start: want error, got nil")
	}
	if got := err.Error(); !strings.Contains(got,"management API") {
		t.Errorf("Start error: got %q, want contains 'management API'", got)
	}
}

func TestStart_PlainListenerLifecycle(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:          "local",
			ListenAddress: "127.0.0.1:0",
			IdleTimeout:   5 * time.Second,
		},
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer shutdown(srv)

	if len(srv.listeners) != 1 {
		t.Fatalf("listeners: got %d, want 1", len(srv.listeners))
	}
	addr := srv.listeners[0].Addr().String()

	// Verify the listener is actually accepting.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
}

func TestStart_TLSListenerLifecycle(t *testing.T) {
	t.Parallel()
	certPath, keyPath := generateSelfSignedCert(t)
	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:             "local",
			ListenAddressTLS: "127.0.0.1:0",
			TLSCertFile:      certPath,
			TLSKeyFile:       keyPath,
			IdleTimeout:      5 * time.Second,
		},
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer shutdown(srv)

	if len(srv.listeners) != 1 {
		t.Fatalf("listeners: got %d, want 1", len(srv.listeners))
	}
	addr := srv.listeners[0].Addr().String()

	// TLS dial; self-signed cert so we skip verification.
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.DialWithDialer: %v", err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	conn.Close()
}

func TestStart_BothListeners(t *testing.T) {
	t.Parallel()
	certPath, keyPath := generateSelfSignedCert(t)
	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:             "local",
			ListenAddress:    "127.0.0.1:0",
			ListenAddressTLS: "127.0.0.1:0",
			TLSCertFile:      certPath,
			TLSKeyFile:       keyPath,
			IdleTimeout:      5 * time.Second,
		},
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer shutdown(srv)

	if got := len(srv.listeners); got != 2 {
		t.Fatalf("listeners: got %d, want 2", got)
	}
}

func TestAcceptLoop_RejectsOverCap(t *testing.T) {
	// Mutates Global metrics; not parallel.
	metrics.Global.Reset()
	t.Cleanup(metrics.Global.Reset)

	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:           "local",
			ListenAddress:  "127.0.0.1:0",
			MaxConnections: 1,
			IdleTimeout:    30 * time.Second, // hold the slot long enough for the second dial
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer shutdown(srv)

	addr := srv.listeners[0].Addr().String()

	// First connection: accepted, semaphore taken. Hold it open so the
	// connection-handler goroutine keeps the slot.
	first, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("first Dial: %v", err)
	}
	defer first.Close()

	// Wait until the handler has actually accepted (semaphore taken).
	deadline := time.Now().Add(2 * time.Second)
	for metrics.Global.GetTotalConnections() < 1 && time.Now().Before(deadline) {
		runtimeYield()
	}
	if metrics.Global.GetTotalConnections() != 1 {
		t.Fatalf("first connection not accepted in time; total=%d", metrics.Global.GetTotalConnections())
	}

	// Second connection: TCP completes, but server should close immediately
	// because the semaphore is full.
	second, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("second Dial: %v", err)
	}
	defer second.Close()

	// Read should return EOF (or a closed-connection error) shortly.
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	_, err = second.Read(buf)
	if err == nil {
		t.Errorf("read on rejected connection: got nil error, want EOF/close")
	} else if !errors.Is(err, io.EOF) {
		// Some platforms surface this as a different error (e.g., ECONNRESET);
		// any non-nil read error is acceptable, just not nil/timeout.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Errorf("read on rejected connection timed out; expected close")
		}
	}

	// Server should have counted exactly one accepted, one failed.
	if got := metrics.Global.GetTotalConnections(); got != 1 {
		t.Errorf("TotalConnections: got %d, want 1", got)
	}
	if got := metrics.Global.GetFailedConnections(); got < 1 {
		t.Errorf("FailedConnections: got %d, want >= 1", got)
	}
}

func TestReload_RejectsInvalidConfig(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	initial := `server:
  mode: "local"
  listen_address: "127.0.0.1:0"
  server_id: "Initial"
local_storage:
  log_directory: "/tmp/x"
`
	if err := os.WriteFile(configPath, []byte(initial), 0600); err != nil {
		t.Fatalf("write initial: %v", err)
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	logLevel := new(slog.LevelVar)
	srv, err := NewServer(cfg, configPath, logLevel)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.cancel)

	// Now write a config with an invalid mode so Validate fails. (We can't
	// test "no listen address" because LoadConfig fills in the default.)
	invalid := `server:
  mode: "magic"
  listen_address: "127.0.0.1:0"
local_storage:
  log_directory: "/tmp/x"
`
	if err := os.WriteFile(configPath, []byte(invalid), 0600); err != nil {
		t.Fatalf("write invalid: %v", err)
	}
	srv.reload()

	// Original config (with ServerID "Initial") must still be in place.
	if got := srv.config.Load().Server.ServerID; got != "Initial" {
		t.Errorf("ServerID after rejected reload: got %q, want %q", got, "Initial")
	}
}

func TestReload_LoadFailureKeepsOldConfig(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	initial := `server:
  mode: "local"
  listen_address: "127.0.0.1:0"
  server_id: "Initial"
local_storage:
  log_directory: "/tmp/x"
`
	if err := os.WriteFile(configPath, []byte(initial), 0600); err != nil {
		t.Fatalf("write initial: %v", err)
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	srv, err := NewServer(cfg, configPath, new(slog.LevelVar))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.cancel)

	// Replace file content with malformed YAML.
	malformed := "server:\n  listen_address: [a, b\n  not yaml"
	if err := os.WriteFile(configPath, []byte(malformed), 0600); err != nil {
		t.Fatalf("write malformed: %v", err)
	}
	srv.reload()

	if got := srv.config.Load().Server.ServerID; got != "Initial" {
		t.Errorf("ServerID after load failure: got %q, want %q", got, "Initial")
	}
}

// --- existing reload coverage ---

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
	t.Cleanup(srv.cancel)

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
		beforeCfg := srv.config.Load()

		srv.reload()

		if logLevel.Level() != slog.LevelError {
			t.Errorf("Expected log level ERROR to remain after missing config reload, got %s", logLevel.Level())
		}
		if got := srv.config.Load(); got != beforeCfg {
			t.Error("Expected missing config reload to keep previous config pointer")
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

func TestReload_RejectsRestartRequiredChanges(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	initial := `server:
  mode: "local"
  listen_address: "127.0.0.1:30343"
  server_id: "Initial"
  max_connections: 10
local_storage:
  log_directory: "/tmp/test-logs"
`
	if err := os.WriteFile(configPath, []byte(initial), 0600); err != nil {
		t.Fatalf("write initial: %v", err)
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	tests := []struct {
		name   string
		update string
	}{
		{
			name: "mode",
			update: `server:
  mode: "relay"
  listen_address: "127.0.0.1:30343"
  server_id: "Changed"
  max_connections: 10
relay:
  upstream_host: "127.0.0.1:30344"
  relay_cache_directory: "/tmp/cache"
local_storage:
  log_directory: "/tmp/test-logs"
`,
		},
		{
			name: "listen address",
			update: `server:
  mode: "local"
  listen_address: "127.0.0.1:40404"
  server_id: "Changed"
  max_connections: 10
local_storage:
  log_directory: "/tmp/test-logs"
`,
		},
		{
			name: "max connections",
			update: `server:
  mode: "local"
  listen_address: "127.0.0.1:30343"
  server_id: "Changed"
  max_connections: 20
local_storage:
  log_directory: "/tmp/test-logs"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logLevel := new(slog.LevelVar)
			srv, err := NewServer(cfg, configPath, logLevel)
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			t.Cleanup(srv.cancel)

			if err := os.WriteFile(configPath, []byte(tt.update), 0600); err != nil {
				t.Fatalf("write update: %v", err)
			}
			srv.reload()

			loaded := srv.config.Load()
			if loaded.Server.ServerID != "Initial" {
				t.Errorf("ServerID after rejected reload: got %q, want Initial", loaded.Server.ServerID)
			}
		})
	}
}

// --- tiny helpers (kept private to this test file) ---

// runtimeYield gives the runtime a brief moment between polls.
func runtimeYield() {
	time.Sleep(time.Millisecond)
}
