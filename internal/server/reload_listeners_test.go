// SPDX-License-Identifier: Apache-2.0
// Filename: internal/server/reload_listeners_test.go
package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"testing"
	"time"
)

// freeTCPPort returns a port that was bindable a moment ago.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// reloadTestServer starts a plaintext-only server on addr and returns it plus
// the config path SIGHUP would re-read.
func reloadTestServer(t *testing.T, addr string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf("server:\n  mode: \"local\"\n  listen_address: %q\n  server_id: \"Initial\"\nlocal_storage:\n  log_directory: %q\n",
		addr, filepath.Join(dir, "logs"))
	if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	srv, err := NewServer(cfg, configPath, new(slog.LevelVar))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		srv.cancel()
		for _, l := range srv.listeners {
			_ = l.ln.Close()
		}
		srv.waitGroup.Wait()
	})
	return srv, configPath
}

func dialable(t *testing.T, addr string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// TestReload_RebindsListeners is ARCH-019 and CONF-019 together: SIGHUP must
// move the listening socket and must NOT drop the connections already
// established on the old one.
//
// Before this, a moved or added listen_address was refused outright and needed
// a full restart -- and a restart drops every established connection, each of
// which takes down the command it was logging, because sudoers leaves
// ignore_iolog_errors false (plugins/sudoers/log_client.c:1918-1921).
func TestReload_RebindsListeners(t *testing.T) {
	oldAddr := fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t))
	newAddr := fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t))
	srv, configPath := reloadTestServer(t, oldAddr)

	// An established connection that must survive the reload.
	established, err := net.DialTimeout("tcp", oldAddr, time.Second)
	if err != nil {
		t.Fatalf("dial before reload: %v", err)
	}
	defer established.Close()

	body := fmt.Sprintf("server:\n  mode: \"local\"\n  listen_address: %q\n  server_id: \"Initial\"\nlocal_storage:\n  log_directory: %q\n",
		newAddr, filepath.Join(t.TempDir(), "logs"))
	if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	srv.reload()

	if !dialable(t, newAddr) {
		t.Errorf("new listen address %s is not accepting; the reload did not bind it", newAddr)
	}
	if dialable(t, oldAddr) {
		t.Errorf("old listen address %s is still accepting; the reload did not release it", oldAddr)
	}

	// The pre-existing connection must still be usable. A write to a listener
	// that was merely closed still succeeds; a torn-down connection does not.
	if err := established.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := established.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Errorf("connection established before the reload was dropped by it: %v", err)
	}

	if got := srv.config.Load().Server.ListenAddress; got != newAddr {
		t.Errorf("stored config listen_address = %q, want %q", got, newAddr)
	}
	if len(srv.listeners) != 1 || srv.listeners[0].addr != newAddr {
		t.Errorf("listener set = %+v, want exactly one on %s", srv.listeners, newAddr)
	}
}

// TestReload_UnbindableAddressKeepsPreviousListeners covers the rollback. C
// frees the old listeners before binding the new ones, so a failed bind can
// leave it with nothing listening and it calls sudo_fatalx and exits
// (logsrvd/logsrvd.c:1809-1874). Binding first means a reload that cannot be
// satisfied changes nothing and the daemon keeps serving where it was.
func TestReload_UnbindableAddressKeepsPreviousListeners(t *testing.T) {
	oldAddr := fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t))
	srv, configPath := reloadTestServer(t, oldAddr)

	// Hold a port so the reload's bind cannot succeed.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer blocker.Close()
	takenAddr := blocker.Addr().String()

	body := fmt.Sprintf("server:\n  mode: \"local\"\n  listen_address: %q\n  server_id: \"Initial\"\nlocal_storage:\n  log_directory: %q\n",
		takenAddr, filepath.Join(t.TempDir(), "logs"))
	if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	srv.reload()

	if !dialable(t, oldAddr) {
		t.Error("original listen address stopped accepting after a reload that could not bind its replacement")
	}
	if got := srv.config.Load().Server.ListenAddress; got != oldAddr {
		t.Errorf("config was swapped despite the failed reload: listen_address = %q, want %q", got, oldAddr)
	}
}

// TestReload_UnchangedAddressReusesSocket pins the reuse half of CONF-019: an
// address string present in both configurations must keep its existing socket
// rather than being rebound, which is what makes a reload that only changes an
// unrelated setting invisible to clients.
func TestReload_UnchangedAddressReusesSocket(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t))
	srv, configPath := reloadTestServer(t, addr)

	before := srv.listeners[0]

	body := fmt.Sprintf("server:\n  mode: \"local\"\n  listen_address: %q\n  server_id: \"Changed\"\nlocal_storage:\n  log_directory: %q\n",
		addr, filepath.Join(t.TempDir(), "logs"))
	if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	srv.reload()

	if len(srv.listeners) != 1 {
		t.Fatalf("listener count = %d, want 1", len(srv.listeners))
	}
	if srv.listeners[0] != before {
		t.Error("listener was rebound although its address string did not change")
	}
	if got := srv.config.Load().Server.ServerID; got != "Changed" {
		t.Errorf("ServerID = %q, want Changed: the reload should have been applied", got)
	}
}

// TestReload_SwapsTLSParametersWithoutRebinding is the TLS half of ARCH-019.
// Turning tls_check_peer on must take effect for the next handshake, and it
// must do so without disturbing the listening socket -- a rebind would open a
// window in which connects are refused, and a refused connect means sudo does
// not run the command (ignore_iolog_errors defaults to false).
//
// The certificate half needs no reload at all: keyPairReloader re-reads the key
// pair per handshake, so an in-place renewal is picked up with no signal. That
// is covered by certreload_test.go.
func TestReload_SwapsTLSParametersWithoutRebinding(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "srv.pem"), filepath.Join(dir, "srv.key")
	writeKeyPairAt(t, certPath, keyPath, 1)
	ca := newCA(t, dir)

	configPath := filepath.Join(dir, "config.yaml")
	writeTLSConfig := func(checkPeer bool) {
		t.Helper()
		// listen_address is pinned empty: the shipped default is 127.0.0.1:30343,
		// and leaving it implicit would bind a second, plaintext listener and make
		// listeners[0] the wrong socket.
		body := fmt.Sprintf("server:\n  mode: \"local\"\n  listen_address: \"\"\n  listen_address_tls: %q\n"+
			"  tls_cert_file: %q\n  tls_key_file: %q\n  tls_cacert_file: %q\n  tls_check_peer: %t\n"+
			"local_storage:\n  log_directory: %q\n",
			"127.0.0.1:0", certPath, keyPath, ca.caPEMPath, checkPeer, filepath.Join(dir, "logs"))
		if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}

	writeTLSConfig(false)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	srv, err := NewServer(cfg, configPath, new(slog.LevelVar))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		srv.cancel()
		for _, l := range srv.listeners {
			_ = l.ln.Close()
		}
		srv.waitGroup.Wait()
	})

	addr := srv.listeners[0].ln.Addr().String()
	socketBefore := srv.listeners[0]

	// check_peer off: a certificate-less client is accepted.
	if err := dialTLS(t, addr, certPath, nil); err != nil {
		t.Fatalf("certificate-less client rejected before the reload: %v", err)
	}

	// listen_address_tls is written as :0 in both files, so the address STRING
	// is unchanged and the socket must be reused -- otherwise a rebind would
	// pick a different ephemeral port and addr would go stale.
	writeTLSConfig(true)
	srv.reload()

	if len(srv.listeners) != 1 || srv.listeners[0] != socketBefore {
		t.Fatal("the TLS listener was rebound; parameters must swap behind the existing socket")
	}
	if srv.listeners[0].ln.Addr().String() != addr {
		t.Fatalf("listener address changed from %s to %s across the reload", addr, srv.listeners[0].ln.Addr())
	}

	// check_peer on: the same certificate-less client must now be refused.
	if err := dialTLS(t, addr, certPath, nil); err == nil {
		t.Error("certificate-less client still accepted after tls_check_peer was enabled by reload")
	}

	// ...and a properly issued client certificate must be accepted.
	clientCert := ca.issueClient(t, dir, "relay-1")
	if err := dialTLS(t, addr, certPath, []tls.Certificate{clientCert}); err != nil {
		t.Errorf("client with a CA-issued certificate rejected after reload: %v", err)
	}
}
