// SPDX-License-Identifier: Apache-2.0
// Filename: internal/config/mutual_tls_test.go
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRelayTLSInheritsFromServerPerKey pins the inheritance rule for the relay's
// TLS material.
//
// C builds the relay SSL_CTX with TLS_RELAY_STR(config, f) = `relay.f ?: server.f`
// (logsrvd/logsrvd_conf.c:65-71, 1809-1827), applied PER KEY. Setting only
// `[relay] tls_cacert` therefore leaves the relay presenting the server's
// certificate and key — it does not switch the whole block over to relay values
// and leave the rest empty.
//
// All-or-nothing inheritance would be the easy mistake: an operator who sets a
// relay-specific CA to trust a different upstream would silently stop presenting
// any client certificate at all, and every flush would fail at the upstream's
// handshake with the cache growing behind it.
//
// Conformance: docs/logsrvd-reference/ TLS-025, CONF-045.
func TestRelayTLSInheritsFromServerPerKey(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			TLSCertFile:   "/srv/cert.pem",
			TLSKeyFile:    "/srv/key.pem",
			TLSCACertFile: "/srv/ca.pem",
		},
	}

	t.Run("AllUnsetInheritsEverything", func(t *testing.T) {
		if got := cfg.RelayTLSCertFile(); got != "/srv/cert.pem" {
			t.Errorf("cert = %q, want the server's /srv/cert.pem", got)
		}
		if got := cfg.RelayTLSKeyFile(); got != "/srv/key.pem" {
			t.Errorf("key = %q, want the server's /srv/key.pem", got)
		}
		if got := cfg.RelayTLSCACertFile(); got != "/srv/ca.pem" {
			t.Errorf("cacert = %q, want the server's /srv/ca.pem", got)
		}
	})

	t.Run("OneRelayKeyDoesNotDisinheritTheRest", func(t *testing.T) {
		c := *cfg
		c.Relay.TLSCACertFile = "/relay/ca.pem"

		if got := c.RelayTLSCACertFile(); got != "/relay/ca.pem" {
			t.Errorf("cacert = %q, want the relay's own /relay/ca.pem", got)
		}
		// The point of the test: cert and key must STILL come from the server.
		if got := c.RelayTLSCertFile(); got != "/srv/cert.pem" {
			t.Errorf("cert = %q, want /srv/cert.pem; overriding one relay TLS key must "+
				"not stop the others inheriting, or the relay silently presents no "+
				"client certificate", got)
		}
		if got := c.RelayTLSKeyFile(); got != "/srv/key.pem" {
			t.Errorf("key = %q, want /srv/key.pem", got)
		}
	})

	t.Run("RelayValuesWinWhenSet", func(t *testing.T) {
		c := *cfg
		c.Relay.TLSCertFile = "/relay/cert.pem"
		c.Relay.TLSKeyFile = "/relay/key.pem"
		if got := c.RelayTLSCertFile(); got != "/relay/cert.pem" {
			t.Errorf("cert = %q, want /relay/cert.pem", got)
		}
		if got := c.RelayTLSKeyFile(); got != "/relay/key.pem" {
			t.Errorf("key = %q, want /relay/key.pem", got)
		}
	})
}

// TestMutualTLSValidation covers the config errors that would otherwise surface
// as a confusing handshake failure at runtime.
func TestMutualTLSValidation(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		return p
	}

	// A half-configured key pair can never produce a usable certificate; failing
	// at load beats failing at every upstream handshake.
	t.Run("RelayCertWithoutKeyIsRejected", func(t *testing.T) {
		cfg, err := LoadConfig(write(t, "server:\n  mode: \"relay\"\nrelay:\n"+
			"  upstream_host: \"h:1\"\n  tls_cert_file: \"/relay/cert.pem\"\n"))
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		err = Validate(cfg)
		if err == nil {
			t.Fatal("a relay tls_cert_file with no tls_key_file was accepted")
		}
		if !strings.Contains(err.Error(), "tls_key_file") {
			t.Errorf("error %q should name the missing tls_key_file", err)
		}
	})

	// tls_check_peer is the whole point of the feature; enabling it on a server
	// with no TLS listener is a configuration that can never do anything.
	t.Run("CheckPeerWithoutTLSListenerIsRejected", func(t *testing.T) {
		cfg, err := LoadConfig(write(t, "server:\n  mode: \"local\"\n  tls_check_peer: true\n"))
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if err := Validate(cfg); err == nil {
			t.Error("tls_check_peer was accepted with no TLS listener configured; it would " +
				"silently have no effect")
		}
	})

	// C's default is off (logsrvd_conf.c:1688), and matching it is what keeps the
	// out-of-the-box posture identical.
	t.Run("CheckPeerDefaultsOff", func(t *testing.T) {
		cfg, err := LoadConfig(write(t, "server:\n  mode: \"local\"\n"))
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.Server.TLSCheckPeer {
			t.Error("tls_check_peer defaulted to true; C defaults it false, and turning it " +
				"on by default would reject every existing client at the handshake")
		}
	})
}
