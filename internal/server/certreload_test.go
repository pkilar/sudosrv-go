// SPDX-License-Identifier: Apache-2.0
// Filename: internal/server/certreload_test.go

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"testing"
	"time"
)

// writeKeyPairAt writes a fresh self-signed cert+key to the given paths,
// overwriting whatever is there, and returns the serial number so a test can
// tell one generation of the certificate from the next.
//
// The file modification time is guaranteed to differ from the previous
// generation's: Linux stamps inode timestamps from a coarse clock (typically
// 1-4ms granularity), so two writes inside the same tick would otherwise be
// indistinguishable to a stat-based freshness check. Real certificate renewals
// are days apart; this loop only makes the test deterministic.
func writeKeyPairAt(t *testing.T, certPath, keyPath string, serial int64) *big.Int {
	t.Helper()

	prevModTime := time.Time{}
	if fi, err := os.Stat(certPath); err == nil {
		prevModTime = fi.ModTime()
	}

	sn := big.NewInt(serial)
	for attempt := 0; ; attempt++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		template := x509.Certificate{
			SerialNumber:          sn,
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
		writePEM(t, certPath, "CERTIFICATE", derBytes)
		writePEM(t, keyPath, "EC PRIVATE KEY", keyBytes)

		fi, err := os.Stat(certPath)
		if err != nil {
			t.Fatalf("stat cert: %v", err)
		}
		if !fi.ModTime().Equal(prevModTime) {
			return sn
		}
		if attempt > 100 {
			t.Fatalf("cert file modification time never advanced past %v", prevModTime)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		f.Close()
		t.Fatalf("encode %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}

// servedSerial performs a TLS handshake against addr and returns the serial
// number of the certificate the server presented.
func servedSerial(t *testing.T, addr string) *big.Int {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.DialWithDialer: %v", err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("server presented no certificate")
	}
	return certs[0].SerialNumber
}

// TestTLSListener_PicksUpRenewedCertificate asserts that a certificate renewed
// in place on disk is served to the next client without a restart, which is
// what certbot/cert-manager renew-and-reload assumes. Before the per-handshake
// load, the key pair was read exactly once at Start() and the old certificate
// was served until the process was restarted — silently, until it expired and
// every TLS client's sudo refused to run.
// Conformance: docs/logsrvd-reference/ CONF-018.
func TestTLSListener_PicksUpRenewedCertificate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	first := writeKeyPairAt(t, certPath, keyPath, 1)

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

	addr := srv.listeners[0].Addr().String()
	if got := servedSerial(t, addr); got.Cmp(first) != 0 {
		t.Fatalf("initial handshake: served serial %v, want %v", got, first)
	}

	// Renew in place, exactly as an ACME client does.
	second := writeKeyPairAt(t, certPath, keyPath, 2)
	if got := servedSerial(t, addr); got.Cmp(second) != 0 {
		t.Fatalf("after renewal: served serial %v, want %v (stale certificate)", got, second)
	}

	// An unchanged file must not be reloaded, and must keep working.
	if got := servedSerial(t, addr); got.Cmp(second) != 0 {
		t.Fatalf("second handshake after renewal: served serial %v, want %v", got, second)
	}
}

// TestTLSListener_KeepsLastGoodCertificateOnBadRenewal covers the window where
// the certificate has been replaced on disk but the matching key has not yet
// been written. Serving the last known-good pair keeps clients connecting,
// mirroring C, where a configuration whose apply fails leaves the running
// configuration untouched (logsrvd/logsrvd.c:1879-1890).
// Conformance: docs/logsrvd-reference/ CONF-018.
func TestTLSListener_KeepsLastGoodCertificateOnBadRenewal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	good := writeKeyPairAt(t, certPath, keyPath, 7)

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

	addr := srv.listeners[0].Addr().String()
	if got := servedSerial(t, addr); got.Cmp(good) != 0 {
		t.Fatalf("initial handshake: served serial %v, want %v", got, good)
	}

	// Truncate the certificate: the pair no longer parses.
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\ntrunc"), 0o600); err != nil {
		t.Fatalf("truncate cert: %v", err)
	}
	if got := servedSerial(t, addr); got.Cmp(good) != 0 {
		t.Fatalf("after bad renewal: served serial %v, want the last good %v", got, good)
	}

	// Once the renewal completes, the new pair is picked up.
	renewed := writeKeyPairAt(t, certPath, keyPath, 8)
	if got := servedSerial(t, addr); got.Cmp(renewed) != 0 {
		t.Fatalf("after completed renewal: served serial %v, want %v", got, renewed)
	}
}
