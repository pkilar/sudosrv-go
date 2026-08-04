// SPDX-License-Identifier: Apache-2.0
// Filename: internal/server/mutual_tls_test.go
package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"testing"
	"time"
)

// caFixture is a throwaway CA plus the material needed to exercise both sides of
// a client-certificate handshake.
type caFixture struct {
	caPEMPath string
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
}

func newCA(t *testing.T, dir string) *caFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "sudosrv test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	p := filepath.Join(dir, "ca.pem")
	writePEM(t, p, "CERTIFICATE", der)
	return &caFixture{caPEMPath: p, caCert: cert, caKey: key}
}

// issueClient returns a key pair signed by this CA, suitable for client auth.
func (c *caFixture) issueClient(t *testing.T, dir, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, c.caCert, &key.PublicKey, c.caKey)
	if err != nil {
		t.Fatalf("sign client cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSServer boots a TLS-only server and returns it with its bound address.
func startTLSServer(t *testing.T, certPath, keyPath, caPath string, checkPeer bool) (*Server, string) {
	t.Helper()
	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:             "local",
			ListenAddressTLS: "127.0.0.1:0",
			TLSCertFile:      certPath,
			TLSKeyFile:       keyPath,
			TLSCACertFile:    caPath,
			TLSCheckPeer:     checkPeer,
			ServerTimeout:    5 * time.Second,
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return srv, srv.listeners[0].Addr().String()
}

// serverRoots trusts the server's own self-signed certificate, so these tests
// verify the SERVER properly and still isolate what they are actually about --
// whether the server demands a certificate from the CLIENT. Skipping server
// verification would work too, but a test that disables it teaches the pattern.
func serverRoots(t *testing.T, certPath string) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read server cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("server cert is not usable PEM")
	}
	return pool
}

// dialTLS attempts a handshake against addr with the given client certs.
func dialTLS(t *testing.T, addr, serverCertPath string, certs []tls.Certificate) error {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		RootCAs:      serverRoots(t, serverCertPath),
		ServerName:   "localhost",
		Certificates: certs,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return err
	}

	// A successful Handshake() is NOT proof the server accepted us. Under TLS 1.3
	// the server transmits its own Finished before it has processed the client's
	// Certificate, so tls.Dial returns cleanly and a rejection arrives afterwards
	// as a `bad certificate` alert on the next read. Asserting only on Handshake()
	// would make these tests pass no matter what the server does with ClientAuth.
	//
	// This server sends nothing until it receives a ClientHello protocol message,
	// so a read timeout means the connection is alive and we were accepted, while
	// any other error is the alert.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	var buf [1]byte
	_, readErr := conn.Read(buf[:])
	var ne net.Error
	if errors.As(readErr, &ne) && ne.Timeout() {
		return nil // still connected: accepted
	}
	return readErr
}

// TestClientCertificateIsRequiredWhenCheckPeerIsSet is the core of mutual TLS:
// with tls_check_peer on, a client that presents no certificate must be rejected
// during the handshake, not merely recorded as unverified.
//
// C sets SSL_VERIFY_PEER together with SSL_VERIFY_FAIL_IF_NO_PEER_CERT
// (logsrvd/logsrvd.c:1451-1462). The second bit is the one that matters: without
// it a peer opts out of authentication by staying silent, which defeats the
// entire setting. crypto/tls draws the same distinction as
// VerifyClientCertIfGiven vs RequireAndVerifyClientCert.
//
// Conformance: docs/logsrvd-reference/ TLS-015, CONF-035.
func TestClientCertificateIsRequiredWhenCheckPeerIsSet(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	certPath, keyPath := generateSelfSignedCert(t)

	srv, addr := startTLSServer(t, certPath, keyPath, ca.caPEMPath, true)
	defer shutdown(srv)

	t.Run("NoClientCertIsRejected", func(t *testing.T) {
		if err := dialTLS(t, addr, certPath, nil); err == nil {
			t.Error("a client presenting no certificate completed the handshake; " +
				"tls_check_peer must reject it, or authentication is optional in practice")
		}
	})

	t.Run("CertFromAnotherCAIsRejected", func(t *testing.T) {
		other := newCA(t, t.TempDir())
		if err := dialTLS(t, addr, certPath, []tls.Certificate{other.issueClient(t, dir, "impostor")}); err == nil {
			t.Error("a client certificate signed by an unconfigured CA was accepted")
		}
	})

	t.Run("CertFromTheConfiguredCAIsAccepted", func(t *testing.T) {
		if err := dialTLS(t, addr, certPath, []tls.Certificate{ca.issueClient(t, dir, "relay01")}); err != nil {
			t.Errorf("a client certificate signed by the configured CA was rejected: %v", err)
		}
	})
}

// TestCheckPeerOffAcceptsClientsWithoutCertificates guards the default: turning
// the feature off must leave the previous posture exactly as it was, since C
// also defaults tls_checkpeer to false (logsrvd/logsrvd_conf.c:1688).
func TestCheckPeerOffAcceptsClientsWithoutCertificates(t *testing.T) {
	certPath, keyPath := generateSelfSignedCert(t)
	srv, addr := startTLSServer(t, certPath, keyPath, "", false)
	defer shutdown(srv)

	if err := dialTLS(t, addr, certPath, nil); err != nil {
		t.Errorf("with tls_check_peer off a client without a certificate must still connect, got: %v", err)
	}
}

// TestUnreadableCABundleFailsStartup covers the trust-anchor footgun: a typo'd
// tls_cacert_file must not silently fall back to the platform trust store, or an
// operator who meant to trust exactly one private CA ends up trusting the whole
// public web PKI. C treats either load failure as fatal (logsrvd/tls_init.c:294-319).
//
// Conformance: docs/logsrvd-reference/ TLS-007, CONF-031.
func TestUnreadableCABundleFailsStartup(t *testing.T) {
	t.Run("MissingFile", func(t *testing.T) {
		if _, err := loadCAPool(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
			t.Error("a missing CA bundle was accepted; startup would silently use the system trust store")
		}
	})

	t.Run("NotPEM", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "junk.pem")
		if err := os.WriteFile(p, []byte("this is not a certificate\n"), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := loadCAPool(p); err == nil {
			t.Error("a CA bundle with no certificates was accepted")
		}
	})

	t.Run("EmptyPathMeansSystemStore", func(t *testing.T) {
		pool, err := loadCAPool("")
		if err != nil {
			t.Fatalf("empty path must not error: %v", err)
		}
		if pool != nil {
			t.Error("empty path must yield a nil pool, which crypto/tls reads as the platform trust store")
		}
	})

}
