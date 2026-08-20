// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/client_cert_test.go
package relay

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
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"testing"
	"time"
)

// mtlsFixture is a CA plus a server and client key pair it signed, written to
// disk in the form the config expects.
type mtlsFixture struct {
	caPath, srvCert, srvKey, cliCert, cliKey string
	pool                                     *x509.CertPool
}

func newMTLSFixture(t *testing.T) *mtlsFixture {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relay test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	issue := func(cn string, server bool) (certPath, keyPath string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		if server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.DNSNames = []string{"localhost"}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("sign %s: %v", cn, err)
		}
		kb, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("marshal key: %v", err)
		}
		certPath = filepath.Join(dir, cn+".pem")
		keyPath = filepath.Join(dir, cn+".key")
		writeBlock(t, certPath, "CERTIFICATE", der)
		writeBlock(t, keyPath, "EC PRIVATE KEY", kb)
		return certPath, keyPath
	}

	f := &mtlsFixture{caPath: filepath.Join(dir, "ca.pem"), pool: x509.NewCertPool()}
	writeBlock(t, f.caPath, "CERTIFICATE", caDER)
	f.pool.AddCert(caCert)
	f.srvCert, f.srvKey = issue("upstream", true)
	f.cliCert, f.cliKey = issue("relay", false)
	return f
}

func writeBlock(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}

// startMTLSUpstream runs a TLS upstream that REQUIRES a client certificate,
// completes the ClientHello handshake, then drains.
func startMTLSUpstream(t *testing.T, f *mtlsFixture) string {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(f.srvCert, f.srvKey)
	if err != nil {
		t.Fatalf("load upstream key pair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    f.pool,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer conn.Close()
				proc := protocol.NewProcessor(conn, conn)
				if _, err := proc.ReadClientMessage(); err != nil {
					return
				}
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_Hello{Hello: &pb.ServerHello{}},
				})
				drain(proc)
			})
		}
	})
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	return ln.Addr().String()
}

// TestRelayPresentsClientCertificateToUpstream is the relay half of mutual TLS.
//
// An upstream running with tls_checkpeer rejects any peer that presents no
// certificate. Without the ability to present one, every flush fails at the
// handshake — and because relaying is store-and-forward the downstream client
// has already been told the session was accepted, so the failure is invisible
// from the client side while the cache directory grows without bound.
//
// Conformance: docs/logsrvd-reference/ TLS-025, CONF-045.
func TestRelayPresentsClientCertificateToUpstream(t *testing.T) {
	f := newMTLSFixture(t)
	addr := startMTLSUpstream(t, f)

	base := func() *config.RelayConfig {
		return &config.RelayConfig{
			UpstreamHost:   addr,
			UseTLS:         true,
			ConnectTimeout: 5 * time.Second,
			TLSCACertFile:  f.caPath, // trust the upstream's private CA
		}
	}

	t.Run("WithoutClientCertTheUpstreamRejectsUs", func(t *testing.T) {
		proc, err := connectToUpstream(t.Context(), base())
		if err == nil {
			_ = proc.Close()
			t.Error("connected to an upstream requiring client certs while presenting none; " +
				"every flush would appear to succeed against a server that refuses us")
		}
	})

	t.Run("WithClientCertTheHandshakeSucceeds", func(t *testing.T) {
		cfg := base()
		cfg.TLSCertFile = f.cliCert
		cfg.TLSKeyFile = f.cliKey
		proc, err := connectToUpstream(t.Context(), cfg)
		if err != nil {
			t.Fatalf("relay could not authenticate to the upstream with a valid client cert: %v", err)
		}
		_ = proc.Close()
	})

	// A private-CA upstream is the normal case for this feature; without a
	// configurable bundle it could only be trusted by installing the CA
	// system-wide or disabling verification entirely.
	t.Run("WithoutTheCABundleTheUpstreamIsUntrusted", func(t *testing.T) {
		cfg := base()
		cfg.TLSCACertFile = ""
		cfg.TLSCertFile = f.cliCert
		cfg.TLSKeyFile = f.cliKey
		proc, err := connectToUpstream(t.Context(), cfg)
		if err == nil {
			_ = proc.Close()
			t.Error("a privately-signed upstream verified against the system trust store")
		}
	})

	t.Run("UnreadableCABundleIsAnError", func(t *testing.T) {
		cfg := base()
		cfg.TLSCACertFile = filepath.Join(t.TempDir(), "absent.pem")
		if _, err := connectToUpstream(t.Context(), cfg); err == nil {
			t.Error("a missing relay CA bundle was accepted; it would silently fall back to " +
				"the system trust store")
		}
	})
}
