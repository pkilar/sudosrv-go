// SPDX-License-Identifier: Apache-2.0
// Filename: internal/server/tlsparams.go
package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"sudosrv/internal/config"
	"sync/atomic"
)

// tlsParams is the set of [server] settings that shape the TLS listener's
// handshake. It is comparable by ==, which is the whole point: reload decides
// whether anything needs rebuilding by comparing two of these rather than by
// inspecting a live tls.Config.
type tlsParams struct {
	certFile   string
	keyFile    string
	minVersion string
	checkPeer  bool
	caCertFile string
	ciphers    string // the configured TLS 1.2 suite list, joined; see CONF-033
}

func tlsParamsFrom(cfg *config.Config) tlsParams {
	return tlsParams{
		certFile:   cfg.Server.TLSCertFile,
		keyFile:    cfg.Server.TLSKeyFile,
		minVersion: cfg.Server.TLSMinVersion,
		checkPeer:  cfg.Server.TLSCheckPeer,
		caCertFile: cfg.Server.TLSCACertFile,
		ciphers:    cfg.Server.TLSCiphersKey(),
	}
}

// tlsConfigProvider supplies the TLS listener's configuration per handshake and
// lets SIGHUP swap it without touching the listening socket.
//
// The alternative -- closing the TLS listener and re-binding it with a new
// tls.Config -- would work, since closing a net.Listener leaves accepted
// connections alone, but it opens a window in which connects to that port are
// refused. A refused connect is not a cosmetic problem here: sudoers leaves
// ignore_iolog_errors false, so a client that cannot reach the log server does
// not run its command (plugins/sudoers/log_client.c:1918-1922). Swapping the
// config behind GetConfigForClient closes that window entirely.
//
// C achieves the same end differently: logsrvd_conf_apply builds a fresh
// SSL_CTX on every apply and the listener picks it up, while existing
// connections keep the context they handshook with
// (logsrvd/logsrvd_conf.c:1792-1806). In-flight sessions are undisturbed either
// way, which is what ARCH-019 requires.
//
// Conformance: docs/logsrvd-reference/ ARCH-019, CONF-018, CONF-019.
type tlsConfigProvider struct {
	// current is read on every handshake and replaced wholesale on reload, so
	// a handshake in flight keeps the config it started with.
	current atomic.Pointer[tls.Config]
	// params is the fingerprint behind current. Only reload reads or writes it,
	// and reload is single-goroutine (the signal loop in Wait).
	params tlsParams
}

// newTLSConfigProvider builds the initial configuration. A failure here is a
// startup failure, matching C, where init_tls_context() failing aborts the
// apply (logsrvd/logsrvd_conf.c:1801-1805).
func newTLSConfigProvider(cfg *config.Config) (*tlsConfigProvider, error) {
	p := &tlsConfigProvider{}
	tc, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	p.current.Store(tc)
	p.params = tlsParamsFrom(cfg)
	return p, nil
}

// listenerConfig is the tls.Config handed to tls.NewListener. It carries only
// the callback: every real parameter comes from whatever GetConfigForClient
// returns, so a reload is visible to the very next handshake.
func (p *tlsConfigProvider) listenerConfig() *tls.Config {
	return &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return p.current.Load(), nil
		},
		// MinVersion is set here too. crypto/tls reads it from the returned
		// config for the handshake, but leaving the listener's own config at the
		// zero value would advertise a weaker floor to anything that inspects it
		// before the callback runs.
		MinVersion: p.current.Load().MinVersion,
	}
}

// update rebuilds the configuration if any TLS parameter changed. It reports
// whether anything changed, and leaves the previous configuration in force if
// the new one cannot be built -- the same "keep running on a bad apply" rule C
// follows (logsrvd/logsrvd.c:1879-1890).
func (p *tlsConfigProvider) update(cfg *config.Config) (bool, error) {
	next := tlsParamsFrom(cfg)
	if next == p.params {
		return false, nil
	}
	tc, err := buildTLSConfig(cfg)
	if err != nil {
		return false, err
	}
	p.current.Store(tc)
	p.params = next
	return true, nil
}

// buildTLSConfig assembles the listener's TLS configuration from [server].
func buildTLSConfig(cfg *config.Config) (*tls.Config, error) {
	// The key pair is fetched per handshake, not pinned here, so a certificate
	// renewed IN PLACE is picked up without a restart and without a signal. See
	// keyPairReloader. Certificates is left empty on purpose: with it populated,
	// crypto/tls skips GetCertificate for clients that send no SNI.
	// Conformance: docs/logsrvd-reference/ CONF-018.
	certReloader, err := newKeyPairReloader(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}
	minVer, err := config.TLSVersion(cfg.Server.TLSMinVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid server tls_min_version: %w", err)
	}
	suites, err := config.CipherSuites(cfg.Server.TLSCiphersV12)
	if err != nil {
		return nil, fmt.Errorf("server.tls_ciphers_v12: %w", err)
	}
	tlsConfig := &tls.Config{
		GetCertificate: certReloader.GetCertificate,
		MinVersion:     minVer,
		CipherSuites:   suites,
	}
	// Mutual TLS. RequireAndVerifyClientCert is the pair of OpenSSL bits C sets
	// when tls_checkpeer is on -- SSL_VERIFY_PEER together with
	// SSL_VERIFY_FAIL_IF_NO_PEER_CERT (logsrvd/logsrvd.c:1451-1462) -- so a
	// client presenting NO certificate is rejected during the handshake rather
	// than merely left unverified. Anything weaker (VerifyClientCertIfGiven)
	// would let a peer opt out of authentication by simply staying silent, which
	// is the whole failure this setting exists to prevent.
	//
	// A nil ClientCAs means the platform trust store, matching C's fallback to
	// SSL_CTX_set_default_verify_paths when no bundle is named.
	//
	// Conformance: docs/logsrvd-reference/ TLS-015, TLS-007, CONF-035.
	if cfg.Server.TLSCheckPeer {
		pool, err := loadCAPool(cfg.Server.TLSCACertFile)
		if err != nil {
			return nil, fmt.Errorf("server.tls_cacert_file: %w", err)
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = pool
		slog.Info("Client certificate authentication enabled",
			"ca_bundle", cmpOrSystem(cfg.Server.TLSCACertFile))
	}
	return tlsConfig, nil
}
