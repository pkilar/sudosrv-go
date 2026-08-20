// SPDX-License-Identifier: Apache-2.0
// Filename: internal/server/certreload.go
package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// keyPairReloader supplies the TLS listener's certificate at handshake time,
// re-reading the files from disk whenever they change underneath us.
//
// Do not "simplify" this back to a single tls.LoadX509KeyPair stored in
// tls.Config.Certificates. sudo_logsrvd builds a fresh SSL_CTX -- and therefore
// re-reads tls_cert_key/tls_key_path from disk -- every time a configuration is
// applied, which includes every SIGHUP (logsrvd/logsrvd_conf.c:1792-1806 called
// from logsrvd_conf_apply, via logsrvd_conf_read in server_reload at
// logsrvd/logsrvd.c:1879-1890). Loading once at listener construction made a
// certificate renewed in place invisible: the Go reload path compares only the
// configured path STRINGS, so SIGHUP logged "Config reload complete" while the
// expired certificate kept being served. certbot and cert-manager both renew in
// place and reload. When the old certificate finally expired, every TLS client's
// handshake failed, log_server_open() returned NULL, sudoers_io_open() returned
// -1 (plugins/sudoers/iolog.c:855-867) and -- ignore_iolog_errors being false by
// default (plugins/sudoers/defaults.c:610) -- sudo refused to run ANY command on
// every host pointed at this server. Reading per handshake needs no signal at
// all and cannot report a false success.
// Conformance: docs/logsrvd-reference/ CONF-018.
type keyPairReloader struct {
	certFile string
	keyFile  string

	// mu guards everything below. It is held across the stat calls on the
	// handshake path; those hit cached inode metadata and cost far less than
	// the signature the handshake is about to compute.
	mu sync.Mutex
	// cert is the last successfully loaded pair, served whenever a reload
	// attempt fails so a half-written renewal cannot take the listener down.
	cert *tls.Certificate
	// certStamp/keyStamp identify the file generation behind cert. A reload
	// is attempted only when one of them changes, so the steady state is two
	// stat calls per handshake and no file reads or parsing.
	certStamp fileStamp
	keyStamp  fileStamp
	// warnedStamp is the generation we last logged a load failure for, so a
	// broken pair produces one line per change rather than one per handshake.
	warnedStamp [2]fileStamp
}

// fileStamp is the cheap identity of a file's contents. Comparable by ==, so
// modTime is kept as Unix nanoseconds rather than a time.Time (whose == also
// compares the monotonic reading and location pointer).
type fileStamp struct {
	modTimeNano int64
	size        int64
	// exists distinguishes "stat failed" from a zero-length file at the
	// epoch, so a vanished file is never mistaken for an unchanged one.
	exists bool
}

func statStamp(path string) fileStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{modTimeNano: fi.ModTime().UnixNano(), size: fi.Size(), exists: true}
}

// newKeyPairReloader loads the key pair once so a missing or malformed
// certificate fails startup rather than the first handshake, matching both the
// previous behaviour and C, where init_tls_context() failing aborts the apply
// (logsrvd/logsrvd_conf.c:1801-1805).
func newKeyPairReloader(certFile, keyFile string) (*keyPairReloader, error) {
	r := &keyPairReloader{certFile: certFile, keyFile: keyFile}
	certStamp, keyStamp := statStamp(certFile), statStamp(keyFile)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	r.cert = &cert
	r.certStamp, r.keyStamp = certStamp, keyStamp
	return r, nil
}

// GetCertificate is installed as tls.Config.GetCertificate. It must be the only
// certificate source on that config: tls.Config.getCertificate consults
// GetCertificate only when Certificates is empty or the client sent SNI
// (crypto/tls/common.go), and a sudo client is not obliged to send SNI.
func (r *keyPairReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Stamps are read before the pair itself, so a renewal landing between the
	// stat and the read is caught by the next handshake instead of being
	// recorded as the current generation.
	certStamp, keyStamp := statStamp(r.certFile), statStamp(r.keyFile)
	bothPresent := certStamp.exists && keyStamp.exists
	unchanged := certStamp == r.certStamp && keyStamp == r.keyStamp
	if bothPresent && unchanged {
		return r.cert, nil
	}

	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		// A renewal is two file writes and we can be looking between them, so
		// a failure here is expected and transient. Keep serving the last good
		// pair -- C likewise leaves the running configuration in place when an
		// apply fails (logsrvd/logsrvd.c:1879-1890) -- and retry on the next
		// handshake, since the stamps are deliberately not advanced.
		if stamp := [2]fileStamp{certStamp, keyStamp}; stamp != r.warnedStamp {
			r.warnedStamp = stamp
			slog.Warn("TLS key pair changed on disk but could not be loaded; still serving the previously loaded certificate",
				"cert_file", r.certFile, "key_file", r.keyFile, "error", err)
		}
		if r.cert != nil {
			return r.cert, nil
		}
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}

	r.cert = &cert
	r.certStamp, r.keyStamp = certStamp, keyStamp
	r.warnedStamp = [2]fileStamp{}
	slog.Info("Reloaded TLS key pair", "cert_file", r.certFile, "key_file", r.keyFile)
	return r.cert, nil
}
