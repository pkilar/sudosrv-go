// SPDX-License-Identifier: Apache-2.0
// Filename: internal/server/capool.go
package server

import (
	"crypto/x509"
	"fmt"
	"os"
)

// loadCAPool builds an x509 pool from a PEM bundle, or returns nil to mean "use
// the platform trust store".
//
// The nil-for-system-store convention mirrors C: with no tls_cacert configured
// the daemon calls SSL_CTX_set_default_verify_paths, and only uses
// SSL_CTX_load_verify_locations when a bundle is named
// (logsrvd/tls_init.c:294-319). crypto/tls applies the same meaning to a nil
// ClientCAs/RootCAs, so the two line up without special-casing.
//
// A named bundle that cannot be read, or that contains no certificates, is a
// hard error rather than a silent fallback — also matching C, where either
// failure is fatal (`goto bad`). Falling back to the system store here would be
// the dangerous reading: an operator who names a private CA and gets a typo in
// the path would silently end up trusting the public web PKI instead of the one
// CA they meant to trust.
//
// Conformance: docs/logsrvd-reference/ TLS-007, CONF-031.
func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %s contains no usable PEM certificates", path)
	}
	return pool, nil
}
