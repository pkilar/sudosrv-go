// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/authinfo.go
package logshell

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Authentication methods recorded with a session.
const (
	// AuthMethodCert means an SSH certificate authenticated the session, so a
	// human is named in its key ID.
	AuthMethodCert = "publickey-cert"
	// AuthMethodKey means a plain public key did. Under the certificate design
	// this is the break-glass account or a key the fallback audit missed, and it
	// is worth alerting on rather than treating as normal.
	AuthMethodKey = "publickey"
)

// AuthInfo is the credential that opened this session.
//
// It exists because direct root login destroys the attribution sudo gets for
// free: the account is root, and the only place a human's name survives is the
// certificate. sshd writes the credentials it accepted to the file named by
// SSH_USER_AUTH when ExposeAuthInfo is on, and this is that file, parsed.
type AuthInfo struct {
	// Method is one of the AuthMethod* constants, or "" when nothing was read.
	Method string

	// KeyID is the certificate's key ID: the human, typically a Kerberos
	// principal. Empty for a plain key.
	KeyID string

	// Serial is the certificate serial, the join key between the CA's issuance
	// log and this host's sshd auth log.
	Serial uint64

	// Principals are the certificate's valid principals, e.g. root-web.
	Principals []string

	// CAFingerprint identifies the signing CA, which is what distinguishes a
	// normal issuance from the emergency CA.
	CAFingerprint string

	// KeyFingerprint identifies the presented credential itself, and is the only
	// identifier available when it was a plain key.
	KeyFingerprint string
}

// ErrNoCredential reports that nothing in the auth-info file parsed as a public
// credential.
var ErrNoCredential = errors.New("no public credential found")

// ReadAuthInfo parses the file sshd names in SSH_USER_AUTH.
//
// Every failure here is reportable, never fatal. The caller logs at crit and
// carries on: a session recorded without attribution is enormously better than a
// session refused because attribution could not be read, and refusing would put
// a file sshd wrote on the critical path of every root login.
func ReadAuthInfo(path string) (AuthInfo, error) {
	if path == "" {
		return AuthInfo{}, errors.New("SSH_USER_AUTH is not set (is ExposeAuthInfo enabled?)")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from sshd, read as the session user
	if err != nil {
		return AuthInfo{}, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseAuthInfo(raw)
}

// ParseAuthInfo parses auth-info content. Split from ReadAuthInfo so the format
// can be tested without a file.
//
// Each line is "<method> <keytype> <base64>". The method field is not matched
// against a list: OpenSSH has added method names over time, and a line whose
// third field decodes to a public key is a credential whatever the first field
// says. A line that does not decode is skipped rather than failing the file,
// because one unparseable line must not discard a certificate on the next.
//
// A certificate always wins over a plain key, regardless of order: only the
// certificate names a human, which is the entire purpose of reading this.
func ParseAuthInfo(raw []byte) (AuthInfo, error) {
	var plain AuthInfo
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			continue
		}
		pub, err := ssh.ParsePublicKey(blob)
		if err != nil {
			continue
		}
		if cert, ok := pub.(*ssh.Certificate); ok {
			return AuthInfo{
				Method:         AuthMethodCert,
				KeyID:          cert.KeyId,
				Serial:         cert.Serial,
				Principals:     cert.ValidPrincipals,
				CAFingerprint:  ssh.FingerprintSHA256(cert.SignatureKey),
				KeyFingerprint: ssh.FingerprintSHA256(cert),
			}, nil
		}
		if plain.Method == "" {
			plain = AuthInfo{Method: AuthMethodKey, KeyFingerprint: ssh.FingerprintSHA256(pub)}
		}
	}
	if plain.Method != "" {
		return plain, nil
	}
	return AuthInfo{}, ErrNoCredential
}
