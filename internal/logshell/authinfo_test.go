// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/authinfo_test.go
package logshell

import (
	"path/filepath"
	"testing"
)

func authinfoPath(name string) string { return filepath.Join("testdata", "authinfo", name) }

// TestReadAuthInfoCertificates is the attribution requirement, R-2.
//
// A session running AS root learns which human opened it from the certificate
// sshd exposes via SSH_USER_AUTH. The key ID and serial live inside the base64
// certificate blob, which is why the reference shell wrapper in the design
// document could not actually do this and why it is in Go.
//
// All three key algorithms are exercised because the certificate's key-specific
// fields differ per algorithm, and getting that wrong yields plausible garbage
// rather than an error.
func TestReadAuthInfoCertificates(t *testing.T) {
	for _, name := range []string{"cert-ed25519.authinfo", "cert-rsa.authinfo", "cert-ecdsa.authinfo"} {
		t.Run(name, func(t *testing.T) {
			got, err := ReadAuthInfo(authinfoPath(name))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Method != AuthMethodCert {
				t.Errorf("Method = %q, want %q", got.Method, AuthMethodCert)
			}
			if got.KeyID != "jsmith@CORP.EXAMPLE.COM" {
				t.Errorf("KeyID = %q, want jsmith@CORP.EXAMPLE.COM", got.KeyID)
			}
			if got.Serial != 20260819000137 {
				t.Errorf("Serial = %d, want 20260819000137", got.Serial)
			}
			if len(got.Principals) != 2 || got.Principals[0] != "root-web" {
				t.Errorf("Principals = %v, want [root-web root-everywhere]", got.Principals)
			}
			if len(got.CAFingerprint) < 8 || got.CAFingerprint[:7] != "SHA256:" {
				t.Errorf("CAFingerprint = %q, want a SHA256: fingerprint", got.CAFingerprint)
			}
		})
	}
}

// TestReadAuthInfoPlainKeyIsASignalNotAnError.
//
// A root SSH login that presents a plain key rather than a certificate is
// exactly what the certificate migration intends to eliminate: the break-glass
// account, or a key the fallback audit missed. It is recorded as a fact with no
// key ID, so a SIEM rule can fire on it.
func TestReadAuthInfoPlainKeyIsASignalNotAnError(t *testing.T) {
	got, err := ReadAuthInfo(authinfoPath("plainkey.authinfo"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Method != AuthMethodKey {
		t.Errorf("Method = %q, want %q", got.Method, AuthMethodKey)
	}
	if got.KeyID != "" {
		t.Errorf("KeyID = %q, want empty for a plain key", got.KeyID)
	}
	if got.KeyFingerprint == "" {
		t.Error("KeyFingerprint must be recorded so the credential is identifiable")
	}
}

// TestReadAuthInfoPrefersTheCertificate.
//
// sshd may list several credentials. A certificate names a human and a plain key
// does not, so the certificate wins regardless of line order.
func TestReadAuthInfoPrefersTheCertificate(t *testing.T) {
	got, err := ReadAuthInfo(authinfoPath("key-then-cert.authinfo"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Method != AuthMethodCert || got.KeyID != "jsmith@CORP.EXAMPLE.COM" {
		t.Errorf("got %+v, want the certificate", got)
	}
}

// TestReadAuthInfoFailuresAreErrorsNotPanics.
//
// Every one of these must return an error the caller can log and carry on from.
// Attribution failure warns and proceeds: an unattributed recording beats no
// recording, so nothing here may be fatal.
func TestReadAuthInfoFailuresAreErrorsNotPanics(t *testing.T) {
	for _, tt := range []struct{ name, path string }{
		{"unset SSH_USER_AUTH", ""},
		{"missing file", authinfoPath("does-not-exist.authinfo")},
		{"empty file", authinfoPath("empty.authinfo")},
		{"unparseable content", authinfoPath("junk.authinfo")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadAuthInfo(tt.path)
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if got.Method != "" {
				t.Errorf("want a zero AuthInfo on failure, got %+v", got)
			}
		})
	}
}
