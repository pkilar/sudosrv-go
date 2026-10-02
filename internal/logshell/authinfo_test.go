// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/authinfo_test.go
package logshell

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"math"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestParseAuthInfoRetainsCertificateExpiryPolicy(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{
		Key: signer.PublicKey(), CertType: ssh.UserCert, KeyId: "expiry-test",
		ValidBefore: 2000000000,
		Extensions:  map[string]string{TerminateOnCertExpiryExtension: ""},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	raw := "publickey " + cert.Type() + " " + base64.StdEncoding.EncodeToString(cert.Marshal())
	got, err := ParseAuthInfo([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := got.CertificateDeadline(time.Unix(1900000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !deadline.Equal(time.Unix(2000000000, 0)) {
		t.Fatalf("deadline = %v, want certificate ValidBefore", deadline)
	}
}

func TestCertificateDeadline(t *testing.T) {
	now := time.Unix(1900000000, 500000000)
	for _, tt := range []struct {
		name    string
		auth    AuthInfo
		want    time.Time
		wantErr bool
	}{
		{name: "certificate without flag", auth: AuthInfo{Method: AuthMethodCert, ValidBefore: 1}},
		{name: "plain key ignores flag", auth: AuthInfo{Method: AuthMethodKey, ValidBefore: 1, Extensions: map[string]string{TerminateOnCertExpiryExtension: ""}}},
		{name: "opted in", auth: AuthInfo{Method: AuthMethodCert, ValidBefore: 1900000001, Extensions: map[string]string{TerminateOnCertExpiryExtension: ""}}, want: time.Unix(1900000001, 0)},
		{name: "expired", auth: AuthInfo{Method: AuthMethodCert, ValidBefore: 1899999999, Extensions: map[string]string{TerminateOnCertExpiryExtension: ""}}, wantErr: true},
		{name: "expiry second already reached", auth: AuthInfo{Method: AuthMethodCert, ValidBefore: 1900000000, Extensions: map[string]string{TerminateOnCertExpiryExtension: ""}}, wantErr: true},
		{name: "zero expiry", auth: AuthInfo{Method: AuthMethodCert, Extensions: map[string]string{TerminateOnCertExpiryExtension: ""}}, wantErr: true},
		{name: "infinite validity", auth: AuthInfo{Method: AuthMethodCert, ValidBefore: ssh.CertTimeInfinity, Extensions: map[string]string{TerminateOnCertExpiryExtension: ""}}},
		{name: "out of range", auth: AuthInfo{Method: AuthMethodCert, ValidBefore: math.MaxInt64 + 1, Extensions: map[string]string{TerminateOnCertExpiryExtension: ""}}, wantErr: true},
		{name: "flag with value", auth: AuthInfo{Method: AuthMethodCert, ValidBefore: 1900000001, Extensions: map[string]string{TerminateOnCertExpiryExtension: "true"}}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.auth.CertificateDeadline(now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !got.Equal(tt.want) {
				t.Errorf("deadline = %v, want %v", got, tt.want)
			}
		})
	}
}

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
