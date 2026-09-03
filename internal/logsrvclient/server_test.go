// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logsrvclient/server_test.go
package logsrvclient

import (
	"strings"
	"testing"
)

func TestParseServer(t *testing.T) {
	for _, tc := range []struct {
		spec    string
		address string
		useTLS  bool
	}{
		{"sudo-iolog.acme.com", "sudo-iolog.acme.com:30343", false},
		{"sudo-iolog.acme.com(tls)", "sudo-iolog.acme.com:30344", true},
		{"sudo-iolog.acme.com:9999", "sudo-iolog.acme.com:9999", false},
		{"sudo-iolog.acme.com:9999(tls)", "sudo-iolog.acme.com:9999", true},
		{"127.0.0.1", "127.0.0.1:30343", false},
		{"[2001:db8::1]", "[2001:db8::1]:30343", false},
		{"[2001:db8::1]:9999(tls)", "[2001:db8::1]:9999", true},
		{"2001:db8::1", "[2001:db8::1]:30343", false},
		{"  sudo-iolog.acme.com(tls)  ", "sudo-iolog.acme.com:30344", true},
	} {
		got, err := ParseServer(tc.spec)
		if err != nil {
			t.Errorf("ParseServer(%q): unexpected error %v", tc.spec, err)
			continue
		}
		if got.Address != tc.address || got.UseTLS != tc.useTLS {
			t.Errorf("ParseServer(%q) = {%q, %v}, want {%q, %v}",
				tc.spec, got.Address, got.UseTLS, tc.address, tc.useTLS)
		}
	}
}

// The suffix is the single token deciding whether a transcript crosses the
// network in the clear. A typo in it must fail loudly, never fall through to
// plaintext or be read as part of a hostname.
func TestParseServerRejectsMalformedSuffix(t *testing.T) {
	for _, spec := range []string{
		"sudo-iolog.acme.com(ssl)",
		"sudo-iolog.acme.com(TLS)",
		"sudo-iolog.acme.com()",
		"sudo-iolog.acme.com(tls",
	} {
		if got, err := ParseServer(spec); err == nil {
			t.Errorf("ParseServer(%q) = %+v, want an error", spec, got)
		}
	}
}

func TestParseServerRejectsEmptyAndHostless(t *testing.T) {
	for _, spec := range []string{"", "   ", "(tls)", ":", ":30344", "host:"} {
		if got, err := ParseServer(spec); err == nil {
			t.Errorf("ParseServer(%q) = %+v, want an error", spec, got)
		}
	}
}

// The message is shown while refusing a login, so it must name the input.
func TestParseServerErrorNamesTheSpec(t *testing.T) {
	_, err := ParseServer("sudo-iolog.acme.com(ssl)")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "sudo-iolog.acme.com(ssl)") {
		t.Errorf("error %q does not name the offending spec", err)
	}
}
