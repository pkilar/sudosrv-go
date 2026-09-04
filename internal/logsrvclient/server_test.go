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
		{"sudo-iolog.acme.com(TLS)", "sudo-iolog.acme.com:30344", true},
		{"sudo-iolog.acme.com(Tls)", "sudo-iolog.acme.com:30344", true},
		{"sudo-iolog.acme.com:9999(TLS)", "sudo-iolog.acme.com:9999", true},
		{"[2001:db8::1](TLS)", "[2001:db8::1]:30344", true},
		{"[127.0.0.1]", "127.0.0.1:30343", false},
		{"[fe80::1%eth0]", "[fe80::1%eth0]:30343", false},
		{"[fe80::1%eth0]:9999(tls)", "[fe80::1%eth0]:9999", true},
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
		"sudo-iolog.acme.com()",
		"sudo-iolog.acme.com(tls",
		// Stripping one "(tls)" must not leave a parenthesised remainder to be
		// taken for a hostname.
		"sudo-iolog.acme.com(ssl)(tls)",
		"sudo-iolog.acme.com()(tls)",
		"sudo-iolog.acme.com(tls)(tls)",
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

// A spec with an incomplete, extra, or trailing bracket must be rejected
// outright, never reduced by naive bracket-stripping to an empty or mangled
// host -- an empty host resolves to the local system on dial, so a typo'd
// bracket must not silently redirect a session transcript there.
func TestParseServerRejectsMalformedBrackets(t *testing.T) {
	for _, spec := range []string{"[]", "[", "]", "][", "]abc[", "[::1]extra"} {
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

// Brackets denote an IP literal. Accepting a DNS name inside them would let a
// malformed address resolve and send transcripts to an unintended host, and a
// mistyped IPv6 literal would surface as a DNS error at login rather than as a
// config error at -validate. sudo's own parser only locates the ']'; this is
// deliberately stricter.
func TestParseServerRejectsBracketedNonIP(t *testing.T) {
	for _, spec := range []string{
		"[logsrv.example]",
		"[logsrv.example]:9999",
		"[logsrv.example](tls)",
		"[2001:db8:::1]",
		"[]",
		"[fe80::1%]",
		"[127.0.0.1%eth0]",
	} {
		if got, err := ParseServer(spec); err == nil {
			t.Errorf("ParseServer(%q) = %+v, want an error", spec, got)
		}
	}
}
