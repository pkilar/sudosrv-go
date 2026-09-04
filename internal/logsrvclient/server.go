// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logsrvclient/server.go
package logsrvclient

import (
	"fmt"
	"net"
	"strings"
)

// Default ports, matching sudo's log_servers: the (tls) suffix selects both the
// transport and the port, so an operator writes one token rather than two.
const (
	DefaultPort    = "30343"
	DefaultTLSPort = "30344"
)

// tlsSuffix is the ONLY accepted suffix, matched case-insensitively because
// sudo does the same -- lib/iolog/host_port.c compares it with strcasecmp, so
// "(TLS)" is as valid as "(tls)" in a sudoers log_servers list and must not be
// refused here.
//
// Anything else parenthesised is an error rather than a hostname. That part is
// deliberately STRICTER than sudo, which truncates at '(' and silently falls
// through to plaintext on an unrecognised flag: this token alone decides
// whether a session transcript crosses the network in the clear, so a typo in
// it must not degrade quietly.
const tlsSuffix = "(tls)"

// Target is one resolved log server. Address always carries an explicit port,
// so callers need no defaulting logic and can print it in diagnostics verbatim.
type Target struct {
	Address string
	UseTLS  bool
}

// ParseServer resolves one sudo-style log server address: host[:port][(tls)].
func ParseServer(spec string) (Target, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return Target{}, fmt.Errorf("log server address is empty")
	}

	useTLS := false
	switch {
	case len(s) >= len(tlsSuffix) && strings.EqualFold(s[len(s)-len(tlsSuffix):], tlsSuffix):
		useTLS = true
		s = s[:len(s)-len(tlsSuffix)]
	case strings.HasSuffix(s, ")"):
		i := strings.LastIndex(s, "(")
		if i == -1 {
			return Target{}, fmt.Errorf("log server %q: unbalanced %q", spec, ")")
		}
		return Target{}, fmt.Errorf(
			"log server %q: %q is not a recognised suffix; only %q, in any case, selects TLS",
			spec, s[i:], tlsSuffix)
	}

	// Checked AFTER the suffix is stripped rather than as another case of the
	// switch above: a case there is unreachable once the "(tls)" case matches,
	// so stripping one suffix would leave a parenthesised remainder to be taken
	// for a hostname -- "h(ssl)(tls)" resolving the host "h(ssl)". Parentheses
	// are never part of a host, so any that survive here are an error.
	if strings.ContainsAny(s, "()") {
		return Target{}, fmt.Errorf(
			"log server %q: %q is not a valid host; parentheses appear only in a trailing %s suffix",
			spec, s, tlsSuffix)
	}

	if s == "" {
		return Target{}, fmt.Errorf("log server %q: no host before %q", spec, tlsSuffix)
	}

	port := DefaultPort
	if useTLS {
		port = DefaultTLSPort
	}

	// SplitHostPort succeeds only when a port is actually present. It checks
	// bracket STRUCTURE but not the contents, so a bracketed host still has to
	// be validated as an IP literal below.
	if host, p, err := net.SplitHostPort(s); err == nil {
		if host == "" {
			return Target{}, fmt.Errorf("log server %q: no host before the port", spec)
		}
		if p == "" {
			return Target{}, fmt.Errorf("log server %q: empty port", spec)
		}
		if strings.HasPrefix(s, "[") {
			if err := checkBracketed(host, spec); err != nil {
				return Target{}, err
			}
		}
		return Target{Address: net.JoinHostPort(host, p), UseTLS: useTLS}, nil
	}

	// No port. A spec containing '[' or ']' must be a single, complete IPv6
	// literal -- '[' at the very start, ']' at the very end, and nothing else
	// bracketed or trailing -- rather than have stray or unbalanced brackets
	// silently stripped into a mangled or empty host.
	host := s
	if strings.ContainsAny(s, "[]") {
		if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' || strings.ContainsAny(s[1:len(s)-1], "[]") {
			return Target{}, fmt.Errorf("log server %q: malformed brackets", spec)
		}
		host = s[1 : len(s)-1]
		if err := checkBracketed(host, spec); err != nil {
			return Target{}, err
		}
	}
	if host == "" {
		return Target{}, fmt.Errorf("log server %q: no host before the port", spec)
	}
	return Target{Address: net.JoinHostPort(host, port), UseTLS: useTLS}, nil
}

// checkBracketed validates the contents of a [...] host.
//
// Brackets denote an IP literal, so a name inside them is a typo rather than a
// host. sudo's parser only locates the ']' and never inspects what precedes it
// (lib/iolog/host_port.c), which means "[logsrv.example]" resolves through DNS
// and ships transcripts to a host the operator never wrote in brackets, while a
// mistyped literal like "[2001:db8:::1]" surfaces as a dial error at the next
// login instead of a config error at -validate. logsh refuses a login rather
// than failing open, so the config-time error is the one worth having.
func checkBracketed(inner, spec string) error {
	addr, zone, hasZone := strings.Cut(inner, "%")
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("log server %q: %q is bracketed but is not an IP address", spec, addr)
	}
	if hasZone {
		if zone == "" {
			return fmt.Errorf("log server %q: empty zone after %q", spec, "%")
		}
		if ip.To4() != nil {
			return fmt.Errorf("log server %q: a zone is only meaningful on an IPv6 address", spec)
		}
	}
	return nil
}
