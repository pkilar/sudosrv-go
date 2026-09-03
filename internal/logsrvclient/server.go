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

// tlsSuffix is the ONLY accepted suffix. Anything else parenthesised is an
// error rather than a hostname: this token alone decides whether a session
// transcript crosses the network in the clear, and a typo in it must not
// degrade quietly to plaintext.
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
	case strings.HasSuffix(s, tlsSuffix):
		useTLS = true
		s = strings.TrimSuffix(s, tlsSuffix)
	case strings.HasSuffix(s, ")"):
		i := strings.LastIndex(s, "(")
		if i == -1 {
			return Target{}, fmt.Errorf("log server %q: unbalanced %q", spec, ")")
		}
		return Target{}, fmt.Errorf(
			"log server %q: %q is not a recognised suffix; only %q selects TLS",
			spec, s[i:], tlsSuffix)
	case strings.Contains(s, "("):
		return Target{}, fmt.Errorf("log server %q: unbalanced %q", spec, "(")
	}

	if s == "" {
		return Target{}, fmt.Errorf("log server %q: no host before %q", spec, tlsSuffix)
	}

	port := DefaultPort
	if useTLS {
		port = DefaultTLSPort
	}

	// SplitHostPort succeeds only when a port is actually present; it also
	// validates the bracketed IPv6 form for us.
	if host, p, err := net.SplitHostPort(s); err == nil {
		if host == "" {
			return Target{}, fmt.Errorf("log server %q: no host before the port", spec)
		}
		if p == "" {
			return Target{}, fmt.Errorf("log server %q: empty port", spec)
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
			return Target{}, fmt.Errorf("log server %q: malformed IPv6 literal", spec)
		}
		host = s[1 : len(s)-1]
	}
	if host == "" {
		return Target{}, fmt.Errorf("log server %q: no host before the port", spec)
	}
	return Target{Address: net.JoinHostPort(host, port), UseTLS: useTLS}, nil
}
