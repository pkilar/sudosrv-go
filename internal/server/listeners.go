// SPDX-License-Identifier: Apache-2.0
// Filename: internal/server/listeners.go
package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sudosrv/internal/config"
)

// boundListener pairs a live listener with the CONFIGURATION address string it
// was created from.
//
// The string is what reconciliation compares, not the resolved socket address,
// mirroring C: server_setup() matches the verbatim listen_address strings
// (addr->sa_str) of the new configuration against the existing listeners
// (logsrvd/logsrvd.c:1809-1874). A consequence worth knowing about, shared with
// C: changing DNS so that an unchanged address string now resolves elsewhere
// does NOT rebind, because the string did not change.
// Conformance: docs/logsrvd-reference/ CONF-019.
type boundListener struct {
	addr  string // the configured address string
	isTLS bool
	ln    net.Listener
}

// listenerSet is the address plan a configuration asks for.
func listenerSet(cfg *config.Config) []struct {
	addr  string
	isTLS bool
} {
	var want []struct {
		addr  string
		isTLS bool
	}
	if cfg.Server.ListenAddress != "" {
		want = append(want, struct {
			addr  string
			isTLS bool
		}{cfg.Server.ListenAddress, false})
	}
	if cfg.Server.ListenAddressTLS != "" {
		want = append(want, struct {
			addr  string
			isTLS bool
		}{cfg.Server.ListenAddressTLS, true})
	}
	return want
}

// bindListener binds one listener and wraps it in TLS when required.
func (s *Server) bindListener(addr string, isTLS bool) (*boundListener, error) {
	base, err := listenTCP(s.ctx, addr)
	if err != nil {
		kind := "plaintext"
		if isTLS {
			kind = "TLS"
		}
		return nil, fmt.Errorf("failed to start %s listener on %s: %w", kind, addr, err)
	}
	bl := &boundListener{addr: addr, isTLS: isTLS, ln: base}
	if isTLS {
		if s.tlsProvider == nil {
			_ = base.Close()
			return nil, fmt.Errorf("internal: TLS listener requested on %s with no TLS configuration built", addr)
		}
		bl.ln = tls.NewListener(base, s.tlsProvider.listenerConfig())
	}
	return bl, nil
}

// reconcileListeners brings the live listener set in line with cfg, leaving
// every established connection untouched.
//
// It binds every NEW address before closing any removed one, which is where it
// deliberately parts company with C. C frees the departing listeners first and
// binds afterwards, so a bind failure can leave the daemon with nothing
// listening -- at which point server_reload() calls sudo_fatalx("unable to setup
// listen socket") and the process exits (logsrvd/logsrvd.c:1809-1874). Binding
// first means a reload that cannot be satisfied changes nothing and the daemon
// keeps serving on the addresses it already had, which is the same
// keep-the-previous-config rule the rest of reload() follows.
//
// The one case C handles and this does not is swapping two listeners' ports in a
// single reload: the new bind collides with the old socket that has not been
// released yet. That reload is refused with a clear error and needs either two
// reloads or a restart.
//
// Closing a net.Listener stops accepts; it does not disturb connections already
// accepted from it, so in-flight sessions survive a listener being removed.
// Conformance: docs/logsrvd-reference/ ARCH-019, CONF-019.
func (s *Server) reconcileListeners(cfg *config.Config) error {
	want := listenerSet(cfg)

	keep := make([]*boundListener, 0, len(want))
	var added []*boundListener
	used := make(map[*boundListener]bool, len(s.listeners))

	for _, w := range want {
		var match *boundListener
		for _, have := range s.listeners {
			if !used[have] && have.addr == w.addr && have.isTLS == w.isTLS {
				match = have
				break
			}
		}
		if match != nil {
			used[match] = true
			keep = append(keep, match)
			continue
		}
		bl, err := s.bindListener(w.addr, w.isTLS)
		if err != nil {
			// Roll back: close only what THIS call bound. Everything that was
			// already serving keeps serving.
			for _, a := range added {
				_ = a.ln.Close()
			}
			return err
		}
		added = append(added, bl)
		keep = append(keep, bl)
	}

	// Every bind succeeded; retire the listeners the new configuration dropped.
	for _, have := range s.listeners {
		if used[have] {
			continue
		}
		if err := have.ln.Close(); err != nil {
			slog.Error("Failed to close listener removed by reload", "address", have.addr, "error", err)
		} else {
			slog.Info("Stopped listener removed by reload", "address", have.addr, "tls", have.isTLS)
		}
	}

	s.listeners = keep

	// Serve the newly bound ones only now, so a rolled-back reload never spawns
	// an accept loop for a listener it then closed.
	for _, bl := range added {
		s.waitGroup.Go(func() { s.acceptLoop(bl.ln) })
		slog.Info("Started listener added by reload", "address", bl.addr, "tls", bl.isTLS)
	}
	return nil
}
