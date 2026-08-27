// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/route_test.go
package logshell

import (
	"path/filepath"
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
			// There is only ONE key space: the table's keys (internal-sftp,
			// rsync, git-shell), never a route's own realized Exec[0]. The
			// sftp route's exec target -- /usr/lib/ssh/sftp-server -- is not
			// itself a matching key, so a client naming it directly gets no
			// translation and falls to the default route, same as any other
			// ordinary command.
			name: "a route's own exec target is not itself a matching key", original: "/usr/lib/ssh/sftp-server -l INFO",
			wantKind: RouteDefault, wantPath: "", wantArgs: []string{"-c", "/usr/lib/ssh/sftp-server -l INFO"},
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
		// The one branch that legitimately places client text into an argv --
		// RouteCommand -- had no hostile coverage at all before this case: no
		// other entry here has field 0 "git-shell". This proves "one argv
		// element, never re-split" rather than just asserting it in a comment.
		"git-shell -c x\nrm -rf /; $(id)",
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
			// A matched route: the full argv (Path plus Args) must equal
			// EXACTLY what the config named for the key that matched, and
			// Original must be the client's string verbatim. Comparing against
			// the live table -- rather than a fixed exception list of "known
			// safe" substrings -- means a new route added to testRoutes can
			// never quietly widen what counts as acceptable leakage, and this
			// also catches a Path bug (e.g. Path: fields[0]) that a check of
			// Args alone would miss.
			route, ok := f.Routes[filepath.Base(strings.Fields(original)[0])]
			if !ok {
				t.Fatalf("Resolve reported a match (%v) but no table entry accounts for %q", got.Kind, original)
			}
			wantArgv := route.Exec
			if len(wantArgv) == 0 {
				// A Command route's argv is [Command, "-c", original] -- the one
				// shape that legitimately carries client text, as a single
				// opaque argv element that logsh never re-splits or hands to a
				// shell.
				wantArgv = []string{route.Command, "-c", original}
			}
			if gotArgv := append([]string{got.Path}, got.Args...); !slices.Equal(gotArgv, wantArgv) {
				t.Errorf("matched-route argv = %q, want %q", gotArgv, wantArgv)
			}
			if got.Original != original {
				t.Errorf("Original = %q, want %q", got.Original, original)
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

// TestResolveMalformedRouteFallsThroughToDefault.
//
// A route with neither Exec nor Command set -- a "exce:" typo in yaml, say --
// is malformed. Config.Validate is meant to reject it before Resolve ever sees
// it, but Resolve must not assume Validate ran: treating the match as usable
// would produce Kind: RouteCommand with Path: "", which breaks Target's own
// documented invariant (Path is empty only for RouteInteractive and
// RouteDefault) and would report NeedsShell() == true for a route the caller
// believes was matched. So a match with nothing runnable behind it must behave
// exactly like no match at all.
func TestResolveMalformedRouteFallsThroughToDefault(t *testing.T) {
	f := ForceCommandConfig{Routes: map[string]Route{
		"broken": {}, // neither Exec nor Command set
	}}
	got := f.Resolve("broken -x")
	if got.Kind != RouteDefault {
		t.Errorf("Kind = %v, want RouteDefault", got.Kind)
	}
	if got.Path != "" {
		t.Errorf("Path = %q, want empty", got.Path)
	}
	if !slices.Equal(got.Args, []string{"-c", "broken -x"}) {
		t.Errorf("Args = %q, want [-c broken -x]", got.Args)
	}
	if got.Original != "broken -x" {
		t.Errorf("Original = %q, want %q", got.Original, "broken -x")
	}
}
