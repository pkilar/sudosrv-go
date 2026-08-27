// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/route.go
package logshell

import (
	"path/filepath"
	"strings"
)

// ForceCommandConfig configures the forced-command entry point.
//
// SECURITY: everything in this file runs before any user code in a root SSH
// session, on a string the client chose. Read it as security-relevant code.
type ForceCommandConfig struct {
	// Shell overrides the account's own shell for the interactive and default
	// routes. NORMALLY EMPTY.
	//
	// Empty means the session runs the shell in the account's passwd entry --
	// what sshd would have exec'd without ForceCommand, so enabling the recorder
	// changes which shell runs on no host. Setting this pins one shell for every
	// host sharing the file, which will differ from the account's real shell
	// wherever the two disagree and from what a console login gives. Warnings
	// says so.
	Shell string `yaml:"shell"`

	// Routes maps a program basename to what should run instead.
	//
	// It is a LITERAL ALLOWLIST, not a pattern language: keys are matched exactly
	// against the basename of the first whitespace-separated field of
	// SSH_ORIGINAL_COMMAND. No globs, no regular expressions, no prefix matching,
	// no case folding. See Resolve for why that is the safe shape.
	Routes map[string]Route `yaml:"routes"`
}

// Route is one entry in the table. Exactly one of Exec and Command is set;
// Config.Validate enforces that.
type Route struct {
	// Exec is a complete argv, taken verbatim from the configuration file. The
	// client's command reaches the program only through the inherited
	// SSH_ORIGINAL_COMMAND variable -- which is exactly how rrsync expects it,
	// and how sshd would have delivered it.
	Exec []string `yaml:"exec"`

	// Command names a program run as `prog -c "<SSH_ORIGINAL_COMMAND>"`, with the
	// command as ONE argv element that is never re-split and never passed
	// through a shell by logsh. This is the shape git-shell expects.
	Command string `yaml:"command"`
}

// RouteKind is what a resolved target turns out to be.
type RouteKind int

const (
	// RouteInteractive means the client requested no command. The caller runs
	// the account's shell with no arguments -- and decides recorded-versus-not
	// from whether a terminal is attached, NEVER from this kind.
	RouteInteractive RouteKind = iota
	// RouteExec means a route matched and named a complete argv.
	RouteExec
	// RouteCommand means a route matched and named a program to pass the
	// original command to.
	RouteCommand
	// RouteDefault means nothing matched: the account's shell runs the original
	// command, exactly as it would with no ForceCommand present.
	RouteDefault
)

func (k RouteKind) String() string {
	switch k {
	case RouteInteractive:
		return "interactive"
	case RouteExec:
		return "exec"
	case RouteCommand:
		return "command"
	default:
		return "default"
	}
}

// Target is a resolved thing to run.
type Target struct {
	// Kind is which branch was taken.
	Kind RouteKind

	// Path is the program to exec, EMPTY for RouteInteractive and RouteDefault.
	// Those two run the account's shell, which routing does not resolve --
	// Config.ResolveEntryShell does, and the caller fills it in.
	Path string

	// Args are the arguments after argv[0].
	Args []string

	// Original is SSH_ORIGINAL_COMMAND verbatim, for the session record.
	Original string
}

// NeedsShell reports whether the caller must resolve the account's shell to
// complete this target.
func (t Target) NeedsShell() bool { return t.Path == "" }

// Resolve decides what a forced-command session runs.
//
// The matching rule, in full:
//
//  1. An EMPTY original means no command was requested: interactive. The routes
//     are not consulted. Note that this is not the same question as "is there a
//     terminal" -- the caller settles that separately, because `ssh -t host cmd`
//     supplies both.
//  2. Otherwise: split on whitespace, take field 0, take its basename, and look
//     that up as an EXACT map key.
//  3. No match: the default route, `shell -c "<original>"`.
//
// Why exact basename matching is the safe shape. The only two things that can
// happen to an unrecognised client string are that it becomes a single -c
// argument, or nothing -- so NO BRANCH IS MORE PERMISSIVE than a host with no
// ForceCommand at all. Metacharacters defeat matching rather than exploiting it:
// "sftp-server; rm -rf /" has field 0 "sftp-server;", which is not the key
// "sftp-server", so it falls to the default route and the shell handles the whole
// string as it always would.
//
// That failure direction is deliberate. A matcher that stripped punctuation
// before comparing would match the sftp route and silently DISCARD the rest of
// the command -- a change in meaning invisible to the client and absent from the
// transcript. Refusing to match is the honest outcome.
func (f ForceCommandConfig) Resolve(original string) Target {
	if original == "" {
		return Target{Kind: RouteInteractive}
	}

	// strings.Fields on a whitespace-only string yields nothing, which falls
	// through to the default route -- correct, since the client did send a
	// command and the shell should see exactly what they sent.
	if fields := strings.Fields(original); len(fields) > 0 {
		if r, ok := f.Routes[filepath.Base(fields[0])]; ok {
			if len(r.Exec) > 0 {
				// The argv is the CONFIG's, verbatim. Nothing from the client
				// appears in it; the client's string travels in the inherited
				// SSH_ORIGINAL_COMMAND, as sshd would have delivered it.
				return Target{
					Kind:     RouteExec,
					Path:     r.Exec[0],
					Args:     append([]string(nil), r.Exec[1:]...),
					Original: original,
				}
			}
			return Target{
				Kind:     RouteCommand,
				Path:     r.Command,
				Args:     []string{"-c", original},
				Original: original,
			}
		}
	}
	return Target{Kind: RouteDefault, Args: []string{"-c", original}, Original: original}
}
