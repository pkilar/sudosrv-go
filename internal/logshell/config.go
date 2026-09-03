// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/config.go
package logshell

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sudosrv/internal/eventlog"
	"sudosrv/internal/logsrvclient"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultConfigPath is where logsh looks when no -config is given. It is a
// compiled-in absolute path rather than anything relative or environment-driven:
// logsh is a login shell, so $PWD and the environment are attacker-influenced at
// the moment it starts.
const DefaultConfigPath = "/etc/logsh/logsh.yaml"

// Config is the complete logsh configuration.
//
// Option names track sudo's iolog knobs (log_ttyin, log_ttyout, iolog_flush,
// ...) so that an operator who knows sudoers does not have to learn a second
// vocabulary for the same concepts.
type Config struct {
	// Shells maps an invocation name to the real shell it stands for. logsh is
	// a multi-call binary: /usr/sbin/lbash is a symlink to it, and the name it
	// was invoked under selects the shell to exec.
	//
	// The mapping is explicit rather than derived by stripping the leading "l",
	// because inference would turn any symlink an administrator happens to
	// create into an exec primitive. Only what is listed here can be run.
	Shells map[string]string `yaml:"shells"`

	// RecordUsers lists the accounts whose sessions are recorded. A user not
	// named here gets the real shell with no recording and no log entry, which
	// is what makes it safe to install logsh as a system-wide shell before
	// deciding who it applies to.
	RecordUsers []string `yaml:"record_users"`

	// Stream toggles. The tty pair applies to interactive (PTY) sessions; the
	// std* trio applies to non-interactive ones.
	//
	// LogTTYIn defaults to FALSE and LogTTYOut to TRUE. Note carefully that this
	// does NOT mean keystrokes go unrecorded: terminal echo puts almost
	// everything typed into the ttyout stream anyway. Disabling ttyin only
	// protects the moments when echo is off, which is to say password prompts.
	// The user-facing notice must say so; see doc/ for the wording.
	LogTTYIn  bool `yaml:"log_ttyin"`
	LogTTYOut bool `yaml:"log_ttyout"`
	LogStdin  bool `yaml:"log_stdin"`
	LogStdout bool `yaml:"log_stdout"`
	LogStderr bool `yaml:"log_stderr"`

	// IologFlush forces each buffer to the server as it is produced rather than
	// batching. Matches sudo's iolog_flush.
	IologFlush bool `yaml:"iolog_flush"`

	Server ServerConfig `yaml:"server"`

	// FailClosed refuses the session when it cannot be recorded at all. See
	// FailClosed's precise meaning in the failure-mode logic: it fires only when
	// the local journal cannot be opened AND the server is unreachable, never on
	// a mere network blip, because a blip must not lock out a fleet.
	FailClosed bool `yaml:"fail_closed"`

	// NestedSessions decides what to do when logsh finds itself inside something
	// that may already be recording: record, metadata, or skip. Default record.
	//
	// It applies to sudo only. Nesting inside another logsh always skips, because
	// there is nothing to weigh up -- the outer logsh is certainly capturing these
	// bytes, they pass through its pty to get here.
	//
	// Under sudo it IS a judgement call, and logsh cannot make it: sudo records
	// I/O only when the matched sudoers rule carries log_output, and nothing
	// visible from inside the session says whether it did.
	//
	// So the default is `record`, and it is deliberately the WASTEFUL option.
	// `metadata` was the default first, on the reasoning that it drops the
	// duplicate transcript while still recording that the session happened. That
	// reasoning was wrong in one specific and important case: on a host whose
	// sudoers rule lacks log_output, `ordinary shell -> sudo -i -> root logsh`
	// leaves the root session's commands and output captured by NOTHING. A
	// de-duplication feature that produces an unrecorded privileged session in
	// its default configuration has made things worse, not better.
	//
	// Duplication is recoverable -- both copies carry the same session UUID, so a
	// SIEM can drop one. A transcript nobody took is gone. Choose `metadata` or
	// `skip` once you can state that every sudoers rule reaching a shell carries
	// log_output; until then the cost of the default is disk.
	NestedSessions string `yaml:"nested_sessions"`

	// CommandLog logs each executed command to LOCAL syslog, keyed by a session
	// UUID. Independent of session recording in every direction: its own toggle,
	// its own destination, and it works whether the session is recorded,
	// journalled, or not recorded at all.
	CommandLog CommandLogConfig `yaml:"command_log"`

	// ForceCommand configures the sshd ForceCommand entry point: which shell an
	// interactive root SSH session runs, and what a client's requested command
	// is routed to. Only consulted when logsh is invoked as EntryName.
	ForceCommand ForceCommandConfig `yaml:"force_command"`

	// BreakGlassMarker names a root-owned file whose existence forces fail-open
	// for the session, with a crit-priority syslog alert and a banner on the
	// terminal. It is the recovery path for "the box is reachable but recording
	// is broken"; the complementary path for "the box is not reachable" is a
	// second uid-0 account with a plain shell, which lives in sshd config rather
	// than here.
	BreakGlassMarker string `yaml:"break_glass_marker"`
}

// ServerConfig locates the log server logsh reports to.
//
// SECURITY: logsh runs as the logging-in user, not as root -- it is that user's
// login shell, exec'd by sshd after privileges have already been dropped. It
// therefore cannot hold a secret the user is not allowed to have. A TLS client
// key readable by logsh is readable by the user, who can then impersonate this
// host to the central log server and forge or suppress audit records.
//
// The supported topology for any site using client certificates is therefore:
//
//	logsh (as user) --loopback--> sudosrv in relay mode (as root) --mTLS--> central
//
// The local relay daemon owns the host credentials and the journal spool, both
// staying root-only, and logsh connects to 127.0.0.1 with no client certificate
// at all. That also keeps one user from reading another's spooled transcript.
//
// logsh itself carries no TLSCertFile/TLSKeyFile fields at all, not even as an
// opt-in escape hatch: any key logsh could read, the logging-in user could read
// too, and could then forge or suppress audit records under this host's
// identity. logsrvclient still has those fields -- sudosrv's relay uses them,
// running as root -- but ServerConfig below does not project them.
type ServerConfig struct {
	// LogServers is sudo's log_servers, in order of preference. Each entry is
	// host[:port][(tls)]; the suffix selects TLS and port 30344, its absence
	// plaintext and 30343. See logsrvclient.ParseServer.
	LogServers []string `yaml:"log_servers"`

	// CABundle verifies the server, matching sudo's log_server_cabundle. Empty
	// means the system trust store.
	CABundle string `yaml:"ca_bundle"`

	// Verify is sudo's log_server_verify. A pointer because absent must mean
	// TRUE: a plain bool cannot distinguish "not written" from "written false",
	// and defaulting verification off would be the wrong way round. Read it
	// through VerifyEnabled.
	Verify *bool `yaml:"verify"`

	ConnectTimeout  time.Duration `yaml:"connect_timeout"`
	ResponseTimeout time.Duration `yaml:"response_timeout"`

	// JournalDirectory holds sessions that could not be delivered live. It must
	// be writable by every recorded user, so with the loopback topology above it
	// should be left empty and the local relay's own cache used instead.
	JournalDirectory string `yaml:"journal_directory"`
}

// ClientID is announced to the log server in the ClientHello, naming this
// component so a server's records distinguish a shell-recorded session from one
// sent by sudo or forwarded by a relay.
const ClientID = "GoSudoLogSh/1.0"

// DefaultConfig returns a Config populated with defaults.
//
// Load calls this first and lets yaml.Unmarshal merge the file on top. yaml.v3
// only overwrites fields present in the document, so an omitted key keeps its
// default while an explicit `log_ttyout: false` still turns the stream off --
// which a zero-value re-application pass could not distinguish. This mirrors
// internal/config.defaultConfig.
func DefaultConfig() *Config {
	return &Config{
		// The common set. A mapping whose shell is not installed is a warning,
		// not an error: a host without fish is normal. Invoking a name whose
		// shell is missing is fatal, and that is checked at dispatch time.
		Shells: map[string]string{
			"lsh":   "/bin/sh",
			"lbash": "/bin/bash",
			"lzsh":  "/bin/zsh",
			"lksh":  "/bin/ksh",
			"lfish": "/usr/bin/fish",
		},
		RecordUsers: nil, // empty: record nobody until an operator opts an account in
		LogTTYIn:    false,
		LogTTYOut:   true,
		LogStdin:    false,
		LogStdout:   false,
		LogStderr:   false,
		IologFlush:  true,
		Server: ServerConfig{
			// A local sudosrv relay on loopback, plaintext: the recommended
			// topology, and what the previous upstream_host default resolved to.
			LogServers:      []string{"127.0.0.1"},
			ConnectTimeout:  5 * time.Second,
			ResponseTimeout: 30 * time.Second,
		},
		CommandLog: CommandLogConfig{
			Enabled:        false, // opt-in: it is ptrace, see CommandLogConfig.Enabled
			SyslogFacility: "authpriv",
			SyslogPriority: "info",
			MaxLen:         DefaultCommandLogMaxLen,
			Required:       false,
		},
		NestedSessions: NestedModeRecord,
		FailClosed:     true,
		// ForceCommand is deliberately zero: no shell override (so the account's
		// own passwd shell is used) and no routes (so every command reaches the
		// default route). That is the correct posture for a host that has not
		// enabled the forced-command entry point at all.
		BreakGlassMarker: "/etc/logsh/bypass",
	}
}

// Load reads and validates the configuration at path.
//
// The file must be owned by root and not writable by group or other. It names
// which binary root's shell execs and which accounts are recorded, so a user who
// can write it chooses both. This is the same reasoning that guards
// api.auth_token_file in the server config, applied to a higher-value target.
//
// It must however remain READABLE by every recorded user, because logsh reads it
// after sshd has dropped to that user. Mode 0644 root:root is correct; 0600 is
// not, and would lock out exactly the accounts it was meant to protect.
func Load(path string) (*Config, error) { return load(path, 0) }

// load is Load with the required owner uid as a parameter so the permission
// logic can be exercised by an unprivileged test. Load always passes 0; nothing
// else may.
func load(path string, ownerUID uint32) (*Config, error) {
	if err := CheckPerms(path, ownerUID); err != nil {
		return nil, err
	}
	return LoadUnchecked(path)
}

// removedServerKeys maps a key removed from server: in 0.4.0 to what
// replaces it, so removedKeyError can name a fix instead of just a key.
//
// It intentionally does not double as the set removedKeyError checks
// against -- that set comes from ServerConfig's own struct tags, via
// recognizedServerKeys, so a key this map fails to list (or one a later
// change to ServerConfig removes and this map never learns about) is still
// caught, just with a generic message instead of a specific "use X instead"
// one. See removedKeyError.
var removedServerKeys = map[string]string{
	"upstream_host":   `server.log_servers, e.g. ["127.0.0.1"] or ["host(tls)"]`,
	"use_tls":         `the "(tls)" suffix on a server.log_servers entry, e.g. ["host(tls)"]`,
	"tls_skip_verify": "server.verify: false",
	"tls_cacert_file": "server.ca_bundle",
	"tls_cert_file":   "nothing: logsh no longer presents a client certificate",
	"tls_key_file":    "nothing: logsh no longer presents a client certificate",
	"tls_min_version": "nothing: the TLS floor is pinned at 1.3",
}

// recognizedServerKeys returns the YAML keys ServerConfig understands, by
// walking its struct tags the same way gopkg.in/yaml.v3's getStructInfo does
// (yaml.go, unexported) rather than a second, hand-copied list -- a
// hand-copied list is one refactor away from rejecting a key that a later
// change to ServerConfig adds, and on a login shell that rejection is a
// lockout, not a cosmetic bug. See addYAMLKeys for the rules this follows.
func recognizedServerKeys() map[string]bool {
	keys := make(map[string]bool)
	addYAMLKeys(reflect.TypeFor[ServerConfig](), keys)
	return keys
}

// addYAMLKeys adds every top-level YAML key t contributes to keys, matching
// gopkg.in/yaml.v3@v3.0.1's getStructInfo field-by-field rather than just
// "does the field have a yaml tag":
//
//   - An unexported, non-anonymous field is skipped outright -- yaml.v3
//     cannot set it either.
//   - A bare `yaml:"-"` (no comma; the whole tag, checked before any
//     splitting) skips the field. `yaml:"-,anything"` is NOT this case, and
//     names the field "-" like any other explicit tag would.
//   - `,inline` on a struct (or pointer-to-struct) field hoists that
//     struct's own keys into the caller's set instead of adding one key for
//     the field itself; addYAMLKeys recurses to collect them. An inline MAP
//     is not handled -- ServerConfig has no map field today, and one would
//     make every key valid, which this map[string]bool result cannot
//     express.
//   - A field with no tag at all -- explicitly untagged, or anonymous with
//     no ",inline" -- falls back to strings.ToLower(field.Name). For an
//     anonymous field, reflect.StructField.Name IS the embedded type's own
//     name, so this one fallback correctly covers both cases at once.
//
// Getting any one of these wrong means a key yaml.v3 itself would decode is
// one removedKeyError rejects: a lockout in the code meant to prevent one.
func addYAMLKeys(t reflect.Type, keys map[string]bool) {
	for f := range t.Fields() {
		if f.PkgPath != "" && !f.Anonymous {
			continue // unexported, non-anonymous: yaml.v3 skips it too
		}
		tag := f.Tag.Get("yaml")
		if tag == "-" {
			continue // exact match only, checked before any comma split
		}
		name, opts, _ := strings.Cut(tag, ",")
		inline := false
		for opt := range strings.SplitSeq(opts, ",") {
			if opt == "inline" {
				inline = true
				break
			}
		}
		if inline {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				addYAMLKeys(ft, keys)
			}
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		keys[name] = true
	}
}

// removedKeyError reports every unrecognised key present under server:,
// sorted, or nil if every key there is one ServerConfig understands.
//
// This exists because yaml.Unmarshal ignores keys with no matching field:
// left unchecked, an old config's upstream_host is silently dropped,
// LogServers keeps its loopback default, Validate sees a non-empty list and
// passes, and every recorded session on that host is sent to 127.0.0.1 in
// the clear instead of the configured TLS server -- no error, no warning.
// Because an unusable config makes logsh refuse a login, the message this
// produces has to name every offending key, and where known its
// replacement, on sight: a typical unconverted config carries several of
// these keys at once, and an operator locked out of the host should not
// have to run -validate three times to hear about all of them.
//
// A key listed in removedServerKeys gets that specific replacement. Any
// other unrecognised key is still reported, just with a generic message --
// a removed key this table fails to list would otherwise fail exactly as
// silently as upstream_host did, which is why the check is not limited to
// the map's keys.
//
// Deliberately scoped to the server: block: the rest of the document stays
// as permissive to unknown keys as yaml.Unmarshal always was.
func removedKeyError(data []byte) error {
	var probe struct {
		Server map[string]any `yaml:"server"`
	}
	// If this second decode of the same bytes fails, the real Unmarshal a
	// few lines below (into cfg, which embeds ServerConfig) should already
	// have failed and returned: decoding into a typed struct is at least as
	// strict as decoding the same mapping into map[string]any, so a
	// map[string]any decode failing here, after the typed decode already
	// succeeded, would mean that assumption broke. Report it rather than
	// assume it can't happen -- silently discarding an error this task's own
	// probe hit is exactly the kind of silent pass-through this task exists
	// to close.
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("parsing server: block: %w", err)
	}
	recognized := recognizedServerKeys()
	keys := make([]string, 0, len(probe.Server))
	for k := range probe.Server {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic: report the same keys, in the same order, every time

	var lines []string
	for _, k := range keys {
		if recognized[k] {
			continue
		}
		if replacement, ok := removedServerKeys[k]; ok {
			lines = append(lines, fmt.Sprintf("server.%s was removed in 0.4.0; use %s", k, replacement))
			continue
		}
		allowed := make([]string, 0, len(recognized))
		for rk := range recognized {
			allowed = append(allowed, rk)
		}
		sort.Strings(allowed)
		lines = append(lines, fmt.Sprintf("server.%s is not a recognised config key (recognised: %s)", k, strings.Join(allowed, ", ")))
	}
	if len(lines) == 0 {
		return nil
	}
	noun := "key"
	if len(lines) != 1 {
		noun = "keys"
	}
	return fmt.Errorf("%d unusable %s under server:\n  %s", len(lines), noun, strings.Join(lines, "\n  "))
}

// LoadUnchecked parses and validates the CONTENT of a configuration file,
// skipping the ownership and mode gate.
//
// It exists so `logsh -validate` can report content errors and permission errors
// independently. Without it, an administrator drafting a config in their home
// directory would only ever be told about the ownership -- the syntax error two
// lines down would stay hidden until after they had installed the file as root.
//
// The runtime path must never use this. Use Load.
func LoadUnchecked(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	// Empty the shells map before unmarshalling, then restore the built-ins only
	// if the document omitted the key entirely.
	//
	// yaml.v3 MERGES a mapping into a pre-populated Go map rather than replacing
	// it, which is the opposite of what this field means. Shells is documented as
	// an allowlist, so an operator who writes out four entries is saying "these
	// four and nothing else" -- but a straight unmarshal would leave every
	// built-in default in place alongside them. Someone removing lfish from their
	// config to harden the host would find lfish still worked.
	//
	// Slices do not need this: yaml.v3 replaces a sequence outright, so
	// RecordUsers already behaves as written.
	builtinShells := cfg.Shells
	cfg.Shells = nil

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	// Must run before Validate, and scoped to server: only (see removedKeyError):
	// an old upstream_host/use_tls pair would otherwise leave LogServers at its
	// loopback default, which Validate sees as a perfectly valid non-empty list.
	if err := removedKeyError(data); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	if cfg.Shells == nil {
		cfg.Shells = builtinShells
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// RequiredOwnerUID is the uid a configuration file and its directory must belong
// to. Exported so callers doing their own reporting pass the same value Load
// enforces rather than a literal of their own.
const RequiredOwnerUID = 0

// CheckPerms refuses a configuration file that a non-root user could
// rewrite, and refuses one sitting in a directory a non-root user could rewrite.
//
// Checking the directory as well as the file is not belt-and-braces. A
// root-owned 0644 file inside a user-writable directory can be replaced wholesale
// by rename(2) without ever writing to the original inode, and the replacement
// then chooses which binary root's login shell execs. Only checking the file
// would leave that open.
//
// Symlinks are followed deliberately: os.Stat is correct here because a symlink
// in a root-owned directory could only have been placed by root.
func CheckPerms(path string, ownerUID uint32) error {
	check := func(p string, what string) error {
		st, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("stat %s %s: %w", what, p, err)
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			// Non-POSIX platform; the ownership question is not answerable, and
			// guessing "fine" would silently drop the check.
			return fmt.Errorf("cannot determine ownership of %s %s on this platform", what, p)
		}
		if sys.Uid != ownerUID {
			return fmt.Errorf("%s %s is owned by uid %d, not %d: it selects which binary a login shell execs", what, p, sys.Uid, ownerUID)
		}
		if st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("%s %s is writable by group or other (mode %04o)", what, p, st.Mode().Perm())
		}
		return nil
	}
	if err := check(filepath.Dir(path), "config directory"); err != nil {
		return err
	}
	return check(path, "config file")
}

// Validate reports configuration that cannot work or cannot be trusted.
func (c *Config) Validate() error {
	if len(c.Shells) == 0 {
		return fmt.Errorf("shells: map is empty, so every invocation would be refused")
	}
	for name, shell := range c.Shells {
		if name == "" {
			return fmt.Errorf("shells: empty invocation name")
		}
		if !filepath.IsAbs(shell) {
			return fmt.Errorf("shells[%s]: %q is not an absolute path", name, shell)
		}
	}
	// One name, one meaning. EntryName selects the forced-command mode from
	// argv[0]; a mapping under the same key would make that symlink resolvable
	// as a login shell too, and which behaviour won would depend on the order of
	// two predicates in main rather than on anything the operator wrote.
	if _, ok := c.Shells[EntryName]; ok {
		return fmt.Errorf("shells[%s]: %s names the forced-command entry point and cannot also be a shell mapping", EntryName, EntryName)
	}
	if len(c.Server.LogServers) == 0 {
		return fmt.Errorf("server.log_servers: at least one log server must be listed")
	}
	for _, spec := range c.Server.LogServers {
		if _, err := logsrvclient.ParseServer(spec); err != nil {
			return fmt.Errorf("server.log_servers: %w", err)
		}
	}
	if c.Server.CABundle != "" {
		if !filepath.IsAbs(c.Server.CABundle) {
			return fmt.Errorf("server.ca_bundle: %s must be an absolute path", c.Server.CABundle)
		}
		st, err := os.Stat(c.Server.CABundle)
		if err != nil {
			return fmt.Errorf("server.ca_bundle: %w", err)
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("server.ca_bundle: %s is not a regular file", c.Server.CABundle)
		}
	}
	switch c.NestedSessions {
	case "", NestedModeRecord, NestedModeMetadata, NestedModeSkip:
	default:
		return fmt.Errorf("nested_sessions: %q is not one of %q, %q, %q",
			c.NestedSessions, NestedModeRecord, NestedModeMetadata, NestedModeSkip)
	}
	if c.CommandLog.Enabled {
		if _, err := eventlog.ParseFacility(c.CommandLog.SyslogFacility); err != nil {
			return fmt.Errorf("command_log.syslog_facility: %w", err)
		}
		if _, err := eventlog.ParsePriority(c.CommandLog.SyslogPriority); err != nil {
			return fmt.Errorf("command_log.syslog_priority: %w", err)
		}
	}
	if c.BreakGlassMarker != "" && !filepath.IsAbs(c.BreakGlassMarker) {
		return fmt.Errorf("break_glass_marker: %q is not an absolute path", c.BreakGlassMarker)
	}
	for name, r := range c.ForceCommand.Routes {
		// The key is matched against the BASENAME of the first field of
		// SSH_ORIGINAL_COMMAND, so a key holding whitespace or a slash can never
		// match anything. It would look configured and route nothing, which is a
		// silent gap rather than a visible failure -- hence an error.
		if name == "" || strings.ContainsAny(name, " \t/") {
			return fmt.Errorf("force_command.routes[%q]: a key is matched against the basename of the client's command, so it cannot be empty or contain whitespace or a slash", name)
		}
		hasExec, hasCommand := len(r.Exec) > 0, r.Command != ""
		if hasExec == hasCommand {
			return fmt.Errorf("force_command.routes[%s]: set exactly one of exec or command", name)
		}
		prog := r.Command
		if hasExec {
			prog = r.Exec[0]
		}
		if !filepath.IsAbs(prog) {
			return fmt.Errorf("force_command.routes[%s]: %q is not an absolute path", name, prog)
		}
	}

	// The override is a configuration value, so the shells allowlist applies to
	// it. A passwd-derived shell is deliberately NOT gated the same way: see
	// ResolveEntryShell.
	if c.ForceCommand.Shell != "" {
		allowed := false
		for _, shell := range c.Shells {
			if shell == c.ForceCommand.Shell {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("force_command.shell: %q is not one of the shells map's values", c.ForceCommand.Shell)
		}
	}
	return nil
}

// Warnings reports configuration that works but is probably a mistake. They are
// surfaced by -validate and logged at startup rather than being fatal, because
// each is legitimate on some host somewhere.
func (c *Config) Warnings() []string {
	var w []string

	// Both non-default values depend on a claim logsh cannot verify.
	switch c.NestedSessions {
	case NestedModeSkip:
		w = append(w, "nested_sessions is \"skip\": a session under sudo is not recorded here at "+
			"all, and no record of it is kept either. Only safe if every sudoers rule reaching "+
			"a shell carries log_output, which logsh cannot check.")
	case NestedModeMetadata:
		w = append(w, "nested_sessions is \"metadata\": a session under sudo keeps a record but no "+
			"transcript. If the matched sudoers rule lacks log_output, nothing anywhere captures "+
			"what was run. Only safe if every such rule carries log_output.")
	}
	if c.CommandLog.Enabled {
		w = append(w, "command_log is enabled: it traces execve with ptrace, so strace and gdb "+
			"WILL NOT WORK inside a recorded session, and every exec costs a stop. It is also "+
			"blocked outright where kernel.yama.ptrace_scope is 2 or 3.")
	}
	if !c.VerifyEnabled() {
		w = append(w, "server.verify is false: session transcripts will be sent to any peer "+
			"that completes a handshake")
		if c.Server.CABundle != "" {
			w = append(w, "server.ca_bundle is set but server.verify is false, so the bundle is not used")
		}
	}
	if c.Server.CABundle != "" {
		// logsh drops to the logging-in user before connecting, but -validate is
		// normally run as root and can read a bundle the session cannot. Without
		// this the config validates and every recorded session then fails its
		// handshake.
		if st, err := os.Stat(c.Server.CABundle); err == nil && st.Mode().Perm()&0o044 == 0 {
			w = append(w, fmt.Sprintf(
				"server.ca_bundle %s is not readable by group or other: logsh runs as the "+
					"logging-in user, so every recorded session will fail its TLS handshake",
				c.Server.CABundle))
		}
	}
	if len(c.RecordUsers) == 0 {
		w = append(w, "record_users is empty: no session will be recorded")
	}
	if !c.LogTTYOut {
		w = append(w, "log_ttyout is false: an interactive session records essentially nothing")
	}
	for name, shell := range c.Shells {
		if st, err := os.Stat(shell); err != nil {
			w = append(w, fmt.Sprintf("shells[%s]: %s is not present on this host", name, shell))
		} else if st.Mode()&0111 == 0 {
			w = append(w, fmt.Sprintf("shells[%s]: %s is not executable", name, shell))
		}
	}
	if c.ForceCommand.Shell != "" {
		w = append(w, fmt.Sprintf(
			"force_command.shell is set to %s: forced-command sessions run it instead of the "+
				"account's own shell from %s, so they will differ from a console login on any host "+
				"where the two disagree. Leave it unset unless that is what you want.",
			c.ForceCommand.Shell, PasswdPath))
	}
	if len(c.ForceCommand.Routes) > 0 || c.ForceCommand.Shell != "" {
		if !c.ShouldRecord("root", 0) {
			w = append(w, "force_command is configured but record_users names neither root nor 0: "+
				"forced-command sessions would be routed correctly and recorded not at all")
		}
		// No warning here about a missing internal-sftp route. Whether one is
		// needed is a property of the host, not of this file: sshd naming a real
		// sftp-server binary sends that path as the client's command and needs no
		// route at all. `logsh -selftest` reads sshd_config and answers it
		// definitively, so a speculative "this might be a problem, I cannot tell"
		// here would be noise -- and noise is how warnings get ignored.
	}
	return w
}

// ShouldRecord reports whether sessions for this account are recorded. An entry
// in RecordUsers matches either the account name or its numeric uid.
//
// Accepting a numeric uid is not a convenience. logsh is built with CGO
// disabled so that a broken dynamic linker can never make a login shell
// unexecutable, and in that mode os/user parses /etc/passwd directly with no NSS
// -- so a name lookup fails for any LDAP or SSSD account. Were the decision made
// on the name alone, such an account would silently fall out of the allowlist
// and go unrecorded. Listing the uid keeps the decision working with no name at
// all, which is why callers pass "" rather than treating lookup failure as
// fatal.
func (c *Config) ShouldRecord(username string, uid int) bool {
	if username != "" && slices.Contains(c.RecordUsers, username) {
		return true
	}
	return slices.Contains(c.RecordUsers, strconv.Itoa(uid))
}

// VerifyEnabled reports whether the server certificate is verified. Absent
// means yes; only an explicit `verify: false` turns it off.
func (c *Config) VerifyEnabled() bool {
	return c.Server.Verify == nil || *c.Server.Verify
}

// ClientConfig is the address-FREE projection: identity, TLS policy and
// timeouts. Use it where a connection already exists and only its settings are
// needed. To dial, use ClientConfigs, which fills in an address per server.
func (c *Config) ClientConfig() logsrvclient.Config {
	return logsrvclient.Config{
		ClientID:      ClientID,
		TLSSkipVerify: !c.VerifyEnabled(),
		// Pinned, not configurable. An empty string here already means 1.3
		// (logsrvclient.Config.TLSMinVersion, resolved by config.TLSVersion),
		// so this is not a guard against a lower default today -- it is
		// belt-and-braces: explicit beats implicit, and the floor stays 1.3
		// here even if that empty-string mapping is ever changed.
		TLSMinVersion:   "1.3",
		TLSCACertFile:   c.Server.CABundle,
		ConnectTimeout:  c.Server.ConnectTimeout,
		ResponseTimeout: c.Server.ResponseTimeout,
	}
}

// ClientConfigs resolves every configured server, in the order written.
func (c *Config) ClientConfigs() ([]logsrvclient.Config, error) {
	out := make([]logsrvclient.Config, 0, len(c.Server.LogServers))
	for _, spec := range c.Server.LogServers {
		t, err := logsrvclient.ParseServer(spec)
		if err != nil {
			return nil, err
		}
		cc := c.ClientConfig()
		cc.UpstreamHost = t.Address
		cc.UseTLS = t.UseTLS
		out = append(out, cc)
	}
	return out, nil
}
