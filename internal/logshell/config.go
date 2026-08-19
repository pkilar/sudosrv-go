// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/config.go
package logshell

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sudosrv/internal/config"
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

	// RecordDir makes this a standalone recorder: the session is written to
	// that directory as a sudoreplay-compatible I/O log and no log server is
	// contacted at all. It is what `logsh -record` sets.
	//
	// `yaml:"-"` is load-bearing, not tidiness. A local recording is written by
	// the very user being recorded, as that user, so they can edit or delete
	// it -- it is a capture, not an audit trail. Were this settable from
	// logsh.yaml, an administrator could believe they had configured recording
	// for an account while giving that account full control of its own
	// evidence. Standalone recording is something a user asks for on their own
	// command line, for their own session, and nowhere else.
	RecordDir string `yaml:"-"`

	// RecordWire additionally writes the session in RAW WIRE FORMAT beside the
	// I/O log: the same length-prefixed ClientMessage stream logsh would have
	// sent a server, which cmd/wiredump reads.
	//
	// The two are not redundant. The I/O log is the processed form -- streams
	// split per file, delays flattened into a timing file, ttyin masked by the
	// password filter -- and is what sudoreplay and anything sudo-compatible
	// consumes. The wire file is what the client actually produced, before any
	// of that, which is what makes it the artefact for debugging the recorder
	// itself rather than the session.
	//
	// `yaml:"-"` for the same reason as RecordDir: it is only reachable from
	// the command line, alongside -record.
	RecordWire bool `yaml:"-"`

	// NestedSessions decides what to do when logsh finds itself inside something
	// that may already be recording: record, metadata, or skip. Default metadata.
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
// The TLSCertFile/TLSKeyFile fields exist for the case where logsh runs on a
// host whose credentials genuinely are user-readable (a single-admin box, a lab)
// and for symmetry with the relay config. Validate warns when they are set,
// because on a multi-user host setting them is a privilege escalation.
type ServerConfig struct {
	UpstreamHost  string `yaml:"upstream_host"`
	UseTLS        bool   `yaml:"use_tls"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify"`
	TLSMinVersion string `yaml:"tls_min_version"`
	TLSCertFile   string `yaml:"tls_cert_file"`
	TLSKeyFile    string `yaml:"tls_key_file"`
	TLSCACertFile string `yaml:"tls_cacert_file"`

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
			UpstreamHost:    "127.0.0.1:30343",
			UseTLS:          false, // loopback to a local relay by default
			TLSMinVersion:   "1.3",
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
		NestedSessions:   NestedModeRecord,
		FailClosed:       true,
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
	if c.Server.UpstreamHost == "" {
		return fmt.Errorf("server.upstream_host: must be set")
	}
	if (c.Server.TLSCertFile == "") != (c.Server.TLSKeyFile == "") {
		return fmt.Errorf("server: tls_cert_file and tls_key_file must be set together")
	}
	// Reuse the server's mapping rather than duplicating it, so logsh and
	// sudosrv can never disagree about what "1.2" means.
	if _, err := config.TLSVersion(c.Server.TLSMinVersion); err != nil {
		return fmt.Errorf("server: %w", err)
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
	return nil
}

// Warnings reports configuration that works but is probably a mistake. They are
// surfaced by -validate and logged at startup rather than being fatal, because
// each is legitimate on some host somewhere.
func (c *Config) Warnings() []string {
	var w []string

	// See the ServerConfig doc comment: on a multi-user host a user-readable
	// client key lets any recorded user impersonate the host to the log server.
	if c.Server.TLSCertFile != "" {
		w = append(w, fmt.Sprintf(
			"server.tls_cert_file is set: logsh runs as the logging-in user, so %s and its key "+
				"are readable by every recorded user and can be used to forge audit records. "+
				"Prefer a local sudosrv relay on loopback that holds the credentials as root.",
			c.Server.TLSCertFile))
	}
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
	if c.Server.TLSSkipVerify {
		w = append(w, "server.tls_skip_verify is set: session transcripts will be sent to any peer that completes a handshake")
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

// ClientConfig projects the server section onto the neutral client config.
func (c *Config) ClientConfig() logsrvclient.Config {
	return logsrvclient.Config{
		ClientID:        ClientID,
		UpstreamHost:    c.Server.UpstreamHost,
		UseTLS:          c.Server.UseTLS,
		TLSSkipVerify:   c.Server.TLSSkipVerify,
		TLSMinVersion:   c.Server.TLSMinVersion,
		TLSCertFile:     c.Server.TLSCertFile,
		TLSKeyFile:      c.Server.TLSKeyFile,
		TLSCACertFile:   c.Server.TLSCACertFile,
		ConnectTimeout:  c.Server.ConnectTimeout,
		ResponseTimeout: c.Server.ResponseTimeout,
	}
}
