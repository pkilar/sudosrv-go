// SPDX-License-Identifier: Apache-2.0
// Filename: internal/config/config.go
package config

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TLSVersion maps a "1.2"/"1.3" config string to the crypto/tls version
// constant. An empty string defaults to TLS 1.3, so manually-constructed configs
// that omit the field still resolve. Any other value is rejected so a typo
// cannot silently weaken the floor.
//
// The 1.3 floor is a deliberate divergence. C pins a 1.2 minimum with no maximum
// on both sides — SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) at
// plugins/sudoers/log_client.c:214 and logsrvd/tls_init.c:283 — so a stock sudo
// client negotiates 1.3 with us whenever its OpenSSL supports it, which every
// OpenSSL from 1.1.1 (2018) onwards does. What the higher floor actually
// excludes is a client linked against an older OpenSSL: it cannot complete the
// handshake at all, and because sudo's ignore_iolog_errors defaults to false
// that client's command is then killed rather than merely unlogged.
//
// The escape hatch is one config line, server.tls_min_version: "1.2" (and
// relay.tls_min_version for the upstream dial), which restores C's floor exactly.
// Prefer that over lowering the default: sites with no pre-1.1.1 clients should
// not carry a weaker floor for the ones that do.
//
// Conformance: docs/logsrvd-reference/ TLS-004.
func TLSVersion(s string) (uint16, error) {
	switch s {
	case "", "1.3":
		return tls.VersionTLS13, nil
	case "1.2":
		return tls.VersionTLS12, nil
	default:
		return 0, fmt.Errorf("unsupported tls_min_version %q (supported: \"1.2\", \"1.3\")", s)
	}
}

// CipherSuites resolves configured TLS 1.2 suite names to crypto/tls IDs. An
// empty list returns nil, which leaves Go's default selection in force.
//
// Unlike C, an unrecognized name is an ERROR rather than a warning-plus-
// fallback. C warns and silently reverts to its default list when OpenSSL
// rejects the configured string (logsrvd/tls_init.c:117-181), which means a
// typo in a hardening change leaves the server running the defaults while the
// config file and the change record both claim otherwise. Failing the load
// makes the typo visible at the moment it is introduced.
//
// Insecure suites are not offered: only the forward-secret AEAD suites Go
// reports in tls.CipherSuites() are selectable. tls.InsecureCipherSuites()
// (CBC, RC4, 3DES, and the non-ECDHE RSA key exchanges) is deliberately not
// consulted, so no configuration can talk this server down to them.
func CipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}
	byName := make(map[string]uint16, len(tls.CipherSuites()))
	for _, cs := range tls.CipherSuites() {
		byName[cs.Name] = cs.ID
	}
	suites := make([]uint16, 0, len(names))
	for _, n := range names {
		id, ok := byName[strings.ToUpper(strings.TrimSpace(n))]
		if !ok {
			return nil, fmt.Errorf("unknown or insecure TLS 1.2 cipher suite %q; "+
				"use an IANA name from crypto/tls (for example TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)", n)
		}
		suites = append(suites, id)
	}
	return suites, nil
}

// TLSCiphersKey renders the configured suite list as a single comparable
// string, so reload can detect a change with ==.
func (c *ServerConfig) TLSCiphersKey() string {
	return strings.Join(c.TLSCiphersV12, ",")
}

// Config holds the application's configuration.
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Relay        RelayConfig        `yaml:"relay"`
	LocalStorage LocalStorageConfig `yaml:"local_storage"`
	API          APIConfig          `yaml:"api"`
}

// ServerConfig holds server-specific settings.
type ServerConfig struct {
	Mode             string `yaml:"mode"` // "local" or "relay"
	ListenAddress    string `yaml:"listen_address"`
	ListenAddressTLS string `yaml:"listen_address_tls"`
	TLSCertFile      string `yaml:"tls_cert_file"`
	TLSKeyFile       string `yaml:"tls_key_file"`
	TLSMinVersion    string `yaml:"tls_min_version"` // "1.2" or "1.3" (default "1.3") for the protocol TLS listener
	// TLSCheckPeer requires every TLS client to present a certificate that
	// verifies against TLSCACertFile (or the system trust store). Default false,
	// matching C's tls_checkpeer (logsrvd/logsrvd_conf.c:1688) -- turning it on
	// by default would reject every existing client at the handshake.
	// Conformance: docs/logsrvd-reference/ TLS-015, CONF-035.
	TLSCheckPeer bool `yaml:"tls_check_peer"`
	// TLSCACertFile is the CA bundle used to verify client certificates when
	// TLSCheckPeer is set, and the pool the relay uses to verify an upstream.
	// Empty means the system trust store, matching C's fallback to
	// SSL_CTX_set_default_verify_paths (logsrvd/tls_init.c:294-319).
	// Conformance: docs/logsrvd-reference/ TLS-007, CONF-031.
	TLSCACertFile string `yaml:"tls_cacert_file"`
	// TLSCiphersV12 selects the TLS 1.2 cipher suites, by IANA name
	// (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ...). Empty means Go's default
	// selection, which is already restricted to forward-secret AEAD suites and
	// is ordered by the runtime using per-platform AES-NI detection -- a better
	// default than a hand-written list, so prefer leaving this unset.
	//
	// It is deliberately NOT an OpenSSL cipher string: C takes "HIGH:!aNULL"
	// and hands it to SSL_CTX_set_cipher_list (logsrvd/tls_init.c:117-181),
	// syntax only OpenSSL can parse. Naming suites individually is the honest
	// translation; a config written for C will not load here, which is louder
	// and safer than silently accepting a string we would have to guess at.
	//
	// There is no tls_ciphers_v13 counterpart because Go does not permit TLS 1.3
	// suite selection at all: crypto/tls ignores CipherSuites for 1.3 and always
	// offers its three AEAD suites. C's equivalent knob defaults to
	// TLS_AES_256_GCM_SHA384, which Go offers, so the negotiated result agrees
	// on the default path. Conformance: docs/logsrvd-reference/ CONF-033.
	TLSCiphersV12 []string      `yaml:"tls_ciphers_v12"`
	ServerID      string        `yaml:"server_id"`
	IdleTimeout   time.Duration `yaml:"idle_timeout"`
	// ServerTimeout bounds writes to the client and the TLS handshake, mirroring
	// C's [server] timeout (default 30s). It is NOT an idle read deadline — see
	// IdleTimeout, which is a different knob with the opposite default. 0 or
	// negative disables it, matching C's "A value of 0 will disable the timeout".
	ServerTimeout             time.Duration `yaml:"server_timeout"`
	MaxConnections            int           `yaml:"max_connections"`              // 0 disables the cap
	ServerOperationalLogLevel string        `yaml:"server_operational_log_level"` // e.g., "debug", "info", "warn", "error"
}

// RelayConfig holds settings for relay mode.
type RelayConfig struct {
	UpstreamHost string `yaml:"upstream_host"`
	UseTLS       bool   `yaml:"use_tls"`
	// TLSSkipVerify disables chain and hostname verification of the upstream
	// certificate. It defaults to FALSE, i.e. the upstream is verified — a
	// deliberate divergence from C, which does not verify by default: [relay]
	// tls_checkpeer is tri-state and falls back to [server] tls_checkpeer
	// (logsrvd/logsrvd_conf.c:341-346), which is initialised to false
	// (logsrvd/logsrvd_conf.c:1688), and tls_client_setup only installs
	// SSL_CTX_set_verify when check_peer is set (logsrvd/tls_client.c:251-256).
	// Stock sudo_logsrvd therefore relays complete transcripts of privileged
	// sessions to any peer that completes a handshake.
	//
	// Being stricter is the point; the cost is that a private-CA or self-signed
	// upstream that C would have accepted is refused on every dial here. Go uses
	// the system root store, so a private CA is handled by installing it there or
	// by setting SSL_CERT_FILE — there is no relay CA-bundle key. Setting this to
	// true reproduces C's posture and is warned about loudly at startup
	// (cmd/sudosrv/main.go). Conformance: docs/logsrvd-reference/ TLS-027.
	TLSSkipVerify bool   `yaml:"tls_skip_verify"`
	TLSMinVersion string `yaml:"tls_min_version"` // "1.2" or "1.3" (default "1.3") for the upstream dial
	// Relay TLS material. Each of these falls back to the [server] value when
	// empty, PER KEY -- setting only TLSCACertFile leaves the relay presenting
	// the server's certificate and key. Resolve them through Config's
	// RelayTLS*File accessors rather than reading the fields directly.
	// Conformance: docs/logsrvd-reference/ TLS-025, CONF-045.
	TLSCertFile    string        `yaml:"tls_cert_file"`   // client cert presented to the upstream
	TLSKeyFile     string        `yaml:"tls_key_file"`    // key for TLSCertFile
	TLSCACertFile  string        `yaml:"tls_cacert_file"` // CA bundle used to verify the upstream
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	// ResponseTimeout bounds each message exchange with the upstream AFTER the
	// connection is established, mirroring C's [relay] timeout (default 30s,
	// logsrvd/logsrvd_conf.c:827-841,1639). It is deliberately a separate knob
	// from ConnectTimeout: the dial budget is a latency figure, while this is
	// how long a busy upstream may take to fsync a session and answer.
	//
	// Reusing the 5s ConnectTimeout here made an upstream that acknowledged a
	// session in more than 5s fail the flush, so the cache file was kept and the
	// entire session replayed on the next attempt — the same transcript stored
	// twice upstream under two log IDs. Conformance: docs/logsrvd-reference/ CONF-039.
	ResponseTimeout     time.Duration `yaml:"response_timeout"`
	RelayCacheDirectory string        `yaml:"relay_cache_directory"`
	ReconnectAttempts   int           `yaml:"reconnect_attempts"`
	// RequireUpstream makes relay mode fail CLOSED: the upstream must be
	// reachable at accept time or the session is refused, which makes sudo
	// decline to run the command. Default false, i.e. fail open -- an
	// unreachable upstream spools to the local cache and delivers later, which
	// keeps privileged work running through an outage.
	//
	// C's default relay streams to the upstream and refuses the command when the
	// relay list is exhausted; its store_first mode behaves like this server's
	// default. Sites that require an auditable path to exist before privileged
	// execution set this to true and accept that an upstream outage blocks sudo.
	// Conformance: docs/logsrvd-reference/ RELAY-010.
	RequireUpstream      bool          `yaml:"require_upstream"`
	MaxReconnectInterval time.Duration `yaml:"max_reconnect_interval"`
}

// APIConfig holds settings for the optional management HTTP API. An empty
// ListenAddress disables the API entirely.
//
// Authentication is required when the API is enabled: AuthTokenFile (preferred)
// points at a file whose contents are the bearer token; AuthToken (discouraged
// in production) provides the token inline. If both are set, AuthTokenFile
// wins. Whitespace surrounding a file's contents is trimmed at load time.
//
// TLS is optional. When TLSCertFile and TLSKeyFile are set, the API listener
// terminates TLS using those credentials; otherwise it serves plaintext HTTP
// (intended for localhost-only deployments).
type APIConfig struct {
	ListenAddress string `yaml:"listen_address"`  // empty disables the API
	AuthToken     string `yaml:"auth_token"`      // inline (discouraged)
	AuthTokenFile string `yaml:"auth_token_file"` // path to file containing the token (preferred)
	TLSCertFile   string `yaml:"tls_cert_file"`
	TLSKeyFile    string `yaml:"tls_key_file"`
}

// LocalStorageConfig holds settings for local storage mode.
type LocalStorageConfig struct {
	LogDirectory string `yaml:"log_directory"` // Base directory, used if iolog_dir is not set
	IologDir     string `yaml:"iolog_dir"`     // sudoers-style I/O log directory path
	IologFile    string `yaml:"iolog_file"`    // sudoers-style I/O log session file name
	// IologMode is C's single [iolog] iolog_mode knob (default 0600). Both the
	// file mode and the directory mode are DERIVED from it by DeriveIologModes
	// rather than configured independently -- see that function for the rule.
	// Conformance: docs/logsrvd-reference/ CONF-055.
	IologMode uint32 `yaml:"iolog_mode"`
	// DirPermissions and FilePermissions are pre-CONF-055 overrides, retained
	// because the strict decoder (see unmarshalConfig) turns a removed key into a
	// startup failure for every config that still sets one. Zero means "unset,
	// derive from IologMode"; a non-zero value wins for that dimension alone and
	// logs a deprecation warning. Read the effective values through
	// EffectiveDirMode/EffectiveFileMode, never these fields directly.
	DirPermissions  uint32 `yaml:"dir_permissions"`  // deprecated; overrides the derived directory mode
	FilePermissions uint32 `yaml:"file_permissions"` // deprecated; overrides the derived file mode
	Compress        bool   `yaml:"compress"`         // Enable gzip compression for I/O log files
	PasswordFilter  bool   `yaml:"password_filter"`  // Enable regex-based password filtering
	// PassPromptRegex replaces the built-in password-prompt pattern set when
	// non-empty -- it does not add to it, matching C, where the first
	// passprompt_regex line discards the default and later lines append
	// (logsrvd/logsrvd_conf.c:507-519). An empty list keeps the built-ins.
	// Conformance: docs/logsrvd-reference/ CONF-057.
	PassPromptRegex []string `yaml:"passprompt_regex"`
}

// MaxPassPromptRegexLen is C's ceiling on a single passprompt_regex pattern
// (lib/util/regex.c:143-188, "regular expression too large").
const MaxPassPromptRegexLen = 1024

// DeriveIologModes reproduces C's derivation of the file and directory modes
// from the single iolog_mode setting (lib/iolog/iolog_conf.c:110-128):
//
//	iolog_filemode = S_IRUSR|S_IWUSR;
//	iolog_filemode |= mode & (S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
//	iolog_dirmode = iolog_filemode | S_IXUSR;
//	if (iolog_dirmode & (S_IRGRP|S_IWGRP)) iolog_dirmode |= S_IXGRP;
//	if (iolog_dirmode & (S_IROTH|S_IWOTH)) iolog_dirmode |= S_IXOTH;
//
// Three consequences worth stating, because they are not what a reader expects
// from a mode-like setting: owner read+write are forced on regardless of the
// configured value; only the group/other READ and WRITE bits are honored, so
// setuid/setgid/sticky and any configured execute bits are discarded; and the
// directory execute bits are re-derived from the surviving read/write bits
// rather than taken from the input. iolog_mode 0750 therefore yields file 0640
// and directory 0750, and the default 0600 yields file 0600 and directory 0700.
func DeriveIologModes(mode uint32) (fileMode, dirMode uint32) {
	fileMode = 0600 | (mode & 0066)
	dirMode = fileMode | 0100
	if dirMode&0060 != 0 {
		dirMode |= 0010
	}
	if dirMode&0006 != 0 {
		dirMode |= 0001
	}
	return fileMode, dirMode
}

// EffectiveFileMode is the mode session files are created with: the deprecated
// file_permissions override when set, otherwise the value derived from iolog_mode.
func (c *LocalStorageConfig) EffectiveFileMode() uint32 {
	if c.FilePermissions != 0 {
		return c.FilePermissions
	}
	fileMode, _ := DeriveIologModes(c.IologMode)
	return fileMode
}

// EffectiveDirMode is the mode session directories are created with: the
// deprecated dir_permissions override when set, otherwise the derived value.
func (c *LocalStorageConfig) EffectiveDirMode() uint32 {
	if c.DirPermissions != 0 {
		return c.DirPermissions
	}
	_, dirMode := DeriveIologModes(c.IologMode)
	return dirMode
}

// LoadConfig reads the configuration from a YAML file. A missing file is an
// error so a typo in -config or a missing deployment artifact cannot silently
// replace the documented secure defaults with whatever yaml.v3 leaves in a
// half-populated struct.
func LoadConfig(path string) (*Config, error) {
	config := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if err := unmarshalConfig(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// LoadConfigRequired is retained as an alias for LoadConfig so existing SIGHUP
// reload call sites do not need to change. Both functions now have identical
// fail-fast semantics on a missing file.
func LoadConfigRequired(path string) (*Config, error) {
	return LoadConfig(path)
}

// defaultConfig returns a Config populated with all secure defaults.
//
// LoadConfig calls this first, then yaml.Unmarshal merges user values on top.
// yaml.v3 only overwrites fields that appear in the YAML, so any field the
// user omits keeps its default — including PasswordFilter, IologDir, etc.
// applyZeroValueDefaults is a defensive second pass that re-applies the few
// numeric defaults a user could accidentally zero out (e.g., idle_timeout: 0).
func defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Mode:                      "local",
			ListenAddress:             "127.0.0.1:30343",
			ServerID:                  "GoSudoLogSrv/1.0",
			IdleTimeout:               0,                // 0 = no idle read deadline. DO NOT give this a finite default; see below.
			ServerTimeout:             30 * time.Second, // C's DEFAULT_SOCKET_TIMEOUT_SEC; bounds writes + TLS handshake.
			MaxConnections:            10000,
			TLSMinVersion:             "1.3",  // Secure default; "1.2" available for legacy clients
			ServerOperationalLogLevel: "info", // Default log level
		},
		Relay: RelayConfig{
			ConnectTimeout:       5 * time.Second,
			ResponseTimeout:      30 * time.Second, // C's [relay] timeout default; see RelayConfig.ResponseTimeout.
			RelayCacheDirectory:  "/var/log/gosudo-relay-cache",
			ReconnectAttempts:    -1, // Default to trying forever
			MaxReconnectInterval: 1 * time.Minute,
			TLSSkipVerify:        false, // Default to secure TLS verification
			TLSMinVersion:        "1.3", // Secure default; "1.2" available for legacy upstreams
		},
		LocalStorage: LocalStorageConfig{
			LogDirectory: "/var/log/gosudo-io",
			IologDir:     "%{LIVEDIR}/%{user}", // Default sudoers-style path
			IologFile:    "%{seq}",             // Default sudoers-style file name
			// C's default (logsrvd/logsrvd_conf.c:471-485), deriving file 0600 and
			// directory 0700 -- owner-only. The deprecated overrides stay zero so
			// EffectiveFileMode/EffectiveDirMode fall through to the derivation.
			IologMode:       0600,
			DirPermissions:  0,     // unset; derived from IologMode
			FilePermissions: 0,     // unset; derived from IologMode
			Compress:        false, // Compression disabled by default for compatibility
			PasswordFilter:  true,  // Password filtering enabled by default for security
		},
	}
}

// unmarshalConfig decodes the config file STRICTLY: a key that maps to no
// struct field is a fatal error, never a silent no-op.
//
// C behaves the same way. logsrvd_conf_parse() aborts the whole parse on an
// unrecognized key -- "%s:%d [%s] illegal key: %s" (logsrvd/logsrvd_conf.c:1291)
// -- and sudo_logsrvd turns that into EXIT_FAILURE at startup
// (logsrvd/logsrvd.c:2275). Plain yaml.Unmarshal ignores unknown keys, so a
// single-character typo like "listen_addres:" used to decode with err == nil and
// leave the daemon bound to the 127.0.0.1:30343 default -- reachable only from
// localhost -- while the operator's config said 0.0.0.0 and the log said nothing.
// The same silence hid typos in tls_cert_file, password_filter and auth_token_file,
// each of which fails open on a security control. Do not relax this back to
// yaml.Unmarshal. Conformance: docs/logsrvd-reference/ CONF-002.
// Guarded by TestLoadConfigRejectsUnknownKeys.
// Relay TLS material inherits from the [server] section on a PER-KEY basis, the
// same rule as C's TLS_RELAY_STR macro (logsrvd/logsrvd_conf.c:65-71, 1809-1827):
// each value falls back independently, so overriding one does not disinherit the
// others. All-or-nothing inheritance would mean an operator setting a
// relay-specific CA silently stops presenting a client certificate, and every
// flush then fails at the upstream handshake with the cache growing behind it.
//
// Conformance: docs/logsrvd-reference/ TLS-025, CONF-045.
func relayOrServer(relay, server string) string {
	if relay != "" {
		return relay
	}
	return server
}

// resolveRelayTLSInheritance copies the effective TLS material into the relay
// section so RelayConfig is self-contained. It is idempotent: the accessors
// return the relay value once set, so re-running changes nothing.
func resolveRelayTLSInheritance(c *Config) {
	c.Relay.TLSCertFile = c.RelayTLSCertFile()
	c.Relay.TLSKeyFile = c.RelayTLSKeyFile()
	c.Relay.TLSCACertFile = c.RelayTLSCACertFile()
}

// RelayTLSCertFile is the client certificate the relay presents upstream.
func (c *Config) RelayTLSCertFile() string {
	return relayOrServer(c.Relay.TLSCertFile, c.Server.TLSCertFile)
}

// RelayTLSKeyFile is the key for RelayTLSCertFile.
func (c *Config) RelayTLSKeyFile() string {
	return relayOrServer(c.Relay.TLSKeyFile, c.Server.TLSKeyFile)
}

// RelayTLSCACertFile is the CA bundle used to verify the upstream. Empty means
// the system trust store.
func (c *Config) RelayTLSCACertFile() string {
	return relayOrServer(c.Relay.TLSCACertFile, c.Server.TLSCACertFile)
}

func unmarshalConfig(data []byte, config *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(config); err != nil {
		// An empty or comment-only file yields io.EOF; that is not an error,
		// it just means "use the defaults".
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to unmarshal config YAML: %w", err)
		}
	}

	// Re-apply defaults for zero-valued fields that yaml may have cleared
	// when a section is partially specified in the config file.
	applyZeroValueDefaults(config)

	// Fold the [server] TLS material into the relay section, per key, so
	// everything downstream reads effective values from RelayConfig alone and no
	// caller has to remember the inheritance rule. Doing it once here also means
	// -validate and -dry-run print what will actually be used, not what was typed.
	resolveRelayTLSInheritance(config)

	return nil
}

// applyZeroValueDefaults restores default values for fields that yaml.Unmarshal
// may have zeroed when a section was partially specified.
func applyZeroValueDefaults(cfg *Config) {
	// idle_timeout is deliberately ABSENT from this function. Do not add it.
	//
	// Any value <= 0 (omitted, "0s", or the legacy "-1s" opt-out) means "no idle
	// read deadline", and that is the default. Re-defaulting a zero here to some
	// finite duration is exactly the bug this comment exists to prevent: it
	// SIGKILLs the user's command on an idle interactive session. The full chain,
	// verified in the sudo 1.9.18 sources:
	//
	//   1. C sudo_logsrvd arms its steady-state read event with a NULL timeout
	//      (logsrvd/logsrvd.c:1372, "No read timeout, client messages may happen
	//      at arbitrary times") — it never disconnects an idle client.
	//   2. sudo's def_ignore_iolog_errors defaults to false
	//      (plugins/sudoers/defaults.c:610).
	//   3. So when the log connection drops, the client calls loopbreak()
	//      (plugins/sudoers/log_client.c:1919, "Break out of sudo event loop and
	//      kill the command") and terminate_command() SIGKILLs the user's shell.
	//
	// Net effect of a finite default: `sudo -s` left at a prompt past the timeout
	// has the server hang up and the user's root shell killed under them. A
	// larger default only delays it. Operators who genuinely want a deadline set
	// a positive idle_timeout explicitly and accept that consequence.
	//
	// Conformance: docs/logsrvd-reference/ ARCH-024, ARCH-045, CONF-025 (breaking).
	// Guarded by TestIdleTimeoutDefaultsToDisabled (this package) and
	// TestIdleReadDeadlineOptOut/ShippedDefaultArmsNoReadDeadline (internal/connection).
	if cfg.Server.MaxConnections < 0 {
		cfg.Server.MaxConnections = 0
	}
	if cfg.Server.TLSMinVersion == "" {
		cfg.Server.TLSMinVersion = "1.3"
	}
	if cfg.Relay.TLSMinVersion == "" {
		cfg.Relay.TLSMinVersion = "1.3"
	}
	if cfg.Relay.ConnectTimeout == 0 {
		cfg.Relay.ConnectTimeout = 5 * time.Second
	}
	if cfg.Relay.ResponseTimeout == 0 {
		cfg.Relay.ResponseTimeout = 30 * time.Second
	}
	if cfg.Relay.MaxReconnectInterval == 0 {
		cfg.Relay.MaxReconnectInterval = 1 * time.Minute
	}

	// YAML 1.2 (gopkg.in/yaml.v3) treats 0750 as decimal 750, not octal.
	// Auto-correct values where all digits are 0-7, which strongly indicates
	// the user intended octal (e.g., decimal 750 → octal 0750 = 488).
	//
	// iolog_mode needs no zero-value default above: 0 derives to file 0600 and
	// directory 0700 because DeriveIologModes forces owner read+write on, which
	// is exactly the documented default. A yaml-zeroed iolog_mode is therefore
	// indistinguishable from an omitted one, by construction rather than by luck.
	cfg.LocalStorage.IologMode = reinterpretDecimalAsOctal(cfg.LocalStorage.IologMode, "iolog_mode")
	cfg.LocalStorage.DirPermissions = reinterpretDecimalAsOctal(cfg.LocalStorage.DirPermissions, "dir_permissions")
	cfg.LocalStorage.FilePermissions = reinterpretDecimalAsOctal(cfg.LocalStorage.FilePermissions, "file_permissions")

	if cfg.LocalStorage.DirPermissions != 0 {
		slog.Warn("local_storage.dir_permissions is deprecated; set local_storage.iolog_mode instead and let the directory mode be derived from it",
			"dir_permissions", fmt.Sprintf("0%o", cfg.LocalStorage.DirPermissions))
	}
	if cfg.LocalStorage.FilePermissions != 0 {
		slog.Warn("local_storage.file_permissions is deprecated; set local_storage.iolog_mode instead and let the file mode be derived from it",
			"file_permissions", fmt.Sprintf("0%o", cfg.LocalStorage.FilePermissions))
	}
}

// Validate performs structural and security validation on a loaded Config.
// Called at startup and on SIGHUP reload so an incoherent reload can be
// rejected without clobbering the running server's view of the world.
func Validate(cfg *Config) error {
	if cfg.Server.Mode != "local" && cfg.Server.Mode != "relay" {
		return fmt.Errorf("invalid server mode: %s (must be 'local' or 'relay')", cfg.Server.Mode)
	}
	if cfg.Server.ListenAddress == "" && cfg.Server.ListenAddressTLS == "" {
		return fmt.Errorf("at least one listen address must be configured")
	}
	if cfg.Server.ListenAddressTLS != "" {
		if cfg.Server.TLSCertFile == "" || cfg.Server.TLSKeyFile == "" {
			return fmt.Errorf("TLS certificate and key files must be specified for TLS listener")
		}
	}
	// tls_check_peer only does anything on a TLS listener. Accepting it without
	// one would leave an operator believing client certificates are required
	// while every connection arrives unauthenticated on the plaintext port.
	// Conformance: docs/logsrvd-reference/ TLS-015.
	if cfg.Server.TLSCheckPeer && cfg.Server.ListenAddressTLS == "" {
		return fmt.Errorf("server.tls_check_peer requires a TLS listener; set listen_address_tls")
	}
	// A half-configured key pair can never produce a usable certificate. Failing
	// here beats failing at every upstream handshake with the relay cache growing
	// behind it. Conformance: docs/logsrvd-reference/ TLS-025, CONF-045.
	if (cfg.Relay.TLSCertFile == "") != (cfg.Relay.TLSKeyFile == "") {
		return fmt.Errorf("relay.tls_cert_file and relay.tls_key_file must be set together")
	}
	if _, err := TLSVersion(cfg.Server.TLSMinVersion); err != nil {
		return fmt.Errorf("server.%w", err)
	}
	if _, err := CipherSuites(cfg.Server.TLSCiphersV12); err != nil {
		return fmt.Errorf("server.tls_ciphers_v12: %w", err)
	}
	if _, err := TLSVersion(cfg.Relay.TLSMinVersion); err != nil {
		return fmt.Errorf("relay.%w", err)
	}
	if cfg.Server.Mode == "relay" {
		if cfg.Relay.UpstreamHost == "" {
			return fmt.Errorf("upstream_host must be configured in relay mode")
		}
		if cfg.Relay.RelayCacheDirectory == "" {
			return fmt.Errorf("relay_cache_directory must be configured in relay mode")
		}
	}
	if cfg.Server.Mode != "relay" && cfg.Relay.UpstreamHost != "" {
		// C has no mode key: a non-empty relay list is itself the switch that
		// puts sudo_logsrvd into relay mode, and every relay code path is
		// guarded by !TAILQ_EMPTY(logsrvd_conf_relay_address())
		// (logsrvd/logsrvd.c:1546,1652; logsrvd/logsrvd_conf.c:821-825). Here
		// server.mode is the switch instead, so configuring relay.upstream_host
		// and forgetting server.mode used to be accepted silently: the daemon
		// wrote every session to local_storage.log_directory while the operator
		// believed transcripts were being centralised upstream, and nothing in
		// the startup log said otherwise. Discovery typically came months later,
		// when someone went looking for a session on the central host.
		//
		// Reject rather than infer relay mode from the populated block: a
		// package upgrade that adds this check must not silently flip a daemon
		// that has been storing locally into forwarding privileged session
		// transcripts to a host the operator never intended.
		// Conformance: docs/logsrvd-reference/ CONF-038.
		// Guarded by TestValidate/relay_upstream_host_set_while_mode_is_local_rejects.
		return fmt.Errorf("relay.upstream_host is set but server.mode is %q: "+
			"set server.mode to \"relay\" to forward sessions upstream, or remove relay.upstream_host",
			cfg.Server.Mode)
	}
	if cfg.Server.Mode == "local" {
		if err := ValidatePermissions(&cfg.LocalStorage); err != nil {
			return err
		}
		if err := ValidatePassPromptRegex(cfg.LocalStorage.PassPromptRegex); err != nil {
			return err
		}
	}
	if cfg.API.ListenAddress != "" {
		if cfg.API.AuthToken == "" && cfg.API.AuthTokenFile == "" {
			return fmt.Errorf("api.listen_address is set but neither api.auth_token nor api.auth_token_file is configured")
		}
		if (cfg.API.TLSCertFile == "") != (cfg.API.TLSKeyFile == "") {
			return fmt.Errorf("api.tls_cert_file and api.tls_key_file must both be set or both empty")
		}
		if err := validateAuthTokenFile(cfg.API.AuthTokenFile); err != nil {
			return err
		}
		// Plaintext HTTP is acceptable only for loopback deployments: every
		// request carries the static bearer token, so serving it on a routable
		// interface without TLS exposes the credential to the network. Warn
		// rather than refuse so existing trusted-network deployments keep
		// working, but make the exposure unmissable in the startup log.
		if cfg.API.TLSCertFile == "" && !isLoopbackListenAddress(cfg.API.ListenAddress) {
			slog.Warn("INSECURE: api.listen_address is not loopback and api TLS is not configured — "+
				"the bearer token will traverse the network in cleartext. "+
				"Configure api.tls_cert_file/api.tls_key_file or bind to 127.0.0.1.",
				"listen_address", cfg.API.ListenAddress)
		}
	}
	return nil
}

// isLoopbackListenAddress reports whether a listen address string is bound to
// a loopback interface. An empty host (":8080"), a wildcard address, or an
// unparsable host is treated as NOT loopback, so the caller errs on the side
// of warning.
func isLoopbackListenAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateAuthTokenFile enforces the security preconditions documented for the
// preferred AuthTokenFile credential path: absolute path, file exists, and the
// mode forbids group/other access. A world-readable token file accepted as
// "preferred" would be a silent regression.
func validateAuthTokenFile(path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("api.auth_token_file must be an absolute path, got %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("api.auth_token_file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("api.auth_token_file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("api.auth_token_file %s has mode 0%o; require 0600 or 0400 (no group/other access)",
			path, info.Mode().Perm())
	}
	return nil
}

// ValidatePermissions rejects permission combinations that would expose sudo
// session transcripts to unprivileged users. Returns an error rather than a
// warning — misconfigured permissions are a security incident waiting to
// happen and should block startup.
// It validates the EFFECTIVE modes, so it covers a value that arrived via
// iolog_mode as well as one set through the deprecated overrides.
func ValidatePermissions(cfg *LocalStorageConfig) error {
	dirMode, fileMode := cfg.EffectiveDirMode(), cfg.EffectiveFileMode()
	// World-writable (o+w, 0002) on any session artefact lets another local
	// user tamper with audit logs.
	if dirMode&0002 != 0 {
		return fmt.Errorf("effective directory mode 0%o is world-writable; refusing to start", dirMode)
	}
	if fileMode&0002 != 0 {
		return fmt.Errorf("effective file mode 0%o is world-writable; refusing to start", fileMode)
	}
	// World-readable (o+r, 0004) on file permissions exposes sudo transcripts
	// (which may contain sensitive command output) to any local user.
	if fileMode&0004 != 0 {
		return fmt.Errorf("effective file mode 0%o is world-readable; sudo transcripts may contain secrets — refusing to start", fileMode)
	}
	// Directories without owner-exec are not traversable; this catches the
	// classic `dir_permissions: 644` mistake (auto-octalled from decimal),
	// which would otherwise produce inscrutable runtime errors. The derivation
	// always sets this bit, so only an explicit dir_permissions can trip it.
	if dirMode&0100 == 0 {
		return fmt.Errorf("effective directory mode 0%o lacks owner-exec bit; directories would not be traversable", dirMode)
	}
	return nil
}

// ValidatePassPromptRegex compiles every configured prompt pattern so a bad one
// fails the config load rather than silently disabling prompt detection at
// runtime, which is C's behavior (any compilation failure aborts the apply,
// logsrvd/logsrvd_conf.c:1750-1754).
//
// Go's regexp handles a leading (?i) natively, so C's convention of writing
// "(?i)foo" -- optionally after a leading "^" -- to request case-insensitivity
// needs no special handling here; it is accepted as written.
func ValidatePassPromptRegex(patterns []string) error {
	for _, p := range patterns {
		if len(p) > MaxPassPromptRegexLen {
			return fmt.Errorf("passprompt_regex pattern is %d bytes; the maximum is %d", len(p), MaxPassPromptRegexLen)
		}
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("passprompt_regex %q: %w", p, err)
		}
	}
	return nil
}

// reinterpretDecimalAsOctal detects values where YAML 1.2 parsed an intended
// octal literal (e.g., 0750) as decimal 750 and converts it to the correct
// octal value (0o750 = 488). Only converts when every decimal digit is 0-7,
// which is a strong signal the user intended octal notation. Values already
// within 0-0o777 (0-511) are returned unchanged.
//
// ValidatePermissions runs after this conversion, so any resulting value that
// would be unsafe (world-writable, world-readable file, dir without owner-exec)
// still blocks startup with a clear error.
func reinterpretDecimalAsOctal(val uint32, fieldName string) uint32 {
	if val <= 0o777 {
		return val // Already a valid permission value
	}
	// Check if all decimal digits are 0-7 (i.e., looks like an octal literal)
	tmp := val
	var octalVal uint32
	multiplier := uint32(1)
	for tmp > 0 {
		digit := tmp % 10
		if digit > 7 {
			// Contains 8 or 9 — not an octal literal, just a bad value
			slog.Warn("permission value exceeds 0777 and contains non-octal digits; use quoted octal (e.g., \"0750\")",
				"field", fieldName, "value", val)
			return val
		}
		octalVal += digit * multiplier
		multiplier *= 8
		tmp /= 10
	}
	slog.Warn("auto-corrected YAML 1.2 decimal to octal; quote the value in config to silence this warning",
		"field", fieldName, "decimal", val, "octal", fmt.Sprintf("0o%o", octalVal))
	return octalVal
}

// ParseLogLevel converts a string log level to slog.Level with validation.
// Exported for use by main.go and server.go to avoid duplication.
func ParseLogLevel(levelStr string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %s (supported: debug, info, warn, error)", levelStr)
	}
}

// Create an example config file if it doesn't exist
// Filename: config.yaml
/*
server:
  mode: "local"  # or "relay"
  listen_address: "0.0.0.0:30343"
  listen_address_tls: "0.0.0.0:30344"
  tls_cert_file: "server.crt"
  tls_key_file: "server.key"
  server_id: "GoSudoLogSrv/1.0"
  # idle_timeout: off by default (C parity). Setting it kills idle interactive
  # sessions — see applyZeroValueDefaults above before enabling.
  server_operational_log_level: "debug" # Supported levels: debug, info, warn, error

# Settings for when server.mode is "relay"
relay:
  upstream_host: "127.0.0.1:30343"
  use_tls: false
  tls_skip_verify: false  # Set to true only for testing with self-signed certs
  connect_timeout: 5s      # dial budget
  response_timeout: 30s    # upstream reply budget once connected
  relay_cache_directory: "/var/spool/sudosrv-cache"
  reconnect_attempts: -1  # Number of retries, -1 for infinite
  max_reconnect_interval: "2m" # Maximum time to wait between retries

# Settings for when server.mode is "local"
local_storage:
  # Base directory used for the %{LIVEDIR} escape and the sequence file.
  log_directory: "/var/log/gosudo-io"

  # Directory path for session logs, with support for sudoers-style escape sequences.
  # If specified, this overrides the simpler default behavior.
  # Supported escapes:
  #   User: %{user}, %{uid}, %{group}, %{gid}
  #   RunAs User: %{runuser}, %{runuid}, %{rungroup}, %{rungid}
  #   Host/Command: %{hostname}, %{command} (basename), %{command_path} (full path)
  #   Date/Time: %{year}, %{month}, %{day}, %{hour}, %{minute}, %{second}, %{epoch}
  #   Misc: %{seq}, %{rand}, %{LIVEDIR}, %% (literal %)
  iolog_dir: "%{LIVEDIR}/%{year}-%{month}/%{user}"

  # File name for the session log directory, with support for the same escapes.
  iolog_file: "%{epoch}-%{rand}-%{command}"

  # Enable gzip compression for I/O log data files (stdin/stdout/stderr/ttyin/ttyout)
  # Disabled by default for compatibility with older tools
  compress: false

  # Enable password filtering to prevent passwords from being logged in cleartext
  # Uses regex pattern matching to detect password prompts and mask input
  # Enabled by default for security
  password_filter: true

*/
