// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/config_test.go
package logshell

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// writeConfig drops a config file into its own directory and returns the path.
// Both are owned by the test user, so tests reach load() with that uid rather
// than Load()'s hardcoded 0.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "logsh.yaml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func selfUID(t *testing.T) uint32 {
	t.Helper()
	return uint32(os.Getuid())
}

// TestLoadPreservesDefaultTrueBools is the subtle one.
//
// log_ttyout defaults to TRUE, so a config that omits it must keep recording
// output, while one that says `log_ttyout: false` must actually stop. A
// defaults-reapplied-over-zero-values scheme cannot tell those apart and would
// silently ignore the operator's explicit false, leaving them convinced they had
// turned output capture off when they had not. Loading into a pre-populated
// struct and letting yaml.v3 overwrite only the keys present is what makes the
// distinction work.
func TestLoadPreservesDefaultTrueBools(t *testing.T) {
	omitted, err := load(writeConfig(t, "record_users: [root]\n"), selfUID(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !omitted.LogTTYOut {
		t.Error("log_ttyout omitted: got false, want the true default")
	}
	if omitted.LogTTYIn {
		t.Error("log_ttyin omitted: got true, want the false default")
	}

	explicit, err := load(writeConfig(t, "log_ttyout: false\nlog_ttyin: true\n"), selfUID(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if explicit.LogTTYOut {
		t.Error("an explicit `log_ttyout: false` was ignored; the operator's setting must win")
	}
	if !explicit.LogTTYIn {
		t.Error("an explicit `log_ttyin: true` was ignored")
	}
}

// TestLoadShellsMapReplacesBuiltins guards the allowlist contract.
//
// yaml.v3 merges a mapping into a pre-populated Go map instead of replacing it,
// so without an explicit reset an operator's four-entry shells block would land
// on top of the built-in defaults and quietly keep every name they left out. A
// site removing lfish to harden a host would find lfish still resolved.
func TestLoadShellsMapReplacesBuiltins(t *testing.T) {
	cfg, err := load(writeConfig(t, "shells:\n  lbash: /bin/bash\n"), selfUID(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Shells) != 1 {
		t.Errorf("shells = %v, want only the one entry the config declared; the built-in "+
			"defaults were merged in and names the operator omitted still resolve", cfg.Shells)
	}
	if _, ok := cfg.Shells["lfish"]; ok {
		t.Error("lfish survived a config that did not mention it")
	}

	// Omitting the key entirely still gets a usable default set, so a minimal
	// config is not a locked door.
	omitted, err := load(writeConfig(t, "record_users: [root]\n"), selfUID(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(omitted.Shells) == 0 {
		t.Error("omitting shells produced an empty map, which would refuse every invocation")
	}
}

func TestLoadRejectsGroupWritableConfig(t *testing.T) {
	path := writeConfig(t, "record_users: [root]\n")
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	if _, err := load(path, selfUID(t)); err == nil {
		t.Error("a group-writable config was accepted; anyone in that group could choose " +
			"which binary a login shell execs")
	}
}

// TestLoadRejectsWritableConfigDirectory covers the attack the file-mode check
// alone would miss: a root-owned 0644 config inside a world-writable directory
// can be swapped wholesale with rename(2), never touching the original inode.
func TestLoadRejectsWritableConfigDirectory(t *testing.T) {
	path := writeConfig(t, "record_users: [root]\n")
	if err := os.Chmod(filepath.Dir(path), 0777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), 0700) })

	if _, err := load(path, selfUID(t)); err == nil {
		t.Error("a config in a world-writable directory was accepted; it could be replaced " +
			"by rename without ever being written to")
	}
}

// TestLoadRequiresRootOwnership proves Load really passes 0, rather than the
// permission check being inert. A config owned by the invoking user must be
// refused -- that is precisely the case where a recorded user could switch off
// their own recording.
func TestLoadRequiresRootOwnership(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; a self-owned config is legitimately root-owned")
	}
	path := writeConfig(t, "record_users: [root]\n")
	if _, err := Load(path); err == nil {
		t.Error("Load accepted a config owned by the invoking user")
	} else if !strings.Contains(err.Error(), "not 0") {
		t.Errorf("Load failed for the wrong reason: %v", err)
	}
}

func TestShouldRecord(t *testing.T) {
	cfg := &Config{RecordUsers: []string{"root", "1001"}}

	if !cfg.ShouldRecord("root", 0) {
		t.Error("a listed account name was not matched")
	}
	if cfg.ShouldRecord("nobody", 65534) {
		t.Error("an unlisted account was matched")
	}

	// The numeric form exists for NSS-provided accounts, which a cgo-free
	// os/user cannot resolve to a name at all. Matching must work with no name.
	if !cfg.ShouldRecord("", 1001) {
		t.Error("a uid listed numerically was not matched when the name lookup failed; " +
			"an LDAP account would silently go unrecorded")
	}
	if cfg.ShouldRecord("", 1002) {
		t.Error("an unlisted uid was matched")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name:    "empty shells map",
			mutate:  func(c *Config) { c.Shells = nil },
			wantErr: "empty",
		},
		{
			name:    "relative shell path",
			mutate:  func(c *Config) { c.Shells = map[string]string{"lbash": "bash"} },
			wantErr: "absolute",
		},
		{
			name:    "empty log_servers list",
			mutate:  func(c *Config) { c.Server.LogServers = nil },
			wantErr: "log_servers",
		},
		{
			name:    "relative break-glass marker",
			mutate:  func(c *Config) { c.BreakGlassMarker = "bypass" },
			wantErr: "absolute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}

	if err := DefaultConfig().Validate(); err != nil {
		t.Errorf("the shipped defaults do not validate: %v", err)
	}
}

// TestShippedExampleConfigIsValid keeps examples/logsh.yaml honest.
//
// It lives outside the repository root deliberately: internal/config globs
// ../../*.yaml and loads every hit as a sudosrv config, so a logsh config placed
// there fails that test with a wall of unknown-key errors. Being out of that
// glob means nothing else validates this file, which is exactly why this test
// has to.
func TestShippedExampleConfigIsValid(t *testing.T) {
	const path = "../../examples/logsh.yaml"
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the shipped example config is missing: %v", err)
	}
	cfg, err := LoadUnchecked(path)
	if err != nil {
		t.Fatalf("the shipped example config does not load: %v", err)
	}

	// The example is also the documentation for the two defaults an operator is
	// most likely to get wrong, so assert it actually demonstrates them.
	if !cfg.LogTTYOut {
		t.Error("the example turns log_ttyout off; it is meant to show the default")
	}
	if cfg.LogTTYIn {
		t.Error("the example turns log_ttyin on; it is meant to show the default")
	}
	if !cfg.FailClosed {
		t.Error("the example disables fail_closed; it is meant to show the default posture")
	}
}

func TestClientConfigCarriesLogshClientID(t *testing.T) {
	// The server's records must distinguish a shell-recorded session from one
	// sent by sudo or forwarded by a relay.
	if got := DefaultConfig().ClientConfig().ClientID; got != ClientID {
		t.Errorf("ClientID = %q, want %q", got, ClientID)
	}
	if ClientID == "GoSudoLogSrv-Relay/1.0" {
		t.Error("logsh is announcing itself as the relay")
	}
}

// TestValidateRejectsEntryNameAsShell stops one name meaning two things.
//
// logsh-entry selects the forced-command mode from argv[0]. A shells mapping
// under the same key would make the same symlink also resolvable as a login
// shell, and which one won would depend on the order of two predicates in main.
func TestValidateRejectsEntryNameAsShell(t *testing.T) {
	_, err := load(writeConfig(t, "record_users: [root]\nshells:\n  logsh-entry: /bin/bash\n"), selfUID(t))
	if err == nil {
		t.Fatal("want an error for shells[logsh-entry], got nil")
	}
	if !strings.Contains(err.Error(), EntryName) {
		t.Errorf("error should name %q, got: %v", EntryName, err)
	}
}

// TestValidateForceCommandRoutes.
//
// Each of these is an error rather than a warning because each produces a
// SILENT recording gap or a broken session: a route that can never match, a
// route with no program, or a program logsh cannot exec.
func TestValidateForceCommandRoutes(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			// Matching is on the basename of field 0, so a key containing a
			// slash could never match anything. It would look configured and
			// route nothing.
			name: "key with a slash",
			body: "record_users: [root]\nforce_command:\n  routes:\n    /usr/bin/rsync:\n      command: /bin/sh\n",
			want: "basename",
		},
		{
			name: "key with whitespace",
			body: "record_users: [root]\nforce_command:\n  routes:\n    \"rsync --server\":\n      command: /bin/sh\n",
			want: "basename",
		},
		{
			name: "neither exec nor command",
			body: "record_users: [root]\nforce_command:\n  routes:\n    rsync: {}\n",
			want: "exactly one",
		},
		{
			name: "both exec and command",
			body: "record_users: [root]\nforce_command:\n  routes:\n    rsync:\n      exec: [/usr/bin/rrsync]\n      command: /bin/sh\n",
			want: "exactly one",
		},
		{
			name: "relative program",
			body: "record_users: [root]\nforce_command:\n  routes:\n    rsync:\n      exec: [rrsync, -no-del]\n",
			want: "absolute path",
		},
		{
			// The override is a config value like any other, so the shells
			// allowlist applies to it -- unlike a passwd-derived shell, where
			// applying it would be a lockout for no gain.
			name: "shell override outside the allowlist",
			body: "record_users: [root]\nforce_command:\n  shell: /bin/evil\n",
			want: "shells",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(writeConfig(t, tt.body), selfUID(t))
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error should mention %q, got: %v", tt.want, err)
			}
		})
	}
}

// TestValidateAcceptsAGoodForceCommandConfig, so the errors above are not
// simply rejecting everything.
func TestValidateAcceptsAGoodForceCommandConfig(t *testing.T) {
	body := "record_users: [root]\n" +
		"force_command:\n" +
		"  routes:\n" +
		"    internal-sftp:\n" +
		"      exec: [/usr/lib/ssh/sftp-server, -l, INFO]\n" +
		"    git-shell:\n" +
		"      command: /usr/bin/git-shell\n"
	cfg, err := load(writeConfig(t, body), selfUID(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ForceCommand.Routes) != 2 {
		t.Errorf("got %d routes, want 2", len(cfg.ForceCommand.Routes))
	}
}

// TestWarningsForceCommandWithoutRootRecorded is the likeliest single
// misconfiguration, and the most silent: sessions would be routed correctly and
// recorded not at all.
func TestWarningsForceCommandWithoutRootRecorded(t *testing.T) {
	body := "record_users: [alice]\n" +
		"force_command:\n  routes:\n    internal-sftp:\n      exec: [/usr/lib/ssh/sftp-server]\n"
	cfg, err := load(writeConfig(t, body), selfUID(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.ContainsFunc(cfg.Warnings(), func(w string) bool { return strings.Contains(w, "record_users") }) {
		t.Errorf("want a record_users warning, got %v", cfg.Warnings())
	}
}

// TestWarningsShellOverride makes the footgun visible: pinning one shell
// fleet-wide diverges from the account's real shell and from a console login.
func TestWarningsShellOverride(t *testing.T) {
	body := "record_users: [root]\nforce_command:\n  shell: /bin/bash\n"
	cfg, err := load(writeConfig(t, body), selfUID(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.ContainsFunc(cfg.Warnings(), func(w string) bool { return strings.Contains(w, "force_command.shell") }) {
		t.Errorf("want a force_command.shell warning, got %v", cfg.Warnings())
	}
}

func TestClientConfigsResolveEachServerInOrder(t *testing.T) {
	c := DefaultConfig()
	c.Server.LogServers = []string{"a.example(tls)", "b.example:9999", "c.example"}
	got, err := c.ClientConfigs()
	if err != nil {
		t.Fatalf("ClientConfigs: %v", err)
	}
	want := []struct {
		host string
		tls  bool
	}{
		{"a.example:30344", true},
		{"b.example:9999", false},
		{"c.example:30343", false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d configs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].UpstreamHost != want[i].host || got[i].UseTLS != want[i].tls {
			t.Errorf("config %d = {%q, %v}, want {%q, %v}",
				i, got[i].UpstreamHost, got[i].UseTLS, want[i].host, want[i].tls)
		}
	}
}

// Absent means verify; only an explicit false disables it.
func TestVerifyDefaultsToOn(t *testing.T) {
	c := DefaultConfig()
	if !c.VerifyEnabled() {
		t.Error("verification must default to on")
	}
	if c.ClientConfig().TLSSkipVerify {
		t.Error("TLSSkipVerify must be false when verification is on")
	}
	no := false
	c.Server.Verify = &no
	if c.VerifyEnabled() {
		t.Error("verify: false must disable verification")
	}
	if !c.ClientConfig().TLSSkipVerify {
		t.Error("TLSSkipVerify must be true when verify is false")
	}
}

// TLSMinVersion is pinned to "1.3" explicitly even though an empty string
// already resolves to 1.3 today (config.TLSVersion) -- explicit beats
// implicit, and it keeps the floor from moving if that default ever does.
func TestClientConfigPinsTLSFloor(t *testing.T) {
	if got := DefaultConfig().ClientConfig().TLSMinVersion; got != "1.3" {
		t.Errorf("TLSMinVersion = %q, want \"1.3\"", got)
	}
}

func TestClientConfigCarriesTheCABundle(t *testing.T) {
	c := DefaultConfig()
	c.Server.CABundle = "/etc/logsh/ca.pem"
	if got := c.ClientConfig().TLSCACertFile; got != "/etc/logsh/ca.pem" {
		t.Errorf("TLSCACertFile = %q, want the ca_bundle", got)
	}
}

func TestValidateRejectsAnEmptyServerList(t *testing.T) {
	c := DefaultConfig()
	c.Server.LogServers = nil
	if err := c.Validate(); err == nil {
		t.Error("an empty log_servers list must not validate")
	}
}

func TestValidateRejectsAnUnparsableServer(t *testing.T) {
	c := DefaultConfig()
	c.Server.LogServers = []string{"good.example", "bad.example(ssl)"}
	err := c.Validate()
	if err == nil {
		t.Fatal("an unparsable entry must not validate")
	}
	if !strings.Contains(err.Error(), "bad.example(ssl)") {
		t.Errorf("error %q should name the offending entry", err)
	}
}

func TestValidateRejectsARelativeCABundle(t *testing.T) {
	c := DefaultConfig()
	c.Server.CABundle = "ca.pem"
	if err := c.Validate(); err == nil {
		t.Error("a relative ca_bundle must not validate")
	}
}

func TestWarnsWhenVerificationIsOff(t *testing.T) {
	c := DefaultConfig()
	no := false
	c.Server.Verify = &no
	c.Server.CABundle = "/etc/logsh/ca.pem"
	joined := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(joined, "any peer that completes a handshake") {
		t.Error("verify: false must warn that transcripts go to any peer")
	}
	if !strings.Contains(joined, "not used") {
		t.Error("a ca_bundle alongside verify: false must warn that it is ignored")
	}
}

// -validate normally runs as root and can read a 0600 bundle that the
// logging-in user cannot; without this the session fails its handshake instead.
func TestWarnsWhenTheCABundleIsUnreadableByTheUser(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(bundle, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := DefaultConfig()
	c.Server.CABundle = bundle
	if !strings.Contains(strings.Join(c.Warnings(), "\n"), "readable") {
		t.Error("a group/other-unreadable ca_bundle must warn")
	}
}

// yaml.Unmarshal ignores unknown keys, so an old config would otherwise fail
// with "no servers configured" and never mention the key it ignored.
func TestLoadNamesRemovedServerKeys(t *testing.T) {
	for _, tc := range []struct{ key, wants string }{
		{"upstream_host: \"127.0.0.1:30343\"", "log_servers"},
		{"use_tls: true", "log_servers"},
		{"tls_skip_verify: true", "verify"},
		{"tls_cacert_file: /etc/logsh/ca.pem", "ca_bundle"},
		{"tls_cert_file: /etc/logsh/c.pem", "client certificate"},
		{"tls_min_version: \"1.2\"", "1.3"},
	} {
		// writeConfig + load(_, selfUID(t)) is how this suite loads a config
		// without tripping Load's hardcoded root-ownership requirement.
		path := writeConfig(t, "record_users: [root]\nserver:\n  "+tc.key+"\n")
		_, err := load(path, selfUID(t))
		if err == nil {
			t.Errorf("%s: expected an error", tc.key)
			continue
		}
		if !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("%s: error %q does not point at %q", tc.key, err, tc.wants)
		}
	}
}

// TestRecognizedServerKeysMatchesServerConfig pins the key set removedKeyError
// derives by reflection, so a change to ServerConfig's yaml tags that drops a
// key -- which would make removedKeyError reject a config that legitimately
// uses it -- shows up here first, instead of as a lockout report from a host.
func TestRecognizedServerKeysMatchesServerConfig(t *testing.T) {
	want := []string{
		"log_servers", "ca_bundle", "verify",
		"connect_timeout", "response_timeout", "journal_directory",
	}
	got := recognizedServerKeys()

	// Tied to the struct itself, not just to the literal list below.
	// ServerConfig carries no inline or embedded field today, so it
	// contributes exactly one key per field; NumField is therefore the
	// count addYAMLKeys must produce. A field the helper fails to name --
	// an added field with no yaml tag was the exact gap found in review --
	// changes this count without necessarily changing len(want), so this
	// catches it even when nobody remembers to update the list below.
	if wantCount := reflect.TypeFor[ServerConfig]().NumField(); len(got) != wantCount {
		t.Fatalf("recognizedServerKeys() has %d keys, want %d (one per ServerConfig field): %v",
			len(got), wantCount, got)
	}
	if len(got) != len(want) {
		t.Fatalf("recognizedServerKeys() = %v, want exactly %v", got, want)
	}
	for _, k := range want {
		if !got[k] {
			t.Errorf("recognizedServerKeys() is missing %q", k)
		}
	}
}

// probeInline is hoisted into yamlTagProbe below by ,inline: yaml.v3 splices
// its own key(s) straight into the parent mapping, rather than nesting them
// under a key named for the field that holds it.
type probeInline struct {
	Inner string `yaml:"inner_key"`
}

// ProbeEmbedded is embedded WITHOUT ,inline in yamlTagProbe below: yaml.v3
// still gives it exactly one key of its own -- strings.ToLower of its type
// name, since the field carries no tag -- rather than hoisting Value the way
// ,inline would.
type ProbeEmbedded struct {
	Value string `yaml:"embedded_value"`
}

// yamlTagProbe exercises every yaml.v3 tag form review found missing from
// addYAMLKeys's coverage: no tag at all, ,inline, a plain (non-inline)
// anonymous field, an explicit "-", and an unexported non-anonymous field.
// ServerConfig has none of these today, but a future field could be any of
// them, and getting one wrong means a key yaml.v3 itself would decode is one
// removedKeyError rejects -- a lockout in the code meant to prevent one.
type yamlTagProbe struct {
	Explicit   string `yaml:"explicit_name"`
	Untagged   string
	unexported string      `yaml:"ignored_because_unexported"` //nolint:unused // read only via addYAMLKeys' reflection; asserted below to contribute no key
	Skipped    string      `yaml:"-"`
	Inline     probeInline `yaml:",inline"`
	ProbeEmbedded
}

func TestAddYAMLKeysMatchesEveryTagForm(t *testing.T) {
	keys := make(map[string]bool)
	addYAMLKeys(reflect.TypeFor[yamlTagProbe](), keys)

	want := []string{
		"explicit_name", // an explicit yaml:"..." tag
		"untagged",      // no tag: yaml.v3 falls back to strings.ToLower(field name)
		"inner_key",     // ,inline hoists the nested struct's own key(s)
		"probeembedded", // anonymous without ,inline: keyed by strings.ToLower(type name)
	}
	if len(keys) != len(want) {
		t.Fatalf("addYAMLKeys(yamlTagProbe) = %v, want exactly %v", keys, want)
	}
	for _, k := range want {
		if !keys[k] {
			t.Errorf("addYAMLKeys(yamlTagProbe) is missing %q", k)
		}
	}
	if keys["ignored_because_unexported"] {
		t.Error("an unexported, non-anonymous field must not contribute a key")
	}
	if keys["inline"] || keys["Inline"] {
		t.Error(",inline must hoist the nested struct's own keys, not add one named for the field")
	}
	if keys["skipped"] || keys["Skipped"] || keys["-"] {
		t.Error(`yaml:"-" must not contribute a key`)
	}
}

// TestRemovedKeyErrorAcceptsEveryRecognizedKey is the other direction from
// TestLoadNamesRemovedServerKeys: every key ServerConfig actually understands
// must still pass, or rejecting unrecognised keys would trade the silent
// misdirection this task fixes for an outright lockout on a valid config.
func TestRemovedKeyErrorAcceptsEveryRecognizedKey(t *testing.T) {
	body := "server:\n" +
		"  log_servers: [\"central.example(tls)\"]\n" +
		"  ca_bundle: /etc/logsh/ca.pem\n" +
		"  verify: true\n" +
		"  connect_timeout: 5s\n" +
		"  response_timeout: 30s\n" +
		"  journal_directory: \"\"\n"
	if err := removedKeyError([]byte(body)); err != nil {
		t.Errorf("a config using only recognised server keys was rejected: %v", err)
	}
}

// TestLoadNamesGenericUnknownServerKey is the corrected-premise case: a
// server: key that is neither current nor one of the six enumerated removals
// must still be rejected, by name. Without this, a removed key this task's
// table fails to list -- or a plain typo -- would fail exactly as silently as
// upstream_host used to: the default log_servers stays in place, Validate
// sees a non-empty list, and the config passes.
func TestLoadNamesGenericUnknownServerKey(t *testing.T) {
	path := writeConfig(t, "record_users: [root]\nserver:\n  frobnicate: true\n")
	_, err := load(path, selfUID(t))
	if err == nil {
		t.Fatal("an unrecognised server key was accepted")
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("error %q does not name the offending key", err)
	}
	if strings.Contains(err.Error(), "0.4.0") {
		t.Errorf("error %q claims a removal version for a key that was never enumerated", err)
	}
}

// TestRemovedKeyErrorIsDeterministic guards the sort in removedKeyError, and
// that every bad key is reported, not just the first. Go randomizes map
// iteration order per call, so without the sort, an operator fixing the
// keys a run happened to report would just uncover a different set, or a
// different order, next time they validated -- and a typical unconverted
// config carries several of these keys together, so reporting only one
// would turn a single edit into repeated edit/validate cycles.
func TestRemovedKeyErrorIsDeterministic(t *testing.T) {
	body := "server:\n  use_tls: true\n  upstream_host: \"x\"\n  tls_skip_verify: true\n"
	want := "3 unusable keys under server:\n" +
		"  server.tls_skip_verify was removed in 0.4.0; use server.verify: false\n" +
		"  server.upstream_host was removed in 0.4.0; use server.log_servers, e.g. [\"127.0.0.1\"] or [\"host(tls)\"]\n" +
		"  server.use_tls was removed in 0.4.0; use the \"(tls)\" suffix on a server.log_servers entry, e.g. [\"host(tls)\"]"
	for range 20 {
		err := removedKeyError([]byte(body))
		if err == nil {
			t.Fatal("want an error")
		}
		if err.Error() != want {
			t.Fatalf("error =\n%s\nwant\n%s", err, want)
		}
	}
}

// TestLoadAcceptsAFullyModernServerBlock is the end-to-end green case this
// task needs alongside TestLoadNamesRemovedServerKeys: a config using every
// key ServerConfig currently understands must load cleanly through the real
// load() path -- CheckPerms, the real yaml.Unmarshal, removedKeyError and
// Validate together, not just removedKeyError in isolation the way
// TestRemovedKeyErrorAcceptsEveryRecognizedKey exercises it. Until Task 6
// rewrites examples/logsh.yaml, this is the only green proof that a valid,
// current config is not rejected by this task's own check; it must stay
// green regardless of when that lands.
func TestLoadAcceptsAFullyModernServerBlock(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(bundle, []byte("x"), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	body := "record_users: [root]\n" +
		"server:\n" +
		"  log_servers: [\"central.example(tls)\"]\n" +
		"  ca_bundle: \"" + bundle + "\"\n" +
		"  verify: true\n" +
		"  connect_timeout: 5s\n" +
		"  response_timeout: 30s\n" +
		"  journal_directory: \"\"\n"
	cfg, err := load(writeConfig(t, body), selfUID(t))
	if err != nil {
		t.Fatalf("a config using only recognised server keys was rejected: %v", err)
	}
	if len(cfg.Server.LogServers) != 1 || cfg.Server.LogServers[0] != "central.example(tls)" {
		t.Errorf("Server.LogServers = %v, want [central.example(tls)]", cfg.Server.LogServers)
	}
	if cfg.Server.CABundle != bundle {
		t.Errorf("Server.CABundle = %q, want %q", cfg.Server.CABundle, bundle)
	}
}
