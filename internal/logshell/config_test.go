// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/config_test.go
package logshell

import (
	"os"
	"path/filepath"
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
			name:    "missing upstream",
			mutate:  func(c *Config) { c.Server.UpstreamHost = "" },
			wantErr: "upstream_host",
		},
		{
			name:    "half-configured TLS pair",
			mutate:  func(c *Config) { c.Server.TLSCertFile = "/etc/logsh/cert.pem" },
			wantErr: "together",
		},
		{
			name:    "bad tls_min_version",
			mutate:  func(c *Config) { c.Server.TLSMinVersion = "1.1" },
			wantErr: "tls_min_version",
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

// TestWarningsFlagsUserReadableClientKey guards the property that makes the
// whole deployment model safe: logsh runs as the logging-in user, so a client
// certificate it can read is one that user can steal and use to forge audit
// records against the central server.
func TestWarningsFlagsUserReadableClientKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RecordUsers = []string{"root"}
	cfg.Server.TLSCertFile = "/etc/logsh/client.pem"
	cfg.Server.TLSKeyFile = "/etc/logsh/client.key"

	var found bool
	for _, w := range cfg.Warnings() {
		if strings.Contains(w, "tls_cert_file") {
			found = true
		}
	}
	if !found {
		t.Error("configuring a client certificate produced no warning, though logsh runs as " +
			"the logging-in user and the key would be readable by them")
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
