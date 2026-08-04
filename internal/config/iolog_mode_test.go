// SPDX-License-Identifier: Apache-2.0
// Filename: internal/config/iolog_mode_test.go
package config

import (
	"strings"
	"testing"
)

// TestDeriveIologModes pins the derivation in lib/iolog/iolog_conf.c:110-128.
// The cases that matter are the counter-intuitive ones: owner read+write are
// forced on even for mode 0, configured execute bits are discarded, and the
// directory execute bits are re-derived from the surviving read/write bits.
// Conformance: docs/logsrvd-reference/ CONF-055.
func TestDeriveIologModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		mode     uint32
		wantFile uint32
		wantDir  uint32
	}{
		{"C default 0600", 0600, 0600, 0700},
		{"zero still forces owner rw", 0, 0600, 0700},
		{"0750 yields 0640 file and 0750 dir", 0750, 0640, 0750},
		{"0640 group-read", 0640, 0640, 0750},
		{"0660 group-write implies group-exec on dir", 0660, 0660, 0770},
		{"0666 other-write implies other-exec on dir", 0666, 0666, 0777},
		{"0604 other-read", 0604, 0604, 0705},
		{"owner bits in input are ignored, always 0600", 0100, 0600, 0700},
		{"configured group-exec alone is discarded", 0610, 0600, 0700},
		{"setuid/setgid/sticky are discarded", 07600, 0600, 0700},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotFile, gotDir := DeriveIologModes(tt.mode)
			if gotFile != tt.wantFile {
				t.Errorf("DeriveIologModes(0%o) file = 0%o, want 0%o", tt.mode, gotFile, tt.wantFile)
			}
			if gotDir != tt.wantDir {
				t.Errorf("DeriveIologModes(0%o) dir = 0%o, want 0%o", tt.mode, gotDir, tt.wantDir)
			}
		})
	}
}

// TestEffectiveModesPreferExplicitOverride covers the migration path: a config
// that still sets the deprecated keys keeps its old modes, per dimension, so an
// upgrade cannot silently tighten permissions out from under a log shipper.
func TestEffectiveModesPreferExplicitOverride(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		cfg              LocalStorageConfig
		wantDir, wantFil uint32
	}{
		{"both derived", LocalStorageConfig{IologMode: 0600}, 0700, 0600},
		{"dir overridden only", LocalStorageConfig{IologMode: 0600, DirPermissions: 0750}, 0750, 0600},
		{"file overridden only", LocalStorageConfig{IologMode: 0600, FilePermissions: 0640}, 0700, 0640},
		{"both overridden", LocalStorageConfig{IologMode: 0600, DirPermissions: 0755, FilePermissions: 0644}, 0755, 0644},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.cfg.EffectiveDirMode(); got != tt.wantDir {
				t.Errorf("EffectiveDirMode() = 0%o, want 0%o", got, tt.wantDir)
			}
			if got := tt.cfg.EffectiveFileMode(); got != tt.wantFil {
				t.Errorf("EffectiveFileMode() = 0%o, want 0%o", got, tt.wantFil)
			}
		})
	}
}

// TestIologModeYAMLRoundTrip checks the whole load path, including the YAML 1.2
// decimal-to-octal correction that "iolog_mode: 0640" needs.
func TestIologModeYAMLRoundTrip(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	if err := unmarshalConfig([]byte("local_storage:\n  iolog_mode: 0640\n"), cfg); err != nil {
		t.Fatalf("unmarshalConfig: %v", err)
	}
	if cfg.LocalStorage.IologMode != 0640 {
		t.Fatalf("IologMode = 0%o, want 0640 (decimal 640 should be re-read as octal)", cfg.LocalStorage.IologMode)
	}
	if got := cfg.LocalStorage.EffectiveFileMode(); got != 0640 {
		t.Errorf("EffectiveFileMode() = 0%o, want 0640", got)
	}
	if got := cfg.LocalStorage.EffectiveDirMode(); got != 0750 {
		t.Errorf("EffectiveDirMode() = 0%o, want 0750", got)
	}
}

// TestValidatePassPromptRegex pins CONF-057's load-time rejection: a bad
// pattern must fail the config load, not silently disable prompt detection.
func TestValidatePassPromptRegex(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		patterns []string
		wantErr  string
	}{
		{"empty is fine", nil, ""},
		{"valid patterns", []string{`[Pp]assword[: ]*`, `(?i)passphrase`}, ""},
		{"leading (?i) accepted as C writes it", []string{`(?i)password:`}, ""},
		{"^ before (?i) accepted", []string{`^(?i)password:`}, ""},
		{"uncompilable pattern rejected", []string{`[unterminated`}, "passprompt_regex"},
		{"one bad pattern among good ones rejected", []string{`ok`, `*bad`}, "passprompt_regex"},
		{"over-long pattern rejected", []string{strings.Repeat("a", MaxPassPromptRegexLen+1)}, "maximum is 1024"},
		{"exactly at the limit accepted", []string{strings.Repeat("a", MaxPassPromptRegexLen)}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePassPromptRegex(tt.patterns)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("ValidatePassPromptRegex(): unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("ValidatePassPromptRegex(): want error containing %q, got nil", tt.wantErr)
			case tt.wantErr != "" && err != nil && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("ValidatePassPromptRegex(): want error containing %q, got %q", tt.wantErr, err)
			}
		})
	}
}

// TestValidateRejectsBadPassPromptRegex confirms the check is actually reached
// from Validate in local mode, not merely available as a helper.
func TestValidateRejectsBadPassPromptRegex(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	cfg.LocalStorage.PassPromptRegex = []string{`[unterminated`}
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "passprompt_regex") {
		t.Fatalf("Validate() = %v, want a passprompt_regex error", err)
	}
}
