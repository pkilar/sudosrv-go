// SPDX-License-Identifier: Apache-2.0
// Filename: internal/storage/filter_test.go
package storage

import "testing"

// TestPasswordFilter_DetectsPrompts covers the baseline patterns: ASCII,
// non-ASCII (German), and the standard sudo prompt shape.
func TestPasswordFilter_DetectsPrompts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		prompt string
	}{
		{"english password", "Password: "},
		{"passwd colon", "passwd: "},
		{"passphrase", "Enter passphrase:"},
		{"sudo style", "[sudo] password for alice: "},
		{"german", "Passwort: "},
		{"fullwidth colon", "Password："},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := NewPasswordFilter()
			f.CheckOutput([]byte(tc.prompt))
			if !f.IsFiltering() {
				t.Fatalf("prompt %q did not trigger filtering", tc.prompt)
			}
		})
	}
}

// TestPasswordFilter_StripsCSI verifies the CSI bypass fix: terminal redraw
// often interleaves cursor/color codes between "Password" and ":", which
// previously prevented the regex from matching and let the secret through.
func TestPasswordFilter_StripsCSI(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		prompt string
	}{
		{"clear-to-EOL between word and colon", "Password\x1b[K: "},
		{"color reset between word and colon", "Password\x1b[0m: "},
		{"cursor move embedded", "Pass\x1b[1;5Hword: "},
		{"multiple CSI sequences", "\x1b[1mPassword\x1b[0m\x1b[K: "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := NewPasswordFilter()
			f.CheckOutput([]byte(tc.prompt))
			if !f.IsFiltering() {
				t.Fatalf("CSI-embedded prompt %q did not trigger filtering", tc.prompt)
			}
		})
	}
}

// TestPasswordFilter_SplitAcrossCalls verifies the rolling-window tail
// preserves enough context to match a prompt that arrives in two pieces.
func TestPasswordFilter_SplitAcrossCalls(t *testing.T) {
	t.Parallel()
	f := NewPasswordFilter()
	f.CheckOutput([]byte("Passw"))
	if f.IsFiltering() {
		t.Fatal("partial prompt should not trigger filtering yet")
	}
	f.CheckOutput([]byte("ord: "))
	if !f.IsFiltering() {
		t.Fatal("completed prompt across calls did not trigger filtering")
	}
}

// TestPasswordFilter_MasksInputUntilNewline verifies FilterInput masks bytes
// while filtering is active and disables itself on newline.
func TestPasswordFilter_MasksInputUntilNewline(t *testing.T) {
	t.Parallel()
	f := NewPasswordFilter()
	f.CheckOutput([]byte("Password: "))
	if !f.IsFiltering() {
		t.Fatal("setup failed: filter did not engage")
	}
	got := f.FilterInput([]byte("secret\n"))
	want := "******\n"
	if string(got) != want {
		t.Errorf("FilterInput(secret\\n) = %q, want %q", got, want)
	}
	if f.IsFiltering() {
		t.Error("filter should be disabled after newline")
	}
}

// TestPasswordFilter_NonFilteringPassthrough verifies non-prompt output does
// not trigger filtering and input passes through unchanged.
func TestPasswordFilter_NonFilteringPassthrough(t *testing.T) {
	t.Parallel()
	f := NewPasswordFilter()
	f.CheckOutput([]byte("hello world\n"))
	if f.IsFiltering() {
		t.Error("non-prompt output should not trigger filtering")
	}
	got := f.FilterInput([]byte("hello"))
	if string(got) != "hello" {
		t.Errorf("FilterInput should passthrough when not filtering, got %q", got)
	}
}

// TestPasswordFilter_Reset clears filtering state for session reuse safety.
func TestPasswordFilter_Reset(t *testing.T) {
	t.Parallel()
	f := NewPasswordFilter()
	f.CheckOutput([]byte("Password: "))
	if !f.IsFiltering() {
		t.Fatal("setup failed")
	}
	f.Reset()
	if f.IsFiltering() {
		t.Error("Reset should clear isFiltering")
	}
}
