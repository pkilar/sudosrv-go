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

// TestPasswordFilter_ColonlessPrompts verifies prompts that do not end in a
// colon still arm masking. C's default passprompt regex is "[Pp]assword[: ]*"
// (include/sudo_iolog.h:65) whose trailing quantifier permits zero characters,
// so sudo_logsrvd masks after a bare "Password". Requiring a colon here would
// write the secret verbatim into ttyin for every colon-less prompt.
func TestPasswordFilter_ColonlessPrompts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		prompt string
	}{
		{"bare word", "Enter your password"},
		{"angle bracket", "Password > "},
		{"question mark", "Password? "},
		{"space only", "Password "},
		{"passphrase no colon", "Enter passphrase for key '/home/a/.ssh/id_ed25519'"},
		{"german no colon", "Passwort eingeben"},
		{"spanish no colon", "Introduzca la contraseña"},
		{"french no colon", "Entrez le mot de passe"},
		{"portuguese no colon", "Digite a senha"},
		{"russian no colon", "Введите пароль"},
		{"chinese no colon", "请输入密码"},
		{"japanese no colon", "パスワードを入力"},
		{"pin no colon", "Enter PIN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := NewPasswordFilter()
			f.CheckOutput([]byte(tc.prompt))
			if !f.IsFiltering() {
				t.Fatalf("colon-less prompt %q did not trigger filtering", tc.prompt)
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

// TestDefaultPromptPatternsCompile guards the panic in NewPasswordFilter, which
// is only safe while every built-in pattern is known-good.
func TestDefaultPromptPatternsCompile(t *testing.T) {
	t.Parallel()
	if _, err := NewPasswordFilterWithPatterns(nil); err != nil {
		t.Fatalf("built-in prompt patterns must compile: %v", err)
	}
}

// TestConfiguredPatternsReplaceDefaults pins CONF-057's replace-don't-append
// rule: once an operator configures any pattern, the built-in set is gone. A
// site that narrows detection to its own PAM prompt must not keep silently
// matching "password" everywhere, which is what appending would do.
func TestConfiguredPatternsReplaceDefaults(t *testing.T) {
	t.Parallel()

	f, err := NewPasswordFilterWithPatterns([]string{`Enter unlock code`})
	if err != nil {
		t.Fatalf("NewPasswordFilterWithPatterns: %v", err)
	}

	// The built-in "password" pattern must no longer be active.
	f.CheckOutput([]byte("Password: "))
	if f.IsFiltering() {
		t.Error("a configured pattern set must REPLACE the built-ins, but the built-in password prompt still armed masking")
	}

	// The configured pattern must be.
	f.CheckOutput([]byte("Enter unlock code: "))
	if !f.IsFiltering() {
		t.Error("the configured pattern did not arm masking")
	}
	if got := string(f.FilterInput([]byte("hunter2\n"))); got != "*******\n" {
		t.Errorf("FilterInput() = %q, want %q", got, "*******\n")
	}
}

// TestEmptyPatternListKeepsDefaults is the other half: an operator who
// configures nothing keeps the built-in multi-locale set.
func TestEmptyPatternListKeepsDefaults(t *testing.T) {
	t.Parallel()
	f, err := NewPasswordFilterWithPatterns(nil)
	if err != nil {
		t.Fatalf("NewPasswordFilterWithPatterns: %v", err)
	}
	f.CheckOutput([]byte("Passwort: "))
	if !f.IsFiltering() {
		t.Error("built-in locale patterns should still be active when none are configured")
	}
}

// TestBadConfiguredPatternErrors keeps the constructor from silently shipping a
// filter with fewer patterns than the operator asked for.
func TestBadConfiguredPatternErrors(t *testing.T) {
	t.Parallel()
	if _, err := NewPasswordFilterWithPatterns([]string{`[unterminated`}); err == nil {
		t.Fatal("NewPasswordFilterWithPatterns() accepted an uncompilable pattern")
	}
}
