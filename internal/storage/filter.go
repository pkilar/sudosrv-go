// SPDX-License-Identifier: Apache-2.0
// Filename: internal/storage/filter.go
package storage

import (
	"regexp"
	"sync"
)

// tailWindowSize is the number of trailing output bytes carried over between
// CheckOutput calls so prompts split across I/O buffer boundaries still match.
// 128 bytes fits a long multi-byte prompt plus ANSI escape sequences.
const tailWindowSize = 128

// PasswordFilter provides regex-based password prompt detection and input masking.
// It maintains a sliding window of recent tty output so prompts that straddle
// message boundaries still trigger filtering. All methods are safe for
// concurrent use.
type PasswordFilter struct {
	mu          sync.Mutex
	patterns    []*regexp.Regexp
	tail        []byte // rolling tail of recent output to catch split prompts
	isFiltering bool
}

// NewPasswordFilter creates a password filter seeded with a set of common
// password / passphrase / PIN prompts spanning several locales and prompt
// styles. Additional patterns can be added via AddPattern.
//
// The patterns are case-insensitive and match common sudo, ssh, and su prompts:
//   - "password"/"passwd" (en), "passphrase", "PIN"
//   - "passwort" (de), "contraseña" (es), "mot de passe" (fr), "senha" (pt),
//     "пароль" (ru), "密码"/"パスワード" (CJK)
func NewPasswordFilter() *PasswordFilter {
	filter := &PasswordFilter{}
	defaults := []string{
		`(?i)pass(word|phrase|wd)\s*[:：]`,
		`(?i)\bPIN\b\s*[:：]`,
		`(?i)\bpasswort\b\s*[:：]`,
		`(?i)contrase[ñn]a\s*[:：]`,
		`(?i)mot de passe\s*[:：]`,
		`(?i)\bsenha\b\s*[:：]`,
		`пароль\s*[:：]`,
		`密码\s*[:：]`,
		`パスワード\s*[:：]`,
	}
	for _, p := range defaults {
		_ = filter.AddPattern(p)
	}
	return filter
}

// AddPattern compiles and appends a prompt-detection regex.
func (f *PasswordFilter) AddPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.patterns = append(f.patterns, re)
	f.mu.Unlock()
	return nil
}

// CheckOutput examines terminal output for password prompts. A rolling tail
// from prior calls is prepended so a prompt split across two I/O buffers (for
// example "Passw" arriving in one message and "ord:" in the next) still
// matches. Call on TTYOUT data.
func (f *PasswordFilter) CheckOutput(data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Build the search window: previous tail + current data.
	window := data
	if len(f.tail) > 0 {
		window = make([]byte, 0, len(f.tail)+len(data))
		window = append(window, f.tail...)
		window = append(window, data...)
	}

	for _, pattern := range f.patterns {
		if pattern.Match(window) {
			f.isFiltering = true
			// Clear the tail on a match so the next prompt doesn't keep firing
			// on the stale window; input will flip filtering off on newline.
			f.tail = f.tail[:0]
			return
		}
	}

	// Preserve the last tailWindowSize bytes for the next call.
	if len(window) > tailWindowSize {
		window = window[len(window)-tailWindowSize:]
	}
	f.tail = append(f.tail[:0], window...)
}

// FilterInput masks input bytes while filtering is active. A carriage return
// or newline disables filtering and is itself passed through unmasked; any
// bytes after a newline in the same chunk are returned as-is (they belong to
// the next line, not the password). Call on TTYIN data.
func (f *PasswordFilter) FilterInput(data []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.isFiltering {
		return data
	}

	masked := make([]byte, len(data))
	disabledAt := -1
	for i, b := range data {
		if disabledAt >= 0 {
			// Already past the newline boundary — pass through unchanged.
			masked[i] = b
			continue
		}
		if b == '\n' || b == '\r' {
			masked[i] = b
			disabledAt = i
			continue
		}
		masked[i] = '*'
	}
	if disabledAt >= 0 {
		f.isFiltering = false
	}
	return masked
}

// Reset clears filtering state and the sliding window.
func (f *PasswordFilter) Reset() {
	f.mu.Lock()
	f.isFiltering = false
	f.tail = f.tail[:0]
	f.mu.Unlock()
}

// IsFiltering reports whether the filter is currently masking input.
func (f *PasswordFilter) IsFiltering() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.isFiltering
}
