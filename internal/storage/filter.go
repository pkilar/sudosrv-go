// Filename: internal/storage/filter.go
package storage

import (
	"bytes"
	"regexp"
)

// PasswordFilter provides regex-based password prompt detection and input masking.
// Matches sudo's iolog_filter implementation for password filtering.
type PasswordFilter struct {
	patterns  []*regexp.Regexp
	isFiltering bool
}

// NewPasswordFilter creates a new password filter with default pattern.
// Default pattern matches "[Pp]assword[: ]*" similar to sudo's implementation.
func NewPasswordFilter() *PasswordFilter {
	filter := &PasswordFilter{
		patterns: make([]*regexp.Regexp, 0),
	}
	// Add default password prompt pattern
	filter.AddPattern(`[Pp]assword[:\s]*`)
	return filter
}

// AddPattern adds a regex pattern to detect password prompts.
// Patterns are compiled and added to the filter's pattern list.
func (f *PasswordFilter) AddPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	f.patterns = append(f.patterns, re)
	return nil
}

// CheckOutput examines terminal output for password prompts.
// If a prompt is detected, enables filtering mode.
// Should be called on TTYOUT data.
func (f *PasswordFilter) CheckOutput(data []byte) {
	// Check if any pattern matches the output
	for _, pattern := range f.patterns {
		if pattern.Match(data) {
			f.isFiltering = true
			return
		}
	}
}

// FilterInput masks input data if filtering is active.
// Returns masked data (asterisks) if filtering, or original data if not.
// Automatically disables filtering on newline characters.
// Should be called on TTYIN data.
func (f *PasswordFilter) FilterInput(data []byte) []byte {
	if !f.isFiltering {
		return data
	}

	// Check if data contains newline - if so, stop filtering
	if bytes.Contains(data, []byte("\n")) || bytes.Contains(data, []byte("\r")) {
		f.isFiltering = false
		// Mask everything up to the newline
		masked := make([]byte, len(data))
		for i := range data {
			if data[i] == '\n' || data[i] == '\r' {
				masked[i] = data[i] // Preserve newline
			} else {
				masked[i] = '*'
			}
		}
		return masked
	}

	// Mask all characters with asterisks
	masked := make([]byte, len(data))
	for i := range masked {
		masked[i] = '*'
	}
	return masked
}

// Reset clears the filtering state.
func (f *PasswordFilter) Reset() {
	f.isFiltering = false
}

// IsFiltering returns whether the filter is currently active.
func (f *PasswordFilter) IsFiltering() bool {
	return f.isFiltering
}
