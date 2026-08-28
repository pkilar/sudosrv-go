// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/sshdconfig_test.go
package logshell

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCfg(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestSftpSubsystemReadsAnExternalBinary(t *testing.T) {
	dir := t.TempDir()
	cfg := writeCfg(t, dir, "sshd_config",
		"# comment\nPermitRootLogin yes\nSubsystem sftp /usr/libexec/openssh/sftp-server\n")
	got, err := SftpSubsystem(cfg)
	if err != nil {
		t.Fatalf("SftpSubsystem: %v", err)
	}
	if got != "/usr/libexec/openssh/sftp-server" {
		t.Errorf("got %q, want the RHEL path", got)
	}
}

// sshd keywords are case-insensitive, and the argument may carry options.
func TestSftpSubsystemIsCaseInsensitiveAndKeepsArguments(t *testing.T) {
	dir := t.TempDir()
	cfg := writeCfg(t, dir, "sshd_config", "SUBSYSTEM   SFTP   /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO\n")
	got, err := SftpSubsystem(cfg)
	if err != nil {
		t.Fatalf("SftpSubsystem: %v", err)
	}
	if got != "/usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO" {
		t.Errorf("got %q, want the path with its arguments", got)
	}
}

func TestSftpSubsystemDetectsInternalSftp(t *testing.T) {
	dir := t.TempDir()
	cfg := writeCfg(t, dir, "sshd_config", "Subsystem sftp internal-sftp\n")
	got, _ := SftpSubsystem(cfg)
	if got != "internal-sftp" {
		t.Errorf("got %q, want internal-sftp", got)
	}
}

// Most distributions reach their drop-in directory through Include, so a parser
// that only reads the top-level file finds nothing on a stock host.
func TestSftpSubsystemFollowsInclude(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "sshd_config.d/50-sftp.conf", "Subsystem sftp /usr/libexec/openssh/sftp-server\n")
	cfg := writeCfg(t, dir, "sshd_config", "Include sshd_config.d/*.conf\nPermitRootLogin no\n")
	got, err := SftpSubsystem(cfg)
	if err != nil {
		t.Fatalf("SftpSubsystem: %v", err)
	}
	if got != "/usr/libexec/openssh/sftp-server" {
		t.Errorf("got %q, want the included path", got)
	}
}

// sshd takes the FIRST value it obtains for a keyword, and Include is processed
// where it appears -- so an include above a later line wins.
func TestSftpSubsystemFirstValueWins(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "sshd_config.d/10-first.conf", "Subsystem sftp internal-sftp\n")
	cfg := writeCfg(t, dir, "sshd_config",
		"Include sshd_config.d/*.conf\nSubsystem sftp /usr/lib/ssh/sftp-server\n")
	got, _ := SftpSubsystem(cfg)
	if got != "internal-sftp" {
		t.Errorf("got %q, want the first value (from the include)", got)
	}
}

func TestSftpSubsystemAbsentIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	cfg := writeCfg(t, dir, "sshd_config", "PermitRootLogin yes\n")
	got, err := SftpSubsystem(cfg)
	if err != nil {
		t.Fatalf("a config without a Subsystem line is normal, not an error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestSftpSubsystemMissingFileIsNotAnError(t *testing.T) {
	got, err := SftpSubsystem(filepath.Join(t.TempDir(), "nope"))
	if err != nil || got != "" {
		t.Errorf("a missing sshd_config should read as unknown, got %q, %v", got, err)
	}
}

// The suggestion must name something that exists; an unusable path in an error
// message sends the reader somewhere that cannot work.
func TestFindSftpServerOnlyReturnsSomethingReal(t *testing.T) {
	got := FindSftpServer()
	if got == "" {
		t.Skip("no sftp-server installed on this host")
	}
	st, err := os.Stat(got)
	if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		t.Errorf("FindSftpServer returned %q, which is not an executable file", got)
	}
}
