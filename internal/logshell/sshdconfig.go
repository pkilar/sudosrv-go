// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/sshdconfig.go
package logshell

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// sshdIncludeMaxDepth bounds Include recursion. sshd itself refuses to nest
// beyond a fixed depth; the point here is only that a configuration which
// includes itself must not hang the caller.
const sshdIncludeMaxDepth = 16

// SshdConfigPath is where sshd's configuration lives. A constant rather than a
// literal at the call site, so a test or a scratch root can point elsewhere.
const SshdConfigPath = "/etc/ssh/sshd_config"

// SftpSubsystem returns the command sshd would run for the "sftp" subsystem on
// this host, or "" if the configuration does not name one.
//
// It exists because the correct sftp-server path is a property of the host, not
// of this project: RHEL puts it in /usr/libexec/openssh, Debian in
// /usr/lib/openssh, Arch in /usr/lib/ssh. sshd_config already records which,
// so asking it beats shipping a guess -- and the answer also says whether an
// internal-sftp route is needed at all, since a host naming a real binary sends
// that binary's path as the client's command and needs no route.
//
// A missing or unreadable file reads as "unknown" rather than an error: the
// caller is reporting on a host's configuration, and being unable to see it is
// not the same as the host being misconfigured.
func SftpSubsystem(configPath string) (string, error) {
	return sftpSubsystem(configPath, filepath.Dir(configPath), 0)
}

func sftpSubsystem(path, base string, depth int) (string, error) {
	if depth >= sshdIncludeMaxDepth {
		return "", nil
	}
	f, err := os.Open(path) // #nosec G304 -- an operator-supplied config path
	if err != nil {
		return "", nil
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		// sshd keywords are case-insensitive; their arguments are not.
		switch strings.ToLower(fields[0]) {
		case "include":
			// Include is processed where it appears, and sshd keeps the FIRST
			// value it obtains for a keyword -- so a Subsystem inside an include
			// above a later Subsystem line is the one that takes effect.
			for _, pattern := range fields[1:] {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(base, pattern)
				}
				matches, globErr := filepath.Glob(pattern)
				if globErr != nil {
					continue
				}
				for _, m := range matches {
					if got, _ := sftpSubsystem(m, base, depth+1); got != "" {
						return got, nil
					}
				}
			}
		case "subsystem":
			if len(fields) >= 3 && strings.EqualFold(fields[1], "sftp") {
				return strings.Join(fields[2:], " "), nil
			}
		}
	}
	return "", sc.Err()
}

// knownSftpServerPaths are where the distributions put the sftp-server binary.
// Used only to make an error message actionable: when sshd is configured for
// internal-sftp there is no path in the configuration to quote back, so the
// remedy has to name one that exists here.
var knownSftpServerPaths = []string{
	"/usr/libexec/openssh/sftp-server", // RHEL, Fedora
	"/usr/lib/openssh/sftp-server",     // Debian, Ubuntu
	"/usr/lib/ssh/sftp-server",         // Arch
}

// FindSftpServer returns the first sftp-server binary present on this host, or
// "" if none of the known locations has one. It never guesses a path that does
// not exist: an unusable suggestion is worse than none.
func FindSftpServer() string {
	for _, p := range knownSftpServerPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}
