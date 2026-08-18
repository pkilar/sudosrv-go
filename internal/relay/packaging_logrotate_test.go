// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/packaging_logrotate_test.go
package relay

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestShippedLogrotateDoesNotRotateRelayCache checks that no logrotate config
// this repo installs can touch the relay cache spool.
//
// The relay cache directory is not a log directory. It is a spool of sudo
// session journals that have NOT yet reached the upstream server, and the only
// handles on them are their names: an in-process flush reopens
// {uuid}.log/{uuid}.log.flushing by name, and ScanOrphans finds a crashed run's
// backlog by globbing exactly those two patterns. A logrotate stanza covering
// the spool renames {uuid}.log to {uuid}.log.1 (then .log.1.gz), which both
// paths stop seeing, and deletes it a few weeks later. C ships no logrotate
// config at all, and its journals are UUID-named with no .log suffix under
// <relay_dir>/incoming and <relay_dir>/outgoing (logsrvd/logsrvd_journal.c:112-118,491-493),
// so nothing there is exposed to a *.log glob either.
//
// Conformance: docs/logsrvd-reference/ CONF-042.
func TestShippedLogrotateDoesNotRotateRelayCache(t *testing.T) {
	cacheDirs := shippedRelayCacheDirs(t)
	configs := shippedLogrotateConfigs(t)

	for _, path := range configs {
		stanzas := parseLogrotateStanzas(t, path)
		if len(stanzas) == 0 {
			t.Errorf("%s: parsed no stanzas at all, so this check proves nothing", path)
		}
		for _, stanza := range stanzas {
			for _, pattern := range stanza.patterns {
				for _, dir := range cacheDirs {
					if name, ok := logrotateCoversCache(pattern, dir); ok {
						t.Errorf("%s:%d: stanza pattern %q rotates the relay cache spool %s "+
							"(it matches %s); rotation renames undelivered session journals out "+
							"from under both the in-process flush and ScanOrphans, then deletes them",
							path, stanza.line, pattern, dir, name)
					}
				}
			}
		}
	}
}

// logrotateCoversCache reports whether a logrotate path pattern would select a
// relay cache file living in dir, and which file name proves it.
func logrotateCoversCache(pattern, dir string) (string, bool) {
	if filepath.Clean(pattern) == filepath.Clean(dir) {
		return dir, true
	}
	// A representative session cache file in each state the spool can hold. Any
	// of them being rotated loses the session — and the two parked states are
	// the ones that matter most, because a parked journal is by definition the
	// only surviving copy of a session that never reached the upstream.
	const uuid = "0f5c2b1e-0f7b-4a0f-9a1e-7d3f2c4b6a80"
	for _, name := range []string{
		uuid + ".log",
		uuid + ".log" + FlushingSuffix,
		uuid + ".log" + DeliveredSuffix,
		uuid + ".log" + RejectedSuffix,
		uuid + ".log" + IncompleteSuffix,
	} {
		full := filepath.Join(dir, name)
		if ok, err := filepath.Match(pattern, full); err == nil && ok {
			return full, true
		}
	}
	return "", false
}

var relayCacheDirRe = regexp.MustCompile(`relay_cache_directory:\s*"?([^"\s#]+)"?`)

// shippedRelayCacheDirs reads the spool paths out of the packaged configs, so
// that renaming the spool moves this test with it rather than silently
// disarming it.
func shippedRelayCacheDirs(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	var dirs []string
	for _, p := range []string{
		"../../packaging/config/sudosrv.yaml",
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("reading packaged config %s: %v", p, err)
		}
		for _, m := range relayCacheDirRe.FindAllStringSubmatch(string(data), -1) {
			if dir := m[1]; !seen[dir] {
				seen[dir] = true
				dirs = append(dirs, dir)
			}
		}
	}
	if len(dirs) == 0 {
		t.Fatal("no relay_cache_directory found in the packaged configs; " +
			"this test can no longer tell which directory is the relay spool")
	}
	return dirs
}

func shippedLogrotateConfigs(t *testing.T) []string {
	t.Helper()
	var configs []string
	for _, pattern := range []string{
		"../../packaging/logrotate/*.logrotate",
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		configs = append(configs, matches...)
	}
	// One file now, not one per format: the per-format copies were merged into
	// packaging/logrotate/ so they cannot drift. Whether every format actually
	// INSTALLS it is a separate question, and the answer used to be no --
	// Debian shipped none at all. TestEveryFormatInstallsTheSharedAssets in
	// internal/logshell covers that; this test covers the content.
	if len(configs) != 1 {
		t.Fatalf("expected exactly the one shared logrotate config, found %v", configs)
	}
	return configs
}

type logrotateStanza struct {
	line     int
	patterns []string
}

// parseLogrotateStanzas extracts the path patterns heading each `{ ... }` block.
// logrotate allows several whitespace- or newline-separated patterns per stanza.
func parseLogrotateStanzas(t *testing.T, path string) []logrotateStanza {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	var (
		stanzas    []logrotateStanza
		header     []string
		headerLine int
		depth      int
	)
	for i, raw := range strings.Split(string(data), "\n") {
		line, _, _ := strings.Cut(raw, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if depth > 0 {
			depth -= strings.Count(line, "}")
			continue
		}
		if headerLine == 0 {
			headerLine = i + 1
		}
		before, body, found := strings.Cut(line, "{")
		if !found {
			header = append(header, strings.Fields(line)...)
			continue
		}
		header = append(header, strings.Fields(before)...)
		stanzas = append(stanzas, logrotateStanza{line: headerLine, patterns: header})
		header, headerLine = nil, 0
		depth = 1 - strings.Count(body, "}")
	}
	return stanzas
}
