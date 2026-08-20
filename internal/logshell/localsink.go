// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/localsink.go
package logshell

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sudosrv/internal/config"
	"sudosrv/internal/logsrvclient"
	"sudosrv/internal/storage"
	pb "sudosrv/pkg/sudosrv_proto"

	"uuid"
)

// localSink writes a session straight to a sudoreplay-compatible directory on
// this host, with no log server involved.
//
// It is the standalone recorder behind `logsh -record`: the session lands as
// the same file set the daemon would have written -- log, log.json, timing and
// the I/O streams -- so anything that already consumes sudo I/O logs consumes
// these unchanged.
//
// It is built on internal/storage rather than writing the files itself, which
// is the whole point. That package is what the server uses, it is the code the
// conformance work in docs/logsrvd-reference is written against, and the timing
// format, the log.json field set, the path escapes and the password filter all
// come with it. A second implementation would be a second thing to keep
// correct, and the first divergence would be silent.
//
// NOT an audit path. A local recording is written by the user being recorded,
// as that user, so they can edit or delete it. That is fine for its purpose --
// capturing a session to replay or turn into a video -- and unacceptable for
// accountability, which is why Config.RecordDir cannot be set from a
// configuration file. See its declaration.
type localSink struct {
	cfg     *config.LocalStorageConfig
	dir     string
	session *storage.Session

	// wire is the optional raw copy: every message, in the framing a server
	// would have received, written beside the I/O log. wireErr latches the
	// first write failure -- once framing is broken by a short write the rest
	// of the file is unreadable, so there is nothing to gain by continuing, and
	// Finish reports it rather than leaving a truncated file to be discovered
	// by whoever reads it next.
	wire     *os.File
	wirePath string
	wireErr  error
}

// WireFileName is the raw copy's name inside the recording directory. Fixed
// rather than derived, so a capture is one predictable path for the caller to
// hand to cmd/wiredump. It sits inside the I/O log directory deliberately:
// sudoreplay reads specific filenames and ignores anything else there, so the
// two forms travel together as one artefact.
const WireFileName = "session.wire"

// newLocalSink prepares a sink that will write into dir.
//
// dir is the SESSION directory -- the one that ends up holding log, timing and
// ttyout -- not a root to search. The caller names it, so it can tell the user
// where the recording went before the session starts rather than hunting for it
// afterwards.
func newLocalSink(dir string, alsoWire bool) (*localSink, error) {
	if dir == "" {
		return nil, fmt.Errorf("no record directory given")
	}
	_, name, err := splitSessionDir(dir)
	if err != nil {
		return nil, err
	}
	// Created up front so the sequence file below has somewhere to go, and so
	// an unwritable path fails here -- before a shell is started -- rather than
	// after the user has typed into a session that turns out not to be recorded.
	if err := os.MkdirAll(dir, localRecordDirMode); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", dir, err)
	}
	dir = filepath.Clean(abs)

	var wire *os.File
	var wirePath string
	if alsoWire {
		wirePath = filepath.Join(dir, WireFileName)
		// O_EXCL: the caller already refuses a directory holding a recording,
		// and this is the same refusal one level down -- appending to an
		// existing wire file would splice two sessions into one stream that
		// decodes without complaint and describes neither.
		wire, err = os.OpenFile(wirePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, localRecordMode)
		if err != nil {
			return nil, fmt.Errorf("creating %s: %w", wirePath, err)
		}
	}

	return &localSink{
		dir:      dir,
		wire:     wire,
		wirePath: wirePath,
		cfg: &config.LocalStorageConfig{
			// IologDir and IologFile together are the session path. They are
			// taken literally, which splitSessionDir guarantees by refusing a
			// path containing '%' -- see the reason there.
			//
			// LogDirectory is where storage keeps its sequence file. Nothing
			// here uses %{seq}, but buildSessionPath allocates one regardless,
			// so a `seq` file is going to be written somewhere -- and it points
			// at the recording directory rather than its parent so that it
			// lands INSIDE the capture. Pointing it at the parent drops a stray
			// `seq` into whatever directory the user happened to record into,
			// which for `logsh -record ~/demo` means their home directory.
			LogDirectory: dir,
			IologDir:     filepath.Dir(dir),
			IologFile:    name,
			IologMode:    localRecordMode,
			// Compression is off: these files exist to be fed to a replay or a
			// converter, and a gzipped stream is one more thing for that tool to
			// have to handle.
			Compress: false,
			// On, matching the server's default, and with the built-in pattern
			// set (an empty PassPromptRegex means "use the defaults"). A local
			// recording is still a recording of a terminal, and a password
			// prompt in it is still a password prompt -- a demo capture that
			// immortalises a sudo password would be a poor trade for the
			// convenience of not filtering.
			PasswordFilter: true,
		},
	}, nil
}

// splitSessionDir turns the requested session directory into the parent and
// name storage.buildSessionPath wants, after making it absolute so the path
// reported back to the user is unambiguous.
//
// A '%' anywhere in the path is refused rather than escaped. The expansion in
// buildSessionPath runs %{...} substitution first and strftime second, so the
// obvious escape -- doubling '%' -- does not survive contact with a name like
// "run%{user}": doubling gives "run%%{user}", which still contains the literal
// "%{user}" the substituter looks for. Refusing is the honest answer, and a
// recording directory has no need of one.
func splitSessionDir(dir string) (parent, name string, err error) {
	if strings.Contains(dir, "%") {
		return "", "", fmt.Errorf("record directory %q contains '%%', which the "+
			"I/O log path expansion would interpret; choose a name without it", dir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", fmt.Errorf("resolving %s: %w", dir, err)
	}
	abs = filepath.Clean(abs)
	parent, name = filepath.Split(abs)
	name = strings.TrimSuffix(name, string(filepath.Separator))
	parent = filepath.Clean(parent)
	if name == "" || name == "." || parent == abs {
		return "", "", fmt.Errorf("record directory %q has no name to write into", dir)
	}
	return parent, name, nil
}

// localRecordMode is the permission seed for a standalone recording. 0600 gives
// files 0600 and the directory 0700 once config.DeriveIologModes has run, which
// is the right default for something written into a user's own directory.
const localRecordMode = 0o600

// localRecordDirMode is the mode the recording directory is created with. It
// matches what DeriveIologModes produces from localRecordMode, so the directory
// storage later writes into is not widened or narrowed by having been made
// here first.
const localRecordDirMode = 0o700

// tap writes one message to the raw copy, if there is one.
//
// The tap runs BEFORE the message reaches storage, so the wire file holds what
// the client produced even for a message the I/O log then rejects. That is the
// point of keeping it: it is the record of what was sent, not of what was
// successfully stored.
func (l *localSink) tap(msg *pb.ClientMessage) {
	if l.wire == nil || l.wireErr != nil {
		return
	}
	if err := logsrvclient.WriteMessage(l.wire, msg); err != nil {
		l.wireErr = fmt.Errorf("writing %s: %w", l.wirePath, err)
	}
}

func (l *localSink) Start(_ context.Context, accept *pb.ClientMessage) (string, error) {
	msg := accept.GetAcceptMsg()
	if msg == nil {
		return "", fmt.Errorf("first message is not an AcceptMessage")
	}
	l.tap(accept)
	session, err := storage.NewSession(uuid.NewV4(), msg, l.cfg)
	if err != nil {
		return "", fmt.Errorf("creating the recording in %s: %w", l.dir, err)
	}
	l.session = session
	if _, err := session.HandleClientMessage(accept); err != nil {
		_ = session.Close()
		l.session = nil
		return "", fmt.Errorf("writing the session metadata: %w", err)
	}
	return session.LogID(), nil
}

func (l *localSink) Send(msg *pb.ClientMessage) error {
	if l.session == nil {
		return fmt.Errorf("recording was never started")
	}
	l.tap(msg)
	// The ServerMessage a real server would return here is a commit point, and
	// there is nobody to send it to: the bytes are already on this disk, which
	// is what a commit point would have been promising.
	_, err := l.session.HandleClientMessage(msg)
	return err
}

// Finish has nothing to wait for. Durability is not a round trip here -- every
// buffer was written as it arrived -- so unlike the streaming and journal sinks
// there is no acknowledgement to block on.
//
// It does report a failed raw copy. Returning the error costs the caller
// nothing it needs: RunRecorded keeps the shell's exit status and reports the
// failure separately, so the user still gets their exit code and still gets
// told that the wire file beside their intact I/O log is incomplete.
func (l *localSink) Finish(context.Context, time.Duration) error { return l.wireErr }

// Close finalises the session: storage.Session closes the stream files and
// chmods timing read-only, which is what marks a recording complete.
func (l *localSink) Close() error {
	if l.wire != nil {
		if err := l.wire.Close(); err != nil && l.wireErr == nil {
			l.wireErr = fmt.Errorf("closing %s: %w", l.wirePath, err)
		}
		l.wire = nil
	}
	if l.session == nil {
		return l.wireErr
	}
	err := l.session.Close()
	l.session = nil
	if err != nil {
		return err
	}
	return l.wireErr
}

// Dir is where the recording was written.
func (l *localSink) Dir() string { return l.dir }
