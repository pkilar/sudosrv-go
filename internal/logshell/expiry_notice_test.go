// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type expiryNoticeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *expiryNoticeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *expiryNoticeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestExpiryRemainingRoundsUp(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{-time.Second, "0s"},
		{time.Nanosecond, "1s"},
		{time.Minute, "1m"},
		{time.Minute + time.Nanosecond, "1m 1s"},
		{time.Hour, "1h"},
		{time.Hour + time.Minute + time.Nanosecond, "1h 1m 1s"},
	} {
		if got := expiryRemaining(tc.d); got != tc.want {
			t.Errorf("expiryRemaining(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestExpiryNoticeStartupAndWarning(t *testing.T) {
	var out expiryNoticeBuffer
	deadline := time.Now().Add(time.Minute + 100*time.Millisecond)
	stop := startExpiryNotice(deadline, &out)
	defer stop()
	startup := out.String()
	if !strings.Contains(startup, deadline.UTC().Format("2006-01-02 15:04:05 UTC")) || !strings.Contains(startup, "1m 1s") {
		t.Fatalf("startup notice = %q, want UTC expiry and rounded-up remaining time", startup)
	}
	if strings.Contains(strings.ToLower(startup), "warning") {
		t.Fatalf("warning arrived before the last minute: %q", startup)
	}
	limit := time.Now().Add(2 * time.Second)
	for !strings.Contains(strings.ToLower(out.String()), "warning") && time.Now().Before(limit) {
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	if got := out.String(); strings.Count(strings.ToLower(got), "warning") != 1 {
		t.Fatalf("notice = %q, want exactly one last-minute warning", got)
	}
}

func TestExpiryNoticeImmediateWarning(t *testing.T) {
	var out expiryNoticeBuffer
	stop := startExpiryNotice(time.Now().Add(30*time.Second), &out)
	defer stop()
	limit := time.Now().Add(time.Second)
	for !strings.Contains(strings.ToLower(out.String()), "warning") && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	stop()
	if got := out.String(); strings.Count(strings.ToLower(got), "warning") != 1 {
		t.Fatalf("notice = %q, want immediate last-minute warning", got)
	}
}

func TestExpiryNoticeDisabledAndExpired(t *testing.T) {
	for _, deadline := range []time.Time{{}, time.Now().Add(-time.Second)} {
		var out expiryNoticeBuffer
		stop := startExpiryNotice(deadline, &out)
		stop()
		if got := out.String(); got != "" {
			t.Fatalf("deadline %v produced notice %q", deadline, got)
		}
	}
}

func TestExpiryNoticeStopCancelsWarning(t *testing.T) {
	var out expiryNoticeBuffer
	stop := startExpiryNotice(time.Now().Add(time.Minute+80*time.Millisecond), &out)
	stop()
	before := out.String()
	time.Sleep(120 * time.Millisecond)
	stop() // Cleanup is safe more than once.
	if after := out.String(); after != before {
		t.Fatalf("notice changed after stop: before %q, after %q", before, after)
	}
}

func TestExpiryNoticeStalledWriterIsBounded(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	raw, err := w.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fillErr error
	err = raw.Control(func(fd uintptr) {
		if fillErr = unix.SetNonblock(int(fd), true); fillErr != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			if _, fillErr = unix.Write(int(fd), buf); fillErr != nil {
				break
			}
		}
	})
	if err != nil || fillErr != unix.EAGAIN {
		t.Fatalf("fill pipe: %v, %v", err, fillErr)
	}
	start := time.Now()
	stop := startExpiryNotice(time.Now().Add(2*time.Minute), w)
	stop()
	if time.Since(start) > 2*time.Second {
		t.Fatal("notice blocked on a client that stopped reading")
	}
}

func TestExpiryNoticeTerminalDoesNotCorruptStdout(t *testing.T) {
	for _, mode := range []string{"recorded", "unrecorded", "metadata"} {
		t.Run(mode, func(t *testing.T) {
			outer, slave := outerTerminal(t)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			data := make(chan string, 1)
			go func() { b, _ := io.ReadAll(r); data <- string(b) }()
			notice := make(chan string, 1)
			go func() { b := make([]byte, 4096); n, _ := outer.Master.Read(b); notice <- string(b[:n]) }()
			spec := RunSpec{Config: testConfig(newMockServer(t).addr), ShellPath: "/bin/sh", EnvShell: "/bin/sh",
				Invocation: Invocation{Args: []string{"-c", "printf payload"}},
				Std:        StdIO{In: slave, Out: w, Err: w}, ExpiryDeadline: time.Now().Add(2 * time.Minute)}
			var outcome Outcome
			switch mode {
			case "recorded":
				outcome, err = RunRecorded(t.Context(), spec, TerminalIO{In: slave, Out: w})
			case "unrecorded":
				outcome, err = RunUnrecorded(spec)
			case "metadata":
				outcome, err = RunMetadataOnly(t.Context(), spec, Nesting{Kind: NestedSudo})
			}
			if err != nil || outcome.ExitCode != 0 {
				t.Fatalf("outcome %+v, error %v", outcome, err)
			}
			_ = w.Close()
			if got := <-data; got != "payload" {
				t.Fatalf("stdout = %q, want payload", got)
			}
			select {
			case got := <-notice:
				if !strings.Contains(got, spec.ExpiryDeadline.UTC().Format("2006-01-02 15:04:05 UTC")) {
					t.Fatalf("terminal notice = %q", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("terminal received no expiry notice")
			}
		})
	}
}

func TestExpiryNoticeNonInteractivePipesRemainClean(t *testing.T) {
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	_ = inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()
	defer outW.Close()
	data := make(chan string, 1)
	go func() { b, _ := io.ReadAll(outR); data <- string(b) }()
	spec := RunSpec{Config: testConfig(newMockServer(t).addr), ShellPath: "/bin/sh", EnvShell: "/bin/sh",
		Invocation: Invocation{Args: []string{"-c", "printf payload; printf error >&2"}},
		Std:        StdIO{In: inR, Out: outW, Err: outW}, ExpiryDeadline: time.Now().Add(30 * time.Second)}
	outcome, err := RunNonInteractive(t.Context(), spec)
	if err != nil || outcome.ExitCode != 0 {
		t.Fatalf("outcome %+v, error %v", outcome, err)
	}
	_ = outW.Close()
	if got := <-data; got != "payloaderror" {
		t.Fatalf("pipe output = %q, want payloaderror", got)
	}
}
