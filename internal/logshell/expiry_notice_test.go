// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
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
	stop := startExpiryNotice(deadline, &out, DefaultConfig())
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

func TestExpiryNoticeSkipsElapsedReminders(t *testing.T) {
	var out expiryNoticeBuffer
	stop := startExpiryNotice(time.Now().Add(30*time.Second), &out, DefaultConfig())
	defer stop()
	stop()
	if got := out.String(); strings.Contains(strings.ToLower(got), "warning") || !strings.Contains(got, "Expiration:") {
		t.Fatalf("notice = %q, want startup banner without elapsed reminders", got)
	}
}

func TestExpiryNoticeConfiguredThresholds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out expiryNoticeBuffer
		cfg := DefaultConfig()
		// Input order must not change chronological delivery.
		cfg.SessionExpirationReminders = "1m,1h,5m,15m"
		stop := startExpiryNotice(time.Now().Add(2*time.Hour), &out, cfg)
		defer stop()
		synctest.Wait()
		for i, advance := range []time.Duration{time.Hour, 45 * time.Minute, 10 * time.Minute, 4 * time.Minute} {
			time.Sleep(advance - time.Nanosecond)
			synctest.Wait()
			if got := strings.Count(out.String(), "WARNING:"); got != i {
				t.Fatalf("before threshold %d: got %d reminders", i, got)
			}
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			if got := strings.Count(out.String(), "WARNING:"); got != i+1 {
				t.Fatalf("at threshold %d: got %d reminders", i, got)
			}
		}
		stop()
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if got := strings.Count(out.String(), "WARNING:"); got != 4 {
			t.Fatalf("got %d reminders, want exactly four", got)
		}
	})
}

func TestExpiryNoticeRemindersDisabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out expiryNoticeBuffer
		cfg := DefaultConfig()
		cfg.SessionExpirationReminders = ""
		stop := startExpiryNotice(time.Now().Add(2*time.Hour), &out, cfg)
		defer stop()
		time.Sleep(3 * time.Hour)
		synctest.Wait()
		if got := out.String(); !strings.Contains(got, "Expiration:") || strings.Contains(got, "WARNING:") {
			t.Fatalf("notice = %q, want only the startup banner", got)
		}
	})
}

func TestExpiryNoticeTimezone(t *testing.T) {
	previous := time.Local
	time.Local = time.FixedZone("SERVER", -7*60*60)
	t.Cleanup(func() { time.Local = previous })
	deadline := time.Now().Add(2 * time.Hour)
	for _, zone := range []string{"UTC", "local"} {
		cfg := DefaultConfig()
		cfg.SessionExpirationTimezone = zone
		cfg.SessionExpirationReminders = ""
		var out expiryNoticeBuffer
		stop := startExpiryNotice(deadline, &out, cfg)
		stop()
		want := deadline.UTC().Format("2006-01-02 15:04:05 UTC")
		if zone == "local" {
			want = deadline.In(time.Local).Format("2006-01-02 15:04:05 SERVER (UTC-07:00)")
		}
		if got := out.String(); !strings.Contains(got, want) {
			t.Errorf("timezone %s: notice = %q, want %q", zone, got, want)
		}
	}
}

func TestExpiryNoticeDisabledAndExpired(t *testing.T) {
	for _, deadline := range []time.Time{{}, time.Now().Add(-time.Second)} {
		var out expiryNoticeBuffer
		stop := startExpiryNotice(deadline, &out, DefaultConfig())
		stop()
		if got := out.String(); got != "" {
			t.Fatalf("deadline %v produced notice %q", deadline, got)
		}
	}
}

func TestExpiryNoticeStopCancelsWarning(t *testing.T) {
	var out expiryNoticeBuffer
	stop := startExpiryNotice(time.Now().Add(time.Minute+80*time.Millisecond), &out, DefaultConfig())
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
	stop := startExpiryNotice(time.Now().Add(2*time.Minute), w, DefaultConfig())
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
			spec := RunSpec{Config: testConfig(newMockServer(t).addr), ShellPath: "/bin/sh", EnvShell: "/bin/sh",
				Invocation: Invocation{Args: []string{"-c", "printf payload"}},
				Std:        StdIO{In: slave, Out: w, Err: w}, ExpiryDeadline: time.Now().Add(2 * time.Minute)}
			wantNotice := spec.ExpiryDeadline.UTC().Format("2006-01-02 15:04:05 UTC")
			notice := make(chan string, 1)
			stopReader := make(chan struct{})
			readerDone := make(chan struct{})
			fd := int(outer.Master.Fd())
			go func() {
				defer close(readerDone)
				var received strings.Builder
				defer func() { notice <- received.String() }()
				buf := make([]byte, 4096)
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				limit := time.Now().Add(2 * time.Second)
				for time.Now().Before(limit) {
					select {
					case <-stopReader:
						return
					default:
					}
					// PTY reads can split a notice at any byte. Poll in short
					// intervals so cleanup can join the reader before the helper
					// closes its terminal descriptors, even when no data arrives.
					n, err := unix.Poll(poll, 50)
					if errors.Is(err, unix.EINTR) {
						continue
					}
					if err != nil {
						return
					}
					if n == 0 {
						continue
					}
					n, err = unix.Read(fd, buf)
					if errors.Is(err, unix.EINTR) {
						continue
					}
					if n > 0 {
						_, _ = received.Write(buf[:n])
					}
					if strings.Contains(received.String(), wantNotice) || err != nil || n == 0 {
						return
					}
				}
			}()
			t.Cleanup(func() { close(stopReader); <-readerDone })
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
				if !strings.Contains(got, wantNotice) {
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
