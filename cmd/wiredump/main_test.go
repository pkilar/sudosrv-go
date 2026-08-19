// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/wiredump/main_test.go
package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"sudosrv/internal/logsrvclient"
	pb "sudosrv/pkg/sudosrv_proto"
)

func spec(d time.Duration) *pb.TimeSpec {
	return &pb.TimeSpec{TvSec: int64(d / time.Second), TvNsec: int32(d % time.Second)}
}

func ttyout(d time.Duration, data string) *pb.ClientMessage {
	return &pb.ClientMessage{Type: &pb.ClientMessage_TtyoutBuf{
		TtyoutBuf: &pb.IoBuffer{Delay: spec(d), Data: []byte(data)},
	}}
}

// journal writes messages in the same framing the client uses, so these tests
// exercise the real reader rather than a stand-in for it.
func journal(t *testing.T, msgs ...*pb.ClientMessage) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	for _, m := range msgs {
		if err := logsrvclient.WriteMessage(&buf, m); err != nil {
			t.Fatal(err)
		}
	}
	return &buf
}

// TestDumpReportsDelaysAndTotal is the tool's whole purpose: the delays it
// prints must be the ones in the file. A dumper that quietly rounded, dropped
// or re-derived a delay would send someone debugging a timing complaint in
// exactly the wrong direction.
func TestDumpReportsDelaysAndTotal(t *testing.T) {
	in := journal(t,
		ttyout(0, "prompt"),
		ttyout(2500*time.Millisecond, "l"),
		ttyout(9*time.Millisecond, "total 4"),
	)
	var out bytes.Buffer
	res := dump(in, &out, true)

	if res.err != nil {
		t.Fatalf("clean journal reported an error: %v", res.err)
	}
	if res.messages != 3 {
		t.Errorf("messages = %d, want 3", res.messages)
	}
	if want := 2509 * time.Millisecond; res.total != want {
		t.Errorf("total = %v, want %v", res.total, want)
	}
	if !strings.Contains(out.String(), "2.500") {
		t.Errorf("the 2.5s delay is not in the output:\n%s", out.String())
	}
}

// TestDumpFlagsLongDelays covers the summary a reader actually acts on: which
// message carries the pause.
func TestDumpFlagsLongDelays(t *testing.T) {
	in := journal(t,
		ttyout(0, "prompt"),
		ttyout(3*time.Second, "l"),
		ttyout(5*time.Millisecond, "output"),
	)
	res := dump(in, &bytes.Buffer{}, true)

	if len(res.gaps) != 1 {
		t.Fatalf("gaps = %v, want exactly the one 3s delay", res.gaps)
	}
	if !strings.Contains(res.gaps[0], "#2") || !strings.Contains(res.gaps[0], "3.000") {
		t.Errorf("gap does not name the message and its delay: %q", res.gaps[0])
	}
	// The short delay must not be listed: a summary that flags everything
	// flags nothing.
	if strings.Contains(strings.Join(res.gaps, " "), "#3") {
		t.Errorf("a 5ms delay was reported as a gap: %v", res.gaps)
	}
}

// TestDumpReportsATruncatedFile matters more than it looks. A journal cut off
// mid-write is the normal shape of an interrupted session, and it is exactly
// the file someone runs this on. Reporting it as a clean read would claim the
// session ended where the file stops.
func TestDumpReportsATruncatedFile(t *testing.T) {
	full := journal(t, ttyout(0, "prompt"), ttyout(time.Second, "output"))
	cut := full.Bytes()[:full.Len()-4] // lose the tail of the last message

	res := dump(bytes.NewReader(cut), &bytes.Buffer{}, true)
	if res.err == nil {
		t.Fatal("a truncated journal decoded without error")
	}
	if res.messages != 1 {
		t.Errorf("messages = %d, want the 1 that was intact", res.messages)
	}
}

// TestDumpRejectsAnOversizedLength guards the property that makes this safe to
// point at a corrupt file: the length prefix is attacker- or corruption-
// controlled, so it must be bounded before it becomes an allocation. Reusing
// logsrvclient.ReadMessage is what provides that, and this fails if the tool
// ever grows its own framing loop without the check.
func TestDumpRejectsAnOversizedLength(t *testing.T) {
	// 0xFFFFFFFF bytes claimed, nothing following.
	res := dump(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff}), &bytes.Buffer{}, true)
	if res.err == nil {
		t.Fatal("an oversized length prefix was accepted")
	}
	if !strings.Contains(res.err.Error(), "exceeds limit") {
		t.Errorf("error does not name the size limit: %v", res.err)
	}
}

// TestDumpContentFlagSuppressesSessionData covers the privacy switch. A journal
// is written before the server's password filter runs, so ttyin can hold a
// secret that never reaches the finished I/O log.
func TestDumpContentFlagSuppressesSessionData(t *testing.T) {
	const secret = "hunter2"
	in := journal(t, &pb.ClientMessage{Type: &pb.ClientMessage_TtyinBuf{
		TtyinBuf: &pb.IoBuffer{Delay: spec(0), Data: []byte(secret)},
	}})

	var out bytes.Buffer
	dump(in, &out, false)
	if strings.Contains(out.String(), secret) {
		t.Errorf("-content=false still printed the buffer:\n%s", out.String())
	}
	// And the line itself must still be there, or the flag would be a way to
	// hide messages rather than their contents.
	if !strings.Contains(out.String(), "ttyin") {
		t.Errorf("-content=false dropped the message entirely:\n%s", out.String())
	}
}

// TestDumpContentFlagKeepsMetadata is the other half of that switch. The accept
// summary names the command and the terminal, which is what identifies a
// session; suppressing it along with the buffers would leave someone unable to
// tell which recording they are looking at, for no privacy gain -- it is not
// session content.
func TestDumpContentFlagKeepsMetadata(t *testing.T) {
	in := journal(t,
		&pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
			ExpectIobufs: true,
			InfoMsgs: []*pb.InfoMessage{
				{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/zsh"}},
				{Key: "ttyname", Value: &pb.InfoMessage_Strval{Strval: "/dev/pts/8"}},
			},
		}}},
		&pb.ClientMessage{Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 3}}},
	)

	var out bytes.Buffer
	dump(in, &out, false)
	for _, want := range []string{"/bin/zsh", "/dev/pts/8", "exit_value=3"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("-content=false suppressed metadata %q:\n%s", want, out.String())
		}
	}
}
