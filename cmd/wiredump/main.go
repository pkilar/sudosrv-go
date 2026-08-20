// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/wiredump/main.go

// Command wiredump decodes a sudosrv wire-format file and prints what it
// contains: one line per message with the delay the CLIENT recorded, a running
// total, the message kind and the payload size.
//
// It reads the framing used by logsh's journals and by internal/relay's cache —
// a 4-byte big-endian length followed by a protobuf ClientMessage. Point it at
// any of them:
//
//	{journal_directory}/logsh-*.journal          and the parked .undelivered,
//	                                             .incomplete, .corrupt, .rejected
//	{relay_cache_directory}/{uuid}.log           and .flushing, .incomplete
//
// The delays it prints are the ones the client computed, before any server ever
// saw them, which is what makes it the tool for answering "did the client
// record this timeline wrongly, or did something downstream change it?" A
// replay that pauses where the session did not will show the offending delay
// here, attached to the message that carries it.
//
// It decodes with logsrvclient.ReadMessage — the same reader the flush path
// uses — deliberately, so a file this tool reports as intact cannot be one the
// real code chokes on, and vice versa.
//
// PRIVACY. -content prints the first bytes of each buffer, which is session
// content. A journal is written by the client, so it has NOT been through the
// server's password filter: ttyin may hold a password that would have been
// masked in the finished I/O log. Use -content=false when that matters.
//
// Exit status is 0 for a file that decodes cleanly to its end, 1 for one that
// is truncated, oversized or malformed, and 2 for a usage or I/O error.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"sudosrv/internal/logsrvclient"
	pb "sudosrv/pkg/sudosrv_proto"
)

// previewBytes is how much of each buffer -content shows. Enough to tell a
// prompt from command output from a keystroke echo, which is what the tool is
// for, without reproducing the session.
const previewBytes = 46

func duration(ts *pb.TimeSpec) time.Duration {
	return time.Duration(ts.GetTvSec())*time.Second + time.Duration(ts.GetTvNsec())*time.Nanosecond
}

// preview renders bytes on one line. Escapes are shown as <ESC> because
// recognising them is most of reading a terminal transcript; everything else
// unprintable becomes '.' so the column cannot be broken by the data.
func preview(b []byte) string {
	if len(b) > previewBytes {
		b = b[:previewBytes]
	}
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == 0x1b:
			sb.WriteString("<ESC>")
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c < 0x20 || c > 0x7e:
			sb.WriteByte('.')
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// describe reduces one message to the kind, delay, payload size and a preview.
//
// isContent distinguishes a preview that is SESSION DATA from one that is
// metadata. Only the I/O buffers carry what the user typed and saw; the accept
// summary, the exit status and the window size are what identify a session and
// are the most useful thing on the line. Suppressing those along with the
// buffers would make -content=false a way to hide the structure rather than
// the content.
func describe(msg *pb.ClientMessage) (kind string, delay time.Duration, size int, prev string, isContent bool) {
	buf := func(b *pb.IoBuffer) (time.Duration, int, string, bool) {
		return duration(b.GetDelay()), len(b.GetData()), preview(b.GetData()), true
	}
	switch m := msg.Type.(type) {
	case *pb.ClientMessage_AcceptMsg:
		info := map[string]string{}
		for _, i := range m.AcceptMsg.GetInfoMsgs() {
			switch v := i.Value.(type) {
			case *pb.InfoMessage_Strval:
				info[i.GetKey()] = v.Strval
			case *pb.InfoMessage_Numval:
				info[i.GetKey()] = strconv.FormatInt(v.Numval, 10)
			}
		}
		return "accept", 0, 0, fmt.Sprintf(
			"command=%q ttyname=%s lines=%s cols=%s expect_iobufs=%v",
			info["command"], info["ttyname"], info["lines"], info["columns"],
			m.AcceptMsg.GetExpectIobufs()), false
	case *pb.ClientMessage_TtyoutBuf:
		d, n, p, c := buf(m.TtyoutBuf)
		return "ttyout", d, n, p, c
	case *pb.ClientMessage_TtyinBuf:
		d, n, p, c := buf(m.TtyinBuf)
		return "ttyin", d, n, p, c
	case *pb.ClientMessage_StdoutBuf:
		d, n, p, c := buf(m.StdoutBuf)
		return "stdout", d, n, p, c
	case *pb.ClientMessage_StderrBuf:
		d, n, p, c := buf(m.StderrBuf)
		return "stderr", d, n, p, c
	case *pb.ClientMessage_StdinBuf:
		d, n, p, c := buf(m.StdinBuf)
		return "stdin", d, n, p, c
	case *pb.ClientMessage_WinsizeEvent:
		e := m.WinsizeEvent
		return "winsize", duration(e.GetDelay()), 0,
			fmt.Sprintf("%dx%d", e.GetRows(), e.GetCols()), false
	case *pb.ClientMessage_SuspendEvent:
		e := m.SuspendEvent
		return "suspend", duration(e.GetDelay()), 0, e.GetSignal(), false
	case *pb.ClientMessage_ExitMsg:
		e := m.ExitMsg
		return "exit", 0, 0, fmt.Sprintf("exit_value=%d signal=%q run_time=%v",
			e.GetExitValue(), e.GetSignal(), duration(e.GetRunTime())), false
	case *pb.ClientMessage_RestartMsg:
		return "restart", 0, 0, m.RestartMsg.GetLogId(), false
	case *pb.ClientMessage_AlertMsg:
		return "alert", 0, 0, m.AlertMsg.GetReason(), false
	default:
		return fmt.Sprintf("%T", m), 0, 0, "", false
	}
}

// gapThreshold is the delay at or above which a message is called out in the
// summary. A replay pause a viewer notices is at least this long, and listing
// them turns "the recording stalls somewhere" into a specific message.
const gapThreshold = time.Second

type result struct {
	messages int
	total    time.Duration
	gaps     []string
	// err is set when the file did not decode cleanly to its end. A truncated
	// journal is the normal shape of a session interrupted mid-write, so this
	// is reported rather than treated as a crash -- but it is never silent.
	err error
}

// Write errors are deliberately not checked per call. main writes through a
// bufio.Writer, which latches its first error, turns later writes into no-ops
// and returns that error from Flush -- which main does check, and exits 2 on.
// Tests write to a bytes.Buffer, which cannot fail. Checking each call would
// add a branch per line that no caller can reach.
func dump(r io.Reader, w io.Writer, showContent bool) result {
	var res result
	_, _ = fmt.Fprintf(w, "%5s %10s %12s %-9s %7s  %s\n",
		"#", "delay", "cumulative", "kind", "bytes", "preview")

	for {
		msg, err := logsrvclient.ReadMessage(r)
		if err != nil {
			// io.EOF at a message boundary is the clean end of the file.
			// Anything else -- a partial length, a partial body, an oversized
			// length, bad protobuf -- means the rest of the file is not
			// recoverable, so stop and say why.
			if !errors.Is(err, io.EOF) {
				res.err = fmt.Errorf("after %d messages: %w", res.messages, err)
			}
			break
		}
		res.messages++

		kind, delay, size, prev, isContent := describe(msg)
		res.total += delay
		if delay >= gapThreshold {
			res.gaps = append(res.gaps, fmt.Sprintf("#%d %s after %.3fs -> %s",
				res.messages, kind, delay.Seconds(), prev))
		}
		if isContent && !showContent {
			prev = ""
		}
		_, _ = fmt.Fprintf(w, "%5d %10.3f %12.3f %-9s %7d  %s\n",
			res.messages, delay.Seconds(), res.total.Seconds(), kind, size, prev)
	}

	_, _ = fmt.Fprintf(w, "\n%d messages, total client-recorded time %.3fs\n",
		res.messages, res.total.Seconds())
	if len(res.gaps) == 0 {
		_, _ = fmt.Fprintf(w, "no single delay >= %v\n", gapThreshold)
	} else {
		_, _ = fmt.Fprintf(w, "%d delays >= %v:\n", len(res.gaps), gapThreshold)
		for _, g := range res.gaps {
			_, _ = fmt.Fprintf(w, "  %s\n", g)
		}
	}
	if res.err != nil {
		_, _ = fmt.Fprintf(w, "\nfile does not decode to its end: %v\n", res.err)
	}
	return res
}

func main() {
	showContent := flag.Bool("content", true,
		"show a short preview of each I/O buffer; this is session content, and "+
			"a journal has not been through the server's password filter. "+
			"Message metadata is shown either way")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"usage: wiredump [-content=false] <journal-or-cache-file>\n\n"+
				"Decodes a logsh journal or relay cache file and prints the delay,\n"+
				"kind and size of every message it holds.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	os.Exit(run(flag.Arg(0), *showContent))
}

// run holds everything after flag parsing so its deferred close actually runs.
// os.Exit does not unwind defers, so calling it from main alongside a
// `defer f.Close()` reads as if the file is released when it never is.
func run(path string, showContent bool) int {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wiredump:", err)
		return 2
	}
	defer f.Close()

	out := bufio.NewWriter(os.Stdout)
	res := dump(bufio.NewReader(f), out, showContent)
	if err := out.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, "wiredump:", err)
		return 2
	}
	if res.err != nil {
		return 1
	}
	return 0
}
