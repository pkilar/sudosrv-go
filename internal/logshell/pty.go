// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/pty.go
package logshell

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// The pseudo-terminal and termios primitives logsh needs, built on the stdlib
// syscall package rather than golang.org/x/sys.
//
// syscall carries every constant used here for both architectures this project
// ships (linux/amd64 and linux/arm64), and the module deliberately keeps its
// dependency list to three. syscall.Flock is already used the same way in
// internal/storage, so this is the established shape for this tree rather than a
// new one.

// ioctlPtr issues an ioctl whose argument is a pointer.
//
// The unsafe.Pointer is converted to uintptr inside the Syscall call expression,
// which is the one form the unsafe.Pointer rules permit: anywhere else the
// garbage collector could move or free the pointee between the conversion and
// the call.
func ioctlPtr(fd, req uintptr, p unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(p)); errno != 0 {
		return errno
	}
	return nil
}

// PTY is an allocated pseudo-terminal pair. Master is this process's end; Name
// is the slave device the child will use as its controlling terminal.
type PTY struct {
	Master *os.File
	Name   string
}

// OpenPTY allocates a new pseudo-terminal pair.
//
// O_NOCTTY on the master matters: without it, a logsh that somehow had no
// controlling terminal would acquire the INNER pty as its own, and the signals
// the inner tty driver generates for the child would be delivered to the
// recorder as well.
func OpenPTY() (*PTY, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}

	var unlock int32 // 0 == unlocked
	if err := ioctlPtr(master.Fd(), syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		_ = master.Close()
		return nil, fmt.Errorf("unlockpt: %w", err)
	}

	var n uint32
	if err := ioctlPtr(master.Fd(), syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		_ = master.Close()
		return nil, fmt.Errorf("ptsname: %w", err)
	}

	return &PTY{Master: master, Name: fmt.Sprintf("/dev/pts/%d", n)}, nil
}

// OpenSlave opens the slave end. The caller must close it after starting the
// child: while any descriptor for the slave remains open in THIS process,
// reading the master never reports EOF, so the relay would hang forever after
// the shell exits instead of finishing the session.
func (p *PTY) OpenSlave() (*os.File, error) {
	f, err := os.OpenFile(p.Name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", p.Name, err)
	}
	return f, nil
}

func (p *PTY) Close() error { return p.Master.Close() }

// GetTermios reads a descriptor's terminal attributes.
func GetTermios(fd uintptr) (*syscall.Termios, error) {
	var t syscall.Termios
	if err := ioctlPtr(fd, syscall.TCGETS, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	return &t, nil
}

// SetTermios writes a descriptor's terminal attributes.
func SetTermios(fd uintptr, t *syscall.Termios) error {
	return ioctlPtr(fd, syscall.TCSETS, unsafe.Pointer(t))
}

// MakeRaw puts a descriptor into raw mode and returns the previous settings so
// the caller can restore them.
//
// This is cfmakeraw. It is what lets the recorder relay bytes without the outer
// terminal interpreting any of them: no echo, no line editing, no signal
// generation, no CR/LF translation. Every one of those jobs still happens, but
// on the INNER pty, where the shell expects them.
//
// KNOWN SECURITY REGRESSION, inherent to every second-pty recorder including
// script(1), tlog and sudo: sshd emits SSH_MSG_IGNORE padding to blunt
// keystroke-timing traffic analysis, but only while the pty has ECHO off AND
// ICANON on (channels.c:2339-2352). Raw mode clears both, so that countermeasure
// silently stops firing for the whole session. There is no recorder-level fix --
// restoring ICANON would line-buffer the relay and destroy interactive use.
func MakeRaw(fd uintptr) (*syscall.Termios, error) {
	prev, err := GetTermios(fd)
	if err != nil {
		return nil, err
	}

	raw := *prev
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	// Block until at least one byte is available, with no inter-byte timer:
	// a read returns as soon as the user types, which is what keeps an
	// interactive session feeling direct.
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0

	if err := SetTermios(fd, &raw); err != nil {
		return nil, err
	}
	return prev, nil
}

// WinSize is a terminal's dimensions.
type WinSize struct {
	Rows, Cols uint16
}

// winsize mirrors struct winsize. The pixel fields are unused but must be
// present: the ioctl reads and writes the whole structure.
type winsize struct {
	rows, cols, xpixel, ypixel uint16
}

// GetWinSize reads a terminal's dimensions.
func GetWinSize(fd uintptr) (WinSize, error) {
	var ws winsize
	if err := ioctlPtr(fd, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return WinSize{}, err
	}
	return WinSize{Rows: ws.rows, Cols: ws.cols}, nil
}

// SetWinSize sets a terminal's dimensions.
//
// Propagating this to the inner pty on every SIGWINCH is not cosmetic. The
// shell and everything it runs ask the INNER terminal how big it is, so without
// it full-screen programs -- vim, top, less -- render against stale dimensions
// and the recorded transcript replays as corrupt.
func SetWinSize(fd uintptr, s WinSize) error {
	ws := winsize{rows: s.Rows, cols: s.Cols}
	return ioctlPtr(fd, syscall.TIOCSWINSZ, unsafe.Pointer(&ws))
}

// IsTerminal reports whether fd refers to a terminal.
//
// This is the gate that decides whether a session is recorded as an interactive
// transcript or as a metadata-only record -- and it is deliberately NOT a test
// for the presence of "-c". `ssh -t host /bin/bash` passes a command AND
// allocates a pty; keying off "-c" would classify it as non-interactive and hand
// the user a fully interactive, entirely unrecorded shell.
func IsTerminal(fd uintptr) bool {
	_, err := GetTermios(fd)
	return err == nil
}
