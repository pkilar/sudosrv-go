// SPDX-License-Identifier: Apache-2.0
// Filename: internal/server/keepalive_linux_test.go

//go:build linux

package server

import (
	"context"
	"net"
	"syscall"
	"testing"
)

// systemKeepaliveDefaults reads the kernel's per-socket keepalive defaults from
// a freshly created, untouched TCP socket. These are the values sudo_logsrvd
// leaves in place, so they are what an accepted connection must carry.
func systemKeepaliveDefaults(t *testing.T) (idle, interval, count int) {
	t.Helper()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer func() {
		if cerr := syscall.Close(fd); cerr != nil {
			t.Errorf("close reference socket: %v", cerr)
		}
	}()

	if idle, err = syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE); err != nil {
		t.Fatalf("getsockopt TCP_KEEPIDLE: %v", err)
	}
	if interval, err = syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL); err != nil {
		t.Fatalf("getsockopt TCP_KEEPINTVL: %v", err)
	}
	if count, err = syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT); err != nil {
		t.Fatalf("getsockopt TCP_KEEPCNT: %v", err)
	}
	return idle, interval, count
}

// keepaliveState reports the keepalive socket options actually in effect on an
// accepted connection.
func keepaliveState(t *testing.T, conn net.Conn) (enabled, idle, interval, count int) {
	t.Helper()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("accepted connection is %T, want *net.TCPConn", conn)
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		if enabled, ctrlErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE); ctrlErr != nil {
			return
		}
		if idle, ctrlErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE); ctrlErr != nil {
			return
		}
		if interval, ctrlErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL); ctrlErr != nil {
			return
		}
		count, ctrlErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT)
	}); err != nil {
		t.Fatalf("raw.Control: %v", err)
	}
	if ctrlErr != nil {
		t.Fatalf("getsockopt on accepted connection: %v", ctrlErr)
	}
	return enabled, idle, interval, count
}

// TestAcceptedConnectionKeepaliveMatchesSystemDefaults pins ARCH-016: accepted
// client sockets must carry SO_KEEPALIVE with the *system's* idle/interval/count,
// exactly as sudo_logsrvd leaves them (logsrvd/logsrvd.c:1744-1750). Go's own
// defaults (15s idle, 15s interval, 9 probes) would declare a peer dead after
// ~150s and, because the sudo client treats a lost log connection as fatal, kill
// the user's command.
func TestAcceptedConnectionKeepaliveMatchesSystemDefaults(t *testing.T) {
	wantIdle, wantInterval, wantCount := systemKeepaliveDefaults(t)

	ln, err := listenTCP(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
	defer func() {
		if cerr := ln.Close(); cerr != nil {
			t.Errorf("close listener: %v", cerr)
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() {
		if cerr := client.Close(); cerr != nil {
			t.Errorf("close client: %v", cerr)
		}
	}()

	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() {
		if cerr := server.Close(); cerr != nil {
			t.Errorf("close server conn: %v", cerr)
		}
	}()

	enabled, idle, interval, count := keepaliveState(t, server)

	if enabled == 0 {
		t.Error("SO_KEEPALIVE is not set on the accepted socket; sudo_logsrvd always sets it")
	}
	if idle != wantIdle {
		t.Errorf("TCP_KEEPIDLE = %ds, want the system default %ds: the server is overriding kernel keepalive timing", idle, wantIdle)
	}
	if interval != wantInterval {
		t.Errorf("TCP_KEEPINTVL = %ds, want the system default %ds: the server is overriding kernel keepalive timing", interval, wantInterval)
	}
	if count != wantCount {
		t.Errorf("TCP_KEEPCNT = %d, want the system default %d: the server is overriding kernel keepalive timing", count, wantCount)
	}
}
