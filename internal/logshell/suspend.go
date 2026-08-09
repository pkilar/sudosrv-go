// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/suspend.go
package logshell

import (
	"os"
	"os/signal"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"syscall"
)

// SuspendSignals are the names the log server accepts in a CommandSuspend
// message: bare, with no "SIG" prefix, matching C's sig2str and the validation
// in internal/storage.
var SuspendSignals = map[string]bool{
	"STOP": true, "TSTP": true, "CONT": true, "TTIN": true, "TTOU": true,
}

// Suspend records that the session stopped or resumed.
//
// An unrecognised name is dropped rather than sent. internal/storage REJECTS a
// CommandSuspend carrying anything outside its allowed set, and a rejected
// message tears down the session -- so a stray name here would cost the whole
// transcript, not just the one event.
func (r *Recorder) Suspend(name string) error {
	if !SuspendSignals[name] {
		return nil
	}
	return r.send(func(d *pb.TimeSpec) *pb.ClientMessage {
		return &pb.ClientMessage{Type: &pb.ClientMessage_SuspendEvent{
			SuspendEvent: &pb.CommandSuspend{Delay: d, Signal: name},
		}}
	})
}

// watchSuspend makes logsh survive being stopped, and records it when it is.
//
// WHAT THIS IS NOT. sudo suspends the command it runs and hands the terminal
// back to the shell that invoked it. logsh has no such shell to hand back to --
// it IS the login shell -- so the ^Z case people expect from sudo does not arise
// here. It cannot, either: the outer terminal is in raw mode with ISIG cleared,
// so ^Z is relayed to the inner pty as a plain byte, where the inner tty driver
// generates SIGTSTP for whatever the recorded shell has in the foreground. Job
// control inside a recorded session therefore works exactly as it would with no
// recorder present, and logsh never sees it.
//
// What is left is the case where something stops logsh directly -- kill -TSTP,
// or a SIGTTIN/SIGTTOU from being moved to the background. Without handling,
// logsh would stop with the user's terminal still in raw mode: no echo, no line
// editing, no ^C. The terminal would appear dead, and the user has no shell to
// type `reset` into because logsh is their shell.
//
// So: restore the terminal, record the stop, actually stop, and on resume put
// everything back.
func watchSuspend(fd uintptr, saved, raw *syscall.Termios, rec *Recorder) func() {
	ch := make(chan os.Signal, 1)
	stops := []os.Signal{syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU}
	signal.Notify(ch, stops...)

	done := make(chan struct{})
	var once sync.Once

	go func() {
		for {
			select {
			case sig := <-ch:
				sysSig, ok := sig.(syscall.Signal)
				if !ok {
					continue
				}
				name := signalName(sysSig)

				_ = rec.Suspend(name)
				// Hand the user back a usable terminal before going away.
				if saved != nil {
					_ = SetTermios(fd, saved)
				}

				// Re-raise with the default disposition so the process really
				// stops. Notify would otherwise keep swallowing it and the stop
				// would never happen.
				signal.Reset(sysSig)
				_ = syscall.Kill(syscall.Getpid(), sysSig)

				// ---- stopped here until SIGCONT ----

				signal.Notify(ch, stops...)
				if raw != nil {
					_ = SetTermios(fd, raw)
				}
				_ = rec.Suspend("CONT")
			case <-done:
				return
			}
		}
	}()

	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
		})
	}
}
