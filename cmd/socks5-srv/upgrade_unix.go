// SPDX-License-Identifier: Apache-2.0 OR MIT

//go:build unix

package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

const (
	envListenerFD = "SOCKS5_LISTENER_FD"
	envReadyFD    = "SOCKS5_READY_FD"
)

// upgradeSignal returns a channel that receives SIGUSR2 signals.
// Selecting on this channel lets the main loop trigger a graceful upgrade.
func upgradeSignal() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR2)
	return ch
}

// inheritListener returns a listener inherited from a parent process during
// a graceful upgrade. Returns (nil, nil) when no listener was inherited.
func inheritListener() (net.Listener, error) {
	if os.Getenv(envListenerFD) == "" {
		return nil, nil
	}
	// fd 3 is the first ExtraFile passed by the parent process.
	f := os.NewFile(3, "inherited-listener")
	if f == nil {
		return nil, fmt.Errorf("inherited listener fd 3 is not valid")
	}
	ln, err := net.FileListener(f)
	f.Close() // FileListener dups; close our copy.
	if err != nil {
		return nil, fmt.Errorf("inherited listener: %w", err)
	}
	os.Unsetenv(envListenerFD) // prevent re-inheritance on next upgrade
	return ln, nil
}

// sdNotify sends a state string to systemd's notification socket.
// Silent no-op when NOTIFY_SOCKET is not set (not running under
// systemd Type=notify). Implements sd_notify(3) without any dependency.
func sdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte(state))
}

// signalReady notifies the parent process (via readiness pipe) and systemd
// (via sd_notify) that this process is accepting connections.
func signalReady() {
	// Notify parent process if started via upgrade.
	if os.Getenv(envReadyFD) != "" {
		// fd 4 is the second ExtraFile passed by the parent (readiness pipe).
		f := os.NewFile(4, "ready-signal")
		if f != nil {
			f.Write([]byte{1})
			f.Close()
		}
		os.Unsetenv(envReadyFD)
	}

	// Notify systemd: update tracked PID and signal readiness.
	// No-op when NOTIFY_SOCKET is not set.
	sdNotify(fmt.Sprintf("MAINPID=%d\nREADY=1", os.Getpid()))
}

// startUpgrade re-executes the on-disk binary, passing the active listener
// to the new process. It blocks until the child signals readiness (i.e. is
// accepting connections) or fails to start.
func startUpgrade(ln net.Listener, logger *slog.Logger) error {
	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("listener is %T, not *net.TCPListener", ln)
	}
	f, err := tcpLn.File()
	if err != nil {
		return fmt.Errorf("listener file descriptor: %w", err)
	}
	defer f.Close()

	// Readiness pipe: child writes a byte once it is accepting.
	// If the child dies before that, Read returns EOF.
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("readiness pipe: %w", err)
	}
	defer readyR.Close()

	exe, err := os.Executable()
	if err != nil {
		readyW.Close()
		return fmt.Errorf("resolve executable path: %w", err)
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{f, readyW} // fd 3 = listener, fd 4 = ready pipe
	cmd.Env = append(os.Environ(), envListenerFD+"=3", envReadyFD+"=4")

	if err := cmd.Start(); err != nil {
		readyW.Close()
		return fmt.Errorf("start new process: %w", err)
	}
	readyW.Close() // parent's copy; child has its own
	logger.Warn("upgrade: new process started, waiting for readiness", "pid", cmd.Process.Pid)

	// Detach: let the child run independently. The goroutine reaps the
	// child's exit status to prevent a zombie if the parent outlives it.
	go cmd.Wait()

	// Block until the child signals readiness or dies.
	var buf [1]byte
	if _, err := readyR.Read(buf[:]); err != nil {
		return fmt.Errorf("new process failed to become ready: %w", err)
	}

	logger.Warn("upgrade: new process is ready", "pid", cmd.Process.Pid)
	return nil
}
