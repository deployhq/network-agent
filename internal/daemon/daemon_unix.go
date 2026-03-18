//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// IsRunning returns true if a process with the given PID exists.
func IsRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	if err == syscall.EPERM {
		return true // exists but not owned by us
	}
	return false
}

// kill sends SIGTERM to pid.
func kill(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

// Start launches the agent as a detached background process.
// self is the path to the current executable; pidPath is where to write the PID.
func Start(self, pidPath, logPath string) {
	// Open (or create) the log file for the child's stdout/stderr.
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open log file: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command(self, "run")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // detach from terminal
	}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		fmt.Fprintf(os.Stderr, "Failed to start agent: %v\n", err)
		os.Exit(1)
	}
	logFile.Close()

	pid := cmd.Process.Pid
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write PID file: %v\n", err)
	}

	fmt.Printf("Deploy agent started. Process ID %d\n", pid)
}

// WaitForStop polls until the process with pid is no longer running, with timeout.
func WaitForStop(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !IsRunning(pid) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
