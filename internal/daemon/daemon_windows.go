//go:build windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess      = modkernel32.NewProc("OpenProcess")
	procTerminateProcess = modkernel32.NewProc("TerminateProcess")
	procCloseHandle      = modkernel32.NewProc("CloseHandle")
)

const processQueryLimitedInformation = 0x1000
const processTerminate = 0x0001

// IsRunning returns true if a process with the given PID exists on Windows.
func IsRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
		return false
	}
	_, _, _ = procCloseHandle.Call(handle)
	return true
}

// kill terminates the process with the given PID on Windows.
func kill(pid int) error {
	handle, _, err := procOpenProcess.Call(processTerminate, 0, uintptr(pid))
	if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer procCloseHandle.Call(handle)
	r, _, err := procTerminateProcess.Call(handle, 1)
	if r == 0 {
		return fmt.Errorf("TerminateProcess: %w", err)
	}
	return nil
}

// Start launches the agent as a background process on Windows.
func Start(self, pidPath, logPath string) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open log file: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command(self, "run")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
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

// WaitForStop polls until the process with pid is no longer running.
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

// Silence "unused" for unsafe import.
var _ = unsafe.Sizeof(0)
