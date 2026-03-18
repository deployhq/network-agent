// Package daemon provides cross-platform utilities for starting, stopping, and
// querying the background agent process.
package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// WritePID writes the current process PID to path.
func WritePID(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644)
}

// ReadPID reads a PID from path. Returns 0 if the file does not exist.
func ReadPID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, nil // treat corrupt PID file as "not running"
	}
	return pid, nil
}

// RemovePID deletes the PID file, ignoring missing-file errors.
func RemovePID(path string) {
	os.Remove(path)
}

// Status prints the agent status and exits with the appropriate code.
// Exit 0: running. Exit 1: not running.
func Status(pidPath string) {
	pid, err := ReadPID(pidPath)
	if err != nil || pid == 0 {
		fmt.Println("Deploy agent is not running.")
		os.Exit(1)
	}
	if IsRunning(pid) {
		fmt.Printf("Deploy agent is running. PID %d\n", pid)
	} else {
		fmt.Println("Deploy agent is not running.")
		os.Exit(1)
	}
}

// Stop sends SIGTERM to the process in the PID file.
func Stop(pidPath string) {
	pid, err := ReadPID(pidPath)
	if err != nil || pid == 0 || !IsRunning(pid) {
		fmt.Println("Deploy agent is not running")
		os.Exit(1)
	}
	if err := kill(pid); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to stop agent: %v\n", err)
		os.Exit(1)
	}
	RemovePID(pidPath)
	fmt.Printf("Deploy agent stopped. Process ID %d\n", pid)
}
