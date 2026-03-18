// Package install writes the platform-specific service definition for
// network-agent and enables it so it starts automatically on login/boot.
package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/deployhq/network-agent/internal/config"
)

// Run installs network-agent as a background service on the current platform.
// executable is the absolute path to the running binary (os.Executable()).
func Run(paths config.Paths, executable string) {
	switch runtime.GOOS {
	case "darwin":
		installLaunchd(paths, executable)
	case "linux":
		installSystemd(paths, executable)
	default:
		fmt.Printf("Automatic service installation is not supported on %s.\n", runtime.GOOS)
		fmt.Printf("Run the agent manually with: %s run\n", executable)
	}
}

// --- macOS (launchd) -------------------------------------------------------

const launchdPlistPath = "Library/LaunchAgents/com.deployhq.network-agent.plist"

func installLaunchd(paths config.Paths, executable string) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot determine home directory: %v\n", err)
		os.Exit(1)
	}

	plistDest := filepath.Join(home, launchdPlistPath)
	if err := os.MkdirAll(filepath.Dir(plistDest), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create LaunchAgents directory: %v\n", err)
		os.Exit(1)
	}

	plist := buildPlist(executable, paths.Log)
	if err := os.WriteFile(plistDest, []byte(plist), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write plist: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %s\n", plistDest)

	// Unload first in case a previous version is loaded.
	_ = exec.Command("launchctl", "unload", plistDest).Run()

	out, err := exec.Command("launchctl", "load", "-w", plistDest).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "launchctl load failed: %v\n%s\n", err, out)
		os.Exit(1)
	}
	fmt.Println("Service installed and started. network-agent will launch automatically on login.")
}

func buildPlist(executable, logPath string) string {
	return strings.Join([]string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"`,
		`  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`,
		`<plist version="1.0">`,
		`<dict>`,
		`  <key>Label</key>`,
		`  <string>com.deployhq.network-agent</string>`,
		`  <key>ProgramArguments</key>`,
		`  <array>`,
		`    <string>` + executable + `</string>`,
		`    <string>run</string>`,
		`  </array>`,
		`  <key>RunAtLoad</key>`,
		`  <true/>`,
		`  <key>KeepAlive</key>`,
		`  <true/>`,
		`  <key>StandardOutPath</key>`,
		`  <string>` + logPath + `</string>`,
		`  <key>StandardErrorPath</key>`,
		`  <string>` + logPath + `</string>`,
		`</dict>`,
		`</plist>`,
	}, "\n")
}

// --- Linux (systemd user) --------------------------------------------------

func installSystemd(paths config.Paths, executable string) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot determine home directory: %v\n", err)
		os.Exit(1)
	}

	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create systemd user unit directory: %v\n", err)
		os.Exit(1)
	}

	unitDest := filepath.Join(unitDir, "network-agent.service")
	unit := buildUnit(executable)
	if err := os.WriteFile(unitDest, []byte(unit), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write unit file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %s\n", unitDest)

	run := func(args ...string) bool {
		out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "systemctl %s failed: %v\n%s\n", strings.Join(args, " "), err, out)
			return false
		}
		return true
	}

	if !run("daemon-reload") || !run("enable", "--now", "network-agent") {
		os.Exit(1)
	}
	fmt.Println("Service installed and started. network-agent will launch automatically on login.")
}

func buildUnit(executable string) string {
	return strings.Join([]string{
		`[Unit]`,
		`Description=DeployHQ Network Agent`,
		`After=network.target`,
		``,
		`[Service]`,
		`ExecStart=` + executable + ` run`,
		`Restart=always`,
		`RestartSec=10`,
		``,
		`[Install]`,
		`WantedBy=default.target`,
	}, "\n") + "\n"
}
