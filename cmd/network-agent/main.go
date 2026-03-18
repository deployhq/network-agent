// Command network-agent is a Go reimplementation of the Ruby network-agent gem.
// It creates a reverse TLS tunnel from inside customer firewalls to DeployHQ's
// agent server, enabling deployments to servers behind firewalls.
//
// Usage: network-agent [-v|--verbose] <command>
//
// Commands:
//
//	setup       Generate certificate and access list
//	start       Start agent in background
//	stop        Stop running agent
//	restart     Stop then start the agent
//	run         Run agent in foreground (used by start internally)
//	status      Show whether agent is running
//	accesslist  Display the current access list
//	install     Install as a system service (launchd on macOS, systemd on Linux)
//	check       Verify configuration and test server connectivity
//	version     Print agent version
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deployhq/network-agent/internal/acl"
	"github.com/deployhq/network-agent/internal/caroot"
	"github.com/deployhq/network-agent/internal/config"
	"github.com/deployhq/network-agent/internal/daemon"
	"github.com/deployhq/network-agent/internal/install"
	"github.com/deployhq/network-agent/internal/setup"
	"github.com/deployhq/network-agent/internal/tunnel"
)

// Version is injected at build time via ldflags: -X main.Version=x.y.z
var Version = "dev"

func main() {
	args := os.Args[1:]
	verbose := false

	// Strip -v / --verbose flags
	filtered := args[:0]
	for _, a := range args {
		if a == "-v" || a == "--verbose" {
			verbose = true
		} else {
			filtered = append(filtered, a)
		}
	}
	args = filtered

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	paths := config.DefaultPaths()
	cmd := args[0]

	switch cmd {
	case "setup":
		setup.Run(paths, config.CertificateURL())

	case "start":
		cmdStart(paths, verbose)

	case "stop":
		daemon.Stop(paths.PID)

	case "restart":
		cmdRestart(paths, verbose)

	case "run":
		cmdRun(paths, verbose)

	case "status":
		daemon.Status(paths.PID)

	case "accesslist":
		cmdAccessList(paths)

	case "install":
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot determine executable path: %v\n", err)
			os.Exit(1)
		}
		ensureConfigured(paths)
		install.Run(paths, self)

	case "check":
		cmdCheck(paths)

	case "version":
		fmt.Println(Version)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: network-agent [setup|start|stop|restart|run|status|accesslist|install|check|version]")
}

func cmdStart(paths config.Paths, verbose bool) {
	pid, _ := daemon.ReadPID(paths.PID)
	if pid != 0 && daemon.IsRunning(pid) {
		fmt.Printf("Deploy agent already running. Process ID %d\n", pid)
		os.Exit(1)
	}
	ensureConfigured(paths)

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot determine executable path: %v\n", err)
		os.Exit(1)
	}
	daemon.Start(self, paths.PID, paths.Log)
}

func cmdRestart(paths config.Paths, verbose bool) {
	pid, _ := daemon.ReadPID(paths.PID)
	if pid != 0 && daemon.IsRunning(pid) {
		daemon.Stop(paths.PID)
		if !daemon.WaitForStop(pid, 10*time.Second) {
			fmt.Fprintln(os.Stderr, "Agent did not stop in time")
			os.Exit(1)
		}
	}
	cmdStart(paths, verbose)
}

func cmdRun(paths config.Paths, verbose bool) {
	ensureConfigured(paths)

	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	tlsCfg, err := config.NewTLSConfig(paths, caroot.CACert, config.VerifyTLS())
	if err != nil {
		log.Error("TLS configuration error", "err", err)
		os.Exit(1)
	}

	// Handle SIGTERM / SIGINT for clean shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigc
		log.Info("received signal, stopping", "signal", sig)
		daemon.RemovePID(paths.PID)
		os.Exit(0)
	}()

	// Write PID so that 'stop' works after 'run' is backgrounded by 'start'.
	// If PID already written by the parent (start), this is a no-op for our PID.
	_ = daemon.WritePID(paths.PID)

	if err := tunnel.RunAgent(tlsCfg, paths, log); err != nil {
		log.Error("agent stopped with error", "err", err)
		daemon.RemovePID(paths.PID)
		os.Exit(1)
	}
}

func cmdAccessList(paths config.Paths) {
	entries := acl.Entries(paths.Access)
	fmt.Println("Access list:")
	for _, e := range entries {
		fmt.Printf(" - %s\n", e)
	}
	fmt.Println()
	fmt.Printf("To edit the list of allowed servers, please modify %s\n", paths.Access)
}

func ensureConfigured(paths config.Paths) {
	if _, err := os.Stat(paths.Certificate); os.IsNotExist(err) {
		fmt.Println(`Deploy agent is not configured. Please run "network-agent setup" first.`)
		os.Exit(1)
	}
	if _, err := os.Stat(paths.Access); os.IsNotExist(err) {
		fmt.Println(`Deploy agent is not configured. Please run "network-agent setup" first.`)
		os.Exit(1)
	}
}

func cmdCheck(paths config.Paths) {
	fmt.Println("Checking network-agent configuration...")
	ok := true

	// --- Certificate -------------------------------------------------------
	certData, err := os.ReadFile(paths.Certificate)
	if err != nil {
		fmt.Printf("  Certificate   FAIL  not found (%s)\n", paths.Certificate)
		ok = false
	} else {
		block, _ := pem.Decode(certData)
		if block == nil {
			fmt.Printf("  Certificate   FAIL  cannot parse PEM (%s)\n", paths.Certificate)
			ok = false
		} else {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Printf("  Certificate   FAIL  cannot parse certificate: %v\n", err)
				ok = false
			} else {
				daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
				if daysLeft < 0 {
					fmt.Printf("  Certificate   FAIL  expired %d days ago\n", -daysLeft)
					ok = false
				} else if daysLeft < 30 {
					fmt.Printf("  Certificate   WARN  expires in %d days\n", daysLeft)
				} else {
					fmt.Printf("  Certificate   OK    valid, expires in %d days\n", daysLeft)
				}
			}
		}
	}

	// --- Private key -------------------------------------------------------
	if _, err := os.Stat(paths.Key); os.IsNotExist(err) {
		fmt.Printf("  Private key   FAIL  not found (%s)\n", paths.Key)
		ok = false
	} else {
		fmt.Printf("  Private key   OK    %s\n", paths.Key)
	}

	// --- Access list -------------------------------------------------------
	entries := acl.Entries(paths.Access)
	if len(entries) == 0 {
		fmt.Println("  Access list   OK    empty (only localhost allowed)")
	} else {
		fmt.Printf("  Access list   OK    %d entr", len(entries))
		if len(entries) == 1 {
			fmt.Print("y")
		} else {
			fmt.Print("ies")
		}
		fmt.Printf(" (%s", entries[0])
		if len(entries) > 1 {
			fmt.Printf(", ...")
		}
		fmt.Println(")")
	}

	// --- Connectivity ------------------------------------------------------
	serverAddr := config.ServerHost() + ":" + config.ServerPort
	fmt.Printf("  Connectivity  ")

	tlsCfg, err := config.NewTLSConfig(paths, caroot.CACert, config.VerifyTLS())
	if err != nil {
		fmt.Printf("FAIL  TLS config error: %v\n", err)
		ok = false
	} else {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp",
			serverAddr,
			tlsCfg,
		)
		if err != nil {
			fmt.Printf("FAIL  cannot reach %s: %v\n", serverAddr, err)
			ok = false
		} else {
			conn.Close()
			fmt.Printf("OK    connected to %s\n", serverAddr)
		}
	}

	fmt.Println()
	if ok {
		fmt.Println("All checks passed.")
	} else {
		fmt.Println("One or more checks failed.")
		os.Exit(1)
	}
}
