// Package setup implements the interactive setup wizard that provisions an agent
// certificate from the DeployHQ API and writes the initial access list.
package setup

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/deployhq/network-agent/internal/config"
)

// Run executes the interactive setup wizard.
func Run(paths config.Paths, certURL string) {
	if err := config.EnsureDir(paths.Config); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create config directory: %v\n", err)
		os.Exit(1)
	}

	// Warn if already configured
	if fileExists(paths.Certificate) || fileExists(paths.Access) {
		fmt.Println("***************************** WARNING *****************************")
		fmt.Println("The Deploy agent has already been configured. Are you sure you wish")
		fmt.Println("to remove the existing configuration and generate a new one?")
		fmt.Println()
		resp := ask("Remove existing configuration? [no]: ")
		if resp != "yes" {
			os.Exit(1)
		}
		fmt.Println()
	}

	claimCode := generateCertificate(paths, certURL)
	generateAccessList(paths)

	fmt.Println()
	fmt.Println("You can now associate this Agent with your Deploy account.")
	fmt.Println("Browse to Settings -> Agents in your account and enter the code below:")
	fmt.Println()
	fmt.Printf(" >> %s <<\n", claimCode)
	fmt.Println()
	fmt.Println("You can start the agent using the following command:")
	fmt.Println()
	fmt.Println(" # network-agent start")
	fmt.Println()
}

// generateCertificate prompts for an agent name, calls the API, and writes cert/key files.
func generateCertificate(paths config.Paths, certURL string) string {
	fmt.Println("This tool will assist you in generating a certificate for your Deploy agent.")
	fmt.Println("Please enter a name for this agent.")

	name := ask("Agent Name: ")
	if len(name) < 2 {
		fmt.Fprintln(os.Stderr, "Name must be at least 2 characters.")
		os.Exit(1)
	}

	body, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		fatalf("encoding request: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, certURL, bytes.NewReader(body))
	if err != nil {
		fatalf("creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fatalf("calling API: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fatalf("reading response: %v", err)
	}

	var result struct {
		Status string `json:"status"`
		Data   struct {
			ClaimCode   string `json:"claim_code"`
			Certificate string `json:"certificate"`
			PrivateKey  string `json:"private_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		fatalf("parsing response: %v\nBody: %s", err, respBody)
	}

	if result.Status != "success" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "An error occurred obtaining a certificate.")
		fmt.Fprintln(os.Stderr, "Please contact support, quoting the debug information below:")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "HTTP %d\n%s\n", resp.StatusCode, respBody)
		os.Exit(1)
	}

	if err := os.WriteFile(paths.Certificate, []byte(result.Data.Certificate), 0600); err != nil {
		fatalf("writing certificate: %v", err)
	}
	if err := os.WriteFile(paths.Key, []byte(result.Data.PrivateKey), 0600); err != nil {
		fatalf("writing private key: %v", err)
	}

	fmt.Println()
	fmt.Println("Certificate has been successfully generated and installed.")
	fmt.Println()

	return result.Data.ClaimCode
}

// generateAccessList prompts for optional extra IPs and writes agent.access.
func generateAccessList(paths config.Paths) {
	fmt.Println("By default this utility only allows connections from DeployHQ to localhost.")
	fmt.Println("To deploy to other hosts or networks enter their addresses below:")

	var userHosts []string
	for {
		host := ask("IP Address [leave blank to finish]: ")
		if host == "" {
			break
		}
		userHosts = append(userHosts, host)
	}

	f, err := os.OpenFile(paths.Access, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fatalf("opening access list: %v", err)
	}
	defer f.Close()

	fmt.Fprint(f, "# This file contains a list of host and network addresses the Deploy agent\n")
	fmt.Fprint(f, "# will allow connections to. Add IPs or networks (CIDR format) as needed.\n\n")
	fmt.Fprint(f, "# Allow deployments to localhost\n")
	fmt.Fprint(f, "127.0.0.1\n")
	fmt.Fprint(f, "::1\n")

	if len(userHosts) > 0 {
		fmt.Fprint(f, "\n# User defined destinations\n")
		for _, h := range userHosts {
			fmt.Fprintf(f, "%s\n", h)
		}
	}
}

// ask prints the prompt and reads a line from stdin.
func ask(prompt string) string {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	// EOF or interrupt
	fmt.Println()
	os.Exit(1)
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
