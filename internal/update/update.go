// Package update implements self-update for network-agent.
// It fetches the latest release from GitHub, compares it with the running
// version, and replaces the current executable in-place.
package update

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const repo = "deployhq/network-agent"

// Run checks for a newer release and upgrades the binary if one is found.
// currentVersion is the version baked in at build time (e.g. "0.1.0").
func Run(currentVersion string) {
	fmt.Println("Checking for updates...")

	latest, err := fetchLatestVersion()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking for updates: %v\n", err)
		os.Exit(1)
	}

	// Normalise: strip leading "v" for comparison.
	latestClean := strings.TrimPrefix(latest, "v")
	currentClean := strings.TrimPrefix(currentVersion, "v")

	if latestClean == currentClean || currentVersion == "dev" && latestClean == "" {
		fmt.Printf("Already up to date (%s).\n", currentVersion)
		return
	}
	if currentClean == latestClean {
		fmt.Printf("Already up to date (%s).\n", currentVersion)
		return
	}

	fmt.Printf("New version available: %s → %s\n", currentVersion, latest)
	fmt.Println("Downloading...")

	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot determine executable path: %v\n", err)
		os.Exit(1)
	}

	if err := downloadAndReplace(latest, execPath); err != nil {
		fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Updated to %s.\n", latest)
	fmt.Println("")
	fmt.Println("Restart the agent to use the new version:")
	fmt.Println("  network-agent restart")
}

// fetchLatestVersion returns the tag name of the latest GitHub release.
func fetchLatestVersion() (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	resp, err := http.Get(url) //nolint:gosec,noctx
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned %s", resp.Status)
	}

	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("parsing release response: %w", err)
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("no release found")
	}
	return rel.TagName, nil
}

// downloadAndReplace downloads the release tarball for the current platform
// and atomically replaces execPath with the new binary.
func downloadAndReplace(tag, execPath string) error {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	version := strings.TrimPrefix(tag, "v")

	filename := fmt.Sprintf("network-agent_%s_%s_%s.tar.gz", version, goos, goarch)
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, tag, filename)

	resp, err := http.Get(url) //nolint:gosec,noctx
	if err != nil {
		return fmt.Errorf("downloading release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %s", resp.Status)
	}

	// Extract the binary from the tarball into a temp file next to the
	// current executable so the rename is atomic (same filesystem).
	dir := filepath.Dir(execPath)
	tmp, err := os.CreateTemp(dir, "network-agent-update-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // clean up on failure

	if err := extractBinary(resp.Body, tmp); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	if err := os.Chmod(tmpName, 0755); err != nil { //nolint:gosec
		return fmt.Errorf("setting permissions: %w", err)
	}

	// Atomic replace.
	if err := os.Rename(tmpName, execPath); err != nil {
		return fmt.Errorf("replacing binary: %w", err)
	}
	return nil
}

// extractBinary reads a .tar.gz stream and writes the first file named
// "network-agent" (or "network-agent.exe") into dst.
func extractBinary(r io.Reader, dst io.Writer) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("reading gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		name := filepath.Base(hdr.Name)
		if name == "network-agent" || name == "network-agent.exe" {
			if _, err := io.Copy(dst, tr); err != nil { //nolint:gosec
				return fmt.Errorf("writing binary: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("binary not found in release archive")
}
