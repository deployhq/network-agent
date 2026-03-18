// Package config provides file paths and environment variable constants that
// mirror the Ruby agent's constant definitions.
package config

import (
	"os"
	"path/filepath"
)

// Paths returns the well-known paths used by the agent, rooted under ~/.deploy.
type Paths struct {
	Config      string // ~/.deploy
	Certificate string // ~/.deploy/agent.crt
	Key         string // ~/.deploy/agent.key
	PID         string // ~/.deploy/agent.pid
	Log         string // ~/.deploy/agent.log
	Access      string // ~/.deploy/agent.access
}

// DefaultPaths returns paths under the user's home directory.
func DefaultPaths() Paths {
	home, err := os.UserHomeDir()
	if err != nil {
		panic("cannot determine home directory: " + err.Error())
	}
	base := filepath.Join(home, ".deploy")
	return Paths{
		Config:      base,
		Certificate: filepath.Join(base, "agent.crt"),
		Key:         filepath.Join(base, "agent.key"),
		PID:         filepath.Join(base, "agent.pid"),
		Log:         filepath.Join(base, "agent.log"),
		Access:      filepath.Join(base, "agent.access"),
	}
}

// ServerHost returns the TLS proxy host, overridable via DEPLOY_AGENT_PROXY_IP.
func ServerHost() string {
	if h := os.Getenv("DEPLOY_AGENT_PROXY_IP"); h != "" {
		return h
	}
	return "agent.deployhq.com"
}

// ServerPort is the port used by the agent server.
const ServerPort = "7777"

// CertificateURL returns the API endpoint for agent provisioning,
// overridable via DEPLOY_AGENT_CERTIFICATE_URL.
func CertificateURL() string {
	if u := os.Getenv("DEPLOY_AGENT_CERTIFICATE_URL"); u != "" {
		return u
	}
	return "https://api.deployhq.com/api/v1/agents/create"
}

// VerifyTLS returns false when DEPLOY_AGENT_NOVERIFY is set (for dev/testing).
func VerifyTLS() bool {
	return os.Getenv("DEPLOY_AGENT_NOVERIFY") == ""
}
