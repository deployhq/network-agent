package config

import (
	"fmt"
	"os"
)

// CAFileEnv names the environment variable that overrides the CA bundle used
// to verify the DeployHQ agent server.
const CAFileEnv = "DEPLOY_AGENT_CA_FILE"

// CACert returns the CA bundle the agent should trust.
//
// By default this is the bundle compiled into the binary, passed in as
// embedded. Setting DEPLOY_AGENT_CA_FILE to a PEM file path replaces it — for
// staging, for a private agent server, and as the escape hatch that lets an
// operator trust a newly issued CA without waiting for a new release.
//
// An unreadable override is an error rather than a silent fall back to the
// embedded bundle: trusting a different CA than the operator asked for is worse
// than refusing to start.
func CACert(embedded []byte) ([]byte, error) {
	path := os.Getenv(CAFileEnv)
	if path == "" {
		return embedded, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s %q: %w", CAFileEnv, path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("reading %s %q: file is empty", CAFileEnv, path)
	}
	return data, nil
}
