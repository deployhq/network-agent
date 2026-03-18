package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// NewTLSConfig builds a mutual-TLS config for the agent:
//   - Client certificate: ~/.deploy/agent.crt + agent.key
//   - Server verification: embedded CA cert passed in via caCert
//
// When verify is false, server certificate verification is skipped (dev/testing).
//
// Go 1.15+ rejects certificates that rely on the legacy Common Name field
// instead of Subject Alternative Names. The DeployHQ agent server uses such a
// certificate, so when verify is true we use InsecureSkipVerify + a custom
// VerifyConnection callback that checks the CA chain and then falls back to CN
// matching when no SANs are present.
func NewTLSConfig(paths Paths, caCert []byte, verify bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(paths.Certificate, paths.Key)
	if err != nil {
		return nil, fmt.Errorf("loading agent certificate: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if !verify {
		cfg.InsecureSkipVerify = true //nolint:gosec // intentional for dev
		return cfg, nil
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	serverHost := ServerHost()
	// Strip port if present (e.g. "agent.deployhq.com:7777" → "agent.deployhq.com").
	if i := strings.LastIndex(serverHost, ":"); i >= 0 {
		serverHost = serverHost[:i]
	}

	// InsecureSkipVerify disables Go's built-in hostname check so we can do
	// our own CN-aware check in VerifyConnection below.
	cfg.InsecureSkipVerify = true //nolint:gosec
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("server sent no certificate")
		}
		leaf := cs.PeerCertificates[0]

		// Build intermediate pool from the rest of the chain.
		intermediates := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}

		// Verify the certificate chain without hostname (Go rejects CN-only certs
		// when DNSName is set, so we check the hostname separately below).
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intermediates,
		})
		if err != nil {
			return fmt.Errorf("certificate verification failed: %w", err)
		}

		// Hostname check: prefer SANs, fall back to CN for legacy certs.
		if len(leaf.DNSNames) > 0 || len(leaf.IPAddresses) > 0 {
			return leaf.VerifyHostname(serverHost)
		}
		if !strings.EqualFold(leaf.Subject.CommonName, serverHost) {
			return fmt.Errorf("certificate CN %q does not match server host %q",
				leaf.Subject.CommonName, serverHost)
		}
		return nil
	}

	return cfg, nil
}

// EnsureDir creates the ~/.deploy directory if it does not exist.
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0700)
}
