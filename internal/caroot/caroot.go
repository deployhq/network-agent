// Package caroot embeds the DeployHQ CA certificate used to verify the agent server.
//
// ca.crt is a PEM bundle, not necessarily a single certificate: during a CA
// rotation it holds both the outgoing and the incoming CA so that one binary
// verifies an agent server presenting a leaf from either.
package caroot

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	_ "embed"
)

//go:embed ca.crt
var CACert []byte

// Certificates parses every certificate in the embedded bundle, in file order.
//
// It exists so the number of trusted CAs is observable — by `network-agent
// check`, by tests, and by anyone verifying that a release actually shipped the
// bundle it was supposed to.
func Certificates() ([]*x509.Certificate, error) {
	return ParseBundle(CACert)
}

// ParseBundle parses every CERTIFICATE block in a PEM bundle. Non-certificate
// blocks are skipped; any unparsable certificate block, or a bundle holding no
// certificates at all, is an error.
func ParseBundle(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d in bundle: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in bundle")
	}
	return certs, nil
}
