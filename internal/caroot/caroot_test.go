package caroot_test

import (
	"testing"
	"time"

	"github.com/deployhq/network-agent/internal/caroot"
)

// TestEmbeddedBundleParses is the release-time guard for the CA bundle: it
// proves the embedded PEM is well formed and reports how many CAs it holds, so
// appending the new DeployHQ CA before a release is a visible, verifiable
// change rather than an unchecked assumption.
func TestEmbeddedBundleParses(t *testing.T) {
	certs, err := caroot.Certificates()
	if err != nil {
		t.Fatalf("parsing embedded CA bundle: %v", err)
	}
	if len(certs) < 1 {
		t.Fatal("embedded CA bundle holds no certificates")
	}

	t.Logf("embedded CA bundle holds %d certificate(s)", len(certs))
	for i, c := range certs {
		t.Logf("  [%d] subject=%q issuer=%q serial=%s notAfter=%s isCA=%v",
			i, c.Subject.String(), c.Issuer.String(), c.SerialNumber,
			c.NotAfter.UTC().Format(time.RFC3339), c.IsCA)

		if !c.IsCA {
			t.Errorf("[%d] %q is not a CA certificate", i, c.Subject.CommonName)
		}
	}
}

// TestParseBundleRejectsGarbage keeps ParseBundle honest: a bundle that does
// not parse must be an error, never an empty-but-successful result that would
// ship a binary trusting nothing.
func TestParseBundleRejectsGarbage(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"not pem", []byte("hello, world")},
		{"pem but not a certificate", []byte("-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----\n")},
		{"corrupt certificate block", []byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := caroot.ParseBundle(tt.data); err == nil {
				t.Error("expected an error, got none")
			}
		})
	}
}
