package certrenew_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/deployhq/network-agent/internal/certrenew"
	"github.com/deployhq/network-agent/internal/testca"
)

// agentCN and agentSerial mirror how DeployHQ identifies an agent: the subject
// common name and the serial number are the identity, and a renewal must
// preserve both while changing only the issuer.
const (
	agentCN     = "Deploy Agent #42"
	agentSerial = 42
)

type fixture struct {
	dir         string
	certPath    string
	keyPath     string
	current     *x509.Certificate
	originalPEM []byte

	// renewed is the certificate the backend would legitimately hand back:
	// the same key, subject and serial, re-signed by the new CA.
	renewed []byte

	// The refusable variants.
	wrongSerial  []byte
	wrongSubject []byte
	wrongKey     []byte
	unknownCA    []byte

	roots *x509.CertPool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	oldCA := testca.New(t, "old")
	newCA := testca.New(t, "new")
	otherCA := testca.New(t, "someone else")

	agent := oldCA.Issue(t, agentCN, agentSerial)
	impostor := newCA.Issue(t, agentCN, agentSerial) // same identity, different key

	dir := t.TempDir()
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(certPath, agent.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, agent.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	return &fixture{
		dir:          dir,
		certPath:     certPath,
		keyPath:      keyPath,
		current:      agent.Cert,
		originalPEM:  agent.CertPEM,
		renewed:      newCA.Reissue(t, agent, agentCN, agentSerial),
		wrongSerial:  newCA.Reissue(t, agent, agentCN, agentSerial+1),
		wrongSubject: newCA.Reissue(t, agent, "Deploy Agent #99", agentSerial),
		wrongKey:     impostor.CertPEM,
		unknownCA:    otherCA.Reissue(t, agent, agentCN, agentSerial),
		roots:        testca.Pool(oldCA, newCA),
	}
}

func (f *fixture) request(candidate []byte) certrenew.Request {
	return certrenew.Request{
		CertPath:     f.certPath,
		KeyPath:      f.keyPath,
		Roots:        f.roots,
		Current:      f.current,
		CandidatePEM: candidate,
	}
}

// onDisk reads the certificate file, so a test can assert it was left alone.
func (f *fixture) onDisk(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(f.certPath)
	if err != nil {
		t.Fatalf("reading %s: %v", f.certPath, err)
	}
	return data
}

// TestApplyInstallsRenewedCertificate is the happy path: a certificate
// re-signed under the new CA, keeping key, subject and serial, replaces the
// file on disk.
func TestApplyInstallsRenewedCertificate(t *testing.T) {
	f := newFixture(t)

	installed, err := certrenew.Apply(f.request(f.renewed))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := f.onDisk(t); !bytes.Equal(got, f.renewed) {
		t.Error("certificate file does not hold the renewed certificate")
	}
	if installed.Issuer.CommonName != "Deploy Dev CA (new)" {
		t.Errorf("issuer = %q, want %q", installed.Issuer.CommonName, "Deploy Dev CA (new)")
	}
	if installed.Subject.CommonName != agentCN {
		t.Errorf("subject CN = %q, want %q", installed.Subject.CommonName, agentCN)
	}
	if installed.SerialNumber.Int64() != agentSerial {
		t.Errorf("serial = %s, want %d", installed.SerialNumber, agentSerial)
	}
	if installed.Issuer.CommonName == f.current.Issuer.CommonName {
		t.Error("issuer did not change — the fixture is not exercising a renewal")
	}

	// The renewed certificate must still be usable: it has to load as a key
	// pair with the untouched private key, or the agent is offline.
	reloaded, err := certrenew.LoadCurrent(f.certPath)
	if err != nil {
		t.Fatalf("LoadCurrent after Apply: %v", err)
	}
	if !reloaded.Equal(installed) {
		t.Error("certificate read back from disk differs from the one Apply reported")
	}
}

// TestApplyIsANoOpWhenTheCertificateIsAlreadyInstalled: a server that keeps
// answering RENEWED with the certificate the agent already presents must not
// push it through a connect-renew-reconnect loop forever. The comparison is on
// the DER, so re-encoded PEM does not read as a different certificate.
func TestApplyIsANoOpWhenTheCertificateIsAlreadyInstalled(t *testing.T) {
	tests := []struct {
		name      string
		candidate func(f *fixture) []byte
	}{
		{"the exact bytes on disk", func(f *fixture) []byte { return f.originalPEM }},
		{"the same certificate, re-encoded", func(f *fixture) []byte {
			block, _ := pem.Decode(f.originalPEM)
			if block == nil {
				t.Fatal("fixture certificate is not PEM")
			}
			// Same DER, different PEM framing: extra trailing newline and a
			// header the original does not carry.
			out := pem.EncodeToMemory(&pem.Block{
				Type:    "CERTIFICATE",
				Headers: map[string]string{"Comment": "re-encoded"},
				Bytes:   block.Bytes,
			})
			return append(out, '\n')
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			before, err := os.Stat(f.certPath)
			if err != nil {
				t.Fatal(err)
			}

			candidate := tt.candidate(f)
			if _, err := certrenew.Apply(f.request(candidate)); !errors.Is(err, certrenew.ErrUnchanged) {
				t.Fatalf("Apply returned %v, want ErrUnchanged", err)
			}

			if !bytes.Equal(f.onDisk(t), f.originalPEM) {
				t.Error("certificate file was rewritten")
			}
			after, err := os.Stat(f.certPath)
			if err != nil {
				t.Fatal(err)
			}
			if !after.ModTime().Equal(before.ModTime()) {
				t.Error("certificate file was touched")
			}
			if _, err := os.Stat(f.certPath + ".tmp"); err == nil {
				t.Error("temporary file left behind")
			}
		})
	}
}

// TestApplyLeavesFileUntouchedOnEveryRejection is the safety property that
// matters most: any failed check must leave the existing certificate byte for
// byte intact, because a broken agent.crt takes the agent offline behind a
// customer firewall where nobody can repair it.
func TestApplyLeavesFileUntouchedOnEveryRejection(t *testing.T) {
	tests := []struct {
		name      string
		candidate func(f *fixture) []byte
	}{
		{"wrong private key", func(f *fixture) []byte { return f.wrongKey }},
		{"wrong serial number", func(f *fixture) []byte { return f.wrongSerial }},
		{"wrong subject", func(f *fixture) []byte { return f.wrongSubject }},
		{"unknown issuer", func(f *fixture) []byte { return f.unknownCA }},
		{"malformed pem", func(f *fixture) []byte { return []byte("-----BEGIN CERTIFICATE-----\nnope\n") }},
		{"not pem at all", func(f *fixture) []byte { return []byte("certainly not a certificate") }},
		{"empty", func(f *fixture) []byte { return nil }},
		{"pem block of the wrong type", func(f *fixture) []byte {
			return []byte("-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n")
		}},
		{"corrupt certificate der", func(f *fixture) []byte {
			return []byte("-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			before := f.onDisk(t)

			installed, err := certrenew.Apply(f.request(tt.candidate(f)))
			if err == nil {
				t.Fatalf("Apply accepted a %s certificate", tt.name)
			}
			if installed != nil {
				t.Error("Apply returned a certificate alongside an error")
			}
			t.Logf("rejected: %v", err)

			if after := f.onDisk(t); !bytes.Equal(before, after) {
				t.Error("certificate file was modified despite the rejection")
			}
			if !bytes.Equal(f.onDisk(t), f.originalPEM) {
				t.Error("certificate file no longer holds the original certificate")
			}

			// The temporary file must not be left behind either.
			if _, err := os.Stat(f.certPath + ".tmp"); err == nil {
				t.Error("temporary file left behind after a rejected renewal")
			}
		})
	}
}

// TestApplyRejectsUntrustedRoots covers the failure this whole project exists
// to prevent: a certificate whose own dates are fine but whose issuer this
// agent does not trust must not be installed.
func TestApplyRejectsUntrustedRoots(t *testing.T) {
	f := newFixture(t)

	req := f.request(f.renewed)
	req.Roots = x509.NewCertPool() // trusts nothing

	if _, err := certrenew.Apply(req); err == nil {
		t.Fatal("Apply accepted a certificate that chains to no trusted CA")
	}
	if !bytes.Equal(f.onDisk(t), f.originalPEM) {
		t.Error("certificate file was modified")
	}
}

// TestValidateRejectsMissingInputs guards the caller contract: without a
// current certificate or a root pool there is nothing to validate against, and
// silently accepting would be the worst possible default.
func TestValidateRejectsMissingInputs(t *testing.T) {
	f := newFixture(t)

	t.Run("no current certificate", func(t *testing.T) {
		req := f.request(f.renewed)
		req.Current = nil
		if _, err := certrenew.Validate(req); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("no roots", func(t *testing.T) {
		req := f.request(f.renewed)
		req.Roots = nil
		if _, err := certrenew.Validate(req); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("missing private key file", func(t *testing.T) {
		req := f.request(f.renewed)
		req.KeyPath = filepath.Join(f.dir, "does-not-exist.key")
		if _, err := certrenew.Validate(req); err == nil {
			t.Error("expected an error")
		}
	})
}

// TestValidateHasNoSideEffects: Validate is the pure half of Apply and must
// never touch the certificate file, not even on success.
func TestValidateHasNoSideEffects(t *testing.T) {
	f := newFixture(t)

	if _, err := certrenew.Validate(f.request(f.renewed)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !bytes.Equal(f.onDisk(t), f.originalPEM) {
		t.Error("Validate modified the certificate file")
	}
}

// TestApplyWithRSAKeys pins the key-pairing check against production's key
// algorithm. DeployHQ mints 4096-bit RSA keys; the size is irrelevant here but
// the algorithm is not, because the pairing check is algorithm-specific.
func TestApplyWithRSAKeys(t *testing.T) {
	oldCA := testca.New(t, "old")
	newCA := testca.New(t, "new")
	agent := oldCA.IssueWithKey(t, agentCN, agentSerial, testca.KeyRSA)
	impostor := newCA.IssueWithKey(t, agentCN, agentSerial, testca.KeyRSA)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(certPath, agent.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, agent.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	req := certrenew.Request{
		CertPath: certPath,
		KeyPath:  keyPath,
		Roots:    testca.Pool(oldCA, newCA),
		Current:  agent.Cert,
	}

	req.CandidatePEM = impostor.CertPEM
	if _, err := certrenew.Apply(req); err == nil {
		t.Error("Apply accepted an RSA certificate for a different key")
	}

	req.CandidatePEM = newCA.Reissue(t, agent, agentCN, agentSerial)
	if _, err := certrenew.Apply(req); err != nil {
		t.Fatalf("Apply rejected a valid RSA renewal: %v", err)
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, req.CandidatePEM) {
		t.Error("RSA renewal was not written")
	}
}

// TestApplyWritesPrivateFile: the certificate itself is not secret, but the
// agent's ~/.deploy directory is 0700 and the renewal must not widen anything.
func TestApplyWritesPrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes do not apply on Windows")
	}
	f := newFixture(t)

	if _, err := certrenew.Apply(f.request(f.renewed)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	info, err := os.Stat(f.certPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("mode = %#o, want 0600", perm)
	}
}

// TestApplyReplacesAStaleTempFile: a crash mid-renewal can leave agent.crt.tmp
// behind. The next attempt must overwrite it rather than fail forever.
func TestApplyReplacesAStaleTempFile(t *testing.T) {
	f := newFixture(t)

	stale := f.certPath + ".tmp"
	if err := os.WriteFile(stale, []byte("leftover from a crashed renewal"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := certrenew.Apply(f.request(f.renewed)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Equal(f.onDisk(t), f.renewed) {
		t.Error("renewed certificate was not installed over a stale temp file")
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("temp file still present after a successful renewal")
	}
}

// TestLoadCurrent covers the helper the tunnel uses to learn which certificate
// it is presenting before asking the server to renew it.
func TestLoadCurrent(t *testing.T) {
	f := newFixture(t)

	cert, err := certrenew.LoadCurrent(f.certPath)
	if err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	if cert.Subject.CommonName != agentCN || cert.SerialNumber.Int64() != agentSerial {
		t.Errorf("loaded %q serial %s", cert.Subject.CommonName, cert.SerialNumber)
	}

	t.Run("missing file", func(t *testing.T) {
		if _, err := certrenew.LoadCurrent(filepath.Join(f.dir, "nope.crt")); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("not a certificate", func(t *testing.T) {
		path := filepath.Join(f.dir, "garbage.crt")
		if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := certrenew.LoadCurrent(path); err == nil {
			t.Error("expected an error")
		}
	})
}
