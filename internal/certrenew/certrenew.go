// Package certrenew validates a certificate the DeployHQ backend has re-issued
// for this agent and installs it over ~/.deploy/agent.crt.
//
// Renewal happens during a CA rotation: the backend re-signs the public key it
// already holds for the agent under the new CA, preserving the subject and the
// serial number that identify the agent, so the agent keeps its existing
// private key and only the certificate file changes.
//
// Two properties matter more than anything else here:
//
//   - Nothing is written unless every check passes. A bad certificate that
//     replaced a good one would take the agent offline behind a customer
//     firewall, where nobody can fix it.
//   - The replacement is atomic. A reader must see either the whole old
//     certificate or the whole new one, never a truncated file.
package certrenew

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrUnchanged reports that the offered certificate is byte for byte the one
// already installed, so there is nothing to write.
//
// It is a normal outcome, not a failure: a server that keeps answering RENEWED
// with the certificate the agent already has must not push it through a
// connect-renew-reconnect loop forever.
var ErrUnchanged = errors.New("certificate is already installed")

// renameAttempts / renameDelay bound the retry loop around the final rename.
//
// On Unix os.Rename is a single atomic syscall and never needs a retry. On
// Windows it is MoveFileEx(MOVEFILE_REPLACE_EXISTING), which fails with a
// sharing violation while another process (antivirus, a backup agent, an
// installer) holds the destination open without FILE_SHARE_DELETE. Those holds
// are short, so retrying a few times turns a transient collision into a
// successful renewal instead of a skipped one.
const (
	renameAttempts = 5
	renameDelay    = 200 * time.Millisecond
)

// Request describes a single renewal attempt.
type Request struct {
	// CertPath is the certificate file to replace (~/.deploy/agent.crt).
	CertPath string

	// KeyPath is the agent's private key. It is never written; the candidate
	// certificate must pair with the key already on disk.
	KeyPath string

	// Roots are the trust anchors the candidate certificate must chain to —
	// the same CA bundle the agent uses to verify the server.
	Roots *x509.CertPool

	// Current is the certificate the agent is using now. The candidate must
	// carry the same subject and serial number, because those are how the
	// backend identifies this agent.
	Current *x509.Certificate

	// CandidatePEM is the PEM-encoded certificate offered by the server.
	CandidatePEM []byte
}

// Apply validates req.CandidatePEM and, only when every check passes and the
// certificate actually differs from the one installed, atomically replaces the
// file at req.CertPath with it.
//
// On any error — ErrUnchanged included — nothing has been written and the
// existing certificate file is untouched. The returned certificate is the newly
// installed one.
func Apply(req Request) (*x509.Certificate, error) {
	candidate, err := Validate(req)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(req.CertPath, req.CandidatePEM); err != nil {
		return nil, err
	}
	return candidate, nil
}

// Validate runs every check on the candidate certificate without touching the
// filesystem except to read the private key. It is separated from Apply so the
// checks can be exercised — and reasoned about — on their own.
func Validate(req Request) (*x509.Certificate, error) {
	if req.Current == nil {
		return nil, fmt.Errorf("no current certificate to compare against")
	}
	if req.Roots == nil {
		return nil, fmt.Errorf("no CA roots to verify against")
	}

	block, _ := pem.Decode(req.CandidatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("renewed certificate is not a PEM certificate")
	}
	candidate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing renewed certificate: %w", err)
	}

	// (a) The certificate must pair with the private key already on disk.
	// tls.X509KeyPair does exactly this comparison, for every key type Go
	// supports, and fails with "private key does not match public key".
	keyPEM, err := os.ReadFile(req.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key %s: %w", req.KeyPath, err)
	}
	if _, err := tls.X509KeyPair(req.CandidatePEM, keyPEM); err != nil {
		return nil, fmt.Errorf("renewed certificate does not pair with %s: %w", req.KeyPath, err)
	}

	// (b) Subject and serial identify the agent to the backend. A renewal
	// changes the issuer, never the identity — anything else is not a renewal
	// of *this* agent's certificate and must not overwrite it.
	if !bytes.Equal(candidate.RawSubject, req.Current.RawSubject) {
		return nil, fmt.Errorf("renewed certificate subject %q does not match current %q",
			candidate.Subject.String(), req.Current.Subject.String())
	}
	if candidate.SerialNumber.Cmp(req.Current.SerialNumber) != 0 {
		return nil, fmt.Errorf("renewed certificate serial %s does not match current %s",
			candidate.SerialNumber, req.Current.SerialNumber)
	}

	// (c) The certificate must chain to a CA this agent trusts. Mirrors the
	// VerifyOptions used by config.NewTLSConfig's VerifyConnection: roots only
	// and no DNSName, because DeployHQ's certificates are CN-only with no SANs.
	// KeyUsageAny because an agent certificate carries no extended key usage
	// extension at all and the zero value of KeyUsages would demand ServerAuth.
	if _, err := candidate.Verify(x509.VerifyOptions{
		Roots:     req.Roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("renewed certificate does not verify against the trusted CAs: %w", err)
	}

	// Last, once the candidate is known good: is it the one already installed?
	// Compare the DER, so PEM line endings or trailing whitespace cannot make
	// an identical certificate look like a new one.
	if bytes.Equal(candidate.Raw, req.Current.Raw) {
		return candidate, ErrUnchanged
	}

	return candidate, nil
}

// LoadCurrent reads and parses the certificate currently installed at path.
func LoadCurrent(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s is not a PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cert, nil
}

// writeAtomic writes data to "<dst>.tmp" in dst's own directory, flushes it to
// stable storage, and renames it over dst. Same directory so the rename stays
// within one filesystem, which is what makes it atomic.
func writeAtomic(dst string, data []byte) error {
	tmp := dst + ".tmp"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("syncing %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("closing %s: %w", tmp, err)
	}

	if err := renameWithRetry(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// renameWithRetry renames src over dst, retrying a few times so a transient
// Windows sharing violation does not abandon an otherwise valid renewal.
func renameWithRetry(src, dst string) error {
	var err error
	for attempt := 1; attempt <= renameAttempts; attempt++ {
		if err = os.Rename(src, dst); err == nil {
			return nil
		}
		if attempt < renameAttempts {
			time.Sleep(renameDelay)
		}
	}
	return fmt.Errorf("replacing %s after %d attempts: %w", filepath.Base(dst), renameAttempts, err)
}
