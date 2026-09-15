// Package testca mints certificates shaped like DeployHQ's real ones, for use
// in tests. It is imported only from _test.go files and so is not linked into
// the released binary.
//
// The shapes matter. DeployHQ's CA, its agent-server leaf and its agent client
// certificates all predate SAN-only verification:
//
//   - CA: CN "Deploy Dev CA (<name>)" under O=aTech Media Ltd, serial 1,
//     basicConstraints CA:TRUE, keyUsage certSign+crlSign.
//   - Leaves (both the server's and the agent's): a Common Name and nothing
//     else — no subjectAltName, no extendedKeyUsage, no keyUsage. The missing
//     SAN is exactly why config.NewTLSConfig needs its CN fallback, and the
//     missing EKU is why certificate verification has to ask for
//     ExtKeyUsageAny.
//
// Keys are ECDSA P-256 by default because tests generate a lot of them.
// Production uses 4096-bit RSA; pass KeyRSA where the key type is the thing
// under test.
package testca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// KeyType selects the key algorithm for a generated certificate.
type KeyType int

const (
	// KeyECDSA is a P-256 key: fast to generate, used everywhere the key
	// algorithm is irrelevant to what the test is proving.
	KeyECDSA KeyType = iota
	// KeyRSA is a 2048-bit RSA key, matching production's algorithm (production
	// uses 4096 bits; the size changes nothing that is under test here).
	KeyRSA
)

// CA is a self-signed certificate authority that can issue leaves.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte

	key crypto.Signer
}

// Identity is a key pair plus the certificate currently issued for it.
type Identity struct {
	Cert    *x509.Certificate
	CertPEM []byte
	KeyPEM  []byte

	key crypto.Signer
}

// New creates a CA named "Deploy Dev CA (<name>)".
func New(t *testing.T, name string) *CA {
	t.Helper()
	return NewWithKey(t, name, KeyECDSA)
}

// NewWithKey creates a CA with an explicit key algorithm.
func NewWithKey(t *testing.T, name string, kt KeyType) *CA {
	t.Helper()
	key := generateKey(t, kt)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject("Deploy Dev CA (" + name + ")"),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	return &CA{Cert: cert, CertPEM: certPEM(der), key: key}
}

// Pool returns a certificate pool trusting just this CA.
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// Issue mints a CN-only leaf with a fresh key pair.
func (ca *CA) Issue(t *testing.T, commonName string, serial int64) *Identity {
	t.Helper()
	return ca.IssueWithKey(t, commonName, serial, KeyECDSA)
}

// IssueWithKey mints a CN-only leaf with a fresh key pair of the given type.
func (ca *CA) IssueWithKey(t *testing.T, commonName string, serial int64, kt KeyType) *Identity {
	t.Helper()
	key := generateKey(t, kt)
	certPEMBytes, cert := ca.sign(t, key.Public(), commonName, serial)
	return &Identity{Cert: cert, CertPEM: certPEMBytes, KeyPEM: keyPEM(t, key), key: key}
}

// Reissue signs an existing identity's public key again under this CA — the
// renewal operation the backend performs. Passing the identity's own common
// name and serial produces a valid renewal; passing different ones produces the
// certificates a correct agent must refuse.
func (ca *CA) Reissue(t *testing.T, id *Identity, commonName string, serial int64) []byte {
	t.Helper()
	certPEMBytes, _ := ca.sign(t, id.key.Public(), commonName, serial)
	return certPEMBytes
}

func (ca *CA) sign(t *testing.T, pub crypto.PublicKey, commonName string, serial int64) ([]byte, *x509.Certificate) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      subject(commonName),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		// No SANs, no KeyUsage, no ExtKeyUsage: exactly as DeployHQ mints them.
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		t.Fatalf("signing certificate for %q: %v", commonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate for %q: %v", commonName, err)
	}
	return certPEM(der), cert
}

// TLS returns the identity as a tls.Certificate.
func (id *Identity) TLS(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		t.Fatalf("building tls.Certificate: %v", err)
	}
	return cert
}

// Bundle concatenates CA certificates into one PEM bundle, as internal/caroot's
// ca.crt holds them during a rotation.
func Bundle(cas ...*CA) []byte {
	var out []byte
	for _, ca := range cas {
		out = append(out, ca.CertPEM...)
	}
	return out
}

// Pool returns a pool trusting every given CA.
func Pool(cas ...*CA) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, ca := range cas {
		pool.AddCert(ca.Cert)
	}
	return pool
}

// subject mirrors lib/certificate_authority.rb's distinguished name.
func subject(commonName string) pkix.Name {
	return pkix.Name{
		Country:            []string{"GB"},
		Province:           []string{"Dorset"},
		Locality:           []string{"Poole"},
		Organization:       []string{"aTech Media Ltd"},
		OrganizationalUnit: []string{"Deploy"},
		CommonName:         commonName,
	}
}

func generateKey(t *testing.T, kt KeyType) crypto.Signer {
	t.Helper()
	switch kt {
	case KeyRSA:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generating RSA key: %v", err)
		}
		return key
	default:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating ECDSA key: %v", err)
		}
		return key
	}
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
