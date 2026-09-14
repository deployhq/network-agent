package config_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deployhq/network-agent/internal/config"
	"github.com/deployhq/network-agent/internal/testca"
)

const serverCN = "agent.deployhq.com"

// writeIdentity puts a key pair on disk the way `network-agent setup` does and
// returns the paths for it.
func writeIdentity(t *testing.T, id *testca.Identity) config.Paths {
	t.Helper()
	dir := t.TempDir()
	paths := config.Paths{
		Config:      dir,
		Certificate: filepath.Join(dir, "agent.crt"),
		Key:         filepath.Join(dir, "agent.key"),
	}
	if err := os.WriteFile(paths.Certificate, id.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Key, id.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return paths
}

// TestVerifyConnectionAcceptsEitherCAInTheBundle is the property the whole CA
// rotation rests on: one binary carrying a two-CA bundle must accept an agent
// server presenting a leaf from either CA, and nothing else.
func TestVerifyConnectionAcceptsEitherCAInTheBundle(t *testing.T) {
	t.Setenv("DEPLOY_AGENT_PROXY_IP", serverCN)

	oldCA := testca.New(t, "old")
	newCA := testca.New(t, "new")
	strangerCA := testca.New(t, "stranger")

	paths := writeIdentity(t, oldCA.Issue(t, "Deploy Agent #42", 42))

	cfg, err := config.NewTLSConfig(paths, testca.Bundle(oldCA, newCA), true)
	if err != nil {
		t.Fatalf("NewTLSConfig: %v", err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("VerifyConnection was not installed")
	}

	tests := []struct {
		name    string
		leaf    *x509.Certificate
		wantErr bool
	}{
		{"leaf from the outgoing CA", oldCA.Issue(t, serverCN, 1).Cert, false},
		{"leaf from the incoming CA", newCA.Issue(t, serverCN, 1).Cert, false},
		{"leaf from an untrusted CA", strangerCA.Issue(t, serverCN, 1).Cert, true},
		{"right CA, wrong common name", oldCA.Issue(t, "evil.example.com", 2).Cert, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.VerifyConnection(tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{tt.leaf},
			})
			if tt.wantErr && err == nil {
				t.Error("expected verification to fail, it succeeded")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected verification to succeed, got: %v", err)
			}
			if err != nil {
				t.Logf("rejected: %v", err)
			}
		})
	}

	t.Run("no certificate at all", func(t *testing.T) {
		if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
			t.Error("expected verification to fail when the server sends nothing")
		}
	})
}

// TestBundleOrderIsIrrelevant: nobody should have to think about which CA comes
// first in ca.crt when appending the new one.
func TestBundleOrderIsIrrelevant(t *testing.T) {
	t.Setenv("DEPLOY_AGENT_PROXY_IP", serverCN)

	oldCA := testca.New(t, "old")
	newCA := testca.New(t, "new")
	paths := writeIdentity(t, oldCA.Issue(t, "Deploy Agent #42", 42))

	leaves := map[string]*x509.Certificate{
		"old": oldCA.Issue(t, serverCN, 1).Cert,
		"new": newCA.Issue(t, serverCN, 1).Cert,
	}

	for name, bundle := range map[string][]byte{
		"old first": testca.Bundle(oldCA, newCA),
		"new first": testca.Bundle(newCA, oldCA),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.NewTLSConfig(paths, bundle, true)
			if err != nil {
				t.Fatalf("NewTLSConfig: %v", err)
			}
			for which, leaf := range leaves {
				if err := cfg.VerifyConnection(tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{leaf},
				}); err != nil {
					t.Errorf("%s leaf rejected: %v", which, err)
				}
			}
		})
	}
}

// TestGetClientCertificatePresentsRenewedCertificate is the regression test for
// the bug that made in-band renewal impossible: one *tls.Config is built at
// start-up and reused for every reconnect, so a client certificate cached in
// it would keep being presented until the process restarted.
//
// Replacing agent.crt on disk must change what the very next handshake
// presents, with no new config and no restart.
func TestGetClientCertificatePresentsRenewedCertificate(t *testing.T) {
	oldCA := testca.New(t, "old")
	newCA := testca.New(t, "new")

	agent := oldCA.Issue(t, "Deploy Agent #42", 42)
	paths := writeIdentity(t, agent)

	server := newTestServer(t, oldCA.Issue(t, serverCN, 1), testca.Pool(oldCA, newCA))

	// verify=false keeps the server's own certificate out of the picture; the
	// client certificate is what is under test and it is loaded the same way
	// on both paths.
	cfg, err := config.NewTLSConfig(paths, testca.Bundle(oldCA, newCA), false)
	if err != nil {
		t.Fatalf("NewTLSConfig: %v", err)
	}
	// Structural checks first, but non-fatal: the handshakes below are the real
	// evidence and should still run and report if these ever regress.
	if cfg.Certificates != nil {
		t.Error("Certificates is populated — a cached certificate cannot be renewed without a restart")
	}
	if cfg.GetClientCertificate == nil {
		t.Error("GetClientCertificate was not installed")
	}

	if got := server.issuerSeen(t, cfg); got != "Deploy Dev CA (old)" {
		t.Fatalf("first handshake presented issuer %q, want the old CA", got)
	}

	// The renewal: same key, same subject, same serial, new issuer.
	renewed := newCA.Reissue(t, agent, "Deploy Agent #42", 42)
	if err := os.WriteFile(paths.Certificate, renewed, 0600); err != nil {
		t.Fatal(err)
	}

	if got := server.issuerSeen(t, cfg); got != "Deploy Dev CA (new)" {
		t.Errorf("second handshake presented issuer %q, want the new CA — the certificate was not reloaded", got)
	}
}

// TestNewTLSConfigRejectsBadInputs: every one of these must fail loudly at
// start-up rather than at handshake time behind a customer firewall.
func TestNewTLSConfigRejectsBadInputs(t *testing.T) {
	ca := testca.New(t, "old")
	good := ca.Issue(t, "Deploy Agent #42", 42)
	other := ca.Issue(t, "Deploy Agent #42", 42) // same identity, different key

	t.Run("missing certificate", func(t *testing.T) {
		paths := writeIdentity(t, good)
		if err := os.Remove(paths.Certificate); err != nil {
			t.Fatal(err)
		}
		if _, err := config.NewTLSConfig(paths, ca.CertPEM, true); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("missing key", func(t *testing.T) {
		paths := writeIdentity(t, good)
		if err := os.Remove(paths.Key); err != nil {
			t.Fatal(err)
		}
		if _, err := config.NewTLSConfig(paths, ca.CertPEM, true); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("certificate and key do not match", func(t *testing.T) {
		paths := writeIdentity(t, good)
		if err := os.WriteFile(paths.Key, other.KeyPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := config.NewTLSConfig(paths, ca.CertPEM, true); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("unparsable CA bundle", func(t *testing.T) {
		paths := writeIdentity(t, good)
		if _, err := config.NewTLSConfig(paths, []byte("not a certificate"), true); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestNewCertPool(t *testing.T) {
	oldCA := testca.New(t, "old")
	newCA := testca.New(t, "new")

	if _, err := config.NewCertPool(testca.Bundle(oldCA, newCA)); err != nil {
		t.Errorf("two-CA bundle: %v", err)
	}
	if _, err := config.NewCertPool(nil); err == nil {
		t.Error("empty bundle should be an error")
	}
	if _, err := config.NewCertPool([]byte("garbage")); err == nil {
		t.Error("unparsable bundle should be an error")
	}
}

// ── test server ──────────────────────────────────────────────────────────────

// testServer accepts one mTLS connection at a time and reports the issuer of
// the client certificate it was shown.
type testServer struct {
	ln net.Listener
}

func newTestServer(t *testing.T, leaf *testca.Identity, clientCAs *x509.CertPool) *testServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leaf.TLS(t)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return &testServer{ln: ln}
}

// issuerSeen dials the server with cfg and returns the issuer common name of
// the client certificate the server was actually shown — the only authority on
// which certificate went on the wire.
func (s *testServer) issuerSeen(t *testing.T, cfg *tls.Config) string {
	t.Helper()

	type result struct {
		issuer string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := s.ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		tc := conn.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			done <- result{err: err}
			return
		}
		peer := tc.ConnectionState().PeerCertificates
		if len(peer) == 0 {
			done <- result{err: errors.New("server saw no client certificate")}
			return
		}
		done <- result{issuer: peer[0].Issuer.CommonName}
	}()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", s.ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("dialling test server: %v", err)
	}
	defer conn.Close()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("test server: %v", r.err)
		}
		return r.issuer
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for the test server")
		return ""
	}
}
