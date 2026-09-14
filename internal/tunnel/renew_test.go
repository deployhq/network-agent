package tunnel_test

// In-band certificate renewal over the tunnel.
//
// The exchange under test: the agent sends RENEW_REQUEST once per connection
// carrying "go/<version>"; the server answers RENEW_RESPONSE with status
// RENEWED (a re-signed certificate), CURRENT, or ERROR. Only RENEWED writes
// anything, and only after the new certificate has been fully validated.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deployhq/network-agent/internal/acl"
	"github.com/deployhq/network-agent/internal/certrenew"
	"github.com/deployhq/network-agent/internal/config"
	"github.com/deployhq/network-agent/internal/protocol"
	"github.com/deployhq/network-agent/internal/testca"
	"github.com/deployhq/network-agent/internal/tunnel"
)

const (
	agentCN     = "Deploy Agent #42"
	agentSerial = 42
	testVersion = "1.2.3"
)

// renewFixture wires a real mTLS connection between a fake DeployHQ server and
// an agent whose client certificate lives on disk, so a renewal that replaces
// that file is observable exactly as it would be in production.
type renewFixture struct {
	certPath string
	keyPath  string

	originalPEM  []byte // what agent.crt held before the exchange
	renewedPEM   []byte // a legitimate renewal: same key, subject and serial
	untrustedPEM []byte // signed by a CA the agent does not trust

	ln   net.Listener
	opts tunnel.Options
	cfg  *tls.Config
}

func newRenewFixture(t *testing.T) *renewFixture {
	t.Helper()

	oldCA := testca.New(t, "old")
	newCA := testca.New(t, "new")
	otherCA := testca.New(t, "someone else")

	agent := oldCA.Issue(t, agentCN, agentSerial)
	server := oldCA.Issue(t, "agent.deployhq.com", 1)

	dir := t.TempDir()
	f := &renewFixture{
		certPath:     filepath.Join(dir, "agent.crt"),
		keyPath:      filepath.Join(dir, "agent.key"),
		originalPEM:  agent.CertPEM,
		renewedPEM:   newCA.Reissue(t, agent, agentCN, agentSerial),
		untrustedPEM: otherCA.Reissue(t, agent, agentCN, agentSerial),
	}
	if err := os.WriteFile(f.certPath, agent.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.keyPath, agent.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// The server trusts both CAs, as the backend does throughout a rotation.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{server.TLS(t)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    testca.Pool(oldCA, newCA),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f.ln = ln

	paths := config.Paths{Certificate: f.certPath, Key: f.keyPath}

	// verify=false: the server's own certificate is not what these tests are
	// about, and it keeps the fixture free of hostname gymnastics. The client
	// certificate is still loaded from disk per handshake either way.
	cfg, err := config.NewTLSConfig(paths, testca.Bundle(oldCA, newCA), false)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg = cfg
	f.opts = tunnel.Options{
		Version: testVersion,
		Paths:   paths,
		CARoots: testca.Pool(oldCA, newCA),
	}
	return f
}

// connect starts the agent and returns the accepted server-side connection.
func (f *renewFixture) connect(t *testing.T, opts tunnel.Options) (net.Conn, <-chan error) {
	t.Helper()
	errc := runAgentConn(t, f.cfg, f.ln.Addr().String(), acl.Parse("127.0.0.1"), opts)

	connCh := make(chan net.Conn, 1)
	go func() {
		conn, err := f.ln.Accept()
		if err == nil {
			connCh <- conn
		}
	}()
	select {
	case conn := <-connCh:
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		t.Cleanup(func() { conn.Close() })
		// Accept returns before the handshake runs, so force it here: the
		// client certificate the agent presented is the whole point of these
		// tests and it is not observable until the handshake completes.
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			t.Fatalf("server-side handshake: %v", err)
		}
		return conn, errc
	case <-time.After(5 * time.Second):
		t.Fatal("timeout accepting agent connection")
		return nil, nil
	}
}

// peerIssuerCN reports the issuer of the client certificate the agent
// presented — the authoritative answer to "which certificate went on the wire".
func peerIssuerCN(t *testing.T, conn net.Conn) string {
	t.Helper()
	peer := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(peer) == 0 {
		t.Fatal("server saw no client certificate")
	}
	return peer[0].Issuer.CommonName
}

func (f *renewFixture) certOnDisk(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(f.certPath)
	if err != nil {
		t.Fatalf("reading %s: %v", f.certPath, err)
	}
	return data
}

// TestRenewRequestSentOnConnect: the request goes out once, immediately after
// the handshake, carrying the implementation and version the backend needs to
// tell Go agents from Ruby ones.
func TestRenewRequestSentOnConnect(t *testing.T) {
	f := newRenewFixture(t)
	serverConn, errc := f.connect(t, f.opts)
	rd := newServerReader(t, serverConn)

	pkt := rd.next()
	if pkt.Cmd != protocol.CmdRenewRequest {
		t.Fatalf("first packet cmd = %d, want %d (RENEW_REQUEST)", pkt.Cmd, protocol.CmdRenewRequest)
	}
	if got := protocol.ParseRenewRequest(pkt.Payload); got != "go/"+testVersion {
		t.Errorf("identifier = %q, want %q", got, "go/"+testVersion)
	}

	stopAgent(t, serverConn, errc)
}

// TestNoRenewRequestWhenRenewalDisabled: with zero Options — no CA roots, no
// paths — the agent must not ask. An agent that cannot safely install a
// certificate has no business requesting one.
func TestNoRenewRequestWhenRenewalDisabled(t *testing.T) {
	f := newRenewFixture(t)
	serverConn, errc := f.connect(t, tunnel.Options{})
	rd := newServerReader(t, serverConn)

	echoHost, echoPort := startEchoTarget(t)
	if _, err := serverConn.Write(buildCreateRequest(1, echoHost, echoPort)); err != nil {
		t.Fatal(err)
	}

	// A renewal request would have been queued before anything else, so the
	// first non-keepalive packet proves whether one was sent.
	pkt := rd.next()
	if pkt.Cmd == protocol.CmdRenewRequest {
		t.Fatal("agent sent RENEW_REQUEST with renewal disabled")
	}
	if pkt.Cmd != protocol.CmdCreateResponse {
		t.Fatalf("first packet cmd = %d, want %d (CREATE_RESPONSE)", pkt.Cmd, protocol.CmdCreateResponse)
	}

	stopAgent(t, serverConn, errc)
}

// TestRenewedCertificateIsInstalledAndConnectionRecycled is the happy path:
// the certificate on disk is replaced and Run returns the reconnect signal, so
// the next handshake presents the new certificate.
func TestRenewedCertificateIsInstalledAndConnectionRecycled(t *testing.T) {
	f := newRenewFixture(t)
	serverConn, errc := f.connect(t, f.opts)

	if got := peerIssuerCN(t, serverConn); got != "Deploy Dev CA (old)" {
		t.Fatalf("first connection presented issuer %q, want the old CA", got)
	}

	if _, err := serverConn.Write(protocol.EncodeRenewResponse(protocol.RenewStatusRenewed, f.renewedPEM)); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errc:
		if !errors.Is(err, tunnel.ErrCertificateRenewed) {
			t.Fatalf("Run returned %v, want ErrCertificateRenewed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: agent did not recycle the connection after renewal")
	}

	if got := f.certOnDisk(t); !bytes.Equal(got, f.renewedPEM) {
		t.Fatal("agent.crt does not hold the renewed certificate")
	}

	installed, err := certrenew.LoadCurrent(f.certPath)
	if err != nil {
		t.Fatal(err)
	}
	if installed.Issuer.CommonName != "Deploy Dev CA (new)" {
		t.Errorf("issuer = %q, want the new CA", installed.Issuer.CommonName)
	}
	if installed.SerialNumber.Int64() != agentSerial || installed.Subject.CommonName != agentCN {
		t.Errorf("renewal changed the agent's identity: %q serial %s",
			installed.Subject.CommonName, installed.SerialNumber)
	}

	// A reconnect is only useful if the renewed certificate is actually
	// presented, which is what GetClientCertificate buys — prove it end to end.
	serverConn.Close()
	next, nextErrc := f.connect(t, f.opts)
	if got := peerIssuerCN(t, next); got != "Deploy Dev CA (new)" {
		t.Errorf("second connection presented issuer %q, want the new CA", got)
	}
	stopAgent(t, next, nextErrc)
}

// TestRenewResponseStatusesThatWriteNothing: CURRENT and ERROR are normal
// answers, not failures. Neither may touch agent.crt and neither may drop the
// tunnel — the agent is mid-deployment as far as it knows.
func TestRenewResponseStatusesThatWriteNothing(t *testing.T) {
	tests := []struct {
		name   string
		status byte
		body   func(f *renewFixture) []byte
	}{
		{"current", protocol.RenewStatusCurrent, func(*renewFixture) []byte { return nil }},
		{"error", protocol.RenewStatusError, func(*renewFixture) []byte { return []byte("agent has no certificate on file") }},
		{"renewed but untrusted issuer", protocol.RenewStatusRenewed, func(f *renewFixture) []byte { return f.untrustedPEM }},
		{"renewed but malformed", protocol.RenewStatusRenewed, func(*renewFixture) []byte { return []byte("not a certificate") }},
		{"renewed with an empty body", protocol.RenewStatusRenewed, func(*renewFixture) []byte { return nil }},
		{"unknown status", 200, func(*renewFixture) []byte { return nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRenewFixture(t)
			serverConn, errc := f.connect(t, f.opts)
			rd := newServerReader(t, serverConn)

			if pkt := rd.next(); pkt.Cmd != protocol.CmdRenewRequest {
				t.Fatalf("expected RENEW_REQUEST first, got cmd=%d", pkt.Cmd)
			}

			if _, err := serverConn.Write(protocol.EncodeRenewResponse(tt.status, tt.body(f))); err != nil {
				t.Fatal(err)
			}

			// The connection must still be serving traffic afterwards.
			echoHost, echoPort := startEchoTarget(t)
			if _, err := serverConn.Write(buildCreateRequest(5, echoHost, echoPort)); err != nil {
				t.Fatal(err)
			}
			resp := rd.next()
			if resp.Cmd != protocol.CmdCreateResponse {
				t.Fatalf("expected CREATE_RESPONSE, got cmd=%d — connection did not survive", resp.Cmd)
			}
			if _, status, reason, _ := protocol.ParseCreateResponse(resp.Payload); status != 0 {
				t.Fatalf("CREATE_RESPONSE status=%d reason=%q", status, reason)
			}

			if got := f.certOnDisk(t); !bytes.Equal(got, f.originalPEM) {
				t.Error("agent.crt was modified")
			}
			if _, err := os.Stat(f.certPath + ".tmp"); err == nil {
				t.Error("temporary file left behind")
			}

			select {
			case err := <-errc:
				t.Fatalf("agent exited: %v", err)
			default:
			}

			stopAgent(t, serverConn, errc)
		})
	}
}

// TestMalformedRenewResponseIgnored: a zero-length payload cannot carry a
// status byte. It must be shrugged off, like any other frame the agent cannot
// make sense of.
func TestMalformedRenewResponseIgnored(t *testing.T) {
	f := newRenewFixture(t)
	serverConn, errc := f.connect(t, f.opts)
	rd := newServerReader(t, serverConn)

	if pkt := rd.next(); pkt.Cmd != protocol.CmdRenewRequest {
		t.Fatalf("expected RENEW_REQUEST first, got cmd=%d", pkt.Cmd)
	}

	if _, err := serverConn.Write(protocol.EncodePacket(protocol.CmdRenewResponse, nil)); err != nil {
		t.Fatal(err)
	}

	echoHost, echoPort := startEchoTarget(t)
	if _, err := serverConn.Write(buildCreateRequest(9, echoHost, echoPort)); err != nil {
		t.Fatal(err)
	}
	if resp := rd.next(); resp.Cmd != protocol.CmdCreateResponse {
		t.Fatalf("expected CREATE_RESPONSE, got cmd=%d", resp.Cmd)
	}
	if got := f.certOnDisk(t); !bytes.Equal(got, f.originalPEM) {
		t.Error("agent.crt was modified")
	}

	stopAgent(t, serverConn, errc)
}

// TestRenewResponseIgnoredWhenRenewalDisabled: the server never sends one
// unsolicited, so this can only happen if something has gone wrong. Ignore it
// rather than writing a certificate that could not be verified.
func TestRenewResponseIgnoredWhenRenewalDisabled(t *testing.T) {
	f := newRenewFixture(t)
	serverConn, errc := f.connect(t, tunnel.Options{})
	rd := newServerReader(t, serverConn)

	if _, err := serverConn.Write(protocol.EncodeRenewResponse(protocol.RenewStatusRenewed, f.renewedPEM)); err != nil {
		t.Fatal(err)
	}

	echoHost, echoPort := startEchoTarget(t)
	if _, err := serverConn.Write(buildCreateRequest(3, echoHost, echoPort)); err != nil {
		t.Fatal(err)
	}
	if resp := rd.next(); resp.Cmd != protocol.CmdCreateResponse {
		t.Fatalf("expected CREATE_RESPONSE, got cmd=%d", resp.Cmd)
	}
	if got := f.certOnDisk(t); !bytes.Equal(got, f.originalPEM) {
		t.Error("agent.crt was modified with renewal disabled")
	}

	stopAgent(t, serverConn, errc)
}

// TestUnknownCommandsAreStillTolerated: adding commands 8 and 9 must not have
// narrowed what the agent shrugs off. Deployed v0.2.0 agents ignore unknown
// bytes, and this build has to keep doing the same for whatever comes next.
func TestUnknownCommandsAreStillTolerated(t *testing.T) {
	certs := generateTestCerts(t)
	srv := newFakeServer(t, certs)
	errc := connectAgent(t, srv.addr(), certs, acl.Parse("127.0.0.1"))

	serverConn := srv.accept()
	defer serverConn.Close()
	rd := newServerReader(t, serverConn)

	for _, cmd := range []byte{10, 99, 200, 255} {
		if _, err := serverConn.Write(protocol.EncodePacket(cmd, []byte("payload"))); err != nil {
			t.Fatalf("writing cmd %d: %v", cmd, err)
		}
	}

	select {
	case err := <-errc:
		t.Fatalf("agent exited after unknown commands: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	echoHost, echoPort := startEchoTarget(t)
	if _, err := serverConn.Write(buildCreateRequest(77, echoHost, echoPort)); err != nil {
		t.Fatal(err)
	}
	resp := rd.next()
	if resp.Cmd != protocol.CmdCreateResponse {
		t.Fatalf("expected CREATE_RESPONSE after unknown commands, got cmd=%d", resp.Cmd)
	}

	stopAgent(t, serverConn, errc)
}

// TestRenewalDisabledWithoutRoots pins the individual preconditions: every one
// of them is required, so a half-configured agent never writes a certificate.
func TestRenewalRequiresCompleteOptions(t *testing.T) {
	full := tunnel.Options{
		Version: testVersion,
		Paths:   config.Paths{Certificate: "/tmp/agent.crt", Key: "/tmp/agent.key"},
		CARoots: x509.NewCertPool(),
	}

	tests := []struct {
		name   string
		mutate func(o *tunnel.Options)
	}{
		{"no CA roots", func(o *tunnel.Options) { o.CARoots = nil }},
		{"no certificate path", func(o *tunnel.Options) { o.Paths.Certificate = "" }},
		{"no key path", func(o *tunnel.Options) { o.Paths.Key = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRenewFixture(t)
			opts := full
			tt.mutate(&opts)

			serverConn, errc := f.connect(t, opts)
			rd := newServerReader(t, serverConn)

			echoHost, echoPort := startEchoTarget(t)
			if _, err := serverConn.Write(buildCreateRequest(1, echoHost, echoPort)); err != nil {
				t.Fatal(err)
			}
			if pkt := rd.next(); pkt.Cmd == protocol.CmdRenewRequest {
				t.Error("agent asked for renewal despite incomplete options")
			}

			stopAgent(t, serverConn, errc)
		})
	}
}
