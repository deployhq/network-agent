package tunnel_test

// Integration tests that drive the full protocol exchange in-process.
//
// Architecture:
//
//	fake server (TLS listener) ←mTLS→ ServerConn (Go agent)
//	                                         ↓ TCP
//	                                   echo / close-immediately target
//
// Test-scoped TLS certificates are generated in memory — no files on disk.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/deployhq/network-agent/internal/acl"
	"github.com/deployhq/network-agent/internal/protocol"
	"github.com/deployhq/network-agent/internal/tunnel"
)

// ── TLS cert helpers ─────────────────────────────────────────────────────────

type testCerts struct {
	caPool     *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

func generateTestCerts(t *testing.T) *testCerts {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	sign := func(serial int64, tmpl *x509.Certificate) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.SerialNumber = big.NewInt(serial)
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, _ := x509.MarshalECPrivateKey(key)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	serverCert := sign(2, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "test-server"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	clientCert := sign(3, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "test-agent"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return &testCerts{caPool: caPool, serverCert: serverCert, clientCert: clientCert}
}

// ── Fake server ──────────────────────────────────────────────────────────────

type fakeServer struct {
	ln net.Listener
	t  *testing.T
}

func newFakeServer(t *testing.T, certs *testCerts) *fakeServer {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{certs.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certs.caPool,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return &fakeServer{ln: ln, t: t}
}

func (s *fakeServer) addr() string { return s.ln.Addr().String() }

func (s *fakeServer) accept() net.Conn {
	s.t.Helper()
	connCh := make(chan net.Conn, 1)
	go func() {
		conn, err := s.ln.Accept()
		if err == nil {
			connCh <- conn
		}
	}()
	select {
	case conn := <-connCh:
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		return conn
	case <-time.After(5 * time.Second):
		s.t.Fatal("fakeServer.accept: timeout")
		return nil
	}
}

// ── serverReader ─────────────────────────────────────────────────────────────

// serverReader accumulates raw bytes from a conn and returns decoded packets,
// silently skipping KEEPALIVE packets.
type serverReader struct {
	conn net.Conn
	buf  []byte
	t    *testing.T
}

func newServerReader(t *testing.T, conn net.Conn) *serverReader {
	return &serverReader{conn: conn, t: t}
}

func (r *serverReader) next() protocol.Packet {
	r.t.Helper()
	tmp := make([]byte, 4096)
	for {
		pkts, remaining := protocol.DecodePackets(r.buf)
		r.buf = remaining
		for _, p := range pkts {
			if p.Cmd != protocol.CmdKeepalive {
				return p
			}
		}
		r.conn.SetDeadline(time.Now().Add(5 * time.Second))
		n, err := r.conn.Read(tmp)
		if n > 0 {
			r.buf = append(r.buf, tmp[:n]...)
		}
		if err != nil {
			r.t.Fatalf("serverReader.next: %v", err)
		}
	}
}

// ── Agent helper ─────────────────────────────────────────────────────────────

// connectAgent starts the agent in a goroutine and returns immediately.
// The TLS handshake completes once the caller's fake server calls accept().
func connectAgent(t *testing.T, serverAddr string, certs *testCerts, access *acl.AccessList) <-chan error {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{certs.clientCert},
		RootCAs:      certs.caPool,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	errc := make(chan error, 1)
	go func() {
		sc, err := tunnel.Connect(cfg, serverAddr, access, log)
		if err != nil {
			errc <- err
			return
		}
		errc <- sc.Run()
	}()
	return errc
}

// ── TCP target helpers ───────────────────────────────────────────────────────

// startEchoTarget starts a TCP server that echoes all data back.
// Returns host and port strings.
func startEchoTarget(t *testing.T) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), fmt.Sprint(addr.Port)
}

// startCloseImmediateTarget starts a TCP server that closes the connection right after accepting.
func startCloseImmediateTarget(t *testing.T) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), fmt.Sprint(addr.Port)
}

// stopAgent sends REJECT to cleanly terminate the agent and waits for Run() to return.
func stopAgent(t *testing.T, serverConn net.Conn, errc <-chan error) {
	t.Helper()
	serverConn.Write(protocol.EncodePacket(protocol.CmdReject, []byte("test done")))
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for agent to stop")
	}
}

// buildCreateRequest encodes a CREATE_REQUEST frame (server→agent direction).
// Mirrors: send_packet([COMMAND_CREATE_REQUEST, id, "#{host}/#{port}"].pack('Cna*'))
func buildCreateRequest(connID uint16, host, port string) []byte {
	hostPort := host + "/" + port
	payload := make([]byte, 2+len(hostPort))
	payload[0] = byte(connID >> 8)
	payload[1] = byte(connID)
	copy(payload[2:], hostPort)
	return protocol.EncodePacket(protocol.CmdCreateRequest, payload)
}

// ── Tests ────────────────────────────────────────────────────────────────────

// TestFullDataFlow: CREATE_REQUEST → data echo → DESTROY
func TestFullDataFlow(t *testing.T) {
	certs := generateTestCerts(t)
	srv := newFakeServer(t, certs)
	errc := connectAgent(t, srv.addr(), certs, acl.Parse("127.0.0.1"))

	serverConn := srv.accept()
	defer serverConn.Close()
	rd := newServerReader(t, serverConn)

	echoHost, echoPort := startEchoTarget(t)
	connID := uint16(1)

	// CREATE_REQUEST
	serverConn.Write(buildCreateRequest(connID, echoHost, echoPort))

	// Expect CREATE_RESPONSE status=0
	resp := rd.next()
	if resp.Cmd != protocol.CmdCreateResponse {
		t.Fatalf("expected CREATE_RESPONSE, got cmd=%d", resp.Cmd)
	}
	gotID, status, reason, _ := protocol.ParseCreateResponse(resp.Payload)
	if gotID != connID || status != 0 {
		t.Fatalf("CREATE_RESPONSE id=%d status=%d reason=%q", gotID, status, reason)
	}

	// DATA round-trip
	serverConn.Write(protocol.EncodeData(connID, []byte("hello")))
	data := rd.next()
	if data.Cmd != protocol.CmdData {
		t.Fatalf("expected DATA, got cmd=%d", data.Cmd)
	}
	_, payload, _ := protocol.ParseData(data.Payload)
	if string(payload) != "hello" {
		t.Errorf("echo: got %q, want %q", payload, "hello")
	}

	// DESTROY
	serverConn.Write(protocol.EncodeDestroy(connID))

	stopAgent(t, serverConn, errc)
}

// TestACLDenied: request to a host not in the access list gets status=1 immediately.
func TestACLDenied(t *testing.T) {
	certs := generateTestCerts(t)
	srv := newFakeServer(t, certs)
	errc := connectAgent(t, srv.addr(), certs, acl.Parse("127.0.0.1")) // 10.0.0.1 not allowed

	serverConn := srv.accept()
	defer serverConn.Close()
	rd := newServerReader(t, serverConn)

	serverConn.Write(buildCreateRequest(1, "10.0.0.1", "22"))

	resp := rd.next()
	if resp.Cmd != protocol.CmdCreateResponse {
		t.Fatalf("expected CREATE_RESPONSE, got cmd=%d", resp.Cmd)
	}
	_, status, reason, _ := protocol.ParseCreateResponse(resp.Payload)
	if status != 1 {
		t.Errorf("expected status=1 (denied), got %d", status)
	}
	if reason == "" {
		t.Error("expected non-empty denial reason")
	}
	t.Logf("denial reason: %s", reason)

	stopAgent(t, serverConn, errc)
}

// TestREJECT_StopsAgent: REJECT causes Run() to return ErrRejected, no reconnect.
func TestREJECT_StopsAgent(t *testing.T) {
	certs := generateTestCerts(t)
	srv := newFakeServer(t, certs)
	errc := connectAgent(t, srv.addr(), certs, acl.Parse("127.0.0.1"))

	serverConn := srv.accept()
	defer serverConn.Close()

	serverConn.Write(protocol.EncodePacket(protocol.CmdReject, []byte("not authorised")))

	select {
	case err := <-errc:
		var rejected tunnel.ErrRejected
		if !errors.As(err, &rejected) {
			t.Errorf("expected ErrRejected, got %T: %v", err, err)
		}
		if rejected.Reason != "not authorised" {
			t.Errorf("reason: got %q, want %q", rejected.Reason, "not authorised")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: agent did not stop after REJECT")
	}
}

// TestDestinationUnreachable: agent returns CREATE_RESPONSE(status=1) when dial fails.
func TestDestinationUnreachable(t *testing.T) {
	certs := generateTestCerts(t)
	srv := newFakeServer(t, certs)
	errc := connectAgent(t, srv.addr(), certs, acl.Parse("127.0.0.1"))

	serverConn := srv.accept()
	defer serverConn.Close()
	rd := newServerReader(t, serverConn)

	// Port 1 is virtually guaranteed closed
	serverConn.Write(buildCreateRequest(7, "127.0.0.1", "1"))

	resp := rd.next()
	if resp.Cmd != protocol.CmdCreateResponse {
		t.Fatalf("expected CREATE_RESPONSE, got cmd=%d", resp.Cmd)
	}
	_, status, reason, _ := protocol.ParseCreateResponse(resp.Payload)
	if status != 1 {
		t.Errorf("expected status=1 (unreachable), got %d", status)
	}
	if reason == "" {
		t.Error("expected non-empty error reason")
	}
	t.Logf("dial error: %s", reason)

	stopAgent(t, serverConn, errc)
}

// TestConcurrentConnections: 5 simultaneous CREATE_REQUESTs all succeed.
// Also exercises the ServerConn.dests map under the race detector.
func TestConcurrentConnections(t *testing.T) {
	const n = 5

	certs := generateTestCerts(t)
	srv := newFakeServer(t, certs)
	errc := connectAgent(t, srv.addr(), certs, acl.Parse("127.0.0.1"))

	serverConn := srv.accept()
	defer serverConn.Close()

	// Start n echo targets
	targets := make([][2]string, n)
	for i := range targets {
		h, p := startEchoTarget(t)
		targets[i] = [2]string{h, p}
	}

	// Send all CREATE_REQUESTs concurrently
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			serverConn.Write(buildCreateRequest(id, targets[id-1][0], targets[id-1][1]))
		}(uint16(i + 1))
	}
	wg.Wait()

	// Collect n CREATE_RESPONSEs (order may vary)
	serverConn.SetDeadline(time.Now().Add(10 * time.Second))
	rd := newServerReader(t, serverConn)
	responses := make(map[uint16]byte)
	for i := 0; i < n; i++ {
		pkt := rd.next()
		if pkt.Cmd != protocol.CmdCreateResponse {
			t.Fatalf("[%d] expected CREATE_RESPONSE, got cmd=%d", i, pkt.Cmd)
		}
		connID, status, _, _ := protocol.ParseCreateResponse(pkt.Payload)
		responses[connID] = status
	}

	for id := uint16(1); id <= n; id++ {
		status, found := responses[id]
		if !found {
			t.Errorf("no response for conn=%d", id)
		} else if status != 0 {
			t.Errorf("conn=%d expected status=0, got %d", id, status)
		}
	}

	stopAgent(t, serverConn, errc)
}

// TestMultipleDataExchanges: several DATA packets on one connection are echoed in order.
func TestMultipleDataExchanges(t *testing.T) {
	certs := generateTestCerts(t)
	srv := newFakeServer(t, certs)
	errc := connectAgent(t, srv.addr(), certs, acl.Parse("127.0.0.1"))

	serverConn := srv.accept()
	defer serverConn.Close()
	rd := newServerReader(t, serverConn)

	echoHost, echoPort := startEchoTarget(t)
	connID := uint16(1)

	serverConn.Write(buildCreateRequest(connID, echoHost, echoPort))
	if resp := rd.next(); resp.Cmd != protocol.CmdCreateResponse {
		t.Fatalf("expected CREATE_RESPONSE, got %d", resp.Cmd)
	}

	for _, msg := range []string{"foo", "bar", "baz", "qux"} {
		serverConn.Write(protocol.EncodeData(connID, []byte(msg)))
		pkt := rd.next()
		if pkt.Cmd != protocol.CmdData {
			t.Fatalf("expected DATA, got %d", pkt.Cmd)
		}
		_, payload, _ := protocol.ParseData(pkt.Payload)
		if string(payload) != msg {
			t.Errorf("echo mismatch: got %q, want %q", payload, msg)
		}
	}

	stopAgent(t, serverConn, errc)
}

// TestDestinationClosesSendsDestroy: when the TCP destination closes,
// the agent sends DESTROY back to the server.
func TestDestinationClosesSendsDestroy(t *testing.T) {
	certs := generateTestCerts(t)
	srv := newFakeServer(t, certs)
	errc := connectAgent(t, srv.addr(), certs, acl.Parse("127.0.0.1"))

	serverConn := srv.accept()
	defer serverConn.Close()
	rd := newServerReader(t, serverConn)

	closeHost, closePort := startCloseImmediateTarget(t)
	connID := uint16(1)

	serverConn.Write(buildCreateRequest(connID, closeHost, closePort))

	// First packet must be CREATE_RESPONSE
	resp := rd.next()
	if resp.Cmd != protocol.CmdCreateResponse {
		t.Fatalf("expected CREATE_RESPONSE, got %d", resp.Cmd)
	}
	_, status, _, _ := protocol.ParseCreateResponse(resp.Payload)
	if status != 0 {
		t.Skip("destination closed before connect completed — race, skipping")
	}

	// Second packet must be DESTROY (destination closed its side)
	destroy := rd.next()
	if destroy.Cmd != protocol.CmdDestroy {
		t.Fatalf("expected DESTROY, got cmd=%d", destroy.Cmd)
	}
	gotID, ok := protocol.ParseDestroy(destroy.Payload)
	if !ok || gotID != connID {
		t.Errorf("DESTROY connID: got %d, want %d ok=%v", gotID, connID, ok)
	}

	stopAgent(t, serverConn, errc)
}
