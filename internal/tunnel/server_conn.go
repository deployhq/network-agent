// Package tunnel manages the mTLS connection to the DeployHQ agent server
// and the set of destination TCP connections it proxies.
package tunnel

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/deployhq/network-agent/internal/acl"
	"github.com/deployhq/network-agent/internal/protocol"
)

const (
	keepaliveInterval = 60 * time.Second
	readBufSize       = 32768
)

// ServerConn represents an active mTLS connection to the DeployHQ server.
type ServerConn struct {
	conn       *tls.Conn
	serverSend chan []byte   // packets queued for writing to the server
	done       chan struct{} // closed when Run() begins shutdown

	access *acl.AccessList

	mu    sync.Mutex
	dests map[uint16]*destConn

	log *slog.Logger
}

// Connect dials the server and performs the mTLS handshake.
func Connect(tlsCfg *tls.Config, serverAddr string, access *acl.AccessList, log *slog.Logger) (*ServerConn, error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 30 * time.Second},
		"tcp",
		serverAddr,
		tlsCfg,
	)
	if err != nil {
		return nil, err
	}
	log.Info("connected to server", "addr", serverAddr)

	return &ServerConn{
		conn:       conn,
		serverSend: make(chan []byte, 256),
		done:       make(chan struct{}),
		access:     access,
		dests:      make(map[uint16]*destConn),
		log:        log,
	}, nil
}

// Run starts the write and keepalive goroutines, then drives the read loop.
// It blocks until the connection is closed and returns ErrRejected on REJECT.
func (sc *ServerConn) Run() error {
	go sc.writeLoop()
	go sc.keepaliveLoop()

	err := sc.readLoop()

	// Signal all goroutines (destConn readLoops, keepalive) to stop.
	close(sc.done)

	// Close all destination connections so their readLoops unblock.
	sc.mu.Lock()
	for _, d := range sc.dests {
		d.conn.Close()
	}
	sc.dests = make(map[uint16]*destConn)
	sc.mu.Unlock()

	sc.conn.Close()
	return err
}

// ErrRejected is returned when the server sends a REJECT packet.
type ErrRejected struct{ Reason string }

func (e ErrRejected) Error() string { return "server rejected connection: " + e.Reason }

// readLoop reads frames from the server and dispatches them.
func (sc *ServerConn) readLoop() error {
	buf := make([]byte, 0, readBufSize)
	tmp := make([]byte, readBufSize)

	for {
		n, err := sc.conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			packets, remaining := protocol.DecodePackets(buf)
			buf = append(buf[:0], remaining...)
			for _, pkt := range packets {
				if err := sc.handlePacket(pkt); err != nil {
					return err
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				sc.log.Info("server closed connection")
			} else {
				sc.log.Info("server connection error", "err", err)
			}
			return err
		}
	}
}

// handlePacket dispatches a decoded packet by command type.
// Called synchronously from readLoop — done is not yet closed here.
func (sc *ServerConn) handlePacket(pkt protocol.Packet) error {
	switch pkt.Cmd {
	case protocol.CmdCreateRequest:
		connID, host, port, ok := protocol.ParseCreateRequest(pkt.Payload)
		if !ok {
			sc.log.Warn("malformed CREATE_REQUEST")
			return nil
		}
		sc.log.Info("connection request", "id", connID, "host", host, "port", port)

		if !sc.access.Allows(host) {
			sc.log.Info("destination denied by access list", "id", connID, "host", host)
			sc.serverSend <- protocol.EncodeCreateResponse(connID, 1, "Destination address not allowed")
			return nil
		}

		host, port, err := parseHostPort(host, port)
		if err != nil {
			sc.serverSend <- protocol.EncodeCreateResponse(connID, 1, err.Error())
			return nil
		}

		go sc.dialAndRegister(connID, host, port)

	case protocol.CmdDestroy:
		connID, ok := protocol.ParseDestroy(pkt.Payload)
		if !ok {
			return nil
		}
		sc.log.Info("close requested by server", "id", connID)
		sc.mu.Lock()
		d, exists := sc.dests[connID]
		sc.mu.Unlock()
		if exists {
			d.conn.Close()
		}

	case protocol.CmdData:
		connID, data, ok := protocol.ParseData(pkt.Payload)
		if !ok {
			return nil
		}
		sc.log.Debug("data from server", "id", connID, "bytes", len(data))
		sc.mu.Lock()
		d := sc.dests[connID]
		sc.mu.Unlock()
		if d != nil {
			d.send(data)
		}

	case protocol.CmdReject:
		reason := string(pkt.Payload)
		sc.log.Warn("server rejected connection", "reason", reason)
		return ErrRejected{Reason: reason}

	case protocol.CmdReconnect:
		sc.log.Warn("server requested reconnect")
		return io.EOF

	case protocol.CmdKeepalive:
		// no-op

	default:
		sc.log.Warn("unknown command", "cmd", pkt.Cmd)
	}
	return nil
}

// dialAndRegister dials the destination and starts its read loop.
func (sc *ServerConn) dialAndRegister(connID uint16, host, port string) {
	d := dialDest(connID, host, port, sc.serverSend, sc.done, sc.log)
	if d == nil {
		return
	}
	sc.mu.Lock()
	sc.dests[connID] = d
	sc.mu.Unlock()

	d.readLoop(sc)
}

// removeDest removes a destination from the map (called by destConn.readLoop).
func (sc *ServerConn) removeDest(connID uint16) {
	sc.mu.Lock()
	delete(sc.dests, connID)
	sc.mu.Unlock()
}

// writeLoop drains serverSend and writes to the TLS connection.
// Exits when done is closed or a write error occurs.
func (sc *ServerConn) writeLoop() {
	for {
		select {
		case pkt := <-sc.serverSend:
			for len(pkt) > 0 {
				n, err := sc.conn.Write(pkt)
				if err != nil {
					return
				}
				pkt = pkt[n:]
			}
		case <-sc.done:
			return
		}
	}
}

// keepaliveLoop sends a KEEPALIVE every 60 seconds until done is closed.
func (sc *ServerConn) keepaliveLoop() {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			select {
			case sc.serverSend <- protocol.EncodeKeepalive():
			case <-sc.done:
				return
			}
		case <-sc.done:
			return
		}
	}
}
