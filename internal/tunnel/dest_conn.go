package tunnel

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/deployhq/network-agent/internal/protocol"
)

// destConn manages one TCP connection to a backend destination server.
type destConn struct {
	id         uint16
	conn       net.Conn
	serverSend chan<- []byte // write-only view into ServerConn.serverSend
	done       <-chan struct{}
	log        *slog.Logger
}

// dialDest dials the destination and returns a connected destConn.
// All sends to serverSend use select+done so they never block after shutdown.
func dialDest(id uint16, host, port string, serverSend chan<- []byte, done <-chan struct{}, log *slog.Logger) *destConn {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		log.Info("destination connection failed", "id", id, "addr", addr, "err", err)
		select {
		case serverSend <- protocol.EncodeCreateResponse(id, 1, err.Error()):
		case <-done:
		}
		return nil
	}
	log.Info("connected to destination", "id", id, "addr", addr)
	select {
	case serverSend <- protocol.EncodeCreateResponse(id, 0, ""):
	case <-done:
		conn.Close()
		return nil
	}
	return &destConn{id: id, conn: conn, serverSend: serverSend, done: done, log: log}
}

// readLoop reads data from the TCP destination and forwards DATA packets to the server.
// When the destination closes, a DESTROY is sent and the connection is removed from sc.
func (d *destConn) readLoop(sc *ServerConn) {
	defer func() {
		d.conn.Close()
		d.log.Info("destination closed", "id", d.id)
		select {
		case sc.serverSend <- protocol.EncodeDestroy(d.id):
		case <-sc.done:
		}
		sc.removeDest(d.id)
	}()

	buf := make([]byte, 32768)
	for {
		n, err := d.conn.Read(buf)
		if n > 0 {
			d.log.Debug("data from destination", "id", d.id, "bytes", n)
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case sc.serverSend <- protocol.EncodeData(d.id, chunk):
			case <-sc.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// send writes data to the destination TCP socket synchronously.
func (d *destConn) send(data []byte) {
	for len(data) > 0 {
		n, err := d.conn.Write(data)
		if err != nil {
			d.log.Debug("destination write error", "id", d.id, "err", err)
			return
		}
		data = data[n:]
	}
}

// parseHostPort validates that host is a valid IP address.
func parseHostPort(host, port string) (string, string, error) {
	if net.ParseIP(host) == nil {
		return "", "", fmt.Errorf("destination must be an IP address, got %q", host)
	}
	return host, port, nil
}
