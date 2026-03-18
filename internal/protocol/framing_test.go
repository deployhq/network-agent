package protocol_test

import (
	"bytes"
	"testing"

	"github.com/deployhq/network-agent/internal/protocol"
)

func TestEncodeDecodeRoundtrip(t *testing.T) {
	tests := []struct {
		name    string
		cmd     byte
		payload []byte
	}{
		{"keepalive", protocol.CmdKeepalive, nil},
		{"destroy", protocol.CmdDestroy, []byte{0x00, 0x01}},
		{"data", protocol.CmdData, []byte{0x00, 0x02, 'h', 'i'}},
		{"reconnect", protocol.CmdReconnect, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := protocol.EncodePacket(tt.cmd, tt.payload)
			packets, remaining := protocol.DecodePackets(frame)
			if len(remaining) != 0 {
				t.Fatalf("unexpected remaining bytes: %v", remaining)
			}
			if len(packets) != 1 {
				t.Fatalf("expected 1 packet, got %d", len(packets))
			}
			if packets[0].Cmd != tt.cmd {
				t.Errorf("cmd: got %d, want %d", packets[0].Cmd, tt.cmd)
			}
			if !bytes.Equal(packets[0].Payload, tt.payload) {
				t.Errorf("payload: got %v, want %v", packets[0].Payload, tt.payload)
			}
		})
	}
}

// TestFrameLength verifies that the 2-byte length includes itself (matches Ruby).
// Ruby: send_packet(data) → [data.bytesize+2, data].pack('na*')
func TestFrameLength(t *testing.T) {
	// KEEPALIVE: cmd=7, no payload → frame = [0x00, 0x03, 0x07]
	frame := protocol.EncodeKeepalive()
	if len(frame) != 3 {
		t.Fatalf("keepalive frame length: got %d, want 3", len(frame))
	}
	if frame[0] != 0x00 || frame[1] != 0x03 {
		t.Errorf("keepalive length field: got %02x %02x, want 00 03", frame[0], frame[1])
	}
	if frame[2] != protocol.CmdKeepalive {
		t.Errorf("keepalive cmd byte: got %d, want %d", frame[2], protocol.CmdKeepalive)
	}
}

func TestDecodeMultiplePackets(t *testing.T) {
	var buf []byte
	buf = append(buf, protocol.EncodeKeepalive()...)
	buf = append(buf, protocol.EncodeDestroy(42)...)
	buf = append(buf, protocol.EncodeKeepalive()...)

	packets, remaining := protocol.DecodePackets(buf)
	if len(remaining) != 0 {
		t.Fatalf("unexpected remaining: %v", remaining)
	}
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}
	if packets[0].Cmd != protocol.CmdKeepalive {
		t.Error("packet[0] should be keepalive")
	}
	if packets[1].Cmd != protocol.CmdDestroy {
		t.Error("packet[1] should be destroy")
	}
}

func TestDecodeIncompleteFrame(t *testing.T) {
	// Partial keepalive — only the length bytes, no cmd byte yet
	partial := []byte{0x00, 0x03} // says total=3 but only 2 bytes here
	packets, remaining := protocol.DecodePackets(partial)
	if len(packets) != 0 {
		t.Errorf("expected no packets from partial frame, got %d", len(packets))
	}
	if !bytes.Equal(remaining, partial) {
		t.Errorf("remaining should be the original partial bytes")
	}
}

func TestCreateResponseEncode(t *testing.T) {
	// Success: cmd=2, connID=1, status=0 → payload=[0,1,0] → frame=[0,6, 2, 0,1,0]
	frame := protocol.EncodeCreateResponse(1, 0, "")
	if len(frame) != 6 {
		t.Fatalf("expected frame length 6, got %d", len(frame))
	}
	// Verify it round-trips
	packets, _ := protocol.DecodePackets(frame)
	if len(packets) != 1 {
		t.Fatal("no packets decoded")
	}
	connID, status, reason, ok := protocol.ParseCreateResponse(packets[0].Payload)
	if !ok || connID != 1 || status != 0 || reason != "" {
		t.Errorf("unexpected: connID=%d status=%d reason=%q ok=%v", connID, status, reason, ok)
	}
}

func TestCreateResponseEncodeFailure(t *testing.T) {
	frame := protocol.EncodeCreateResponse(5, 1, "connection refused")
	packets, _ := protocol.DecodePackets(frame)
	connID, status, reason, ok := protocol.ParseCreateResponse(packets[0].Payload)
	if !ok || connID != 5 || status != 1 || reason != "connection refused" {
		t.Errorf("unexpected: connID=%d status=%d reason=%q ok=%v", connID, status, reason, ok)
	}
}

func TestParseCreateRequest(t *testing.T) {
	// Build payload: connID=3, host="192.168.1.1", port="22"
	// Matches server: [COMMAND_CREATE_REQUEST, id, "#{ip}/#{port}"].pack('Cna*')
	// The payload (after stripping cmd byte) is: [id_hi, id_lo, "192.168.1.1/22"...]
	payload := []byte{0x00, 0x03}
	payload = append(payload, []byte("192.168.1.1/22")...)
	connID, host, port, ok := protocol.ParseCreateRequest(payload)
	if !ok || connID != 3 || host != "192.168.1.1" || port != "22" {
		t.Errorf("got connID=%d host=%q port=%q ok=%v", connID, host, port, ok)
	}
}

func TestEncodeData(t *testing.T) {
	data := []byte("hello world")
	frame := protocol.EncodeData(7, data)
	packets, _ := protocol.DecodePackets(frame)
	connID, got, ok := protocol.ParseData(packets[0].Payload)
	if !ok || connID != 7 || !bytes.Equal(got, data) {
		t.Errorf("data round-trip failed: connID=%d data=%q ok=%v", connID, got, ok)
	}
}
