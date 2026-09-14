package protocol_test

import (
	"bytes"
	"testing"

	"github.com/deployhq/network-agent/internal/protocol"
)

// The renewal command bytes are part of a wire contract shared with the Ruby
// agent and the DeployHQ backend. Pin them so a reorder of the const block
// cannot silently change what goes on the wire.
func TestRenewCommandBytes(t *testing.T) {
	if protocol.CmdRenewRequest != 8 {
		t.Errorf("CmdRenewRequest = %d, want 8", protocol.CmdRenewRequest)
	}
	if protocol.CmdRenewResponse != 9 {
		t.Errorf("CmdRenewResponse = %d, want 9", protocol.CmdRenewResponse)
	}
	if protocol.RenewStatusRenewed != 0 || protocol.RenewStatusCurrent != 1 || protocol.RenewStatusError != 2 {
		t.Errorf("renew statuses = %d/%d/%d, want 0/1/2",
			protocol.RenewStatusRenewed, protocol.RenewStatusCurrent, protocol.RenewStatusError)
	}
}

func TestEncodeRenewRequest(t *testing.T) {
	frame := protocol.EncodeRenewRequest("go/1.2.3")

	want := []byte{0x00, 0x0b, 0x08, 'g', 'o', '/', '1', '.', '2', '.', '3'}
	if !bytes.Equal(frame, want) {
		t.Fatalf("frame = % x, want % x", frame, want)
	}

	packets, remaining := protocol.DecodePackets(frame)
	if len(packets) != 1 || len(remaining) != 0 {
		t.Fatalf("decoded %d packets, %d remaining bytes", len(packets), len(remaining))
	}
	if got := protocol.ParseRenewRequest(packets[0].Payload); got != "go/1.2.3" {
		t.Errorf("identifier = %q, want %q", got, "go/1.2.3")
	}
}

func TestRenewResponseRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		status byte
		body   []byte
	}{
		{"renewed", protocol.RenewStatusRenewed, []byte("-----BEGIN CERTIFICATE-----\n")},
		{"current", protocol.RenewStatusCurrent, nil},
		{"error", protocol.RenewStatusError, []byte("no certificate on file")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := protocol.EncodeRenewResponse(tt.status, tt.body)
			packets, remaining := protocol.DecodePackets(frame)
			if len(packets) != 1 || len(remaining) != 0 {
				t.Fatalf("decoded %d packets, %d remaining bytes", len(packets), len(remaining))
			}
			if packets[0].Cmd != protocol.CmdRenewResponse {
				t.Fatalf("cmd = %d, want %d", packets[0].Cmd, protocol.CmdRenewResponse)
			}
			status, body, ok := protocol.ParseRenewResponse(packets[0].Payload)
			if !ok {
				t.Fatal("ParseRenewResponse reported a malformed payload")
			}
			if status != tt.status {
				t.Errorf("status = %d, want %d", status, tt.status)
			}
			if !bytes.Equal(body, tt.body) && !(len(body) == 0 && len(tt.body) == 0) {
				t.Errorf("body = %q, want %q", body, tt.body)
			}
		})
	}
}

func TestParseRenewResponseRejectsEmptyPayload(t *testing.T) {
	if _, _, ok := protocol.ParseRenewResponse(nil); ok {
		t.Error("empty payload should not parse as a renew response")
	}
}
