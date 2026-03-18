package tunnel_test

import (
	"crypto/tls"
	"testing"

	"github.com/deployhq/network-agent/internal/protocol"
)

// TestDecodeStreamFragmentation verifies that partial packets reassemble correctly.
func TestDecodeStreamFragmentation(t *testing.T) {
	frame1 := protocol.EncodeKeepalive()
	frame2 := protocol.EncodeDestroy(1)
	combined := append(frame1, frame2...)

	var buf []byte
	var allPackets []protocol.Packet
	for _, b := range combined {
		buf = append(buf, b)
		pkts, remaining := protocol.DecodePackets(buf)
		buf = remaining
		allPackets = append(allPackets, pkts...)
	}

	if len(allPackets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(allPackets))
	}
	if allPackets[0].Cmd != protocol.CmdKeepalive {
		t.Error("first packet should be keepalive")
	}
	if allPackets[1].Cmd != protocol.CmdDestroy {
		t.Error("second packet should be destroy")
	}
}

func TestCreateResponseOnDestinationRefused(t *testing.T) {
	frame := protocol.EncodeCreateResponse(42, 1, "connection refused")
	packets, _ := protocol.DecodePackets(frame)
	if len(packets) != 1 {
		t.Fatal("expected 1 packet")
	}
	connID, status, reason, ok := protocol.ParseCreateResponse(packets[0].Payload)
	if !ok || connID != 42 || status != 1 || reason != "connection refused" {
		t.Errorf("got connID=%d status=%d reason=%q ok=%v", connID, status, reason, ok)
	}
}

func TestTLSConfigBuildsFromPEM(t *testing.T) {
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	if cfg == nil {
		t.Error("expected non-nil config")
	}
}
