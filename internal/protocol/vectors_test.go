package protocol_test

// Ruby byte-vector compatibility tests.
//
// Every expected byte sequence below was derived from the Ruby agent's
// send_packet implementation:
//
//	send_packet(data)  →  @tx_buffer << [data.bytesize+2, data].pack('na*')
//
// and the per-command pack strings in server_connection.rb and
// agent_connection.rb. If any of these fail the wire format has drifted.

import (
	"bytes"
	"testing"

	"github.com/deployhq/network-agent/internal/protocol"
)

type vectorCase struct {
	name string
	got  []byte
	want []byte
}

func TestRubyByteVectors(t *testing.T) {
	cases := []vectorCase{
		// KEEPALIVE
		// Ruby: send_packet([7].pack('C'))
		//       data=[0x07] (1B) → frame=[0x00,0x03,0x07]
		{
			name: "keepalive",
			got:  protocol.EncodeKeepalive(),
			want: []byte{0x00, 0x03, 0x07},
		},

		// RECONNECT
		// Ruby: send_packet([6].pack('C'))
		//       data=[0x06] (1B) → frame=[0x00,0x03,0x06]
		{
			name: "reconnect",
			got:  protocol.EncodePacket(protocol.CmdReconnect, nil),
			want: []byte{0x00, 0x03, 0x06},
		},

		// DESTROY conn=42
		// Ruby: send_packet([3,42].pack('Cn'))
		//       data=[0x03,0x00,0x2A] (3B) → frame=[0x00,0x05,0x03,0x00,0x2A]
		{
			name: "destroy conn=42",
			got:  protocol.EncodeDestroy(42),
			want: []byte{0x00, 0x05, 0x03, 0x00, 0x2A},
		},

		// CREATE_RESPONSE success conn=1
		// Ruby: send_packet([2,1,0].pack('CnC'))
		//       data=[0x02,0x00,0x01,0x00] (4B) → frame=[0x00,0x06,0x02,0x00,0x01,0x00]
		{
			name: "create_response success conn=1",
			got:  protocol.EncodeCreateResponse(1, 0, ""),
			want: []byte{0x00, 0x06, 0x02, 0x00, 0x01, 0x00},
		},

		// CREATE_RESPONSE failure conn=2 reason="Destination address not allowed"
		// Ruby: send_packet([2,2,1,reason].pack('CnCa*'))
		//       reason = "Destination address not allowed" (31 bytes)
		//       data = 1+2+1+31 = 35B → total = 37 = 0x25
		{
			name: "create_response denied conn=2",
			got:  protocol.EncodeCreateResponse(2, 1, "Destination address not allowed"),
			want: append(
				[]byte{0x00, 0x25, 0x02, 0x00, 0x02, 0x01},
				[]byte("Destination address not allowed")...,
			),
		},

		// DATA conn=1 payload="hello"
		// Ruby: send_packet([4,1,"hello"].pack('Cna*'))
		//       data=[0x04,0x00,0x01,'h','e','l','l','o'] (8B) → total=10=0x0A
		{
			name: "data conn=1 hello",
			got:  protocol.EncodeData(1, []byte("hello")),
			want: []byte{0x00, 0x0A, 0x04, 0x00, 0x01, 'h', 'e', 'l', 'l', 'o'},
		},

		// REJECT "test"
		// Ruby: send_packet([5,"test"].pack('Ca*'))
		//       data=[0x05,'t','e','s','t'] (5B) → total=7=0x07
		{
			name: "reject reason=test",
			got:  protocol.EncodePacket(protocol.CmdReject, []byte("test")),
			want: []byte{0x00, 0x07, 0x05, 't', 'e', 's', 't'},
		},

		// CREATE_REQUEST conn=3 host="127.0.0.1" port="22" (server→agent direction)
		// Ruby: send_packet([1,3,"127.0.0.1/22"].pack('Cna*'))
		//       "127.0.0.1/22" = 12B
		//       data = 1+2+12 = 15B → total = 17 = 0x11
		{
			name: "create_request conn=3 127.0.0.1/22",
			got: protocol.EncodePacket(protocol.CmdCreateRequest,
				append([]byte{0x00, 0x03}, []byte("127.0.0.1/22")...),
			),
			want: append(
				[]byte{0x00, 0x11, 0x01, 0x00, 0x03},
				[]byte("127.0.0.1/22")...,
			),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !bytes.Equal(tc.got, tc.want) {
				t.Errorf("\ngot:  %#v\nwant: %#v", tc.got, tc.want)
			}
		})
	}
}

// TestParseRubyFrames verifies that frames written by the Ruby server decode
// correctly on the Go agent side.
func TestParseRubyFrames(t *testing.T) {
	// CREATE_REQUEST from server: conn=3 host="192.168.1.1" port="22"
	// Ruby: send_packet([1,3,"192.168.1.1/22"].pack('Cna*'))
	//       "192.168.1.1/22" = 14B, data=15B, total=17=0x11 ... wait 1+2+14=17, total=19=0x13
	raw := append(
		[]byte{0x00, 0x13, 0x01, 0x00, 0x03},
		[]byte("192.168.1.1/22")...,
	)
	packets, remaining := protocol.DecodePackets(raw)
	if len(remaining) != 0 || len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d (remaining %d)", len(packets), len(remaining))
	}
	pkt := packets[0]
	if pkt.Cmd != protocol.CmdCreateRequest {
		t.Errorf("cmd: got %d want %d", pkt.Cmd, protocol.CmdCreateRequest)
	}
	connID, host, port, ok := protocol.ParseCreateRequest(pkt.Payload)
	if !ok || connID != 3 || host != "192.168.1.1" || port != "22" {
		t.Errorf("got connID=%d host=%q port=%q ok=%v", connID, host, port, ok)
	}
}

// TestLengthFieldIncludesItself is the single most critical property:
// the uint16 length field counts itself (matches Ruby's data.bytesize+2).
func TestLengthFieldIncludesItself(t *testing.T) {
	frames := [][]byte{
		protocol.EncodeKeepalive(),
		protocol.EncodeDestroy(1),
		protocol.EncodeData(1, []byte("test")),
		protocol.EncodeCreateResponse(1, 0, ""),
		protocol.EncodeCreateResponse(1, 1, "some error"),
	}
	for _, f := range frames {
		declared := int(f[0])<<8 | int(f[1])
		if declared != len(f) {
			t.Errorf("length field %d != actual frame length %d", declared, len(f))
		}
	}
}
