// Package protocol implements the binary wire format used between the network-agent
// and the DeployHQ agent server.
//
// Frame layout (all multi-byte integers are big-endian):
//
//	[uint16: total_frame_size][cmd: 1 byte][payload: N bytes]
//
// total_frame_size = 2 (length field itself) + 1 (cmd) + len(payload)
//
// This matches the Ruby implementation:
//
//	send_packet(data)  →  @tx_buffer << [data.bytesize+2, data].pack('na*')
package protocol

import "encoding/binary"

// Packet holds a decoded command + its payload.
type Packet struct {
	Cmd     byte
	Payload []byte
}

// EncodePacket builds a complete wire frame for the given command and payload.
func EncodePacket(cmd byte, payload []byte) []byte {
	totalLen := 2 + 1 + len(payload) // length field + cmd + payload
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(totalLen))
	buf[2] = cmd
	copy(buf[3:], payload)
	return buf
}

// DecodePackets extracts all complete packets from buf.
// Incomplete trailing bytes are returned as remaining.
func DecodePackets(buf []byte) (packets []Packet, remaining []byte) {
	for len(buf) >= 2 {
		totalLen := int(binary.BigEndian.Uint16(buf[0:2]))
		if totalLen < 3 || len(buf) < totalLen {
			break // incomplete frame
		}
		cmd := buf[2]
		payload := make([]byte, totalLen-3)
		copy(payload, buf[3:totalLen])
		packets = append(packets, Packet{Cmd: cmd, Payload: payload})
		buf = buf[totalLen:]
	}
	return packets, buf
}

// --- Per-command encode helpers ---

// EncodeCreateResponse encodes a CREATE_RESPONSE packet.
// status=0 means success; any other value means failure (reason required).
func EncodeCreateResponse(connID uint16, status byte, reason string) []byte {
	payload := make([]byte, 3+len(reason))
	binary.BigEndian.PutUint16(payload[0:2], connID)
	payload[2] = status
	copy(payload[3:], reason)
	return EncodePacket(CmdCreateResponse, payload)
}

// EncodeDestroy encodes a DESTROY packet for the given connection ID.
func EncodeDestroy(connID uint16) []byte {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload[0:2], connID)
	return EncodePacket(CmdDestroy, payload)
}

// EncodeData encodes a DATA packet carrying arbitrary bytes for connID.
func EncodeData(connID uint16, data []byte) []byte {
	payload := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(payload[0:2], connID)
	copy(payload[2:], data)
	return EncodePacket(CmdData, payload)
}

// EncodeKeepalive encodes a KEEPALIVE packet.
func EncodeKeepalive() []byte {
	return EncodePacket(CmdKeepalive, nil)
}

// --- Per-command parse helpers ---

// ParseCreateRequest parses a CREATE_REQUEST payload into connID, host, port.
// Host and port are separated by '/' (not ':') per the protocol spec.
func ParseCreateRequest(payload []byte) (connID uint16, host, port string, ok bool) {
	if len(payload) < 3 {
		return
	}
	connID = binary.BigEndian.Uint16(payload[0:2])
	hostPort := string(payload[2:])
	for i := 0; i < len(hostPort); i++ {
		if hostPort[i] == '/' {
			host = hostPort[:i]
			port = hostPort[i+1:]
			ok = true
			return
		}
	}
	return
}

// ParseCreateResponse parses a CREATE_RESPONSE payload.
func ParseCreateResponse(payload []byte) (connID uint16, status byte, reason string, ok bool) {
	if len(payload) < 3 {
		return
	}
	connID = binary.BigEndian.Uint16(payload[0:2])
	status = payload[2]
	reason = string(payload[3:])
	ok = true
	return
}

// ParseDestroy parses a DESTROY payload and returns the connection ID.
func ParseDestroy(payload []byte) (connID uint16, ok bool) {
	if len(payload) < 2 {
		return
	}
	connID = binary.BigEndian.Uint16(payload[0:2])
	ok = true
	return
}

// ParseData parses a DATA payload and returns connID + data bytes.
func ParseData(payload []byte) (connID uint16, data []byte, ok bool) {
	if len(payload) < 2 {
		return
	}
	connID = binary.BigEndian.Uint16(payload[0:2])
	data = payload[2:]
	ok = true
	return
}
