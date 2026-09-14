package protocol

// Command byte constants — must match the server-side AgentConnection Ruby class.
const (
	CmdCreateRequest  byte = 1
	CmdCreateResponse byte = 2
	CmdDestroy        byte = 3
	CmdData           byte = 4
	CmdReject         byte = 5
	CmdReconnect      byte = 6
	CmdKeepalive      byte = 7

	// CmdRenewRequest is sent by the agent once per connection, immediately
	// after the TLS handshake. Its payload is a UTF-8 implementation/version
	// identifier such as "go/0.3.0"; the server decides whether the agent's
	// client certificate needs re-issuing under a newer CA.
	CmdRenewRequest byte = 8

	// CmdRenewResponse is the server's answer to CmdRenewRequest. Its payload
	// is [status:1][body], see the RenewStatus* constants. The server never
	// sends it unsolicited.
	CmdRenewResponse byte = 9
)

// Renewal response statuses, carried in the first payload byte of a
// CmdRenewResponse frame.
const (
	// RenewStatusRenewed means the body holds a new client certificate in PEM
	// form, re-issued for the agent's existing key pair.
	RenewStatusRenewed byte = 0

	// RenewStatusCurrent means the agent's certificate is already current.
	// There is no body.
	RenewStatusCurrent byte = 1

	// RenewStatusError means renewal failed server-side. The body is a UTF-8
	// diagnostic message; the agent logs it and carries on with its current
	// certificate.
	RenewStatusError byte = 2
)
