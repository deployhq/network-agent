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
)
