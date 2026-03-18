// Package caroot embeds the DeployHQ CA certificate used to verify the agent server.
package caroot

import _ "embed"

//go:embed ca.crt
var CACert []byte
