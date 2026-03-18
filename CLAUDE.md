# CLAUDE.md

This file provides guidance to Claude Code when working with the network-agent repository.

## Overview

Go rewrite of the [deploy-agent](https://github.com/deployhq/deploy-agent) Ruby gem.
Single static binary that creates a reverse mTLS tunnel from inside customer firewalls
to the DeployHQ agent server, enabling deployments to servers not directly reachable
from the internet.

## Key Constraints

- **Zero external dependencies** — stdlib only (`crypto/tls`, `net`, `log/slog`, `embed`)
- **Wire-compatible** with the Ruby deploy-agent v1.4.1 — no server-side changes allowed
- **Static binaries** — `CGO_ENABLED=0` always

## Common Commands

```bash
make build        # Build binary for current platform
make test         # Run tests with race detector
make lint         # Run golangci-lint
make build-all    # Cross-compile all platforms into dist/
go test -race -v ./...  # Verbose test output
```

## Project Structure

```
cmd/network-agent/    # CLI entry point (main.go)
internal/
  protocol/           # Binary wire format (encode/decode) — no external deps
  acl/                # IP/CIDR access list parser
  config/             # File paths, TLS config, env vars
  caroot/             # Embedded CA certificate (ca.crt)
  tunnel/             # mTLS connection + goroutine lifecycle
  setup/              # Interactive setup wizard
  daemon/             # PID file, background process management
```

## Protocol (Wire Format)

Frame layout — must not change without coordinating with the server side:

```
[uint16 BE: total_frame_size][cmd: 1 byte][payload: N bytes]
```

`total_frame_size` includes the 2-byte length field itself.

Commands: `CREATE_REQUEST(1)`, `CREATE_RESPONSE(2)`, `DESTROY(3)`, `DATA(4)`,
`REJECT(5)`, `RECONNECT(6)`, `KEEPALIVE(7)`.

Reference implementations:
- Agent side: `../deploy-agent/lib/deploy_agent/server_connection.rb`
- Server side: `../deployhq/lib/agent_server/agent_connection.rb`

## Configuration Files (`~/.deploy/`)

| File           | Description                          |
|----------------|--------------------------------------|
| `agent.crt`    | Client certificate                   |
| `agent.key`    | Private key                          |
| `agent.access` | Allowed destination IPs/CIDRs        |
| `agent.pid`    | PID of running background process    |
| `agent.log`    | Log file written by background agent |

## Environment Variables

| Variable                       | Default                                            |
|--------------------------------|----------------------------------------------------|
| `DEPLOY_AGENT_PROXY_IP`        | `agent.deployhq.com`                               |
| `DEPLOY_AGENT_CERTIFICATE_URL` | `https://api.deployhq.com/api/v1/agents/create`   |
| `DEPLOY_AGENT_NOVERIFY`        | unset (set to skip TLS verification in dev)        |

## Testing

```bash
go test -race ./...                   # All packages
go test -race ./internal/protocol/... # Protocol only
go test -race ./internal/acl/...      # ACL only
```

No external test infrastructure required — all tests are in-process.
Phase 5 E2E tests (real mTLS against staging) are run manually.

## Cross-Compilation

All platforms must build cleanly. Check with `make build-all` or:

```bash
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/network-agent
GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/network-agent
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/network-agent
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/network-agent
```

## Adding New Features

- Keep the protocol package dependency-free — it is the ground truth for wire format
- The access list is reloaded on each reconnect (see `tunnel/agent.go`) — no restart needed for ACL changes
- Daemon backgrounding uses re-exec (not fork) — see `internal/daemon/`
- Build tags `!windows` / `windows` separate Unix/Windows daemon code
