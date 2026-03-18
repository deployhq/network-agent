# network-agent (Go)

Go rewrite of the [deploy-agent](https://github.com/deployhq/deploy-agent) Ruby gem.

Single static binary — no Ruby runtime required.

## What it does

Creates a reverse mTLS tunnel from inside a customer firewall to the DeployHQ agent
server (`agent.deployhq.com:7777`), enabling deployments to servers that aren't
directly reachable from the internet.

## Installation

```bash
curl -sSL https://raw.githubusercontent.com/deployhq/network-agent/main/install.sh | bash
```

Or download the binary for your platform from the [releases](../../releases) page and
place it in your `PATH`.

## Usage

```
network-agent setup        # Generate certificate and access list (~/.deploy/)
network-agent start        # Start agent in background
network-agent stop         # Stop running agent
network-agent restart      # Stop then start
network-agent run          # Run in foreground (useful for systemd, Docker)
network-agent status       # Show whether agent is running
network-agent accesslist   # Display the current IP access list
network-agent install      # Install as a system service (launchd on macOS, systemd on Linux)
network-agent check        # Verify configuration and test server connectivity
network-agent version      # Print agent version
```

Add `-v` / `--verbose` before the command for debug logging.

## Configuration files (`~/.deploy/`)

| File          | Description                                  |
|---------------|----------------------------------------------|
| `agent.crt`   | Client certificate (provisioned by `setup`)  |
| `agent.key`   | Private key                                  |
| `agent.access`| Allowed destination IPs/CIDRs (one per line) |
| `agent.pid`   | PID of the running background process        |
| `agent.log`   | Log file (written by background process)     |

## Access list format

```
# This file lists IPs/networks the agent is allowed to connect to.
# Lines starting with # are comments; empty lines are ignored.
# Only the first whitespace-separated field on each line is used.

127.0.0.1
::1
192.168.1.0/24
10.0.0.0/8
```

## Migration from Ruby gem

Users already running the Ruby gem can migrate in place — the Go binary uses the
same `~/.deploy/` configuration files:

1. `network-agent stop` (Ruby)
2. Replace `network-agent` binary in `$PATH` with the Go binary
3. `network-agent start` (Go)

To roll back: stop the Go binary, reinstall the gem, start again.

## Environment variables

| Variable                     | Default                                          | Description                         |
|------------------------------|--------------------------------------------------|-------------------------------------|
| `DEPLOY_AGENT_PROXY_IP`      | `agent.deployhq.com`                             | Agent server hostname/IP            |
| `DEPLOY_AGENT_CERTIFICATE_URL` | `https://api.deployhq.com/api/v1/agents/create` | Certificate provisioning endpoint   |
| `DEPLOY_AGENT_NOVERIFY`      | unset                                            | Set to skip TLS server verification |

## Building from source

```
go build ./cmd/network-agent   # build binary
make test                     # run all tests with race detector
make build-all                # cross-compile all platforms
```

Requires Go 1.22+. Zero external dependencies.

## Protocol

Wire-compatible with the Ruby network-agent v1.4.1. See
[`internal/protocol/framing.go`](internal/protocol/framing.go) for the full
binary protocol specification.
