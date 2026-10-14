# network-agent

A secure proxy that allows [DeployHQ](https://www.deployhq.com) to forward connections
to servers behind firewalls. The agent establishes an outbound TLS connection to
DeployHQ's servers and proxies deployment traffic to allowed destinations based on an
IP/network allowlist.

## How It Works

```
                    TLS (port 7777)
  DeployHQ  <————————————————————————>  Deploy Agent  ————>  Your Server(s)
              mutual authentication      (behind firewall)     proxy
```

The agent connects **outbound** to DeployHQ, so no inbound firewall rules are needed.
Connections to destination servers are restricted to an explicit allowlist of IPs and
networks.

Go rewrite of the [deploy-agent](https://github.com/deployhq/deploy-agent) Ruby gem —
single static binary, no Ruby runtime required.

## Installation

```bash
curl -sSL https://deployhq.com/install/network-agent | bash
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
network-agent update       # Update to the latest version
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

## Upgrading

```bash
network-agent update && network-agent restart
```

`update` replaces the binary in place; `restart` is what makes the running
agent pick it up. Both steps are needed — there is no background update check.

## Certificate renewal

DeployHQ is rotating the certificate authority behind the agent connection. The
agent handles its side automatically: on each connection it tells DeployHQ which
version it is running, and if DeployHQ has re-issued its client certificate the
agent validates the new one, replaces `~/.deploy/agent.crt`, and reconnects to
start using it. Nothing is written unless the new certificate pairs with the
existing private key, keeps the same identity, and is signed by a trusted CA —
and the replacement is atomic, so a failure never leaves a half-written
certificate behind.

Nothing is required of you beyond running a recent version. There is no
interruption to deployments, no new claim code, and no change to
`~/.deploy/agent.key`, which never leaves the machine.

`network-agent check` prints the certificate authorities the binary trusts and
when they expire.

## Migration from Ruby gem

Users already running the Ruby gem can migrate in place — the Go binary uses the
same `~/.deploy/` configuration files:

1. `deploy-agent stop` (Ruby gem)
2. Install the Go binary: `curl -sSL https://deployhq.com/install/network-agent | bash`
3. `network-agent start` (Go)

To roll back: `network-agent stop`, then `gem install deploy-agent` and `deploy-agent start`.

## Environment variables

| Variable                     | Default                                          | Description                         |
|------------------------------|--------------------------------------------------|-------------------------------------|
| `DEPLOY_AGENT_PROXY_IP`      | `agent.deployhq.com`                             | Agent server hostname/IP            |
| `DEPLOY_AGENT_CERTIFICATE_URL` | `https://api.deployhq.com/api/v1/agents/create` | Certificate provisioning endpoint   |
| `DEPLOY_AGENT_NOVERIFY`      | unset                                            | Set to skip TLS server verification |
| `DEPLOY_AGENT_CA_FILE`       | unset (uses the bundled CAs)                     | Path to a PEM bundle of certificate authorities to trust instead of the ones built into the binary. Unreadable or empty is an error, not a fall back. |

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
