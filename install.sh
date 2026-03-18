#!/usr/bin/env bash
# install.sh — download and install the latest network-agent binary
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/deployhq/network-agent/main/install.sh | bash
#
# Override install directory:
#   INSTALL_DIR=/usr/local/bin bash install.sh

set -euo pipefail

REPO="deployhq/network-agent"
BINARY="network-agent"

# ── Detect OS and architecture ───────────────────────────────────────────────

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  darwin | linux) ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)          ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

# ── Resolve latest version ───────────────────────────────────────────────────

echo "Fetching latest release..."
LATEST=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' \
  | head -1 \
  | cut -d'"' -f4)

if [ -z "$LATEST" ]; then
  echo "Could not determine latest release. Check https://github.com/${REPO}/releases" >&2
  exit 1
fi

VERSION="${LATEST#v}"
echo "Latest version: ${LATEST}"

# ── Download ─────────────────────────────────────────────────────────────────

FILENAME="${BINARY}_${VERSION}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${FILENAME}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Downloading ${FILENAME}..."
curl -sSL "$URL" -o "${TMP}/${FILENAME}"
tar -xzf "${TMP}/${FILENAME}" -C "$TMP"

# ── Install ───────────────────────────────────────────────────────────────────

if [ -z "${INSTALL_DIR:-}" ]; then
  if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
fi

install -m 755 "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

echo ""
echo "Installed ${BINARY} ${LATEST} to ${INSTALL_DIR}/${BINARY}"

# Warn if INSTALL_DIR is not in PATH
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "  Note: ${INSTALL_DIR} is not in your PATH."
    echo "  Add it with:  export PATH=\"\$PATH:${INSTALL_DIR}\""
    ;;
esac

echo ""
echo "Get started:"
echo "  ${BINARY} setup    # provision certificate"
echo "  ${BINARY} start    # start the agent"
