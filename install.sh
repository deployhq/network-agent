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

# ── PATH setup ────────────────────────────────────────────────────────────────
# When installing to ~/.local/bin, ensure the directory is in the shell profile
# and always tell the user to reload — curl|bash runs in a subprocess and cannot
# update the parent shell's PATH or hash table.

RELOAD_CMD=""

if [ "$INSTALL_DIR" != "/usr/local/bin" ]; then
  PROFILE=""
  if [ -f "${HOME}/.bashrc" ]; then
    PROFILE="${HOME}/.bashrc"
  elif [ -f "${HOME}/.bash_profile" ]; then
    PROFILE="${HOME}/.bash_profile"
  elif [ -f "${HOME}/.zshrc" ]; then
    PROFILE="${HOME}/.zshrc"
  elif [ -f "${HOME}/.profile" ]; then
    PROFILE="${HOME}/.profile"
  fi

  if [ -n "$PROFILE" ]; then
    LINE="export PATH=\"\$PATH:${INSTALL_DIR}\""
    if ! grep -qF "$LINE" "$PROFILE" 2>/dev/null; then
      echo "" >> "$PROFILE"
      echo "# Added by network-agent installer" >> "$PROFILE"
      echo "$LINE" >> "$PROFILE"
    fi
    RELOAD_CMD="source ${PROFILE}"
  else
    RELOAD_CMD="export PATH=\"\$PATH:${INSTALL_DIR}\""
  fi
fi

# ── Get started ───────────────────────────────────────────────────────────────

echo ""
echo "Get started:"
if [ -n "$RELOAD_CMD" ]; then
  echo "  ${RELOAD_CMD}"
fi
echo "  ${BINARY} setup    # provision certificate"
echo "  ${BINARY} start    # start the agent"
