#!/usr/bin/env bash
# Downloads the sing-box core for Linux into src-tauri/binaries/.
# These binaries are gitignored; run this once after cloning (and in CI).
set -euo pipefail

SINGBOX_VERSION="1.14.0"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/src-tauri/binaries"
mkdir -p "$BIN"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) sbarch="amd64" ;;
  aarch64|arm64) sbarch="arm64" ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${sbarch}.tar.gz"
echo "Downloading sing-box ${SINGBOX_VERSION} (${sbarch}) ..."
curl -sSL "$url" -o "$TMP/sb.tar.gz"
tar -xzf "$TMP/sb.tar.gz" -C "$TMP"
found="$(find "$TMP" -type f -name sing-box | head -1)"
cp "$found" "$BIN/sing-box"
chmod +x "$BIN/sing-box"
echo "Done: $BIN/sing-box"
"$BIN/sing-box" version
