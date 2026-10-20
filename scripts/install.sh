#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIRECTORY="${NKP_BINDIR:-$HOME/.local/bin}"

command -v go >/dev/null 2>&1 || { echo "install: go is required" >&2; exit 1; }
mkdir -p "$INSTALL_DIRECTORY"
TEMPORARY_BINARY=$(mktemp "$INSTALL_DIRECTORY/.nkp.XXXXXX")
trap 'rm -f "$TEMPORARY_BINARY"' EXIT

cd "$REPOSITORY_ROOT"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$TEMPORARY_BINARY" .
chmod 755 "$TEMPORARY_BINARY"
mv -f "$TEMPORARY_BINARY" "$INSTALL_DIRECTORY/nkp"
trap - EXIT

echo "installed: $INSTALL_DIRECTORY/nkp"
case ":$PATH:" in
    *":$(cd "$INSTALL_DIRECTORY" && pwd):"*) ;;
    *) echo "install: $INSTALL_DIRECTORY is not on PATH" >&2 ;;
esac
