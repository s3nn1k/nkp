#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIRECTORY="${1:-$REPOSITORY_ROOT/bin}"
PLATFORMS=(
    darwin-arm64
    darwin-amd64
    linux-amd64
    linux-arm64
    windows-amd64
)

mkdir -p "$OUTPUT_DIRECTORY"
case "$OUTPUT_DIRECTORY" in /*) ;; *) OUTPUT_DIRECTORY="$PWD/$OUTPUT_DIRECTORY" ;; esac
cd "$REPOSITORY_ROOT"

for platform in "${PLATFORMS[@]}"; do
    operating_system="${platform%-*}"
    architecture="${platform#*-}"
    extension=""
    [ "$operating_system" = windows ] && extension=.exe
    output_path="$OUTPUT_DIRECTORY/nkp-$platform$extension"
    echo "building: $output_path"
    CGO_ENABLED=0 GOOS="$operating_system" GOARCH="$architecture" \
        go build -trimpath -ldflags "-s -w" -o "$output_path" .
done
