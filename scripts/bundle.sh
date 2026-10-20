#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VAULT_DIRECTORY="${NKP_VAULT:-}"
OUTPUT_DIRECTORY="${NKP_DIST_DIR:-$REPOSITORY_ROOT/dist}"

[ -n "$VAULT_DIRECTORY" ] || { echo "bundle: NKP_VAULT is not set" >&2; exit 1; }
[ -d "$VAULT_DIRECTORY" ] || { echo "bundle: vault not found: $VAULT_DIRECTORY" >&2; exit 1; }
[ -f "$VAULT_DIRECTORY/README.md" ] || { echo "bundle: recovery README not found in $VAULT_DIRECTORY" >&2; exit 1; }

BASES=()
if [ "$#" -eq 0 ]; then
    for base_path in "$VAULT_DIRECTORY"/*.nkpb; do
        [ -f "$base_path" ] && BASES+=("$base_path")
    done
else
    for requested_path in "$@"; do
        case "$requested_path" in
            /*|*/*) base_path="$requested_path" ;;
            *) base_path="$VAULT_DIRECTORY/$requested_path" ;;
        esac
        [ -f "$base_path" ] || { echo "bundle: base not found: $base_path" >&2; exit 1; }
        BASES+=("$base_path")
    done
fi
[ "${#BASES[@]}" -gt 0 ] || { echo "bundle: no .nkpb bases found in $VAULT_DIRECTORY" >&2; exit 1; }

TIMESTAMP=$(date +%Y%m%d-%H%M)
BUNDLE_NAME="nkp-bundle-$TIMESTAMP"
STAGING_DIRECTORY=$(mktemp -d)
trap 'rm -rf "$STAGING_DIRECTORY"' EXIT
BUNDLE_ROOT="$STAGING_DIRECTORY/$BUNDLE_NAME"
mkdir -p "$BUNDLE_ROOT/bin" "$BUNDLE_ROOT/vault"

"$REPOSITORY_ROOT/scripts/build.sh" "$BUNDLE_ROOT/bin"
for base_path in "${BASES[@]}"; do
    cp "$base_path" "$BUNDLE_ROOT/vault/$(basename "$base_path")"
done
cp "$VAULT_DIRECTORY/README.md" "$BUNDLE_ROOT/vault/README.md"
cp "$REPOSITORY_ROOT/FORMAT.md" "$BUNDLE_ROOT/FORMAT.md"

cat > "$BUNDLE_ROOT/README.md" <<EOF
# nkp recovery bundle

This archive contains encrypted bases, static nkp binaries, and recovery documentation.
The master passwords are not included.

## Use

Choose the binary for the current operating system, then run:

\`\`\`sh
export NKP_VAULT="\$PWD/vault"
./bin/nkp-<os>-<arch> info main
./bin/nkp-<os>-<arch> list main
./bin/nkp-<os>-<arch> show main section
\`\`\`

See \`vault/README.md\` and \`FORMAT.md\` for recovery details.

Generated: $TIMESTAMP
EOF

mkdir -p "$OUTPUT_DIRECTORY"
OUTPUT_PATH="$OUTPUT_DIRECTORY/$BUNDLE_NAME.tar.gz"
tar -C "$STAGING_DIRECTORY" -czf "$OUTPUT_PATH.part" "$BUNDLE_NAME"
mv -f "$OUTPUT_PATH.part" "$OUTPUT_PATH"
echo "bundled: $OUTPUT_PATH"
