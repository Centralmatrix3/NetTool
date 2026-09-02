#!/usr/bin/env bash

set -euo pipefail

SINGBOX_VERSION="${SINGBOX_VERSION:-1.14.0}"

if [[ "${1:-}" == "--version" ]]; then
    SINGBOX_VERSION="$2"
    shift 2
fi

INPUT_PATH="${1:-Ruleset/Sing-box}"
OUTPUT_PATH="${2:-$INPUT_PATH}"
SINGBOX_ARCH="linux-amd64"
SINGBOX_DIR="sing-box-${SINGBOX_VERSION}-${SINGBOX_ARCH}"
SINGBOX_ARCHIVE="sing-box.tar.gz"

curl -fsSL -o "$SINGBOX_ARCHIVE" "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${SINGBOX_DIR}.tar.gz"
tar -xzf "$SINGBOX_ARCHIVE"
chmod +x "${SINGBOX_DIR}/sing-box"
sudo mv "${SINGBOX_DIR}/sing-box" /usr/local/bin/sing-box
sing-box version

mkdir -p "$OUTPUT_PATH"
for file in "$INPUT_PATH"/*.json; do
    [ ! -f "$file" ] && echo "$file Not Found." && continue
    filename="$(basename "${file%.json}")"
    sing-box rule-set compile "$file" -o "$OUTPUT_PATH/$filename.srs"
done
rm -rf "$SINGBOX_ARCHIVE" "$SINGBOX_DIR"
