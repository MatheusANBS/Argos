#!/usr/bin/env bash
set -euo pipefail
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.codex/skills"
TARGET_DIR="${1:-${CODEX_HOME:-$HOME/.codex}/skills}"
mkdir -p "$TARGET_DIR"
for skill in "$SOURCE_DIR"/*; do
  [ -d "$skill" ] || continue
  name="$(basename "$skill")"
  rm -rf "$TARGET_DIR/$name"
  cp -R "$skill" "$TARGET_DIR/$name"
  printf 'installed %s\n' "$name"
done
