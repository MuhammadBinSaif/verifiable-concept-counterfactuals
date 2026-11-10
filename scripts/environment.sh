#!/usr/bin/env bash
set -euo pipefail
release_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$release_root"
if [[ -d "$release_root/.venv/bin" ]]; then export PATH="$release_root/.venv/bin:$PATH"; fi
export PYTHONDONTWRITEBYTECODE=1
export NODE_COMPILE_CACHE="$release_root/.cache/node"
export npm_config_cache="$release_root/.cache/npm"
mkdir -p "$release_root/.cache/tmp"
export TMPDIR="$release_root/.cache/tmp"
