#!/usr/bin/env bash
set -euo pipefail

echo "[npm-export-import] Starting..."
exec python3 /app/npm_export_import.py
