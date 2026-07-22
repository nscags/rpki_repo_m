#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="$HOME/.rpki-cache/repository"
VRPS_FILE="$SCRIPT_DIR/rpki_vrps.csv"
HOSTNAMES_FILE="$SCRIPT_DIR/repo_hostnames.txt"

# ── Step 1: Fresh Routinator scan (optional) ───────────────────────────────────
if [[ "${1:-}" == "--fresh" ]]; then
    echo "[1/3] Running fresh Routinator scan..."
    routinator --fresh vrps --format csv --output "$VRPS_FILE"
    echo "      Saved VRPs to $VRPS_FILE"
else
    echo "[1/3] Skipping Routinator scan (pass --fresh to run it)"
    if [[ ! -f "$VRPS_FILE" ]]; then
        echo "ERROR: $VRPS_FILE not found. Run with --fresh first." >&2
        exit 1
    fi
fi

# ── Step 2: Extract hostnames from Routinator cache ────────────────────────────
echo "[2/3] Extracting hostnames from cache..."

{
    ls "$CACHE_DIR/rsync/" 2>/dev/null
    ls "$CACHE_DIR/rrdp/"  2>/dev/null
} | grep -v '^tmp$' | sort -u > "$HOSTNAMES_FILE"

count=$(wc -l < "$HOSTNAMES_FILE")
echo "      Found $count hostnames → $HOSTNAMES_FILE"

# ── Step 3: Run analysis ───────────────────────────────────────────────────────
echo "[3/3] Running analysis..."
cd "$SCRIPT_DIR"
python3 analyze_repos.py
