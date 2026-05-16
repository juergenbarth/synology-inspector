#!/usr/bin/env bash
# build-members-zip.sh
# Creates the Members ZIP (public files + pdf-export.js + patched index.html).
# Run from the project root: ./build-members-zip.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="1.0"
OUT="$SCRIPT_DIR/dist/synology-inspector-members-v${VERSION}.zip"
TMP="$SCRIPT_DIR/dist/_tmp_members"

# ── Checks ────────────────────────────────────────────────────────────────────

if [ ! -f "$SCRIPT_DIR/js/pdf-export.js" ]; then
    echo "ERROR: js/pdf-export.js not found — place the members file there first." >&2
    exit 1
fi

# ── Prepare temp directory ────────────────────────────────────────────────────

rm -rf "$TMP"
mkdir -p "$TMP"

# Copy all public files
rsync -a \
    --exclude='.git' \
    --exclude='.gitignore' \
    --exclude='*.dss' \
    --exclude='*.png' \
    --exclude='*.jpg' \
    --exclude='*.jpeg' \
    --exclude='ConfigBkp' \
    --exclude='dist' \
    --exclude='build-members-zip.sh' \
    --exclude='.DS_Store' \
    "$SCRIPT_DIR/" "$TMP/"

# Keep only the logo image
mkdir -p "$TMP/img"
cp "$SCRIPT_DIR/img/logo-jklp.png" "$TMP/img/logo-jklp.png"

# ── Add members-only file ─────────────────────────────────────────────────────

cp "$SCRIPT_DIR/js/pdf-export.js" "$TMP/js/pdf-export.js"

# ── Patch index.html — inject pdf-export.js script tag before app.js ─────────

sed -i '' \
    's|    <!-- ── app.js — must be last|    <!-- ── Members only ──────────────────────────────────────────────── -->\n    <script src="js/pdf-export.js"></script>\n\n    <!-- ── app.js — must be last|' \
    "$TMP/index.html"

# ── Create ZIP ────────────────────────────────────────────────────────────────

mkdir -p "$SCRIPT_DIR/dist"
rm -f "$OUT"
cd "$TMP"
zip -r "$OUT" . -x "*.DS_Store"
cd "$SCRIPT_DIR"

# ── Cleanup ───────────────────────────────────────────────────────────────────

rm -rf "$TMP"

echo "✓ Members ZIP created: $OUT"
