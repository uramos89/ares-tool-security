#!/usr/bin/env bash
# Ares Tool Security — Full Scan Script
# Runs all 4 modules in sequence against a single target.
# Generates 4 separate .md reports in reports/
#
# Usage: ./scripts/full-scan.sh https://example.com

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:?Usage: $0 <target-url>}"
MODULES_DIR="$SCRIPT_DIR/modules"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║    Ares Tool Security — Full Scan       ║"
echo "  ║    Target: $TARGET"
echo "  ╚══════════════════════════════════════════╝"
echo ""

for module in web-audit brute-force ddos-audit vuln-scan; do
    module_path="$MODULES_DIR/$module.py"
    if [ -f "$module_path" ]; then
        echo ""
        echo "  ── Running: $module ──"
        python3 "$module_path" "$TARGET" 2>&1
        echo ""
        echo "  ── Done: $module ──"
        echo ""
    else
        echo "  ⚠️  Module not found: $module.py — skipping"
    fi
done

echo "  ╔══════════════════════════════════════════╗"
echo "  ║    Full scan complete                    ║"
echo "  ║    Reports in: $SCRIPT_DIR/reports/"
echo "  ╚══════════════════════════════════════════╝"
