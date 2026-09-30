#!/usr/bin/env bash
# sync-ponydirect.sh: refresh vendor/ponydirect/ from a PonyDirect-Kotlin checkout.
# Delete-and-recopy the library's main sources (not its tests), so removals upstream propagate.
# Record the commit in vendor/README.md and run the test suite afterward.
#
# Usage: tools/sync-ponydirect.sh [path-to-PonyDirect-Kotlin]   (default: ../PonyDirect-Kotlin)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PD_ROOT="${1:-$REPO_ROOT/../PonyDirect-Kotlin}"
SRC="$PD_ROOT/ponydirect/src/main/kotlin/com/ponydirect"
DST="$REPO_ROOT/vendor/ponydirect/com/ponydirect"

[ -d "$SRC" ] || { echo "error: $SRC not found (pass the PonyDirect-Kotlin path)"; exit 1; }

rm -rf "$DST"
mkdir -p "$DST"
cp "$SRC"/*.kt "$DST"/
echo "Synced $(find "$DST" -name '*.kt' | wc -l | tr -d ' ') .kt files to vendor/ponydirect/com/ponydirect"
if git -C "$PD_ROOT" rev-parse --short HEAD >/dev/null 2>&1; then
    echo "PonyDirect-Kotlin commit: $(git -C "$PD_ROOT" rev-parse --short HEAD) (record it in vendor/README.md)"
fi
