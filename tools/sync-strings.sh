#!/usr/bin/env bash
# sync-strings.sh — refresh vendor/app-strings/ from the PGPonyAndroid working tree (D11).
#
# The desktop does not maintain a second translation of anything Android already says. Android's
# six strings.xml files are vendored VERBATIM, exactly like the crypto source, and this script is
# the only thing that writes them:
#
#   app/src/main/res/values/strings.xml         → vendor/app-strings/values/strings.xml
#   app/src/main/res/values-de/strings.xml      → vendor/app-strings/values-de/strings.xml
#   …and es / fr / ja / pt-rBR
#
# Desktop-owned strings — the ones Android has no equivalent for — live in i18n/ and are NEVER
# touched here. build.gradle.kts mounts the two trees under /i18n/android and /i18n/desktop on
# the classpath; Strings.kt resolves ownership from whichever layer's ENGLISH file declares a key.
#
# Delete-and-recopy, so a key retired upstream actually disappears here. Runs the audit at the
# end: a placeholder mismatch that reaches this repo is an upstream bug, and fixing it here would
# be silently reverted by the next sync.
#
# Usage: tools/sync-strings.sh [path-to-PGPonyAndroid]   (default: ../PGPonyAndroid)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_ROOT="${1:-$REPO_ROOT/../PGPonyAndroid}"
RES="$ANDROID_ROOT/app/src/main/res"
DST="$REPO_ROOT/vendor/app-strings"

LOCALES=(values values-de values-es values-fr values-ja values-pt-rBR)

[ -f "$RES/values/strings.xml" ] || {
    echo "error: $RES/values/strings.xml not found (pass the PGPonyAndroid path)" >&2
    exit 1
}

for d in "${LOCALES[@]}"; do
    [ -f "$RES/$d/strings.xml" ] || {
        echo "error: $RES/$d/strings.xml is missing — Android dropped a locale, or the tree moved." >&2
        echo "       Update LOCALES here, I18n.SUPPORTED in Strings.kt and LOCALE_DIRS in" >&2
        echo "       tools/i18n-audit.py together, then re-run." >&2
        exit 1
    }
done

rm -rf "$DST"
for d in "${LOCALES[@]}"; do
    mkdir -p "$DST/$d"
    cp "$RES/$d/strings.xml" "$DST/$d/strings.xml"
    printf '  %-14s %5d keys\n' "$d" "$(grep -c '<string name=' "$DST/$d/strings.xml" || true)"
done

echo "Synced ${#LOCALES[@]} files → vendor/app-strings/"
echo

if command -v python3 >/dev/null 2>&1; then
    python3 "$REPO_ROOT/tools/i18n-audit.py" || {
        echo >&2
        echo "Audit failed. Findings under vendor/app-strings/ are UPSTREAM bugs: fix them in" >&2
        echo "PGPonyAndroid and re-run this script. Never hand-edit vendor/." >&2
        exit 1
    }
else
    echo "python3 not found — skipping the audit. Run tools/i18n-audit.py before committing."
fi

echo "Now run: ./gradlew test"
