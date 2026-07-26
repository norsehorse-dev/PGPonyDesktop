#!/usr/bin/env bash
# sync-vendor.sh — refresh vendor/ from the PGPonyAndroid working tree.
# Delete-and-recopy so removals upstream propagate. Run the test suite afterward.
#
# Synced trees:
#   app/src/main/java/com/pgpony/android/crypto      → vendor/app-crypto/...        (D1)
#   app/src/main/java/com/pgpony/android/data        → vendor/app-data/...          (D2a)
#   app/src/main/java/com/pgpony/android/backup      → vendor/app-backup/...        (D6)
#   app/src/main/java/com/pgpony/android/network     → vendor/app-network/...       (D4)
#   app/src/main/java/com/pgpony/android/keyserver   → vendor/app-network/...       (D4)
#   app/src/test/kotlin/com/pgpony/android/crypto    → vendor/app-crypto-tests/...  (D5)
#   app/src/test/kotlin/.../data/PGPKeyEntityKeyIdTest.kt → same tree               (D5)
#   app/src/test/kotlin/.../backup/BackupCodecTest.kt     → same tree               (D6)
#   app/src/test/resources                           → vendor/app-test-resources/   (D5)
#
# ALL trees sync together, every run — never refresh one in isolation (D5 Fix1: a
# main-tree/test-tree snapshot skew produced phantom unresolved references).
#
# Usage: tools/sync-vendor.sh [path-to-PGPonyAndroid]   (default: ../PGPonyAndroid)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_ROOT="${1:-$REPO_ROOT/../PGPonyAndroid}"
BASE="$ANDROID_ROOT/app/src/main/java/com/pgpony/android"

[ -d "$BASE/crypto" ] || { echo "error: $BASE/crypto not found (pass the PGPonyAndroid path)"; exit 1; }

sync_tree() { # $1 = source subdir under com/pgpony/android, $2 = vendor root name
    local src="$BASE/$1"
    local dst="$REPO_ROOT/vendor/$2/com/pgpony/android/$1"
    rm -rf "$dst"
    mkdir -p "$(dirname "$dst")"
    cp -R "$src" "$dst"
    find "$dst" \( -name ".DS_Store" -o -name "*.bak" -o -name ".fuse_hidden*" \) -delete
    echo "Synced $(find "$dst" -name '*.kt' | wc -l | tr -d ' ') .kt files → vendor/$2/…/$1"
}

sync_tree crypto app-crypto
sync_tree data app-data
sync_tree backup app-backup
sync_tree network app-network
sync_tree keyserver app-network

# D5 — the crypto unit-test suite + fixtures.
TSRC="$ANDROID_ROOT/app/src/test"
TDST="$REPO_ROOT/vendor/app-crypto-tests/com/pgpony/android"
rm -rf "$TDST"
mkdir -p "$TDST/data"
cp -R "$TSRC/kotlin/com/pgpony/android/crypto" "$TDST/crypto"
cp "$TSRC/kotlin/com/pgpony/android/data/PGPKeyEntityKeyIdTest.kt" "$TDST/data/" 2>/dev/null || true
mkdir -p "$TDST/backup"
cp "$TSRC/kotlin/com/pgpony/android/backup/BackupCodecTest.kt" "$TDST/backup/" 2>/dev/null || true
rm -rf "$REPO_ROOT/vendor/app-test-resources"
mkdir -p "$REPO_ROOT/vendor/app-test-resources"
cp -R "$TSRC/resources/." "$REPO_ROOT/vendor/app-test-resources/"
find "$TDST" "$REPO_ROOT/vendor/app-test-resources" \( -name ".DS_Store" -o -name "*.bak" \) -delete
echo "Synced $(find "$TDST" -name '*.kt' | wc -l | tr -d ' ') test .kt files + $(find "$REPO_ROOT/vendor/app-test-resources" -type f | wc -l | tr -d ' ') fixtures"

echo "Remember: excluded files + shims are inventoried in vendor/README.md."
echo "Now run: ./gradlew test && ./gradlew run --args=selftest"
