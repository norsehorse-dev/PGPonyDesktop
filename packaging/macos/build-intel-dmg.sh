#!/bin/sh
# build-intel-dmg.sh: the Intel (x86_64) dmg, built on an Apple silicon Mac under Rosetta 2.
#
# jpackage cannot cross-compile, but an x86_64 JDK runs under Rosetta, and everything Compose picks
# per machine (the Skiko natives, the bundled Java runtime, the launcher) follows the architecture
# of the JDK that runs Gradle. So this is the normal dmg build on an x86_64 JDK 17, followed by a
# check that every native file in the app came out x86_64.
#
#   X64_JDK=<x86_64 JDK 17>/Contents/Home packaging/macos/build-intel-dmg.sh [task] [gradle args]
#
# The task defaults to packageDmg (unsigned, for a local try). For a release, source the
# notarization env and pass notarizeDmg plus the teamID property, as in RELEASING.md section 3.
# It runs `clean` first and leaves its result in $OUT_DIR (default ~/pgpony-release) as
# PGPony-macOS-intel.dmg, so copy the Apple silicon dmg out of build/ before running it.
set -eu
: "${X64_JDK:?set X64_JDK to the Contents/Home folder of an x86_64 JDK 17}"
OUT_DIR="${OUT_DIR:-$HOME/pgpony-release}"
cd "$(dirname "$0")/../.."

if [ ! -x "$X64_JDK/bin/java" ]; then
  echo "no JDK at $X64_JDK (expected bin/java under it; point X64_JDK at the JDK's Contents/Home)" >&2; exit 1
fi
if ! file "$X64_JDK/bin/java" | grep -q x86_64; then
  echo "$X64_JDK/bin/java is not an x86_64 binary" >&2; exit 1
fi
if ! arch -x86_64 /usr/bin/true 2>/dev/null; then
  echo "Rosetta 2 is not installed: softwareupdate --install-rosetta --agree-to-license" >&2; exit 1
fi
if [ $# -gt 0 ]; then TASK="$1"; shift; else TASK=packageDmg; fi

# Only this JDK may serve as the toolchain, so an arm64 JDK 17 found elsewhere on the Mac can
# never be picked for compiling or for jpackage.
export JAVA_HOME="$X64_JDK"
arch -x86_64 ./gradlew \
  -Porg.gradle.java.installations.auto-detect=false \
  -Porg.gradle.java.installations.auto-download=false \
  -Porg.gradle.java.installations.paths="$X64_JDK" \
  clean "$TASK" "$@"

DMG=$(ls build/compose/binaries/main/dmg/PGPony-*.dmg)
MNT=$(mktemp -d /tmp/pgpony-intel.XXXXXX)
hdiutil attach "$DMG" -nobrowse -readonly -mountpoint "$MNT" >/dev/null
trap 'hdiutil detach "$MNT" >/dev/null 2>&1 || true' EXIT
APP="$MNT/PGPony.app"

# Every Mach-O file in the bundle must be x86_64. An arm64-only one means the arm64 JDK or
# arm64 natives leaked in, and the app would not start on an Intel Mac.
BAD=0
find "$APP" -type f | while read -r f; do
  if file "$f" | grep -q 'Mach-O'; then
    if ! lipo -archs "$f" 2>/dev/null | grep -q x86_64; then
      echo "not x86_64: ${f#"$APP"/}"; echo x
    fi
  fi
done > /tmp/pgpony-intel-check.txt
if grep -q '^x$' /tmp/pgpony-intel-check.txt; then
  grep -v '^x$' /tmp/pgpony-intel-check.txt >&2; BAD=1
fi
# Skiko's dylib travels inside a jar, so check which runtime jar was bundled.
if ! ls "$APP/Contents/app" | grep -q 'skiko-awt-runtime-macos-x64'; then
  echo "the bundled Skiko runtime is not macos-x64:" >&2
  ls "$APP/Contents/app" | grep skiko >&2 || true
  BAD=1
fi
[ "$BAD" -eq 0 ] || { echo "Intel dmg check failed" >&2; exit 1; }

mkdir -p "$OUT_DIR"
cp "$DMG" "$OUT_DIR/PGPony-macOS-intel.dmg"
echo "Intel dmg checked: every native file is x86_64. Saved as $OUT_DIR/PGPony-macOS-intel.dmg"
