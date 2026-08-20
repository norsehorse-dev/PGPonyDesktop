#!/bin/sh
# linux-wrap-launcher.sh <app-image-root>
#
# Wraps the jpackage launcher so it preloads the system libfreetype before the JVM starts, fixing
# the blank GTK file chooser on Linux (issue #1).
#
# Root cause: on Linux, Compose/Skiko loads its own FreeType into the process and its symbols sit
# ahead of the system copy in the global scope. When AWT opens a GTK file chooser, GTK binds its
# text drawing to Skiko's FreeType instead of the system one, every widget fails to draw with
# "error occurred in libfreetype", and the picker opens empty. Preloading the system
# libfreetype.so.6 puts one FreeType ahead of everything so the JVM and GTK agree; Skiko's own UI
# is unaffected because it links FreeType statically. Replacing the JDK runtime's bundled
# libfreetype does NOT fix this (verified: the interposer is Skiko's copy, not the JDK's), so the
# fix must be an LD_PRELOAD set before the JVM starts, which means wrapping the launcher.
#
# The jpackage launcher locates its config by its own basename, so the real ELF is renamed to
# PGPony.bin (config renamed to match) and a shell PGPony takes its place. ldconfig is not on a
# typical login PATH, so it is tried by absolute path first, then a glob of the multiarch library
# dirs as a fallback. Idempotent: re-running on an already-wrapped image is a no-op.
set -eu

APP="${1:?usage: linux-wrap-launcher.sh <app-image-root>}"
BIN="$APP/bin/PGPony"
CFG="$APP/lib/app/PGPony.cfg"

if [ -e "$APP/bin/PGPony.bin" ]; then
  echo "linux-wrap-launcher: $APP already wrapped, nothing to do"
  exit 0
fi
if [ ! -f "$BIN" ] || [ ! -f "$CFG" ]; then
  echo "linux-wrap-launcher: expected launcher $BIN and config $CFG" >&2
  exit 1
fi

mv "$BIN" "$APP/bin/PGPony.bin"
mv "$CFG" "$APP/lib/app/PGPony.bin.cfg"

cat > "$BIN" <<'WRAP'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
SYS_FT=""
for LDC in ldconfig /sbin/ldconfig /usr/sbin/ldconfig; do
  SYS_FT="$("$LDC" -p 2>/dev/null | awk '/libfreetype\.so\.6/ {print $NF; exit}')"
  [ -n "$SYS_FT" ] && break
done
if [ -z "$SYS_FT" ]; then
  for d in /usr/lib/*/ /usr/lib/ /lib/*/ /lib/; do
    if [ -e "${d}libfreetype.so.6" ]; then SYS_FT="${d}libfreetype.so.6"; break; fi
  done
fi
if [ -n "$SYS_FT" ] && [ -e "$SYS_FT" ]; then
  LD_PRELOAD="${SYS_FT}${LD_PRELOAD:+:$LD_PRELOAD}"
  export LD_PRELOAD
fi
exec "$HERE/PGPony.bin" "$@"
WRAP
chmod +x "$BIN"
echo "linux-wrap-launcher: wrapped $BIN (real launcher -> PGPony.bin)"
