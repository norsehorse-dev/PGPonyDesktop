#!/bin/zsh
# make-portable-macos.sh <notarized.dmg> <out.zip>
#
# PGPony Desktop 3.1.0 (plan 3e.4): the macOS portable zip. Copies PGPony.app out of a
# notarized, stapled release dmg, staples the app itself (a zip has no dmg to carry the ticket,
# and a portable copy may be opened offline), checks it with Gatekeeper, and zips it beside an
# empty PGPony-data folder, which is what switches portable mode on.
#
# Run after section 3 of RELEASING.md, once per dmg:
#   zsh packaging/release/make-portable-macos.sh ~/pgpony-release/PGPony-macOS.dmg ~/pgpony-release/PGPony-macOS-portable.zip
#   zsh packaging/release/make-portable-macos.sh ~/pgpony-release/PGPony-macOS-intel.dmg ~/pgpony-release/PGPony-macOS-intel-portable.zip

set -euo pipefail

dmg=${1:?usage: make-portable-macos.sh <dmg> <out.zip>}
out=${2:?usage: make-portable-macos.sh <dmg> <out.zip>}
[[ -f $dmg ]] || { print -u2 "no such dmg: $dmg"; exit 1; }
[[ -e $out ]] && { print -u2 "refusing to overwrite $out"; exit 1; }

mnt=$(mktemp -d /tmp/pgpony-portable-mnt.XXXXXX)
work=$(mktemp -d /tmp/pgpony-portable-work.XXXXXX)
cleanup() {
  hdiutil detach "$mnt" -quiet 2>/dev/null || true
  rm -rf "$work"
  rmdir "$mnt" 2>/dev/null || true
}
trap cleanup EXIT

hdiutil attach "$dmg" -nobrowse -readonly -mountpoint "$mnt" -quiet
mkdir -p "$work/PGPony/PGPony-data"
ditto "$mnt/PGPony.app" "$work/PGPony/PGPony.app"
cat > "$work/PGPony/PGPony-data/README.txt" <<'TXT'
PGPony keeps its keys and settings in this folder while it runs from here.
Delete or rename the folder and PGPony uses the computer's own folders again.
To update, replace PGPony.app with the new version and keep this folder.
TXT

xcrun stapler staple "$work/PGPony/PGPony.app"
xcrun stapler validate "$work/PGPony/PGPony.app"
spctl -a -t exec -vv "$work/PGPony/PGPony.app"

ditto -c -k --sequesterRsrc --keepParent "$work/PGPony" "$out"
ls -l "$out"
