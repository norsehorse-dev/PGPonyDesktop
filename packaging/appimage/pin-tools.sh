#!/bin/sh
# Pin appimagetool and the type2 runtime for the release build.
#
#   packaging/appimage/pin-tools.sh [appimagetool-version] [type2-runtime-version]
#
# Downloads both architectures of each tool at the given release (default: the versions already
# in tools.pin), checks the runtime's detached signature against the key published in the
# type2-runtime repository when gpg is available, and rewrites tools.pin with the sha256 of what
# it downloaded. Nothing is run. Review `git diff packaging/appimage/tools.pin` before committing.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
pin="$here/tools.pin"
. "$pin"
tool_version=${1:-$APPIMAGETOOL_VERSION}
runtime_version=${2:-$TYPE2_RUNTIME_VERSION}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() {
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"
}

sha() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

for arch in x86_64 aarch64; do
  fetch "https://github.com/AppImage/appimagetool/releases/download/$tool_version/appimagetool-$arch.AppImage" "$work/appimagetool-$arch"
  fetch "https://github.com/AppImage/type2-runtime/releases/download/$runtime_version/runtime-$arch" "$work/runtime-$arch"
done

if command -v gpg >/dev/null 2>&1; then
  fetch "https://raw.githubusercontent.com/AppImage/type2-runtime/$runtime_version/signing-pubkey.asc" "$work/signing-pubkey.asc"
  export GNUPGHOME="$work/gnupg"
  mkdir -m 700 "$GNUPGHOME"
  gpg --quiet --import "$work/signing-pubkey.asc"
  for arch in x86_64 aarch64; do
    if fetch "https://github.com/AppImage/type2-runtime/releases/download/$runtime_version/runtime-$arch.sig" "$work/runtime-$arch.sig"; then
      gpg --verify "$work/runtime-$arch.sig" "$work/runtime-$arch"
    else
      echo "note: no runtime-$arch.sig in release $runtime_version, signature not checked"
    fi
  done
else
  echo "note: gpg not found, runtime signatures not checked"
fi

cat > "$pin.new" <<PIN
$(sed -n '/^#/p' "$pin")
APPIMAGETOOL_VERSION=$tool_version
TYPE2_RUNTIME_VERSION=$runtime_version
APPIMAGETOOL_X86_64_SHA256=$(sha "$work/appimagetool-x86_64")
APPIMAGETOOL_AARCH64_SHA256=$(sha "$work/appimagetool-aarch64")
RUNTIME_X86_64_SHA256=$(sha "$work/runtime-x86_64")
RUNTIME_AARCH64_SHA256=$(sha "$work/runtime-aarch64")
PIN
mv "$pin.new" "$pin"
cat "$pin"
