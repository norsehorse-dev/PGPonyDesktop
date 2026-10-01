#!/bin/bash
# Compare two builds of the PGPony Linux app image before the CI one is signed.
#
#   packaging/release/compare-builds.sh <A> <B> [--all]
#
# A and B are each a portable tarball (.tar.gz), an AppImage, a .deb, or an already extracted
# app directory. Typical use (RELEASING.md section 4): A is the tarball CI attached to the draft,
# B is the tarball built from the same tag on a machine you control. Also useful: the CI tarball
# against the CI AppImage of the same architecture, which shows that the AppImage step added
# nothing to the app.
#
# What is compared: every jar in lib/app, entry by entry, by the sha256 of each entry's content.
# Timestamps and entry order are ignored, since a jar rebuilt from the same sources differs in
# those alone. That covers PGPony's own code and every library it ships. The launcher configuration
# beside them (lib/app/*.cfg: classpath, main class, JVM options) must match byte for byte. Exit
# status is 0 when all of these match and 1 otherwise.
#
# With --all, every other file is compared by sha256 as well and differences are listed. They are
# informational only: the bundled Java runtime and the native launcher come from whichever JDK did
# the build, so they match only when both sides used the same JDK build.
#
# Needs python3. A .deb needs dpkg-deb; an AppImage needs unsquashfs (squashfs-tools).
set -euo pipefail

if [ $# -lt 2 ]; then
  sed -n '2,22p' "$0"
  exit 2
fi
A=$1
B=$2
ALL=${3:-}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Offset of the squashfs image inside an AppImage: the end of the runtime ELF's section table.
appimage_offset() {
  python3 - "$1" <<'PY'
import struct, sys
with open(sys.argv[1], 'rb') as f:
    h = f.read(64)
if h[:4] != b'\x7fELF':
    sys.exit('not an ELF file')
if h[4] == 2:
    shoff, = struct.unpack_from('<Q', h, 0x28)
    shentsize, shnum = struct.unpack_from('<HH', h, 0x3A)
else:
    shoff, = struct.unpack_from('<I', h, 0x20)
    shentsize, shnum = struct.unpack_from('<HH', h, 0x2E)
print(shoff + shentsize * shnum)
PY
}

# Unpack $1 into directory $2 and print the app root (the directory holding lib/app).
unpack() {
  local src=$1 dest=$2
  mkdir -p "$dest"
  if [ -d "$src" ]; then
    dest=$src
  else
    case "$src" in
      *.tar.gz|*.tgz) tar -xzf "$src" -C "$dest" ;;
      *.deb) dpkg-deb -x "$src" "$dest" ;;
      *.AppImage) unsquashfs -q -n -o "$(appimage_offset "$src")" -d "$dest/squashfs-root" "$src" >/dev/null ;;
      *) echo "unknown kind of build: $src" >&2; exit 2 ;;
    esac
  fi
  local appdir
  appdir=$(find "$dest" -type d -path '*/lib/app' | head -n 1)
  if [ -z "$appdir" ]; then
    echo "no lib/app directory in $src" >&2
    exit 2
  fi
  dirname "$(dirname "$appdir")"
}

rootA=$(unpack "$A" "$work/a")
rootB=$(unpack "$B" "$work/b")
echo "A: $A ($rootA)"
echo "B: $B ($rootB)"

python3 - "$rootA" "$rootB" "$ALL" <<'PY'
import hashlib, os, sys, zipfile

root_a, root_b, show_all = sys.argv[1], sys.argv[2], sys.argv[3] == '--all'

def jar_digest(path):
    # A name stored twice keeps both copies (marked), so a second, different copy hidden behind
    # the first still shows up as a difference.
    out = {}
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            name = info.filename
            while name in out:
                name += ' (again)'
            out[name] = hashlib.sha256(z.read(info)).hexdigest()
    return out

def file_digest(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def files(root):
    out = {}
    for d, _, names in os.walk(root):
        for n in names:
            p = os.path.join(d, n)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            out[os.path.relpath(p, root)] = p
    return out

fa, fb = files(root_a), files(root_b)
jars = sorted(k for k in set(fa) | set(fb) if k.startswith('lib/app/') and k.endswith('.jar'))
bad = 0
for j in jars:
    if j not in fa or j not in fb:
        print('MISSING  %s (only in %s)' % (j, 'A' if j in fa else 'B'))
        bad += 1
        continue
    da, db = jar_digest(fa[j]), jar_digest(fb[j])
    if da == db:
        print('same     %s' % j)
        continue
    bad += 1
    print('DIFFERS  %s' % j)
    for e in sorted(set(da) | set(db)):
        if da.get(e) != db.get(e):
            print('           %s' % e)

# The launcher configuration (classpath, main class, JVM options) decides what the jars run
# with, so it must match byte for byte as well.
cfgs = sorted(k for k in set(fa) | set(fb) if k.startswith('lib/app/') and k.endswith('.cfg'))
for c in cfgs:
    if c not in fa or c not in fb:
        print('MISSING  %s (only in %s)' % (c, 'A' if c in fa else 'B'))
        bad += 1
    elif file_digest(fa[c]) != file_digest(fb[c]):
        print('DIFFERS  %s' % c)
        bad += 1
    else:
        print('same     %s' % c)

if show_all:
    print('')
    print('Other files (informational):')
    for k in sorted(set(fa) | set(fb)):
        if k in jars or k in cfgs:
            continue
        if k not in fa or k not in fb:
            print('  only in %s: %s' % ('A' if k in fa else 'B', k))
            continue
        if file_digest(fa[k]) != file_digest(fb[k]):
            print('  differs: %s' % k)

print('')
if bad:
    print('%d of %d jars and launcher configs differ or are missing.' % (bad, len(jars) + len(cfgs)))
    sys.exit(1)
if not jars:
    print('No jars found in lib/app.')
    sys.exit(1)
print('All %d jars in lib/app match.' % len(jars))
PY
