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
# 3.1.0: jars are paired by name without the content hash Compose appends to each file name
# (foo-1.0-<hash>.jar). Compose re-packs the Skiko runtime jar each time it packages, with fresh
# timestamps, so that one jar gets a new name in every build even when every entry is the same, and
# pairing by full name never compared it. The launcher configuration is compared the same way,
# with those hashes taken out of its classpath, and PGPony.bin.cfg (the name the release's
# libfreetype launcher wrapper gives it, tools/linux-wrap-launcher.sh) is compared as PGPony.cfg.
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
import hashlib, os, re, sys, zipfile

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

# Compose's content hash in a jar file name: the last dash-separated part, 16 to 32 hex digits.
HASHED = re.compile(r'-[0-9a-f]{16,32}\.jar$')
HASHED_IN_TEXT = re.compile(r'-[0-9a-f]{16,32}\.jar\b')

def stable(name):
    return HASHED.sub('.jar', name)

def by_stable_name(found):
    out, dupes = {}, []
    for k, p in found.items():
        if not (k.startswith('lib/app/') and k.endswith('.jar')):
            continue
        s = stable(k)
        if s in out:
            dupes.append(s)
        out[s] = (k, p)
    return out, dupes

ja, dupes_a = by_stable_name(fa)
jb, dupes_b = by_stable_name(fb)
bad = 0
for d in sorted(set(dupes_a + dupes_b)):
    print('AMBIGUOUS %s (two jars share this name once the hash is taken off)' % d)
    bad += 1
jars = sorted(set(ja) | set(jb))
for j in jars:
    if j not in ja or j not in jb:
        k = (ja.get(j) or jb.get(j))[0]
        print('MISSING  %s (only in %s)' % (k, 'A' if j in ja else 'B'))
        bad += 1
        continue
    (ka, pa), (kb, pb) = ja[j], jb[j]
    da, db = jar_digest(pa), jar_digest(pb)
    label = ka if ka == kb else '%s (B: %s)' % (ka, os.path.basename(kb))
    if da == db:
        print('same     %s' % label)
        continue
    bad += 1
    print('DIFFERS  %s' % label)
    for e in sorted(set(da) | set(db)):
        if da.get(e) != db.get(e):
            print('           %s' % e)

# The launcher configuration (classpath, main class, JVM options) decides what the jars run
# with, so it must match byte for byte as well.
def cfg_map(found):
    out = {}
    for k, p in found.items():
        if k.startswith('lib/app/') and k.endswith('.cfg'):
            out[k.replace('lib/app/PGPony.bin.cfg', 'lib/app/PGPony.cfg')] = (k, p)
    return out

def cfg_text(path):
    with open(path, 'rb') as f:
        return HASHED_IN_TEXT.sub('.jar', f.read().decode('utf-8', 'replace').replace('\r\n', '\n')).encode()

ca, cb = cfg_map(fa), cfg_map(fb)
cfgs = sorted(set(ca) | set(cb))
for c in cfgs:
    if c not in ca or c not in cb:
        print('MISSING  %s (only in %s)' % ((ca.get(c) or cb.get(c))[0], 'A' if c in ca else 'B'))
        bad += 1
        continue
    (ka, pa), (kb, pb) = ca[c], cb[c]
    label = ka if ka == kb else '%s (B: %s)' % (ka, os.path.basename(kb))
    if cfg_text(pa) != cfg_text(pb):
        print('DIFFERS  %s' % label)
        bad += 1
    else:
        print('same     %s' % label)

if show_all:
    print('')
    print('Other files (informational):')
    for k in sorted(set(fa) | set(fb)):
        if k.startswith('lib/app/') and (k.endswith('.jar') or k.endswith('.cfg')):
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
