#!/usr/bin/env python3
"""Generate the desktop icon set from the PGPony master artwork.

The canonical master is the iOS app-icon source — a 1024x1024 full-bleed square
carrying the brand gradient (#4B69F1 -> #B42DEB, top-left to bottom-right) with the
white padlock/pony mark centred on it. The Android adaptive icon, the Play listing
icon and everything here are all derived from that one file, so it stays the single
place the artwork is edited.

    PGPony/Assets.xcassets/AppIcon.appiconset/pgpony-appicon-2014px.png

Run it from the PGPonyDesktop repo root:

    python3 tools/make-icons.py ../PGPony/Assets.xcassets/AppIcon.appiconset/pgpony-appicon-2014px.png

Outputs (all regenerated from scratch, all safe to delete and re-run):

    src/main/resources/icons/pgpony_512.png   window + dock/taskbar icon, nav rail mark
    src/main/resources/icons/pgpony_tray.png  system tray / menu-bar icon
    packaging/pgpony.png                      jpackage, Linux
    packaging/pgpony.ico                      jpackage, Windows (multi-size)
    packaging/pgpony.icns                     jpackage, macOS (multi-size, Retina pairs)

`src/main/resources/icons/pgpony.png` is NOT touched: that one is the 128px family
avatar in the PGPony-apps link list beside agepony, burnpony and friends, and it is
sized and cropped to match them.

Requires Pillow. numpy is used for the corner mask when present and a supersampled
ImageDraw path stands in when it is not, so the script runs on a bare Pillow install.
"""

import os
import struct
import sys

from PIL import Image, ImageDraw

try:
    import numpy as np
except ImportError:  # pragma: no cover - exercised only on a numpy-less box
    np = None

# Apple's continuous corner curve is a superellipse rather than a circular arc: the
# curvature ramps in instead of switching on at the tangent point, which is why a plain
# rounded rectangle reads as visibly "pillowed" next to real macOS icons. Exponent 5 is
# the usual fit; 0.2237 is the corner-radius ratio Apple's own icon template uses.
SQUIRCLE_EXPONENT = 5.0
CORNER_RATIO = 0.2237

# macOS draws app icons inside a fixed grid: on a 1024 canvas the rounded square occupies
# 824px, and the rest is transparent margin the system fills with its drop shadow. Skip it
# and PGPony sits noticeably larger than every other icon in the Dock.
MACOS_CONTENT_RATIO = 824.0 / 1024.0

ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)

# ICNS chunk types. The ic07.. family is PNG-in-container, which every macOS that can run
# a JDK 17 app understands; the older icp4/icp5 entries keep Finder happy at small sizes.
ICNS_CHUNKS = (
    (b"icp4", 16),
    (b"icp5", 32),
    (b"ic11", 32),    # 16pt @2x
    (b"ic12", 64),    # 32pt @2x
    (b"ic07", 128),
    (b"ic13", 256),   # 128pt @2x
    (b"ic08", 256),
    (b"ic14", 512),   # 256pt @2x
    (b"ic09", 512),
    (b"ic10", 1024),  # 512pt @2x
)


def squircle_mask(size):
    """An 8-bit alpha mask: opaque inside the superellipse, transparent outside."""
    radius = size * CORNER_RATIO
    if np is not None:
        # Distance from each pixel centre to the nearest edge, clamped into the corner
        # box. Inside the straight runs one axis is zero and the test always passes, so
        # the same expression covers edges and corners without a special case.
        axis = (np.arange(size, dtype=np.float64) + 0.5)
        dx = np.maximum(radius - axis, axis - (size - radius))
        dy = dx.reshape(-1, 1)
        dx = np.maximum(dx, 0.0) / radius
        dy = np.maximum(dy, 0.0) / radius
        field = dx ** SQUIRCLE_EXPONENT + dy ** SQUIRCLE_EXPONENT
        # One-pixel linear ramp across the boundary in place of a hard cut, so the corners
        # are antialiased rather than stair-stepped.
        edge = np.clip((1.0 - field) * size * 0.5 + 0.5, 0.0, 1.0)
        return Image.fromarray((edge * 255.0).round().astype("uint8"), mode="L")

    scale = 4
    big = size * scale
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, big - 1, big - 1), radius=radius * scale, fill=255
    )
    return mask.resize((size, size), Image.LANCZOS)


def rounded(master, size):
    """The master resampled to `size` with the squircle mask applied, full-bleed."""
    art = master.resize((size, size), Image.LANCZOS).convert("RGBA")
    art.putalpha(squircle_mask(size))
    return art


def macos_tile(master, size):
    """`rounded`, inset into a transparent canvas on the macOS icon grid."""
    content = max(1, int(round(size * MACOS_CONTENT_RATIO)))
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    offset = (size - content) // 2
    canvas.paste(rounded(master, content), (offset, offset))
    return canvas


def write_png(image, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    image.save(path, format="PNG", optimize=True)
    print("  {:<40} {}x{}".format(os.path.relpath(path), image.width, image.height))


def write_icns(master, path):
    """Build the ICNS container by hand.

    Pillow can *read* ICNS but only writes the format on macOS, where it shells out to
    `iconutil`. The container itself is trivial — a magic word, a big-endian total length,
    then typed chunks that are each a 4-byte type, a big-endian length INCLUDING the
    8-byte header, and the payload — so writing it directly keeps the script working the
    same way on every machine, including CI.
    """
    body = b""
    for chunk_type, size in ICNS_CHUNKS:
        png = _png_bytes(macos_tile(master, size))
        body += chunk_type + struct.pack(">I", len(png) + 8) + png
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(b"icns" + struct.pack(">I", len(body) + 8) + body)
    print("  {:<40} {} chunks, {} bytes".format(
        os.path.relpath(path), len(ICNS_CHUNKS), len(body) + 8))


def _png_bytes(image):
    import io

    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


def write_ico(master, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    largest = rounded(master, max(ICO_SIZES))
    largest.save(path, format="ICO", sizes=[(s, s) for s in ICO_SIZES])
    print("  {:<40} {}".format(
        os.path.relpath(path), ", ".join("{}px".format(s) for s in ICO_SIZES)))


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    master_path = argv[1]
    master = Image.open(master_path).convert("RGBA")
    if master.width != master.height:
        print("master must be square, got {}x{}".format(master.width, master.height),
              file=sys.stderr)
        return 1
    if master.width < 512:
        print("master is {}px — expected the 1024px iOS source".format(master.width),
              file=sys.stderr)
        return 1

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print("master  {} ({}x{})".format(master_path, master.width, master.height))
    print("writing under {}".format(root))

    icons = os.path.join(root, "src", "main", "resources", "icons")
    packaging = os.path.join(root, "packaging")

    write_png(rounded(master, 512), os.path.join(icons, "pgpony_512.png"))
    write_png(rounded(master, 128), os.path.join(icons, "pgpony_tray.png"))
    write_png(rounded(master, 512), os.path.join(packaging, "pgpony.png"))
    write_ico(master, os.path.join(packaging, "pgpony.ico"))
    write_icns(master, os.path.join(packaging, "pgpony.icns"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
