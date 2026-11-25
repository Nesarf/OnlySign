#!/usr/bin/env python3
"""Build the Windows application icon from the canonical F.D.C.U.S. mark.

    python build-icon.py            (run from this directory; needs Pillow)

Three decisions are in here, and they are decisions rather than settings:

* **A dark tile, not a bare glyph.** The mark is white ink on transparency, so on its own it
  disappears against a light taskbar or a light Explorer background. The icon is the mark on a
  near-black rounded square instead, which is legible either way.

* **Different art below 48 px.** The wordmark is blackletter; at 16 and 24 px it is not small
  text, it is noise. Those sizes therefore carry the emblem alone -- the umbrella, the sword and
  the bow, the three objects the mark is made of -- scaled larger, which is what a person actually
  recognises at that size.

* **A hand-assembled .ico.** Pillow resizes one image into every size of an ICO, and each size
  here is composed differently, so the container is written directly: a directory of PNG frames.
  That has been the format since Vista and every Windows since reads it.

The .ico is derived from fdcus-mark.png, whose hash is recorded in the README. Rebuilding it
reproduces the same bytes only if the same Pillow renders it, so the hash is a record, not a
promise -- what it does guarantee is that a swapped icon is visible.
"""

import hashlib
import os
import struct

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "fdcus-mark.png")
OUT = os.path.join(HERE, "fdcus.ico")

TILE = (20, 20, 20, 255)   # near-black; not pure black, which reads as a hole on dark themes
RADIUS = 0.22              # of the tile
FULL_MARK = 0.78           # of the tile, for the sizes that can carry the wordmark
EMBLEM_ONLY = 0.90          # larger, because there is no text to make room for
WORDMARK_BOTTOM = 440      # the wordmark occupies the top of the canvas; below this is the emblem
SIZES = (16, 24, 32, 48, 64, 128, 256)
SS = 4                     # supersample factor


def alpha_mask():
    im = Image.open(SRC).convert("RGBA")
    return im.getchannel("A")


def trimmed_square(mask, top=0, bottom=None):
    """Crop to the ink, then centre it on a square canvas with even padding."""
    bottom = mask.height if bottom is None else bottom
    sub = mask.crop((0, top, mask.width, bottom))
    box = sub.getbbox()
    if box is None:
        raise SystemExit("no ink found in the requested band")
    sub = sub.crop(box)
    side = max(sub.width, sub.height)
    pad = int(side * 0.06)
    canvas = side + pad * 2
    out = Image.new("L", (canvas, canvas), 0)
    out.paste(sub, ((canvas - sub.width) // 2, (canvas - sub.height) // 2))
    return out


def white_on(mask, rgb):
    layer = Image.new("RGBA", mask.size, rgb + (0,))
    layer.putalpha(mask)
    return layer


def tile(size, mask, frac):
    big = size * SS
    canvas = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle([0, 0, big - 1, big - 1], radius=int(big * RADIUS), fill=TILE)
    inner = max(1, int(big * frac))
    glyph = white_on(mask.resize((inner, inner), Image.LANCZOS), (255, 255, 255))
    off = (big - inner) // 2
    canvas.alpha_composite(glyph, (off, off))
    return canvas.resize((size, size), Image.LANCZOS)


def write_ico(frames, path):
    """ICONDIR + one ICONDIRENTRY per frame + the PNG payloads."""
    blobs = []
    for f in frames:
        import io
        buf = io.BytesIO()
        f.save(buf, format="PNG", optimize=True)
        blobs.append(buf.getvalue())

    header = struct.pack("<HHH", 0, 1, len(frames))
    offset = len(header) + 16 * len(frames)
    entries = b""
    for f, blob in zip(frames, blobs):
        w = 0 if f.width >= 256 else f.width
        h = 0 if f.height >= 256 else f.height
        entries += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)

    with open(path, "wb") as fh:
        fh.write(header + entries + b"".join(blobs))


def main():
    mask = alpha_mask()
    full = trimmed_square(mask)
    emblem = trimmed_square(mask, top=WORDMARK_BOTTOM)

    frames = []
    for size in SIZES:
        if size < 48:
            frames.append(tile(size, emblem, EMBLEM_ONLY))
        else:
            frames.append(tile(size, full, FULL_MARK))
    write_ico(frames, OUT)

    # A 256 px preview on a light background: the check that the tile actually solves the problem
    # the bare glyph had.
    light = Image.new("RGBA", (296, 296), (245, 245, 245, 255))
    light.alpha_composite(frames[-1], (20, 20))
    light.convert("RGB").save(os.path.join(HERE, "fdcus-icon-preview.png"))

    data = open(OUT, "rb").read()
    print(f"wrote {OUT}")
    print(f"  sizes   : {', '.join(str(s) for s in SIZES)}")
    print(f"  bytes   : {len(data)}")
    print(f"  sha256  : {hashlib.sha256(data).hexdigest().upper()}")
    print(f"  art     : emblem only below 48 px, full mark from 48 px up")

    check = Image.open(OUT)
    print(f"  reopened: {check.format} {check.size}, frames {getattr(check, 'n_frames', 1)}")


if __name__ == "__main__":
    main()
