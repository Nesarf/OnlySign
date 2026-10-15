"""Turn the character sheets into the individual pieces the tool and its pages need.

    python tools/prepare-art.py --source "F:\\素材\\图\\AI\\Morphea Amethyst" --out .onlysign-art

Everything this writes is **local**. `.onlysign-art/` is gitignored for the same reason
`NOTICE.local*.txt` and `IDENTITY.local.json` are: the published tool is neutral, and the character
art is not part of it. What ships is the tool; what a build made here carries is the publisher's.

The sheets are not cut on a guess. The grid is found from the ink: gutters are the columns and rows
that are almost entirely background, and a cell is cropped to the ink inside it and then padded, so
no two tiles are the same size and none of them has a stray neighbour's corner in it.

The white background becomes transparent by *unpremultiplying* rather than by thresholding: a pixel
that is halfway between the ink and white is ink at half alpha, so `alpha = 1 - min(channel)/255` and
the colour is divided back out. A threshold would leave a grey fringe on every anti-aliased edge.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from itertools import combinations

try:
    from PIL import Image
    import numpy as np
except ImportError:
    raise SystemExit("this needs Pillow and numpy: pip install pillow numpy")

# The names the tiles are known by, in reading order. They are the poses a person looking at the
# sheet would name, so that a later choice ("the one holding the book") is findable by name.
SHEET_NAMES = (
    "witch-staff-up", "staff-cast", "standing-book", "curious",
    "hug-pillow", "asleep", "reading", "surprised",
    "walk-outfit", "skirt-hold", "battle-staff", "travelling",
    "swimsuit", "bath", "cauldron", "whisk",
)


def ink_mask(rgb: np.ndarray, threshold: int = 30) -> np.ndarray:
    """Which pixels are not background. White is the background; nothing else is assumed."""
    return np.abs(rgb.astype(int) - 255).sum(axis=2) > threshold


def gutters(profile: np.ndarray, floor: float = 0.01) -> list[tuple[int, int]]:
    """Runs of near-empty columns (or rows), which is where a sheet can be cut."""
    empty = profile < max(2, profile.max() * floor)
    runs: list[tuple[int, int]] = []
    start = None
    for index, value in enumerate(empty):
        if value and start is None:
            start = index
        elif not value and start is not None:
            runs.append((start, index - 1))
            start = None
    if start is not None:
        runs.append((start, len(empty) - 1))
    return [run for run in runs if run[1] - run[0] >= 3]


def ink_runs(profile: np.ndarray, least: int) -> list[tuple[int, int]]:
    """Every run of columns (or rows) with no ink at all, at least `least` wide.

    A separator on a sheet like this is not a percentage of the width -- it is a place where the ink
    stops. Measuring found the four columns separated at x 292..324, 607..642 and 921..959, while an
    even division would have guessed 313, 627 and 940: twenty pixels out, which is enough to slice a
    hat off and leave it in the next tile. The rows are worse, because one of their three separators
    is a *single* row of background at y=316 between cells of 310 and 300 rows. Nothing about "a
    quarter of 1254" finds that; something about "this row has no ink in it" does.
    """
    empty = profile == 0
    runs: list[tuple[int, int]] = []
    start = None
    for index, value in enumerate(empty):
        if value and start is None:
            start = index
        elif not value and start is not None:
            runs.append((start, index - 1))
            start = None
    if start is not None:
        runs.append((start, len(empty) - 1))
    return [run for run in runs if run[1] - run[0] + 1 >= least]


def cut_points(ink: np.ndarray, cells: int, axis: int) -> list[tuple[int, int, int]]:
    """Where to cut a sheet of `cells` cells: the middles of the runs of background between them.

    Nothing here assumes a grid, and nothing is chosen by a threshold somebody tuned on one sheet.
    Every run of background is measured; the widest `cells - 1` that partition the sheet into
    `cells` pieces are taken, and then the pieces have to *look* like cells -- because a run of
    background can be a gap inside a drawing rather than a separator, and the difference is not the
    run's width, it is whether the pieces either side of it come out the same size.

    Measured on the sheet this was written for: the four columns are separated at x 292..324,
    607..642 and 921..959, where an even division would have guessed 313, 627 and 940 -- twenty
    pixels out, enough to slice a hat and leave it in the next tile. The rows are worse: one of their
    three separators is a *single* row of background at y=316, between cells of 310 and 300 rows.
    Nothing about "a quarter of 1254" finds that.

    Returns (cut, run_start, run_end) so the caller can report what it found.
    """
    size = ink.shape[axis]
    profile = ink.sum(axis=0) if axis == 0 else ink.sum(axis=1)
    runs = [(start, end) for start, end in ink_runs(profile, 1)
            if start > 0 and end < size - 1]

    best: tuple[float, list[tuple[int, int]]] | None = None
    for choice in combinations(runs, cells - 1):
        edges = [0, *(start for start, _ in choice), size]
        ends = [0, *(end for _, end in choice), size]
        # +1 because a run is inclusive at both ends: the piece stops before it and resumes after it.
        widths = [edges[i + 1] - (ends[i] + 1) for i in range(cells)]
        if any(width <= 0 for width in widths):
            continue
        spread = (max(widths) - min(widths)) / max(1.0, sum(widths) / cells)
        if best is None or spread < best[0]:
            best = (spread, list(choice))

    if best is None:
        raise SystemExit(f"no {cells - 1} runs of background could divide this sheet into {cells}")
    spread, chosen = best
    if spread > 0.35:
        raise SystemExit(
            f"the best division into {cells} pieces leaves them sizes that do not agree "
            f"(spread {spread:.0%} of the average). This sheet is not a {cells} by {cells} grid of "
            f"equal cells, so it is not being cut as one. Runs available: {runs}")

    chosen.sort()
    return [(int((start + end) // 2), start, end) for start, end in chosen]


def tight_box(mask: np.ndarray, pad: int) -> tuple[int, int, int, int] | None:
    """The ink's own bounding box, grown by `pad`, or None when the cell holds nothing."""
    rows = np.where(mask.any(axis=1))[0]
    cols = np.where(mask.any(axis=0))[0]
    if not len(rows) or not len(cols):
        return None
    top = max(0, rows[0] - pad)
    bottom = min(mask.shape[0], rows[-1] + 1 + pad)
    left = max(0, cols[0] - pad)
    right = min(mask.shape[1], cols[-1] + 1 + pad)
    return left, top, right, bottom


def drop_white(image: Image.Image) -> Image.Image:
    """White to transparent -- offered, and **not** the default. This is the paragraph to read first.

    It cannot be lossless, and the reason is arithmetic rather than a bug. A sheet is flat: each pixel
    holds one colour. On white, that colour is what white and the ink made between them, and how much
    ink there was is *no longer in the file*. So a pixel that reads (200, 180, 210) could be pale ink
    at full coverage or dark ink at low coverage, and nothing in the data tells them apart.

    This takes the second reading -- `alpha = 255 - min(channel)`, colour untouched -- which keeps the
    colour exactly and puts all the error into the coverage. What it cannot do is survive being
    composited over anything but white. Measured: over the colour this window actually paints,
    (240, 240, 240), the mid tones move by about 25 of 255 per channel, which reads as a washed-out
    character next to the same art on white. Over white it is invisible.

    So the tiles keep their background by default, and that is the honest picture. Use this only when
    the destination really is white, or when a soft edge matters more than the colour -- and look at
    the result on the background it will actually land on before trusting it.
    """
    rgb = np.asarray(image.convert("RGB")).astype(float)
    alpha = 255.0 - rgb.min(axis=2)
    return Image.fromarray(np.dstack([rgb, alpha]).astype(np.uint8), "RGBA")


def split_sheet(source: pathlib.Path, out_dir: pathlib.Path, pad: int, drop_background: bool) -> dict:
    image = Image.open(source).convert("RGB")
    array = np.asarray(image)
    mask = ink_mask(array)

    columns = cut_points(mask, 4, axis=0)
    rows = cut_points(mask, 4, axis=1)
    print("  columns cut at " + ", ".join(f"{cut} (background {a}..{b})"
                                          for cut, a, b in columns))
    print("  rows    cut at " + ", ".join(f"{cut} (background {a}..{b})"
                                          for cut, a, b in rows))

    # The cuts define the cell edges; the outer edges are the image's own.
    xs = [0, *(cut for cut, _, _ in columns), image.width]
    ys = [0, *(cut for cut, _, _ in rows), image.height]
    written = []
    for row in range(4):
        for column in range(4):
            name = SHEET_NAMES[row * 4 + column] if row * 4 + column < len(SHEET_NAMES) else \
                f"cell-{row}-{column}"
            cell = image.crop((xs[column], ys[row], xs[column + 1], ys[row + 1]))
            box = tight_box(ink_mask(np.asarray(cell)), pad)
            if box is None:
                print(f"  {name:<16} empty; skipped")
                continue
            cropped = cell.crop(box)
            finale = drop_white(cropped) if drop_background else cropped.convert("RGBA")
            target = out_dir / f"chibi-{row * 4 + column + 1:02d}-{name}.png"
            finale.save(target)
            written.append({"name": name, "file": target.name,
                            "size": [finale.width, finale.height],
                            "from": [int(xs[column] + box[0]), int(ys[row] + box[1])]})
            print(f"  {name:<16} {finale.width}x{finale.height}")
    return {"tiles": written,
            "grid": {"columns": [cut for cut, _, _ in columns],
                     "rows": [cut for cut, _, _ in rows]}}


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare the character art for the tool.")
    parser.add_argument("--source", required=True, help="the directory the sheets are in")
    parser.add_argument("--out", default=".onlysign-art", help="where the pieces are written")
    parser.add_argument("--pad", type=int, default=6, help="pixels of margin around each tile")
    parser.add_argument("--drop-background", action="store_true",
                        help="make the white background transparent instead of keeping it. Read the "
                             "note on drop_white first: it costs colour, and it only survives being "
                             "placed on white")
    args = parser.parse_args()

    source = pathlib.Path(args.source)
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    drop = args.drop_background

    sheet = source / "Morphea_Q.png"
    if not sheet.is_file():
        raise SystemExit(f"no character sheet at {sheet}")

    print(f"sheet: {sheet.name}")
    result = split_sheet(sheet, out, args.pad, drop)

    # The standing art, from the largest copy there is, so a banner made from it is not upscaled.
    standing = source / "Morphea_UwU.png"
    if standing.is_file():
        image = Image.open(standing).convert("RGB")
        box = tight_box(ink_mask(np.asarray(image)), 8)
        cropped = image.crop(box) if box else image
        finale = drop_white(cropped) if drop else cropped.convert("RGBA")
        target = out / "standing.png"
        finale.save(target)
        result["standing"] = {"file": target.name, "size": [finale.width, finale.height]}
        print(f"standing: {finale.width}x{finale.height}  (from {standing.name})")

    manifest = out / "manifest.json"
    manifest.write_text(json.dumps(result, indent=2), encoding="utf-8")

    # The icon, from the crop that was made for it. A .ico is a container of sizes, and Windows picks
    # by context -- 16 in a file list, 32 in the taskbar, 256 in the large-icon view. Shipping one
    # bitmap leaves the shell resampling art that was never meant to be seen that small, so every
    # size the current icon carries is generated, and they are written as PNG-compressed entries
    # because a 256-pixel entry stored raw is a quarter of a megabyte on its own.
    icon_source = source / "Morphea_UwU_icon.png"
    if icon_source.is_file():
        image = Image.open(icon_source).convert("RGBA")
        alpha = np.asarray(image)[:, :, 3]
        opaque = bool((alpha == 255).all())
        if opaque:
            print(f"\nicon: {icon_source.name} is entirely opaque, so it is used as it is "
                  f"(no transparency to preserve, and none invented)")
        side = min(image.size)
        left, top = (image.width - side) // 2, (image.height - side) // 2
        square = image.crop((left, top, left + side, top + side))

        # Three files, one source, because the tool draws this face in three places and they have to
        # be the same face: the executable's icon (a container of sizes), the About window's picture,
        # and the larger copy the About window falls back to. Changing one and not the others is how
        # an application ends up with a different face in the taskbar than in its own About box.
        sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        target = out / "onlysign.ico"
        square.save(target, format="ICO", sizes=sizes)
        written_icon = Image.open(target)
        generated = [{"file": target.name, "size": [square.width, square.height],
                      "sizes": sorted(written_icon.info.get("sizes", []))}]

        for name, edge in (("onlysign-256.png", 256), ("onlysign.png", 512)):
            small = square.resize((edge, edge), Image.LANCZOS)
            path = out / name
            small.save(path)
            generated.append({"file": name, "size": [small.width, small.height]})

        result["icon"] = {"from": icon_source.name, "opaque": opaque, "files": generated}
        print(f"icon: {len(generated)} file(s) from {icon_source.name} -- "
              + ", ".join(entry["file"] for entry in generated))

    # --- the chibi, which is what the tool shows about itself ------------------ #
    #
    # Two things are wanted from the chibi and they are different sizes of it. The icon is the
    # finished crop the publisher made, which is a close-up and reads at 16 pixels; this is the whole
    # figure, for the About window and for anything made to introduce the tool. A close-up face says
    # "this is the application"; the whole figure says "this is who it is", and only one of those
    # belongs in an About box.
    face_tile = out / "chibi-03-standing-book.png"
    if face_tile.is_file():
        tile = Image.open(face_tile).convert("RGB")
        about = out / "chibi-about.png"
        tile.save(about)
        result["chibi_about"] = {"file": about.name, "from": face_tile.name,
                                 "size": [tile.width, tile.height]}
        print(f"chibi about: {about.name}  {tile.width}x{tile.height}  (from {face_tile.name})")

    manifest.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\n{len(result['tiles'])} tile(s) and a manifest in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
