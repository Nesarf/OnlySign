"""Turn a mark into the character art a notice carries.

    python tools/make-notice-art.py --source mark.png --cols 52 --rows 32

The art is text, so it can be looked at directly, pasted anywhere, and edited by hand afterwards --
which is why a notice is a text file rather than something drawn at runtime. What this script buys
is the ability to regenerate it at another size if a console turns out to be narrower than expected.

Two decisions here are about sharpness rather than fidelity, because a console is not a printer:

* **Area averaging, not a smooth filter.** Lanczos resampling rings: it overshoots around edges, and
  a threshold applied afterwards turns that overshoot into ragged, noisy outlines. Averaging each
  cell's coverage and then asking whether the majority of it is ink gives edges that follow the
  original instead of wobbling along it. Bilinear and bicubic have the same problem in smaller
  measure, so the default is `box`.
* **A density ramp is a third option**, and the one that ages best in a terminal: the background
  falls away and the mark is carried by the thickest characters, so it reads at any size and in any
  code page (the ramp here is pure ASCII). `--cols-only` picks the height from the mark's own aspect
  and the cell shape, because a notice has to fit a width and does not care how far it scrolls.

* **Half blocks by default, solid blocks on request.** U+2580 and U+2584 double the vertical detail
  a terminal can show, and they are present in both CP437 and CP936, so no code page is required.
  Their cost is that many fonts leave a hairline between the two halves of a cell, which reads as a
  faint banding across large filled areas. `--style solid` gives that up for solid U+2588 cells,
  which tile without a seam; `--style density` falls back to ASCII for a console with neither.
"""

from __future__ import annotations

import argparse

from PIL import Image
import numpy as np

FILTERS = {"box": Image.BOX, "bilinear": Image.BILINEAR, "bicubic": Image.BICUBIC,
           "lanczos": Image.LANCZOS}

# Dark to light. `ramp` is the style a console shows best when the mark is ink on a dark field: the
# background falls away to spaces and the mark's mass is carried by @, so the drawing appears out of
# the terminal rather than sitting on it as a filled plate.
DENSITY_RAMP = " .:-=+*#%@"

# What one character cell is, height over width. A terminal cell is taller than it is wide -- about
# 2:1 with the usual fonts -- so a mark of a given aspect needs fewer rows than columns than a square
# grid would suggest. Getting this wrong is what makes a drawing look vertically squashed.
DEFAULT_CELL_ASPECT = 2.0

# Named recipes, so a size that looked right once can be asked for by name instead of remembered.
# `packed` is the shape of an art that was drawn by another tool and handed over ready-made: a
# taller cell than a terminal really has, which reads as a slightly condensed mark.
PRESETS = {
    "terminal": {"cell_aspect": 2.0},
    "packed": {"cell_aspect": 2.46},
}


def _coverage(source: str, cols: int, rows: int, resample) -> np.ndarray:
    """The mark's ink, averaged into a grid twice as tall as the requested character rows."""
    alpha = np.asarray(Image.open(source).convert("RGBA"))[..., 3].astype(float)
    rows_with_ink, columns_with_ink = np.nonzero(alpha > 0)
    if not len(rows_with_ink):
        raise SystemExit("that image has no opaque pixels, so there is nothing to draw")
    ink = alpha[rows_with_ink.min():rows_with_ink.max() + 1,
                columns_with_ink.min():columns_with_ink.max() + 1]
    return np.asarray(Image.fromarray(ink).resize((cols, rows * 2), resample)).astype(float) / 255.0


def art(source: str, cols: int, rows: int, *, style: str = "half", resample: str = "box",
        threshold: float = 0.5, ramp: str = "") -> list[str]:
    cover = _coverage(source, cols, rows, FILTERS[resample])
    top = cover[0::2, :] >= threshold
    bottom = cover[1::2, :] >= threshold
    average = (cover[0::2, :] + cover[1::2, :]) / 2.0

    lines: list[str] = []
    ramp = ramp or DENSITY_RAMP
    for row in range(rows):
        cells = []
        for col in range(cols):
            if style == "half":
                cells.append("\u2588" if (top[row, col] and bottom[row, col])
                             else "\u2580" if top[row, col]
                             else "\u2584" if bottom[row, col]
                             else " ")
            elif style == "solid":
                cells.append("\u2588" if average[row, col] >= threshold else " ")
            else:
                step = min(int(average[row, col] * len(ramp)), len(ramp) - 1)
                cells.append(ramp[step])
        lines.append("".join(cells).rstrip())
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", required=True, help="the mark, as PNG with transparency")
    parser.add_argument("--cols", type=int, default=52)
    parser.add_argument("--rows", type=int, default=32)
    parser.add_argument("--style", default="half", choices=("half", "solid", "density"))
    parser.add_argument("--ramp", default=DENSITY_RAMP,
                        help="the characters for --style density, dark first")
    parser.add_argument("--cols-only", type=int, default=0,
                        help="give a width and let the height follow the mark's own aspect, "
                             "which is what a notice wants: width is what must fit")
    parser.add_argument("--preset", default="", choices=("",) + tuple(PRESETS),
                        help="a named cell shape: terminal (2.0) or packed (2.46)")
    parser.add_argument("--cell-aspect", type=float, default=DEFAULT_CELL_ASPECT,
                        help="height over width of one character cell; 2.0 for the usual terminal")
    parser.add_argument("--filter", default="box", choices=tuple(FILTERS),
                        help="how cells are sampled; box averages and keeps edges crisper")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="coverage above which a cell counts as ink")
    args = parser.parse_args(argv)

    if args.preset:
        args.cell_aspect = PRESETS[args.preset]["cell_aspect"]

    cols, rows = args.cols, args.rows
    if args.cols_only:
        # The height follows from the mark and the cell, rather than being asked for: an art that has
        # to fit a terminal has one dimension that matters and one that does not.
        alpha = np.asarray(Image.open(args.source).convert("RGBA"))[..., 3].astype(float)
        ys, xs = np.nonzero(alpha > 0)
        aspect = (ys.max() - ys.min() + 1) / (xs.max() - xs.min() + 1)
        cols = args.cols_only
        rows = max(1, round(cols * aspect / args.cell_aspect))

    for line in art(args.source, cols, rows, style=args.style,
                    resample=args.filter, threshold=args.threshold, ramp=args.ramp):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
