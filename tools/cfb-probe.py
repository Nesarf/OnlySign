"""Diagnose a compound file the way the reader reads it, so a disagreement is visible.

`onlysign/engine/container.py` finds an MSI's signature by walking the file's own allocation tables.
Every number it walks by comes out of the file it is reading, so a file whose tables disagree with
its own header can send that walk past the end of the structure it is supposed to be reading, and the
bytes beyond it then parse as directory entries that were never there.

This reports, per file: what the header declares, what the chain actually yields, and what the reader
returned -- so "the reader is fine" is a measurement rather than an assumption.

Read-only. Nothing is written, no file is modified, and only the first `--max-bytes` of each file is
read, so pointing it at a directory of large packages does not pull them all into memory.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from onlysign.engine.container import (  # noqa: E402
    CFB_MAGIC,
    DIRECTORY_ENTRY_SIZE,
    SECTOR_SPECIAL,
    CompoundFile,
)


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def probe(path: Path, max_bytes: int) -> dict:
    size = path.stat().st_size
    result = {"path": path, "size": size, "ok": False}
    if size > max_bytes:
        # A truncated read would make every table look corrupt, which is a statement about the probe
        # rather than about the file, so refuse rather than report nonsense.
        result["note"] = f"larger than the read limit ({size} > {max_bytes}), skipped"
        return result
    with path.open("rb") as handle:
        data = handle.read(max_bytes)
    if len(data) < 512 or data[:8] != CFB_MAGIC:
        result["note"] = "not a compound file"
        return result
    sector_size = 1 << struct.unpack_from("<H", data, 30)[0]
    version = struct.unpack_from("<H", data, 26)[0]
    declared_dir_sectors = u32(data, 40)
    declared_fat_sectors = u32(data, 44)
    declared_dir_start = u32(data, 48)
    # Sector 0 begins after the header, so the count is one less than the whole sectors in the file.
    total_sectors = max(0, len(data) // sector_size - 1)
    per_sector = sector_size // DIRECTORY_ENTRY_SIZE

    try:
        cf = CompoundFile(data)
        table = cf.fat()
    except Exception as error:  # a probe reports, it does not crash the sweep
        result["note"] = f"reader refused it: {error!r}"
        return result

    # Walk the chain by hand, bounded by the file rather than by the reader's cap, and note the first
    # sector that repeats: a table that revisits a sector describes a cycle, not a stream.
    walked: list[int] = []
    seen: set[int] = set()
    current = declared_dir_start
    while current < SECTOR_SPECIAL and len(walked) <= total_sectors:
        if current in seen:
            result["cycle_at"] = len(walked)
            break
        seen.add(current)
        walked.append(current)
        if current >= len(table):
            break
        current = table[current]

    entries = cf.directory()
    named = [entry for entry in entries if entry[0]]
    result.update(
        ok=True,
        version=version,
        sector_size=sector_size,
        total_sectors=total_sectors,
        declared_dir_sectors=declared_dir_sectors,
        implied_entries=declared_dir_sectors * per_sector,
        declared_fat_sectors=declared_fat_sectors,
        fat_entries=len(table),
        dir_start=declared_dir_start,
        chain_walked=len(walked),
        chain_overran=len(walked) > total_sectors,
        entries_returned=len(entries),
        entries_named=len(named),
        names=[entry[0] for entry in named],
    )
    return result


def show(result: dict) -> None:
    name = result["path"].name
    if not result["ok"]:
        print(f"{name}: {result.get('note', 'unreadable')}")
        return
    flags = []
    if result.get("cycle_at") is not None:
        flags.append(f"CYCLE at step {result['cycle_at']}")
    if result["chain_overran"]:
        flags.append("OVERRAN THE FILE")
    if result["entries_returned"] > result["implied_entries"]:
        flags.append("MORE ENTRIES THAN DECLARED")
    print(f"{name}  ({result['size']} bytes, read {result['size']})")
    print(
        f"  version {result['version']}  sector {result['sector_size']}  "
        f"total sectors {result['total_sectors']}"
    )
    print(
        f"  header declares dir {result['declared_dir_sectors']} sectors "
        f"({result['implied_entries']} entries), fat {result['declared_fat_sectors']} sectors "
        f"({result['fat_entries']} entries)"
    )
    if not result["implied_entries"]:
        print("  version 3: the header is required to state no directory size, so the chain is the"
              " only source and the file is the only bound")
    print(
        f"  dir chain start {result['dir_start']}, walked {result['chain_walked']} sectors"
    )
    print(
        f"  reader returned {result['entries_returned']} entries, "
        f"{result['entries_named']} named"
    )
    for entry_name in result["names"][:12]:
        print(f"    {entry_name!r}")
    if flags:
        print(f"  {'  '.join(flags)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Show how a compound file's tables and the reader agree.")
    parser.add_argument("targets", nargs="+", help="compound files, or directories to sweep")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=32 << 20,
        help="read at most this much of each file (default 32 MiB)",
    )
    parser.add_argument("--limit", type=int, default=0, help="stop after this many files (0 = all)")
    parser.add_argument("--quiet", action="store_true", help="only files where something disagrees")
    args = parser.parse_args(argv)

    files: list[Path] = []
    for target in args.targets:
        path = Path(target)
        if path.is_dir():
            files.extend(sorted(entry for entry in path.iterdir() if entry.is_file()))
        else:
            files.append(path)
    if args.limit:
        files = files[: args.limit]

    disagreeing = 0
    checked = 0
    skipped = 0
    for path in files:
        result = probe(path, args.max_bytes)
        if not result["ok"]:
            skipped += 1
            if not args.quiet:
                show(result)
            continue
        checked += 1
        # Version 3 files are required to leave the directory sector count as zero, so there is
        # nothing to compare against there and an empty header is not a disagreement.
        bad = (
            result["chain_overran"]
            or result.get("cycle_at") is not None
            or (
                result["implied_entries"]
                and result["entries_returned"] > result["implied_entries"]
            )
        )
        if bad:
            disagreeing += 1
        if bad or not args.quiet:
            show(result)
    print(f"\n{checked} compound files read, {disagreeing} where the tables disagree with the header")
    if skipped:
        print(f"{skipped} not read (not a compound file, refused by the reader, or over the read limit)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
