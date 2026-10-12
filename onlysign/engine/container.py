"""Reading a signature out of a container that embeds one, for formats that are not PE.

A PE file carries its signature in a certificate table that is simply appended, which is why the
rest of this engine can treat a signature as "bytes at the end". A package format does not: an MSI
is a compound file, and its signature lives *inside* as one stream among many, so reading it means
walking the file's own allocation tables rather than looking at its tail.

This matters for more than completeness. Where the engine cannot read the signature a file carries,
it falls back to asking Windows, and Windows answers a different question: it consults the machine's
security catalogs, so a package whose own signature is present but untrusted can still come back
"Valid" because a catalog says Microsoft signed it. Reading the embedded signature removes that
ambiguity -- the answer stops depending on what this machine happens to have been told.

Only the parts of the format that are needed are implemented, and the code says which those are
rather than pretending to be a general reader.
"""

from __future__ import annotations

import struct

# Compound File Binary: the eight bytes every such file starts with, and the values that stand in for
# "no more sectors" in every one of its tables.
CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
SECTOR_END = 0xFFFFFFFE
SECTOR_FREE = 0xFFFFFFFF
SECTOR_FAT = 0xFFFFFFFD
SECTOR_DIFAT = 0xFFFFFFFC
SECTOR_SPECIAL = 0xFFFFFFFA
MAX_SECTORS = 1 << 22          # a bound so a corrupt chain cannot walk forever
MAX_DIFAT_SECTORS = 1 << 16
# The bound whose absence caused an incident, and the reason the others were not enough: every length
# this parser is told comes out of the file it is reading, so none of them can be believed. Bounding
# the number of *steps* does nothing about the number of *bytes* -- a chain of four million sectors
# is four million times a sector, and that is what fills memory. A signature is tens of kilobytes, so
# a stream claiming more than this is refused rather than allocated, and the worst a doctored length
# can cost is this much.
MAX_STREAM_BYTES = 16 << 20
MAX_TABLE_BYTES = 64 << 20

# The stream an MSI keeps its signature in. The leading U+0005 is not decoration: it marks a name
# that is not part of the installer's table schema, and a reader that looks for "DigitalSignature"
# without it finds nothing.
MSI_SIGNATURE_STREAM = "\u0005DigitalSignature"

DIRECTORY_ENTRY_SIZE = 128
NAME_BYTES = 64


class NotAContainer(ValueError):
    """Raised when a file is not a compound file at all, so the caller can fall back."""


def _u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


class CompoundFile:
    """Enough of a compound file to find one stream by name and read it whole."""

    def __init__(self, data: bytes):
        if len(data) < 512 or data[:8] != CFB_MAGIC:
            raise NotAContainer("not a compound file")
        self.data = data
        # Two-byte fields, not four: reading a dword here swallows the neighbouring shift as well and
        # produces a sector size of a few billion, which is how this was found.
        self.sector_size = 1 << struct.unpack_from("<H", data, 30)[0]
        self.mini_sector_size = 1 << struct.unpack_from("<H", data, 32)[0]
        if self.sector_size not in (512, 4096) or not 0 < self.mini_sector_size <= self.sector_size:
            raise NotAContainer(f"implausible sector sizes ({self.sector_size}/{self.mini_sector_size})")
        self.fat_sector_count = _u32(data, 44)
        # How many sectors the directory occupies, as the file itself states it. Version 3 files
        # leave this zero and the size has to come from the chain; version 4 files state it, and
        # believing the statement is what keeps a chain walk from leaving the directory behind.
        self.directory_sector_count = _u32(data, 40)
        self.directory_start = _u32(data, 48)
        self.mini_cutoff = _u32(data, 56)
        self.mini_fat_start = _u32(data, 60)
        self.difat_start = _u32(data, 68)
        self.difat_count = _u32(data, 72)
        self._fat: list[int] | None = None
        self._mini_fat: list[int] | None = None

    # --- sectors -------------------------------------------------------------- #

    def _plausible(self, size: int) -> int:
        """A claimed length, clamped to what a stream in this file could actually be."""
        return max(0, min(int(size), len(self.data), MAX_STREAM_BYTES))

    def sector(self, index: int) -> bytes:
        # Sector 0 starts *after* the header, so the offset is (index + 1) sectors in. Writing this
        # as a constant 512 plus index times the sector size is the same arithmetic whenever sectors
        # are 512 bytes -- which is why it survived every 512-byte file it was tested on -- and is
        # 3584 bytes wrong on a 4096-byte one. That offset landed inside the FAT instead of the
        # directory, so the "FAT" was FAT bytes read at a wrong stride, the directory chain walked
        # a table that described something else, and a 1.2 MB package handed back 64 MB of entries
        # that were never in it. A file's own numbers being off by one sector is not detectable from
        # the numbers; it is detectable from the structure they describe, and the header of a FAT
        # names itself with SECTOR_FAT at index 0.
        start = (index + 1) * self.sector_size
        if index < 0 or start + self.sector_size > len(self.data):
            raise NotAContainer(f"sector {index} is outside the file")
        return self.data[start:start + self.sector_size]

    @property
    def total_sectors(self) -> int:
        """How many whole sectors this file has, which is the one bound a chain cannot exceed."""
        return max(0, len(self.data) // self.sector_size - 1)

    def _difat(self) -> list[int]:
        """The list of sectors holding the FAT: 109 in the header, then however many it chains to."""
        entries = [_u32(self.data, 76 + 4 * index) for index in range(109)]
        next_sector = self.difat_start
        seen = 0
        per_sector = self.sector_size // 4 - 1
        while next_sector not in (SECTOR_END, SECTOR_FREE) and seen < MAX_DIFAT_SECTORS:
            block = self.sector(next_sector)
            for index in range(per_sector):
                entries.append(_u32(block, 4 * index))
            next_sector = _u32(block, 4 * per_sector)
            seen += 1
        return [entry for entry in entries if entry < SECTOR_SPECIAL]

    def fat(self) -> list[int]:
        if self._fat is not None:
            return self._fat
        entries: list[int] = []
        for sector_index in self._difat():
            block = self.sector(sector_index)
            entries.extend(struct.unpack_from(f"<{self.sector_size // 4}I", block, 0))
        self._fat = entries
        return entries

    def mini_fat(self) -> list[int]:
        if self._mini_fat is not None:
            return self._mini_fat
        entries: list[int] = []
        for sector_index in self._chain(self.mini_fat_start, limit=MAX_SECTORS):
            block = self.sector(sector_index)
            entries.extend(struct.unpack_from(f"<{self.sector_size // 4}I", block, 0))
        self._mini_fat = entries
        return entries

    def _chain(self, start: int, limit: int = MAX_SECTORS):
        """Follow a FAT chain, refusing one that revisits a sector.

        A bound on the number of steps says how long a walk may be, not whether it means anything: a
        table that loops walks to the bound and hands back bytes from sectors the structure never
        owned. Revisiting a sector is something a correct chain never does, so it is the condition
        worth testing. A chain that leaves the file is caught by `sector` instead.
        """
        table = self.fat()
        current = start
        steps = 0
        seen: set[int] = set()
        while current < SECTOR_SPECIAL and steps < limit:
            if current in seen:
                raise NotAContainer(f"allocation chain revisits sector {current}")
            seen.add(current)
            yield current
            if current >= len(table):
                return
            current = table[current]
            steps += 1

    def _read_chain(self, start: int, size: int, *, mini: bool) -> bytes:
        size = self._plausible(size)
        if mini:
            table = self.mini_fat()
            block_size = self.mini_sector_size
            root = self._root_stream()
        else:
            table = self.fat()
            block_size = self.sector_size
            root = b""
        out = bytearray()
        current = start
        steps = 0
        seen: set[int] = set()
        while current < SECTOR_SPECIAL and steps < MAX_SECTORS and len(out) < size:
            if current in seen:
                raise NotAContainer(f"allocation chain revisits sector {current}")
            seen.add(current)
            if mini:
                begin = current * block_size
                out += root[begin:begin + block_size]
            else:
                out += self.sector(current)
            if current >= len(table):
                break
            current = table[current]
            steps += 1
        return bytes(out[:size])

    # --- the directory -------------------------------------------------------- #

    def _root_stream(self) -> bytes:
        if getattr(self, "_root_cache", None) is None:
            entries = self.directory()
            root = entries[0] if entries else None
            if root is None:
                self._root_cache = b""
            else:
                _name, start, size = root
                self._root_cache = self._read_chain(start, size, mini=False)
        return self._root_cache

    def directory(self) -> list[tuple[str, int, int]]:
        """(size, first sector) for every stream entry, in directory order."""
        if getattr(self, "_directory_cache", None) is not None:
            return self._directory_cache
        # The header states how many sectors the directory occupies, and that statement is the only
        # thing here that says where the directory *ends*. Walking the chain until a byte cap instead
        # is what let a 1.2 MB package produce 64 MB of entries: the walk kept going through sectors
        # the directory never owned and parsed all of them as entries. The number still comes out of
        # the file, so it is clamped to the file rather than trusted.
        declared = min(self.directory_sector_count, self.total_sectors)
        raw = bytearray()
        for step, sector_index in enumerate(self._chain(self.directory_start)):
            if declared and step >= declared:
                break
            if len(raw) >= MAX_TABLE_BYTES:
                break
            raw += self.sector(sector_index)
        entries: list[tuple[int, int]] = []
        for offset in range(0, len(raw) - DIRECTORY_ENTRY_SIZE + 1, DIRECTORY_ENTRY_SIZE):
            name_length = struct.unpack_from("<H", raw, offset + 64)[0]
            object_type = raw[offset + 66]
            if object_type not in (1, 2, 5) or not 2 <= name_length <= NAME_BYTES:
                name = ""
            else:
                name = raw[offset:offset + name_length - 2].decode("utf-16-le", "replace")
            # A private attribute so the caller can look names up without a second parse.
            entries.append((name, _u32(raw, offset + 116), struct.unpack_from("<Q", raw, offset + 120)[0]))
        self._directory_cache = entries
        return entries

    def stream(self, wanted: str) -> bytes | None:
        """One stream by name, or None when this file does not have it."""
        for name, start, size in self.directory():
            if name != wanted or size == 0:
                continue
            size = self._plausible(size)
            if size == 0:
                continue
            mini = size < self.mini_cutoff
            return self._read_chain(start, size, mini=mini)
        return None
