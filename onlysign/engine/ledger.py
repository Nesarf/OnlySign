"""The record of what was signed.

The on-disk format is not this project's invention: an existing signing toolchain on this machine
already writes it, and two implementations that write the same file have to write the same bytes or
neither can read the other. So it is fixed here on purpose:

* one line of compact JSON per signing, UTF-8, **no byte order mark**, LF endings;
* every record carries ``sha256_signed`` (the file as signed) *and* ``sha256_unsigned`` (as it was
  before signing), because Authenticode appends a certificate table and only one of those answers
  "which bytes did we sign";
* every record carries ``prev``, the sha256 of the previous line's text -- which turns an edit to
  the file into a visible break in a chain instead of a silent one.

The append is the part worth reading twice. Reading the tip and writing the line are **one**
operation, held under a handle that excludes other writers. When they are two operations, two
signings that overlap name the same parent, and the chain then reports a fork whose only innocent
explanation is a race -- so it reads as "someone edited the ledger" on a file nobody touched. That
failure was reproduced once. This is the fix, and the self-test keeps it fixed.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import os
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Any, Iterator

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001          # readers stay welcome; a second writer is refused
_OPEN_ALWAYS = 4
_FILE_ATTRIBUTE_NORMAL = 0x80
_ERROR_SHARING_VIOLATION = 32
_INVALID_HANDLE = ctypes.c_void_p(-1).value

LOCK_TIMEOUT = 10.0
LOCK_INTERVAL = 0.25

SIGN_EVENT = "sign"
PUBLISHED_EVENT = "published"
RELOCATED_EVENT = "relocated"


def hash_file(path: str | os.PathLike[str], *, chunk: int = 1 << 20) -> str:
    """SHA-256 of a file, uppercase hex -- the shape the existing ledger already contains."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest().upper()


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


@dataclass
class Ledger:
    records: list[dict] = field(default_factory=list)
    raw: list[str] = field(default_factory=list)
    broken: int = 0

    def __len__(self) -> int:
        return len(self.records)

    @property
    def tip(self) -> str:
        return hash_text(self.raw[-1]) if self.raw else ""


def read(path: str | os.PathLike[str]) -> Ledger:
    """Read the ledger, counting the lines that did not parse rather than hiding them.

    The file is read as UTF-8 without being offered a choice. Reading it with the machine's ANSI
    code page turns a Chinese note into mojibake and, because the tail byte of the last character
    pairs with the closing quote, makes that line unparseable -- one character, one whole record.
    """
    ledger = Ledger()
    try:
        with open(path, "r", encoding="utf-8", newline="") as fh:
            text = fh.read()
    except FileNotFoundError:
        return ledger
    for line in text.split("\n"):
        if not line.strip():
            continue
        # A CR belongs to the line ending, not to the line. The existing toolchain hashes the line
        # without it, and this ledger must agree with that one byte for byte.
        if line.endswith("\r"):
            line = line[:-1]
        try:
            record = json.loads(line)
        except ValueError:
            ledger.broken += 1
            continue
        ledger.records.append(record)
        ledger.raw.append(line)
    return ledger


def chain(ledger: Ledger) -> dict[str, Any]:
    """Walk the chain and report where it does not line up.

    A record written before the chain existed has no ``prev`` at all and is counted as unchained. A
    record whose ``prev`` is empty is the start of a chain -- the ledger was empty when it was
    written -- which is a beginning rather than a hole.
    """
    breaks: list[int] = []
    chained = 0
    unchained = 0
    for index, record in enumerate(ledger.records):
        if "prev" not in record:
            unchained += 1
            continue
        if not record["prev"]:
            chained += 1
            continue
        expected = hash_text(ledger.raw[index - 1]) if index > 0 else ""
        if record["prev"] != expected:
            breaks.append(index + 1)
        chained += 1
    return {"chained": chained, "unchained": unchained, "broken_at": breaks}


@contextlib.contextmanager
def exclusive(path: str | os.PathLike[str],
              timeout: float = LOCK_TIMEOUT,
              interval: float = LOCK_INTERVAL) -> Iterator[Any]:
    """Open a file for reading and writing while refusing other writers.

    ``CreateFileW`` with ``FILE_SHARE_READ`` is what Python's own ``open`` cannot express: the
    default sharing mode on Windows lets a second writer in, and a lock that lets the other writer
    in is not a lock. Readers are still allowed through, so a status view never blocks a signing.
    """
    deadline = time.monotonic() + timeout
    handle = None
    while True:
        handle = _kernel32.CreateFileW(str(path), _GENERIC_READ | _GENERIC_WRITE, _FILE_SHARE_READ,
                                       None, _OPEN_ALWAYS, _FILE_ATTRIBUTE_NORMAL, None)
        if handle and handle != _INVALID_HANDLE:
            break
        error = ctypes.get_last_error()
        handle = None
        if error != _ERROR_SHARING_VIOLATION or time.monotonic() >= deadline:
            raise OSError(error, f"could not open {path} for writing", str(path))
        time.sleep(interval)
    import msvcrt
    fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    try:
        with os.fdopen(fd, "r+b", closefd=True) as fh:
            yield fh
    except Exception:
        raise


def append(path: str | os.PathLike[str], record: dict) -> dict:
    """Append one record, taking the chain's tip inside the lock that excludes other writers."""
    path = str(path)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with exclusive(path) as fh:
        fh.seek(0)
        existing = fh.read().decode("utf-8")
        lines = [line for line in existing.split("\n") if line.strip()]
        tip = hash_text(lines[-1][:-1] if lines and lines[-1].endswith("\r") else lines[-1]) if lines else ""
        stored = dict(record)
        stored["prev"] = tip
        payload = json.dumps(stored, ensure_ascii=False, separators=(",", ":")) + "\n"
        fh.seek(0, os.SEEK_END)
        fh.write(payload.encode("utf-8"))
        fh.flush()
        os.fsync(fh.fileno())
    return stored
