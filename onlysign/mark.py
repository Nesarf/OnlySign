"""Leaving a mark on a file, for the platforms and formats that have no signature slot.

Two verbs, and they are not the same one:

* **Signing** is what a platform gives you -- a PE certificate table, an MSI stream, a CAB's
  appended blob. It needs cryptography, a container, and something to trust.
* **Marking** is what this does. It needs no cryptography at all: only somewhere to put text
  that will still be there later.

What a mark is for is attribution -- who says this is theirs -- while a signature answers a
different question, who vouches for these bytes. Both belong on an artifact, and they should
name the same party, because a reader who finds one should be able to find the other.

    ONLYSIGN-MARK v1 | (c) PRIMARY [SECONDARY] | sha256:ab12cd… | kind:hash-record

Square brackets, not a dash or a plus: those read as "and", and what is wanted is "belongs to".
A secondary mark is a connotation of the primary, not a peer of it.

**A mark does not make a file trustworthy and this file never pretends otherwise.** `kind:`
carries what strength the mark has, and a reader who does not check it has only learned who
claimed the file.

**Write the mark before signing, never after.** Changing a file changes its bytes, and every
signature over those bytes stops verifying -- so a mark added after signing turns a signed
artifact into a broken one. This is not a caveat appended to the design; it is the reason the
order is what it is.
"""

from __future__ import annotations

import hashlib
import os
import struct

MARK_PREFIX = "ONLYSIGN-MARK v1"
ZIP_EOCD = b"PK\x05\x06"
ZIP_EOCD_MIN = 22
ZIP_COMMENT_MAX = 65535


def mark_line(*, primary: str, secondary: list[str] | None = None, digest: str = "",
              kind: str = "hash-record", year: str = "") -> str:
    """The one line that is a whole mark.

    One line on purpose. Anything that can hold text can hold this -- a zip comment, an ISO
    label, a tape header, a README, a forum post, a printed listing -- so the same mark travels
    wherever the artifact goes, and a person can compare it by eye.
    """
    who = "(c) " + primary
    if year:
        who = "(c) " + year + " " + primary
    for extra in secondary or []:
        who += " [" + extra + "]"
    parts = [MARK_PREFIX, who]
    if digest:
        parts.append("sha256:" + digest)
    parts.append("kind:" + kind)
    return " | ".join(parts)


def parse_mark(text: str) -> dict:
    """Read a mark back into its parts, or an empty dict if this is not one."""
    if not text or MARK_PREFIX not in text:
        return {}
    found = {"raw": text.strip()}
    for piece in text.split("|"):
        piece = piece.strip()
        if piece.startswith("(c) "):
            found["holder"] = piece
        elif piece.startswith("sha256:"):
            found["sha256"] = piece.split(":", 1)[1]
        elif piece.startswith("kind:"):
            found["kind"] = piece.split(":", 1)[1]
    return found


def digest_of(path: str) -> str:
    """sha256 of the file, read in pieces so a large artifact is not held in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(1 << 20)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


# --- zip ---------------------------------------------------------------------- #

def zip_comment(path: str) -> str:
    """What a zip says about itself, or an empty string.

    Read from the end of the file, where the end-of-central-directory record keeps it. The
    record may sit up to 64 KiB from the end when a comment is present, so the tail is searched
    rather than the last 22 bytes assumed.
    """
    size = os.path.getsize(path)
    window = min(size, ZIP_COMMENT_MAX + ZIP_EOCD_MIN)
    with open(path, "rb") as handle:
        handle.seek(size - window)
        tail = handle.read(window)
    at = tail.rfind(ZIP_EOCD)
    while at >= 0:
        if at + ZIP_EOCD_MIN <= len(tail):
            length = struct.unpack_from("<H", tail, at + 20)[0]
            if at + ZIP_EOCD_MIN + length == len(tail):
                return tail[at + ZIP_EOCD_MIN:].decode("utf-8", "replace")
        at = tail.rfind(ZIP_EOCD, 0, at)
    return ""


def put_zip_comment(path: str, comment: str) -> None:
    """Set a zip's comment, replacing whatever was there.

    Only the comment length field and the bytes after it change, so the archive's contents are
    untouched -- but the file's bytes are not, which is why this must happen before signing.
    """
    blob = comment.encode("utf-8")
    if len(blob) > ZIP_COMMENT_MAX:
        raise ValueError(f"a zip comment cannot exceed {ZIP_COMMENT_MAX} bytes")
    with open(path, "r+b") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        window = min(size, ZIP_COMMENT_MAX + ZIP_EOCD_MIN)
        handle.seek(size - window)
        tail = handle.read(window)
        at = tail.rfind(ZIP_EOCD)
        if at < 0:
            raise ValueError("no end-of-central-directory record: this is not a zip")
        eocd_at = size - window + at
        handle.seek(eocd_at + 20)
        handle.write(struct.pack("<H", len(blob)))
        handle.write(blob)
        handle.truncate()
