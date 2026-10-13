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
import json
import os
import struct
from pathlib import Path

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


def names_from(path: str) -> tuple[str, list[str]]:
    """The names to mark with, from a local file and never from this repository.

    Same rule as the build's identity: the tool is published neutral, so nothing in it says whose it
    is, and a mark that belongs to somebody loads that somewhere else. Returns empty values rather
    than inventing a name -- a mark that says "(c) its publisher" is not a mark, and a caller that
    gets nothing back should refuse rather than write one.
    """
    if not path:
        return "", []
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"could not read the identity file {path}: {exc}") from None
    primary = str(raw.get("primary", "")).strip()
    secondary = [str(item).strip() for item in (raw.get("secondary") or []) if str(item).strip()]
    return primary, secondary


# --- zip ---------------------------------------------------------------------- #

def zip_eocd_at(path: str, size: int | None = None) -> int | None:
    """Where the end-of-central-directory record starts, or None if this is not a zip.

    The record may sit up to 64 KiB from the end when a comment is present, so the tail is searched
    rather than the last 22 bytes assumed -- and the candidate is accepted only when the comment
    length it declares reaches exactly to the end of the file, which is what makes the record the
    real one rather than a byte sequence that happens to look like it.
    """
    if size is None:
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
                return size - window + at
        at = tail.rfind(ZIP_EOCD, 0, at)
    return None


def zip_comment(path: str) -> str:
    """What a zip says about itself, or an empty string."""
    size = os.path.getsize(path)
    at = zip_eocd_at(path, size)
    if at is None:
        return ""
    with open(path, "rb") as handle:
        handle.seek(at + ZIP_EOCD_MIN)
        return handle.read(size - at - ZIP_EOCD_MIN).decode("utf-8", "replace")


def put_zip_comment(path: str, comment: str) -> None:
    """Set a zip's comment, replacing whatever was there.

    Only the comment length field and the bytes after it change, so the archive's contents are
    untouched -- but the file's bytes are not, which is why this must happen before signing.
    """
    blob = comment.encode("utf-8")
    if len(blob) > ZIP_COMMENT_MAX:
        raise ValueError(f"a zip comment cannot exceed {ZIP_COMMENT_MAX} bytes")
    size = os.path.getsize(path)
    at = zip_eocd_at(path, size)
    if at is None:
        raise ValueError("no end-of-central-directory record: this is not a zip")
    with open(path, "r+b") as handle:
        handle.seek(at + 20)
        handle.write(struct.pack("<H", len(blob)))
        handle.write(blob)
        handle.truncate()


def zip_body_digest(path: str) -> str:
    """The sha256 of a zip with its comment removed and the comment-length field zeroed.

    This exists because of a trap that is easy not to see. A digest written into a zip's own comment
    cannot describe the file that contains it: the comment is part of the file, so the value would
    have to depend on itself, and any number put there would be wrong the moment it was written.

    What it can describe is the archive *without* any comment -- and a reader can reproduce that:
    find the end-of-central-directory record, take everything before the comment-length field,
    append two zero bytes, hash it. Zeroing the length is what makes it one number for the archive
    whether or not a comment is present, so the same mark checks out against the marked file and
    against the same file with the comment stripped.
    """
    size = os.path.getsize(path)
    at = zip_eocd_at(path, size)
    if at is None:
        raise ValueError("no end-of-central-directory record: this is not a zip")
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        remaining = at + 20                      # up to, but not including, the comment length
        while remaining:
            block = handle.read(min(1 << 20, remaining))
            if not block:
                break
            digest.update(block)
            remaining -= len(block)
    digest.update(b"\x00\x00")
    return digest.hexdigest()


def mark_zip(path: str, *, primary: str, secondary: list[str] | None = None, year: str = "",
             digest: bool = True, dry_run: bool = False) -> dict:
    """Put a mark in a zip's comment, digesting the archive without any comment.

    One function rather than three calls at the caller, because the order matters and getting it
    wrong is silent: the digest has to be taken before the comment is written, or it describes an
    archive that includes the previous mark. Doing it here means there is one place to be right.
    """
    body = zip_body_digest(path) if digest else ""
    line = mark_line(primary=primary, secondary=secondary, digest=body, year=year,
                     kind="hash-record" if body else "visibility")
    if not dry_run:
        put_zip_comment(path, line)
    return {"path": path, "line": line, "digest": body, "wrote": not dry_run}


def read_zip_mark(path: str) -> dict:
    """What mark a zip carries, and whether its digest still describes the archive.

    The check is the point of the digest, so it is done here rather than left to a reader: a mark
    whose hash no longer matches says the archive changed after it was marked, which is exactly the
    thing a hash in a mark is for.
    """
    found = parse_mark(zip_comment(path))
    if not found:
        return {"path": path, "marked": False}
    found["path"] = path
    found["marked"] = True
    if found.get("sha256"):
        found["digest_matches"] = found["sha256"] == zip_body_digest(path)
    return found
