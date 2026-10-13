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
import io
import json
import os
import struct
from pathlib import Path

MARK_PREFIX = "ONLYSIGN-MARK v1"
ZIP_EOCD = b"PK\x05\x06"
ZIP_EOCD_MIN = 22
ZIP_COMMENT_MAX = 65535
# The tar carrier appends one member with this name and nothing else. A member rather than a header
# field because a member is what every tar reader already shows: `tar -tvf` lists it and
# `tar -xOf archive NAME` prints it, with no knowledge of this tool on the reading side.
TAR_MEMBER = "ONLYSIGN-MARK"
TAR_BLOCK = 512


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


# --- tar ---------------------------------------------------------------------- #
#
# The same problem as the zip comment, with a different answer. A tar has no comment field at all,
# so the mark goes in as a *member*: one extra entry whose content is the mark line. Every reader
# shows it without knowing anything about this tool, and nothing that was already in the archive is
# touched -- the member is appended, and the bytes before it are the archive as it arrived.
#
# Which is where the digest comes from, and it is tidier here than for a zip: the digest is taken
# over the archive *up to the mark member*, so for a freshly marked file it is exactly the sha256 of
# the archive that was there before. A reader can recompute it without knowing this tool, and it is
# the same number as the download's own hash.

def _tar_length(block: bytes) -> int:
    """The size field of a tar header, in octal, or -1 when it does not read as one."""
    field = block[124:136].split(b"\x00", 1)[0].strip()
    try:
        return int(field or b"0", 8)
    except ValueError:
        return -1


def tar_mark_offset(path: str) -> int | None:
    """Where the mark member's header starts, or None when this tar does not carry one.

    Walked block by block rather than loaded: a tar can be gigabytes, and the question only needs the
    headers. A zero block is the end-of-archive marker, so the walk stops there rather than reading
    whatever happens to follow the archive in the file.
    """
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        offset = 0
        while offset + TAR_BLOCK <= size:
            handle.seek(offset)
            block = handle.read(TAR_BLOCK)
            if block == bytes(TAR_BLOCK):
                return None
            name = block[:100].split(b"\x00", 1)[0].decode("utf-8", "replace")
            if name == TAR_MEMBER:
                return offset
            length = _tar_length(block)
            if length < 0:
                return None                       # not a tar header: stop rather than guess
            offset += TAR_BLOCK + ((length + TAR_BLOCK - 1) // TAR_BLOCK) * TAR_BLOCK
    return None


def _tar_content_end(path: str) -> int:
    """Where the members stop, which is the first zero block.

    What follows is the end-of-archive marker and then padding to the writer's record size, so this
    is the length of the part that means anything. Measured while writing this: a two-member tar was
    10240 bytes with its members ending at 7168, so a digest taken over the whole file and one taken
    over the members are two different numbers -- and only the second can be recomputed from the
    marked file, because marking writes over the padding.
    """
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        offset = 0
        while offset + TAR_BLOCK <= size:
            handle.seek(offset)
            block = handle.read(TAR_BLOCK)
            if block == bytes(TAR_BLOCK):
                return offset
            length = _tar_length(block)
            if length < 0:
                return offset
            offset += TAR_BLOCK + ((length + TAR_BLOCK - 1) // TAR_BLOCK) * TAR_BLOCK
    return size


def tar_body_digest(path: str) -> str:
    """The sha256 of a tar's members, up to its mark member when it carries one.

    Marking does not change this number: the mark is appended after the members, so the bytes hashed
    are the same before and after, and a reader can recompute it from the marked file alone. That is
    the reason for defining it over the member region rather than over the file -- and the trade-off
    is that it is NOT the number `sha256sum` prints, because the trailing padding is excluded. A
    digest a marked archive could never recompute would be the worse of the two.
    """
    stop = tar_mark_offset(path)
    if stop is None:
        stop = _tar_content_end(path)
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        remaining = stop
        while remaining:
            block = handle.read(min(1 << 20, remaining))
            if not block:
                break
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def mark_tar(path: str, *, primary: str, secondary: list[str] | None = None, year: str = "",
             digest: bool = True, dry_run: bool = False) -> dict:
    """Put the mark in a tar as one appended member.

    Marking twice replaces rather than stacks: an existing mark member is cut off first, so the
    archive returns to the bytes it arrived as and the digest taken afterwards is that archive's own
    hash again. Appending a second member instead would leave the first one in the file for every
    reader to find, saying something nobody meant to keep saying.
    """
    import tarfile                                            # only for writing a correct header
    existing = tar_mark_offset(path)
    body = tar_body_digest(path) if digest else ""
    line = mark_line(primary=primary, secondary=secondary, digest=body, year=year,
                     kind="hash-record" if body else "visibility")
    if dry_run:
        return {"path": path, "line": line, "digest": body, "wrote": False}
    if existing is not None:
        # Cut the old mark off, and put a valid end-of-archive marker back: truncating at the member
        # leaves a tar with no end, and opening that in append mode fails with "empty header" -- which
        # is how marking twice was found to be broken rather than merely untested.
        with open(path, "r+b") as handle:
            handle.truncate(existing)
            handle.seek(existing)
            handle.write(bytes(TAR_BLOCK * 2))
    payload = (line + "\n").encode("utf-8")
    info = tarfile.TarInfo(TAR_MEMBER)
    info.size = len(payload)
    info.mtime = 0                       # a fixed timestamp, so the same archive marks to the same
    info.mode = 0o644                    # bytes on any day and any machine
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    try:
        archive = tarfile.open(path, "a", format=tarfile.USTAR_FORMAT)
    except tarfile.TarError as exc:
        raise ValueError(
            f"tarfile will not open this archive for appending ({exc}) -- it is not a tar, or it is "
            f"one whose headers do not check out") from None
    with archive:
        try:
            archive.addfile(info, io.BytesIO(payload))
        except tarfile.TarError as exc:
            # tarfile refuses an archive whose headers do not check out, and it says so in its own
            # vocabulary. A person marking a file they downloaded wants the sentence, not the term.
            raise ValueError(
                f"tarfile will not append to this archive ({exc}) -- it is not a tar, or it is one "
                f"whose headers do not check out") from None
    return {"path": path, "line": line, "digest": body, "wrote": True}


def read_tar_mark(path: str) -> dict:
    """What mark a tar carries, and whether its digest still describes the archive."""
    offset = tar_mark_offset(path)
    if offset is None:
        return {"path": path, "marked": False}
    with open(path, "rb") as handle:
        handle.seek(offset)
        block = handle.read(TAR_BLOCK)
        length = _tar_length(block)
        if length < 0:
            return {"path": path, "marked": False}
        text = handle.read(length).decode("utf-8", "replace").strip()
    found = parse_mark(text)
    if not found:
        return {"path": path, "marked": False}
    found["path"] = path
    found["marked"] = True
    found["member"] = TAR_MEMBER
    if found.get("sha256"):
        found["digest_matches"] = found["sha256"] == tar_body_digest(path)
    return found
