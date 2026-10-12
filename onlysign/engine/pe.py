"""What a file actually is, and what a signature physically is.

The extension is a claim; the first bytes are the file. A tool that puts a signature on something
should say what it is about to sign before it signs it, and it should not be told by a name that
anyone can change.

The second half of this module is the part that makes signatures less mysterious: an Authenticode
signature on a PE file is a table appended after everything else, found through one directory entry
in the optional header. Removing it means clearing that entry and truncating the file where the
table began. That is also why "sign last" is not a preference -- any later rewrite of the contents
lands before the table or moves it, and the signature stops matching.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

KIND_PE = "pe"
KIND_MSI = "msi"
KIND_CAB = "cab"
KIND_DER = "der"
KIND_UNKNOWN = "unknown"

# What Windows will accept an embedded Authenticode signature on. A DER file is most likely a
# catalog, which Authenticode does cover, but this tool has not exercised that path -- so it is
# reported and left unselected rather than promised.
SIGNED_BY_AUTHENTICODE = frozenset({KIND_PE, KIND_MSI, KIND_CAB})

_MAGIC = (
    (b"MZ", KIND_PE),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", KIND_MSI),   # OLE compound file
    (b"MSCF", KIND_CAB),
)

_DESCRIPTION = {
    KIND_PE: "a PE image (an executable or a library)",
    KIND_MSI: "an MSI package",
    KIND_CAB: "a cabinet",
    KIND_DER: "a DER/PKCS#7 file, which is usually a catalog",
    KIND_UNKNOWN: "not a file type this tool recognises",
}


def identify(path: str | os.PathLike[str]) -> str:
    """The kind of file this is, decided by its leading bytes."""
    with open(path, "rb") as fh:
        head = fh.read(8)
    for magic, kind in _MAGIC:
        if head.startswith(magic):
            return kind
    if len(head) >= 2 and head[0] == 0x30 and head[1] in (0x80, 0x81, 0x82):
        return KIND_DER
    return KIND_UNKNOWN


def describe(kind: str) -> str:
    return _DESCRIPTION.get(kind, _DESCRIPTION[KIND_UNKNOWN])


def signable(kind: str) -> bool:
    return kind in SIGNED_BY_AUTHENTICODE


def _looks_like_certificate_table(data: bytes | bytearray, offset: int) -> bool:
    """Whether the bytes at ``offset`` are a WIN_CERTIFICATE naming a length that fits.

    The directory entry is a number the file wrote about itself, and a packer that appends to an
    already-signed image does not always fix it: `postject` was measured leaving it pointing at the
    offset the base image had, which after the append lands inside section data. So the bytes at the
    offset are asked to prove they are a table rather than being taken on the entry's word -- a
    WIN_CERTIFICATE header (``dwLength``, ``wRevision``, ``wCertificateType``) whose revision and type
    are the ones Authenticode writes and whose length fits inside the file.

    Measured on both cases: a real table says revision 0x0200, type 0x0002 and a length reaching
    exactly to the end of the file, and its payload starts with the 0x30 of a DER SEQUENCE; what sits
    at a stale offset reads as three unrelated values.
    """
    if offset < 0 or offset + 8 > len(data):
        return False
    length, revision, kind = struct.unpack_from("<IHH", data, offset)
    if revision not in (0x0100, 0x0200) or kind not in (0x0001, 0x0002):
        return False
    return 8 <= length <= len(data) - offset


def pe_certificate_table(path: str | os.PathLike[str]) -> tuple[int, int] | None:
    """``(offset, size)`` of the embedded signature, or None when there is none.

    The entry is index 4 (``IMAGE_DIRECTORY_ENTRY_SECURITY``) of the data directory, which sits at
    offset 96 in a PE32 optional header and 112 in a PE32+ one, eight bytes per entry.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset <= 0 or pe_offset + 24 >= len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:
        directory = optional + 96
    elif magic == 0x20B:
        directory = optional + 112
    else:
        return None
    entry = directory + 4 * 8
    if entry + 8 > len(data):
        return None
    offset, size = struct.unpack_from("<II", data, entry)
    if not size or not offset:
        return None
    return offset, size


def checksum_field(data: bytes | bytearray) -> int:
    """Where the PE checksum lives, or -1 if this is not a PE.

    The same offset for both widths, which is worth knowing rather than guessing: a 32-bit optional
    header carries BaseOfData and a 4-byte ImageBase where a 64-bit one carries an 8-byte ImageBase,
    so the two differ by four bytes and then **re-align at offset 32**. Everything after that,
    CheckSum included, sits in the same place.
    """
    if len(data) < 0x40:
        return -1
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 + 20 + 2 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return -1
    optional = pe_offset + 4 + 20
    if struct.unpack_from("<H", data, optional)[0] not in (0x10B, 0x20B):
        return -1
    return optional + 64


def recompute_checksum(data: bytearray) -> int:
    """Write the PE checksum the way the linker and the signing tools write it, and return it.

    Verified rather than assumed: run against every binary in System32 and SysWOW64 it reproduces
    the value already stored in the header, 60 out of 60 -- which is the only reason it is safe to
    use for putting a file back the way it was. The four bytes of the field itself count as zero,
    and the file length is added at the end.
    """
    offset = checksum_field(data)
    if offset < 0 or offset + 4 > len(data):
        return 0
    total = 0
    length = len(data)
    for index in range(0, length - (length % 2), 2):
        if offset <= index < offset + 4:
            continue
        total += data[index] | (data[index + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
    if length % 2:
        total += data[length - 1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    value = (total + length) & 0xFFFFFFFF
    struct.pack_into("<I", data, offset, value)
    return value


def strip_signature(path: str | os.PathLike[str]) -> int:
    """Remove an embedded signature in place. Returns the number of bytes removed, 0 if none.

    Written rather than borrowed: ``signtool remove`` refuses some Microsoft binaries outright and,
    on a catalog-signed one, exits reporting success having removed nothing at all. Doing it here
    also makes plain what the operation is -- clearing one entry and dropping a table off the end.
    """
    table = pe_certificate_table(path)
    if table is None:
        return 0
    offset, _size = table
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    if offset >= len(data):
        raise ValueError(f"{path}: the certificate table points past the end of the file")
    # Refusing here rather than cutting: everything from the offset to the end is dropped, so acting
    # on a wrong offset deletes bytes the entry never claimed. Measured on a stale entry: 19296 bytes
    # removed, of which 11696 were the image's own data -- and the file still identified as a PE
    # afterwards, so nothing downstream noticed. A wrong entry is a symptom of a tool that appended
    # without updating the directory, and saying so is more useful than doing what it says.
    if not _looks_like_certificate_table(data, offset):
        raise ValueError(
            f"{path}: the certificate table entry points at {offset} but there is no WIN_CERTIFICATE "
            f"there, so this entry was not written by whatever appended the signature -- stripping on "
            f"that number would cut into the file's own data")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    directory = optional + (96 if magic == 0x10B else 112)
    entry = directory + 4 * 8
    removed = len(data) - offset
    del data[offset:]
    struct.pack_into("<II", data, entry, 0, 0)
    # And the checksum, which signing recomputed over the file *with* the signature. Leaving it
    # alone is what makes a stripped file match neither hash on record: the bytes are the ones from
    # before signing, but one field in the header still describes the signed version. Putting it
    # back is what lets an audit say "the signature was removed" rather than only "there is none".
    recompute_checksum(data)
    with open(path, "wb") as fh:
        fh.write(bytes(data))
    return removed


# DER-encoded object identifiers that appear inside a signed table when the signature was stamped:
# 1.2.840.113549.1.9.16.2.14 (an RFC 3161 signature timestamp) and 1.2.840.113549.1.9.6 (the older
# counter-signature). Searching for these is a byte-level question with a byte-level answer, which is
# the point: the alternative is a verdict that can be about a catalog entry instead of this file.
_TIMESTAMP_OIDS = (
    bytes.fromhex("2a864886f70d010910020e"),
    bytes.fromhex("2a864886f70d010906"),
)


def signature_blob(path: str | os.PathLike[str]) -> bytes | None:
    """The bytes of the embedded signature table, or None when there is none."""
    table = pe_certificate_table(path)
    if table is None:
        return None
    offset, size = table
    with open(path, "rb") as fh:
        fh.seek(offset)
        return fh.read(size)


def has_timestamp_attribute(path: str | os.PathLike[str]) -> bool:
    """Whether the file's own signature was stamped by a timestamp authority."""
    blob = signature_blob(path)
    if not blob:
        return False
    return any(oid in blob for oid in _TIMESTAMP_OIDS)


@dataclass
class SignatureState:
    """Everything a signing attempt can change about a file, so it can be put back.

    Measured rather than assumed: when the timestamp authority cannot be reached,
    ``Set-AuthenticodeSignature`` appends a complete signature and *does not* take it back -- unlike
    ``signtool``, which restores the file. What changes is exactly three things: the length, the
    four-byte PE checksum, and the eight-byte certificate-table entry. The body is untouched.
    """

    size: int
    checksum_offset: int
    checksum: bytes
    entry_offset: int
    entry: bytes


def capture_state(path: str | os.PathLike[str]) -> SignatureState | None:
    """What would have to be restored if a signing attempt did not finish. None for a non-PE file."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset <= 0 or pe_offset + 24 >= len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        return None
    directory = optional + (96 if magic == 0x10B else 112)
    entry = directory + 4 * 8
    checksum = optional + 64
    if entry + 8 > len(data) or checksum + 4 > len(data):
        return None
    return SignatureState(
        size=len(data),
        checksum_offset=checksum,
        checksum=data[checksum:checksum + 4],
        entry_offset=entry,
        entry=data[entry:entry + 8],
    )


def restore_state(path: str | os.PathLike[str], state: SignatureState) -> int:
    """Put a file back the way it was, and report how many bytes were dropped off the end."""
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    dropped = max(0, len(data) - state.size)
    del data[state.size:]
    data[state.checksum_offset:state.checksum_offset + 4] = state.checksum
    data[state.entry_offset:state.entry_offset + 8] = state.entry
    with open(path, "wb") as fh:
        fh.write(bytes(data))
    return dropped
