"""A mark in 512 bytes: the one part of a disk that every PC has been able to read since 1981.

The mark module exists for formats that have nowhere to sign a file. This is the floor of that idea.
A boot sector is not a file format with a slot to put attribution in -- it is the first sector of a
disk, read by the firmware before any operating system exists, on machines that cannot verify a
signature and in some cases cannot run anything modern at all. That is exactly the case the mark is
for: somewhere to put text that will still be there later, needing no cryptography.

What it is worth is worth stating plainly, because it is easy to oversell. A mark in a boot sector is
**visibility only**. Nothing vouches for it. Anyone can write these 512 bytes, and `kind:` says so.
What it buys is reach -- a machine from 1981 onward can be made to display who claims the disk.

The sector prints the same characters twice, on purpose:

* **INT 10h teletype**, which is what a person at a real screen sees. This is the oldest output path
  a PC BIOS has, and it is why the text appears without any driver or operating system.
* **COM1**, which is what a script, an emulator or a serial console can capture as text. Without it
  there is no way to check the sector does what it says without a screen, and "verified" would mean
  "it assembled".

The code is assembled with nasm once and embedded here, so the tool needs no assembler. nasm is the
authority for the encoding and `ndisasm -b 16 -o 0x7C00` prints what these bytes are; both were run
rather than the bytes being written by hand and called correct. The listing at the end of this module
is that output.
"""

from __future__ import annotations

import os

# The code up to the point where the text begins. Fixed length, no relocations that depend on where
# the text lands: the `mov si, 0x7C44` inside it is assembled against TEXT_OFFSET, so the two are
# checked against each other rather than assumed to agree.
CODE = bytes.fromhex(
    "fa31c08ed88ec08ed0bc007cfbbafb03"
    "b080eebaf803b001eebaf90330c0eeba"
    "fb03b003eebafa03b0c7eebaf803be44"
    "7cbb0700ac84c07407b40ecd10eeebf4"
    "faf4ebfc"
)

TEXT_OFFSET = len(CODE)
SECTOR_SIZE = 512
BOOT_SIGNATURE = b"\x55\xAA"
SIGNATURE_OFFSET = SECTOR_SIZE - 2
LINE_ENDING = b"\r\n"
# The text ends with a carriage return and a line feed and then a NUL the code tests for. The line
# ending is part of the sector rather than the caller's business because what a sector prints is a
# *line*: on a screen the cursor should end up below it, and a serial capture that runs into whatever
# is printed next is not a line anybody can parse.
MAX_TEXT_BYTES = SIGNATURE_OFFSET - TEXT_OFFSET - len(LINE_ENDING) - 1

# `mov si, 0x7C44` -- the text address the code was assembled with. The sector is loaded at 0x7C00
# by the firmware, which is the only thing that makes this a constant.
LOAD_ADDRESS = 0x7C00
_SI_IMMEDIATE_AT = 0x2E              # offset of the `BE` opcode in `BE 44 7C`
_SI_IMMEDIATE = CODE[_SI_IMMEDIATE_AT + 1: _SI_IMMEDIATE_AT + 3]

FLOPPY_IMAGE_BYTES = 1474560         # a 1.44 MB floppy: three sectors of BPB-free boot record and
FLOPPY_SECTOR_BYTES = 512            # the rest zeros, so an emulator has a device to boot from

# com1 data register: the port the code writes each character to as well as the screen.
COM1 = 0x3F8
BIOS_TELETYPE = 0x10


class MarkDoesNotFit(ValueError):
    """Raised when the text is longer than a boot sector can carry."""


def build(text: str) -> bytes:
    """One 512-byte sector carrying `text`, ending in the boot signature.

    Refuses rather than truncates. A mark that has been quietly shortened is worse than no mark: it
    would still parse as a mark and would name a party that never agreed to what it now says.
    """
    encoded = text.encode("ascii", "strict")
    if len(encoded) > MAX_TEXT_BYTES:
        raise MarkDoesNotFit(
            f"{len(encoded)} bytes of text will not fit in a boot sector: the code takes "
            f"{TEXT_OFFSET} bytes, the line ending {len(LINE_ENDING)}, the terminating NUL 1, and "
            f"the boot signature 2, which leaves {MAX_TEXT_BYTES}"
        )
    body = CODE + encoded + LINE_ENDING + b"\x00"
    sector = bytearray(SECTOR_SIZE)
    sector[0:len(body)] = body
    sector[SIGNATURE_OFFSET:SECTOR_SIZE] = BOOT_SIGNATURE
    return bytes(sector)


def read(blob: bytes) -> dict:
    """What this sector says, and whether it is one of these sectors at all.

    Read-only and believing nothing: the report separates what the bytes prove (there is a boot
    signature, there is text) from what the text claims (who wrote it, and what the mark says its own
    strength is), because those are different things and only the first is a fact about the file.
    """
    report: dict = {"size": len(blob), "is_sector": False, "carries_mark": False, "text": "",
                    "problems": []}
    if len(blob) != SECTOR_SIZE:
        report["problems"].append(f"not a sector: {len(blob)} bytes rather than {SECTOR_SIZE}")
        return report
    report["boot_signature"] = blob[SIGNATURE_OFFSET:SECTOR_SIZE] == BOOT_SIGNATURE
    if not report["boot_signature"]:
        report["problems"].append("no 55 AA at offset 510, so firmware would not run this")
        return report
    report["is_sector"] = True
    report["our_code"] = blob[:TEXT_OFFSET] == CODE
    if not report["our_code"]:
        report["problems"].append(
            "the boot code is not the code this tool writes, so the text below may not be all "
            "of what the sector does"
        )
    text_bytes = blob[TEXT_OFFSET:SIGNATURE_OFFSET]
    end = text_bytes.find(b"\x00")
    if end < 0:
        report["problems"].append("the text is not terminated, so the code would run past it")
        return report
    decoded = text_bytes[:end].decode("ascii", "replace")
    if decoded.endswith("\r\n"):
        decoded = decoded[:-2]
    report["text"] = decoded
    report["carries_mark"] = bool(report["text"])
    return report


def floppy_image(text: str) -> bytes:
    """The sector as the boot record of a 1.44 MB image, which is what an emulator can boot.

    A bare 512-byte file is the sector and nothing else; an emulator wants a device. The rest of the
    image is zeros -- this is not a filesystem and does not pretend to be one. The point of the
    image is that a machine with no operating system at all will still run its first sector.
    """
    sector = build(text)
    return sector + bytes(FLOPPY_IMAGE_BYTES - SECTOR_SIZE)


def write(path: str | os.PathLike[str], text: str) -> int:
    """Write the sector to a file and report how many bytes went in."""
    sector = build(text)
    with open(path, "wb") as handle:
        handle.write(sector)
    return len(sector)


def write_image(path: str | os.PathLike[str], text: str) -> int:
    """Write the bootable image, for handing to an emulator."""
    image = floppy_image(text)
    with open(path, "wb") as handle:
        handle.write(image)
    return len(image)


def text_offset_matches() -> bool:
    """Whether the address the code loads really is where the text is.

    The one thing in here that could be wrong silently: `mov si, 0x7C44` is an immediate, so if the
    code were ever edited to a different length without reassembling, the sector would still look
    well-formed and would print whatever happened to be at the old address. Checked rather than
    trusted, and the assembler is what makes it true.
    """
    return int.from_bytes(_SI_IMMEDIATE, "little") == LOAD_ADDRESS + TEXT_OFFSET


# ndisasm -b 16 -o 0x7C00 boot.bin, the code half only:
#
#   00007C00  FA                cli
#   00007C01  31C0              xor ax,ax
#   00007C03  8ED8              mov ds,ax
#   00007C05  8EC0              mov es,ax
#   00007C07  8ED0              mov ss,ax
#   00007C09  BC007C            mov sp,0x7c00
#   00007C0C  FB                sti
#   00007C0D  BAFB03            mov dx,0x3fb        ; COM1 line control
#   00007C10  B080              mov al,0x80         ; divisor latch on
#   00007C12  EE                out dx,al
#   00007C13  BAF803            mov dx,0x3f8        ; divisor low
#   00007C16  B001              mov al,0x1          ; 115200
#   00007C18  EE                out dx,al
#   00007C19  BAF903            mov dx,0x3f9
#   00007C1C  30C0              xor al,al
#   00007C1E  EE                out dx,al
#   00007C1F  BAFB03            mov dx,0x3fb
#   00007C22  B003              mov al,0x3          ; 8N1, latch off
#   00007C24  EE                out dx,al
#   00007C25  BAFA03            mov dx,0x3fa        ; FIFO control
#   00007C28  B0C7              mov al,0xc7         ; enable, clear, 14-byte threshold
#   00007C2A  EE                out dx,al
#   00007C2B  BAF803            mov dx,0x3f8        ; back to the data register
#   00007C2E  BE447C            mov si,0x7c44       ; the text, at LOAD_ADDRESS + TEXT_OFFSET
#   00007C31  BB0700            mov bx,0x7          ; teletype page 0, light grey
#   00007C34  AC                lodsb
#   00007C35  84C0              test al,al
#   00007C37  7407              jz 0x7c40
#   00007C39  B40E              mov ah,0xe
#   00007C3B  CD10              int 0x10
#   00007C3D  EE                out dx,al
#   00007C3E  EBF4              jmp short 0x7c34
#   00007C40  FA                cli
#   00007C41  F4                hlt
#   00007C42  EBF C             jmp short 0x7c40
