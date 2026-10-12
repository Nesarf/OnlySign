"""Boot the mark sector on real firmware, and print what comes back.

The self-test executes the sector on Unicorn, which is QEMU's CPU core but has no BIOS: it supplies
INT 10h itself and stubs the firmware handoff. That verifies the machine code and says nothing about
whether firmware would load this sector, hand it control and run it. This does that half. It is a
separate script rather than a check in the suite for the same reason `terminal-probe.ps1` is a
separate script: it needs something a normal run does not have, and a suite that skips half its
checks on a machine without QEMU is worse than one that does not pretend to make the claim.

    python tools/boot-check.py                       # builds an image and boots it here
    python tools/boot-check.py --qemu <qemu-system-i386.exe>
    python tools/boot-check.py --identity IDENTITY.local.json   # the real names, not the test's

The image is written to a scratch directory and never into the repository, because with an identity
file its text is that identity's names.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from onlysign import mark  # noqa: E402
from onlysign.engine import bootmark  # noqa: E402

TEST_MARK = "ONLYSIGN-MARK v1 | (c) TEST-PRIMARY [TEST-SECONDARY] | kind:boot-sector"

QEMU_CANDIDATES = (
    r"E:\DaShaoHuo\apps\qemu\qemu-system-i386.exe",
    r"C:\Program Files\qemu\qemu-system-i386.exe",
)


def find_qemu(explicit: str) -> str:
    if explicit:
        return explicit
    found = _on_path("qemu-system-i386")
    if found:
        return found
    for candidate in QEMU_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    raise SystemExit("no qemu-system-i386; pass --qemu with its path")


def _on_path(name: str) -> str:
    from shutil import which
    return which(name) or which(name + ".exe") or ""


def mark_text(identity: str) -> str:
    if not identity:
        return TEST_MARK
    names = json.loads(Path(identity).read_text(encoding="utf-8"))
    return mark.mark_line(primary=names["primary"], secondary=names.get("secondary"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Boot the mark sector on real firmware.")
    parser.add_argument("--qemu", default="", help="qemu-system-i386; found automatically otherwise")
    parser.add_argument("--identity", default="", help="a local identity JSON, for the real names")
    parser.add_argument("--seconds", type=int, default=25,
                        help="how long to let it run (the sector halts, so it never exits by itself)")
    parser.add_argument("--keep", default="", help="write the image here and leave it")
    args = parser.parse_args()

    qemu = find_qemu(args.qemu)
    text = mark_text(args.identity)
    print(f"qemu     : {qemu}")
    print(f"mark line: {text!r}")

    scratch = args.keep or tempfile.mkdtemp(prefix="bootmark-")
    Path(scratch).mkdir(parents=True, exist_ok=True)
    image = Path(scratch) / "mark.img"
    size = bootmark.write_image(image, text)
    print(f"image    : {image}  ({size} bytes, boot record = the sector)")

    # `if=floppy` and an explicit `format=raw`, because QEMU otherwise probes and warns that guessing
    # a raw image is dangerous -- which is true, and the warning buries the output being looked for.
    command = [
        qemu,
        "-drive", f"file={image},format=raw,if=floppy",
        "-display", "none",
        "-serial", "stdio",
        "-no-reboot",
    ]
    print(f"booting  : {' '.join(command)}")
    try:
        done = subprocess.run(command, capture_output=True, timeout=args.seconds)
        output = done.stdout + done.stderr
    except subprocess.TimeoutExpired as expired:
        # Expected: the sector halts and loops, so QEMU never exits on its own.
        output = (expired.stdout or b"") + (expired.stderr or b"")

    captured = output.decode("utf-8", "replace")
    print()
    print("what came down the serial line:")
    for line in captured.splitlines():
        print(f"   {line}")
    print()
    if text in captured:
        print("the firmware loaded the sector and the mark came back: this is the half Unicorn cannot do")
        return 0
    print("the mark did not come back, so either the image or the boot path is wrong")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
