"""Build the installer: an MSI carrying the window, the command line, the licence and a shortcut.

    python tools/build-msi.py                        # neutral, as the published tool ships
    python tools/build-msi.py --identity IDENTITY.local.json

Three decisions this makes, and why.

**The identity is an input.** The product name, maker and description come from a local identity
file; without one the installer says `OnlySign` / `its publisher`, which is what the repository is
allowed to say. The same rule the build follows, applied to the installer, and the reason the source
file carries tokens rather than names.

**The licence page shows the licence that is actually shipped.** The text is read out of `LICENSE`
and converted, not retyped: a second copy of the terms is a second copy that can drift, and a
licence page showing something other than the licence is worse than no licence page.

**The version comes from the executable.** WiX's `Version` field is four numbers and no letters, and
it has to agree with what the binaries declare about themselves -- an installer that says one version
while the thing it installed says another is a support call with no answer. So it is read from the
built executable's own version resource, and the build fails if the two do not exist.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
WIX_CANDIDATES = (
    r"E:\DaShaoHuo\tools\dotnet-tools\wix.exe",
    r"C:\Program Files (x86)\WiX Toolset v5\bin\wix.exe",
    r"C:\Program Files\WiX Toolset v5\bin\wix.exe",
)
UPGRADE_CODE = "8d3f0a52-1c47-4e69-b5a8-2f7c9d6e14b3"
FOLDER_DEFAULT = "OnlySign"
WIX_EXTENSION_VERSION = "5.0.2"


def find_wix(explicit: str) -> str:
    if explicit:
        if os.path.isfile(explicit):
            return explicit
        raise SystemExit(f"no wix at {explicit}")
    for candidate in WIX_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    found = shutil.which("wix")
    if found:
        return found
    raise SystemExit("WiX was not found; pass --wix <path to wix.exe>")


def identity_from(path: str) -> dict:
    """Who the installer says published this, from a local file and never from the repository."""
    fallback = {"product": "OnlySign", "maker": "its publisher",
                "description": "Sign local build artifacts", "folder": FOLDER_DEFAULT}
    if not path:
        return fallback
    try:
        raw = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"could not read the identity file {path}: {exc}") from None
    product = str(raw.get("product") or "").strip()
    maker = str(raw.get("primary") or "").strip()
    return {
        "product": product or fallback["product"],
        "maker": maker or fallback["maker"],
        "description": str(raw.get("description") or fallback["description"]).strip(),
        # The install directory is a Latin name on purpose: a path with a non-ASCII segment in it is
        # a path that some other tool, somewhere, will mangle.
        "folder": re.sub(r"[^A-Za-z0-9._-]", "", product) or FOLDER_DEFAULT,
    }


def version_of(exe: pathlib.Path) -> str:
    """The version the executable claims, which is the one the installer has to agree with.

    Read from the version resource rather than restated here, because two numbers that must match
    should be one number.
    """
    import ctypes

    size = ctypes.windll.version.GetFileVersionInfoSizeW(str(exe), None)
    if not size:
        raise SystemExit(f"{exe} carries no version resource, so the installer has nothing to match")
    buffer = ctypes.create_string_buffer(size)
    if not ctypes.windll.version.GetFileVersionInfoW(str(exe), 0, size, buffer):
        raise SystemExit(f"could not read the version resource of {exe}")
    pointer = ctypes.c_void_p()
    length = ctypes.c_uint()
    if not ctypes.windll.version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer),
                                               ctypes.byref(length)):
        raise SystemExit(f"could not read the fixed version block of {exe}")

    class FixedFileInfo(ctypes.Structure):
        _fields_ = [("dwSignature", ctypes.c_uint32), ("dwStrucVersion", ctypes.c_uint32),
                    ("dwFileVersionMS", ctypes.c_uint32), ("dwFileVersionLS", ctypes.c_uint32),
                    ("dwProductVersionMS", ctypes.c_uint32), ("dwProductVersionLS", ctypes.c_uint32),
                    ("dwFileFlagsMask", ctypes.c_uint32), ("dwFileFlags", ctypes.c_uint32),
                    ("dwFileOS", ctypes.c_uint32), ("dwFileType", ctypes.c_uint32),
                    ("dwFileSubtype", ctypes.c_uint32), ("dwFileDateMS", ctypes.c_uint32),
                    ("dwFileDateLS", ctypes.c_uint32)]

    info = ctypes.cast(pointer, ctypes.POINTER(FixedFileInfo)).contents
    return "{}.{}.{}.{}".format(info.dwFileVersionMS >> 16, info.dwFileVersionMS & 0xFFFF,
                                info.dwFileVersionLS >> 16, info.dwFileVersionLS & 0xFFFF)


def licence_rtf(licence: pathlib.Path, out: pathlib.Path) -> None:
    """The plain-text licence, wrapped as the RTF the installer's licence page needs.

    Not hand-written and not summarised: the same words the installed LICENSE file contains, escaped
    for RTF so that a backslash or a brace in the text cannot corrupt the document.
    """
    lines = licence.read_text(encoding="utf-8").splitlines()

    def escape(line: str) -> str:
        return line.replace("\\", r"\\").replace("{", r"\{").replace("}", r"\}")

    body = "\\par\n".join(escape(line) for line in lines)
    document = ("{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0\\fswiss Consolas;}}"
                "\\fs16\\f0 " + body + "\\par}")
    # RTF is the one thing here that is not plain text, so it is written as bytes: a stray encoding
    # step would break the license page in a way that only shows up on somebody else's machine.
    out.write_bytes(document.encode("ascii", "replace"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the OnlySign installer.")
    parser.add_argument("--identity", default="",
                        help="a local JSON file naming who the build belongs to")
    parser.add_argument("--dist", default=str(ROOT / "dist"), help="where the built executables are")
    parser.add_argument("--out", default="", help="where to write the .msi")
    parser.add_argument("--wix", default="", help="path to wix.exe")
    parser.add_argument("--keep-work", action="store_true")
    args = parser.parse_args()

    dist = pathlib.Path(args.dist).resolve()
    window_exe = dist / "OnlySign.exe"
    console_exe = dist / "OnlySign-console.exe"
    for path in (window_exe, console_exe):
        if not path.is_file():
            raise SystemExit(f"{path} is missing -- build the executables first "
                             f"(python tools/build.py, then --console --name OnlySign-console)")

    identity = identity_from(args.identity)
    version = version_of(window_exe)
    out = pathlib.Path(args.out).resolve() if args.out else dist / f"OnlySign-{version}.msi"
    out.parent.mkdir(parents=True, exist_ok=True)

    work = pathlib.Path(tempfile.mkdtemp(prefix="onlysign-msi-"))
    try:
        source = (ROOT / "installer" / "onlysign.wxs").read_text(encoding="utf-8")
        rtf = work / "LICENCE.rtf"
        licence_rtf(ROOT / "LICENSE", rtf)

        replacements = {
            "__PRODUCT__": identity["product"],
            "__MAKER__": identity["maker"],
            "__DESCRIPTION__": identity["description"],
            "__VERSION__": version,
            "__UPGRADE_CODE__": UPGRADE_CODE,
            "__FOLDER__": identity["folder"],
            "__ICON__": str(ROOT / "mark" / "onlysign.ico"),
            "__WINDOW_EXE__": str(window_exe),
            "__CONSOLE_EXE__": str(console_exe),
            "__LICENSE__": str(ROOT / "LICENSE"),
            "__NOTICE__": str(ROOT / "NOTICE"),
            "__LICENSE_RTF__": str(rtf),
        }
        for token, value in replacements.items():
            source = source.replace(token, value)
        remaining = re.findall(r"__[A-Z_]+__", source)
        if remaining:
            raise SystemExit(f"unsubstituted token(s): {sorted(set(remaining))}")

        authored = work / "onlysign.wxs"
        authored.write_text(source, encoding="utf-8")
        print(f"  product  : {identity['product']}")
        print(f"  maker    : {identity['maker']}")
        print(f"  version  : {version}  (from {window_exe.name})")
        print(f"  folder   : {identity['folder']}")

        # The extension is named by the path to its DLL. Pointing WiX at the extension's *name* and
        # hoping it searches a directory does not work here -- the search found nothing and the error
        # said only "could not be found, checked paths: WixToolset.UI.wixext", which reads as if the
        # name were wrong rather than the search. A path cannot be mis-searched.
        extension = ROOT / "installer" / "extensions" / "wixext5" / "WixToolset.UI.wixext.dll"
        if not extension.is_file():
            raise SystemExit(
                f"the UI extension is not installed at {extension}. It is a separate download:\n"
                f"  https://www.nuget.org/api/v2/package/WixToolset.UI.wixext/{WIX_EXTENSION_VERSION}\n"
                f"  the .nupkg is a zip; put wixext5/WixToolset.UI.wixext.dll at that path.")

        arguments = [find_wix(args.wix), "build", str(authored), "-arch", "x64",
                     "-ext", str(extension), "-o", str(out)]
        result = subprocess.run(arguments, capture_output=True, text=True)
        for line in (result.stdout or "").splitlines():
            if line.strip():
                print(f"  wix: {line}")
        if result.returncode != 0:
            for line in (result.stderr or "").splitlines():
                print(f"  wix error: {line}")
            return 1
        if not out.is_file():
            print("wix reported success and wrote nothing")
            return 1
        print(f"\nbuilt {out}  ({out.stat().st_size / 1048576:.1f} MB)")
    finally:
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"work kept at {work}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
