"""Building the one-file executable.

    python tools/build.py                        the window, no console
    python tools/build.py --console              the same, but with a console -- for checking
    python tools/build.py --icon path\\to.ico

PyInstaller is the only thing this needs, and it is not a dependency of the tool: it is a dependency
of *building the tool*. The Python it runs under is `--python` (the interpreter running this script
by default), so a machine that keeps a packaging environment separate can point at it.

The work directory goes to the system temp area rather than the project, because a build leaves a
great deal behind that nobody wants to see in a source tree.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY = os.path.join(ROOT, "OnlySign.py")


DEFAULT_IDENTITY = {
    "product": "OnlySign",
    "version": "1.0.0",
    "company": "its publisher",
    "copyright": "(c) its publisher",
    "trademarks": "",
    "description": "Signs files, and ships a gate that checks the signature before installing.",
}


def identity_from(path: str) -> dict:
    """The names to stamp, from a local file, never from this repository.

    The tool is published neutral: nothing in it says whose it is. A build that belongs to
    somebody loads that somewhere else -- a JSON file with `primary`, optional `secondary` marks,
    and the product details. Without one, the generic wording above is used, which is the same
    choice NOTICE.txt already makes.

    The secondary marks are written to LegalTrademarks rather than appended to the copyright
    line, because a secondary mark is a mark and the copyright line is a claim of ownership over
    the work. Keeping them in separate fields keeps the relation visible instead of flattening it
    into a list.
    """
    if not path:
        return dict(DEFAULT_IDENTITY)
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"could not read the identity file {path}: {exc}") from None
    merged = dict(DEFAULT_IDENTITY)
    primary = str(raw.get("primary", "")).strip()
    if primary:
        merged["company"] = primary
        merged["copyright"] = "(c) " + primary
    secondary = [str(s).strip() for s in raw.get("secondary", []) if str(s).strip()]
    if secondary:
        merged["trademarks"] = "  ".join(secondary)
    for key in ("product", "version", "description"):
        if raw.get(key):
            merged[key] = str(raw[key])
    return merged


def write_version_file(identity: dict, target: str) -> str:
    """Write the VSVersionInfo that PyInstaller reads with --version-file.

    Every value goes in through json.dumps, which yields an ASCII-safe quoted literal -- so a
    name with a quote, a backslash or a character outside ASCII cannot break the file it is
    being written into.
    """
    ver = identity["version"]
    parts = [int(n) for n in (ver.split(".") + ["0", "0", "0", "0"])[:4] if n.isdigit()] or [1, 0, 0, 0]
    while len(parts) < 4:
        parts.append(0)
    quad = "(" + ", ".join(str(n) for n in parts) + ")"
    fields = [
        ("CompanyName", identity["company"]),
        ("FileDescription", identity["description"]),
        ("FileVersion", ver),
        ("LegalCopyright", identity["copyright"]),
        ("LegalTrademarks", identity["trademarks"]),
        ("OriginalFilename", os.path.basename(target)),
        ("ProductName", identity["product"]),
        ("ProductVersion", ver),
    ]
    rows = ("," + chr(10)).join("            StringStruct(%s, %s)" % (json.dumps(k), json.dumps(v))
                        for k, v in fields)
    NL = chr(10)
    text = (
        "VSVersionInfo(" + NL
        + "  ffi=FixedFileInfo(filevers=" + quad + ", prodvers=" + quad + "," + NL
        + "                    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0," + NL
        + "                    date=(0, 0))," + NL
        + "  kids=[" + NL
        + "    StringFileInfo([StringTable('040904B0', [" + NL
        + rows + NL
        + "        ])])," + NL
        + "    VarFileInfo([VarStruct('Translation', [1033, 1200])])" + NL
        + "  ]" + NL
        + ")" + NL
    )
    out = Path(target)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="ascii")
    return str(out)


def pyinstaller_version(python: str) -> str:
    proc = subprocess.run(
        [python, "-c", "import PyInstaller; print(PyInstaller.__version__)"],
        capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(
            f"PyInstaller is not available to {python}.\n"
            f"Install it there (  \"{python}\" -m pip install pyinstaller  ), or point --python at an "
            f"interpreter that has it.")
    return proc.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the OnlySign executable.")
    parser.add_argument("--python", default=sys.executable,
                        help="the interpreter that has PyInstaller")
    parser.add_argument("--console", action="store_true",
                        help="keep a console -- the build that can be tested")
    parser.add_argument("--icon", default=os.path.join(ROOT, "mark", "onlysign.ico"),
                        help="the .ico to use; the one in mark/ by default")
    parser.add_argument("--no-icon", action="store_true", help="build without an icon")
    parser.add_argument("--name", default="OnlySign")
    parser.add_argument(
        "--identity", default="",
        help="a local JSON file naming who the build belongs to; without one the build "
             "stays generic, as the published tool is")
    parser.add_argument("--out", default=os.path.join(ROOT, "dist"),
                        help="where the built executable goes; made absolute before use")
    parser.add_argument("--keep-work", action="store_true")
    args = parser.parse_args(argv)

    version = pyinstaller_version(args.python)
    print(f"PyInstaller {version} under {args.python}")

    args.out = os.path.abspath(args.out)
    work = tempfile.mkdtemp(prefix="onlysign-build-")
    arguments = [
        args.python, "-m", "PyInstaller", "--noconfirm", "--onefile",
        "--name", args.name,
        "--distpath", args.out,
        "--workpath", os.path.join(work, "work"),
        "--specpath", work,
    ]
    arguments.append("--console" if args.console else "--windowed")
    # The notice travels inside the build. Its mark is content, not code, so it is a data file --
    # and a packaged tool that could not introduce itself would be a worse tool than the checkout.
    for extra in (os.path.join(ROOT, "NOTICE.txt"),
                  os.path.join(ROOT, "mark", "onlysign-256.png")):
        if os.path.isfile(extra):
            # The notice's text, and the mark the About window shows in colour. Both are content,
            # so both travel as data rather than being written into the code.
            arguments += ["--add-data", extra + os.pathsep + os.path.relpath(os.path.dirname(extra), ROOT)
                          if extra.endswith(".png") else extra + os.pathsep + "."]
        else:
            print(f"note: {os.path.basename(extra)} is missing; the build will go without it")
    if args.no_icon:
        args.icon = ""
    font_dir = os.path.join(ROOT, "mark", "fonts")
    if os.path.isdir(font_dir):
        # The typeface travels as data too, and is registered for this process only when it runs.
        arguments += ["--add-data", font_dir + os.pathsep + os.path.join("mark", "fonts")]
    identity = identity_from(args.identity or os.path.join(ROOT, "IDENTITY.local.json"))
    version_file = write_version_file(identity, os.path.join(ROOT, "build", "version_info.txt"))
    arguments += ["--version-file", version_file]
    # The copyright belongs in the file, not only beside it: somebody who opens the properties of
    # the executable should see whose work it is without having to find a notice next to it.
    print(f"  version resource: company={identity['company']!r} trademarks={identity['trademarks']!r}")
    if args.icon:
        # Absolute, because PyInstaller resolves a relative icon path against the spec directory it
        # was handed -- which lives in the temp work area -- and not against where the build was
        # started. A relative path here fails with 'icon input file not found' and the path it names
        # is one nobody typed.
        icon = os.path.abspath(args.icon)
        if not os.path.isfile(icon):
            raise SystemExit(f"no icon at {args.icon}  (looked in {icon})")
        arguments += ["--icon", icon]
    arguments.append(ENTRY)

    print("building (this takes a minute) ...")
    proc = subprocess.run(arguments, cwd=ROOT)
    if proc.returncode != 0:
        raise SystemExit(f"PyInstaller exited {proc.returncode}")

    suffix = ".exe" if os.name == "nt" else ""
    built = os.path.join(args.out, args.name + suffix)
    if not os.path.isfile(built):
        raise SystemExit(f"PyInstaller reported success and {built} is not there")
    print(f"\nbuilt {built}  ({os.path.getsize(built) / 1048576:.1f} MB)")
    if not args.console:
        print("This build has no console, so it cannot print. To check one, build with --console "
              "and run 'OnlySign.exe scan --help'.")
    if not args.keep_work:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    else:
        print(f"work directory kept at {work}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
