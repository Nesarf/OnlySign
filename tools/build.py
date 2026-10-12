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
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY = os.path.join(ROOT, "OnlySign.py")


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
