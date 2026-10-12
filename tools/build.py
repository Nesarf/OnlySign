"""Building the one-file executable.

    python tools/build.py                        the window, no console
    python tools/build.py --console              the same, but with a console -- for checking
    python tools/build.py --icon path\\to.ico

PyInstaller is the only thing this needs, and it is not a dependency of the tool: it is a dependency
of *building the tool*. The Python it runs under is `--python` (the interpreter running this script
by default), so a machine that keeps a packaging environment separate can point at it.

There is no icon by default. An icon is identity, and this tool ships without an identity of its own
-- putting someone's mark on a general-purpose tool is a decision for whoever owns the mark, not one
for a build script to make quietly. `--icon` is how that decision gets expressed.

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
    parser.add_argument("--icon", default="", help="an .ico to use; none by default")
    parser.add_argument("--name", default="OnlySign")
    parser.add_argument("--out", default=os.path.join(ROOT, "dist"))
    parser.add_argument("--keep-work", action="store_true")
    args = parser.parse_args(argv)

    version = pyinstaller_version(args.python)
    print(f"PyInstaller {version} under {args.python}")

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
    notice_file = os.path.join(ROOT, "NOTICE.txt")
    if os.path.isfile(notice_file):
        arguments += ["--add-data", notice_file + os.pathsep + "."]
    else:
        print("note: NOTICE.txt is missing, so the build will carry the notice without its mark")
    if args.icon:
        if not os.path.isfile(args.icon):
            raise SystemExit(f"no icon at {args.icon}")
        arguments += ["--icon", args.icon]
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
