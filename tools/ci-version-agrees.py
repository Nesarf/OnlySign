"""The version is declared once and everything agrees with it.

Run by CI on every change, and runnable by hand. It exists because this repository had the version
written in three places and two of them disagreed: the binaries said 1.0.0 while `pyproject.toml` said
0.1.0. The fix was a guard in `tools/build.py` plus a check in the self-test, and both only run when
somebody actually builds -- so a change to metadata alone could reintroduce the drift and nothing would
notice until a release.

What is compared:

* `pyproject.toml`'s `version`, which is the one that goes into a distributable package
* `IDENTITY.local.json`'s `version`, when that file is present, which is where the executable and the
  installer read their version from

`IDENTITY.local.json` is gitignored, so on a fresh clone -- and in CI -- it is absent. That is not a
failure: the published state has one number and no second one to disagree with. It says so and exits 0.

    python tools/ci-version-agrees.py
"""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main() -> int:
    pyproject = ROOT / "pyproject.toml"
    if not pyproject.is_file():
        print(f"::error::no {pyproject}")
        return 1
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    print(f"pyproject.toml declares : {declared}")

    identity = ROOT / "IDENTITY.local.json"
    if not identity.is_file():
        print("IDENTITY.local.json    : absent (gitignored)")
        print("one number, nothing to disagree with -- the published state")
        return 0

    try:
        published = str(json.loads(identity.read_text(encoding="utf-8")).get("version", "")).strip()
    except ValueError as exc:
        print(f"::error::IDENTITY.local.json is not valid JSON: {exc}")
        return 1
    print(f"IDENTITY.local.json says: {published}")

    if not published:
        print("::error::IDENTITY.local.json carries no version")
        return 1
    if published != declared:
        # The workflow turns this into an annotation; the message is written to be read on its own too.
        print(f"::error::the version disagrees: pyproject.toml says {declared}, "
              f"the identity says {published}")
        return 1
    print("they agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
