"""The one place that talks to Windows.

Everything this tool asks the operating system to do goes through here. Two traps cost a session on
the machine this was written on, and both are fixed structurally rather than remembered:

**A script that has to be decoded is a script that can be misdecoded.** Windows PowerShell reads a
``.ps1`` with no byte order mark using the machine's ANSI code page. A script containing anything
outside ASCII is then misread before it runs, and if the last character of a string is one whose
tail byte pairs with the closing quote, the file does not parse at all. Scripts here are therefore
never written to disk: they travel as ``-EncodedCommand`` -- base64 of UTF-16LE -- which is ASCII by
construction and decoded by PowerShell as UTF-16. A path with a Chinese character in it is not
merely tolerated; the ambiguity does not exist.

**A module that cannot be found is not an error you get to see.** PowerShell resolves a module by
walking ``PSModulePath`` in order and taking the first directory that holds it. A PowerShell 7
session exports its own module directories at the front of that variable, so a 5.1 child started
from there loads version 7's binary modules, fails, and ``Set-AuthenticodeSignature`` -- which lives
in ``Microsoft.PowerShell.Security`` -- simply ceases to exist. The child is handed a clean
``PSModulePath`` here, which is the whole fix.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import subprocess
from typing import Any

_SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
_WINDOWS_POWERSHELL = os.path.join(_SYSTEM_ROOT, "System32", "WindowsPowerShell", "v1.0")

POWERSHELL = os.path.join(_WINDOWS_POWERSHELL, "powershell.exe")

# Exactly the module directory of the Windows PowerShell that ships with Windows, and nothing else.
OWN_MODULES = os.path.join(_WINDOWS_POWERSHELL, "Modules")

_PREAMBLE = (
    # Without this, a redirected stdout is written in the OEM code page and a path with a Chinese
    # character in it comes back as mojibake that looks like a file that is not there.
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n"
    "$OutputEncoding = [Text.Encoding]::UTF8\n"
    "$ProgressPreference = 'SilentlyContinue'\n"
)

DEFAULT_TIMEOUT = 300.0


class PowerShellError(RuntimeError):
    """PowerShell refused to run, or ran and said no in a way this module could not parse."""

    def __init__(self, message: str, *, stdout: str = "", stderr: str = "", returncode: int | None = None):
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def literal(value: Any) -> str:
    """A value as a PowerShell single-quoted string literal.

    Inside single quotes only the single quote itself has meaning, and doubling it is the entire
    escaping rule. This is what makes it safe to build a script as text: every value that came from
    a person -- a path, a note, a certificate subject -- passes through here.
    """
    return "'" + str(value).replace("'", "''") + "'"


def available() -> bool:
    return os.path.isfile(POWERSHELL)


def run(script: str, *, timeout: float = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
    """Run a PowerShell script and hand back the finished process."""
    if not available():
        raise PowerShellError(f"no Windows PowerShell at {POWERSHELL}")
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ)
    env["PSModulePath"] = OWN_MODULES
    try:
        proc = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", encoded],
            capture_output=True, env=env, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise PowerShellError(f"PowerShell did not finish within {timeout:g}s") from exc
    return subprocess.CompletedProcess(
        proc.args, proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def call(body: str, *, timeout: float = DEFAULT_TIMEOUT, depth: int = 8) -> Any:
    """Run a script whose value is the answer, and return it.

    The envelope is deliberate: the script reports ``ok`` and either ``value`` or ``error``, so a
    failure is a value this function can describe rather than a return code it has to guess about.
    """
    script = (
        _PREAMBLE
        + "$ErrorActionPreference = 'Stop'\n"
        + "try {\n"
        + "  $OnlySignValue = & {\n" + body + "\n  }\n"
        + f"  @{{ ok = $true; value = $OnlySignValue }} | ConvertTo-Json -Depth {depth:d} -Compress\n"
        + "} catch {\n"
        + "  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress\n"
        + "}\n"
    )
    proc = run(script, timeout=timeout)

    payload = None
    for line in reversed(proc.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if isinstance(payload, dict) and "ok" in payload:
            break
        payload = None
    if payload is None:
        detail = (proc.stderr or proc.stdout).strip()[:600]
        raise PowerShellError(
            f"PowerShell produced no answer (exit {proc.returncode}): {detail}",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode)
    if not payload.get("ok"):
        raise PowerShellError(str(payload.get("error", "PowerShell reported a failure")),
                              stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode)

    # Always a list, because "the value of a script" is not a well-defined shape in PowerShell: a
    # script that writes one line has a string as its value, and a caller doing the natural thing
    # with it -- `for line in ps.call(...)` -- silently walks the characters of that string instead
    # of the lines it expected. That is not hypothetical; it produced a column of single letters
    # during this project. Scripts that want one object use one().
    value = payload.get("value")
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def one(body: str, *, timeout: float = DEFAULT_TIMEOUT) -> Any:
    """``call`` for a script that yields a single object, unwrapped from the one-element list."""
    value = call(body, timeout=timeout)
    if isinstance(value, list):
        return value[0] if value else None
    return value
