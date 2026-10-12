"""The gate that travels with a signed package.

When somebody pulls a package that was signed here, this is what they meet: a notice saying who
made the tool, and one question before anything is installed. The notice is a claim -- "this tool
was developed by somebody" -- and a claim is worth nothing unless the signature behind it is
checked, so the gate checks it first and refuses when it does not hold. A gate that printed the
notice anyway would be a forger's best friend: copy the text, ship malware, keep the notice.

What the gate checks is the **signature the file carries**, not the verdict Windows gives. That
distinction matters more here than anywhere else in this project: these packages are signed with a
self-signed certificate, so on a stranger's machine the chain terminates nowhere and
``Get-AuthenticodeSignature`` reports no valid signature even when the signature is perfectly good
and belongs to the right identity. Judging by the verdict would make every honest package look
forged. So the signer's thumbprint is read out of the file itself and compared with the one pinned
when the gate was written, and the verdict is *reported* beside it rather than trusted.

The gate is three small files and one text file beside the artifact:

    Install.cmd      what a person double-clicks or types; ASCII, because a .cmd is read as ANSI
    Install.ps1      the logic; ASCII only, which is not a style choice -- see below
    Install.target   the artifact's file name, in UTF-8, so a name that is not ASCII is safe
    NOTICE.txt       the notice itself, as content, so it can be edited without touching code

The ``.ps1`` is deliberately free of non-ASCII characters. Windows PowerShell reads a script with no
byte order mark using the machine's ANSI code page, so a script containing a Chinese character can
be misread before it runs -- and one of the packages this is for has a Chinese name. Keeping the
script ASCII and carrying every name in a UTF-8 sidecar removes the possibility rather than
remembering to avoid it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable

from .. import phrases
from ..notice import prompt as notice_prompt
from ..notice import source as notice_source
from ..notice import text as notice_text
from . import signer

NOTICE_FILE = "NOTICE.txt"
TARGET_FILE = "Install.target"
SCRIPT_FILE = "Install.ps1"
COMMAND_FILE = "Install.cmd"
SHELL_FILE = "Install.sh"
PROMPT_FILE = "Install.prompt.txt"
PHRASE_FILE = "Install.phrases.txt"

# The question itself lives in notice.PROMPTS, in every language the tool speaks, and is written
# beside the notice as UTF-8 rather than into the script.


# The same gate for anybody whose shell is not cmd. A .cmd cannot be run by bash at all, and
# MSYS2, WSL, Tabby, WezTerm and Windows Terminal all hand the job to a shell that is not cmd --
# so the door has to exist in a form those can open. ASCII, like the script it calls, and it does
# nothing except find the PowerShell and hand it the same file the .cmd does.
_SHELL = """#!/bin/sh
# The gate that travels with this package, for sh-compatible shells.
here=$(dirname "$0")
for ps in powershell.exe pwsh.exe; do
    if command -v "$ps" >/dev/null 2>&1; then
        exec "$ps" -NoProfile -ExecutionPolicy Bypass -File "$here/{script}" "$@"
    fi
done
echo "This package needs PowerShell, and neither powershell.exe nor pwsh.exe was found." >&2
exit 1
"""

_COMMAND = """@echo off
rem The gate that travels with this package. Double-click it, or run it in a console.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0{script}" %*
echo.
pause
"""

_SCRIPT = r"""# Install.ps1 -- checked before it is believed.
#
# ASCII only, on purpose: Windows PowerShell reads a script with no byte order mark using the
# machine's ANSI code page, and the names this script handles are not always ASCII. Every name
# arrives from a UTF-8 sidecar file instead of being written into the script.
$ErrorActionPreference = 'Stop'
# Windows PowerShell resolves a module by walking PSModulePath in order and taking the first
# directory that holds it. A PowerShell 7 session exports its own module directories at the front of
# that variable, so a script running under the older PowerShell that ships with Windows loads
# version 7's binary modules, fails, and discovers that Get-AuthenticodeSignature below simply does
# not exist. A gate that cannot check anything would then refuse every package -- or, worse, be
# edited to stop checking. Narrowing the path to this PowerShell's own modules is the whole fix.
$env:PSModulePath = (Join-Path $PSHOME 'Modules')
# Only when the output is going somewhere other than a console. Write-Host to a real console goes
# through the console API and is Unicode-safe already, whereas a redirected stream is encoded with
# the machine's code page -- which would turn the mark in the notice into question marks. The
# check keeps this from changing the code page of somebody's console window as a side effect.
if ([Console]::IsOutputRedirected) { [Console]::OutputEncoding = [Text.Encoding]::UTF8 }
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExpectedThumbprint = '__THUMBPRINT__'
$Developer = '__DEVELOPER__'

function Read-Utf8Text([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    return (Get-Content -LiteralPath $path -Raw -Encoding UTF8)
}

# Every line this script says travels in a UTF-8 sidecar, keyed by name, because the script itself
# has to stay ASCII. The English here is the fallback, so a missing sidecar costs the translation and
# never the sentence.
$phrases = @{}
foreach ($line in (Read-Utf8Text (Join-Path $here '__PHRASES__')).Split([char]10)) {
    $trimmed = $line.Trim()
    if (-not $trimmed) { continue }
    $cut = $trimmed.IndexOf('=')
    if ($cut -lt 1) { continue }
    $phrases[$trimmed.Substring(0, $cut).Trim()] = $trimmed.Substring($cut + 1).Trim()
}
function P([string]$key, [string]$fallback) {
    if ($phrases.ContainsKey($key)) { return $phrases[$key] }
    return $fallback
}

$targetName = (Read-Utf8Text (Join-Path $here '__TARGET__')).Trim()
$artifact = Join-Path $here $targetName
$notice = (Read-Utf8Text (Join-Path $here '__NOTICE__')).TrimEnd()
$question = (Read-Utf8Text (Join-Path $here '__PROMPT__')).TrimEnd()
if (-not $question) { $question = 'To proceed with installation? (Y/N)' }

Write-Host ''
if (-not (Test-Path -LiteralPath $artifact)) {
    Write-Host (P 'incomplete' 'This package is incomplete: the file it installs is not beside this script.') -ForegroundColor Red
    Write-Host ((P 'expected' '  expected: ') + $artifact)
    exit 2
}

# The signature the file carries. Read from the file, so that a catalog entry or an untrusted root
# cannot answer a different question than the one being asked.
$carried = ''
try {
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromSignedFile($artifact)
    $carried = $certificate.GetCertHashString()
} catch {
    $carried = ''
}
$verdict = Get-AuthenticodeSignature -LiteralPath $artifact
$stamped = [bool]$verdict.TimeStamperCertificate

Write-Host ((P 'package' 'package : ') + $targetName)
Write-Host ((P 'signer' 'signer  : ') + $(if ($carried) { $carried } else { (P 'signer_none' 'nothing -- the file carries no signature') }))
if ($carried) {
    Write-Host (P 'carried_note' 'read from the file itself, so a catalog entry cannot answer for it')
    Write-Host ((P 'stamped' 'stamped : ') + $(if ($stamped) { (P 'stamped_yes' 'yes') } else { (P 'stamped_no' 'no') }))
    Write-Host ((P 'verdict' 'verdict : ') + $verdict.Status)
    # Printed, and labelled, because it does not always answer about the line above. Get-AuthenticodeSignature
    # consults the machine's security catalogs, so a file whose own signature belongs to nobody
    # trusted can still come back Valid -- because a catalog says Microsoft signed it. That is not a
    # theoretical hazard: it is what this file did the first time the gate was run against it.
    Write-Host (P 'verdict_note_a' '          what Windows says about this file, catalogs included.')
    Write-Host (P 'verdict_note_b' '          It can answer about a different signature than the one above.')
    if ($verdict.Status -ne 'Valid') {
        Write-Host (P 'selfsigned_a' '          A self-signed certificate is its own root.')
        Write-Host (P 'selfsigned_b' '          The check below does not depend on that.')
    }
}
Write-Host ''

if (-not $carried) {
    Write-Host (P 'no_signature_a' 'This package carries no signature.') -ForegroundColor Red
    Write-Host (P 'no_signature_b' 'Installation was not started.') -ForegroundColor Red
    exit 1
}
if ($ExpectedThumbprint -and ($carried -ne $ExpectedThumbprint)) {
    Write-Host (P 'wrong_a' 'This package is NOT signed by the identity it claims.') -ForegroundColor Red
    Write-Host ((P 'wrong_expected' '  expected: ') + $ExpectedThumbprint)
    Write-Host ((P 'wrong_found' '  found   : ') + $carried)
    Write-Host (P 'wrong_b' 'Installation was not started.') -ForegroundColor Red
    exit 1
}
if ($ExpectedThumbprint -and -not $stamped) {
    Write-Host (P 'no_timestamp_a' 'The signature carries no timestamp.') -ForegroundColor Yellow
    Write-Host (P 'no_timestamp_b' 'Installation was not started.') -ForegroundColor Yellow
    exit 1
}

if ($notice) {
    Write-Host $notice
} else {
    Write-Host ("This tool was developed by " + $Developer + ".")
}
Write-Host ''

$answer = ''
if ($args -contains '-Yes' -or $args -contains '--yes') {
    # The consent is still given by a person; it was given when they typed the flag.
    $answer = 'y'
    Write-Host ($question + ' Y' + (P 'answered_cli' '   [answered on the command line]'))
} else {
    $tries = 0
    while ($tries -lt 10) {
        Write-Host ($question + ' ') -NoNewline
        $line = [Console]::In.ReadLine()
        if ($null -eq $line) { break }          # nobody is there to consent
        $answer = $line.Trim().ToLower()
        if ($answer -eq 'y' -or $answer -eq 'yes') { break }
        if ($answer -eq 'n' -or $answer -eq 'no') { break }
        Write-Host (P 'answer_again' 'Please answer Y or N.')
        $answer = ''
        $tries++
    }
}

if ($answer -ne 'y' -and $answer -ne 'yes') {
    Write-Host ''
    Write-Host (P 'not_started' 'Installation was not started.')
    exit 0
}

Write-Host ''
Write-Host (P 'starting' 'Starting the installer...')
Start-Process -FilePath $artifact
exit 0
"""


@dataclass
class Gate:
    artifact: str
    directory: str
    thumbprint: str
    developer: str = "its publisher"
    notice: str = ""

    def paths(self) -> dict[str, str]:
        return {
            "command": os.path.join(self.directory, COMMAND_FILE),
            "shell": os.path.join(self.directory, SHELL_FILE),
            "script": os.path.join(self.directory, SCRIPT_FILE),
            "target": os.path.join(self.directory, TARGET_FILE),
            "notice": os.path.join(self.directory, NOTICE_FILE),
            "prompt": os.path.join(self.directory, PROMPT_FILE),
            "phrases": os.path.join(self.directory, PHRASE_FILE),
        }


def _check_ascii(text: str, what: str) -> None:
    """Refuse to write a script that a machine could misread.

    This is the same trap as the ledger's, one level up: a PowerShell script with no byte order mark
    is decoded using the machine's ANSI code page, so a non-ASCII character inside it can make the
    file fail to parse before a single line runs. Checking here means the failure happens where it
    can be explained, rather than on a stranger's machine where it cannot.
    """
    offending = [(index, character) for index, character in enumerate(text) if ord(character) > 127]
    if offending:
        index, character = offending[0]
        raise ValueError(
            f"{what} would contain a character a Windows PowerShell script cannot safely carry "
            f"({character!r} at position {index}); keep it ASCII and put names in {TARGET_FILE}")


def emit(artifact: str, *, thumbprint: str, directory: str = "", developer: str = "its publisher",
         notice: str | None = None, language: str = "") -> Gate:
    """Write the gate beside the artifact it guards."""
    artifact = os.path.abspath(artifact)
    if not os.path.isfile(artifact):
        raise FileNotFoundError(artifact)
    directory = os.path.abspath(directory or os.path.dirname(artifact))
    os.makedirs(directory, exist_ok=True)

    gate = Gate(artifact=artifact, directory=directory, thumbprint=thumbprint.upper(),
                developer=developer, notice=notice_text(language) if notice is None else notice)

    name = os.path.basename(artifact)
    script = (_SCRIPT
              .replace("__THUMBPRINT__", gate.thumbprint)
              .replace("__DEVELOPER__", developer)
              .replace("__TARGET__", TARGET_FILE)
              .replace("__NOTICE__", NOTICE_FILE)
              .replace("__PROMPT__", PROMPT_FILE)
              .replace("__PHRASES__", PHRASE_FILE))
    command = _COMMAND.replace("{script}", SCRIPT_FILE)
    shell_script = _SHELL.replace("{script}", SCRIPT_FILE)

    _check_ascii(script, SCRIPT_FILE)
    _check_ascii(command, COMMAND_FILE)
    _check_ascii(shell_script, SHELL_FILE)

    paths = gate.paths()
    with open(paths["script"], "w", encoding="utf-8", newline="\r\n") as handle:
        handle.write(script)
    with open(paths["command"], "w", encoding="ascii", newline="\r\n") as handle:
        handle.write(command)
    # LF, because sh reads this one and a CR would end up inside the interpreter name.
    with open(paths["shell"], "w", encoding="ascii", newline=chr(10)) as handle:
        handle.write(shell_script)
    # The name travels in UTF-8, so a package called 修改器-安装程序.exe is not a problem for a
    # script that has to stay ASCII.
    with open(paths["target"], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(name + "\n")
    with open(paths["notice"], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(gate.notice)
    # The question travels beside the notice, in UTF-8, for the same reason the file name does: the
    # script cannot carry it. A Japanese question written into an ASCII script is a question that
    # arrives as mojibake, and a prompt nobody can read is not consent.
    with open(paths["prompt"], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(notice_prompt(language) + "\n")
    # And everything else the script says -- the labels, the refusals, the closing line -- keyed by
    # name, for the same reason. The session a person walks through is in one language throughout,
    # not a translated notice followed by an English refusal.
    with open(paths["phrases"], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(phrases.sidecar(language))
    return gate


def describe(gate: Gate) -> Iterable[str]:
    yield f"the gate was written beside {os.path.basename(gate.artifact)}"
    yield f"  it pins the signer to {gate.thumbprint}"
    yield f"  a person runs {COMMAND_FILE}, reads the notice, and answers one question"
    yield f"  the notice came from {notice_source()}"
    for key, path in gate.paths().items():
        yield f"  {key:<8} {path}"


def check(artifact: str, *, thumbprint: str = "") -> tuple[bool, list[str]]:
    """Whether this artifact would get past its own gate. Used by the tests, and by `sign`."""
    lines: list[str] = []
    own = signer.own_signature(artifact)
    if not own.present:
        lines.append("the file carries no signature")
        return False, lines
    lines.append(f"carried signer: {own.thumbprint}")
    if not own.timestamped:
        lines.append("the signature carries no timestamp")
        return False, lines
    lines.append("timestamp: present")
    if thumbprint and own.thumbprint.upper() != thumbprint.replace(" ", "").upper():
        lines.append(f"expected signer: {thumbprint}")
        return False, lines
    lines.append("the signer is the one that will be pinned")
    return True, lines
