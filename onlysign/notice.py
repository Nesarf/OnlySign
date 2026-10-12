"""The notice a tool introduces itself with.

One text, used in two places: the gate that travels with a signed package, and this tool's own
command line when somebody runs it by hand. The precedent is a terminal-invoked agent that opens
with a mark and a copyright line; the reason is the same in both cases -- a person who typed a
command is owed a sentence about what they just ran and who made it, before it does anything.

The text lives in a file rather than in code, because it is content. A mark drawn in characters is
meant to be edited by hand if a console turns out to be narrower than expected, and none of that
belongs in a string literal. It is read as UTF-8 explicitly, since the file may carry characters
that the machine's ANSI code page would mangle -- the same trap the ledger taught, one level up.

Four file names, and the order between them is the point:

    NOTICE.local.zh.txt / NOTICE.local.en.txt   somebody's own notice, in one language
    NOTICE.local.txt                            somebody's own notice, in either
    NOTICE.zh.txt / NOTICE.en.txt               what the repository ships, in one language
    NOTICE.txt                                  what the repository ships

A notice names who made the tool. That is an identity, and an identity should not have to be
published in order to be used: an organisation can keep its own notices beside its checkout, marked
ignored, while the repository ships a placeholder that belongs to nobody. The same arrangement lets
one person run two identities on one machine.

Every local name is tried before every shipped name, so a real notice is never shadowed by a
placeholder just because the language matched. Within that, the requested language wins: somebody who
asks for Chinese gets a Chinese notice if one exists anywhere, and only then falls back.

Where it is looked for: beside the package, inside the bundle (a frozen build), then beside the
executable. Finally the compiled-in fallback, which is the same sentence without the mark. A missing
file costs the drawing, never the sentence.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

NOTICE_FILE = "NOTICE.txt"
LOCAL_FILE = "NOTICE.local.txt"

LANGUAGES = ("en", "zh", "ja")
DEFAULT_LANGUAGE = "en"
LANGUAGE_ENVIRONMENT = "ONLYSIGN_LANG"

PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FALLBACK = (
    "This tool was developed by its publisher.\n"
    "In the event of any issues whilst using the tool, you may contact the repository "
    "administrator. Alternatively, you may resolve the issue yourself.\n"
)

FALLBACK_ZH = (
    "本工具由其发布者主持开发。\n"
    "如果您在使用过程中出现问题，请与仓库管理员联系——您也可以选择自行解决。\n"
)

FALLBACK_JA = (
    "このツールはその配布者によって開発されました。\n"
    "ツール使用中に問題が発生した場合は、リポジトリ管理者に連絡してください。"
    "あるいは、ご自身で問題を解決することも可能です。\n"
)

# The one question the gate asks, in each language. It lives here rather than inside the generated
# script because that script has to stay ASCII: Windows PowerShell decodes a .ps1 with no byte order
# mark using the machine's ANSI code page, so a Japanese question written into it would be mangled
# before it ever ran. The gate writes this to a UTF-8 sidecar and reads it back.
PROMPTS = {
    "en": "To proceed with installation? (Y/N) ",
    "zh": "确定安装么？（Y/N）",
    "ja": "インストールを続行しますか？ (Y/N)",
}


def prompt(language: str = "") -> str:
    return PROMPTS.get(language, PROMPTS["en"])

_cached: dict[str, tuple[str, str]] = {}


def language(explicit: str = "") -> str:
    """Which language to speak, from the argument, the environment, or the default.

    Deliberately not from the system locale: a tool that changes language because of where it is
    installed is a tool whose output cannot be predicted by the person running it. Being told is
    better than guessing.
    """
    for candidate in (explicit, os.environ.get(LANGUAGE_ENVIRONMENT, "")):
        wanted = (candidate or "").strip().lower()
        for code in LANGUAGES:
            if wanted.startswith(code):
                return code
        # Chinese arrives written three ways, and none of them is "zh" in a person's head.
        if wanted.startswith("cn") or wanted.startswith("chinese"):
            return "zh"
        if wanted.startswith("jp") or wanted.startswith("japanese"):
            return "ja"
    return DEFAULT_LANGUAGE


def _directories() -> list[str]:
    places = [PACKAGE_ROOT]
    bundled = getattr(sys, "_MEIPASS", "")          # PyInstaller unpacks --add-data here
    if bundled:
        places.append(bundled)
    if getattr(sys, "frozen", False):
        places.append(os.path.dirname(sys.executable))
    return places


def _candidates(spoken: str) -> list[str]:
    stem_locals = [f"NOTICE.local.{spoken}.txt", LOCAL_FILE]
    stem_shipped = [f"NOTICE.{spoken}.txt", NOTICE_FILE]
    return [os.path.join(where, name) for name in stem_locals + stem_shipped
            for where in _directories()]


def text(spoken: str = "") -> str:
    """The notice, with the mark when the file is there and without it when it is not."""
    spoken = language(spoken)
    if spoken in _cached:
        return _cached[spoken][0]
    for path in _candidates(spoken):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                loaded = handle.read()
        except OSError:
            continue
        if loaded.strip():
            body = loaded if loaded.endswith("\n") else loaded + "\n"
            _cached[spoken] = (body, path)
            return body
    # Nothing on disk in that language, so say it from the code rather than say nothing.
    body = {"zh": FALLBACK_ZH, "ja": FALLBACK_JA}.get(spoken, FALLBACK)
    _cached[spoken] = (body, "")
    return body


def source(spoken: str = "") -> str:
    """Where the notice came from, so that "the mark travelled with the build" is checkable rather
    than assumed -- an empty answer means the compiled-in copy without the mark was used."""
    spoken = language(spoken)
    text(spoken)
    return _cached[spoken][1] or "built in, without the mark"


def interactive(stream: TextIO | None = None) -> bool:
    """Whether a person is watching, rather than a pipe or a file."""
    stream = stream if stream is not None else sys.stdout
    if stream is None:                              # a windowed build has no stdout at all
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def show(stream: TextIO | None = None, *, quiet: bool = False, spoken: str = "") -> None:
    """Print the notice, unless this is not a person or they asked for silence."""
    stream = stream if stream is not None else sys.stdout
    if quiet or stream is None or not interactive(stream):
        return
    stream.write(text(spoken))
    stream.write("\n")
