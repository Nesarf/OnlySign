"""Finding the artifacts in a project, and being able to say how each one was found.

A scanner that hands back a list of paths is not much use, because the person looking at the list
has no way to judge it. Every candidate here carries the reason it was proposed -- "this directory
is named dist", "this file is named in package.json's electron-builder output", "the workflow
uploads it as an artifact" -- so a wrong entry can be argued with instead of merely distrusted.

Four layers, tried in order, each adding candidates rather than replacing them:

1. **the directory you gave**, if you gave one -- it is taken at its word;
2. **directories that are named like an output directory**, wherever they appear in the tree;
3. **build files that declare where their output goes**, which is the layer that works on a project
   that has not been built yet, or whose output has been cleaned;
4. **the local object library**, which already knows paths this machine has seen before.

What it deliberately does not do is sign anything. Signing is a statement about who made a file, and
a scanner is not entitled to make that statement on someone's behalf.
"""

from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import pe

# Directory names that mean "the build put something here". Deliberately a list of names rather than
# a guess at a layout: a candidate still has to pass the magic-byte test below to be offered, so a
# `build/` full of object files yields nothing.
OUTPUT_DIRECTORY_NAMES = {
    "dist", "build", "out", "output", "outputs", "publish", "artifacts", "release", "releases",
    "target", "bin", "drop", "package", "packages", "installer", "setup",
}

# Paths that are never worth walking: version control, dependency trees, caches, and this tool's own
# scratch. `target` appears in the output-directory list above and here -- the one below wins for
# traversal, because descending into a Rust target tree looking for build configuration is waste.
NEVER_DESCEND = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache",
    ".pytest_cache", ".gradle", ".idea", ".vs", "obj", "CMakeFiles", ".cache",
}

# Files that declare where a build's output lands. Each entry is (glob, reader); a reader returns
# (path, reason) pairs for the paths it can work out.
_BUILD_FILES = ("*.spec", "*.iss", "*.nsi", "*.csproj", "*.wxs", "Cargo.toml", "package.json",
                "pyproject.toml", "setup.py", "Makefile", "makefile")

MAX_FILES_WALKED = 20000
MAX_CANDIDATES = 500


@dataclass
class Candidate:
    path: str
    kind: str
    size: int
    signed: bool
    reason: str
    source: str
    reasons: list[str] = field(default_factory=list)
    # The same reasons as codes and fields. The strings above are what the command line prints, and
    # they are English because a script reads them; a window has to say them in whatever language it
    # is speaking, so it gets the shape of the sentence rather than the sentence.
    why: list[tuple[str, dict]] = field(default_factory=list)
    selected: bool = True

    def describe(self) -> str:
        state = "signed" if self.signed else "unsigned"
        lines = [f"{os.path.basename(self.path)}  [{pe.describe(self.kind)}, {self.size} bytes, "
                 f"{state}]", f"    {self.path}"]
        # Every reason, not just the first: a path that two layers agree about is a stronger
        # proposal than one only a directory name suggested -- and the reader is the one deciding.
        for reason in (self.reasons or [self.reason]):
            lines.append(f"    found: {reason}")
        return "\n".join(lines)


@dataclass
class Scan:
    repo: str = ""
    candidates: list[Candidate] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # The same notes as codes, for the same reason the candidates carry theirs: the command line
    # prints the sentence, a window has to say it in its own language.
    note_codes: list[tuple[str, dict]] = field(default_factory=list)
    examined: int = 0

    def by_source(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for candidate in self.candidates:
            counts[candidate.source] = counts.get(candidate.source, 0) + 1
        return counts


def scan(repo: str, artifact_dir: str = "", *, library_home: str | None = None,
         budget: int = MAX_FILES_WALKED) -> Scan:
    """Propose the artifacts under a project, each with the reason it was proposed."""
    result = Scan(repo=os.path.abspath(repo) if repo else "")
    if result.repo and not os.path.isdir(result.repo):
        raise NotADirectoryError(f"no such directory: {repo}")

    found: dict[str, list[tuple[str, str]]] = {}   # normalised path -> [(source, reason), ...]
    declared_but_empty: list[str] = []

    def offer(path: str, source: str, reason: str, code: str = "", **fields) -> None:
        try:
            key = os.path.normcase(os.path.abspath(path))
        except OSError:
            return
        found.setdefault(key, []).append((source, reason, code, fields))

    # 1. the directory that was given, taken at its word
    if artifact_dir:
        if os.path.isdir(artifact_dir):
            for path in _walk(artifact_dir, budget):
                offer(path, "given", "it is in the directory you named", "why.given")
        else:
            result.notes.append(f"the artifact directory you named does not exist: {artifact_dir}")
            result.note_codes.append(("note.artifact_dir_missing", {"path": artifact_dir}))

    if result.repo:
        # 2. directories named like an output directory
        for path, container in _in_output_directories(result.repo, budget):
            offer(path, "output-directory",
                  f"it is in a directory named '{os.path.basename(container)}'",
                  "why.output_directory", name=os.path.basename(container))

        # 3. build files that declare where their output goes
        for declared, declaring_file in _from_build_files(result.repo):
            expanded = _expand(result.repo, declared)
            if not expanded:
                # A project that says where its output goes and has nothing there has either not
                # been built or points somewhere else. Saying so is more use than a short list.
                declared_but_empty.append((
                    f"{os.path.relpath(declaring_file, result.repo)} says the output is "
                    f"'{declared}', and there is nothing signable there",
                    ("note.declared_empty",
                     {"file": os.path.relpath(declaring_file, result.repo), "declared": declared})))
            for path in expanded:
                offer(path, "build-config",
                      f"{os.path.relpath(declaring_file, result.repo)} says the output is {declared}",
                      "why.build_config",
                      file=os.path.relpath(declaring_file, result.repo), declared=declared)

        # 4. what this machine already knows about this project
        for path, note, name in _from_library(result.repo, library_home):
            offer(path, "library", note, "why.library", name=name)

    for key, entries in sorted(found.items()):
        path = key
        if not os.path.isfile(path):
            continue
        result.examined += 1
        kind = _kind(path)
        if kind is None:
            continue
        from . import signer
        result.candidates.append(Candidate(
            path=path, kind=kind, size=os.path.getsize(path),
            signed=signer.carries_own_signature(path),
            reason=entries[0][1], source=entries[0][0],
            reasons=[reason for _source, reason, _code, _fields in entries],
            why=[(code, fields) for _source, _reason, code, fields in entries],
        ))
        if len(result.candidates) >= MAX_CANDIDATES:
            result.notes.append(f"stopped at {MAX_CANDIDATES} candidates")
            result.note_codes.append(("note.truncated", {"count": MAX_CANDIDATES}))
            break

    # Deduplicated by the sentence, because the same declared-but-empty path can be reached twice
    # and the fields beside it are a dict, which a set cannot hold.
    already_said: set[str] = set()
    for text, code in sorted(declared_but_empty, key=lambda pair: pair[0]):
        if text in already_said:
            continue
        already_said.add(text)
        result.notes.append(text)
        result.note_codes.append(code)
    result.candidates.sort(key=lambda c: (c.source, c.path))
    if not result.candidates:
        result.notes.append(
            "nothing signable was found. If the project has not been built yet, build it first, or "
            "name the directory the artifacts land in.")
        result.note_codes.append(("note.nothing_signable", {}))
    return result


# --- the layers ---------------------------------------------------------------- #

def _walk(root: str, budget: int) -> list[str]:
    """Every file under root, never descending into the names above, up to a budget."""
    out: list[str] = []
    for current, directories, files in os.walk(root):
        directories[:] = [d for d in directories if d not in NEVER_DESCEND]
        for name in files:
            out.append(os.path.join(current, name))
            if len(out) >= budget:
                return out
    return out


def _in_output_directories(repo: str, budget: int) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen = 0
    for current, directories, files in os.walk(repo):
        directories[:] = [d for d in directories if d not in NEVER_DESCEND]
        # A directory named like an output directory is scanned; its subdirectories are not walked
        # again for the same reason, so `build/` does not turn into `build/tmp/obj/...`.
        if os.path.basename(current).lower() in OUTPUT_DIRECTORY_NAMES:
            for name in files:
                out.append((os.path.join(current, name), current))
                seen += 1
            directories[:] = []
        if seen >= budget:
            break
    return out


def _from_build_files(repo: str) -> list[tuple[str, str]]:
    """Declared output paths, each paired with the file that declared it."""
    out: list[tuple[str, str]] = []
    for current, directories, files in os.walk(repo):
        directories[:] = [d for d in directories if d not in NEVER_DESCEND]
        for name in files:
            full = os.path.join(current, name)
            lowered = name.lower()
            if lowered == "package.json":
                out += _from_package_json(full)
            elif lowered.endswith(".spec"):
                out += _from_pyinstaller_spec(full)
            elif lowered.endswith(".iss"):
                out += _from_inno(full)
            elif lowered.endswith(".nsi"):
                out += _from_nsis(full)
            elif lowered.endswith(".csproj"):
                out += _from_csproj(full)
            elif lowered == "cargo.toml":
                out += [(os.path.join("target", "release"), full)]
            elif lowered in ("pyproject.toml", "setup.py"):
                out += [("dist", full)]
            elif lowered in ("makefile",):
                out += _from_makefile(full)

        # CI configuration is the other place a project writes down where its artifacts go
        workflow_dir = os.path.join(current, ".github", "workflows")
        if os.path.isdir(workflow_dir):
            for entry in os.listdir(workflow_dir):
                if entry.lower().endswith((".yml", ".yaml")):
                    out += _from_workflow(os.path.join(workflow_dir, entry))
    return out


def _expand(repo: str, declared: str) -> list[str]:
    """A declared path is usually a directory, sometimes a file, and often a glob.

    The glob matters more than it looks: a workflow says ``path: dist/*.exe`` far more often than it
    names a file, so a reader that only understands directories would quietly find nothing in the
    place a project most explicitly wrote down where its artifacts go.
    """
    target = declared if os.path.isabs(declared) else os.path.join(repo, declared)
    if any(character in declared for character in "*?["):
        matches = glob.glob(target, recursive=True)
        out: list[str] = []
        for match in matches:
            out += _walk(match, 500) if os.path.isdir(match) else [match]
        return out
    if os.path.isdir(target):
        return _walk(target, 2000)
    if os.path.isfile(target):
        return [target]
    return []


def _read(path: str, limit: int = 400_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _from_package_json(path: str) -> list[tuple[str, str]]:
    text = _read(path)
    out: list[tuple[str, str]] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    build = data.get("build")
    if isinstance(build, dict):
        directories = build.get("directories")
        if isinstance(directories, dict) and directories.get("output"):
            out.append((str(directories["output"]), path))
        for key in ("win", "mac", "linux"):
            target = build.get(key)
            if isinstance(target, dict) and target.get("target"):
                out.append((str(build.get("directories", {}).get("output", "dist")), path))
    for key in ("pkg", "nexe", "scripts"):
        block = data.get(key)
        if isinstance(block, str) and re.search(r"--out\b|(^|\s)-o\s", block):
            match = re.search(r"--out(?:dir)?[= ]([^\s]+)", block)
            if match:
                out.append((match.group(1), path))
        elif isinstance(block, dict):
            for command in block.values():
                if isinstance(command, str):
                    match = re.search(r"--out(?:dir)?[= ]([^\s]+)", command)
                    if match:
                        out.append((match.group(1), path))
    return out


def _from_pyinstaller_spec(path: str) -> list[tuple[str, str]]:
    text = _read(path)
    dist = re.search(r"distpath\s*=\s*['\"]([^'\"]+)['\"]", text)
    name = re.search(r"\bname\s*=\s*['\"]([^'\"]+)['\"]", text)
    if dist and name:
        return [(os.path.join(dist.group(1), name.group(1)), path)]
    if dist:
        return [(dist.group(1), path)]
    return []


def _from_inno(path: str) -> list[tuple[str, str]]:
    text = _read(path)
    directory = re.search(r"^\s*OutputDir\s*=\s*(.+?)\s*$", text, re.M)
    base = re.search(r"^\s*OutputBaseFilename\s*=\s*(.+?)\s*$", text, re.M)
    where = directory.group(1) if directory else "Output"
    if base:
        return [(os.path.join(where, base.group(1)), path)]
    return [(where, path)]


def _from_nsis(path: str) -> list[tuple[str, str]]:
    text = _read(path)
    match = re.search(r'^\s*OutFile\s+"([^"]+)"', text, re.M)
    return [(match.group(1), path)] if match else []


def _from_csproj(path: str) -> list[tuple[str, str]]:
    text = _read(path)
    out: list[tuple[str, str]] = []
    for match in re.finditer(r"<OutputPath>([^<]+)</OutputPath>", text):
        out.append((match.group(1).replace("\\", os.sep), path))
    if not out:
        assembly = re.search(r"<AssemblyName>([^<]+)</AssemblyName>", text)
        if assembly:
            out.append((os.path.join("bin", "Release"), path))
    return out


def _from_makefile(path: str) -> list[tuple[str, str]]:
    text = _read(path)
    out: list[tuple[str, str]] = []
    for match in re.finditer(r"(?:-o|--output[= ])\s*([^\s]+)", text):
        out.append((match.group(1), path))
    return out


def _from_workflow(path: str) -> list[tuple[str, str]]:
    """Paths a workflow uploads. A workflow is a project saying where its artifacts are."""
    text = _read(path)
    out: list[tuple[str, str]] = []
    for match in re.finditer(r"^\s*path:\s*(.+?)\s*$", text, re.M):
        value = match.group(1).strip().strip("'\"")
        if value and not value.startswith("|"):
            out.append((value, path))
    for match in re.finditer(r"^\s*files:\s*(.+?)\s*$", text, re.M):
        value = match.group(1).strip().strip("'\"")
        if value:
            for piece in value.split():
                out.append((piece, path))
    return out


def _from_library(repo: str, library_home: str | None) -> list[tuple[str, str, str]]:
    """Paths this machine has already recorded for this project, if the library is readable.

    Reading it rather than asking its plugin keeps the engine free of a dependency on it: a missing
    or unreadable library costs a note, not a failure.
    """
    home = library_home or os.environ.get("DSH_HOME") or ""
    if not home:
        return []
    index = os.path.join(home, "library", "index.json")
    if not os.path.isfile(index):
        return []
    try:
        with open(index, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    objects = data.get("objects") if isinstance(data, dict) else None
    if not isinstance(objects, list):
        return []
    prefix = os.path.normcase(os.path.abspath(repo))
    out: list[tuple[str, str]] = []
    for entry in objects:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not os.path.isabs(path):
            continue
        if not os.path.normcase(path).startswith(prefix):
            continue
        out.append((path, f"the local library recorded it as '{entry.get('name', 'a known object')}'",
                entry.get("name", "")))
        if len(out) >= 50:
            break
    return out


def _kind(path: str) -> str | None:
    try:
        kind = pe.identify(path)
    except OSError:
        return None
    return kind if pe.signable(kind) else None
