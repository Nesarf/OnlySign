"""Run the engine against itself, in a scratch directory.

Every check here exists because the thing it checks was wrong at least once somewhere: a script that
was misdecoded because it was read from disk, a module that could not be loaded because the search
path had been rearranged underneath it, a ledger read with the wrong code page, a chain whose tip
was read outside the lock, and a timestamp authority whose failure left a file in a state nobody had
checked. None of those are theories; they are all things that happened on the machine this was
written on.

Nothing here touches the real ledger, a real certificate store beyond creating and removing its own
throwaway certificate, or any build output.

    python -m onlysign.selftest
    python -m onlysign.selftest --keep        leave the scratch directory behind to look at
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from onlysign import notice as notice_module  # noqa: E402
from onlysign.engine import (  # noqa: E402
    audit, certs, container, discover, gate, ledger, pe, ps, signer, trust, workflow,
)

PASSED = 0
FAILED = 0

SAMPLE_CANDIDATES = (
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
)

UNREACHABLE_AUTHORITY = "http://127.0.0.1:9/"

# A notice of the test's own, so that what the gate does with a notice is checked without depending
# on which notice happens to be installed where this runs.
GATE_NOTICE_MARKER = "Notice written by the self-test."
GATE_TEST_NOTICE = (
    GATE_NOTICE_MARKER + "\n"
    "\n"
    "        \u2588\u2580\u2588   \u2584\u2584\u2584\u2584\n"
    "        \u2588 \u2588   \u2580\u2580\u2580\u2580\n"
    "\n"
    "In the event of any issues whilst using the tool, you may contact the repository "
    "administrator.\n"
)


def check(name: str, body) -> None:
    global PASSED, FAILED
    try:
        body()
    except Exception as exc:                      # noqa: BLE001 - a check may fail any way it likes
        print(f"  FAILED  {name}")
        print(f"          {type(exc).__name__}: {exc}")
        FAILED += 1
    else:
        print(f"  ok      {name}")
        PASSED += 1


def same(actual, expected, what: str) -> None:
    if actual != expected:
        raise AssertionError(f"{what}: got {actual!r}, expected {expected!r}")


def truthy(value, what: str) -> None:
    if not value:
        raise AssertionError(what)


def falsy(value, what: str) -> None:
    if value:
        raise AssertionError(what)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the OnlySign engine against itself.")
    parser.add_argument("--keep", action="store_true", help="keep the scratch directory")
    parser.add_argument("--sample", default="", help="a signed PE to strip and re-sign")
    args = parser.parse_args()

    scratch = Path(tempfile.mkdtemp(prefix="onlysign-selftest-"))
    print("OnlySign engine self-test")
    print(f"  scratch : {scratch}")
    print()

    # --- the bridge to Windows ------------------------------------------------ #
    print("powerShell bridge")

    def value_round_trip():
        same(ps.one("1 + 1"), 2, "a value returned from PowerShell")

    def non_ascii_path_round_trip():
        # The claim: a script carrying a non-ASCII path cannot be misread, because the script is
        # never a file. If this starts failing, something has begun writing scripts to disk again.
        target = scratch / "\u6d4b\u8bd5 \u6587\u4ef6.bin"
        target.write_bytes(b"1234567")
        size = ps.one("(Get-Item -LiteralPath " + ps.literal(str(target)) + ").Length")
        same(size, 7, "the size of a file whose name is not ASCII")

    def module_path_is_this_edition():
        # Windows PowerShell rebuilds part of this variable at startup, so it is not literally what
        # was handed over. The invariant that matters is narrower and is the one that decides
        # whether the tool works: no OTHER PowerShell edition's module directory may sit in the
        # list, because the first directory holding a module wins, and a version 7 directory holds
        # a version 7 Microsoft.PowerShell.Security that version 5.1 cannot load.
        seen = ps.one("$env:PSModulePath")
        parts = [part for part in str(seen).split(";") if part]
        if "WindowsPowerShell" in ps.POWERSHELL:
            truthy(ps.OWN_MODULES in parts, f"this edition's module directory is not in [{seen}]")
            foreign = [part for part in parts if "\\7\\Modules" in part or "/7/Modules" in part]
            same(foreign, [], "module directories belonging to another PowerShell edition")
        else:
            # The other way round for PowerShell 7: its default path deliberately includes the Windows
            # PowerShell directories, and that is where it finds the modules it does not ship.
            truthy(any("WindowsPowerShell" in part for part in parts),
                   f"PowerShell 7 cannot see the Windows PowerShell modules: [{seen}]")

    def the_command_exists():
        # The whole tool rests on one command. Asking for it is the direct test, and it is the thing
        # that disappears -- with an error naming Get-FileHash, or nothing at all -- when the search
        # path above is wrong.
        name = ps.one("(Get-Command Set-AuthenticodeSignature -ErrorAction Stop).Name")
        same(name, "Set-AuthenticodeSignature", "the command this tool depends on")

    check("a value survives the round trip", value_round_trip)
    check("a path that is not ASCII survives the round trip", non_ascii_path_round_trip)
    check("no other PowerShell edition can shadow this one's modules", module_path_is_this_edition)
    check("the signing command is available to the child", the_command_exists)

    # --- the ledger ----------------------------------------------------------- #
    print()
    print("the ledger")

    def known_vector():
        target = scratch / "abc.txt"
        target.write_bytes(b"abc")
        same(ledger.hash_file(target),
             "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
             "sha256(\"abc\")")

    def encoding_round_trip():
        # A note whose last character is one whose tail byte pairs with a closing quote under code
        # page 936 -- the exact shape that made a whole record unreadable when the file was read
        # with the machine's ANSI code page.
        path = scratch / "encoding.ndjson"
        note = "\u7f16\u7801\u5f80\u8fd4 \u5668"
        ledger.append(path, {"t": "x", "name": "n", "note": note})
        raw = path.read_bytes()
        falsy(raw.startswith(b"\xef\xbb\xbf"), "the ledger must be written without a BOM")
        back = ledger.read(path)
        same(back.broken, 0, "lines that did not parse")
        same(back.records[0]["note"], note, "the note read back")

    def sequential_chain():
        path = scratch / "chain.ndjson"
        for index in range(5):
            ledger.append(path, {"t": str(index), "name": f"n{index}"})
        loaded = ledger.read(path)
        walked = ledger.chain(loaded)
        same(len(loaded), 5, "records")
        same(walked["broken_at"], [], "breaks in the chain")
        same(walked["chained"], 5, "chained records")

    def concurrent_chain():
        # The regression test for the fork: separate processes appending at the same moment, with
        # nothing coordinating them beyond the lock the append takes for itself.
        path = scratch / "concurrent.ndjson"
        code = (
            "import sys\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from onlysign.engine import ledger\n"
            f"ledger.append({str(path)!r}, {{'t': 'x', 'name': 'worker'}})\n"
        )
        workers = [subprocess.Popen([sys.executable, "-c", code],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                   for _ in range(6)]
        for worker in workers:
            _out, err = worker.communicate(timeout=120)
            if worker.returncode != 0:
                raise AssertionError(f"an appending process failed: {err.decode('utf-8', 'replace')[:300]}")
        loaded = ledger.read(path)
        walked = ledger.chain(loaded)
        same(len(loaded), 6, "records")
        same(walked["broken_at"], [], "breaks in the chain")

    def edited_line_is_a_break():
        path = scratch / "tamper.ndjson"
        for index in range(3):
            ledger.append(path, {"t": str(index), "name": f"n{index}"})
        lines = path.read_text(encoding="utf-8").split("\n")
        lines[1] = lines[1].replace('"n1"', '"n1-edited"')
        path.write_text("\n".join(lines), encoding="utf-8")
        walked = ledger.chain(ledger.read(path))
        same(len(walked["broken_at"]), 1, "breaks after editing the second line")

    check("sha256 agrees with the published test vector", known_vector)
    check("a non-ASCII note survives the ledger", encoding_round_trip)
    check("appends in a row chain cleanly", sequential_chain)
    check("appends from six processes at once still chain cleanly", concurrent_chain)
    check("an edited line is reported as a break", edited_line_is_a_break)

    # --- what a file is ------------------------------------------------------- #
    print()
    print("file identification")

    def identify_and_strip():
        target = scratch / "sample.exe"
        shutil.copy2(sample_source(args.sample), target)
        same(pe.identify(target), pe.KIND_PE, "the sample's kind")
        truthy(pe.signable(pe.KIND_PE), "a PE image is something Authenticode signs")
        removed = pe.strip_signature(target)
        truthy(removed > 0, "the sample had an embedded signature to remove")
        same(pe.strip_signature(target), 0, "a second removal finds nothing to remove")

    def unknown_kinds():
        target = scratch / "notes.txt"
        target.write_text("not a PE file", encoding="utf-8")
        same(pe.identify(target), pe.KIND_UNKNOWN, "the kind of a text file")
        falsy(pe.signable(pe.KIND_UNKNOWN), "a text file is not signed by Authenticode")

    check("a PE image is identified and its signature can be removed", identify_and_strip)
    check("something that is not an artifact is not called one", unknown_kinds)

    # --- certificates --------------------------------------------------------- #
    print()
    print("certificates")

    subject = "O=OnlySign Self Test (throwaway), CN=OnlySign Self Test"
    pfx = scratch / "throwaway.pfx"
    cer = scratch / "throwaway.cer"
    throwaway: certs.Certificate | None = None

    def make_certificate():
        nonlocal throwaway
        throwaway = certs.create_self_signed(subject, years=1, password="selftest-only",
                                             pfx_path=str(pfx), cer_path=str(cer))
        same(throwaway.subject, subject, "the subject of the new certificate")
        truthy(pfx.is_file() and cer.is_file(), "both halves were written out")
        listed = {c.thumbprint: c for c in certs.list_certificates()}
        truthy(throwaway.thumbprint in listed, "the new certificate is not in the store")
        truthy(listed[throwaway.thumbprint].permits_code_signing,
               "a certificate made for code signing must permit code signing")

    def hardened_key():
        script = (
            "$acl = Get-Acl -LiteralPath " + ps.literal(str(pfx)) + "\n"
            "$names = @($acl.Access | ForEach-Object { $_.IdentityReference.Value })\n"
            "[pscustomobject]@{ count = $names.Count; names = $names }"
        )
        info = ps.one(script)
        truthy(int(info["count"]) >= 1, "the private key's access list is empty")
        joined = " ".join(str(n) for n in info["names"])
        for unwanted in ("Authenticated Users", "\\Users", "Everyone"):
            falsy(unwanted in joined, f"the private key is still open to {unwanted!r}")

    check("a self-signed certificate can be made and is found again", make_certificate)
    check("the private key is not left open to everyone", hardened_key)

    # --- signing -------------------------------------------------------------- #
    print()
    print("signing")

    sample = scratch / "sign-me.exe"
    signed_result: signer.SignResult | None = None

    def prepare():
        shutil.copy2(sample_source(args.sample), sample)
        if not pe.strip_signature(sample):
            raise AssertionError("the sample carries no embedded signature to remove")
        falsy(signer.carries_own_signature(sample),
              "the stripped sample still carries a signature of its own")

    def sign_once():
        nonlocal signed_result
        signed_result = signer.sign_file(sample, thumbprint=throwaway.thumbprint)
        truthy(signed_result.ok, f"signing did not succeed: {signed_result.error or signed_result.skipped}")
        truthy(signed_result.signature.timestamped, "the signature carries no timestamp")
        truthy(signed_result.signature.matches(throwaway.thumbprint), "the signer is not the chosen certificate")
        same(signed_result.timestamp_authority, signer.DEFAULT_TIMESTAMP_AUTHORITIES[0],
             "the authority that answered")
        truthy(signed_result.after_hash != signed_result.before_hash,
               "signing changed nothing, so there is no signature in the file")

    def refuse_second_signature():
        again = signer.sign_file(sample, thumbprint=throwaway.thumbprint)
        falsy(again.ok, "signing an already signed file was allowed")
        truthy("already carries a signature" in again.skipped,
               f"the refusal does not say why: {again.skipped!r}")

    def record_shape():
        record = signed_result.to_record(note="self test")
        for field in ("t", "file", "name", "size", "sha256_signed", "sha256_unsigned",
                      "signer", "thumbprint", "timestamped", "tsa", "note"):
            truthy(field in record, f"the record is missing {field!r}")
        same(record["sha256_signed"], signed_result.after_hash, "the recorded signed hash")
        same(record["sha256_unsigned"], signed_result.before_hash, "the recorded unsigned hash")

    def timestamp_failure_leaves_nothing_behind():
        # The behaviour this rests on was measured before it was relied on: when no authority can be
        # reached, the file must be left exactly as it was rather than carrying a signature that
        # stops verifying when the certificate expires.
        target = scratch / "no-timestamp.exe"
        shutil.copy2(sample_source(args.sample), target)
        pe.strip_signature(target)
        before = ledger.hash_file(target)
        result = signer.sign_file(target, thumbprint=throwaway.thumbprint,
                                  timestamp_authorities=[UNREACHABLE_AUTHORITY],
                                  allow_untimestamped=False)
        falsy(result.ok, "signing with no reachable timestamp authority was reported as success")
        same(ledger.hash_file(target), before, "the file after a failed timestamp")
        falsy(signer.carries_own_signature(target),
              "a timestamp failure left a signature behind, which is the state this test exists to prevent")

    def pinning_line():
        # The end-to-end version of this needs two certificates chosen between; the rule itself is
        # checkable directly, and the branch that enforces it is one comparison away.
        signature = signer.OwnSignature(present=True, thumbprint="AA" * 20)
        truthy(signature.matches("aa" * 20), "a thumbprint in the other case")
        truthy(not signature.matches("BB" * 20), "a different thumbprint must not match")
        truthy(not signer.OwnSignature().matches("AA" * 20), "an absent signer must not match anything")

    check("the sample starts out unsigned", prepare)
    check("signing produces a timestamped signature by the chosen certificate", sign_once)
    check("the same file is refused a second signature", refuse_second_signature)
    check("the record has the shape the ledger expects", record_shape)
    check("a timestamp failure leaves the file untouched and unsigned",
          timestamp_failure_leaves_nothing_behind)
    check("the signer is compared by thumbprint", pinning_line)

    # --- discovery and the audit ---------------------------------------------- #
    print()
    print("discovery and the audit")

    project = scratch / "project"
    (project / "dist").mkdir(parents=True)
    (project / "not-built").mkdir()
    (project / "package.json").write_text(
        json.dumps({"build": {"directories": {"output": "not-built"}}}), encoding="utf-8")
    shutil.copy2(sample_source(args.sample), project / "dist" / "thing.exe")
    pe.strip_signature(project / "dist" / "thing.exe")
    (project / "dist" / "readme.txt").write_text("not an artifact", encoding="utf-8")

    def discovery_finds_it_and_says_why():
        found = discover.scan(str(project))
        names = {os.path.basename(candidate.path) for candidate in found.candidates}
        truthy("thing.exe" in names, f"the artifact in dist/ was not proposed at all: {names}")
        candidate = [c for c in found.candidates if os.path.basename(c.path) == "thing.exe"][0]
        truthy(any("dist" in reason for reason in candidate.reasons),
               f"the reason does not name the directory it was found in: {candidate.reasons}")
        truthy(all(pe.signable(c.kind) for c in found.candidates),
               "something that is not an artifact was proposed")

    def discovery_says_why_a_declared_output_is_empty():
        found = discover.scan(str(project))
        truthy(any("not-built" in note for note in found.notes),
               f"nothing was said about the declared but empty output: {found.notes}")

    def discovery_follows_a_declared_directory():
        declared = project / "not-built"
        shutil.copy2(sample_source(args.sample), declared / "built.exe")
        pe.strip_signature(declared / "built.exe")
        found = discover.scan(str(project))
        candidate = [c for c in found.candidates if os.path.basename(c.path) == "built.exe"]
        truthy(candidate, "an artifact in a directory the project declares was not proposed")
        truthy(any("package.json" in reason for reason in candidate[0].reasons),
               f"the reason does not name the file that declared it: {candidate[0].reasons}")

    def audit_separates_the_two_kinds_of_news():
        ledger_path = scratch / "audit.ndjson"
        stripped = scratch / "stripped.exe"
        absent = scratch / "absent.exe"
        shutil.copy2(sample_source(args.sample), stripped)
        pe.strip_signature(stripped)
        # The unchanged case needs a file that is genuinely signed, so it reuses the one the signing
        # section produced. Recording a stripped file's hash as "as signed" would be a record that
        # cannot be true, and the audit is entitled to say so.
        ledger.append(ledger_path, {"t": "2026-01-01T00:00:00Z", "file": str(sample),
                                    "name": sample.name,
                                    "sha256_signed": ledger.hash_file(sample),
                                    "sha256_unsigned": "0" * 64,
                                    "thumbprint": throwaway.thumbprint})
        ledger.append(ledger_path, {"t": "2026-01-02T00:00:00Z", "file": str(stripped),
                                    "name": "stripped.exe", "sha256_signed": "0" * 64,
                                    "sha256_unsigned": ledger.hash_file(stripped)})
        ledger.append(ledger_path, {"t": "2026-01-03T00:00:00Z", "file": str(absent),
                                    "name": "absent.exe", "sha256_signed": "0" * 64,
                                    "sha256_unsigned": "0" * 64})
        report = audit.audit(ledger_path)
        verdicts = {finding.name: finding.verdict for finding in report.findings}
        same(verdicts[sample.name], audit.UNCHANGED, "a signed file that matches its record")
        same(verdicts["stripped.exe"], audit.NOW_UNSIGNED, "a file whose signature was removed")
        same(verdicts["absent.exe"], audit.GONE, "a record whose file is not there")
        # Only the stripped file should be asking for attention: an artifact that no longer carries
        # its signature is the thing this whole record exists to notice. A file that was moved is
        # not a problem, which is why "gone" is reported without calling anyone to action.
        attention = sorted(finding.name for finding in report.needing_attention())
        same(attention, ["stripped.exe"], "which findings ask for attention")
        truthy("0 changed by something this ledger has no record of" in audit.summarise(report),
               "the summary does not separate the routine cases from the alarming one")

    def execute_refuses_to_pretend():
        plan = workflow.Plan(paths=[str(project / "dist" / "thing.exe")],
                             thumbprint=throwaway.thumbprint)
        try:
            workflow.execute(plan, dry_run=True)
        except ValueError:
            return
        raise AssertionError("execute() accepted dry_run instead of sending the caller to preview()")

    def preview_says_what_would_happen():
        plan = workflow.Plan(paths=[str(project / "dist" / "thing.exe")],
                             thumbprint=throwaway.thumbprint)
        lines = workflow.preview(plan)
        truthy(any("would sign" in line for line in lines),
               f"the preview does not say what it would do: {lines}")
        truthy(any("ledger" in line for line in lines),
               "the preview does not say where the record goes")

    check("an artifact is found and the reason is given", discovery_finds_it_and_says_why)
    check("a declared output with nothing in it is explained",
          discovery_says_why_a_declared_output_is_empty)
    check("a directory the project declares is followed", discovery_follows_a_declared_directory)
    check("the audit tells the routine cases from the alarming one",
          audit_separates_the_two_kinds_of_news)
    check("a dry run cannot be mistaken for a real one", execute_refuses_to_pretend)
    check("the preview says what would happen", preview_says_what_would_happen)

    # --- the gate that travels with a package --------------------------------- #
    print()
    print("the gate")

    def gate_refuses_to_vouch_for_an_unsigned_package():
        unsigned = scratch / "unsigned-gate.exe"
        shutil.copy2(sample_source(args.sample), unsigned)
        pe.strip_signature(unsigned)
        ready, lines = gate.check(str(unsigned))
        falsy(ready, f"an unsigned package passed the gate's own check: {lines}")

    def gate_pins_the_signer():
        ready, lines = gate.check(str(sample), thumbprint=throwaway.thumbprint)
        truthy(ready, f"a properly signed package did not pass: {lines}")
        ready, lines = gate.check(str(sample), thumbprint="AA" * 20)
        falsy(ready, "a package signed by a different identity passed the gate")

    def gate_files_are_ascii_where_a_script_must_be():
        written = gate.emit(str(sample), thumbprint=throwaway.thumbprint)
        paths = written.paths()
        for key in ("script", "command"):
            raw = open(paths[key], "rb").read()
            truthy(all(byte < 128 for byte in raw),
                   f"{os.path.basename(paths[key])} is not pure ASCII, which is how a PowerShell "
                   f"script gets misread on a machine using another code page")
        same(open(paths["target"], encoding="utf-8").read().strip(), os.path.basename(str(sample)),
             "the name the gate will install")
        truthy(open(paths["notice"], encoding="utf-8").read().strip(), "the notice came out empty")

    def _polluted_module_path() -> dict:
        """An environment that breaks PowerShell 5.1's own modules, if this machine can produce one.

        PowerShell 7 puts its module directories at the front of PSModulePath, and the older
        PowerShell then loads version 7's binary modules, fails, and loses Get-AuthenticodeSignature
        entirely. The gate runs in whatever environment a stranger has, so it is handed the worst
        one here rather than the tidy one this process happens to have.
        """
        environment = dict(os.environ)
        polluted = [part for part in environment.get("PSModulePath", "").split(os.pathsep)
                    if part and "powershell" in part.lower() and os.sep + "7" + os.sep in part.lower()]
        if polluted:
            environment["PSModulePath"] = os.pathsep.join(
                polluted + [environment.get("PSModulePath", "")])
        return environment

    def gate_asks_and_respects_no():
        # Run the script the way a person would, with an answer piped in. Declining must show the
        # notice and must not start anything.
        #
        # The notice is supplied here rather than taken from whatever file the checkout happens to
        # carry. A test that reads the repository's own notice passes or fails according to whose
        # notice is installed, which is a property of the person running it and not of the code.
        script = gate.emit(str(sample), thumbprint=throwaway.thumbprint,
                           notice=GATE_TEST_NOTICE).paths()["script"]
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script],
            input=b"n\n", capture_output=True, env=_polluted_module_path(), timeout=300)
        out = proc.stdout.decode("utf-8", "replace")
        if not out:
            raise AssertionError("the gate produced nothing at all; its error was: "
                                 + proc.stderr.decode("utf-8", "replace")[:300])
        truthy(GATE_NOTICE_MARKER in out, f"the notice was not shown: {out[:300]}")
        truthy("\u2588" in out or "\u2580" in out, "the mark in the notice did not survive the trip")
        truthy("To proceed with installation? (Y/N)" in out, "the question was not asked")
        truthy("cannot be opened from this side" in out, "declining did not stop the installation")
        same(proc.returncode, 0, "the exit code after declining")

    def gate_says_which_signature_it_found():
        # Proof that the checks actually ran, rather than that the script merely did not crash: the
        # signer's thumbprint in the output can only come from reading the file's own signature.
        script = gate.emit(str(sample), thumbprint=throwaway.thumbprint,
                           notice=GATE_TEST_NOTICE).paths()["script"]
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script],
            input=b"n\n", capture_output=True, env=_polluted_module_path(), timeout=300)
        out = proc.stdout.decode("utf-8", "replace")
        truthy(throwaway.thumbprint.upper() in out.upper(),
               f"the gate did not report the signer it found: {out[:400]}")
        truthy(os.path.basename(str(sample)) in out, "the gate did not name the package")
        truthy("stamped" in out, "the gate did not say whether the signature carries a timestamp")

    def gate_refuses_a_package_that_does_not_match():
        # The whole point: a package that claims the identity without carrying it must not get as
        # far as being offered for installation.
        directory = scratch / "gate-tampered"
        directory.mkdir()
        target = directory / "thing.exe"
        shutil.copy2(sample, target)
        written = gate.emit(str(target), thumbprint="AA" * 20, directory=str(directory),
                            notice=GATE_TEST_NOTICE)
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", written.paths()["script"]],
            input=b"y\n", capture_output=True, env=_polluted_module_path(), timeout=300)
        out = proc.stdout.decode("utf-8", "replace")
        truthy("NOT signed by the identity it claims" in out,
               f"a package signed by the wrong identity was let through: {out[:400]}")
        falsy(GATE_NOTICE_MARKER in out,
              "the notice was printed for a package the gate had just refused")
        same(proc.returncode, 1, "the exit code after refusing")

    check("the gate will not vouch for an unsigned package", gate_refuses_to_vouch_for_an_unsigned_package)
    check("the gate pins the signer", gate_pins_the_signer)
    check("the script is ASCII and the names are not", gate_files_are_ascii_where_a_script_must_be)
    check("the gate asks, and respects a no", gate_asks_and_respects_no)
    check("the gate reports the signature it found", gate_says_which_signature_it_found)
    check("the gate refuses a package signed by someone else", gate_refuses_a_package_that_does_not_match)

    # --- the notice ----------------------------------------------------------- #
    print()
    print("the notice")

    def notice_prefers_a_local_file_and_the_asked_language():
        # The rule, stated once: somebody's own notice beats anything the repository ships, and
        # within that the language that was asked for wins. Tested against a directory of its own so
        # that the answer does not depend on what happens to be installed in this checkout.
        where = scratch / "notice"
        where.mkdir()
        (where / "NOTICE.txt").write_text("shipped, neutral\n", encoding="utf-8")
        (where / "NOTICE.local.txt").write_text("mine, either language\n", encoding="utf-8")
        (where / "NOTICE.local.zh.txt").write_text("我的，中文\n", encoding="utf-8")
        original = notice_module._directories
        notice_module._directories = lambda: [str(where)]
        notice_module._cached.clear()
        try:
            same(notice_module.text("zh").strip(), "我的，中文",
                 "Chinese, from the local file, when Chinese was asked for")
            same(notice_module.text("en").strip(), "mine, either language",
                 "the local file when it has no English one of its own")
            same(notice_module.source("zh"), str(where / "NOTICE.local.zh.txt"), "where it came from")

            (where / "NOTICE.local.zh.txt").unlink()
            notice_module._cached.clear()
            same(notice_module.text("zh").strip(), "mine, either language",
                 "a real notice rather than a shipped placeholder, when the language has no file")
        finally:
            notice_module._directories = original
            notice_module._cached.clear()

    def notice_is_not_shown_to_a_pipe():
        # A banner inside a machine-readable stream is a bug, not friendliness.
        import io
        quiet = io.StringIO()
        notice_module.show(quiet)
        same(quiet.getvalue(), "", "nothing written when stdout is not a terminal")
        notice_module.show(quiet, quiet=True)
        same(quiet.getvalue(), "", "nothing written when silence was asked for")

    check("the notice is chosen by owner first, then by language",
          notice_prefers_a_local_file_and_the_asked_language)
    check("the notice is not printed into a pipe", notice_is_not_shown_to_a_pipe)


    # --- reading a container -------------------------------------------------- #
    print()
    print("a signature inside a container")

    def _tiny_cfb(payload: bytes, claimed_size: int | None = None, sector: int = 512,
                  directory_loop: bool = False) -> bytes:
        """A compound file built by hand, a few KB of it.

        Hand-built on purpose. The first version of this reader was pointed straight at a real signed
        MSI, and a length field it had misread turned into an allocation of tens of gigabytes -- the
        kind of bug a large input finds and a small one does not. A file this size cannot hurt
        anything, and every field in it was written here, so the reader is checked against something
        known rather than against whatever a real package happens to contain.

        Built at more than one sector size because the arithmetic that finds a sector only agrees
        between them when the sector is 512 bytes. A reader tested at 512 alone passed while reading
        every 4096-byte package wrongly -- it took a wrong stride into the middle of the allocation
        table, followed a table that described something else, and reported entries that were never
        in the file. One size would have kept hiding that, so both are built and both are read.
        """
        import struct
        SECTOR = sector
        FREE, END, FAT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
        header = bytearray(SECTOR)
        header[0:8] = container.CFB_MAGIC
        struct.pack_into("<H", header, 24, 0x003E)
        # Version 4 is the one that uses 4096-byte sectors, and it is also the version whose header
        # states the directory's sector count instead of leaving it to the chain.
        struct.pack_into("<H", header, 26, 0x0004 if SECTOR > 512 else 0x0003)
        struct.pack_into("<H", header, 28, 0xFFFE)
        struct.pack_into("<H", header, 30, SECTOR.bit_length() - 1)
        struct.pack_into("<H", header, 32, 6)
        struct.pack_into("<I", header, 40, 1 if SECTOR > 512 else 0)
        struct.pack_into("<I", header, 44, 1)
        struct.pack_into("<I", header, 48, 0)
        struct.pack_into("<I", header, 56, 4096)
        struct.pack_into("<I", header, 60, END)
        struct.pack_into("<I", header, 68, END)
        struct.pack_into("<I", header, 76, 1)
        for index in range(1, 109):
            struct.pack_into("<I", header, 76 + 4 * index, FREE)

        directory = bytearray(SECTOR)

        def entry(index: int, name: str, kind: int, start: int, size: int) -> None:
            base = index * 128
            raw = name.encode("utf-16-le") + bytes(2)
            directory[base:base + len(raw)] = raw
            struct.pack_into("<H", directory, base + 64, len(raw))
            directory[base + 66] = kind
            struct.pack_into("<I", directory, base + 116, start)
            struct.pack_into("<Q", directory, base + 120, size)

        entry(0, "Root Entry", 5, END, 0)
        entry(1, container.MSI_SIGNATURE_STREAM, 2, 2,
              len(payload) if claimed_size is None else claimed_size)

        count = (len(payload) + SECTOR - 1) // SECTOR
        # The first entry describes sector 0, which holds the directory; the second describes sector
        # 1, which holds this table. A loop here is what a wrong stride looked like from inside the
        # reader: sector 0 pointing back at itself, walked until a byte cap rather than until an end.
        values = [0 if directory_loop else END, FAT]
        values += [2 + i + 1 for i in range(count - 1)] + [END]
        values += [FREE] * (SECTOR // 4 - len(values))
        fat = bytearray(SECTOR)
        for index, value in enumerate(values):
            struct.pack_into("<I", fat, 4 * index, value)
        return bytes(header) + bytes(directory) + bytes(fat) + payload + bytes(SECTOR)

    def container_reads_a_stream_it_was_given():
        payload = bytes(range(256)) * 16
        for sector in (512, 4096):
            parsed = container.CompoundFile(_tiny_cfb(payload, sector=sector))
            same(parsed.sector_size, sector, "the sector size the reader took from the header")
            # Every slot in the directory is an entry, filled or not, and a sector holds one slot
            # per 128 bytes -- so this number is also the check that no more than the declared
            # number of directory sectors was read.
            same(len(parsed.directory()), sector // 128,
                 f"directory entries in a {sector}-byte-sector file")
            blob = parsed.stream(container.MSI_SIGNATURE_STREAM)
            truthy(blob is not None, f"the signature stream was not found at {sector}-byte sectors")
            same(len(blob), len(payload), "the length of the stream that came back")
            truthy(blob == payload, "the bytes are not the ones that went in")
            same(parsed.stream("no such stream"), None, "a stream that is not there")

    def container_does_not_follow_a_chain_that_loops():
        # The shape of the real failure, made small: a directory chain pointing back at its own
        # first sector. A bound on steps does not catch it, because walking to the bound is exactly
        # what a loop does -- the entries beyond the structure parse as entries that were never
        # written, and a 1.2 MB package came back with 64 MB of them.
        payload = bytes(range(256)) * 16
        parsed = container.CompoundFile(_tiny_cfb(payload, directory_loop=True))
        try:
            entries = parsed.directory()
        except container.NotAContainer:
            return
        raise AssertionError(
            f"a directory chain that revisits its own first sector produced {len(entries)} entries"
        )

    def container_does_not_believe_a_claimed_length():
        # The incident, as a test: a length field saying 2^62 must cost nothing. Bounding loop steps
        # is not enough; without a bound on bytes this is where the process dies.
        payload = bytes(range(256)) * 16
        parsed = container.CompoundFile(_tiny_cfb(payload, claimed_size=1 << 62))
        started = time.time()
        blob = parsed.stream(container.MSI_SIGNATURE_STREAM)
        elapsed = time.time() - started
        truthy(elapsed < 5, f"reading a doctored length took {elapsed:.1f}s")
        truthy(blob is None or len(blob) <= len(_tiny_cfb(payload, claimed_size=1 << 62)),
               "a doctored length produced more bytes than the file holds")

    def container_refuses_what_is_not_one():
        try:
            container.CompoundFile(b"not a compound file at all" + bytes(600))
        except container.NotAContainer:
            return
        raise AssertionError("a file that is not a compound file was accepted")

    check("a stream is read out of a compound file at either sector size",
          container_reads_a_stream_it_was_given)
    check("a claimed length is not believed", container_does_not_believe_a_claimed_length)
    check("a directory chain that loops is refused", container_does_not_follow_a_chain_that_loops)
    check("something that is not a container is refused", container_refuses_what_is_not_one)

    # --- cleaning up after itself --------------------------------------------- #
    if throwaway is not None:
        ps.call("Get-ChildItem ('Cert:\\CurrentUser\\My\\' + " + ps.literal(throwaway.thumbprint) +
                 ") | Remove-Item -Force\n'test certificate removed'")

    print()
    print(f"{PASSED} check(s) passed, {FAILED} failed")
    if args.keep:
        print(f"the scratch directory was kept at {scratch}")
    else:
        shutil.rmtree(scratch, ignore_errors=True)
    return 1 if FAILED else 0


def sample_source(explicit: str) -> str:
    """A signed PE to strip. Any signed file will do; these are on every Windows and belong to nobody."""
    if explicit:
        if not os.path.isfile(explicit):
            raise SystemExit(f"no sample file at {explicit}")
        return explicit
    for candidate in SAMPLE_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    raise SystemExit("no signed sample file found; pass --sample <a signed PE>")


if __name__ == "__main__":
    raise SystemExit(main())
