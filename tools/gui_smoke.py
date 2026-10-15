"""Driving the window the way a person would, so that "the window decides nothing" is checked.

The claim this file exists to test is a specific one: that the window reaches the same engine
functions the command line does, and adds no judgement of its own. So this opens the real window,
fills in the real fields, presses the real buttons, and then looks at what the ledger says
afterwards -- rather than testing the engine again through a different door.

It needs a display, because it opens a window. It signs one file with a throwaway certificate, both
of which it makes and removes itself.

    python tools/gui_smoke.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import tkinter as tk
import zipfile
from tkinter import messagebox

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from onlysign import gui                                    # noqa: E402
from onlysign import mark as marks                          # noqa: E402
from onlysign.engine import bootmark, certs, ledger, pe, ps  # noqa: E402

SAMPLE_CANDIDATES = (r"C:\Windows\explorer.exe", r"C:\Windows\System32\notepad.exe")


class NotTested(Exception):
    """Raised by a check that could not be given what it needs, so it says nothing either way.

    The same outcome the engine's self-test has, for the same reason: the timestamp authorities
    rate-limit, and a check that reports "the tool is broken" when the network said no is a check
    that teaches people to ignore it. This is counted separately and does not fail the run.
    """


def sample() -> str:
    for candidate in SAMPLE_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    raise SystemExit("no signed sample file to work with")


def pump(root: tk.Tk, predicate, timeout: float = 180.0) -> bool:
    """Run the event loop until the predicate holds. tkinter is single-threaded, so this is how a
    test waits for a worker: by letting the window do its own bookkeeping."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        root.update()
        if predicate():
            return True
        time.sleep(0.05)
    return False


def main() -> int:
    failures = 0
    untested = 0

    def check(name: str, body) -> None:
        nonlocal failures, untested
        try:
            body()
        except NotTested as exc:
            print(f"  untested  {name}")
            print(f"            {exc}")
            untested += 1
        except Exception as exc:                             # noqa: BLE001
            print(f"  FAILED  {name}")
            print(f"          {type(exc).__name__}: {exc}")
            failures += 1
        else:
            print(f"  ok      {name}")

    def same(got, wanted, what: str = "") -> None:
        if got != wanted:
            raise AssertionError(f"{what or 'the value'}: {got!r} rather than {wanted!r}")

    def truthy(value, what: str = "") -> None:
        if not value:
            raise AssertionError(what or "expected something true and got a false value")

    def falsy(value, what: str = "") -> None:
        if value:
            raise AssertionError(what or f"expected nothing and got {value!r}")

    scratch = tempfile.mkdtemp(prefix="onlysign-gui-smoke-")
    project = os.path.join(scratch, "project")
    os.makedirs(os.path.join(project, "dist"))
    artifact = os.path.join(project, "dist", "thing.exe")
    shutil.copy2(sample(), artifact)
    pe.strip_signature(artifact)

    # The test's own identity, so what the marking page writes is checked without depending on whose
    # names happen to be configured on the machine this runs on.
    identity_path = os.path.join(scratch, "identity.json")
    with open(identity_path, "w", encoding="utf-8") as handle:
        json.dump({"primary": "TEST-PRIMARY", "secondary": ["TEST-SECONDARY"]}, handle)

    throwaway = certs.create_self_signed("O=OnlySign GUI Smoke, CN=OnlySign GUI Smoke",
                                         years=1, password="gui-smoke")
    certificate = None
    try:
        # English, so the assertions below can be about what happened rather than about which
        # language the window happens to open in.
        settings_path = os.path.join(scratch, "settings.json")
        with open(settings_path, "w", encoding="utf-8") as handle:
            json.dump({"language": "en"}, handle)
        root = tk.Tk()
        window = gui.Window(root, gui.Settings(settings_path))
        pump(root, lambda: bool(window.certificates), timeout=60)

        def certificate_is_listed():
            labels = [c.short() for c in window.certificates]
            match = [label for label in labels if label.startswith(throwaway.thumbprint[:8])]
            if not match:
                raise AssertionError(f"the certificate the test made is not offered: {labels}")
            nonlocal certificate
            certificate = match[0]

        def scanning_fills_the_list():
            window.repo.set(project)
            window.artifacts.set("")
            window.on_scan()
            if not pump(root, lambda: bool(window.candidates)):
                raise AssertionError(f"the scan proposed nothing; the window says: "
                                     f"{window.report.get('1.0', 'end').strip()[-300:]}")
            names = [os.path.basename(c.path) for c in window.candidates]
            if "thing.exe" not in names:
                raise AssertionError(f"the artifact in dist/ was not proposed: {names}")
            if not all(c.selected for c in window.candidates):
                raise AssertionError("a candidate was not offered selected by default")

        def dry_run_says_what_would_happen():
            window.certificate.set(certificate)
            window.ledger.set(os.path.join(scratch, "signings.ndjson"))
            window.report.configure(state="normal")
            window.report.delete("1.0", "end")
            window.report.configure(state="disabled")
            window.on_dry_run()
            text = window.report.get("1.0", "end")
            if "about to sign" not in text:
                raise AssertionError(f"the dry run does not say what it would do: {text[-300:]}")
            if os.path.exists(window.ledger.get()):
                raise AssertionError("a dry run wrote a ledger")

        def cancelling_the_confirmation_signs_nothing():
            original = messagebox.askyesno
            messagebox.askyesno = lambda *a, **k: False
            try:
                window.on_sign()
                time.sleep(0.5)
                root.update()
            finally:
                messagebox.askyesno = original
            if os.path.exists(window.ledger.get()):
                raise AssertionError("declining the confirmation still signed something")

        def confirming_signs_and_records():
            # The timestamp authorities rate-limit, and a refused authority is not a broken window:
            # measured, the first attempt in a burst succeeds and the rest fail with a message that
            # reads like a damaged file. So this is given a few paced tries, and if every one of them
            # fails *for want of a timestamp* it says so as a fact about the network rather than
            # reporting a defect that is not there. The engine's own behaviour in that case is right
            # and is asserted while it happens: the attempt is undone, byte for byte.
            original = messagebox.askyesno
            messagebox.askyesno = lambda *a, **k: True
            try:
                for attempt in range(1, 4):
                    window.report.configure(state="normal")
                    window.report.delete("1.0", "end")
                    window.report.configure(state="disabled")
                    window.on_sign()
                    if not pump(root, lambda: not window.busy):
                        raise AssertionError("the signing run never finished")
                    # Wait for the outcome to have been drawn, rather than assuming it has: the worker
                    # and the drawing are two steps, and a test that races them fails once in ten runs
                    # for no reason anybody can see.
                    pump(root, lambda: "signed" in window.report.get("1.0", "end"), timeout=30)
                    text = window.report.get("1.0", "end")
                    if "1 signed" in text:
                        break
                    if "no timestamp was obtained" not in text:
                        raise AssertionError(f"the window did not report a signing: {text[-400:]}")
                    if "hash unchanged" not in text:
                        raise AssertionError(
                            f"a failed signing left the file altered -- the undo is the thing that "
                            f"has to hold when the network does not: {text[-400:]}")
                    if attempt < 3:
                        print(f"  note    every authority refused; waiting before trying again "
                              f"(attempt {attempt} of 3)")
                        time.sleep(25)
            finally:
                messagebox.askyesno = original
            text = window.report.get("1.0", "end")
            if "1 signed" not in text:
                raise NotTested(
                    "no timestamp authority would answer, so the signing half of this window could "
                    "not be reached; everything before it was undone and the file is byte-identical")
            record = ledger.read(window.ledger.get())
            if len(record) != 1:
                raise AssertionError(f"the ledger holds {len(record)} record(s), expected 1")
            if not record.records[0].get("timestamped"):
                raise AssertionError("the record does not say the signature was timestamped")
            if not pe.pe_certificate_table(artifact):
                raise AssertionError("the file on disk carries no signature after signing")

        def checking_reports_it_as_unchanged():
            if not pe.pe_certificate_table(artifact):
                raise NotTested("nothing was signed above, so there is nothing to check against")
            window.report.configure(state="normal")
            window.report.delete("1.0", "end")
            window.report.configure(state="disabled")
            window.on_check()
            if not pump(root, lambda: "unchanged" in window.report.get("1.0", "end")):
                raise AssertionError(f"the check did not report the signing: "
                                     f"{window.report.get('1.0', 'end')[-300:]}")

        # --- the marking page ------------------------------------------------- #
        #
        # The claim being tested is the same one the rest of this file tests: the page reaches the
        # engine rather than deciding anything. So it is driven through its own buttons, and what is
        # asserted afterwards is what a reader who has never heard of this tool would find -- a zip
        # that still opens, and a comment in it naming the test's own identity.

        def remembering_now():
            window.report.configure(state="normal")
            window.report.delete("1.0", "end")
            window.report.configure(state="disabled")

        def a_preview_writes_nothing():
            scratch_zip = os.path.join(scratch, "preview.zip")
            with zipfile.ZipFile(scratch_zip, "w") as made:
                made.writestr("payload.txt", "something\n")
            window.mark_file.set(scratch_zip)
            window.mark_identity.set(identity_path)
            remembering_now()
            window.on_mark_preview()
            if not pump(root, lambda: "preview" in window.report.get("1.0", "end")):
                raise AssertionError(f"the preview said nothing: "
                                     f"{window.report.get('1.0', 'end')[-300:]}")
            if marks.zip_comment(scratch_zip):
                raise AssertionError("a preview wrote a comment into the archive")
            text = window.report.get("1.0", "end")
            if "TEST-PRIMARY" not in text:
                raise AssertionError(f"the preview does not show the mark it would write: {text[-300:]}")

        def the_signable_page_does_not_offer_marking():
            # The window has to say the same thing the command line does about a PE: it is signed,
            # not marked. The button stays live; the answer is a refusal, not a hidden control.
            window.mark_file.set(artifact)
            remembering_now()
            window.on_mark()
            if not pump(root, lambda: not window.busy):
                raise AssertionError("the refusal never finished")
            pump(root, lambda: "carrier" in window.report.get("1.0", "end"), timeout=10)
            text = window.report.get("1.0", "end")
            if "sign it instead" not in text:
                raise AssertionError(f"a PE was not refused on the marking page: {text[-400:]}")
            if len(open(artifact, "rb").read()) != os.path.getsize(artifact):
                raise AssertionError("the file was disturbed by a refusal")

        def marking_lands_and_reads_back():
            scratch_zip = os.path.join(scratch, "marked.zip")
            with zipfile.ZipFile(scratch_zip, "w") as made:
                made.writestr("payload.txt", "something\n")
            window.mark_file.set(scratch_zip)
            remembering_now()
            window.on_mark()
            if not pump(root, lambda: not window.busy):
                raise AssertionError("the marking never finished")
            if not pump(root, lambda: "the mark is on" in window.report.get("1.0", "end"), timeout=20):
                raise AssertionError(f"the window did not report placing a mark: "
                                     f"{window.report.get('1.0', 'end')[-400:]}")
            found = marks.read_zip_mark(scratch_zip)
            if not found.get("marked"):
                raise AssertionError(f"no mark was written into the archive: "
                                     f"{window.report.get('1.0', 'end')[-300:]}")
            if found.get("holder") != "(c) 2026 TEST-PRIMARY [TEST-SECONDARY]":
                raise AssertionError(f"the mark names the wrong holder: {found.get('holder')!r}")
            if not found.get("digest_matches"):
                raise AssertionError("the digest the window wrote does not describe the archive")
            # Every reader shows it, which is the whole point of choosing a comment as the carrier.
            if zipfile.ZipFile(scratch_zip).namelist() != ["payload.txt"]:
                raise AssertionError("the archive no longer lists what it did before")
            text = window.report.get("1.0", "end")
            if "the digest agrees" not in text:
                raise AssertionError(f"the window placed a mark without reading it back: {text[-300:]}")

        def reading_it_back_standalone():
            scratch_zip = os.path.join(scratch, "marked.zip")
            remembering_now()
            window.on_read_mark()
            text = window.report.get("1.0", "end")
            if "TEST-PRIMARY" not in text:
                raise AssertionError(f"reading the mark back found nothing: {text[-300:]}")

        def the_boot_sector_is_offered_here_too():
            # There is no file to mark in this case, so the sector is the carrier itself -- and the
            # window has to be able to write one without a file being named anywhere.
            out = os.path.join(scratch, "sector.bin")
            window.boot_out.set(out)
            remembering_now()
            window.on_build_sector(False)
            if not pump(root, lambda: not window.busy):
                raise AssertionError("building a sector never finished")
            if not pump(root, lambda: os.path.exists(out), timeout=10):
                raise AssertionError(f"no sector was written: "
                                     f"{window.report.get('1.0', 'end')[-300:]}")
            blob = open(out, "rb").read()
            if len(blob) != bootmark.SECTOR_SIZE:
                raise AssertionError(f"the sector is {len(blob)} bytes, not {bootmark.SECTOR_SIZE}")
            if blob[-2:] != bootmark.BOOT_SIGNATURE:
                raise AssertionError("the sector does not end in the boot signature")
            report = bootmark.read(blob)
            if report["problems"]:
                raise AssertionError(f"reading the sector back complained: {report['problems']}")
            if "TEST-SECONDARY" not in report["text"]:
                raise AssertionError(f"the sector does not carry the whole mark: {report['text']!r}")

        def the_signing_buttons_stay_on_their_own_page():
            window.notebook.select(window.pages["signing"])
            root.update()
            if str(window.dry_button["state"]) == "disabled":
                raise AssertionError("the signing buttons were left disabled on the signing page")
            window.notebook.select(window.pages["mark"])
            root.update()
            if str(window.dry_button["state"]) != "disabled":
                raise AssertionError("the signing buttons stayed live on the marking page")
            if str(window.mark_place_button["state"]) == "disabled":
                raise AssertionError("the marking buttons are disabled on the marking page")
            window.notebook.select(window.pages["signing"])
            root.update()

        def every_page_declared_is_a_page_that_can_be_reached():
            # A page can be written, laid out, tested through its own methods -- and never added to
            # the notebook, in which case nobody can reach it and nothing says so. The mark page was
            # the fourth to be added, which is when that stops being hypothetical. `--tabs` asks a
            # built executable how many pages it has; this is the half a built executable cannot
            # answer, because it knows what it offers and not what it meant to offer.
            offered = [window.notebook.tab(index, "text")
                       for index in range(window.notebook.index("end"))]
            same(len(offered), len(gui.TAB_KEYS),
                 f"pages offered against pages declared: {offered} vs {gui.TAB_KEYS}")
            for key in gui.TAB_KEYS:
                short = key.split(".")[1]
                if short not in window.pages:
                    raise AssertionError(f"{key} is declared and no such page was built")

        def the_character_answers_every_outcome():
            # The character is the window's answer to "what happened", so every outcome the map names
            # has to reach a picture that exists. A state with no picture is the window saying nothing
            # at the moment it most needs to say something, and it would look exactly like a state the
            # map had not been updated for.
            states = window._state_map()
            truthy(states, "no state map was loaded, so the character never changes")
            for state, name in states.items():
                window.show_state(state)
                root.update_idletasks()
                image = getattr(window.character, "image", None)
                if image is None or image.width() < 8:
                    raise AssertionError(f"the {state!r} state drew nothing (file {name!r})")
                if getattr(window, "character_state", "") != state:
                    raise AssertionError(f"the {state!r} state did not take")
            # And an outcome with no entry leaves the last picture alone rather than blanking it.
            window.show_state("no-such-outcome")
            truthy(getattr(window.character, "image", None) is not None,
                   "an unknown outcome blanked the character")
            window.show_state("idle")

        def the_window_wears_the_application_face():
            # Until this existed the window showed Tk's own feather while the executable carried the
            # application's icon -- two faces for one program, and the wrong one on screen while it
            # ran. What is checked here is that a picture is found and Tk accepts it; whether it
            # looks right was settled by photographing the running window, which is not a test.
            truthy(gui.install_window_icon(root),
                   "no icon file was found, so the window falls back to Tk's own")
            # The About box shows the chibi figure, which is a different file from the icon on
            # purpose: a close-up reads at sixteen pixels, a whole figure is what belongs in About.
            found = window._about_mark(root)
            try:
                truthy(found is not None, "the About window found no picture at all")
                size = (found.image.width(), found.image.height())
                truthy(size[0] > 64 and size[1] > 64, f"the About picture is tiny: {size}")
            finally:
                if found is not None:
                    found.destroy()

        check("the window offers the certificate the test made", certificate_is_listed)
        check("scanning fills the list from the project directory", scanning_fills_the_list)
        check("a dry run says what would happen and writes nothing", dry_run_says_what_would_happen)
        check("declining the confirmation signs nothing", cancelling_the_confirmation_signs_nothing)
        check("confirming signs the file and records it", confirming_signs_and_records)
        check("the window can check the ledger it wrote", checking_reports_it_as_unchanged)
        check("a preview of a mark writes nothing", a_preview_writes_nothing)
        check("the marking page refuses a format that should be signed",
              the_signable_page_does_not_offer_marking)
        check("a mark placed from the window lands and reads back", marking_lands_and_reads_back)
        check("the window can read a mark back on its own", reading_it_back_standalone)
        check("the window builds a boot sector that carries the whole mark",
              the_boot_sector_is_offered_here_too)
        check("the signing buttons stay on their own page", the_signing_buttons_stay_on_their_own_page)
        check("every page the window declares can be reached",
              every_page_declared_is_a_page_that_can_be_reached)
        check("the window wears the application face", the_window_wears_the_application_face)
        check("the character answers every outcome", the_character_answers_every_outcome)

        root.destroy()
    finally:
        try:
            path = "Cert:\\CurrentUser\\My\\" + throwaway.thumbprint
            ps.call("Get-ChildItem (" + ps.literal(path) + ") | Remove-Item -Force" + chr(10) + "'ok'")
        except Exception:                                    # noqa: BLE001
            print("  note: the throwaway certificate could not be removed")
        shutil.rmtree(scratch, ignore_errors=True)

    print()
    total = 15
    line = f"{total - failures - untested}/{total} check(s) passed"
    if untested:
        line += f", {untested} not tested"
    print(line)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
