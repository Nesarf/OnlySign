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
from tkinter import messagebox

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from onlysign import gui                                    # noqa: E402
from onlysign.engine import certs, ledger, pe, ps           # noqa: E402

SAMPLE_CANDIDATES = (r"C:\Windows\explorer.exe", r"C:\Windows\System32\notepad.exe")


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

    def check(name: str, body) -> None:
        nonlocal failures
        try:
            body()
        except Exception as exc:                             # noqa: BLE001
            print(f"  FAILED  {name}")
            print(f"          {type(exc).__name__}: {exc}")
            failures += 1
        else:
            print(f"  ok      {name}")

    scratch = tempfile.mkdtemp(prefix="onlysign-gui-smoke-")
    project = os.path.join(scratch, "project")
    os.makedirs(os.path.join(project, "dist"))
    artifact = os.path.join(project, "dist", "thing.exe")
    shutil.copy2(sample(), artifact)
    pe.strip_signature(artifact)

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
            original = messagebox.askyesno
            messagebox.askyesno = lambda *a, **k: True
            try:
                window.on_sign()
                if not pump(root, lambda: not window.busy):
                    raise AssertionError("the signing run never finished")
                # Wait for the outcome to have been drawn, rather than assuming it has: the worker
                # and the drawing are two steps, and a test that races them fails once in ten runs
                # for no reason anybody can see.
                pump(root, lambda: "signed" in window.report.get("1.0", "end"), timeout=30)
            finally:
                messagebox.askyesno = original
            text = window.report.get("1.0", "end")
            if "1 signed" not in text:
                raise AssertionError(f"the window did not report a signing: {text[-400:]}")
            record = ledger.read(window.ledger.get())
            if len(record) != 1:
                raise AssertionError(f"the ledger holds {len(record)} record(s), expected 1")
            if not record.records[0].get("timestamped"):
                raise AssertionError("the record does not say the signature was timestamped")
            if not pe.pe_certificate_table(artifact):
                raise AssertionError("the file on disk carries no signature after signing")

        def checking_reports_it_as_unchanged():
            window.report.configure(state="normal")
            window.report.delete("1.0", "end")
            window.report.configure(state="disabled")
            window.on_check()
            if not pump(root, lambda: "unchanged" in window.report.get("1.0", "end")):
                raise AssertionError(f"the check did not report the signing: "
                                     f"{window.report.get('1.0', 'end')[-300:]}")

        check("the window offers the certificate the test made", certificate_is_listed)
        check("scanning fills the list from the project directory", scanning_fills_the_list)
        check("a dry run says what would happen and writes nothing", dry_run_says_what_would_happen)
        check("declining the confirmation signs nothing", cancelling_the_confirmation_signs_nothing)
        check("confirming signs the file and records it", confirming_signs_and_records)
        check("the window can check the ledger it wrote", checking_reports_it_as_unchanged)

        root.destroy()
    finally:
        try:
            path = "Cert:\\CurrentUser\\My\\" + throwaway.thumbprint
            ps.call("Get-ChildItem (" + ps.literal(path) + ") | Remove-Item -Force" + chr(10) + "'ok'")
        except Exception:                                    # noqa: BLE001
            print("  note: the throwaway certificate could not be removed")
        shutil.rmtree(scratch, ignore_errors=True)

    print()
    print(f"{6 - failures}/6 check(s) passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
