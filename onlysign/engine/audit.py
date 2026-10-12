"""Asking the ledger whether it is still true.

The record says what was signed. This asks the disk whether that is still the case, and keeps the
answers apart, because they are not the same kind of news:

* **unchanged** -- the bytes on disk are the bytes that were signed. The ordinary case;
* **superseded** -- the path now holds a later build *that this ledger also signed*. Routine: a
  rebuild and a re-sign. It is reported with the record that replaced it, so it reads as history
  rather than as a problem;
* **changed** -- the bytes match no signing on record. This is the one worth reading;
* **now unsigned** -- the bytes on disk are the ones from *before* signing, so the signature was
  stripped or the file was put back;
* **gone** -- the recorded path does not exist. Which is what happens when a build is signed in a
  temporary directory, or moved afterwards; the ledger records where a file *was*.

The first version of this reported the routine case and the alarming one identically, and six
alarming lines buried the one that mattered.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from . import ledger, signer

UNCHANGED = "unchanged"
SUPERSEDED = "superseded"
CHANGED = "changed"
NOW_UNSIGNED = "now unsigned"
GONE = "gone"
PUBLISHED = "published"
RELOCATED = "relocated"

ALARMING = (CHANGED, NOW_UNSIGNED)


@dataclass
class Finding:
    record: dict
    verdict: str = ""
    current_hash: str = ""
    replaced_by: dict | None = None
    signer_thumbprint: str = ""
    detail: str = ""

    @property
    def name(self) -> str:
        return str(self.record.get("name") or os.path.basename(str(self.record.get("file") or "")))

    @property
    def when(self) -> str:
        return str(self.record.get("t") or "")[:19]


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    broken_lines: int = 0
    chain: dict[str, Any] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for finding in self.findings:
            tally[finding.verdict] = tally.get(finding.verdict, 0) + 1
        return tally

    def needing_attention(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict in ALARMING]


def audit(ledger_path: str | os.PathLike[str]) -> Report:
    """Compare every record in the ledger against the files on disk."""
    loaded = ledger.read(ledger_path)
    report = Report(broken_lines=loaded.broken, chain=ledger.chain(loaded))

    known: dict[str, list[dict]] = {}
    for record in loaded.records:
        digest = record.get("sha256_signed")
        if digest:
            known.setdefault(digest, []).append(record)

    for record in loaded.records:
        event = record.get("event")
        if event == ledger.PUBLISHED_EVENT:
            report.findings.append(Finding(record=record, verdict=PUBLISHED))
            continue
        if event == ledger.RELOCATED_EVENT:
            report.findings.append(Finding(record=record, verdict=RELOCATED))
            continue

        path = str(record.get("file") or "")
        finding = Finding(record=record)
        if not path or not os.path.isfile(path):
            finding.verdict = GONE
            report.findings.append(finding)
            continue

        current = ledger.hash_file(path)
        finding.current_hash = current
        own = signer.own_signature(path)
        finding.signer_thumbprint = own.thumbprint

        # The order of these questions is the design. "Does it still carry a signature" is asked
        # before "do the bytes match", because the answer a person needs first is whether a
        # signature is there at all.
        #
        # And a detail worth knowing, because it looks like a mistake until you have measured it:
        # removing a signature does **not** restore the file to its pre-signing bytes. Signing
        # rewrites the PE checksum, and stripping the table does not put it back, so a file whose
        # signature has been removed matches neither recorded hash. That is why "now unsigned" is
        # decided by the signature's absence rather than by a hash comparison.
        if not own.present:
            finding.verdict = NOW_UNSIGNED
            finding.detail = ("its bytes are the ones from before signing" if current == record.get("sha256_unsigned")
                              else "it carries no signature, and its bytes match neither recorded hash")
        elif current == record.get("sha256_signed"):
            if record.get("thumbprint") and own.thumbprint.upper() != str(record["thumbprint"]).upper():
                finding.verdict = CHANGED
                finding.detail = (f"the recorded signer is {str(record['thumbprint'])[:12]} but the "
                                  f"file carries {own.thumbprint[:12]}")
            else:
                finding.verdict = UNCHANGED
        else:
            others = [r for r in known.get(current, []) if r.get("t") != record.get("t")]
            if others:
                finding.verdict = SUPERSEDED
                finding.replaced_by = sorted(others, key=lambda r: str(r.get("t")))[-1]
            else:
                finding.verdict = CHANGED
        report.findings.append(finding)
    return report


def summarise(report: Report) -> str:
    """One sentence with the number that matters in it, separated from the numbers that do not."""
    tally = report.counts()
    parts = [
        f"{len(report.findings)} record(s)",
        f"{tally.get(UNCHANGED, 0)} unchanged",
        f"{tally.get(SUPERSEDED, 0)} superseded by a later signing",
        f"{tally.get(CHANGED, 0)} changed by something this ledger has no record of",
        f"{tally.get(NOW_UNSIGNED, 0)} now unsigned",
        f"{tally.get(GONE, 0)} gone",
    ]
    line = ", ".join(parts)
    if tally.get(PUBLISHED):
        line += f"; {tally[PUBLISHED]} published"
    if report.broken_lines:
        line += f"; {report.broken_lines} line(s) did not parse"
    if report.chain.get("broken_at"):
        line += (f"; the chain does not line up at line(s) "
                 f"{', '.join(str(n) for n in report.chain['broken_at'])}")
    return line
