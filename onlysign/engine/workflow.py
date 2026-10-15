"""Turning a decision into a signing run.

Everything above this module answers one question. This one puts the answers in order, and the order
is the part with a rule in it:

* **signing comes last.** An Authenticode signature covers the file, so anything that rewrites the
  file afterwards destroys it. Nothing in this workflow touches a signed artifact except to copy it
  somewhere else, and a copy is a new file with its own record;
* **the record is written after the file is signed, from hashes taken before and after**, because
  "which bytes did we sign" and "what was the build" are different questions with different answers;
* **a copy is recorded as a relocation, not by rewriting the signing record.** The chain is only
  worth something while past lines are never rewritten, so "where it went" is a new line. It also
  keeps the honest answer to both questions: it was signed *there*, and it lives *here* now;
* **trust is installed after signing, never before.** The artifacts are the point; if the store
  refuses, the work is not lost.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from . import certs, ledger, pe, signer, trust

TRUST_NONE = "none"
TRUST_USER_PUBLISHERS = "user-publishers"
TRUST_USER_ROOT = "user-root"
TRUST_USER_BOTH = "user-both"
TRUST_MACHINE_BOTH = "machine-both"

TRUST_CHOICES = (TRUST_NONE, TRUST_USER_PUBLISHERS, TRUST_USER_ROOT, TRUST_USER_BOTH,
                 TRUST_MACHINE_BOTH)

TRUST_DESCRIPTION = {
    TRUST_NONE: "leave the trust stores alone",
    TRUST_USER_PUBLISHERS: "this account: a statement about the publisher, which changes no verdict",
    TRUST_USER_ROOT: "this account: the trust anchor, so signatures verify here (Windows asks once)",
    TRUST_USER_BOTH: "this account: both stores, which is what the prompt is for",
    TRUST_MACHINE_BOTH: "every account on this machine: both stores, needs an elevated session",
}


@dataclass
class Plan:
    paths: list[str] = field(default_factory=list)
    thumbprint: str = ""
    note: str = ""
    ledger_path: str = ""
    timestamp_authorities: tuple[str, ...] = signer.DEFAULT_TIMESTAMP_AUTHORITIES
    allow_untimestamped: bool = False
    force: bool = False
    backend: str = signer.BACKEND_POWERSHELL
    output_dir: str = ""
    trust: str = TRUST_NONE

    def certificate(self) -> certs.Certificate:
        found = certs.find(self.thumbprint)
        if found is None:
            raise LookupError(f"no certificate with the thumbprint {self.thumbprint} on this machine")
        return found

    def ledger_at(self) -> str:
        return self.ledger_path or os.path.join(os.getcwd(), ".onlysign", "signings.ndjson")


@dataclass
class Outcome:
    results: list[signer.SignResult] = field(default_factory=list)
    records: list[dict] = field(default_factory=list)
    copies: list[tuple[str, str]] = field(default_factory=list)
    trust_written: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def signed(self) -> list[signer.SignResult]:
        return [r for r in self.results if r.ok]

    @property
    def skipped(self) -> list[signer.SignResult]:
        return [r for r in self.results if r.skipped]

    @property
    def failed(self) -> list[signer.SignResult]:
        return [r for r in self.results if not r.ok and not r.skipped]

    def summary(self) -> str:
        return (f"{len(self.signed)} signed, {len(self.skipped)} skipped, "
                f"{len(self.failed)} failed, {len(self.copies)} copied")


def preview(plan: Plan) -> list[str]:
    """What would happen, in words, without touching anything."""
    lines: list[str] = []
    certificate = plan.certificate()
    lines.append(f"certificate : {certificate.subject}")
    lines.append(f"              {certificate.thumbprint}"
                 f"  ({'expired' if certificate.expired else str(certificate.days_left()) + ' days left'})")
    if not certificate.permits_code_signing:
        lines.append("              WARNING: this certificate does not permit code signing")
    lines.append(f"backend     : {plan.backend}")
    lines.append(f"ledger      : {plan.ledger_at()}")
    if plan.output_dir:
        lines.append(f"copies go to: {plan.output_dir}")
    lines.append(f"trust       : {plan.trust} -- {TRUST_DESCRIPTION.get(plan.trust, '?')}")
    if plan.allow_untimestamped:
        lines.append("timestamps  : NOT REQUIRED -- a signature without one stops verifying when the "
                     "certificate expires")
    else:
        lines.append(f"timestamps  : {', '.join(plan.timestamp_authorities)} in order")
    lines.append("")
    for path in plan.paths:
        if not os.path.isfile(path):
            lines.append(f"  MISSING  {path}")
            continue
        kind = pe.identify(path)
        own = signer.own_signature(path)
        state = f"already signed by {own.subject}" if own.present else "unsigned"
        mark = "would sign" if (pe.signable(kind) and not own.present) or plan.force else "would skip"
        lines.append(f"  {mark:<10} {os.path.basename(path)}  [{pe.describe(kind)}, {state}]")
    return lines


def execute(plan: Plan, *, dry_run: bool = True,
            progress: Callable[[str], None] | None = None) -> Outcome:
    """Carry out a plan. With ``dry_run`` the files are not touched and the ledger is not written."""
    say = progress or (lambda _message: None)
    outcome = Outcome()
    if dry_run:
        raise ValueError("execute() is the real thing; use preview() for a dry run")

    certificate = plan.certificate()
    destination = plan.output_dir
    if destination:
        os.makedirs(destination, exist_ok=True)

    for path in plan.paths:
        say(f"signing {os.path.basename(path)}")
        result = signer.sign_file(
            path, thumbprint=plan.thumbprint,
            timestamp_authorities=plan.timestamp_authorities,
            allow_untimestamped=plan.allow_untimestamped, force=plan.force,
            backend=plan.backend)
        outcome.results.append(result)

        if result.skipped:
            say(f"  skipped: {result.skipped}")
            continue
        if not result.ok:
            say(f"  failed: {result.error}")
            continue

        record = result.to_record(note=plan.note)
        stored = ledger.append(plan.ledger_at(), record)
        outcome.records.append(stored)
        say(f"  signed and recorded ({result.timestamp_authority or 'no timestamp'})")
        if result.repaired:
            # Said out loud rather than left in the record: the bytes that were signed are not the bytes
            # the caller handed over. A stale certificate-table entry had to be cleared first, because a
            # file in that state cannot be timestamped at all -- see `pe._entry_claims_no_certificate`.
            say("    note: a stale certificate-table entry was cleared first; that repair is in the record")

        if destination:
            target = os.path.join(destination, os.path.basename(path))
            if os.path.abspath(target) != os.path.abspath(path):
                shutil.copy2(path, target)
                outcome.copies.append((path, target))
                ledger.append(plan.ledger_at(), {
                    "t": record["t"],
                    "event": ledger.RELOCATED_EVENT,
                    "file": record["file"],
                    "to": os.path.abspath(target),
                    "name": record["name"],
                    "sha256_signed": record["sha256_signed"],
                    "note": "a copy of the signed artifact",
                })
                say(f"  copied to {target}")

    if plan.trust != TRUST_NONE:
        scope = trust.SCOPE_MACHINE if plan.trust == TRUST_MACHINE_BOTH else trust.SCOPE_USER
        publishers = plan.trust in (TRUST_USER_PUBLISHERS, TRUST_USER_BOTH, TRUST_MACHINE_BOTH)
        roots = plan.trust in (TRUST_USER_ROOT, TRUST_USER_BOTH, TRUST_MACHINE_BOTH)
        try:
            outcome.trust_written = trust.install(plan.thumbprint, scope=scope,
                                                 publishers=publishers, roots=roots)
            for store in outcome.trust_written:
                say(f"installed trust in {store}")
        except (PermissionError, ValueError) as exc:
            outcome.notes.append(f"trust was not installed: {exc}")
            say(f"trust was not installed: {exc}")
        outcome.notes.append(trust.verdict(plan.thumbprint))

    return outcome


def describe_outcome(outcome: Outcome) -> Iterable[str]:
    for line in outcome.notes:
        yield line
    if outcome.failed:
        yield ""
        yield "failed:"
        for result in outcome.failed:
            yield f"  {os.path.basename(result.path)}: {result.error}"
    if outcome.skipped:
        yield ""
        yield "skipped:"
        for result in outcome.skipped:
            yield f"  {os.path.basename(result.path)}: {result.skipped}"
