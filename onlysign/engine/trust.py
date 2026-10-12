"""The trust stores, and what installing into each one actually changes.

Two stores, two jobs, and they are not interchangeable:

**Trusted Root Certification Authorities** holds trust anchors. Windows builds a chain from the
signer upward and asks whether it ends somewhere it trusts. A self-signed certificate *is* its own
root, so this is the store that decides whether anything verifies. Nothing substitutes for it.

**Trusted Publishers** is a statement that this publisher is one you accept -- consulted by
installers and by some policies. It is not an anchor. With a certificate only there,
``Get-AuthenticodeSignature`` still reports no valid signature at all.

So "install trust" is really two answers to two questions, and this module refuses to blur them: it
reports the state of all four stores after acting, rather than a count of its own successes.

Three more things worth knowing before using it:

* a trust store is a statement about **this machine**, not about the artifact. Installing one here
  changes nothing on anyone else's. The artifact travels with its signature; the trust has to be
  established separately, wherever it matters;
* writing ``LocalMachine\\Root`` is silent **when the session is already elevated**, because the
  elevation is the consent. Writing ``CurrentUser\\Root`` shows a prompt, and that prompt is the
  defence against a program installing its own root of trust -- so it is left to the person, not
  routed around;
* a root store is a claim of authority. It is an acceptable claim while the key signs software and
  never issues another certificate, and that discipline is what keeps "this machine trusts us"
  meaning "this machine trusts what we signed" and nothing wider.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass

from . import certs, ps

USER_PUBLISHERS = "Cert:\\CurrentUser\\TrustedPublisher"
USER_ROOT = "Cert:\\CurrentUser\\Root"
MACHINE_PUBLISHERS = "Cert:\\LocalMachine\\TrustedPublisher"
MACHINE_ROOT = "Cert:\\LocalMachine\\Root"

STORES = (USER_PUBLISHERS, USER_ROOT, MACHINE_PUBLISHERS, MACHINE_ROOT)

SCOPE_USER = "user"
SCOPE_MACHINE = "machine"


@dataclass
class StoreState:
    store: str
    count: int


def elevated() -> bool:
    """Whether this process can write a machine-wide store without being asked."""
    script = ("([Security.Principal.WindowsPrincipal]::new("
              "[Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("
              "[Security.Principal.WindowsBuiltInRole]::Administrator)")
    return bool(ps.one(script))


def counts(thumbprint: str) -> list[StoreState]:
    """How many entries for this certificate each store holds."""
    wanted = thumbprint.replace(" ", "").upper()
    lines = ["$wanted = " + ps.literal(wanted), "$out = @()"]
    for store in STORES:
        lines += [
            "$n = 0",
            "foreach ($c in @(Get-ChildItem " + ps.literal(store) + " -ErrorAction SilentlyContinue)) {",
            "  if ($c.Thumbprint -eq $wanted) { $n++ }",
            "}",
            "$out += [pscustomobject]@{ store = " + ps.literal(store) + "; count = $n }",
        ]
    lines.append("$out")
    rows = ps.call("\n".join(lines), timeout=60.0) or []
    if isinstance(rows, dict):
        rows = [rows]
    return [StoreState(store=row["store"], count=int(row["count"])) for row in rows]


def root_anchored(thumbprint: str) -> bool:
    """Whether any root store holds it, which is the thing that decides whether anything verifies."""
    return any(state.count > 0 for state in counts(thumbprint)
               if state.store.endswith("\\Root"))


def verdict(thumbprint: str) -> str:
    """What the current state of the stores means, in one sentence."""
    states = {state.store: state.count for state in counts(thumbprint)}
    roots = states.get(USER_ROOT, 0) + states.get(MACHINE_ROOT, 0)
    publishers = states.get(USER_PUBLISHERS, 0) + states.get(MACHINE_PUBLISHERS, 0)
    if roots:
        where = "this account" if states.get(USER_ROOT) else "every account on this machine"
        return f"a root store holds it ({where}), so signatures verify here"
    if publishers:
        return ("only a publisher store holds it, which changes no verdict anywhere: signatures "
                "still report nothing valid. A root store is what decides")
    return "no store holds it, so signatures report nothing valid on this machine"


def install(thumbprint: str, *, scope: str = SCOPE_USER,
            publishers: bool = True, roots: bool = True,
            cer_path: str = "") -> list[str]:
    """Put the public half of a certificate into the stores that were asked for.

    Returns the stores written to. Raises if a machine-wide install is asked for without the
    elevation that would make it silent, because the alternative is a prompt appearing from nowhere.
    """
    if not publishers and not roots:
        raise ValueError("install was asked for with both stores declined, so there is nothing to do")
    if scope == SCOPE_MACHINE and not elevated():
        raise PermissionError(
            "writing a machine-wide store needs an elevated session; without it Windows would ask "
            "for a prompt, and a prompt raised by a background process is how consent stops meaning "
            "anything. Run again from an elevated console, or install for this account only.")

    cleanup = None
    if not cer_path:
        handle, temporary = tempfile.mkstemp(suffix=".cer", prefix="onlysign-trust-")
        os.close(handle)
        cleanup = temporary
        cer_path = temporary
        certs.export_public(thumbprint, cer_path)

    targets: list[str] = []
    if publishers:
        targets.append(USER_PUBLISHERS if scope == SCOPE_USER else MACHINE_PUBLISHERS)
    if roots:
        targets.append(USER_ROOT if scope == SCOPE_USER else MACHINE_ROOT)

    try:
        written: list[str] = []
        for store in targets:
            _remove_subject_entries(store, thumbprint)
            ps.call("Import-Certificate -FilePath " + ps.literal(cer_path)
                    + " -CertStoreLocation " + ps.literal(store) + " | Out-Null" + chr(10) + "'imported'",
                    timeout=120.0)
            written.append(store)
        return written
    finally:
        if cleanup:
            try:
                os.remove(cleanup)
            except OSError:
                pass


def remove(thumbprint: str) -> list[StoreState]:
    """Take the certificate out of every store, and report what is actually left."""
    wanted = thumbprint.replace(" ", "").upper()
    lines = ["$wanted = " + ps.literal(wanted), "$removed = 0"]
    for store in STORES:
        lines += [
            "foreach ($c in @(Get-ChildItem " + ps.literal(store) + " -ErrorAction SilentlyContinue)) {",
            "  if ($c.Thumbprint -eq $wanted) {",
            "    Remove-Item -Path (" + ps.literal(store) + " + '\\' + $c.Thumbprint) -Force -ErrorAction SilentlyContinue",
            "    $removed++",
            "  }",
            "}",
        ]
    lines.append("$removed")
    ps.one("\n".join(lines), timeout=60.0)
    return counts(thumbprint)


def _remove_subject_entries(store: str, thumbprint: str) -> None:
    """Drop this certificate's earlier entries before adding one.

    Without this, installing twice leaves the same certificate in the store twice, which is how a
    store ends up with several entries for one identity and a chain that reports more than it means.
    """
    script = "\n".join([
        "foreach ($c in @(Get-ChildItem " + ps.literal(store) + " -ErrorAction SilentlyContinue)) {",
        "  if ($c.Thumbprint -eq " + ps.literal(thumbprint.replace(" ", "").upper()) + ") {",
        "    Remove-Item -Path (" + ps.literal(store) + " + '\\' + $c.Thumbprint) -Force -ErrorAction SilentlyContinue",
        "  }",
        "}",
        "'pruned'",
    ])
    ps.one(script, timeout=60.0)
