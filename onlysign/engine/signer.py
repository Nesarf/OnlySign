"""Putting a signature on a file, and checking that the right one landed.

Everything here is written the way it is because of something measured, and two of those
measurements are the reason this module is shaped the way it is.

**A verdict and a fact are different questions.** ``Get-AuthenticodeSignature`` consults the
machine's security catalogs as well as the file, so a Microsoft binary whose own signature has been
removed still comes back "signed by Microsoft", with a Microsoft timestamp, status Valid. Asking it
whether *our* signature landed therefore gets an answer about somebody else's. Two functions keep
the questions apart: :func:`windows_verdict` reports what Windows says, and :func:`own_signature`
reports what the file carries, read out of the file -- the signer through the SIP, and the timestamp
by finding a timestamp attribute in the signature table itself.

**A failed timestamp is not a rollback.** ``signtool`` restores the file when the timestamp
authority cannot be reached. ``Set-AuthenticodeSignature`` does not: it appends a complete signature
and leaves it there, so a failure would hand back a file that is signed but not stamped -- the one
state this tool exists to refuse, delivered silently. Measured, not assumed: what changes is the
length, the PE checksum, and the certificate-table entry, and nothing else. So the engine does the
rollback itself, and then proves it by comparing the file's hash with the hash from before.

The rest of the rules are older: a file is never signed twice, the signer is pinned by thumbprint,
and a signature with no timestamp is treated as a failure rather than as a signature.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from . import ledger, pe, ps

# Tried in order. One URL is a single point of failure for a step that is treated as fatal, and the
# machine this was written on could reach only some of them.
DEFAULT_TIMESTAMP_AUTHORITIES = (
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://timestamp.globalsign.com/tsa/r6advanced1",
)

BACKEND_POWERSHELL = "powershell"
BACKEND_SIGNTOOL = "signtool"


@dataclass
class Verdict:
    """What Windows says about a file's signature. It may be answered by a catalog entry."""

    status: str = ""
    present: bool = False
    thumbprint: str = ""
    subject: str = ""
    issuer: str = ""
    timestamped: bool = False
    timestamp_subject: str = ""


@dataclass
class OwnSignature:
    """The signature the file carries itself. Read from the file, so no catalog can answer."""

    present: bool = False
    thumbprint: str = ""
    subject: str = ""
    issuer: str = ""
    timestamped: bool = False

    def matches(self, thumbprint: str) -> bool:
        return bool(self.thumbprint) and self.thumbprint.upper() == thumbprint.replace(" ", "").upper()


@dataclass
class SignResult:
    path: str
    kind: str = pe.KIND_UNKNOWN
    ok: bool = False
    skipped: str = ""
    error: str = ""
    before_hash: str = ""
    after_hash: str = ""
    signature: OwnSignature | None = None
    verdict: Verdict | None = None
    backend: str = ""
    timestamp_authority: str = ""
    attempts: list[str] = field(default_factory=list)
    restored: bool | None = None

    def to_record(self, *, note: str = "", signer: str = "") -> dict[str, Any]:
        """The ledger record for this signing, in the shape the existing toolchain writes."""
        signature = self.signature or OwnSignature()
        return {
            "t": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "file": os.path.abspath(self.path),
            "name": os.path.basename(self.path),
            "size": os.path.getsize(self.path) if os.path.exists(self.path) else 0,
            "sha256_signed": self.after_hash,
            "sha256_unsigned": self.before_hash,
            "signer": signer or signature.subject,
            "thumbprint": signature.thumbprint,
            "timestamped": signature.timestamped,
            "tsa": self.timestamp_authority,
            "backend": self.backend,
            "note": note,
        }


# --- asking the two questions -------------------------------------------------- #

def _verdict_body(path: str) -> str:
    return "\n".join([
        "$signature = Get-AuthenticodeSignature -LiteralPath " + ps.literal(path),
        "$thumbprint = ''", "$subject = ''", "$issuer = ''",
        "if ($signature.SignerCertificate) {",
        "  $thumbprint = $signature.SignerCertificate.Thumbprint",
        "  $subject = $signature.SignerCertificate.Subject",
        "  $issuer = $signature.SignerCertificate.Issuer",
        "}",
        "$stampSubject = ''",
        "if ($signature.TimeStamperCertificate) { $stampSubject = $signature.TimeStamperCertificate.Subject }",
        "[pscustomobject]@{",
        "  status = \"$($signature.Status)\"",
        "  present = [bool]$signature.SignerCertificate",
        "  thumbprint = $thumbprint",
        "  subject = $subject",
        "  issuer = $issuer",
        "  timestamped = [bool]$signature.TimeStamperCertificate",
        "  timestamp_subject = $stampSubject",
        "}",
    ])


def _own_body(path: str) -> str:
    # CreateFromSignedFile reads the signature attached to the file, through the same subject
    # interface package that put it there. A catalog is not consulted, which is the whole reason
    # this question is asked separately.
    #
    # The thumbprint comes from GetCertHashString() rather than from the Thumbprint property, and
    # that is a measurement rather than a preference: this method returns a base X509Certificate
    # whose RawData is an empty array and whose Thumbprint is null, so the two most obvious ways to
    # ask both answer with nothing. GetCertHashString() returns the SHA-1 of the certificate, which
    # is what a thumbprint is.
    return "\n".join([
        "$thumbprint = ''", "$subject = ''", "$issuer = ''",
        "try {",
        "  $own = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromSignedFile("
        + ps.literal(path) + ")",
        "  $thumbprint = $own.GetCertHashString()",
        "  $subject = $own.Subject",
        "  $issuer = $own.Issuer",
        "} catch { }",
        "[pscustomobject]@{ thumbprint = $thumbprint; subject = $subject; issuer = $issuer }",
    ])


def windows_verdict(path: str | os.PathLike[str]) -> Verdict:
    row = ps.one(_verdict_body(str(path)), timeout=60.0) or {}
    return Verdict(
        status=str(row.get("status") or ""),
        present=bool(row.get("present")),
        thumbprint=str(row.get("thumbprint") or ""),
        subject=str(row.get("subject") or ""),
        issuer=str(row.get("issuer") or ""),
        timestamped=bool(row.get("timestamped")),
        timestamp_subject=str(row.get("timestamp_subject") or ""),
    )


def _container_signature(path: str) -> OwnSignature:
    NL = chr(10)
    """The signature a package carries inside itself, read from the file rather than from Windows.

    An MSI keeps its signature as one stream among many in a compound file, and the .NET call that
    reads a PE's signature does not know how to find it -- so before this, an MSI reported that it
    carried no signature at all, and the only answer left was the machine's verdict, which consults
    security catalogs and can therefore be answering about somebody else's signature. Reading the
    PKCS#7 out of the container removes that: the answer stops depending on what this machine has
    been told to trust.
    """
    from . import container
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return OwnSignature()
    try:
        blob = container.CompoundFile(data).stream(container.MSI_SIGNATURE_STREAM)
    except ValueError:
        blob = None
    if not blob:
        return OwnSignature()
    encoded = base64.b64encode(blob).decode("ascii")
    script = (
        # Windows PowerShell does not resolve SignedCms without being told to load the assembly that
        # carries it, so asking for a package's own signature failed on 5.1 with "type not found"
        # while working on 7. The load is allowed to fail rather than abort, because the editions
        # differ in whether the name resolves at all and 7 does not need it.
        "try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }" + NL
        + "$bytes = [Convert]::FromBase64String('" + encoded + "')" + NL
        + "$cms = New-Object System.Security.Cryptography.Pkcs.SignedCms" + NL
        + "$cms.Decode($bytes)" + NL
        + "$info = $cms.SignerInfos[0]" + NL
        + "$cert = $info.Certificate" + NL
        + "$stamped = ($info.CounterSignerInfos.Count -gt 0)" + NL
        + "foreach ($attr in $info.UnsignedAttributes) {" + NL
        + "  $oid = $attr.Oid.Value" + NL
        + "  if ($oid -eq '1.3.6.1.4.1.311.3.3.1' -or $oid -eq '1.2.840.113549.1.9.6') { $stamped = $true }" + NL
        + "}" + NL
        + "[pscustomobject]@{ thumbprint = $cert.GetCertHashString(); subject = $cert.Subject; "
        + "issuer = $cert.Issuer; timestamped = [bool]$stamped }"
    )
    row = ps.one(script, timeout=60.0) or {}
    thumbprint = str(row.get("thumbprint") or "")
    if not thumbprint:
        return OwnSignature()
    return OwnSignature(present=True, thumbprint=thumbprint,
                        subject=str(row.get("subject") or ""),
                        issuer=str(row.get("issuer") or ""),
                        timestamped=bool(row.get("timestamped")))


def own_signature(path: str | os.PathLike[str]) -> OwnSignature:
    """The signature the file carries, or an empty one when it carries none."""
    if not os.path.isfile(path):
        return OwnSignature()
    if pe.identify(path) == pe.KIND_MSI:
        found = _container_signature(str(path))
        if found.present:
            return found
    row = ps.one(_own_body(str(path)), timeout=60.0) or {}
    thumbprint = str(row.get("thumbprint") or "")
    if not thumbprint:
        return OwnSignature()
    if pe.identify(path) == pe.KIND_PE:
        timestamped = pe.has_timestamp_attribute(path)
    else:
        # The signature is inside a container this tool does not parse, so the only answer available
        # is the one Windows gives -- which may be about a catalog. Recorded as a limitation rather
        # than dressed up as a fact.
        timestamped = windows_verdict(path).timestamped
    return OwnSignature(
        present=True,
        thumbprint=thumbprint,
        subject=str(row.get("subject") or ""),
        issuer=str(row.get("issuer") or ""),
        timestamped=timestamped,
    )


def carries_own_signature(path: str | os.PathLike[str]) -> bool:
    return own_signature(path).present


# --- the two backends --------------------------------------------------------- #

def find_signtool() -> str | None:
    """The SDK's signer, if this machine has one.

    Architecture is chosen before version, because sorting the full paths mixes them together and
    'x86' sorts after 'x64' -- which is how a machine with both ends up signing with the 32-bit one.
    """
    found = shutil.which("signtool.exe")
    if found:
        return found
    roots = [os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")]
    for arch in ("x64", "arm64", "x86"):
        candidates: list[str] = []
        for root in roots:
            if not root:
                continue
            kits = os.path.join(root, "Windows Kits", "10", "bin")
            if not os.path.isdir(kits):
                continue
            for version in os.listdir(kits):
                candidate = os.path.join(kits, version, arch, "signtool.exe")
                if os.path.isfile(candidate):
                    candidates.append(candidate)
        if candidates:
            return sorted(candidates)[-1]
    return None


def _sign_body(path: str, thumbprint: str, timestamp_url: str | None) -> str:
    parts = [
        # The key is taken from the certificate store rather than from a file, so no password is
        # ever placed on a command line -- where every process on the machine can read it.
        "$certificate = Get-ChildItem ('Cert:\\CurrentUser\\My\\' + " + ps.literal(thumbprint) + ") -ErrorAction Stop",
        "if (-not $certificate) { throw 'no certificate with that thumbprint in the current user store' }",
        "$parameters = @{",
        "  FilePath = " + ps.literal(path),
        "  Certificate = $certificate",
        "  HashAlgorithm = 'SHA256'",
        "}",
    ]
    if timestamp_url:
        parts.append("$parameters.TimestampServer = " + ps.literal(timestamp_url))
    parts += [
        "$result = Set-AuthenticodeSignature @parameters",
        "[pscustomobject]@{ status = \"$($result.Status)\"; message = \"$($result.StatusMessage)\" }",
    ]
    return "\n".join(parts)


def _sign_with_powershell(path: str, thumbprint: str, timestamp_url: str | None) -> dict[str, Any]:
    return ps.one(_sign_body(path, thumbprint, timestamp_url), timeout=300.0) or {}


def _sign_with_signtool(exe: str, path: str, thumbprint: str, timestamp_url: str | None) -> dict[str, Any]:
    arguments = [exe, "sign", "/sha1", thumbprint, "/fd", "SHA256"]
    if timestamp_url:
        arguments += ["/tr", timestamp_url, "/td", "SHA256"]
    arguments += ["/d", os.path.splitext(os.path.basename(path))[0], path]
    proc = subprocess.run(arguments, capture_output=True, timeout=300,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return {
        "status": "ok" if proc.returncode == 0 else "failed",
        "message": (proc.stdout + proc.stderr).decode("utf-8", "replace").strip()[-600:],
    }


# --- signing ------------------------------------------------------------------ #

def sign_file(path: str | os.PathLike[str], *, thumbprint: str,
              timestamp_authorities: Iterable[str] = DEFAULT_TIMESTAMP_AUTHORITIES,
              allow_untimestamped: bool = False, force: bool = False,
              backend: str = BACKEND_POWERSHELL) -> SignResult:
    """Sign one file, and report exactly what happened to it -- including what it looks like now."""
    path = os.path.abspath(str(path))
    result = SignResult(path=path)
    if not os.path.isfile(path):
        result.error = "no such file"
        return result

    result.kind = pe.identify(path)
    if not pe.signable(result.kind):
        result.skipped = f"{pe.describe(result.kind)} -- not something Authenticode signs"
        return result

    existing = own_signature(path)
    if existing.present and not force:
        result.skipped = (f"already carries a signature from {existing.subject}; signing again would "
                          f"append a second one and make the record of this signing describe the "
                          f"previous signature's output")
        result.signature = existing
        return result

    result.before_hash = ledger.hash_file(path)
    original = pe.capture_state(path)

    if backend == BACKEND_SIGNTOOL:
        exe = find_signtool()
        if not exe:
            result.error = "signtool was asked for and is not on this machine"
            return result
        result.backend = BACKEND_SIGNTOOL
        attempt = lambda url: _sign_with_signtool(exe, path, thumbprint, url)  # noqa: E731
    else:
        result.backend = BACKEND_POWERSHELL
        attempt = lambda url: _sign_with_powershell(path, thumbprint, url)  # noqa: E731

    def roll_back(reason: str) -> None:
        """Undo an attempt that did not produce a signature worth keeping, and say whether it worked."""
        result.error = reason
        if original is None:
            result.restored = None
            result.after_hash = ledger.hash_file(path)
            return
        dropped = pe.restore_state(path, original)
        result.after_hash = ledger.hash_file(path)
        result.restored = (result.after_hash == result.before_hash)
        if result.restored:
            result.error = reason + f" (the file was put back: {dropped} byte(s) removed, hash unchanged)"
        else:
            result.error = (reason + " and the file could NOT be put back exactly as it was; its hash "
                                     "has changed and it should be restored from a copy")
        result.signature = own_signature(path)

    last_error = ""
    stamped = False
    authorities = list(timestamp_authorities) or []
    for url in authorities:
        try:
            outcome = attempt(url)
        except Exception as exc:                                  # noqa: BLE001 - the backend may throw
            outcome = {"status": "failed", "message": str(exc)}
        result.attempts.append(url)
        last_error = str(outcome.get("message", "")) if isinstance(outcome, dict) else ""

        signature = own_signature(path)
        if signature.present and signature.timestamped:
            result.timestamp_authority = url
            stamped = True
            break
        if signature.present and not signature.timestamped:
            # The backend left a signature that can never outlive the certificate, and signing again
            # on top of it would append a second one. Back the whole attempt out instead.
            roll_back(f"{url} produced a signature without a timestamp; the attempt was undone rather "
                      f"than left half-made")
            return result

    if not stamped and authorities:
        if not allow_untimestamped:
            roll_back("no timestamp was obtained from " + ", ".join(result.attempts) +
                      "; a signature without one stops verifying when the certificate expires")
            return result
        try:
            attempt(None)
        except Exception as exc:                                  # noqa: BLE001
            last_error = str(exc)

    signature = own_signature(path)
    if not signature.present:
        result.error = f"the file carries no signature after signing: {last_error}".strip(": ")
        result.signature = signature
        result.after_hash = ledger.hash_file(path)
        return result

    if not signature.matches(thumbprint):
        roll_back(f"the file was signed by {signature.thumbprint} but {thumbprint} was chosen")
        return result

    result.ok = True
    result.signature = signature
    result.after_hash = ledger.hash_file(path)
    result.verdict = windows_verdict(path)
    return result
