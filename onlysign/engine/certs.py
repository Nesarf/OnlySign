"""Certificates: what is available to sign with, and how one comes to exist.

Two of the three functions here exist because "usable by anyone" fails at step one otherwise. Most
people do not own a code signing certificate and have never made one, so a tool that can only use a
certificate you already have is a tool for people who did not need it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import ps

CODE_SIGNING_EKU = "1.3.6.1.5.5.7.3.3"

_LIST_SCRIPT = r"""
$stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
foreach ($store in $stores) {
  foreach ($cert in @(Get-ChildItem $store -ErrorAction SilentlyContinue)) {
    if (-not $cert.HasPrivateKey) { continue }
    $ekuExtension = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
    $usage = @()
    if ($ekuExtension) { $usage = @($ekuExtension.EnhancedKeyUsages | ForEach-Object { $_.Value }) }
    [pscustomobject]@{
      thumbprint   = $cert.Thumbprint
      subject      = $cert.Subject
      issuer       = $cert.Issuer
      notafter     = $cert.NotAfter.ToUniversalTime().ToString('o')
      notbefore    = $cert.NotBefore.ToUniversalTime().ToString('o')
      store        = $store
      hasusage     = [bool]$ekuExtension
      usage        = $usage
      selfsigned   = ($cert.Subject -eq $cert.Issuer)
    }
  }
}
"""


@dataclass
class Certificate:
    thumbprint: str
    subject: str
    issuer: str
    not_after: datetime
    not_before: datetime
    store: str
    usage: list[str]
    usage_restricted: bool
    self_signed: bool

    @property
    def permits_code_signing(self) -> bool:
        """A certificate with no usage restriction permits everything, code signing included."""
        if not self.usage_restricted:
            return True
        return CODE_SIGNING_EKU in self.usage

    @property
    def expired(self) -> bool:
        return self.not_after <= datetime.now(timezone.utc)

    def days_left(self) -> int:
        return int((self.not_after - datetime.now(timezone.utc)).days)

    def short(self) -> str:
        state = "expired" if self.expired else f"{self.days_left()}d left"
        return f"{self.thumbprint[:8]}  {self.subject}  [{state}]"


def _from_row(row: dict[str, Any]) -> Certificate:
    return Certificate(
        thumbprint=row["thumbprint"],
        subject=row["subject"],
        issuer=row["issuer"],
        not_after=datetime.fromisoformat(row["notafter"].replace("Z", "+00:00")),
        not_before=datetime.fromisoformat(row["notbefore"].replace("Z", "+00:00")),
        store=row["store"],
        usage=list(row.get("usage") or []),
        usage_restricted=bool(row.get("hasusage")),
        self_signed=bool(row.get("selfsigned")),
    )


def list_certificates() -> list[Certificate]:
    """Every certificate on this machine that has a private key and could sign something."""
    raw = ps.call(_LIST_SCRIPT)
    if raw is None:
        return []
    if isinstance(raw, dict):
        raw = [raw]
    return [_from_row(row) for row in raw]


def find(thumbprint: str) -> Certificate | None:
    wanted = thumbprint.replace(" ", "").upper()
    for certificate in list_certificates():
        if certificate.thumbprint.upper() == wanted:
            return certificate
    return None


def resolve(spec: str) -> Certificate:
    """Find a certificate from something a person would actually type.

    A full thumbprint is tedious to type and a subject is not unique, so this accepts either: an
    exact thumbprint, an unambiguous prefix of one, or a substring of the subject. An ambiguous
    answer is an error listing the candidates rather than a guess -- choosing a signing identity on
    someone's behalf is not a favour.
    """
    if not spec:
        raise LookupError("no certificate was named")
    certificates = list_certificates()
    wanted = spec.replace(" ", "").upper()
    for certificate in certificates:
        if certificate.thumbprint.upper() == wanted:
            return certificate
    prefix = [c for c in certificates if c.thumbprint.upper().startswith(wanted)]
    if len(prefix) == 1:
        return prefix[0]
    by_subject = [c for c in certificates if spec.lower() in c.subject.lower()]
    if len(by_subject) == 1:
        return by_subject[0]
    matches = prefix or by_subject
    if not matches:
        raise LookupError(
            f"no certificate matches {spec!r} among {len(certificates)} that have a private key")
    listing = "\n".join(f"  {c.thumbprint}  {c.subject}" for c in matches)
    raise LookupError(f"{spec!r} matches more than one certificate:\n{listing}")


def create_self_signed(subject: str, *, years: int = 5, password: str,
                       pfx_path: str | None = None, cer_path: str | None = None) -> Certificate:
    """Make a self-signed code signing certificate and, if asked, write out its two halves.

    A self-signed certificate is not a lesser thing that a commercial one would improve on: it is
    the only form that can state an organization the certificate authorities have no category for,
    and it keeps the root of trust with whoever made the software. What it costs is stated plainly
    elsewhere in this project -- a stranger's Windows will not verify it.
    """
    script = r"""
$secure = ConvertTo-SecureString """ + ps.literal(password) + r""" -AsPlainText -Force
$cert = New-SelfSignedCertificate `
    -Subject """ + ps.literal(subject) + r""" `
    -Type CodeSigningCert `
    -KeyUsage DigitalSignature `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -NotAfter (Get-Date).AddYears(""" + str(int(years)) + r""") `
    -KeyExportPolicy Exportable
if (""" + ps.literal(pfx_path or "") + r""") {
  Export-PfxCertificate -Cert $cert -FilePath """ + ps.literal(pfx_path) + r""" -Password $secure | Out-Null
}
if (""" + ps.literal(cer_path or "") + r""") {
  Export-Certificate -Cert $cert -FilePath """ + ps.literal(cer_path) + r""" -Type CERT | Out-Null
}
$cert | Select-Object Thumbprint, Subject, Issuer,
    @{n='NotAfter';e={$_.NotAfter.ToUniversalTime().ToString('o')}},
    @{n='NotBefore';e={$_.NotBefore.ToUniversalTime().ToString('o')}}
"""
    row = ps.one(script, timeout=120.0)
    if pfx_path:
        harden(pfx_path)
    if cer_path:
        harden(cer_path)
    return Certificate(
        thumbprint=row["Thumbprint"],
        subject=row["Subject"],
        issuer=row["Issuer"],
        not_after=datetime.fromisoformat(row["NotAfter"].replace("Z", "+00:00")),
        not_before=datetime.fromisoformat(row["NotBefore"].replace("Z", "+00:00")),
        store="Cert:\\CurrentUser\\My",
        usage=[CODE_SIGNING_EKU],
        usage_restricted=False,
        self_signed=True,
    )


def export_public(thumbprint: str, cer_path: str) -> None:
    """Write out the public half, which is the part meant to be given away."""
    script = r"""
$cert = Get-ChildItem ('Cert:\CurrentUser\My\' + """ + ps.literal(thumbprint) + r""") -ErrorAction Stop
Export-Certificate -Cert $cert -FilePath """ + ps.literal(cer_path) + r""" -Type CERT | Out-Null
$cert.Thumbprint
"""
    ps.one(script, timeout=60.0)


def import_pfx(pfx_path: str, *, password: str, machine: bool = False) -> Certificate:
    """Bring an existing key in, so a certificate that lives in a file can be used like any other."""
    store = "Cert:\\LocalMachine\\My" if machine else "Cert:\\CurrentUser\\My"
    script = r"""
$secure = ConvertTo-SecureString """ + ps.literal(password) + r""" -AsPlainText -Force
$imported = Import-PfxCertificate -FilePath """ + ps.literal(pfx_path) + r""" `
    -CertStoreLocation """ + ps.literal(store) + r""" -Password $secure
$imported | Select-Object Thumbprint, Subject, Issuer,
    @{n='NotAfter';e={$_.NotAfter.ToUniversalTime().ToString('o')}},
    @{n='NotBefore';e={$_.NotBefore.ToUniversalTime().ToString('o')}}
"""
    row = ps.one(script, timeout=120.0)
    return Certificate(
        thumbprint=row["Thumbprint"], subject=row["Subject"], issuer=row["Issuer"],
        not_after=datetime.fromisoformat(row["NotAfter"].replace("Z", "+00:00")),
        not_before=datetime.fromisoformat(row["NotBefore"].replace("Z", "+00:00")),
        store=store, usage=[], usage_restricted=False, self_signed=False,
    )


def harden(path: str | os.PathLike[str]) -> str:
    """Take a file out from under inherited permissions, keeping three principals and no more.

    This is not caution for its own sake. On the machine this tool was written on, the password file
    had been locked down and the private key beside it had not: the key was readable *and writable*
    by every authenticated user, while the file guarding it was restricted to one account. Doing
    this for both halves is the difference between a hardening step and a gesture.

    Inheritance is dropped rather than edited, because the inherited entries are the ones that hand
    the file to everyone. The three re-granted principals are the account that owns it, the
    administrators of the machine, and the system itself -- fewer than that risks locking the owner
    out of their own key, which is the one failure nobody can undo.
    """
    path = str(path)
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    script = r"""
$target = """ + ps.literal(path) + r"""
$item = Get-Item -LiteralPath $target -Force
$acl = $item.GetAccessControl()
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$added = 0
foreach ($who in @($me, 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
  try {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'Allow')))
    $added++
  } catch { }
}
if ($added -eq 0) { throw 'refusing to write an access list with no entries in it' }
$item.SetAccessControl($acl)
$added
"""
    ps.one(script, timeout=60.0)
    return path
