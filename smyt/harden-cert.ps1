# Option C for the S.M.Y.T. signing certificate: stop this machine trusting it, and make the store key
# non-exportable.
#
# WHY EACH STEP, because a security change without a stated reason is just a change:
#
#   remove the trust   The machine treats this self-signed certificate as an anchor, so anything signed
#                      with its key is accepted here as Valid. Any process running as this account can
#                      use that key directly -- no password, no export -- so the only lever that reduces
#                      the blast radius is not trusting the result. Signing is unaffected: it needs the
#                      key, not the trust.
#
#   non-exportable key A CNG key's export policy cannot be flipped in place; there is no API for it. So
#                      the key is re-created by importing the SAME pfx without -Exportable: the public
#                      key is unchanged, so the certificate and its thumbprint are unchanged, and
#                      everything signed before still verifies against the same certificate.
#
#   the pfx            Left exactly where it is. It is the only copy of the key material and therefore
#                      the safety net for this operation; the password file beside it is dealt with
#                      separately, because that involves a secret this script must not handle.
param([switch]$Apply)

$ErrorActionPreference = 'Continue'
$env:PSModulePath = (Join-Path $PSHOME 'Modules')

$thumb = '4EA54E72A1EEFAE280B99631F7680DBFF461C4F1'
$signingDir = 'D:\DaShaoHuo\build-artifacts\signing'
$pfx = Join-Path $signingDir 'smyt-codesign.pfx'
$pwFile = Join-Path $signingDir 'pfx-password.txt'
$store = 'Cert:\CurrentUser\My'

function Show-State([string]$label) {
  Write-Host ("  --- {0}" -f $label)
  foreach ($s in @('LocalMachine\Root', 'LocalMachine\TrustedPublisher', 'LocalMachine\CA',
                   'CurrentUser\Root', 'CurrentUser\TrustedPublisher', 'CurrentUser\CA', 'CurrentUser\My')) {
    $hit = @(Get-ChildItem -Path ('Cert:\' + $s) -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb })
    Write-Host ('    {0,-32} {1}' -f $s, $(if ($hit.Count) { 'present' } else { '-' }))
  }
  $c = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb }
  if ($c) {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
    if ($rsa) { Write-Host ('    private key export policy        {0}' -f $rsa.Key.ExportPolicy) }
  }
  # A count that must be non-zero, so an empty answer cannot be mistaken for an answer.
  Write-Host ('    (self-check: LocalMachine\Root holds {0} entries)' -f @(Get-ChildItem 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue).Count)
  Write-Host ''
}

Write-Host '  BEFORE'
Show-State 'current state'

if (-not $Apply) {
  Write-Host '  dry run: nothing changed. Pass -Apply to do it.'
  exit 0
}

if (-not (Test-Path $pfx)) { Write-Host '  the pfx is missing -- refusing to touch the key without its backup.' -ForegroundColor Red; exit 1 }
# The password may be sealed or still in the clear; both are accepted, because this script's job is the
# key, not the storage convention. Written this way rather than dot-sourcing smyt-common so that the
# script that re-creates the key does not depend on the module it is re-creating around.
$pw = $null
$sealedPw = [System.IO.Path]::ChangeExtension($pwFile, '.sealed')
if (Test-Path -LiteralPath $sealedPw) {
  $opener = Join-Path $signingDir 'seal.mjs'
  if (-not (Test-Path -LiteralPath $opener)) { Write-Host "  the password is sealed but $opener is missing -- refusing." -ForegroundColor Red; exit 1 }
  $pw = (& node $opener open $sealedPw 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { Write-Host "  could not open $sealedPw -- refusing." -ForegroundColor Red; exit 1 }
} elseif (Test-Path -LiteralPath $pwFile) {
  $pw = (Get-Content -LiteralPath $pwFile -Raw -ErrorAction SilentlyContinue)
}
if (-not $pw) { Write-Host '  no password, sealed or plaintext -- refusing.' -ForegroundColor Red; exit 1 }
$pw = $pw.Trim()
$secure = ConvertTo-SecureString $pw -AsPlainText -Force

# THE PRECONDITION THAT MAKES THIS OPERATION SAFE, checked before anything is deleted: the pfx must
# open with the password beside it, and it must hold THIS certificate. Loading it in memory proves both
# without touching any store. Skipping this is how a "re-create the key" step becomes a key you no
# longer have.
try {
  $probe = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfx, $pw, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
  if (-not $probe.HasPrivateKey) { Write-Host '  the pfx opens but holds no private key -- refusing.' -ForegroundColor Red; exit 1 }
  if ($probe.Thumbprint -ne $thumb) {
    Write-Host ('  the pfx holds a DIFFERENT certificate ({0}) -- refusing.' -f $probe.Thumbprint) -ForegroundColor Red; exit 1
  }
  Write-Host ('  pfx check: opens with the password, holds the private key, certificate {0}' -f $probe.Thumbprint.Substring(0,8))
} catch {
  Write-Host ('  the pfx could not be opened with the password beside it: {0}' -f $_.Exception.Message) -ForegroundColor Red
  Write-Host '  refusing to remove the store key -- that backup is the only copy.' -ForegroundColor Red
  exit 1
}
Write-Host ''

# ---- 1. stop trusting it ----------------------------------------------------
Write-Host '  1. removing the trust (keeping only CurrentUser\My, where signing needs the key)'
foreach ($s in @('LocalMachine\Root', 'LocalMachine\TrustedPublisher', 'LocalMachine\CA',
                 'CurrentUser\Root', 'CurrentUser\TrustedPublisher', 'CurrentUser\CA')) {
  $hit = @(Get-ChildItem -Path ('Cert:\' + $s) -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb })
  if (-not $hit.Count) { Write-Host ('     {0,-32} not there' -f $s); continue }
  try {
    Remove-Item -Path ('Cert:\' + $s + '\' + $thumb) -Force -ErrorAction Stop
    Write-Host ('     {0,-32} removed' -f $s)
  } catch {
    Write-Host ('     {0,-32} COULD NOT REMOVE: {1}' -f $s, $_.Exception.Message) -ForegroundColor Red
  }
}
Write-Host ''

# ---- 2. non-exportable key, same certificate -------------------------------
Write-Host '  2. re-creating the key as non-exportable (same certificate, same thumbprint)'
$before = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb }
if (-not $before) { Write-Host '     the certificate is not in CurrentUser\My -- nothing to re-create' -ForegroundColor Red; exit 1 }
try {
  Remove-Item -Path ($store + '\' + $thumb) -Force -ErrorAction Stop
  Write-Host '     old entry (with the exportable key) removed'
} catch {
  Write-Host ('     could not remove the old entry: {0}' -f $_.Exception.Message) -ForegroundColor Red; exit 1
}
try {
  # No -Exportable: that is the entire point. The public key in the pfx is unchanged, so the imported
  # certificate is the same certificate.
  $imported = Import-PfxCertificate -FilePath $pfx -CertStoreLocation $store -Password $secure
  Write-Host ('     imported: thumbprint {0}' -f $imported.Thumbprint)
  if ($imported.Thumbprint -ne $thumb) {
    Write-Host '     THE THUMBPRINT CHANGED -- something is wrong, stop and look.' -ForegroundColor Red
    exit 1
  }
} catch {
  Write-Host ('     IMPORT FAILED: {0}' -f $_.Exception.Message) -ForegroundColor Red
  Write-Host ('     the pfx is still at {0}; re-import with the same command to recover.' -f $pfx)
  exit 1
}
Write-Host ''

# ---- 3. prove the key still works, without signing anything ----------------
Write-Host '  3. proving the key is still usable (a signature computed in memory, no file touched)'
$c = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb }
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
Write-Host ('     export policy now : {0}' -f $rsa.Key.ExportPolicy)
$data = [System.Text.Encoding]::UTF8.GetBytes('can this key still sign')
try {
  $sig = $rsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $ok = $rsa.VerifyData($data, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  Write-Host ('     in-memory sign + verify: {0}' -f $(if ($ok) { 'works' } else { 'FAILED' }))
} catch {
  Write-Host ('     signing FAILED: {0}' -f $_.Exception.Message) -ForegroundColor Red
}
try {
  $null = $rsa.ExportParameters($true)
  Write-Host '     export of the private key: SUCCEEDED (the policy did not take effect)' -ForegroundColor Red
} catch {
  Write-Host '     export of the private key: refused'
}
Write-Host ''

Write-Host '  AFTER'
Show-State 'new state'
