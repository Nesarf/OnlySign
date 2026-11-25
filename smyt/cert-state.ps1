# Where is the S.M.Y.T. certificate, and does the query actually work?
#
# Written as a FILE, and it pins PSModulePath first, because a PS7-shadowed module path makes
# Get-ChildItem over Cert: answer 0 for EVERY store -- which reads exactly like an empty trust store.
# That mistake produced two wrong conclusions in one session, so every count here is accompanied by a
# count that must be non-zero for the answer to mean anything.
$ErrorActionPreference = 'Continue'
$env:PSModulePath = (Join-Path $PSHOME 'Modules')

$thumb = '4EA54E72A1EEFAE280B99631F7680DBFF461C4F1'

Write-Host '  self-check (these must be non-zero, or nothing below means anything):'
$lmRootAll = @(Get-ChildItem 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue)
$cuMyAll = @(Get-ChildItem 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue)
Write-Host ('    LocalMachine\Root total entries      : {0}' -f $lmRootAll.Count)
Write-Host ('    CurrentUser\My     total entries     : {0}' -f $cuMyAll.Count)
if ($lmRootAll.Count -eq 0) { Write-Host '    QUERY IS BROKEN -- stop reading.' -ForegroundColor Red; exit 9 }
Write-Host ''

$stores = @('LocalMachine\Root', 'LocalMachine\TrustedPublisher', 'LocalMachine\My', 'LocalMachine\CA',
            'CurrentUser\Root', 'CurrentUser\TrustedPublisher', 'CurrentUser\My', 'CurrentUser\CA')
Write-Host '  the certificate, store by store:'
foreach ($s in $stores) {
  $path = 'Cert:\' + $s
  $hit = @(Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb })
  $state = if ($hit.Count -gt 0) { 'present' } else { '-' }
  Write-Host ('    {0,-32} {1}' -f $s, $state)
}

Write-Host ''
Write-Host '  the private key, and whether it can leave the machine:'
$mine = Get-ChildItem 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb }
if ($mine) {
  Write-Host ('    has private key : {0}' -f $mine.HasPrivateKey)
  try {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($mine)
    if ($rsa -is [System.Security.Cryptography.RSACng]) {
      # The CNG path, which is what this key actually is: the CSP properties below report nothing for
      # it, and "not reported" reads like "no policy" when the policy is in fact the interesting part.
      Write-Host ('    key provider    : {0}' -f $rsa.Key.Provider)
      Write-Host ('    export policy   : {0}' -f $rsa.Key.ExportPolicy)
    } elseif ($rsa) {
      $policy = $rsa.CspKeyContainerInfo.ExportPolicy
      Write-Host ('    key container   : {0}' -f $rsa.CspKeyContainerInfo.KeyContainerName)
      Write-Host ('    provider        : {0}' -f $rsa.CspKeyContainerInfo.ProviderName)
      Write-Host ('    export policy   : {0}' -f $(if ($null -eq $policy) { 'not reported (CNG key)' } else { $policy }))
    } else {
      Write-Host '    the key is not RSA, or is not reachable through the RSA extension'
      Write-Host ('    key algorithm   : {0}' -f $mine.PrivateKey.Algorithm)
    }
  } catch {
    Write-Host ('    could not read the key policy: {0}' -f $_.Exception.Message)
  }
} else {
  Write-Host '    not in CurrentUser\My'
}

Write-Host ''
Write-Host '  anything on this machine that mentions trust installation:'
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match 'cert|trust|sign|smyt|onlysign' }
if ($tasks) { $tasks | ForEach-Object { Write-Host ('    task: {0}  [{1}]' -f $_.TaskName, $_.State) } }
else { Write-Host '    no scheduled task by those names' }
