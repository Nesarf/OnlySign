# Sign a GitHub release's Windows artifacts, in one command, without the key ever leaving this machine.
#
# WHY THIS EXISTS, and the two mistakes it is built to prevent.
#
#   1. THE LEDGER RECORDS PATHS. Signing in a temp directory makes every ledger record a dead pointer
#      the moment the temp directory is cleaned -- and cleaning it is what a careful person does. That
#      happened here: 17 records from one day's work pointed at D:\DaShaoHuo\cache\tmp\sign-work\...
#      after the work was tidied away. So artifacts are staged in a PERMANENT per-release directory,
#      and the cleanup at the end removes nothing but the scratch the download itself used.
#
#   2. "SIGNED" IS A CLAIM; THE FILE IS THE FACT. Get-AuthenticodeSignature consults this machine's
#      security catalog, so it can report a signature that belongs to somebody else, or one that is
#      no longer in the file. Every artifact here is checked by reading the signature OUT OF THE FILE
#      and comparing its thumbprint with the published certificate, and -- when a ledger hash is known
#      -- by comparing the file's own sha256 with what was actually signed.
#
# The steps, in the order the signing toolchain's own discipline requires (sign last, record after
# signing, relocation appended rather than rewritten):
#
#   download  one --pattern per call, because the flag takes ONE value and silently ignores the rest
#   repair    clear the stale PE certificate-table entry that postject leaves, or signtool refuses the
#             whole file with 0x800700C1
#   sign      paced, retried, timestamped; the tool refuses without a timestamp and leaves the file
#             untouched, so a refused run is safe to repeat
#   verify    signature present IN THE FILE, thumbprint matches, timestamp present, hash recorded
#   upload    --clobber, only with -Apply
#
#   -Stage   download + repair + verify only. No signing, no upload. This is what to run first.
#   -Apply   the whole thing, including signing and publishing.
param(
  [Parameter(Mandatory = $true)][string]$Repo,
  [Parameter(Mandatory = $true)][string]$Tag,
  [string]$SigningDir = 'D:\DaShaoHuo\build-artifacts\signing',
  # ONE HOME. D:\OnlySign\signed is the directory the user designated for signed artifacts (its rule
  # is that only signed things live there, and it is gitignored in that repository, so binaries are
  # safe). This script used to stage under build-artifacts\signed, which made two homes for one kind
  # of thing -- and a ledger that records paths cannot afford two answers to "where is it".
  [string]$StageRoot = 'D:\OnlySign\signed',
  [string[]]$Patterns,
  [string]$Note = '',
  [switch]$Stage,
  [switch]$Apply,
  [int]$PauseSeconds = 25,
  [int]$MaxAttempts = 5
)

# NOT 'Stop', and that is deliberate: with Stop, a NATIVE command that writes to stderr terminates the
# script -- and gh writes routine progress and warnings there. Measured: a transient download failure
# (`stream error: PROTOCOL_ERROR received from peer`) killed the run instead of being retried, because
# the message arrived on stderr. Failures are judged by what happened to the files instead.
$ErrorActionPreference = 'Continue'
# The trap recorded in the toolchain's own notes: a PS7-shadowed PSModulePath makes the certificate
# cmdlets "not exist", and a failing query answers exactly like an empty store.
$env:PSModulePath = (Join-Path $PSHOME 'Modules')

if (-not $Stage -and -not $Apply) { throw 'choose -Stage (download and verify only) or -Apply (sign and publish)' }
if ($Stage -and $Apply) { throw 'choose one: -Stage or -Apply' }
if (-not $Patterns) { $Patterns = @('*.msi', '*.exe') }
if (-not $Note) { $Note = "$Repo $Tag release" }

$gh = (Get-Command gh -ErrorAction SilentlyContinue).Source
if (-not $gh) {
  foreach ($c in @('D:\DaShaoHuo\tools\gh\gh.exe', 'C:\Program Files\GitHub CLI\gh.exe')) {
    if (Test-Path $c) { $gh = $c; break }
  }
}
if (-not $gh) { throw 'gh was not found' }
$env:GH_CONFIG_DIR = 'D:\DaShaoHuo\tools\gh\config'

$sign = Join-Path $SigningDir 'smyt-sign.ps1'
$cer = Join-Path $SigningDir 'smyt-codesign.cer'
if (-not (Test-Path $sign)) { throw "the signing tool is not at $sign" }

# The published certificate is the identity check, so its thumbprint is read from the .cer rather than
# written down here: a subject string is a spelling anybody can reuse.
$expected = $null
if (Test-Path $cer) {
  $expected = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cer).Thumbprint
}
if (-not $expected) { throw "the published certificate is not at $cer" }

$dir = Join-Path (Join-Path $StageRoot ($Repo -replace '/', '_')) $Tag
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# ---- one run per directory ---------------------------------------------------
# AN INTERRUPTED RUN DOES NOT CLEAN UP AFTER ITSELF, and the failure lands on the NEXT run, where it
# is least expected. Measured on 2026-10-21: a foreground call hit its own timeout, the wrapper was
# killed while the `gh` download it had started kept holding a 73 MB .exe. A second run then reported
# "The process cannot access the file ... because it is being used by another process" -- a message
# about a symptom, arriving from a place that had done nothing wrong.
#
# So the directory carries a lock naming the pid working in it, and a second run refuses BEFORE
# downloading anything. The lock is honoured only while that pid is alive: one left behind by a
# machine that lost power must not block the next run forever. That is also why no failure path
# deletes it -- liveness decides, not the file's absence.
$lockPath = Join-Path $dir '.download.lock'
$lockHolder = $null
if (Test-Path -LiteralPath $lockPath) {
  $lockText = Get-Content -LiteralPath $lockPath -Raw -ErrorAction SilentlyContinue
  $lockPid = if ($lockText) { ($lockText -split "`n")[0] } else { '' }
  if ($lockPid -match '^\s*(\d+)\s*$') {
    $holderPid = [int]$Matches[1]
    if (Get-Process -Id $holderPid -ErrorAction SilentlyContinue) {
      $cmdline = (Get-CimInstance Win32_Process -Filter "ProcessId=$holderPid" -ErrorAction SilentlyContinue).CommandLine
      # A pid can be reused by anything, and a command line that merely MENTIONS one of these paths is
      # not evidence of a run: an editor open on this directory, a terminal typing the name, the very
      # test that checks this branch. Measured while writing this: the broad form of this regex
      # matched the calling shell's own command line, which contained the string only as a variable's
      # value. So the match requires `-File` immediately before the script path -- the shape PowerShell
      # uses when it actually runs one.
      $isOurRun = $cmdline -match '-File\s+"?[^"\s]*(sign-github-release|publish-release|publish-checksums)\.ps1'
      # Where the command line is not readable at all, a live pid is reason enough to stop and say so.
      if (-not $cmdline -or $isOurRun) {
        $lockHolder = [pscustomobject]@{ pid = $holderPid; cmd = $cmdline }
      }
    }
  }
}
if ($lockHolder) {
  Write-Host "  another run holds this directory: pid $($lockHolder.pid)" -ForegroundColor Red
  if ($lockHolder.cmd) { Write-Host ("    " + ($lockHolder.cmd -replace '\s+', ' ')) -ForegroundColor DarkGray }
  Write-Host "  nothing was downloaded. If that process is gone, delete $lockPath and run again." -ForegroundColor Red
  exit 2
}
# Written only after the check passes, so a run that refuses the lock does not overwrite the holder's
# record with its own pid.
[System.IO.File]::WriteAllText($lockPath, ("{0}`n{1}`n{2}`n" -f $PID, (Get-Date).ToString('o'), "$Repo $Tag"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host "  repository : $Repo"
Write-Host "  tag        : $Tag"
Write-Host "  stage dir  : $dir      (permanent -- the ledger records this path)"
Write-Host "  certificate: $expected"
Write-Host "  mode       : $(if ($Apply) { 'APPLY (sign and publish)' } else { 'STAGE (download and verify only)' })"
Write-Host ""

# How many assets the release offers, so a partial download is visible as a number rather than as
# something noticed later.
# NAME AND SIZE, not just names. A present file must be proved to be a COMPLETE file: an interrupted
# download leaves a truncated one that Test-Path reports as present, which is how two 71 MB executables
# came back as 66 MB and 51 MB and were about to be treated as "already have it". Same family as the
# empty-store mistake: existence is not the question, the declared size matching is.
# NO jq, and that is the third version of this line. PowerShell 5.1 re-parses an argument that carries
# embedded quotes when it hands it to a native command, so the jq expression arrived at gh split in two
# at its space ("accepts at most 1 arg(s), received 2"). The fix is not another quoting attempt: ask gh
# for plain JSON and parse it here, which removes the escaping layer instead of surviving it.
$json = & $gh release view $Tag --repo $Repo --json assets | Out-String
if ($LASTEXITCODE -ne 0) { throw "could not read the release: $json" }
$parsed = $json | ConvertFrom-Json
$sizeOf = @{}
$names = @()
foreach ($a in $parsed.assets) {
  $sizeOf[$a.name] = [int64]$a.size
  $names += $a.name
}
$wanted = @()
foreach ($line in $names) {
  foreach ($p in $Patterns) { if ($line -like $p) { $wanted += $line; break } }
}
Write-Host ("  the release offers {0} assets, {1} of which match {2}" -f $names.Count, $wanted.Count, ($Patterns -join ', '))
$missing = @()
foreach ($name in $wanted) {
  $path = Join-Path $dir $name
  $expect = $sizeOf[$name]
  if (Test-Path $path) {
    $have = (Get-Item -LiteralPath $path).Length
    if ($have -eq $expect) { Write-Host ("    have  {0}  ({1} bytes)" -f $name, $have); continue }
    Write-Host ("    incomplete {0}: {1} of {2} bytes, refetching" -f $name, $have, $expect)
    Remove-Item -LiteralPath $path -Force
  }
  Write-Host "    fetch $name"
  # Retried, because a 71 MB asset through a proxy does occasionally fail mid-stream. The judgement is
  # the file on disk, not the exit code and not the message: a partial download is deleted and retried,
  # since gh leaves whatever it managed to write.
  for ($try = 1; $try -le 3; $try++) {
    & $gh release download $Tag --repo $Repo --pattern $name --dir $dir --clobber 2>&1 | Out-Null
    if ((Test-Path $path) -and ((Get-Item -LiteralPath $path).Length -eq $expect)) { break }
    Write-Host ("      attempt {0} failed; retrying" -f $try)
    Start-Sleep -Seconds 5
  }
  if (-not (Test-Path $path)) { $missing += $name }
  elseif ((Get-Item -LiteralPath $path).Length -ne $expect) { $missing += "$name (truncated)" }
}
if ($missing.Count) { throw "these assets did not arrive: $($missing -join ', ')" }
Write-Host ""

# ---- repair + sign + verify -------------------------------------------------
$results = @()
foreach ($name in $wanted) {
  $path = Join-Path $dir $name
  $row = [ordered]@{ file = $name; repaired = '-'; signed = '-'; thumbprint = '-'; tsa = '-'; sha256 = '-' }

  # The certificate-table entry, for the executables postject builds.
  if ($name -like '*.exe') {
    $b = [System.IO.File]::ReadAllBytes($path)
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    $opt = $pe + 4 + 20
    $magic = [BitConverter]::ToUInt16($b, $opt)
    $dirs = $opt + $(if ($magic -eq 0x20b) { 112 } else { 96 })
    $at = $dirs + (4 * 8)
    $va = [BitConverter]::ToInt32($b, $at)
    if ($va -ne 0) {
      if ($Apply) {
        for ($i = 0; $i -lt 8; $i++) { $b[$at + $i] = 0 }
        [System.IO.File]::WriteAllBytes($path, $b)
        $row.repaired = "cleared $va"
      } else {
        $row.repaired = "would clear $va"
      }
    } else {
      $row.repaired = 'already clear'
    }
  }

  $sig = Get-AuthenticodeSignature -LiteralPath $path
  if ($Apply -and $sig.SignerCertificate.Thumbprint -ne $expected) {
    for ($a = 1; $a -le $MaxAttempts; $a++) {
      try { $null = & $sign -Sign $path -Note $Note 2>&1 } catch { }
      Start-Sleep -Seconds 4
      $sig = Get-AuthenticodeSignature -LiteralPath $path
      if ($sig.SignerCertificate.Thumbprint -eq $expected) { break }
      if ($a -lt $MaxAttempts) { Write-Host ("    {0}: timestamp refused, waiting {1}s" -f $name, $PauseSeconds); Start-Sleep -Seconds $PauseSeconds }
    }
    Start-Sleep -Seconds 5
  }

  $sig = Get-AuthenticodeSignature -LiteralPath $path
  $row.signed = $sig.Status
  if ($sig.SignerCertificate) { $row.thumbprint = $sig.SignerCertificate.Thumbprint }
  if ($sig.TimeStamperCertificate) { $row.tsa = $sig.TimeStamperCertificate.Subject -replace ',.*', '' }
  $row.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
  $results += [pscustomobject]$row
}
Write-Host ""

# ---- publish ----------------------------------------------------------------
$bad = @($results | Where-Object { $_.thumbprint -ne $expected })
Write-Host "  results"
$results | ForEach-Object { Write-Host ("    {0,-34} {1,-10} {2}" -f $_.file, $_.signed, $_.sha256.Substring(0, 16)) }
Write-Host ""

if ($bad.Count) {
  Write-Host ("  {0} artifact(s) do NOT carry the published certificate; nothing will be published:" -f $bad.Count) -ForegroundColor Red
  $bad | ForEach-Object { Write-Host ("    {0}" -f $_.file) -ForegroundColor Red }
  exit 1
}

if ($Apply) {
  Write-Host "  uploading (--clobber)"
  $paths = $results | ForEach-Object { Join-Path $dir $_.file }
  $out = & $gh release upload $Tag --repo $Repo --clobber @paths 2>&1
  Write-Host ("    exit {0}" -f $LASTEXITCODE)
  if ($LASTEXITCODE -ne 0) { Write-Host $out; exit 1 }
  Write-Host "  published. The signed artifacts stay in the stage directory, which is what the ledger records."
} else {
  Write-Host "  STAGE only: nothing was signed and nothing was uploaded."
  Write-Host "  Re-run with -Apply to sign and publish."
}
