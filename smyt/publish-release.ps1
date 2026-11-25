# One command for a release's signing tail, in the only order that works.
#
# WHY THIS EXISTS. Two scripts already do the two halves: sign-github-release.ps1 replaces the PE
# artifacts with signed bytes, publish-checksums.ps1 writes and signs a hash list over everything.
# The order between them is not a preference -- Authenticode rewrites the PE it signs, so a list built
# before that describes bytes that no longer exist. Two scripts and one order is exactly the shape a
# person gets wrong on the third release, when the first two went fine. So the order lives here.
#
# Each half is run in its own process, on purpose: both scripts end with `exit 1` on a refusal, and a
# script called in-process would take this one down with it, skipping the second step silently. A
# refusal in step 1 must stop the run, and a child process's exit code makes that visible.
#
#   -Stage   download and verify the PEs, then build and self-check the list. Nothing is published.
#   -Apply   sign and replace the PEs, then build, sign, publish and re-read the list.
param(
  [Parameter(Mandatory = $true)][string]$Repo,
  [Parameter(Mandatory = $true)][string]$Tag,
  [string]$SigningDir = 'D:\DaShaoHuo\build-artifacts\signing',
  [string]$StageRoot = 'D:\OnlySign\signed',
  [string[]]$Patterns,
  [string]$Note = '',
  [int]$PauseSeconds = 25,
  [switch]$Stage,
  [switch]$Apply
)

if (-not $Stage -and -not $Apply) { throw 'choose -Stage (verify only) or -Apply (sign and publish)' }
if ($Stage -and $Apply) { throw 'choose one: -Stage or -Apply' }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$signScript = Join-Path $here 'sign-github-release.ps1'
$sumsScript = Join-Path $here 'publish-checksums.ps1'
foreach ($p in @($signScript, $sumsScript)) { if (-not (Test-Path $p)) { throw "missing: $p" } }

# The same interpreter that is running this, found from the process rather than from PATH: a different
# pwsh on PATH would run the halves against a different $PSHOME, and that has broken these scripts before.
$pwshExe = (Get-Process -Id $PID).Path
$mode = if ($Apply) { '-Apply' } else { '-Stage' }

Write-Host ''
Write-Host '== step 1 of 2: the PE artifacts ================================'
$signArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $signScript,
  '-Repo', $Repo, '-Tag', $Tag, '-SigningDir', $SigningDir, '-StageRoot', $StageRoot, $mode,
  '-PauseSeconds', $PauseSeconds)
if ($Patterns) { $signArgs += '-Patterns'; $signArgs += $Patterns }
if ($Note) { $signArgs += '-Note'; $signArgs += $Note }
& $pwshExe @signArgs
if ($LASTEXITCODE -ne 0) {
  Write-Host ''
  if ($LASTEXITCODE -eq 2) {
    # Not a failure of this run: the stage directory has an owner. Kept separate because "another run
    # is doing this right now" and "this run went wrong" want different reactions from the reader.
    Write-Host 'step 1 refused: another run holds this stage directory. Nothing was downloaded, signed or uploaded.' -ForegroundColor Red
  } else {
    Write-Host ("step 1 failed (exit {0}). The list is NOT built: every hash in it would describe bytes that" -f $LASTEXITCODE) -ForegroundColor Red
    Write-Host 'are about to be replaced, and a list that is wrong in that way still verifies.' -ForegroundColor Red
  }
  exit 1
}

Write-Host ''
Write-Host '== step 2 of 2: the signed hash list ============================'
$sumArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $sumsScript,
  '-Repo', $Repo, '-Tag', $Tag, '-SigningDir', $SigningDir, '-StageRoot', $StageRoot, $mode)
& $pwshExe @sumArgs
if ($LASTEXITCODE -ne 0) {
  Write-Host ''
  Write-Host ("step 2 failed (exit {0}); the PE artifacts are already published and the list is not." -f $LASTEXITCODE) -ForegroundColor Red
  exit 1
}

Write-Host ''
if ($Apply) {
  Write-Host 'both steps finished: signed artifacts replaced, list built, signed, published and re-read.'
} else {
  Write-Host 'both steps checked out. Nothing was signed and nothing was published.'
  Write-Host 'Re-run with -Apply to do it for real.'
}
