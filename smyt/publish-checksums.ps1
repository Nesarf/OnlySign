# Publish a signed SHA256 list for a GitHub release, in one command.
#
# WHY THIS EXISTS. A release has one format that can carry a signature inside itself (PE, through
# Authenticode) and a great many that cannot: .tar.gz, .zip, .deb, .rpm, winget manifests. Signing the
# PEs covers six artifacts out of thirty-one. The other twenty-five arrive as bytes with no provenance
# at all, and a downloader has no way to tell them from anything else that happens to be on the same
# page. So the release carries a list of hashes, and the list carries an Ed25519 signature. One
# signature then covers every artifact, and verifying it needs none of this project's tooling:
# Get-FileHash, sha256sum and ssh-keygen are enough.
#
# THE ORDERING RULE, and why this script cannot get it wrong.
#
#   Authenticode REWRITES the PE it signs. A hash list generated before signing describes bytes that
#   no longer exist afterwards. Doing this by hand means remembering the order, and the third release
#   is where remembering fails. So the hashes here are read from the RELEASE'S OWN digest field --
#   what GitHub holds for each asset -- rather than from a local copy of anything. Whatever moment
#   this runs, the list describes what is being served at that moment, which is the only thing a
#   downloader can check against. Sign first or second stops mattering.
#
#   That is also why it re-reads the release after uploading: the list has to describe the release,
#   not the run.
#
# WHAT IT DOES NOT DO: it does not sign the PEs (sign-github-release.ps1 does that), it does not edit
# the release notes, and it refuses rather than guesses when an asset has no digest.
#
#   -Stage   build the three files, verify the signature locally, compare with what is published.
#            Nothing is uploaded and nothing is replaced.
#   -Apply   the same, then upload with --clobber and re-read the release to prove it landed.
param(
  [Parameter(Mandatory = $true)][string]$Repo,
  [Parameter(Mandatory = $true)][string]$Tag,
  [string]$SigningDir = 'D:\DaShaoHuo\build-artifacts\signing',
  # One home for signed artifacts: the same directory sign-github-release.ps1 stages into, because
  # the list belongs with the things it lists.
  [string]$StageRoot = 'D:\OnlySign\signed',
  [string]$Principal = 'Nesarf@users.noreply.github.com',
  [string]$SshKey = 'C:\Users\Administrator\.ssh\signing_ed25519_20261011',
  [string]$SumsName = 'SHA256SUMS.txt',
  [string]$SignersName = 'allowed_signers',
  [switch]$Stage,
  [switch]$Apply
)

# NOT 'Stop': gh writes routine progress to stderr, and a native command's stderr terminates the
# script under 'Stop'. Failures are judged by what the files say instead. Same reason as the sibling
# script -- it cost a run there to learn.
$ErrorActionPreference = 'Continue'
$env:GH_CONFIG_DIR = 'D:\DaShaoHuo\tools\gh\config'

if (-not $Stage -and -not $Apply) { throw 'choose -Stage (build and verify only) or -Apply (build and publish)' }
if ($Stage -and $Apply) { throw 'choose one: -Stage or -Apply' }

function Resolve-Tool([string]$name, [string[]]$fallbacks) {
  $c = (Get-Command $name -ErrorAction SilentlyContinue).Source
  if ($c) { return $c }
  foreach ($f in $fallbacks) { if (Test-Path $f) { return $f } }
  return $null
}
$gh = Resolve-Tool 'gh' @('D:\DaShaoHuo\tools\gh\gh.exe', 'C:\Program Files\GitHub CLI\gh.exe')
if (-not $gh) { throw 'gh was not found' }
$sshKeygen = Resolve-Tool 'ssh-keygen' @('C:\Windows\System32\OpenSSH\ssh-keygen.exe')
if (-not $sshKeygen) { throw 'ssh-keygen was not found' }
if (-not (Test-Path $SshKey)) { throw "the signing key is not at $SshKey" }

$outDir = Join-Path (Join-Path $StageRoot ($Repo -replace '/', '_')) $Tag
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$sumsPath = Join-Path $outDir $SumsName
$sigPath = "$sumsPath.sig"
$signersPath = Join-Path $outDir $SignersName
$selfNames = @($SumsName, "$SumsName.sig", $SignersName)

Write-Host "  repository : $Repo"
Write-Host "  tag        : $Tag"
Write-Host "  output dir : $outDir"
Write-Host "  signer     : $Principal"
Write-Host "  mode       : $(if ($Apply) { 'APPLY (build and publish)' } else { 'STAGE (build and verify only)' })"
Write-Host ""

# ---- read the release ---------------------------------------------------------
# Plain JSON rather than --jq: PowerShell 5.1 splits a native argument that carries embedded quotes,
# so a jq expression arrives at gh in two pieces. Removing the escaping layer beats surviving it.
function Read-Release {
  $json = & $gh release view $Tag --repo $Repo --json assets | Out-String
  if ($LASTEXITCODE -ne 0) { throw "could not read the release: $json" }
  return ($json | ConvertFrom-Json)
}
$rel = Read-Release
$assets = @($rel.assets)
Write-Host ("  the release offers {0} assets" -f $assets.Count)

$listed = @()
$missingDigest = @()
foreach ($a in $assets) {
  if ($selfNames -contains $a.name) { continue }
  # A digest is the whole point of this script; an empty one is not 'unknown', it is 'cannot do
  # this', because the alternative is hashing something local and calling it what is served.
  if (-not $a.digest -or $a.digest -notmatch '^sha256:([0-9a-f]{64})$') { $missingDigest += $a.name; continue }
  $hex = $Matches[1].ToLowerInvariant()
  # GNU coreutils reads the name as everything after the two-space separator, but treats a leading
  # backslash as an escape marker. A name with a backslash or a newline in it would be written in a
  # form no common verifier decodes the same way, so it stops here instead of producing a list that
  # looks right and checks wrong.
  if ($a.name -match '[\\\r\n]') { throw "the asset name $($a.name) cannot be written into a checksum list unambiguously" }
  $listed += [pscustomobject]@{ name = $a.name; size = [int64]$a.size; sha256 = $hex; digest = $a.digest }
}
if ($missingDigest.Count) {
  Write-Host ("  {0} asset(s) carry no sha256 digest; nothing can be listed honestly:" -f $missingDigest.Count) -ForegroundColor Red
  $missingDigest | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
  exit 1
}
if (-not $listed.Count) { throw 'every asset of this release is one of the three files being generated' }

# Deterministic order, ordinal: two runs over the same release must produce byte-identical files, or
# 'the list is stale' becomes indistinguishable from 'the list was generated on another day'.
$sorted = [string[]]@($listed.name)
[Array]::Sort($sorted, [System.StringComparer]::Ordinal)
$byName = @{}
foreach ($l in $listed) { $byName[$l.name] = $l }
Write-Host ("  {0} artifact(s) to list" -f $sorted.Count)
Write-Host ""

# ---- write the list ----------------------------------------------------------
# LF, not CRLF, and no BOM: the signature covers these bytes, and a verifier on Linux reading the
# same file must hash the same bytes. [File]::WriteAllText with an explicit encoding is the only way
# to be sure -- Out-File would add CRLF on this platform.
$sb = New-Object System.Text.StringBuilder
foreach ($name in $sorted) { $null = $sb.Append(("{0}  {1}" -f $byName[$name].sha256, $name)).Append("`n") }
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($sumsPath, $sb.ToString(), $utf8NoBom)
Write-Host ("  wrote {0}  ({1} bytes, {2} lines, LF)" -f $SumsName, (Get-Item -LiteralPath $sumsPath).Length, $sorted.Count)

# ---- the identity file, derived from the key -------------------------------------------------
# Derived rather than copied from memory: a public key written down by hand is a public key that can
# disagree with the private one that signs, and that failure looks exactly like a tampered release.
$pub = (& $sshKeygen -y -f $SshKey 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $pub -notmatch '^ssh-(ed25519|rsa) ') { throw "could not derive the public key from $SshKey : $pub" }
# KEYTYPE AND BLOB ONLY. ssh-keygen -y appends the key's comment, and allowed_signers is a field
# format: a stray third token is not part of what a verifier reads as the key. Measured here: keeping
# the comment made the file 164 bytes against the 113 of the hand-written one, which is the quiet
# start of 'the file that works' and 'the file that was published' drifting apart.
$pubFields = @($pub -split '\s+' | Select-Object -First 2)
$pub = $pubFields -join ' '
[System.IO.File]::WriteAllText($signersPath, ("{0} {1}`n" -f $Principal, $pub), $utf8NoBom)
Write-Host ("  wrote {0}  ({1})" -f $SignersName, ($pub -replace '^(ssh-[a-z0-9]+ ).*', '$1...'))

# ---- sign ---------------------------------------------------------------------
# -Y sign reads the message from the FILE given to it, so no stdin redirection is involved here.
#
# AND IT ASKS BEFORE OVERWRITING, then answers itself NO when there is nothing to read. Measured on
# this machine: with a .sig already beside the list, ssh-keygen printed
#
#     ... SHA256SUMS.txt.sig already exists. Overwrite (y/n)?
#
# read EOF, kept the old file, and EXITED 0. A stale signature over a freshly built list is the exact
# failure this script exists to prevent, and it would have been reported as success. So the old file
# is removed first and the new one has to be newer than the run that produced it: existence is not
# the question, provenance is. (Same family as Test-Path on a truncated download.)
if (Test-Path $sigPath) { Remove-Item -LiteralPath $sigPath -Force }
$signStartedUtc = [DateTime]::UtcNow
$signOut = & $sshKeygen -Y sign -f $SshKey -n file $sumsPath 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "signing failed (exit $LASTEXITCODE): $signOut" }
if (-not (Test-Path $sigPath)) { throw "the signature was not written: $signOut" }
$sigWrittenUtc = (Get-Item -LiteralPath $sigPath).LastWriteTimeUtc
if ($sigWrittenUtc -lt $signStartedUtc.AddSeconds(-2)) {
  throw ("the signature file predates this run ({0} < {1}); it is not the signature for this list" -f $sigWrittenUtc.ToString('o'), $signStartedUtc.ToString('o'))
}
Write-Host ("  signed -> {0}  ({1} bytes)" -f $SumsName, (Get-Item -LiteralPath $sigPath).Length)

# ---- verify what was just written, by reading the bytes back --------------------------------
# The message goes in on stdin, and it has to be the SAME BYTES: PowerShell's pipeline decodes text
# and rejoins it with its own line endings, which changes the message and turns a good signature into
# a bad one. So the raw bytes are written to the child's stdin directly.
function Test-Signature {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $sshKeygen
  $psi.Arguments = "-Y verify -f `"$signersPath`" -I `"$Principal`" -n file -s `"$sigPath`""
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $p = [System.Diagnostics.Process]::Start($psi)
  $bytes = [System.IO.File]::ReadAllBytes($sumsPath)
  $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
  $p.StandardInput.BaseStream.Flush()
  $p.StandardInput.Close()
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  return [pscustomobject]@{ exit = $p.ExitCode; text = ("$out$err").Trim() }
}
$v = Test-Signature
Write-Host ("  self-check : {0}" -f $v.text)
if ($v.exit -ne 0) {
  Write-Host '  the signature does not verify against the list it was made from; stopping.' -ForegroundColor Red
  exit 1
}

# ---- compare with what is already published ------------------------------------------------
# A stale list is the failure this whole script exists to prevent, so the run reports the difference
# instead of silently replacing it. 0 lines different is the answer worth having.
$published = @($assets | Where-Object { $_.name -eq $SumsName })
if ($published.Count) {
  # Downloaded beside the output, not into %TEMP%: this machine's rule is that scratch does not go
  # on the system drive, and a 3 KB file is exactly the kind that gets forgotten there.
  $prevDir = Join-Path $outDir '_prev'
  New-Item -ItemType Directory -Force -Path $prevDir | Out-Null
  & $gh release download $Tag --repo $Repo --pattern $SumsName --dir $prevDir --clobber 2>&1 | Out-Null
  $old = Get-ChildItem -LiteralPath $prevDir -Filter $SumsName -File -ErrorAction SilentlyContinue
  if ($old) {
    $oldLines = @([System.IO.File]::ReadAllLines($old.FullName))
    $newLines = @([System.IO.File]::ReadAllLines($sumsPath))
    $diff = Compare-Object -ReferenceObject $oldLines -DifferenceObject $newLines
    if ($diff) {
      Write-Host ("  published list differs from the one just built: {0} line(s)" -f @($diff).Count) -ForegroundColor Yellow
      @($diff) | Select-Object -First 6 | ForEach-Object { Write-Host ("    {0} {1}" -f $_.SideIndicator, $_.InputObject) }
    } else {
      Write-Host '  published list is identical to the one just built'
    }
    Remove-Item -LiteralPath $old.FullName -Force
  }
  Remove-Item -LiteralPath $prevDir -Recurse -Force -ErrorAction SilentlyContinue
} else {
  Write-Host '  no list is published yet; this would be the first'
}
Write-Host ""

# ---- publish ------------------------------------------------------------------
$trio = @($sumsPath, $sigPath, $signersPath)
if (-not $Apply) {
  Write-Host '  STAGE only: nothing was uploaded.'
  Write-Host '  Re-run with -Apply to publish the three files.'
  Write-Host ''
  Write-Host '  a downloader can check the release with these three commands:'
  Write-Host '    Get-FileHash -Algorithm SHA256 <file>     (Windows)'
  Write-Host '    sha256sum -c SHA256SUMS.txt               (Linux/macOS)'
  Write-Host ("    ssh-keygen -Y verify -f allowed_signers -I {0} -n file -s {1}.sig < {1}" -f $Principal, $SumsName)
  exit 0
}

Write-Host '  uploading (--clobber)'
$up = & $gh release upload $Tag --repo $Repo --clobber @trio 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { Write-Host $up; exit 1 }
Write-Host ('    exit {0}' -f $LASTEXITCODE)

# ---- read the release again: the list must describe what is served -------------------------
$after = Read-Release
$now = @{}
foreach ($a in $after.assets) { $now[$a.name] = $a }
$problems = @()
foreach ($path in $trio) {
  $n = Split-Path $path -Leaf
  if (-not $now.ContainsKey($n)) { $problems += "$n did not appear in the release"; continue }
  $local = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  $remote = ($now[$n].digest -replace '^sha256:', '')
  if ($local -ne $remote) { $problems += "$n differs after upload (local $local, release $remote)" }
}
# And every listed artifact: the list has to agree with the release, not with the moment it was built.
foreach ($name in $sorted) {
  if (-not $now.ContainsKey($name)) { $problems += "$name is listed but not in the release"; continue }
  if (($now[$name].digest -replace '^sha256:', '') -ne $byName[$name].sha256) { $problems += "$name changed between build and upload" }
}
if ($problems.Count) {
  Write-Host ("  {0} problem(s) after upload:" -f $problems.Count) -ForegroundColor Red
  $problems | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
  exit 1
}
$extra = @($now.Keys | Where-Object { $selfNames -notcontains $_ -and $sorted -notcontains $_ })
if ($extra.Count) { Write-Host ("  note: the release now holds {0} artifact(s) the list does not cover: {1}" -f $extra.Count, ($extra -join ', ')) -ForegroundColor Yellow }
Write-Host ("  verified   : {0} artifact(s) listed, {1} files published, all digests agree" -f $sorted.Count, $trio.Count)
Write-Host '  the three files stay in the stage directory, which is what the ledger records.'
Write-Host ''
Write-Host '  a downloader can check the release with these three commands:'
Write-Host '    Get-FileHash -Algorithm SHA256 <file>     (Windows)'
Write-Host '    sha256sum -c SHA256SUMS.txt               (Linux/macOS)'
Write-Host ("    ssh-keygen -Y verify -f allowed_signers -I {0} -n file -s {1}.sig < {1}" -f $Principal, $SumsName)
