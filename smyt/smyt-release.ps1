# smyt-release.ps1 -- build, sign, verify, and (optionally) publish one artifact
#
# The order is not negotiable: **sign last**. An Authenticode signature covers the whole PE file,
# so any later rewrite of the contents destroys it. Building, then signing, is the only order that
# produces a signed artifact.
#
# Every step is checked rather than assumed:
#   build  -> the file exists and is an executable
#   sign   -> signtool exits 0 AND a timestamp was actually obtained
#   verify -> the signature is present and the signing certificate is the one published here
#   hash   -> recorded before and after signing (Authenticode changes the file)
#   upload -> the digest GitHub reports equals the digest on disk, for every asset uploaded
#
# The last one matters most. An upload that silently truncated or re-encoded would otherwise be
# indistinguishable from a good one, and the whole point of publishing a hash is that it matches.
# That is also why the hash and the public certificate go up with the build: a hash nobody can
# obtain is not a check, and a signature nobody can verify against a pinned certificate is a claim.
#
# Usage:
#   .\smyt-release.ps1 -Build           build with PyInstaller, then sign and verify
#   .\smyt-release.ps1 -Artifact x.exe  sign an artifact that already exists
#   .\smyt-release.ps1 -Build -Publish -Repo Nesarf/Nanodesu -Tag v1.2.0
#   .\smyt-release.ps1 -Build -OutDir E:\somewhere\else

param(
    [string]$Source,
    [string]$Artifact,
    [string]$OutDir = 'D:\DaShaoHuo\build-artifacts\staging',
    [switch]$Build,
    [string]$Name = 'nanodesu',
    [string]$SpecDir = 'D:\DaShaoHuo\cache\tmp\smyt-spec',
    [string]$WorkDir = 'D:\DaShaoHuo\cache\tmp\smyt-work',
    # A toolchain is not a temporary file. This used to point into cache\tmp, which the disk policy
    # tells whoever cleans this machine to empty -- and it had in fact already been emptied, so the
    # build path was broken with nothing to show for it but a missing file at release time.
    [string]$PyiPython = 'D:\DaShaoHuo\toolchains\pyi\Scripts\python.exe',
    [string]$Note = '',
    [switch]$Publish,
    [string]$Repo,
    [string]$Tag,
    [switch]$AllowUnsignedUpload,
    [switch]$AllowAnywhere,
    # The application's icon. An embedded signature has no field for an image, so a built
    # executable is the only place in the artifact itself where the mark can appear. Defaults to
    # mark\fdcus.ico beside this toolchain; -NoIcon builds without one.
    [string]$Icon = '',
    [switch]$NoIcon,
    [string]$SigningDir = ''
)

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $SigningDir) { $SigningDir = $here }

. (Join-Path $here 'smyt-common.ps1')
Repair-SmytModulePath

$paths = Get-SmytPaths -SigningDir $SigningDir
# The scripts come from where this file lives; -SigningDir names the key material and the ledger.
# Keeping those two apart is what lets a release be rehearsed against a copied certificate and a
# scratch ledger without the real record knowing anything about it.
$signScript = Join-Path $here 'smyt-sign.ps1'
if (-not (Test-Path -LiteralPath $signScript)) { throw "signing tool not found at $signScript" }

function Step($n, $text) { Write-Host ""; Write-Host "[$n] $text" -ForegroundColor Cyan }

# --- 0. refuse to work somewhere it has no business deleting ------------------ #
# Step 1 removes the output directory recursively. A parameter that came from a command line is
# one typo away from an empty disk, so it has to name a directory this tool is allowed to name.
$OutDir = Assert-SmytOutDir -Path $OutDir -AllowAnywhere:$AllowAnywhere

# --- 1. obtain the artifact -------------------------------------------------- #
$built = $null
if ($Build) {
    if (-not $Source) { throw "-Build needs -Source <script.py>" }
    if (-not (Test-Path -LiteralPath $Source)) { throw "no such source: $Source" }
    if (-not (Test-Path -LiteralPath $PyiPython)) {
        throw ("the PyInstaller interpreter is not at $PyiPython. Create it once, outside every cache " +
               "directory so a cleanup cannot take it: 'python -m venv D:\DaShaoHuo\toolchains\pyi' then " +
               "'D:\DaShaoHuo\toolchains\pyi\Scripts\python.exe -m pip install pyinstaller', or pass -PyiPython.")
    }

    Step 1 "building with PyInstaller"
    # PyInstaller warns about this itself and says 7.0 will refuse outright, so it is worth saying
    # while it is still only a warning: build as a normal account, and let signing be the step
    # that is elevated.
    $elevated = ([Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($elevated) {
        Write-Warning "this session is elevated, and PyInstaller says running as administrator is neither necessary nor sensible"
    }
    # A clean staging directory every time: a stale artifact from an earlier build is exactly the
    # kind of thing that gets signed and published by mistake.
    if (Test-Path -LiteralPath $OutDir) { Remove-Item -Recurse -Force -LiteralPath $OutDir }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

    $iconPath = ''
    if (-not $NoIcon) {
        $iconPath = $Icon
        if (-not $iconPath) { $iconPath = Join-Path $here 'mark\fdcus.ico' }
        if (-not (Test-Path -LiteralPath $iconPath)) {
            Write-Warning "no icon at $iconPath, so the build gets the default one; pass -Icon or -NoIcon to say which you meant"
            $iconPath = ''
        }
    }

    # Native commands write progress and warnings to stderr, and with ErrorActionPreference set to
    # Stop PowerShell turns any stderr line into a terminating error -- so PyInstaller's own
    # deprecation notice aborted the build. The preference is relaxed for the duration of the call
    # and success is judged by the exit code, which is the thing that actually reports it.
    $pyiArgs = @(
        '-m', 'PyInstaller', '--onefile', '--name', $Name,
        '--distpath', $OutDir, '--workpath', $WorkDir, '--specpath', $SpecDir,
        '--noconfirm', '--console'
    )
    if ($iconPath) {
        $pyiArgs += @('--icon', $iconPath)
        Write-Host "  icon: $iconPath"
    }
    $pyiArgs += $Source

    $r = Invoke-SmytNative -Exe $PyiPython -Arguments $pyiArgs
    if ($r.Code -ne 0) {
        foreach ($line in @($r.Output | Select-Object -Last 6)) { Write-Host "  $line" -ForegroundColor DarkGray }
        throw "PyInstaller exited $($r.Code)"
    }

    $built = Join-Path $OutDir ($Name + '.exe')
    if (-not (Test-Path -LiteralPath $built)) { throw "the build reported success but $built does not exist" }
    Write-Host "built $built ($([int]((Get-Item -LiteralPath $built).Length/1KB)) KB)"
} else {
    Step 1 "using the artifact as given"
    if (-not $Artifact) { throw "give -Artifact <file>, or -Build with -Source <script.py>" }
    if (-not (Test-Path -LiteralPath $Artifact)) { throw "no such artifact: $Artifact" }
    $built = (Resolve-Path -LiteralPath $Artifact).Path
    Write-Host "artifact $built"
}

# A mutable copy: never sign a file that is also the build output, or a re-run signs an
# already-signed file and the ledger records two hashes for one build.
$stage = Join-Path $OutDir ([IO.Path]::GetFileName($built))
if ((Resolve-Path -LiteralPath $built).Path -ne $stage) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    Copy-Item -LiteralPath $built -Destination $stage -Force
}

# --- 2. sign ----------------------------------------------------------------- #
Step 2 "signing"
# The child has to be told which key material and which ledger to use. It used to be left to
# default, which meant it defaulted to the real signing directory -- so a release rehearsed against
# a copied certificate still wrote its record into the real ledger, and said so only in a line of
# output nobody was looking at.
$before = (Read-SmytLedger -Path $paths.Ledger).Count
$signArgs = @('-Sign', $stage, '-SigningDir', $SigningDir)
if ($Note) { $signArgs += @('-Note', $Note) }
$r = Invoke-SmytNative -Exe 'powershell' -Arguments (@(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $signScript) + $signArgs)
foreach ($line in $r.Output) { Write-Host $line }
if ($r.Code -ne 0) { throw "signing failed with exit code $($r.Code)" }

# And then check that the record landed where this release thinks the record goes, rather than
# trusting that it did, because the failure above was silent exactly where it mattered.
$after = (Read-SmytLedger -Path $paths.Ledger).Count
if ($after -le $before) {
    throw ("the signing step reported success but $($paths.Ledger) did not grow, so the record went " +
           "somewhere else -- check that -SigningDir reaches the signing script")
}

# --- 3. verify the signature is actually there -------------------------------- #
Step 3 "verifying the signature"
$sig = Get-SmytSignature -Path $stage
if (-not $sig.Present) {
    if (-not $AllowUnsignedUpload) {
        throw "the file is not signed after signing -- refusing to continue"
    }
    Write-Warning "publishing an UNSIGNED artifact, because -AllowUnsignedUpload was given"
}
$timestamped = $sig.Timestamped

if ($sig.Present) {
    # The subject alone is a string any certificate can carry. The published certificate is the
    # identity, so the pin is its thumbprint, and the ledger records that same thumbprint -- which
    # is what makes "signed by S.M.Y.T." a fact rather than a spelling.
    $identity = Get-SmytIdentity -Paths $paths
    Write-Host "  signer    : $($sig.Subject)"
    Write-Host "  thumbprint: $($sig.Thumbprint)"
    Write-Host "  timestamp : $(if ($timestamped) { 'present' } else { 'MISSING' })"
    Write-Host "  status    : $($sig.Status)"
    if ($sig.Thumbprint -ne $identity.Thumbprint) {
        throw ("the signature is from $($sig.Thumbprint) but the certificate published here is " +
               "$($identity.Thumbprint). Refusing to publish it as an S.M.Y.T. release.")
    }
    if (-not $timestamped) {
        # Without a timestamp the signature dies with the certificate, which for a five-year
        # certificate means every published build stops verifying in 2031. That is worth failing on.
        throw "no timestamp was obtained; the signature would expire with the certificate"
    }
    if ($sig.Status -ne 'Valid') {
        # Expected until the certificate's own root is trusted on this machine. Not fatal: the
        # signature is cryptographically present and timestamped, which is what publishing needs.
        Write-Warning "the signature does not verify on this machine yet (status $($sig.Status))."
        Write-Warning "That is the self-signed root not being trusted here; run smyt-sign.ps1 -Status."
    }
}

# --- 4. hashes --------------------------------------------------------------- #
Step 4 "hashes"
$final = Get-SmytHash -Path $stage
$size = (Get-Item -LiteralPath $stage).Length
Write-Host "  file   : $stage"
Write-Host "  size   : $size bytes"
Write-Host "  sha256 : $final"
# The standard form, '<hash>  <name>', so 'sha256sum -c' and every other tool that reads one of
# these can read this one. A bare hash is a number with no statement attached about what it covers.
$shaFile = $stage + '.sha256'
Set-Content -LiteralPath $shaFile -Value ("{0}  {1}" -f $final, [IO.Path]::GetFileName($stage)) -Encoding ASCII

# --- 5. publish -------------------------------------------------------------- #
if ($Publish) {
    Step 5 "publishing to GitHub"
    if (-not $Repo) { throw "-Publish needs -Repo <owner/name>" }
    if (-not $Tag) { throw "-Publish needs -Tag <tag>" }

    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "gh CLI not found" }

    $assetName = [IO.Path]::GetFileName($stage)
    # GitHub's asset naming ignores the '#label' suffix in some versions, so the local file is
    # given the exact name it should end up with rather than relying on a rename that may not happen.
    $upload = Join-Path $OutDir $assetName
    if ((Resolve-Path -LiteralPath $stage).Path -ne (Resolve-Path -LiteralPath $upload).Path) {
        Copy-Item -LiteralPath $stage -Destination $upload -Force
    }

    # The build, the hash of it, and the public certificate to check both against. A published hash
    # nobody can obtain does not let anyone check anything, and the certificate is what a stranger
    # needs to decide whether to trust the signature at all.
    $assets = @(
        @{ Path = $upload;  Digest = $final }
        @{ Path = $shaFile; Digest = (Get-SmytHash -Path $shaFile) }
    )
    if (Test-Path -LiteralPath $paths.Cer) {
        $assets += @{ Path = $paths.Cer; Digest = (Get-SmytHash -Path $paths.Cer) }
    } else {
        Write-Warning "there is no $($paths.Cer) to publish; nobody can pin the signing certificate to this release"
    }

    # Read the release's assets once as JSON and parse it, rather than filtering with an inline
    # --jq expression: nested quoting through PowerShell mangled the filter into something gh
    # tried to read as a function definition, and the failure arrived looking like a gh bug.
    $before = Invoke-SmytNative -Exe 'gh' -Arguments @('release', 'view', $Tag, '--repo', $Repo, '--json', 'assets')
    $existing = @()
    if ($before.Code -eq 0 -and $before.Output) {
        try { $existing = @((($before.Output -join "`n") | ConvertFrom-Json).assets | ForEach-Object { $_.name }) }
        catch { $existing = @() }
    }

    foreach ($a in $assets) {
        $name = [IO.Path]::GetFileName($a.Path)
        if ($existing -contains $name) {
            Write-Host "  replacing the existing asset $name"
            $null = Invoke-SmytNative -Exe 'gh' -Arguments @('release', 'delete-asset', $Tag, $name, '--repo', $Repo, '--yes')
        }
        $up = Invoke-SmytNative -Exe 'gh' -Arguments @('release', 'upload', $Tag, $a.Path, '--repo', $Repo)
        if ($up.Code -ne 0) {
            foreach ($line in $up.Output) { Write-Host "    $line" -ForegroundColor DarkGray }
            throw "uploading $name failed with exit code $($up.Code)"
        }
    }

    # Verify every published digest against the local one. This is the check that catches an upload
    # that went wrong in a way that would otherwise look like success.
    $after = Invoke-SmytNative -Exe 'gh' -Arguments @('release', 'view', $Tag, '--repo', $Repo, '--json', 'assets')
    if ($after.Code -ne 0 -or -not $after.Output) { throw "could not read back the release $Tag" }
    $remoteAssets = @((($after.Output -join "`n") | ConvertFrom-Json).assets)

    foreach ($a in $assets) {
        $name = [IO.Path]::GetFileName($a.Path)
        $remote = $remoteAssets | Where-Object { $_.name -eq $name } | Select-Object -First 1
        if (-not $remote) { throw "the asset $name is not on release $Tag after uploading it" }
        $remoteHash = ($remote.digest -replace '^sha256:', '').Trim().ToUpper()
        if (-not $remoteHash) { throw "GitHub reported no digest for $name; cannot confirm the upload" }
        if ($remoteHash -ne $a.Digest) {
            throw "published digest for $name is $remoteHash, which does not equal the local $($a.Digest)"
        }
        Write-Host ("  {0,-34} digest matches ({1}...)" -f $name, $remoteHash.Substring(0, 16))
    }

    # Where the build went is recorded as a new line rather than by editing the signing record: the
    # chain only means something while past lines are never rewritten, and "which release is this
    # signing record?" is a question the ledger should be able to answer on its own.
    $publishedThumb = ''
    if ($sig.Present) { $publishedThumb = $sig.Thumbprint }
    $publication = [ordered]@{
        t             = (Get-Date).ToUniversalTime().ToString('o')
        event         = 'published'
        repo          = $Repo
        tag           = $Tag
        url           = "https://github.com/$Repo/releases/tag/$Tag"
        name          = $assetName
        sha256_signed = $final
        thumbprint    = $publishedThumb
        assets        = @($assets | ForEach-Object { [IO.Path]::GetFileName($_.Path) })
        note          = $Note
    }
    Add-SmytLedgerRecord -Path $paths.Ledger -Record $publication
    Write-Host "  recorded the publication in $($paths.Ledger)"
}

# --- summary ----------------------------------------------------------------- #
Step '-' "done"
Write-Host "  artifact  : $stage"
Write-Host "  sha256    : $final"
if ($sig.Present) {
    Write-Host "  signer    : $($sig.Subject)"
    Write-Host "  thumbprint: $($sig.Thumbprint)"
    Write-Host "  timestamp : $(if ($timestamped) { 'yes (survives certificate expiry)' } else { 'no' })"
} else {
    Write-Host "  signer    : NONE (published unsigned on request)" -ForegroundColor Yellow
}
if ($Publish) { Write-Host "  published : https://github.com/$Repo/releases/tag/$Tag" }
