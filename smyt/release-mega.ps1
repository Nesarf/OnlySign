# release-mega.ps1 -- one command for a mega-index-map release.
#
# The shape is release-nanodesu.ps1's: this script owns mega's paths and arguments, and every actual step is the
# toolchain's own work (smyt-blob.ps1 for the signature, git for the tag, gh for the release). Nothing is
# assumed: each step is checked, and a step that fails stops the release rather than leaving a half-published
# version behind.
#
# Steps
#   1. preconditions  worktree clean, package.json version equals -Version, tag not taken, invariants and the
#                     self-check green (skip the last two with -SkipChecks)
#   2. pack           npm pack into a staging directory
#   3. sign           smyt-blob.ps1 -Sign: detached PKCS#7 with an RFC-3161 timestamp, recorded in the ledger
#   4. verify         smyt-blob.ps1 -Verify and -CheckFile, so a signature that does not verify stops here
#   5. archive        tarball, .p7s, .sha256 and the public certificate into the downloads directory
#   6. tag            (with -Tag) an annotated tag at HEAD, pushed - HEAD because the artifact was packed from it
#   7. publish        (with -Publish) wait for the workflow, upload the four assets, write the release notes
#
# Usage:
#   .\release-mega.ps1 -Version 0.3.8                     # check, pack, sign, verify, archive
#   .\release-mega.ps1 -Version 0.3.8 -Tag                # ... and tag + push (starts the release workflow)
#   .\release-mega.ps1 -Version 0.3.8 -Tag -Publish       # ... and attach the signed files to the release
#   .\release-mega.ps1 -Version 0.3.8 -DryRun             # preconditions and pack only, sign nothing
#
# Why signing lives here rather than in the repository: signtool and the certificate store are properties of
# this machine, so a script that drove them could not be shipped in the package without becoming a claim about
# somebody else's machine. docs/verification.md in the repository describes what a reader gets and how to check
# it; this file is how it gets produced.

param(
    [Parameter(Mandatory)][string]$Version,
    [string]$Repo = 'E:\mega-index-map',
    [string]$Downloads = 'D:\DaShaoHuo\downloads',
    [string]$Note,
    [switch]$Tag,
    [switch]$Publish,
    [switch]$PublishOnly,
    [switch]$DryRun,
    [switch]$SkipChecks
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$blob = Join-Path $here 'smyt-blob.ps1'
$cer = Join-Path $here 'smyt-codesign.cer'
$tagName = "v$Version"
# Staging and the transient notes files live under the machine's cache directory, not in $env:TEMP: the standing
# rule on this machine is that no temporary or large file lands on the system drive, and $env:TEMP is exactly
# that drive. ($env:TEMP also came back empty in one run, and Join-Path refuses a null -Path - which is how the
# release body came to be the only step that silently did nothing, after the files had already been uploaded.)
$tmpDir = 'D:\DaShaoHuo\cache\tmp\signing'
New-Item -ItemType Directory -Force $tmpDir | Out-Null
$stage = Join-Path $tmpDir ("mega-release-" + $Version)
$archive = Join-Path $Downloads "mega-index-map-$Version"
$failures = 0
# -PublishOnly skips to step 7 for a tag that is already pushed and signed: watching the workflow, attaching the
# four files and writing the notes, without packing or signing anything a second time.
if ($PublishOnly) { $Publish = $true }

function Step { param([string]$Text) Write-Output ""; Write-Output "== $Text" }
function Ok { param([string]$Text) Write-Output "   $Text" }
function Fail { param([string]$Text) Write-Output "   REFUSED: $Text"; $script:failures++ }
function Run {
    # -Where moves the working directory and puts it back. The first version declared the parameter and never
    # used it, so `npm run check` ran in whatever directory the caller happened to be in - the preconditions
    # caught it by refusing, which is the argument for having preconditions at all.
    param([string]$Exe, [string[]]$Arguments, [string]$Where)
    $cwd = (Get-Location).ProviderPath
    if ($Where) { Set-Location -LiteralPath $Where }
    try {
        $out = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        Set-Location -LiteralPath $cwd
    }
    return [pscustomobject]@{ Code = $code; Output = ($out | Out-String).Trim() }
}

if (-not (Test-Path -LiteralPath $blob)) { throw "the toolchain's smyt-blob.ps1 is not next to this script: $blob" }
if (-not (Test-Path -LiteralPath $cer)) { throw "the public certificate is not next to this script: $cer" }
if (-not (Test-Path -LiteralPath $Repo)) { throw "the repository is not at $Repo" }
$git = 'git'
$npm = 'npm'

if (-not $PublishOnly) {
Step "1. preconditions for $tagName"
$pkgPath = Join-Path $Repo 'package.json'
$pkg = Get-Content -LiteralPath $pkgPath -Raw | ConvertFrom-Json
if ($pkg.version -ne $Version) {
    Fail "package.json says $($pkg.version) and -Version says $Version; bump the manifest first, so the tag, the tarball and the manifest all name the same release"
} else {
    Ok "package.json version is $Version"
}
$status = (Run -Exe $git -Arguments @('-C', $Repo, 'status', '--porcelain')).Output
if ($status) { Fail "the worktree is not clean; commit or stash first:`n$status" } else { Ok 'the worktree is clean' }
$existing = (Run -Exe $git -Arguments @('-C', $Repo, 'tag', '--list', $tagName)).Output
if ($existing) { Fail "tag $tagName already exists" } else { Ok "tag $tagName is free" }
$head = (Run -Exe $git -Arguments @('-C', $Repo, 'rev-parse', 'HEAD')).Output
Ok "HEAD is $($head.Substring(0, 7))"

if (-not $SkipChecks) {
    $check = Run -Exe $npm -Arguments @('run', '--silent', 'check') -Where $Repo
    if ($check.Code -ne 0) { Fail "npm run check failed`n$($check.Output)" } else { Ok 'the four invariants agree' }
    Push-Location $Repo
    try {
        $self = Run -Exe 'node' -Arguments @('scripts/selfcheck.mjs')
        $selfLine = ($self.Output -split "`n" | Where-Object { $_ -match '^summary:' } | Select-Object -Last 1)
        if ($self.Code -ne 0) { Fail "the self-check failed`n$($self.Output)" } else { Ok "self-check: $selfLine" }
    } finally { Pop-Location }
} else {
    Ok 'invariants and self-check skipped on request'
}

if ($failures) { Write-Output ""; Write-Output "$failures precondition(s) failed; nothing was packed, signed or tagged."; exit 1 }

Step '2. pack'
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null
Push-Location $Repo
try { $packed = Run -Exe $npm -Arguments @('pack', '--pack-destination', $stage) } finally { Pop-Location }
if ($packed.Code -ne 0) { Write-Output "   npm pack failed`n$($packed.Output)"; exit 1 }
$tgz = (Get-ChildItem -LiteralPath $stage -Filter '*.tgz' | Select-Object -First 1).FullName
if (-not $tgz) { Write-Output '   npm pack reported success but produced no .tgz'; exit 1 }
$size = (Get-Item -LiteralPath $tgz).Length
$hash = (Get-FileHash -LiteralPath $tgz -Algorithm SHA256).Hash
Ok "$(Split-Path -Leaf $tgz): $size bytes, sha256 $hash"

if ($DryRun) {
    Write-Output ''
    Write-Output "dry run: packed and stopped. Would sign with smyt-blob.ps1, verify, archive to $archive$(if ($Tag) { ", tag $tagName at $($head.Substring(0,7)) and push" })$(if ($Publish) { ', then upload the four assets to the GitHub release' })."
    exit 0
}

Step '3. sign'
$signNote = if ($Note) { $Note } else { "mega-index-map $Version release tarball, commit $($head.Substring(0, 7))" }
$sign = Run -Exe 'pwsh' -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $blob, '-Sign', $tgz, '-Note', $signNote)
if ($sign.Code -ne 0) { Write-Output "   signing failed; nothing was archived or tagged`n$($sign.Output)"; exit 1 }
Ok (($sign.Output -split "`n" | Where-Object { $_ -match 'signature|timestamp|ledger' }) -join "`n   ")

Step '4. verify'
$verify = Run -Exe 'pwsh' -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $blob, '-Verify', $tgz)
$checkFile = Run -Exe 'pwsh' -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $blob, '-CheckFile', $tgz)
if ($verify.Code -ne 0 -or $checkFile.Code -ne 0) {
    Write-Output "   the signature does not verify; stopping before the archive and the tag`n$($verify.Output)`n$($checkFile.Output)"
    exit 1
}
Ok (($verify.Output -split "`n" | Where-Object { $_ -match 'signature|sha256' }) -join "`n   ")
Ok (($checkFile.Output -split "`n" | Where-Object { $_ }) -join "`n   ")

Step '5. archive'
New-Item -ItemType Directory -Force $archive | Out-Null
foreach ($f in @($tgz, "$tgz.p7s", "$tgz.sha256")) { Copy-Item -LiteralPath $f -Destination $archive -Force }
Copy-Item -LiteralPath $cer -Destination $archive -Force
Ok "$archive holds $((Get-ChildItem -LiteralPath $archive).Count) file(s) for a reader to check with"

if ($Tag) {
    Step "6. tag $tagName"
    $notes = Join-Path $tmpDir "mega-$Version-tag.txt"
    @"
mega-index-map $Version

The release tarball published with this tag is signed: PKCS#7 under O=S.M.Y.T., CN=S.M.Y.T. Code Signing,
thumbprint 4EA54E72A1EEFAE280B99631F7680DBFF461C4F1, with an RFC-3161 timestamp. It was built from this
commit.

  $(Split-Path -Leaf $tgz)
  sha256 $hash

The repository's docs/verification.md says how to check it, and what the signature does and does not prove.
"@ | Set-Content -LiteralPath $notes -Encoding UTF8
    $tagged = Run -Exe $git -Arguments @('-C', $Repo, 'tag', '-a', $tagName, $head, '-F', $notes)
    if ($tagged.Code -ne 0) { Write-Output "   git tag failed`n$($tagged.Output)"; exit 1 }
    $pushed = Run -Exe $git -Arguments @('-C', $Repo, 'push', 'origin', $tagName)
    if ($pushed.Code -ne 0) { Write-Output "   git push failed; the tag exists locally only`n$($pushed.Output)"; exit 1 }
    Ok "tagged and pushed $tagName at $($head.Substring(0, 7))"
}

}

if ($Publish) {
    if ($PublishOnly) {
        # Nothing was packed in this run, so the name, the size and the hash come back out of the archive that the
        # earlier run left behind. The first version of this used $tgz directly, which is null here - and because
        # the release notes below are a double-quoted here-string, "$(Split-Path -Leaf $tgz)" was evaluated and
        # blew up on a null -Path after the files had already been uploaded.
        $archived = Get-ChildItem -LiteralPath $archive -Filter '*.tgz' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $archived) { Write-Output "   -PublishOnly needs the archive built earlier, and $archive holds no tarball"; exit 1 }
        $tgz = $archived.FullName
        $size = $archived.Length
        $hashFile = "$tgz.sha256"
        if (-not (Test-Path -LiteralPath $hashFile)) { Write-Output "   $hashFile is missing, so the hash to publish is unknown"; exit 1 }
        $hash = (Get-Content -LiteralPath $hashFile -TotalCount 1).Split(' ')[0].ToUpper()
        Ok "publishing the archive already built: $(Split-Path -Leaf $tgz), $size bytes, sha256 $hash"
    }
    Step '7. publish'
    if (-not $Tag -and -not $PublishOnly) { Write-Output '   -Publish needs -Tag (there is no release without a tag)'; exit 1 }
      # A tag name can be reused (delete, re-push), and gh keeps the runs of the earlier push under the same
      # headBranch. Match on the creation time as well, so only the run that belongs to THIS push is a candidate.
      # Ten minutes is generous for the workflow to appear, and tight enough that two re-releases inside it are
      # the only way to confuse it - which a person would notice anyway.
      $since = (Get-Date).ToUniversalTime().AddMinutes(-10).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $run = $null
    foreach ($attempt in 1..30) {
        # Single-quoted concatenation: PowerShell does not take \" inside a double-quoted string the way a shell does.
          $jq = '.[] | select(.headBranch=="' + $tagName + '" and .createdAt >= "' + $since + '") | .databaseId'
          $list = Run -Exe 'gh' -Arguments @('run', 'list', '--limit', '30', '--json', 'databaseId,headBranch,status,createdAt', '--jq', $jq) -Where $Repo
        if ($list.Output) { $run = ($list.Output -split "`n")[0].Trim(); break }
        Start-Sleep -Seconds 5
    }
    if (-not $run) { Write-Output "   no workflow run appeared for $tagName within 150 s; the tag is pushed, so check it by hand" }
    else {
        Ok "workflow run $run"
        $watch = Run -Exe 'gh' -Arguments @('run', 'watch', $run, '--exit-status') -Where $Repo
        Ok $(if ($watch.Code -eq 0) { 'the workflow succeeded' } else { "the workflow did not succeed; not uploading`n$($watch.Output)" })
        if ($watch.Code -eq 0) {
            $upload = Run -Exe 'gh' -Arguments (@('release', 'upload', $tagName) + (Get-ChildItem -LiteralPath $archive | ForEach-Object { $_.FullName }) + @('--clobber')) -Where $Repo
            if ($upload.Code -ne 0) { Write-Output "   uploading failed`n$($upload.Output)" } else { Ok 'the four signed files are attached' }
            # The workflow's notes carry the install and upgrade lines and the changelog; the signature section is
            # APPENDED to them rather than written over the top. Done by hand the first time, the changelog
            # disappeared - which is why this comment exists.
            $json = (Run -Exe 'gh' -Arguments @('release', 'view', $tagName, '--json', 'body') -Where $Repo).Output
            $existingBody = ''
            if ($json) { try { $existingBody = ($json | ConvertFrom-Json).body } catch { $existingBody = '' } }
            $body = Join-Path $tmpDir "mega-$Version-release.md"
            $signature = @"
**Signed release.** The tarball below is signed with the S.M.Y.T. code signing certificate:

``````
subject    : O=S.M.Y.T., CN=S.M.Y.T. Code Signing
thumbprint : 4EA54E72A1EEFAE280B99631F7680DBFF461C4F1
valid to   : 2031-10-05
``````

``````
sha256 $hash
``````

Check it with nothing but tools you already have:

``````
sha256sum -c $(Split-Path -Leaf $tgz).sha256
openssl cms -verify -inform DER -in $(Split-Path -Leaf $tgz).p7s -noverify -out /dev/null
``````

What the signature does **not** prove: the certificate is self-signed, so Windows on a machine that has not
imported it will not trust the download; a ``.p7s`` is not Authenticode and has no Digital Signatures page; the
signature vouches for these bytes, not for what they contain. The repository's ``docs/verification.md`` walks
through all of it.
"@
            $newBody = if ($existingBody -match '\S') { $existingBody.TrimEnd() + "`n`n" + $signature } else { $signature }
            [System.IO.File]::WriteAllText($body, $newBody, (New-Object System.Text.UTF8Encoding($false)))
            $edited = Run -Exe 'gh' -Arguments @('release', 'edit', $tagName, '--title', "mega-index-map $Version", '--notes-file', $body, '--latest') -Where $Repo
            if ($edited.Code -eq 0) { Ok 'release notes written, and this release marked latest' } else { Write-Output "   editing the release failed`n$($edited.Output)" }
        }
    }
}

if (-not $PublishOnly) {
Write-Output ''
Write-Output "release ${Version}: $size bytes, sha256 $hash"
Write-Output "archived in $archive"
if (-not $Tag) { Write-Output 'not tagged (pass -Tag when the commit is the one you mean to release)' }
if (-not $Publish) { Write-Output 'not published to GitHub (pass -Publish to attach the signed files)' }
}
