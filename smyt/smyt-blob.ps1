# smyt-blob.ps1 -- sign a release artifact that is not a PE file.
#
# Why this exists: smyt-sign.ps1 signs PE images, so its signature is embedded in the file and covers the whole
# image. A JavaScript package, a source tarball or a data file has no place to embed one, and the honest answer
# is not to manufacture an .exe just to have something signable. A detached PKCS#7 signature over the bytes says
# the same two things an Authenticode signature says - who signed it, and that the bytes have not changed - and
# anyone holding the public certificate can check it.
#
# What it deliberately does NOT claim: a detached signature is not Authenticode. Windows shows no Digital
# Signatures tab for it, SmartScreen ignores it, and no trust-store machinery applies. The trust story is the
# toolchain's own: the certificate is self-signed, this machine trusts the root, and a stranger verifies the
# signature only after importing the published .cer on purpose.
#
# The signing itself is signtool, exactly as smyt-sign.ps1 uses it, and for the same reason: signing with
# /sha1 <thumbprint> takes the key from the certificate store, so no password is ever placed on a command line
# where every process on the machine can read it. This script adds the two flags a non-PE artifact needs
# (/p7 to detach the signature, /p7co to state the content type) and reuses the toolchain's thumbprint, hashing
# and append-only ledger, so a blob signing is recorded next to the PE signings with the same field names.
# A blob record sets sha256_signed = sha256_unsigned, because the artifact is left byte-identical and the
# signature lives in a separate .p7s; its note says "detached PKCS#7" so the two kinds are told apart.
#
# Usage:
#   .\smyt-blob.ps1 -Sign <file> [-Note "..."] [-AllowUntimestamped]
#   .\smyt-blob.ps1 -Verify <file>
#   .\smyt-blob.ps1 -CheckFile <file>
#   .\smyt-blob.ps1 -Log [-Last 10]
#
# Three timestamp authorities are tried in order, as in the PE path, because one URL is a single point of
# failure for a step that is treated as fatal. If none answers, nothing is written unless -AllowUntimestamped
# is given, and the record is marked either way.

param(
    [string[]]$Sign,
    [string[]]$Verify,
    [string[]]$CheckFile,
    [string]$Note,
    [string[]]$TimestampUrl = @(
        'http://timestamp.digicert.com',
        'http://timestamp.sectigo.com',
        'http://timestamp.globalsign.com/tsa/r6advanced1'
    ),
    [switch]$AllowUntimestamped,
    [switch]$Log,
    [int]$Last = 10
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'smyt-common.ps1')

try { Repair-SmytModulePath | Out-Null } catch { }
$paths = Get-SmytPaths -SigningDir $here
$identity = Get-SmytIdentity -Paths $paths -RequirePrivateKey
$ledger = $paths.Ledger
$p7co = '1.2.840.113549.1.7.1'   # id-data: a plain CMS over the file's own bytes. signtool's default for /p7 is the Authenticode SIP form (SpcIndirectDataContent), which signs a hash structure rather than the bytes themselves and can then only be verified by Windows SIP machinery - no use to somebody checking a tarball by hand.

function Get-SignToolPath {
    $tool = Get-SmytSignTool
    if ($tool -is [string]) { return $tool }
    foreach ($name in @('Path', 'SignTool', 'Exe')) {
        if ($tool.PSObject.Properties[$name]) { return [string]$tool.$name }
    }
    throw 'could not read the signtool path out of Get-SmytSignTool'
}

$signtool = Get-SignToolPath

function Invoke-SignTool {
    param([string[]]$Arguments)
    $output = & $signtool @Arguments 2>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = ($output | Out-String).Trim() }
}

function Get-DetachedSignaturePath {
    param([string]$Path)
    return "$Path.p7s"
}

function New-BlobSignature {
    # Returns the authority that answered, or $null when the caller allowed an untimestamped signature.
    param([string]$Path, [string]$OutDir)

    $attempts = @()
    foreach ($tsa in $TimestampUrl) { $attempts += , @($tsa) }
    $attempts += , @()
    if (-not $AllowUntimestamped) { $attempts = @($attempts | Where-Object { $_.Count -eq 1 }) }

    $lastError = 'no timestamp authority was tried'
    foreach ($attempt in $attempts) {
        $signArgs = @('sign', '/sha1', $identity.Thumbprint, '/fd', 'sha256', '/p7', $OutDir, '/p7co', $p7co)
        if ($attempt.Count -eq 1) { $signArgs += @('/tr', $attempt[0], '/td', 'sha256') }
        $signArgs += $Path
        $run = Invoke-SignTool -Arguments $signArgs
        if ($run.Code -eq 0) {
            if ($attempt.Count -eq 1) { return $attempt[0] } else { return $null }
        }
        $lastError = $run.Output
        if ($attempt.Count -eq 1) { Write-Warning "timestamp authority $($attempt[0]) did not answer; trying the next one" }
    }
    throw "signtool could not sign $Path`: $lastError"
}

function Test-BlobSignature {
    # Two-part check, and the first part is the one that matters. signtool's /p7 output carries its own copy of
    # the signed bytes (measured: a 359 KB tarball produced a 367 KB .p7s), so verifying the signature alone
    # says the copy inside the file is intact - it says nothing about the file on disk. Measured 2026-10-15:
    # with one byte flipped in the tarball, a signature-only check reported "valid". So: the bytes on disk must
    # be the bytes inside the signature, and then the signature must verify against the published certificate.
    #
    # Verification is the cryptographic check rather than signtool's policy check: signtool verify /p7 refuses
    # to be combined with /pa, and with a self-signed certificate its policy pass reports trust errors on a
    # signature whose bytes are perfectly intact ("Number of errors: 2" - measured the same day).
    param([string]$Path)
    $sigPath = Get-DetachedSignaturePath -Path $Path
    if (-not (Test-Path -LiteralPath $sigPath)) { return [pscustomobject]@{ Ok = $false; Reason = 'no .p7s beside this file' } }
    try {
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $cms.Decode([System.IO.File]::ReadAllBytes($sigPath))
        if ($cms.SignerInfos.Count -ne 1) {
            return [pscustomobject]@{ Ok = $false; Reason = "expected one signer, found $($cms.SignerInfos.Count)" }
        }
        $embedded = $cms.ContentInfo.Content
        if (-not $embedded -or $embedded.Length -eq 0) {
            return [pscustomobject]@{ Ok = $false; Reason = 'the signature carries no copy of the bytes, so nothing ties it to this file' }
        }
        if ($embedded.Length -ne (Get-Item -LiteralPath $Path).Length) {
            return [pscustomobject]@{ Ok = $false; Reason = "the signed copy is $($embedded.Length) bytes and this file is $((Get-Item -LiteralPath $Path).Length)" }
        }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $embeddedHash = ([BitConverter]::ToString($sha.ComputeHash($embedded)) -replace '-', '') } finally { $sha.Dispose() }
        if ($embeddedHash -ne (Get-SmytHash -Path $Path)) {
            return [pscustomobject]@{ Ok = $false; Reason = 'this file is not the file that was signed' }
        }
        # CheckSignature returns void: failure is an exception, not a false return.
        $cms.CheckSignature($true)
        $stamped = @($cms.SignerInfos[0].UnsignedAttributes) | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.3.3.1' }
        $actual = $cms.SignerInfos[0].Certificate.Thumbprint
        if ($actual -ne $identity.Thumbprint) {
            return [pscustomobject]@{ Ok = $false; Reason = "signed by $actual, not by the published $($identity.Thumbprint)" }
        }
        return [pscustomobject]@{ Ok = $true; Reason = "the bytes on disk are the signed bytes, and the PKCS#7 verifies against the published certificate ($actual), timestamped: $(if ($stamped) { 'yes' } else { 'no' })" }
    } catch {
        return [pscustomobject]@{ Ok = $false; Reason = $_.Exception.Message }
    }
}

$failures = 0
$tempRoot = Join-Path $env:TEMP ('smyt-blob-' + [guid]::NewGuid().ToString('N').Substring(0, 8))

if ($Sign) {
    foreach ($item in $Sign) {
        $file = (Resolve-Path -LiteralPath $item).Path
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { Write-Error "not a file: $item"; $failures++; continue }
        if (Test-Path -LiteralPath (Get-DetachedSignaturePath -Path $file)) {
            Write-Error "$file already has a .p7s; remove it deliberately if you mean to re-sign"
            $failures++
            continue
        }

        $hash = Get-SmytHash -Path $file
        $size = (Get-Item -LiteralPath $file).Length
        New-Item -ItemType Directory -Force $tempRoot | Out-Null
        $tsa = New-BlobSignature -Path $file -OutDir $tempRoot

        $produced = Get-ChildItem -LiteralPath $tempRoot -Filter '*.p7' | Select-Object -First 1
        if (-not $produced) { Write-Error "signtool reported success but wrote no .p7 into $tempRoot"; $failures++; continue }
        Move-Item -LiteralPath $produced.FullName -Destination (Get-DetachedSignaturePath -Path $file) -Force

        # The standard "<hash>  <name>" form, so sha256sum -c can read it.
        $name = Split-Path -Leaf $file
        [System.IO.File]::WriteAllText("$file.sha256", "$hash  $name`n", (New-Object System.Text.UTF8Encoding($false)))

        $check = Test-BlobSignature -Path $file
        if (-not $check.Ok) {
            # Nothing half-done: a signature that does not verify is removed rather than left looking like one.
            Remove-Item -LiteralPath (Get-DetachedSignaturePath -Path $file) -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$file.sha256" -Force -ErrorAction SilentlyContinue
            Write-Error "the signature just written does not verify, so it was removed: $($check.Reason)"
            $failures++
            continue
        }

        $record = @{
            t               = (Get-Date).ToString('o')
            file            = $file
            name            = $name
            size            = $size
            sha256_signed   = $hash
            sha256_unsigned = $hash
            signer          = $identity.Subject
            thumbprint      = $identity.Thumbprint
            timestamped     = [bool]$tsa
            tsa             = $tsa
            note            = $(if ($Note) { "$Note (detached PKCS#7, not Authenticode)" } else { 'detached PKCS#7, not Authenticode' })
        }
        Add-SmytLedgerRecord -Path $ledger -Record $record

        Write-Output "signed $name"
        Write-Output "  bytes     : $size, sha256 $hash"
        Write-Output "  signature : $name.p7s (detached PKCS#7), $($check.Reason)"
        Write-Output "  timestamp : $(if ($tsa) { $tsa } else { 'none (recorded as untimestamped)' })"
        Write-Output "  hash file : $name.sha256"
        Write-Output "  ledger    : appended, $((Read-SmytLedger -Path $ledger).Count) record(s) total"
    }
}

if ($Verify) {
    foreach ($item in $Verify) {
        $file = (Resolve-Path -LiteralPath $item).Path
        $check = Test-BlobSignature -Path $file
        $hash = Get-SmytHash -Path $file
        $hashOk = $null
        if (Test-Path -LiteralPath "$file.sha256") {
            $recorded = (Get-Content -LiteralPath "$file.sha256" -TotalCount 1).Split(' ')[0].ToUpper()
            $hashOk = ($recorded -eq $hash)
        }
        Write-Output "$(Split-Path -Leaf $file)"
        Write-Output "  signature : $(if ($check.Ok) { 'valid' } else { 'INVALID' }) - $($check.Reason)"
        Write-Output "  sha256    : $hash$(if ($hashOk -eq $false) { '  (does NOT match the .sha256 beside it)' } elseif ($hashOk -eq $true) { '  (matches the .sha256 beside it)' } else { '  (no .sha256 beside it)' })"
        if (-not $check.Ok) { $failures++ }
    }
}

if ($CheckFile) {
    $read = Read-SmytLedger -Path $ledger
    foreach ($item in $CheckFile) {
        $file = (Resolve-Path -LiteralPath $item).Path
        $hash = Get-SmytHash -Path $file
        $hit = $read.Records | Where-Object { $_.file -eq $file } | Select-Object -Last 1
        if (-not $hit) { Write-Output "NOT IN LEDGER: $file"; $failures++; continue }
        if ($hit.sha256_signed -ne $hash) {
            Write-Output "CHANGED SINCE SIGNING: $file`n  ledger $($hit.sha256_signed)`n  disk   $hash"
            $failures++
            continue
        }
        Write-Output "in the ledger and unchanged: $(Split-Path -Leaf $file) (signed $($hit.t))"
    }
}

if ($Log) {
    $read = Read-SmytLedger -Path $ledger
    # Read-SmytLedger reports Records and Count; a count of lines that did not parse is not exposed as a
    # field, so the honest answer here is 'not checked' rather than a number this script would be inventing.
    $unparsedText = 'not checked (Read-SmytLedger exposes Records and Count only)'
    Write-Output "ledger: $($read.Count) record(s), unparsed lines: $unparsedText"
    foreach ($r in ($read.Records | Select-Object -Last $Last)) {
        Write-Output "  $($r.t)  $(Split-Path -Leaf $r.file)  $(if ($r.note) { $r.note })"
    }
}

if (-not $Sign -and -not $Verify -and -not $CheckFile -and -not $Log) {
    Write-Output 'nothing asked for: pass -Sign, -Verify, -CheckFile or -Log'
}

if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
exit $(if ($failures) { 1 } else { 0 })
