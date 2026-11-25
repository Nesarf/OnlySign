# smyt-selftest.ps1 -- run the signing toolchain against itself, in a scratch directory
#
# Every one of these checks exists because the thing it checks was wrong at least once and nothing
# noticed: the ledger was read with the wrong encoding and lost Chinese records, signtool was
# picked by sorting full paths and an x86 build won, and the chain's tip was read outside the
# append so two concurrent signings forged a fork that looked like an edit. A toolchain whose job
# is to say "this has not been altered" should be able to say that about itself.
#
# Nothing here touches the real ledger, the real certificate's files, the trust stores, or any
# build output: everything happens under -ScratchRoot and is removed afterwards.
#
# Usage:
#   .\smyt-selftest.ps1
#   .\smyt-selftest.ps1 -IncludeCertificateTest    also exercise -NewCertificate, with a throwaway subject
#   .\smyt-selftest.ps1 -Keep                      leave the scratch directory behind to look at

param(
    [string]$SigningDir = '',
    [string]$ScratchRoot = 'D:\DaShaoHuo\cache\tmp\smyt-selftest',
    # A signed PE to strip and then re-sign. Left empty, a list of candidates is tried and the
    # first one whose signature can actually be removed is used: signtool remove refuses some
    # Microsoft binaries outright (notepad, cmd and calc all fail with 0x57 here, explorer does
    # not), so assuming any particular one works is exactly how this test first broke.
    [string]$Sample = '',
    [switch]$IncludeCertificateTest,
    [switch]$Keep
)

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $SigningDir) { $SigningDir = $here }

. (Join-Path $here 'smyt-common.ps1')
Repair-SmytModulePath
Assert-SmytModules 'Get-AuthenticodeSignature'

$signScript = Join-Path $SigningDir 'smyt-sign.ps1'
$failures = 0
$passed = 0

function Check {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Body)
    try {
        & $Body
        Write-Host "  ok      $Name"
        $script:passed++
    } catch {
        Write-Host "  FAILED  $Name" -ForegroundColor Red
        Write-Host "          $($_.Exception.Message)" -ForegroundColor DarkGray
        $script:failures++
    }
}

function Assert-Same {
    param($Actual, $Expected, [string]$What)
    if ($Actual -ne $Expected) { throw "$What : got [$Actual], expected [$Expected]" }
}

function Assert-Throws {
    param([Parameter(Mandatory)][scriptblock]$Body, [string]$Match)
    $message = ''
    $threw = $false
    try { & $Body } catch { $threw = $true; $message = $_.Exception.Message }
    if (-not $threw) { throw "this was expected to fail, and it succeeded" }
    if ($Match -and $message -notlike "*$Match*") { throw "it failed, but for the wrong reason: $message" }
}

function New-VerdictFixture {
    # A real PE with a byte appended, so the hash differs from every other fixture's and
    # Get-AuthenticodeSignature has something it knows how to read.
    param([string]$Source, [string]$Dir, [string]$Name, [string]$Marker)
    $p = Join-Path $Dir $Name
    Copy-Item -LiteralPath $Source -Destination $p -Force
    [System.IO.File]::AppendAllText($p, $Marker)
    return $p
}

function Invoke-Sign {
    param([string[]]$Arguments)
    return (Invoke-SmytNative -Exe 'powershell' -Arguments (@(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $signScript) + $Arguments))
}

function Remove-SmytSignatureTable {
    # Removes an embedded Authenticode signature by clearing the PE's certificate-table entry and
    # truncating the file where that table began. signtool has a remove verb, but it cannot be
    # relied on: it refuses some Microsoft binaries outright (0x57), and on at least one it exits
    # zero having removed nothing. Doing it here also says plainly what a signature physically is
    # -- a table appended after everything else, which is why "sign last" is not a preference.
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 0x40) { throw 'not a PE file (shorter than a DOS header)' }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($peOffset -le 0 -or ($peOffset + 24) -ge $bytes.Length) { throw 'not a PE file (implausible e_lfanew)' }
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45) { throw 'not a PE file (no PE signature)' }

    $optOffset = $peOffset + 24
    $magic = [BitConverter]::ToUInt16($bytes, $optOffset)
    if ($magic -eq 0x10B) { $dirOffset = $optOffset + 96 }        # PE32
    elseif ($magic -eq 0x20B) { $dirOffset = $optOffset + 112 }   # PE32+
    else { throw ("unknown optional header magic 0x{0:X}" -f $magic) }

    $entry = $dirOffset + (4 * 8)   # IMAGE_DIRECTORY_ENTRY_SECURITY
    if (($entry + 8) -gt $bytes.Length) { throw 'the optional header has no certificate-table entry' }
    $certOffset = [int][BitConverter]::ToUInt32($bytes, $entry)
    $certSize = [BitConverter]::ToUInt32($bytes, $entry + 4)
    if ($certSize -eq 0 -or $certOffset -eq 0) { return $false }
    if ($certOffset -ge $bytes.Length) { throw 'the certificate table points past the end of the file' }

    $kept = New-Object byte[] $certOffset
    [Array]::Copy($bytes, $kept, $certOffset)
    for ($i = 0; $i -lt 8; $i++) { $kept[$entry + $i] = 0 }
    [System.IO.File]::WriteAllBytes($Path, $kept)
    return $true
}

# --- scratch ----------------------------------------------------------------- #
if (Test-Path -LiteralPath $ScratchRoot) { Remove-Item -Recurse -Force -LiteralPath $ScratchRoot }
New-Item -ItemType Directory -Force -Path $ScratchRoot | Out-Null
$scratch = $ScratchRoot
$ledger = Join-Path $scratch 'smyt-signings.ndjson'

$real = Get-SmytPaths -SigningDir $SigningDir
$realThumb = ''
if (Test-Path -LiteralPath $real.Cer) {
    $realThumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($real.Cer)).Thumbprint
}
foreach ($f in @($real.Pfx, $real.Cer, $real.Pw)) {
    if (Test-Path -LiteralPath $f) { Copy-Item -LiteralPath $f -Destination (Join-Path $scratch ([IO.Path]::GetFileName($f))) -Force }
}

Write-Host "S.M.Y.T. signing self-test"
Write-Host "  signing dir : $SigningDir"
Write-Host "  scratch     : $scratch"
Write-Host ""

# --- 1. the scripts parse ----------------------------------------------------- #
Write-Host "syntax"
foreach ($f in 'smyt-common.ps1', 'smyt-sign.ps1', 'smyt-release.ps1', 'release-nanodesu.ps1') {
    Check $f {
        $p = Join-Path $here $f
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$errors)
        if ($errors -and $errors.Count) { throw "$($errors.Count) parse error(s), first: $($errors[0].Message)" }
    }
}

# --- 2. hashing --------------------------------------------------------------- #
Write-Host ""
Write-Host "hashing and encoding"
Check 'sha256 of a known string' {
    $f = Join-Path $scratch 'abc.txt'
    Set-Content -LiteralPath $f -Value 'abc' -Encoding ASCII -NoNewline
    # The published test vector for "abc"; a hash function that is merely self-consistent would
    # still fail this.
    Assert-Same (Get-SmytHash -Path $f) 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD' 'sha256("abc")'
}

Check 'the ledger is written without a BOM and read back exactly' {
    $probe = Join-Path $scratch 'encoding.ndjson'
    # This note ends in a character whose tail byte pairs with the closing quote under code page
    # 936 -- the exact shape that used to make a record unparseable.
    #
    # It is built from code points rather than written literally, and that is not fussiness:
    # Windows PowerShell reads a .ps1 with no byte order mark using the machine's ANSI code page,
    # so a literal would be misdecoded here and this file would fail to parse -- the same failure,
    # in the file that tests for it. Keeping this script pure ASCII means no editor, tool or
    # rewrite can break it by dropping a mark it does not know to keep.
    $note = [char]0x7F16 + [char]0x7801 + [char]0x5F80 + [char]0x8FD4 + ' ' + [char]0x5668
    Add-SmytLedgerRecord -Path $probe -Record ([ordered]@{ t = 'x'; name = 'n'; note = $note })
    $bytes = [System.IO.File]::ReadAllBytes($probe)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw 'the ledger was written with a BOM'
    }
    $back = Read-SmytLedger -Path $probe
    Assert-Same $back.Broken 0 'unparseable lines'
    Assert-Same $back.Records[0].note $note 'the note read back'
}

# --- 3. the chain ------------------------------------------------------------- #
Write-Host ""
Write-Host "the ledger chain"
Check 'five appends in a row chain cleanly' {
    $probe = Join-Path $scratch 'chain.ndjson'
    foreach ($i in 1..5) {
        Add-SmytLedgerRecord -Path $probe -Record ([ordered]@{ t = "$i"; name = "n$i" })
    }
    $l = Read-SmytLedger -Path $probe
    $c = Get-SmytLedgerChain -Ledger $l
    Assert-Same $l.Count 5 'records'
    Assert-Same $c.BrokenAt.Count 0 'breaks'
    Assert-Same $c.Chained 5 'chained records'
}

Check 'six signings appending at once still chain cleanly' {
    # The regression test for the fork: five separate processes append to one ledger with no
    # coordination beyond the lock the append takes for itself.
    $probe = Join-Path $scratch 'concurrent.ndjson'
    $common = Join-Path $here 'smyt-common.ps1'
    $jobs = @()
    foreach ($i in 1..6) {
        $jobs += Start-Job -ScriptBlock {
            param($Common, $Ledger, $Index)
            . $Common
            Add-SmytLedgerRecord -Path $Ledger -Record ([ordered]@{
                t    = (Get-Date).ToUniversalTime().ToString('o')
                name = "worker-$Index"
                note = "concurrent $Index"
            })
        } -ArgumentList $common, $probe, $i
    }
    $null = $jobs | Wait-Job
    $broken = @($jobs | Where-Object { $_.State -ne 'Completed' })
    foreach ($j in $jobs) { Remove-Job -Job $j -Force }
    if ($broken.Count -gt 0) { throw "$($broken.Count) of 6 appending processes did not finish" }

    $l = Read-SmytLedger -Path $probe
    $c = Get-SmytLedgerChain -Ledger $l
    Assert-Same $l.Count 6 'records'
    Assert-Same $c.BrokenAt.Count 0 'breaks in the chain'
}

Check 'an edited line is reported as a break' {
    # The other half: the chain has to actually notice an edit, or it is decoration.
    $probe = Join-Path $scratch 'tamper.ndjson'
    foreach ($i in 1..3) { Add-SmytLedgerRecord -Path $probe -Record ([ordered]@{ t = "$i"; name = "n$i" }) }
    $lines = [System.IO.File]::ReadAllLines($probe)
    $lines[1] = $lines[1].Replace('"n2"', '"n2-edited"')
    [System.IO.File]::WriteAllLines($probe, $lines, (New-Object System.Text.UTF8Encoding($false)))
    $l = Read-SmytLedger -Path $probe
    $c = Get-SmytLedgerChain -Ledger $l
    Assert-Same $c.BrokenAt.Count 1 'breaks after editing line 2'
}

# --- 4. the guard rails ------------------------------------------------------- #
Write-Host ""
Write-Host "guard rails"
Check 'a drive root is refused as an output directory' {
    Assert-Throws { $null = Assert-SmytOutDir -Path 'E:\' } 'drive root'
}
Check 'an output directory outside the allowed roots is refused' {
    Assert-Throws { $null = Assert-SmytOutDir -Path 'C:\Temp' } 'outside'
    Assert-Throws { $null = Assert-SmytOutDir -Path 'D:\DaShaoHuo_NOT_REALLY' } 'outside'
}
Check 'a path under the allowed root is accepted' {
    $null = Assert-SmytOutDir -Path 'D:\DaShaoHuo\build-artifacts\staging'
}

Check 'the environment guard puts this PowerShell''s own modules first' {
    $env:PSModulePath = 'C:\Program Files\PowerShell\7\Modules;' + $env:PSModulePath
    Repair-SmytModulePath
    $first = @($env:PSModulePath -split ';')[0]
    Assert-Same $first (Join-Path $PSHOME 'Modules') 'first PSModulePath entry'
}

# --- 5. signing, end to end --------------------------------------------------- #
Write-Host ""
Write-Host "signing, in a scratch directory"
# Named apart from the -Sample parameter on purpose: PowerShell variable names are not case
# sensitive, so a local $sample silently overwrites the parameter $Sample, and the check below
# then looks for a file it has not copied yet.
$sampleCopy = Join-Path $scratch 'sample.exe'
$sources = New-Object System.Collections.ArrayList
if ($Sample) {
    if (-not (Test-Path -LiteralPath $Sample)) { throw "no sample file at $Sample" }
    [void]$sources.Add($Sample)
} else {
    [void]$sources.Add('C:\Windows\explorer.exe')
    [void]$sources.Add('C:\Windows\System32\notepad.exe')
    [void]$sources.Add('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
    # Best of all, something this toolchain signed itself -- it is a real build of ours, and a
    # previous signing is the only thing guaranteed to exist on a machine where this runs.
    $known = Read-SmytLedger -Path $real.Ledger
    foreach ($rec in $known.Records) {
        if ($null -eq $rec.PSObject.Properties['file']) { continue }
        if ($rec.file -and (Test-Path -LiteralPath $rec.file)) { [void]$sources.Add($rec.file) }
    }
}

$copiedFrom = ''
$stripped = $false
$lastFailure = ''
foreach ($cand in $sources) {
    if (-not (Test-Path -LiteralPath $cand)) { continue }
    Copy-Item -LiteralPath $cand -Destination $sampleCopy -Force
    if (-not (Remove-SmytSignatureTable -Path $sampleCopy)) {
        $lastFailure = "$cand carries no embedded signature to remove"
        continue
    }
    $s = Get-SmytSignature -Path $sampleCopy
    if ($s.Present) {
        $lastFailure = "$cand still reports a signature after its certificate table was cleared"
        continue
    }
    $copiedFrom = $cand
    $stripped = $true
    break
}
if (-not $stripped) {
    throw "no usable unsigned sample out of $($sources.Count) candidate(s); last: $lastFailure. Pass -Sample <a signed PE>."
}
Write-Host "  sample taken from $copiedFrom"

Check 'the sample starts out unsigned' {
    $s = Get-SmytSignature -Path $sampleCopy
    if ($s.Present) { throw "the stripped sample still carries a signature from $($s.Subject)" }
}

Check 'a file is signed, timestamped, and by the published certificate' {
    $r = Invoke-Sign @('-Sign', $sampleCopy, '-Note',
        ([char]0x81EA + [char]0x6D4B + [char]0x56DE + [char]0x5F52 + ' ' + [char]0x5668), '-SigningDir', $scratch)
    if ($r.Code -ne 0) { throw "signing exited $($r.Code): $(@($r.Output | Select-Object -Last 3) -join ' | ')" }
    $s = Get-SmytSignature -Path $sampleCopy
    if (-not $s.Present) { throw 'signtool reported success and the file has no signature' }
    if (-not $s.Timestamped) { throw 'the signature carries no timestamp' }
    if ($realThumb -and $s.Thumbprint -ne $realThumb) { throw "signed by $($s.Thumbprint), not the published $realThumb" }
}

Check 'the ledger reads it back as signed and unaltered' {
    $r = Invoke-Sign @('-Check', '-SigningDir', $scratch)
    if ($r.Code -ne 0) { throw "check exited $($r.Code)" }
    $text = @($r.Output) -join "`n"
    if ($text -notmatch '1 unchanged') { throw "the audit did not report an unchanged record: $text" }
    if ($text -notmatch 'chain intact') { throw "the audit did not report an intact chain: $text" }
}

Check 'the ledger record names the file and the published certificate' {
    $l = Read-SmytLedger -Path $ledger
    Assert-Same $l.Count 1 'records'
    Assert-Same $l.Records[0].name 'sample.exe' 'recorded name'
    if ($realThumb) { Assert-Same $l.Records[0].thumbprint $realThumb 'recorded thumbprint' }
    if (-not $l.Records[0].timestamped) { throw 'the record says the signature is not timestamped' }
}

Check 'the same file is refused a second time without -Force' {
    Assert-Throws { $r = Invoke-Sign @('-Sign', $sampleCopy, '-SigningDir', $scratch); if ($r.Code -eq 0) { throw 'it signed again' } else { throw (@($r.Output) -join ' ') } } 'already carries a signature'
}

Check 'asking about a file this tool never signed fails rather than shrugs' {
    Assert-Throws { $r = Invoke-Sign @('-CheckFile', 'C:\Windows\System32\notepad.exe', '-SigningDir', $scratch); throw (@($r.Output) -join ' ') } 'never signed'
}

Check 'a release rehearsal does not append to the real ledger' {
    # -SignOnly, so no PyInstaller build is needed and this stays quick. The failure it is for:
    # -SigningDir used to stop at the edge of the release script, and again at the edge of the
    # wrapper above it, so a rehearsal against a copied certificate still wrote its record into the
    # real ledger -- which is how a test build ended up in the real record.
    $rehearsal = Join-Path $scratch 'rehearsal'
    $keys = Join-Path $rehearsal 'keys'
    New-Item -ItemType Directory -Force -Path $keys | Out-Null
    foreach ($f in @($real.Pfx, $real.Cer, $real.Pw)) {
        if (Test-Path -LiteralPath $f) {
            Copy-Item -LiteralPath $f -Destination (Join-Path $keys ([IO.Path]::GetFileName($f))) -Force
        }
    }
    $artifact = Join-Path $rehearsal 'again.exe'
    Copy-Item -LiteralPath $copiedFrom -Destination $artifact -Force
    if (-not (Remove-SmytSignatureTable -Path $artifact)) {
        throw 'the sample carries no embedded signature to strip for the rehearsal'
    }

    $realBefore = (Read-SmytLedger -Path $real.Ledger).Count
    $r = Invoke-SmytNative -Exe 'powershell' -Arguments @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', (Join-Path $here 'release-nanodesu.ps1'),
        '-SignOnly', $artifact,
        '-SigningDir', $keys,
        '-OutDir', (Join-Path $rehearsal 'out'),
        '-Note', 'rehearsal'
    )
    if ($r.Code -ne 0) {
        throw "the rehearsal exited $($r.Code): $(@($r.Output | Select-Object -Last 3) -join ' | ')"
    }
    $realAfter = (Read-SmytLedger -Path $real.Ledger).Count
    if ($realAfter -ne $realBefore) {
        throw "the rehearsal wrote into the real ledger, which grew from $realBefore to $realAfter records"
    }
    $rehearsalLedger = Join-Path $keys 'smyt-signings.ndjson'
    if ((Read-SmytLedger -Path $rehearsalLedger).Count -ne 1) {
        throw 'the rehearsal did not record its signing in the ledger it was handed'
    }
}

Check 'a move is recorded, and a relocation the ledger cannot confirm is refused' {
    # -Relocate asserts that a known build moved, so its whole value is the verification it refuses to
    # skip. Both halves are exercised: the record it appends for bytes it can account for, and the two
    # refusals for bytes it cannot. The count after the refusals is the assertion that makes the other
    # two worth having -- a verb that refuses loudly and writes anyway has done nothing useful.
    $relocatedHome = Join-Path $scratch 'home'
    New-Item -ItemType Directory -Force -Path $relocatedHome | Out-Null
    $moved = Join-Path $relocatedHome 'sample.exe'
    Copy-Item -LiteralPath $sampleCopy -Destination $moved -Force

    $before = (Read-SmytLedger -Path $ledger).Count
    $r = Invoke-Sign @('-RelocateFrom', $sampleCopy, '-RelocateTo', $moved, '-SigningDir', $scratch)
    if ($r.Code -ne 0) {
        throw "relocating exited $($r.Code): $(@($r.Output | Select-Object -Last 3) -join ' | ')"
    }
    $after = (Read-SmytLedger -Path $ledger).Count
    Assert-Same ($after - $before) 1 'records appended by a relocation'

    $records = (Read-SmytLedger -Path $ledger).Records
    $lastRecord = $records[$records.Count - 1]
    Assert-Same $lastRecord.event 'relocated' 'the appended record is a relocation'
    Assert-Same $lastRecord.from $sampleCopy 'the record names where the file came from'
    Assert-Same $lastRecord.file $moved 'the record names where it is now'
    if (-not $lastRecord.sha256_signed) { throw 'the record carries no hash of what it verified' }

    # One byte flipped in the middle: these are no longer the bytes any record accounts for.
    $flipped = Join-Path $relocatedHome 'flipped.exe'
    $bytes = [System.IO.File]::ReadAllBytes($moved)
    $middle = [int]($bytes.Length / 2)
    $bytes[$middle] = [byte]($bytes[$middle] -bxor 0xFF)
    [System.IO.File]::WriteAllBytes($flipped, $bytes)
    Assert-Throws {
        $r = Invoke-Sign @('-RelocateFrom', $moved, '-RelocateTo', $flipped, '-SigningDir', $scratch)
        throw (@($r.Output) -join ' ')
    } 'sign it instead of relocating it'

    # A file this ledger has never seen. For that one the correct action is to sign it.
    $stranger = Join-Path $relocatedHome 'stranger.exe'
    [System.IO.File]::WriteAllBytes($stranger, [byte[]](1..64))
    Assert-Throws {
        $r = Invoke-Sign @('-RelocateFrom', $moved, '-RelocateTo', $stranger, '-SigningDir', $scratch)
        throw (@($r.Output) -join ' ')
    } 'sign it instead of relocating it'

    Assert-Same (Read-SmytLedger -Path $ledger).Count $after 'records after two refusals'
}

# --- 5b. the verdicts --------------------------------------------------------- #
Write-Host ""
Write-Host "the -Check verdicts"
Check 'every verdict is reached, named, and counted' {
    # The verdict logic is the newest code in the toolchain and was the only part verified by
    # reading output rather than by asserting -- which is the part that rots. One hand-written
    # ledger, five fixtures, one verdict each.
    $v = Join-Path $scratch 'verdicts'
    New-Item -ItemType Directory -Force -Path $v | Out-Null
    $vledger = Join-Path $v 'smyt-signings.ndjson'
    $nowhere = 'F' * 64

    $fMatch = New-VerdictFixture -Source $copiedFrom -Dir $v -Name 'match.exe' -Marker 'match'
    Add-SmytLedgerRecord -Path $vledger -Record ([ordered]@{
        t = '2026-01-01T00:00:00Z'; file = $fMatch; name = 'match.exe'
        sha256_signed = (Get-SmytHash -Path $fMatch); sha256_unsigned = $nowhere
        thumbprint = 'NONE'; timestamped = $true; note = 'unchanged fixture'
    })

    $fSup = New-VerdictFixture -Source $copiedFrom -Dir $v -Name 'superseded.exe' -Marker 'superseded'
    Add-SmytLedgerRecord -Path $vledger -Record ([ordered]@{
        t = '2026-01-01T00:00:00Z'; file = $fSup; name = 'superseded.exe'
        sha256_signed = $nowhere; sha256_unsigned = $nowhere
        thumbprint = 'NONE'; timestamped = $true; note = 'the earlier build'
    })
    Add-SmytLedgerRecord -Path $vledger -Record ([ordered]@{
        t = '2026-01-02T00:00:00Z'; file = $fSup; name = 'superseded.exe'
        sha256_signed = (Get-SmytHash -Path $fSup); sha256_unsigned = $nowhere
        thumbprint = 'NONE'; timestamped = $true; note = 'the build that replaced it'
    })

    $fUnsigned = New-VerdictFixture -Source $copiedFrom -Dir $v -Name 'unsigned.exe' -Marker 'unsigned'
    Add-SmytLedgerRecord -Path $vledger -Record ([ordered]@{
        t = '2026-01-01T00:00:00Z'; file = $fUnsigned; name = 'unsigned.exe'
        sha256_signed = $nowhere; sha256_unsigned = (Get-SmytHash -Path $fUnsigned)
        thumbprint = 'NONE'; timestamped = $true; note = 'stripped fixture'
    })

    $fChanged = New-VerdictFixture -Source $copiedFrom -Dir $v -Name 'changed.exe' -Marker 'changed'
    Add-SmytLedgerRecord -Path $vledger -Record ([ordered]@{
        t = '2026-01-01T00:00:00Z'; file = $fChanged; name = 'changed.exe'
        sha256_signed = $nowhere; sha256_unsigned = $nowhere
        thumbprint = 'NONE'; timestamped = $true; note = 'unknown bytes fixture'
    })

    Add-SmytLedgerRecord -Path $vledger -Record ([ordered]@{
        t = '2026-01-01T00:00:00Z'; file = (Join-Path $v 'gone.exe'); name = 'gone.exe'
        sha256_signed = $nowhere; sha256_unsigned = $nowhere
        thumbprint = 'NONE'; timestamped = $true; note = 'absent fixture'
    })

    # The sixth verdict, and its control. A relocation record is a CLAIM: without the control, a
    # record alone would be enough to stop a missing file being reported as missing, and the verdict
    # would mean "someone wrote a line" rather than "the build is there".
    $fRelocated = New-VerdictFixture -Source $copiedFrom -Dir $v -Name 'relocated.exe' -Marker 'relocated'
    $movedAway = Join-Path $v 'moved-away.exe'
    Add-SmytLedgerRecord -Path $vledger -Record ([ordered]@{
        t = '2026-01-01T00:00:00Z'; file = $movedAway; name = 'moved-away.exe'
        sha256_signed = (Get-SmytHash -Path $fRelocated); sha256_unsigned = $nowhere
        thumbprint = 'NONE'; timestamped = $true; note = 'signed here, then moved'
    })
    Add-SmytLedgerRecord -Path $vledger -Record ([ordered]@{
        event = 'relocated'; t = '2026-01-02T00:00:00Z'; name = 'moved-away.exe'
        file = $fRelocated; from = $movedAway
        sha256_signed = (Get-SmytHash -Path $fRelocated); note = 'moved into the home'
    })

    $fControl = New-VerdictFixture -Source $copiedFrom -Dir $v -Name 'control-target.exe' -Marker 'control'
    $alsoMoved = Join-Path $v 'also-moved-away.exe'
    Add-SmytLedgerRecord -Path $vledger -Record ([ordered]@{
        t = '2026-01-01T00:00:00Z'; file = $alsoMoved; name = 'also-moved-away.exe'
        sha256_signed = $nowhere; sha256_unsigned = $nowhere
        thumbprint = 'NONE'; timestamped = $true; note = 'a relocation record that does not match'
    })
    Add-SmytLedgerRecord -Path $vledger -Record ([ordered]@{
        event = 'relocated'; t = '2026-01-02T00:00:00Z'; name = 'also-moved-away.exe'
        file = $fControl; from = $alsoMoved
        sha256_signed = $nowhere; note = 'names a target whose bytes are not this signing'
    })

    $r = Invoke-Sign @('-Check', '-SigningDir', $v)
    if ($r.Code -ne 0) { throw "check exited $($r.Code)" }
    $text = @($r.Output) -join "`n"

    foreach ($word in 'MATCH', 'SUPERSEDED', 'UNSIGNED', 'CHANGED', 'GONE', 'RELOCATED') {
        if ($text -notmatch $word) { throw "no $word in the audit output" }
    }
    if ($text -notmatch 'replaced by: 2026-01-02') {
        throw 'the superseded record does not name the signing that replaced it'
    }
    if ($text -notmatch '10 record\(s\): 2 unchanged, 1 superseded') {
        throw "the summary does not count the verdicts: $text"
    }
    if ($text -notmatch '1 changed by something this ledger has no record of, 1 now unsigned, 2 gone, 1 moved') {
        throw "the summary does not separate the unexplained change from the others: $text"
    }

    if ($text -notmatch '2 of them record a move rather than a file') {
        throw "the summary does not count the relocation records: $text"
    }
    # The control: a relocation record whose target does not carry that signing's bytes must NOT be
    # reported as relocated, or the verdict means "a line was written".
    $relocatedBlock = [regex]::Match($text, '(?s)RELOCATED.*?(?=\[2026|\z)').Value
    $controlVerdict = [regex]::Match($text, '(?m)^\[2026-01-01.*also-moved-away\.exe\s+(\w+)').Groups[1].Value
    if ($controlVerdict -ne 'GONE') {
        throw "a relocation whose target does not match was reported as $controlVerdict instead of GONE"
    }
    $realVerdict = [regex]::Match($text, '(?m)^\[2026-01-01.*moved-away\.exe\s+(\w+)').Groups[1].Value
    if ($realVerdict -ne 'RELOCATED') {
        throw "a genuine move was reported as $realVerdict instead of RELOCATED"
    }

    # and the single-file form has to say the same thing about the same file
    $one = Invoke-Sign @('-CheckFile', $fSup, '-SigningDir', $v)
    $oneText = @($one.Output) -join "`n"
    if ($oneText -notmatch 'now holds a later S\.M\.Y\.T\. build') {
        throw "the single-file check did not describe the superseded case: $oneText"
    }
    if ($oneText -notmatch 'replaced by: 2026-01-02') {
        throw 'the single-file check did not name the replacement'
    }
}

# --- 6. the certificate, if asked for ----------------------------------------- #
if ($IncludeCertificateTest) {
    Write-Host ""
    Write-Host "the certificate (throwaway subject)"
    $certScratch = Join-Path $scratch 'cert'
    New-Item -ItemType Directory -Force -Path $certScratch | Out-Null
    # Deliberately not the real subject: -NewCertificate removes every certificate in the store
    # that matches the subject it is given, so a test that reused it would delete the real one.
    $throwaway = 'O=S.M.Y.T. SELFTEST (throwaway), CN=S.M.Y.T. Self Test'
    try {
        Check 'a throwaway certificate can be created twice, archiving the first' {
            $r1 = Invoke-Sign @('-NewCertificate', '-SigningDir', $certScratch, '-Subject', $throwaway, '-Years', '1')
            if ($r1.Code -ne 0) { throw "first creation exited $($r1.Code): $(@($r1.Output | Select-Object -Last 2) -join ' | ')" }
            $r2 = Invoke-Sign @('-NewCertificate', '-SigningDir', $certScratch, '-Subject', $throwaway, '-Years', '1')
            if ($r2.Code -ne 0) { throw "second creation exited $($r2.Code): $(@($r2.Output | Select-Object -Last 2) -join ' | ')" }
            $history = Join-Path $certScratch 'history'
            $archived = @(Get-ChildItem $history -ErrorAction SilentlyContinue)
            if ($archived.Count -lt 2) { throw "expected the outgoing pfx and cer in history/, found $($archived.Count) file(s)" }
        }
        Check 'the real certificate was not touched by that' {
            if (-not $realThumb) { return }
            $still = @(Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object { $_.Thumbprint -eq $realThumb })
            if ($still.Count -ne 1) { throw "the real certificate $realThumb is not in the store any more" }
            $realNow = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($real.Cer)).Thumbprint
            Assert-Same $realNow $realThumb 'the published certificate on disk'
        }
    } finally {
        foreach ($c in @(Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object { $_.Subject -like '*Self Test*' })) {
            Remove-Item -Path ("Cert:\CurrentUser\My\" + $c.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- what the JSON reader does to a date -------------------------------------- #
# Read-SmytLedger's contract is to hand back the fields the ledger holds, and a JSON library's
# version behaviour is not allowed to change that. PowerShell 6.0 and later infer [DateTime] from an
# ISO-8601 string; 5.1 leaves it a string. So the same ledger read by the two editions gave two
# types, and the seven places that format `t` with .Substring(0, 19) threw on one of them.
#
# Written against a file this test makes itself, so it holds on whichever edition is running -- the
# real ledger's contents are not the subject and must not be a dependency of a check about parsing.
Check 'a date in the ledger comes back as the text the file holds' {
    $probe = Join-Path $ScratchRoot 'ledger-dates.ndjson'
    $stamp = '2026-10-05T08:43:25.3340146Z'
    # No BOM, by the same reasoning the toolchain pins its encoding everywhere else: a BOM would land
    # inside the first JSON key and make the line a different question than the one being asked.
    $text = '{"t":"' + $stamp + '","name":"probe","note":"n"}'
    [System.IO.File]::WriteAllText($probe, $text, (New-Object System.Text.UTF8Encoding($false)))

    $read = Read-SmytLedger -Path $probe
    Assert-Same $read.Count 1 'records read back'
    Assert-Same $read.Broken 0 'unparseable lines'
    $value = $read.Records[0].t
    if ($value -isnot [string]) { throw "t came back as $($value.GetType().FullName), not a string" }
    Assert-Same $value $stamp 'the text of t'
    # The call the consumers actually make, so the check fails for the reason they would fail.
    Assert-Same $value.Substring(0, 19) '2026-10-05T08:43:25' 'the substring the consumers take'
    $dated = @($read.Records[0].PSObject.Properties | Where-Object { $_.Value -is [datetime] })
    Assert-Same $dated.Count 0 'date-valued fields left as [datetime]'
}

# --- 6. the sealing path ------------------------------------------------------ #
Write-Host ""
Write-Host "the sealed container"
Check 'a secret survives sealing, and the ciphertext is not the secret' {
    # Load-bearing rather than decorative: Get-SmytPfxPassword shells out to `node seal.mjs open`, so
    # signing stops working entirely if this path breaks. It was the one added file with no check --
    # CHANGES.md said so itself -- and the relocated verdict it named alongside has since got one.
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        throw 'node is not on PATH, and the password path needs it: Get-SmytPfxPassword runs seal.mjs'
    }
    $seal = Join-Path $here 'seal.mjs'
    if (-not (Test-Path -LiteralPath $seal)) { throw "no seal.mjs at $seal" }
    # The real key is read and must not be written. Captured so the check can prove it left it alone:
    # a test that damages the key it is testing would be worse than no test.
    $keyFile = Join-Path $here 'sealed.key'
    $keyBefore = ''
    if (Test-Path -LiteralPath $keyFile) { $keyBefore = Get-SmytHash -Path $keyFile }

    $dir = Join-Path $scratch 'sealing'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $secret = 'a secret that must not be readable in the container 2026-10-13'
    $plain = Join-Path $dir 'secret.txt'
    # No BOM, by the same reasoning the toolchain pins its encoding everywhere else.
    [System.IO.File]::WriteAllText($plain, $secret, (New-Object System.Text.UTF8Encoding($false)))

    $container = Join-Path $dir 'secret.sealed'
    # `1>$null 2>$null` and not `2>&1`: merging a native command's stderr into the pipeline makes
    # Windows PowerShell turn each line of it into an ErrorRecord, and this harness runs with
    # $ErrorActionPreference = 'Stop', so a command that fails CORRECTLY threw a terminating error
    # here and failed the check that was watching for its exit code. That is how this check failed
    # under 5.1 the first time it ran, while passing under 7.
    & node $seal seal $plain $container 1>$null 2>$null
    Assert-Same $LASTEXITCODE 0 'the exit code of seal'
    if (-not (Test-Path -LiteralPath $container)) { throw 'sealing wrote no container' }

    # It has to be a container and not the file under a new name. A text reader or a grep getting the
    # secret is precisely the state this exists to end.
    $blob = [System.IO.File]::ReadAllBytes($container)
    if ([System.Text.Encoding]::UTF8.GetString($blob).Contains($secret)) {
        throw 'the container contains the secret in the clear'
    }
    Assert-Same ([System.Text.Encoding]::ASCII.GetString($blob, 0, 5)) 'VSEP1' 'the container magic'

    # `info` is the reason for a format rather than an opaque blob: it says what the file is without
    # the key. Checked because it is the one command that must work when the key does not.
    $info = (& node $seal info $container 2>$null | Out-String)
    Assert-Same $LASTEXITCODE 0 'the exit code of info'
    if ($info -notmatch 'VSEP1') { throw "info did not name the format: $info" }
    if ($info -notmatch ([string]$blob.Length)) { throw "info did not name the container size: $info" }

    # And opening returns the bytes that went in. Compared by hash rather than by string, so a
    # trailing newline or an encoding difference cannot pass as equality.
    $back = Join-Path $dir 'back.txt'
    & node $seal open $container $back 1>$null 2>$null
    Assert-Same $LASTEXITCODE 0 'the exit code of open'
    Assert-Same (Get-SmytHash -Path $back) (Get-SmytHash -Path $plain) 'the round trip'

    # GCM is what makes a modified container fail instead of yielding nonsense, and the format's own
    # documentation claims it. Untested, that claim is a paragraph.
    $tampered = Join-Path $dir 'tampered.sealed'
    $broken = [System.IO.File]::ReadAllBytes($container)
    $firstCipherByte = 5 + 1 + 12 + 8          # magic, version, nonce, plaintext length
    $broken[$firstCipherByte] = [byte](($broken[$firstCipherByte] -bxor 1) -band 0xFF)
    [System.IO.File]::WriteAllBytes($tampered, $broken)
    # The one call here that is EXPECTED to fail, and it needs the preference lowered for the moment:
    # under Windows PowerShell, a native command's stderr becomes an ErrorRecord as soon as it is
    # redirected -- `2>&1` and `2>$null` alike -- and this harness runs with Stop, so node's own
    # "cannot open" line turned into a terminating error and failed the check that was watching for
    # its exit code. Passing under 7 and failing under 5.1 is how that was found.
    $quiet = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & node $seal open $tampered 2>$null
        $tamperCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $quiet
    }
    if ($tamperCode -eq 0) { throw 'a modified container opened instead of being refused' }

    if ($keyBefore) {
        Assert-Same (Get-SmytHash -Path $keyFile) $keyBefore 'the real sealed.key after the check'
    }
}

# --- done --------------------------------------------------------------------- #
Write-Host ""
if (-not $Keep) { Remove-Item -Recurse -Force -LiteralPath $ScratchRoot -ErrorAction SilentlyContinue }
Write-Host "$passed check(s) passed, $failures failed"
if ($Keep) { Write-Host "the scratch directory was kept at $ScratchRoot" }
if ($failures -gt 0) { exit 1 }
