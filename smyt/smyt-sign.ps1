# smyt-sign.ps1 -- sign a build with the S.M.Y.T. code signing certificate
#
# For anything S.M.Y.T. makes or funds. The certificate's organization is S.M.Y.T. itself, which
# is the point: an organization that is not a company cannot be issued a company certificate, and
# should not want one. A commercial certificate authority fills the organization field in from a
# verified *legal entity* -- it asks for registration papers -- so an unaligned academic seminar is
# not merely unable to buy one cheaply, it is outside what that system describes. Self-signing is
# not the consolation prize here. It is the only form that states the truth, and it keeps the root
# of trust with the people who made the thing instead of with a company that can revoke it, change
# its terms, or stop existing.
#
# What that costs, stated honestly: a stranger's Windows will not verify this signature, and will
# not stop showing a SmartScreen warning. On machines where the public certificate is installed,
# the signature verifies and the publisher reads S.M.Y.T.
#
# Usage:
#   .\smyt-sign.ps1 -NewCertificate                        replace the certificate
#   .\smyt-sign.ps1 -Sign <file> [-Note "..."]              sign, verify, and record it
#   .\smyt-sign.ps1 -Verify <file>                          report the signature
#   .\smyt-sign.ps1 -Check                                  compare the whole ledger against the disk
#   .\smyt-sign.ps1 -CheckFile <file>                       assert this file is one we signed
#   .\smyt-sign.ps1 -Status                                 certificate, trust, and ledger state
#   .\smyt-sign.ps1 -InstallTrust [-IncludeRoot]            make it verify on this machine
#   .\smyt-sign.ps1 -Protect                                re-apply the ACLs to the key material
#   .\smyt-sign.ps1 -Log [-Last 20]                         what has been signed
#
# Signing is recorded in smyt-signings.ndjson: one line per signing, with the file's SHA-256 as it
# was signed. A signature without a record of what it covered is half a claim, and the record is
# what lets you answer "is this the build we signed" later. -Check is that answer being asked for
# rather than assumed: a rebuilt file, a stripped signature and a path that now holds a different
# build are three different things, and only one of them is fine.

param(
    [string[]]$Sign,
    [string]$Verify,
    # A move is a statement about a build this tool already signed, so the bytes at the new path are
    # verified against the ledger before anything is appended. Two named scalars rather than one
    # [string[]]: the array form cannot be used under `powershell -File`, and both callers inside this
    # toolchain -- this self-test's wrapper and every release script -- reach the tool that way. A verb
    # its own self-test cannot drive is a verb the self-test does not cover.
    [string]$RelocateFrom = '',
    [string]$RelocateTo = '',
    [switch]$Check,
    [string]$CheckFile,
    [switch]$Status,
    [switch]$NewCertificate,
    [switch]$InstallTrust,
    [switch]$IncludeRoot,
    [switch]$TrustHelp,
    [switch]$MachineTrust,
    [switch]$RemoveTrust,
    [switch]$Protect,
    [switch]$Log,
    [int]$Last = 20,
    # Signing a file that is already signed appends a second signature. The ledger would then hold
    # two records for one file and the second would record the first one's signed bytes as "before
    # signing" -- the field that says what the build was would start lying. Off by default.
    [switch]$Force,
    # A signature with no timestamp dies with the certificate. Refusing is the default; this is
    # for the case where an unverifiable-later signature is genuinely better than none today.
    [switch]$AllowUntimestamped,
    [string]$Note = '',
    [string]$SigningDir = '',
    [string]$Subject = 'O=S.M.Y.T., CN=S.M.Y.T. Code Signing',
    [int]$Years = 5,
    # Timestamp authorities, RFC3161, free and public, tried in order. One URL is a single point
    # of failure for a step that is treated as fatal, and this machine reaches only some of them.
    [string[]]$TimestampUrl = @(
        'http://timestamp.digicert.com',
        'http://timestamp.sectigo.com',
        'http://timestamp.globalsign.com/tsa/r6advanced1'
    )
)

$ErrorActionPreference = 'Stop'

# The toolchain's own directory: the scripts, the certificate and the ledger travel together, so
# the default comes from where this file lives rather than from a path written into three files.
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $SigningDir) { $SigningDir = $here }

. (Join-Path $here 'smyt-common.ps1')
Repair-SmytModulePath

$AllStores = @(
    'Cert:\CurrentUser\TrustedPublisher',
    'Cert:\CurrentUser\Root',
    'Cert:\LocalMachine\TrustedPublisher',
    'Cert:\LocalMachine\Root'
)

function Get-SmytPathsHere { return (Get-SmytPaths -SigningDir $SigningDir) }

function New-SmytCertificate {
    $paths = Get-SmytPathsHere
    Assert-SmytModules 'New-SelfSignedCertificate', 'Export-PfxCertificate', 'ConvertTo-SecureString'
    New-Item -ItemType Directory -Force -Path $SigningDir | Out-Null

    if (-not (Test-Path -LiteralPath $paths.Pw) -and -not (Test-Path -LiteralPath $paths.PwSealed)) {
        # Random, and kept out of the script and off the command line. A password in a shell
        # history is not a password.
        $bytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $plain = [Convert]::ToBase64String($bytes)
        $opener = Join-Path $SigningDir 'seal.mjs'
        if (Test-Path -LiteralPath $opener) {
            # Sealed through standard input: the generated password never exists as a file, not even
            # for the moment a temporary one would live. The plaintext form is not written at all.
            $plain | & node $opener seal - $paths.PwSealed | Out-Null
            if (-not (Test-Path -LiteralPath $paths.PwSealed)) {
                throw 'sealing the password failed; refusing to leave it in the clear'
            }
            Protect-SmytSecret -Path $paths.PwSealed
            Write-Host "generated a password and sealed it; the plaintext form was never written"
        } else {
            # Without the opener there is nothing to seal with. Writing the plaintext is worse than
            # stopping, but it is what the tool did before the container existed, so it is kept as a
            # loud fallback rather than a silent one.
            Write-Warning "seal.mjs is missing, so the password cannot be sealed; writing it in the clear as before"
            $plain | Set-Content -LiteralPath $paths.Pw -Encoding UTF8 -NoNewline
            Protect-SmytSecret -Path $paths.Pw
            Write-Host "generated a password, restricted to the account that owns this key material"
        }
    }

    # Keep the outgoing pair before it is overwritten. The ledger names the certificate that signed
    # each build by thumbprint, so discarding the previous certificate would leave those records
    # pointing at a certificate that no longer exists anywhere -- verification of an old build
    # would then rest on the ledger's word alone.
    if ((Test-Path -LiteralPath $paths.Pfx) -or (Test-Path -LiteralPath $paths.Cer)) {
        $oldThumb = ''
        if (Test-Path -LiteralPath $paths.Cer) {
            try {
                $old = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($paths.Cer)
                $oldThumb = $old.Thumbprint
            } catch { $oldThumb = 'unreadable' }
        }
        New-Item -ItemType Directory -Force -Path $paths.History | Out-Null
        $stamp = (Get-Date).ToString('yyyy-MM-dd-HHmmss')
        foreach ($f in @($paths.Pfx, $paths.Cer)) {
            if (Test-Path -LiteralPath $f) {
                $dest = Join-Path $paths.History ("{0}-{1}-{2}" -f $stamp, $oldThumb, [IO.Path]::GetFileName($f))
                Copy-Item -LiteralPath $f -Destination $dest -Force
                Protect-SmytSecret -Path $dest -Quiet
            }
        }
        Write-Host "archived the outgoing certificate ($oldThumb) in $($paths.History)"
    }

    # Replace, never accumulate. Two valid signing identities make it impossible to say which one
    # signed a given build, which is most of what a signature is for.
    $key = ($Subject -split ',')[-1].Trim()
    foreach ($old in (Get-ChildItem Cert:\CurrentUser\My |
                      Where-Object { $_.Subject -like "*$key*" -and $_.HasPrivateKey })) {
        Write-Host "removing the previous certificate $($old.Thumbprint.Substring(0,12))"
        Remove-Item -Path ("Cert:\CurrentUser\My\" + $old.Thumbprint) -Force
    }

    $secure = ConvertTo-SecureString (Get-SmytPfxPassword -Path $paths.Pw) -AsPlainText -Force
    $cert = New-SelfSignedCertificate `
        -Subject $Subject `
        -Type CodeSigningCert `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears($Years) `
        -KeyExportPolicy Exportable

    Export-PfxCertificate -Cert $cert -FilePath $paths.Pfx -Password $secure | Out-Null
    Export-Certificate -Cert $cert -FilePath $paths.Cer -Type CERT | Out-Null

    # The password was hardened from the start and the private key beside it was not, which left
    # the key writable by every authenticated user. Both halves are protected here, and so is the
    # directory, so the ledger and anything added later inherit the same rule.
    Protect-SmytSecret -Path $paths.Pfx
    Protect-SmytSecret -Path $paths.Cer -Quiet
    Protect-SmytSecret -Path $SigningDir -Quiet

    Write-Host "certificate created"
    Write-Host "  subject    : $($cert.Subject)"
    Write-Host "  thumbprint : $($cert.Thumbprint)"
    Write-Host "  not after  : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
    Write-Host "  pfx        : $($paths.Pfx)   (private key -- never publish this)"
    Write-Host "  cer        : $($paths.Cer)   (public half -- publish freely)"
}

function Invoke-SmytSign {
    param([string]$Target, [string]$NoteText)

    Assert-SmytModules 'Get-AuthenticodeSignature'
    if (-not (Test-Path -LiteralPath $Target)) { throw "no such file: $Target" }
    $paths = Get-SmytPathsHere
    if (-not (Test-Path -LiteralPath $paths.Pfx)) {
        throw "no certificate at $($paths.Pfx) -- run -NewCertificate first"
    }
    $signtool = Get-SmytSignTool
    $resolved = (Resolve-Path -LiteralPath $Target).Path
    $identity = Get-SmytIdentity -Paths $paths -RequirePrivateKey
    $before = Get-SmytHash -Path $resolved

    $already = Get-SmytSignature -Path $resolved
    if ($already.Present -and -not $Force) {
        throw ("$resolved already carries a signature from $($already.Subject). Authenticode appends rather " +
               "than replaces, so signing again would leave two signatures on one file and a ledger record " +
               "whose 'before signing' hash is the previous signature's output. Pass -Force if that is meant.")
    }

    # The description is what the Windows UI shows a user who inspects the file. Say what it is
    # rather than leaving the field blank for the sake of a shorter command line.
    $desc = [IO.Path]::GetFileNameWithoutExtension($resolved)

    if ($identity.InStore) {
        Write-Host "signing key: certificate $($identity.Thumbprint.Substring(0,12)) from the store (no password on any command line)"
    } else {
        Write-Warning "the certificate is not in Cert:\CurrentUser\My, so signtool will read the pfx; its password is on the command line for as long as it runs"
    }

    $stamped = $false
    $tsa = ''
    $failed = New-Object System.Collections.ArrayList
    foreach ($url in $TimestampUrl) {
        $argv = @('sign') + $identity.SignArguments +
                @('/fd', 'SHA256', '/tr', $url, '/td', 'SHA256', '/d', $desc, $resolved)
        $r = Invoke-SmytNative -Exe $signtool -Arguments $argv
        if ($r.Code -eq 0) { $stamped = $true; $tsa = $url; break }
        [void]$failed.Add($url)
        Write-Host "  $url did not answer:" -ForegroundColor DarkGray
        foreach ($line in @($r.Output | Select-Object -Last 2)) { Write-Host "    $line" -ForegroundColor DarkGray }
    }

    if (-not $stamped) {
        if (-not $AllowUntimestamped) {
            # Measured rather than assumed: when the timestamp authority fails, signtool exits
            # non-zero and leaves the file exactly as it found it, so there is nothing to undo.
            throw ("no timestamp was obtained from any authority ($($failed -join ', ')); the file was left " +
                   "unchanged and unsigned. Fix the way out to a timestamp server, or pass -AllowUntimestamped " +
                   "to sign anyway and accept a signature that stops verifying when the certificate expires.")
        }
        Write-Warning "signing without a timestamp: this signature will expire with the certificate"
        $argv = @('sign') + $identity.SignArguments + @('/fd', 'SHA256', '/d', $desc, $resolved)
        $r = Invoke-SmytNative -Exe $signtool -Arguments $argv
        if ($r.Code -ne 0) { throw "signtool exited $($r.Code): $(@($r.Output) -join ' | ')" }
    }

    $sig = Get-SmytSignature -Path $resolved
    if (-not $sig.Present) { throw "signtool reported success but $resolved carries no signature" }
    # The published certificate decides who signs. Without this the check would be a subject string,
    # which any certificate can carry.
    if ($sig.Thumbprint -ne $identity.Thumbprint) {
        throw ("$resolved was signed by $($sig.Thumbprint) but the certificate published here is " +
               "$($identity.Thumbprint); refusing to record it as an S.M.Y.T. build")
    }

    $after = Get-SmytHash -Path $resolved

    # The ledger records the hash of the signed file, which is different from the hash before
    # signing: Authenticode appends a certificate table. Both are kept, because "which bytes did
    # we sign" and "what did they sign" are different questions.
    $record = [ordered]@{
        t               = (Get-Date).ToUniversalTime().ToString('o')
        file            = $resolved
        name            = [IO.Path]::GetFileName($resolved)
        size            = (Get-Item -LiteralPath $resolved).Length
        sha256_signed   = $after
        sha256_unsigned = $before
        signer          = $sig.Subject
        thumbprint      = $sig.Thumbprint
        timestamped     = $sig.Timestamped
        tsa             = $tsa
        note            = $NoteText
    }
    # The chain field is set inside the append, holding a handle no other writer can hold at the
    # same moment. Reading the tip out here is what let two concurrent signings name one parent.
    Add-SmytLedgerRecord -Path $paths.Ledger -Record $record

    Write-Host "signed: $resolved"
    Write-Host "  signer     : $($sig.Subject)"
    Write-Host "  timestamp  : $(if ($stamped) { "$tsa" } else { 'NONE -- the signature will expire with the certificate' })"
    Write-Host "  sha256     : $after"
    Write-Host "  recorded in: $($paths.Ledger)"
    if (-not $stamped) {
        Write-Warning "no timestamp was obtained; re-sign with a reachable -TimestampUrl"
    }
}

function Show-SmytSignature {
    param([string]$Target)
    if (-not (Test-Path -LiteralPath $Target)) { throw "no such file: $Target" }
    $paths = Get-SmytPathsHere
    $s = Get-SmytSignature -Path $Target
    Write-Host "file     : $Target"
    Write-Host "status   : $($s.Status)"
    if (-not $s.Present) {
        Write-Host "signer   : none"
        return
    }
    Write-Host "signer   : $($s.Subject)"
    Write-Host "thumbprint: $($s.Thumbprint)"
    Write-Host "issuer   : $((Get-AuthenticodeSignature -LiteralPath $Target).SignerCertificate.Issuer)"
    Write-Host "valid to : $((Get-AuthenticodeSignature -LiteralPath $Target).SignerCertificate.NotAfter.ToString('yyyy-MM-dd'))"
    Write-Host "timestamp: $(if ($s.Timestamped) { $s.TimestampBy } else { 'none' })"

    if (Test-Path -LiteralPath $paths.Cer) {
        $identity = Get-SmytIdentity -Paths $paths
        if ($s.Thumbprint -eq $identity.Thumbprint) {
            Write-Host "pinned   : matches the certificate published in $([IO.Path]::GetFileName($paths.Cer))"
        } else {
            Write-Host "pinned   : NOT the published S.M.Y.T. certificate ($($identity.Thumbprint.Substring(0,16))...)" -ForegroundColor Yellow
        }
    }
    if ($s.Status -ne 'Valid') {
        Write-Host ""
        Write-Host "The signature is present but does not verify here." -ForegroundColor DarkGray
        Write-Host "A self-signed certificate is its own root, so the chain cannot terminate until its" -ForegroundColor DarkGray
        Write-Host "public half is in a trusted root store. The trust provider refuses to trust it on" -ForegroundColor DarkGray
        Write-Host "anyone's behalf -- by design, and not scripted around." -ForegroundColor DarkGray
        Write-Host "Run -Status to see the four stores, or -TrustHelp for the exact steps." -ForegroundColor DarkGray
    }
}

function Show-SmytCheck {
    # The ledger claims what was signed. This asks the disk whether the claim still holds, which is
    # the question the ledger exists to answer and the one nothing here used to ask. A file that
    # was rebuilt after signing, one whose signature was stripped, and one that is simply gone are
    # three different outcomes of one release, and a record that cannot tell them apart is a note
    # rather than a check.
    param([string]$OnlyFile)

    $paths = Get-SmytPathsHere
    $ledger = Read-SmytLedger -Path $paths.Ledger
    if ($ledger.Count -eq 0) {
        # An empty ledger is not a reason to answer a question about a file with a friendly note
        # and a zero exit code: "nothing here names this file" is the answer, and it is a failure.
        if ($OnlyFile) {
            throw ("the ledger at $($paths.Ledger) is empty, so it names no file at all; " +
                   "$([IO.Path]::GetFileName($OnlyFile)) was never signed here")
        }
        Write-Host "the ledger at $($paths.Ledger) is empty"
        return
    }

    $target = ''
    $targetName = ''
    if ($OnlyFile) {
        if (-not (Test-Path -LiteralPath $OnlyFile)) { throw "no such file: $OnlyFile" }
        $target = (Resolve-Path -LiteralPath $OnlyFile).Path
        $targetName = [IO.Path]::GetFileName($target)
    }

    # Which signed hashes the ledger knows, so a path that now holds a later build can be told apart
    # from a path something unknown has touched. Both are "the bytes differ from this record", but
    # only the second is news, and reporting them the same way buries the one that matters.
    $knownSignings = @{}
    foreach ($r in $ledger.Records) {
        if ($null -eq $r.PSObject.Properties['sha256_signed']) { continue }
        if (-not $knownSignings.ContainsKey($r.sha256_signed)) { $knownSignings[$r.sha256_signed] = @() }
        $knownSignings[$r.sha256_signed] += $r
    }

    # A relocation record is the same KIND of statement as a publication: a fact about a build, not a
    # file to be audited at this path. Without this index a moved artifact reads as GONE, and "gone"
    # is the one verdict a reader cannot act on, because it does not distinguish "moved on purpose"
    # from "vanished" -- which is exactly what moved artifacts here looked like.
    $relocations = @{}
    foreach ($r in $ledger.Records) {
        if ($null -eq $r.PSObject.Properties['event']) { continue }
        if ($r.event -ne 'relocated') { continue }
        if ($r.from) { $relocations[$r.from.ToLower()] = $r }
    }

    $tally = @{ match = 0; superseded = 0; changed = 0; unsigned = 0; gone = 0; relocated = 0 }
    $matched = 0
    $publications = New-Object System.Collections.ArrayList
    $relocationRecords = New-Object System.Collections.ArrayList
    foreach ($rec in $ledger.Records) {
        # A publication record says where a signed build was put, not what a file on disk is now,
        # so it is reported rather than audited -- there is no local file it claims anything about.
        $isPublication = $false
        if ($null -ne $rec.PSObject.Properties['event']) {
            if ($rec.event -eq 'published') { $isPublication = $true }
            elseif ($rec.event -eq 'relocated') {
                [void]$relocationRecords.Add($rec)
                if (-not $OnlyFile) {
                    Write-Host ("[{0}] {1}  RELOCATED" -f $rec.t.Substring(0, 19), $rec.name)
                    Write-Host ("     from      : {0}" -f $rec.from)
                    Write-Host ("     to        : {0}" -f $rec.file)
                    if ($rec.note) { Write-Host ("     note      : {0}" -f $rec.note) }
                }
                continue
            }
        }
        if ($isPublication) {
            [void]$publications.Add($rec)
            if (-not $OnlyFile) {
                Write-Host ("[{0}] {1}  PUBLISHED {2}" -f $rec.t.Substring(0, 19), $rec.name, $rec.tag)
                Write-Host ("     url       : {0}" -f $rec.url)
                Write-Host ("     sha256    : {0}" -f $rec.sha256_signed)
                if ($rec.note) { Write-Host ("     note      : {0}" -f $rec.note) }
            }
            continue
        }
        if ($OnlyFile -and $rec.file -ne $target -and $rec.name -ne $targetName) { continue }
        $matched++
        $verdict = 'gone'
        $current = ''
        $replacedBy = $null
        $relocatedTo = $null
        if (Test-Path -LiteralPath $rec.file) {
            $current = Get-SmytHash -Path $rec.file
            if ($current -eq $rec.sha256_signed) { $verdict = 'match' }
            elseif ($current -eq $rec.sha256_unsigned) { $verdict = 'unsigned' }
            elseif ($knownSignings.ContainsKey($current)) {
                # The bytes here are something this ledger signed, just not this record's signing:
                # the build was rebuilt and re-signed, which is an ordinary afternoon.
                $verdict = 'superseded'
                $replacedBy = @($knownSignings[$current] | Where-Object { $_.t -ne $rec.t } |
                                Sort-Object t | Select-Object -Last 1)
                if ($replacedBy.Count -eq 0) { $replacedBy = $null }
            }
            else { $verdict = 'changed' }
        } elseif ($relocations.ContainsKey($rec.file.ToLower())) {
            # The path is gone, but the ledger itself says where the build went. It counts as relocated
            # only if the bytes AT THE NEW PATH are this record's signed bytes: a relocation record is
            # a claim, and the file is the fact.
            $rel = $relocations[$rec.file.ToLower()]
            if (Test-Path -LiteralPath $rel.file) {
                if ((Get-SmytHash -Path $rel.file) -eq $rec.sha256_signed) {
                    $verdict = 'relocated'
                    $relocatedTo = $rel
                }
            }
        }
        $tally[$verdict]++

        if ($OnlyFile) {
            $line = switch ($verdict) {
                'match'      { 'this is a file S.M.Y.T. signed, unaltered since' }
                'superseded' { 'this path now holds a later S.M.Y.T. build, not the one this record describes' }
                'unsigned'   { 'these are the bytes as they were before signing; the signature is not on them' }
                'changed'    { 'this file has changed since it was signed, and the bytes are not from any signing here' }
                'gone'       { 'the recorded path does not exist, and no record says it was moved' }
                'relocated'  { 'the recorded path is gone, but the ledger records a move and the build is there, unaltered' }
            }
            Write-Host "$($rec.name): $line"
            Write-Host "  signed     : $($rec.t)"
            Write-Host "  sha256     : $($rec.sha256_signed)"
            if ($replacedBy) {
                Write-Host "  replaced by: $($replacedBy.t.Substring(0, 19))  $($replacedBy.note)"
            }
            if ($rec.note) { Write-Host "  note       : $($rec.note)" }
            continue
        }

        Write-Host ("[{0}] {1}  {2}" -f $rec.t.Substring(0, 19), $rec.name, $verdict.ToUpper())
        Write-Host ("     recorded  : {0}" -f $rec.sha256_signed)
        if ($verdict -eq 'gone') {
            Write-Host ("     on disk   : absent ({0})" -f $rec.file)
        } elseif ($verdict -eq 'relocated') {
            Write-Host ("     on disk   : gone there, present at {0}" -f $relocatedTo.file)
            Write-Host ("     moved     : {0}  {1}" -f $relocatedTo.t.Substring(0, 19), $relocatedTo.note)
            $s = Get-SmytSignature -Path $relocatedTo.file
            Write-Host ("     signature : {0}{1}" -f $s.Status, $(if ($s.Present) { " by $($s.Thumbprint.Substring(0,12))" } else { '' }))
        } else {
            Write-Host ("     on disk   : {0}" -f $current)
            if ($replacedBy) {
                Write-Host ("     replaced by: {0}  {1}" -f $replacedBy.t.Substring(0, 19), $replacedBy.note)
            }
            $s = Get-SmytSignature -Path $rec.file
            Write-Host ("     signature : {0}{1}" -f $s.Status, $(if ($s.Present) { " by $($s.Thumbprint.Substring(0,12))" } else { '' }))
            if ($s.Present -and $s.Thumbprint -ne $rec.thumbprint) {
                Write-Host "     signer is not the certificate this record names" -ForegroundColor Yellow
            }
        }
        if ($rec.note) { Write-Host ("     note      : {0}" -f $rec.note) }
    }

    if ($OnlyFile) {
        if ($matched -eq 0) {
            # The honest answer when someone asks about a file this tool never signed is that the
            # ledger has nothing to say about it, not a blank line.
            throw "no signing record in the ledger names $targetName; this tool never signed that file"
        }
        # Where this build went, if it went anywhere, is part of the answer about it.
        $hash = Get-SmytHash -Path $target
        foreach ($pub in $publications) {
            if ($pub.sha256_signed -eq $hash) {
                Write-Host ("published : {0} in {1} on {2}" -f $pub.tag, $pub.repo, $pub.t.Substring(0, 10))
                Write-Host ("            {0}" -f $pub.url)
            }
        }
        return
    }

    if (-not $OnlyFile) {
        Write-Host ""
        Write-Host ("{0} record(s): {1} unchanged, {2} superseded by a later signing of the same path, " -f `
            $ledger.Count, $tally['match'], $tally['superseded'])
        Write-Host ("              {0} changed by something this ledger has no record of, {1} now unsigned, {2} gone, {3} moved" -f `
            $tally['changed'], $tally['unsigned'], $tally['gone'], $tally['relocated'])
        if ($tally['changed'] -gt 0) {
            # This is the line worth reading: a path holding a later build is routine, a path
            # holding bytes nobody here signed is the thing the ledger exists to notice.
            Write-Host "  the changed ones are listed above; anything not described as superseded is unexplained" -ForegroundColor DarkGray
        }
        if ($publications.Count -gt 0) {
            Write-Host "$($publications.Count) of them record a publication rather than a file"
        }
        if ($relocationRecords.Count -gt 0) {
            Write-Host "$($relocationRecords.Count) of them record a move rather than a file"
        }
        if ($ledger.Broken -gt 0) {
            Write-Host "$($ledger.Broken) line(s) did not parse and were skipped" -ForegroundColor Yellow
        }
        $chain = Get-SmytLedgerChain -Ledger $ledger
        if ($chain.BrokenAt.Count -gt 0) {
            # Not "it has been edited": a fork is what an edit looks like, and it is also what an
            # interleaved append used to look like before the append took its own lock.
            Write-Host "the ledger's hash chain does not line up at line(s) $($chain.BrokenAt -join ', ')" -ForegroundColor Yellow
            Write-Host "  those lines do not follow the line before them: either they were edited after" -ForegroundColor DarkGray
            Write-Host "  being written, or they were written by an older version of this tool while" -ForegroundColor DarkGray
            Write-Host "  another signing was appending. Check the recorded hashes against the files." -ForegroundColor DarkGray
        } elseif ($chain.Chained -gt 0) {
            Write-Host "ledger chain intact across $($chain.Chained) record(s)$(if ($chain.Unchained -gt 0) { " ($($chain.Unchained) written before the chain existed)" })"
        }
    }
}

function Show-SmytStatus {
    # The state this script used to describe in prose, which is how the README came to claim a
    # machine-level trust that was no longer installed. A sentence cannot go stale if a command
    # prints it.
    $paths = Get-SmytPathsHere
    Write-Host "S.M.Y.T. signing status"
    Write-Host ""

    try { Write-Host "  signtool     : $(Get-SmytSignTool)" }
    catch { Write-Host "  signtool     : not found" -ForegroundColor Yellow }

    $identity = $null
    try { $identity = Get-SmytIdentity -Paths $paths } catch { }
    if ($identity) {
        Write-Host "  certificate  : $($identity.Thumbprint)"
        Write-Host "                 $($identity.Subject)"
        Write-Host "                 valid to $($identity.NotAfter.ToString('yyyy-MM-dd')); read from the $($identity.Source)"
        Write-Host "                 private key in Cert:\CurrentUser\My: $(if ($identity.InStore) { 'yes' } else { 'no' })"
    } else {
        Write-Host "  certificate  : none here -- run -NewCertificate" -ForegroundColor Yellow
    }
    Write-Host "  pfx          : $(if (Test-Path -LiteralPath $paths.Pfx) { Get-SmytExposure -Path $paths.Pfx } else { 'missing' })"
    if (Test-Path -LiteralPath $paths.PwSealed) {
        Write-Host "  password     : sealed ($(Get-SmytExposure -Path $paths.PwSealed))"
    } elseif (Test-Path -LiteralPath $paths.Pw) {
        Write-Host "  password     : IN THE CLEAR ($(Get-SmytExposure -Path $paths.Pw))"
    } else {
        Write-Host "  password     : missing"
    }
    Write-Host "  directory    : $(Get-SmytExposure -Path $SigningDir)"

    Write-Host ""
    Write-Host "  trust stores holding $(if ($identity) { 'this certificate' } else { 'any S.M.Y.T. certificate' }):"
    $inRoot = 0
    foreach ($store in $AllStores) {
        $hits = @(Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object {
            if ($identity) { $_.Thumbprint -eq $identity.Thumbprint } else { $_.Subject -like '*S.M.Y.T.*' }
        })
        if ($store -like '*\Root') { $inRoot += $hits.Count }
        Write-Host ("    {0,-40} {1}" -f $store, $hits.Count)
    }
    # A certificate in TrustedPublisher is a statement about a publisher; it is not a trust anchor,
    # so it cannot make a chain terminate. Only a root store does that, and a self-signed
    # certificate is its own root.
    Write-Host "    (the CurrentUser Root store shows the machine's root store too, so a machine-wide" -ForegroundColor DarkGray
    Write-Host "     install appears in both lines; LocalMachine is the one that was written)" -ForegroundColor DarkGray
    if ($inRoot -gt 0) {
        Write-Host "  verdict      : a root store holds it, so signatures verify on this machine"
    } else {
        Write-Host "  verdict      : no root store holds it, so every signature reports UnknownError here"
        Write-Host "                 TrustedPublisher alone never fixes this; see -TrustHelp" -ForegroundColor DarkGray
    }

    $ledger = Read-SmytLedger -Path $paths.Ledger
    Write-Host ""
    Write-Host "  ledger       : $($ledger.Count) record(s) in $($paths.Ledger)"
    if ($ledger.Broken -gt 0) { Write-Host "                 $($ledger.Broken) line(s) did not parse" -ForegroundColor Yellow }
    $unstamped = @($ledger.Records | Where-Object { -not $_.timestamped })
    if ($unstamped.Count -gt 0) {
        Write-Host "                 $($unstamped.Count) without a timestamp (these expire with the certificate)" -ForegroundColor Yellow
    }
    if ($ledger.Count -gt 0) {
        $chain = Get-SmytLedgerChain -Ledger $ledger
        if ($chain.BrokenAt.Count -gt 0) {
            Write-Host "                 hash chain broken at line(s) $($chain.BrokenAt -join ', ')" -ForegroundColor Yellow
        }
    }
    Write-Host "                 run -Check to compare the ledger against the files on disk"
}

function Install-SmytTrust {
    $paths = Get-SmytPathsHere
    if (-not (Test-Path -LiteralPath $paths.Cer)) { throw "no certificate at $($paths.Cer)" }
    # Installing repeatedly accumulates copies of the same certificate, which is how a store ends
    # up with several entries for one identity and verification starts reporting "multiple
    # certificates" instead of a clean chain. Remove any entry for this subject first.
    $key = ($Subject -split ',')[-1].Trim()
    foreach ($store in 'TrustedPublisher', 'Root') {
        $path = "Cert:\CurrentUser\$store"
        foreach ($old in (Get-ChildItem $path -ErrorAction SilentlyContinue |
                          Where-Object { $_.Subject -like "*$key*" })) {
            Remove-Item -Path ($path + "\" + $old.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
    }
    Import-Certificate -FilePath $paths.Cer -CertStoreLocation 'Cert:\CurrentUser\TrustedPublisher' |
        Out-Null
    Write-Host "installed the public certificate into Cert:\CurrentUser\TrustedPublisher"
    Write-Host "  that store states who the publisher is; it is not a trust anchor, so on its own it" -ForegroundColor DarkGray
    Write-Host "  changes no verification verdict anywhere." -ForegroundColor DarkGray

    if (-not $IncludeRoot) {
        Write-Host ""
        Write-Host "The root store was left alone, deliberately, and the signature still reports" -ForegroundColor DarkGray
        Write-Host "UnknownError because of it." -ForegroundColor DarkGray
        Write-Host "A self-signed certificate is its own root, so verification needs it in" -ForegroundColor DarkGray
        Write-Host "Cert:\CurrentUser\Root too -- and Windows asks a person to confirm that, which is" -ForegroundColor DarkGray
        Write-Host "the protection against software quietly trusting its own root. Note which store" -ForegroundColor DarkGray
        Write-Host "Windows demands consent for: the one that decides anything." -ForegroundColor DarkGray
        Write-Host "Do it once, by hand: double-click" -ForegroundColor DarkGray
        Write-Host "    $($paths.Cer)" -ForegroundColor DarkGray
        Write-Host "  -> Install Certificate -> Current User ->" -ForegroundColor DarkGray
        Write-Host "  -> Place all certificates in the following store -> Trusted Root Certification Authorities" -ForegroundColor DarkGray
        Write-Host "Then run -Status: it prints the verdict rather than a promise." -ForegroundColor DarkGray
        return
    }
    Import-Certificate -FilePath $paths.Cer -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    Write-Host "installed the public certificate into Cert:\CurrentUser\Root"
    Write-Host "  that store is the trust anchor: signatures now verify for this account" -ForegroundColor DarkGray
}

function Install-SmytMachineTrust {
    # Machine-wide, and installable without a prompt because the caller is already elevated: the
    # elevation *is* the consent. Worth being explicit that this trusts the certificate for every
    # account on the machine, not just this one -- which is right for a build machine and wrong
    # for a shared one.
    $paths = Get-SmytPathsHere
    if (-not ([Security.Principal.WindowsPrincipal]::new(
              [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
              [Security.Principal.WindowsBuiltInRole]::Administrator))) {
        throw "-MachineTrust needs an elevated session"
    }
    $key = ($Subject -split ',')[-1].Trim()
    foreach ($store in 'Cert:\LocalMachine\TrustedPublisher', 'Cert:\LocalMachine\Root') {
        foreach ($old in (Get-ChildItem $store -ErrorAction SilentlyContinue |
                          Where-Object { $_.Subject -like "*$key*" })) {
            Remove-Item -Path ($store + "\" + $old.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
        Import-Certificate -FilePath $paths.Cer -CertStoreLocation $store | Out-Null
        Write-Host "installed the public certificate into $store (all accounts on this machine)"
    }
    Write-Host "  Root is what makes signatures verify here; TrustedPublisher is the narrower" -ForegroundColor DarkGray
    Write-Host "  statement about the publisher, and either one alone would be a different claim." -ForegroundColor DarkGray
}

function Remove-SmytTrust {
    $key = ($Subject -split ',')[-1].Trim()
    $removed = 0
    $failed = 0
    foreach ($store in $AllStores) {
        foreach ($c in (Get-ChildItem $store -ErrorAction SilentlyContinue |
                        Where-Object { $_.Subject -like "*$key*" })) {
            try {
                Remove-Item -Path ($store + "\" + $c.Thumbprint) -Force -ErrorAction Stop
                Write-Host "removed from $store"
                $removed++
            } catch {
                Write-Host "could not remove from ${store}: $($_.Exception.Message)" -ForegroundColor Yellow
                $failed++
            }
        }
    }
    # Report the state before and after rather than a count of our own successes. A tally of what
    # a loop believes it did can disagree with the store -- it did here, under-reporting by two --
    # while the state of the store is the thing that decides whether a signature verifies.
    Write-Host "removed $removed entr(ies) in this pass"
    Write-Host "trusted S.M.Y.T. certificates now:"
    foreach ($store in $AllStores) {
        $left = @(Get-ChildItem $store -ErrorAction SilentlyContinue |
                  Where-Object { $_.Subject -like "*$key*" }).Count
        Write-Host ("  {0,-38} {1}" -f $store, $left)
    }
}

function Protect-SmytFiles {
    $paths = Get-SmytPathsHere
    Protect-SmytSecret -Path $paths.Pfx
    Protect-SmytSecret -Path $paths.Pw
    Protect-SmytSecret -Path $paths.Cer -Quiet
    Protect-SmytSecret -Path $paths.Ledger -Quiet
    Protect-SmytSecret -Path $SigningDir -Quiet
    Write-Host "the key material, the ledger and this directory now grant access to the owner, Administrators and SYSTEM only"
}

function Show-TrustHelp {
    $paths = Get-SmytPathsHere
    Write-Host "Making S.M.Y.T. signatures verify on this machine"
    Write-Host ""
    Write-Host "Two stores, two different jobs, and only one of them decides whether a signature" -ForegroundColor Cyan
    Write-Host "verifies:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Trusted Root Certification Authorities  -- the trust anchors. Windows builds a chain" -ForegroundColor White
    Write-Host "      from the signer up to a root, and a chain that ends at a root it does not trust is" -ForegroundColor DarkGray
    Write-Host "      not trusted, whatever else is installed. A self-signed certificate IS its own root," -ForegroundColor DarkGray
    Write-Host "      so this is the store that decides the verdict. Nothing else can substitute." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Trusted Publishers  -- a statement that this publisher is one you accept, consulted" -ForegroundColor White
    Write-Host "      by installers and by some policies. It is not an anchor: with the certificate only" -ForegroundColor DarkGray
    Write-Host "      here, Get-AuthenticodeSignature still reports UnknownError. It is worth having, but" -ForegroundColor DarkGray
    Write-Host "      it is the second half of the statement, not the first." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "So the honest answer is both -- and the order of importance is the opposite of the" -ForegroundColor Cyan
    Write-Host "order they are usually installed in, because the store that changes nothing installs" -ForegroundColor Cyan
    Write-Host "silently while the one that decides requires a person to agree." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Two ways, both one-time:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  A) This opens the certificate's own import wizard:"
    Write-Host "         Install Certificate"
    Write-Host "           -> Store Location:  Current User"
    Write-Host "           -> Place all certificates in the following store"
    Write-Host "           -> Browse -> Trusted Root Certification Authorities"
    Write-Host ""
    Write-Host "  B) Or run this file from an interactive console and approve the prompt once:"
    Write-Host "         .\smyt-sign.ps1 -InstallTrust -IncludeRoot"
    Write-Host ""
    Write-Host "Afterwards, 'Get-AuthenticodeSignature <file>' reports Valid and the publisher reads"
    Write-Host "S.M.Y.T. Until then it reports UnknownError, which means exactly this and nothing worse."
    Write-Host "Run -Status to have that stated rather than promised."
    Write-Host ""
    if (Test-Path -LiteralPath $paths.Cer) {
        Write-Host "opening $($paths.Cer) ..."
        Start-Process $paths.Cer
    } else {
        Write-Host "no certificate at $($paths.Cer) -- run -NewCertificate first" -ForegroundColor Yellow
    }
}

function Show-SmytLog {
    param([int]$Count)
    $paths = Get-SmytPathsHere
    $ledger = Read-SmytLedger -Path $paths.Ledger
    if ($ledger.Count -eq 0) { Write-Host "nothing has been signed yet ($($paths.Ledger))"; return }
    Write-Host "$($ledger.Count) record(s), most recent last:"
    foreach ($r in ($ledger.Records | Select-Object -Last $Count)) {
        try {
            $isPublication = $false
            if ($null -ne $r.PSObject.Properties['event']) {
                if ($r.event -eq 'published') { $isPublication = $true }
            }
            if ($isPublication) {
                $note = ''
                if ($r.note) { $note = "  -- $($r.note)" }
                Write-Host ("  {0}  {1,-28} {2}  published {3}{4}" -f `
                    $r.t.Substring(0, 19), $r.name, $r.sha256_signed.Substring(0, 16), $r.tag, $note)
                continue
            }
            $note = ''
            if ($r.note) { $note = "  -- $($r.note)" }
            # A record with no timestamp is the one that quietly stops verifying when the
            # certificate expires, so it is marked rather than left to look like the others.
            $mark = ''
            if ($r.timestamped -eq $false) { $mark = '  [no timestamp]' }
            Write-Host ("  {0}  {1,-28} {2}  {3}{4}{5}" -f `
                $r.t.Substring(0, 19), $r.name, $r.sha256_signed.Substring(0, 16), $r.signer, $mark, $note)
        } catch {
            Write-Host "  (a record is missing fields this view needs)" -ForegroundColor Yellow
        }
    }
    if ($ledger.Broken -gt 0) {
        Write-Host "$($ledger.Broken) line(s) in the ledger did not parse" -ForegroundColor Yellow
    }
}

function Invoke-SmytRelocate {
    # A move is a statement that a known build is now somewhere else. It is not a signing event and not
    # an audit finding, so it gets its own record shape: the file, where it came from, and which of the
    # two recorded hashes was verified at the new path.
    #
    # Two hashes may match, and which one did is printed rather than left to be inferred. A build that
    # was signed hashes to sha256_signed; the same build after its signature was stripped hashes to
    # sha256_unsigned. Both are that build and both may legitimately move, but they are different states
    # of it, and a record that does not say which one was checked invites the reader to guess.
    #
    # A file the ledger has never seen is refused on purpose. For that file the correct action is to
    # sign it; a relocation record asserting that a known build moved would be a false statement.
    param([Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string]$To, [string]$NoteText = '')

    $paths = Get-SmytPathsHere
    $ledger = Read-SmytLedger -Path $paths.Ledger

    if (-not (Test-Path -LiteralPath $To -PathType Leaf)) { throw "nothing at the new path: $To" }
    $resolvedNew = (Resolve-Path -LiteralPath $To).Path
    $hash = Get-SmytHash -Path $resolvedNew
    $size = (Get-Item -LiteralPath $resolvedNew).Length

    # Each record is asked directly, rather than through a view of the ledger that another proposed
    # change would have to add. A verb that needs a second patch before it works cannot be taken on its
    # own, and this one is meant to be taken on its own.
    $match = $null
    $matchedAs = ''
    foreach ($record in $ledger.Records) {
        if ($null -ne $record.PSObject.Properties['event']) { continue }
        if ($null -ne $record.PSObject.Properties['sha256_signed'] -and
            $record.sha256_signed -eq $hash) { $match = $record; $matchedAs = 'signed bytes'; break }
        if ($null -ne $record.PSObject.Properties['sha256_unsigned'] -and
            $record.sha256_unsigned -eq $hash) { $match = $record; $matchedAs = 'unsigned bytes'; break }
    }
    if (-not $match) {
        throw ("no record in $($paths.Ledger) carries $hash, so this tool never signed what is now at " +
               "$resolvedNew; sign it instead of relocating it")
    }

    $note = "moved by -Relocate; bytes verified unchanged against $matchedAs"
    if ($NoteText) { $note = $note + '; ' + $NoteText }
    $event = @{
        'event'         = 'relocated'
        't'             = (Get-Date).ToUniversalTime().ToString('o')
        'file'          = $resolvedNew
        'name'          = (Split-Path -Leaf $resolvedNew)
        'size'          = $size
        'from'          = $From
        'sha256_signed' = $match.sha256_signed
        'note'          = $note
    }
    Add-SmytLedgerRecord -Path $paths.Ledger -Record $event

    Write-Host "relocated and recorded"
    Write-Host "  from     : $From"
    Write-Host "  to       : $resolvedNew"
    Write-Host "  verified : sha256 $hash"
    Write-Host "  matched  : $($match.name) in the ledger, as $matchedAs"
}

if ($NewCertificate) { New-SmytCertificate }
if ($Protect)        { Protect-SmytFiles }
if ($InstallTrust)   { Install-SmytTrust }
if ($MachineTrust)   { Install-SmytMachineTrust }
if ($RemoveTrust)    { Remove-SmytTrust }
if ($TrustHelp)      { Show-TrustHelp }
if ($Verify)         { Show-SmytSignature -Target $Verify }
if ($CheckFile)      { Show-SmytCheck -OnlyFile $CheckFile }
if ($Check)          { Show-SmytCheck }
if ($Status)         { Show-SmytStatus }
if ($Log)            { Show-SmytLog -Count $Last }
if ($RelocateFrom -or $RelocateTo) {
    # The dispatch block below does not exit, so a verb that finishes successfully would still print the
    # usage synopsis underneath its own result. This branch ends the run instead.
    if (-not $RelocateFrom) { throw "-RelocateFrom is missing: it is the path the ledger recorded" }
    if (-not $RelocateTo) { throw "-RelocateTo is missing: it is where the file is now" }
    Invoke-SmytRelocate -From $RelocateFrom -To $RelocateTo -NoteText $Note
    exit 0
}
foreach ($target in $Sign) { Invoke-SmytSign -Target $target -NoteText $Note }

if (-not $NewCertificate -and -not $InstallTrust -and -not $MachineTrust -and -not $Protect -and
    -not $RemoveTrust -and -not $TrustHelp -and -not $Verify -and -not $Log -and -not $Sign -and
    -not $RelocateFrom -and -not $RelocateTo -and -not $Check -and -not $CheckFile -and
    -not $Status) {
    Get-Help $PSCommandPath -Detailed
}
