# smyt-common.ps1 -- what all three S.M.Y.T. scripts share
#
# Dot-source it, never run it:
#     . (Join-Path $PSScriptRoot 'smyt-common.ps1')
#
# Two kinds of thing live here, both for the same reason: a second copy would drift from the
# first. The environment guard, because the failure it prevents is invisible and misreported.
# And the signing identity, because reading it from the published certificate is what makes a
# subject string typed into a check unnecessary.

function Repair-SmytModulePath {
    # Windows PowerShell finds a module by walking PSModulePath in order and taking the FIRST
    # directory that holds it. A PowerShell 7 session exports its own module directories at the
    # front of that variable, and any 5.1 process started from there inherits that order -- so
    # 5.1 tries to load 7's binary modules, cannot, and Get-FileHash, Get-AuthenticodeSignature,
    # ConvertTo-SecureString and Get-Acl stop existing in that session. The error names the
    # symptom ("Get-FileHash is not recognized") and hides the cause, so the repair happens here.
    $own = Join-Path $PSHOME 'Modules'
    $parts = @($env:PSModulePath -split ';' | Where-Object { $_ })
    $shadow = @($parts | Where-Object { $_ -match '[\\/]7[\\/]Modules$' })
    if ($parts.Count -eq 0 -or $parts[0] -ne $own) {
        $env:PSModulePath = (@($own) + @($parts | Where-Object { $_ -ne $own })) -join ';'
    }
    if ($shadow.Count -gt 0) {
        Write-Host "environment: PSModulePath carried PowerShell 7 module directories; " -NoNewline -ForegroundColor DarkGray
        Write-Host "$own now comes first" -ForegroundColor DarkGray
    }
}

function Assert-SmytModules {
    param([Parameter(Mandatory)][string[]]$Names)
    $missing = @()
    foreach ($n in $Names) {
        if (-not (Get-Command $n -ErrorAction SilentlyContinue)) { $missing += $n }
    }
    if ($missing.Count -gt 0) {
        $own = Join-Path $PSHOME 'Modules'
        throw ("this session cannot load $($missing -join ', '), so that check cannot run. The Windows " +
               "PowerShell modules are unreachable from PSModulePath [$env:PSModulePath]. Open a plain " +
               "Windows PowerShell console, or set PSModulePath to '$own' first.")
    }
}

function Get-SmytPaths {
    param([Parameter(Mandatory)][string]$SigningDir)
    return [ordered]@{
        Dir     = $SigningDir
        Pfx     = Join-Path $SigningDir 'smyt-codesign.pfx'
        Cer     = Join-Path $SigningDir 'smyt-codesign.cer'
        Pw      = Join-Path $SigningDir 'pfx-password.txt'
        # The same secret, sealed: the convention is that a container REPLACES the extension, so
        # this is what a secret looks like at rest. Pw stays declared because the plaintext form is
        # still what -NewCertificate understands and what older material on this machine looks like.
        PwSealed = Join-Path $SigningDir 'pfx-password.sealed'
        Ledger  = Join-Path $SigningDir 'smyt-signings.ndjson'
        History = Join-Path $SigningDir 'history'
    }
}

function Get-SmytHash {
    # Computed in .NET rather than with Get-FileHash on purpose: this is the one operation the
    # ledger cannot be read or written without, and it must not depend on a module being loadable.
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
                                         [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try { $bytes = $sha.ComputeHash($stream) } finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-SmytTextHash {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) } finally { $sha.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-SmytSignTool {
    $onPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    # Architecture first, then version: the SDK ships the same signtool for several targets and
    # sorting the full paths mixes them together, which is how "x86" wins over "x64" -- '8' sorts
    # after '4'. The highest SDK version within the first architecture that has one is the answer.
    foreach ($arch in 'x64', 'arm64', 'x86') {
        $candidates = @()
        foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
            if (-not $base) { continue }
            $candidates += @(Get-ChildItem (Join-Path $base "Windows Kits\10\bin\*\$arch\signtool.exe") `
                -ErrorAction SilentlyContinue)
        }
        if ($candidates.Count -gt 0) {
            # Every real SDK version reads 10.0.1xxxx or 10.0.2xxxx, so a plain string sort puts
            # them in the right order; a numeric one would be more honest, not more correct.
            return ($candidates | Sort-Object FullName | Select-Object -Last 1).FullName
        }
    }
    throw "signtool.exe not found; install the Windows SDK, or put signtool.exe on PATH"
}

function Get-SmytSealedPath {
    # The convention: the sealed form REPLACES the extension. pfx-password.txt -> pfx-password.sealed.
    param([Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Parent $Path
    $stem = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path -Leaf $Path))
    return (Join-Path $dir ($stem + '.sealed'))
}

function Get-SmytPfxPassword {
    # The sealed form wins when it is there. It is the same secret, and it is the only form that is not
    # sitting in the clear beside the key it protects -- which is the whole reason .sealed exists.
    param([Parameter(Mandatory)][string]$Path)
    $sealed = Get-SmytSealedPath -Path $Path
    if (Test-Path -LiteralPath $sealed) {
        $opener = Join-Path (Split-Path -Parent $PSCommandPath) 'seal.mjs'
        if (-not (Test-Path -LiteralPath $opener)) {
            throw "the password at $sealed is sealed but the opener is missing: $opener"
        }
        $plain = (& node $opener open $sealed 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "could not open $sealed : $plain"
        }
        return $plain.Trim()
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "no password file at $Path and no sealed form beside it -- run -NewCertificate first"
    }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8).Trim()
}

function Get-SmytIdentity {
    # The published .cer is the statement of who signs; the pfx is the key that does it. Reading
    # the thumbprint from the public half means the identity verification demands is the identity
    # that was published, rather than a subject string that anyone can copy into a new certificate.
    param(
        [Parameter(Mandatory)]$Paths,
        [switch]$RequirePrivateKey
    )
    $cert = $null
    $source = ''
    if (Test-Path -LiteralPath $Paths.Cer) {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Paths.Cer)
        $source = 'cer'
    } elseif (Test-Path -LiteralPath $Paths.Pfx) {
        $pw = Get-SmytPfxPassword -Path $Paths.Pw
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Paths.Pfx, $pw)
        $source = 'pfx'
    } else {
        throw "no certificate at $($Paths.Cer) or $($Paths.Pfx) -- run -NewCertificate first"
    }

    $inStore = $null
    if (Test-Path 'Cert:\CurrentUser\My') {
        foreach ($c in @(Get-ChildItem 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue)) {
            if ($c.Thumbprint -eq $cert.Thumbprint -and $c.HasPrivateKey) { $inStore = $c; break }
        }
    }

    # Signing from the store rather than from the pfx keeps the password off the command line,
    # where every process on the machine can read it for as long as signtool is alive. The pfx
    # stays as the offline backup of the key, not as the thing signing happens through.
    $signArgs = @()
    if ($inStore) {
        $signArgs = @('/sha1', $cert.Thumbprint)
    } elseif (Test-Path -LiteralPath $Paths.Pfx) {
        $signArgs = @('/f', $Paths.Pfx, '/p', (Get-SmytPfxPassword -Path $Paths.Pw))
    }

    if ($RequirePrivateKey -and $signArgs.Count -eq 0) {
        throw ("the certificate $($cert.Thumbprint) has no private key here: import $($Paths.Pfx) into " +
               "Cert:\CurrentUser\My, or keep the pfx beside this script.")
    }

    return [ordered]@{
        Thumbprint    = $cert.Thumbprint
        Subject       = $cert.Subject
        NotAfter      = $cert.NotAfter
        Source        = $source
        InStore       = [bool]$inStore
        SignArguments = $signArgs
    }
}

function Get-SmytSignature {
    # One shape for "what does this file carry", so callers do not each repeat the null checks.
    param([Parameter(Mandatory)][string]$Path)
    Assert-SmytModules 'Get-AuthenticodeSignature'
    $s = Get-AuthenticodeSignature -LiteralPath $Path
    $signer = $s.SignerCertificate
    $subject = ''
    $thumbprint = ''
    if ($signer) { $subject = $signer.Subject; $thumbprint = $signer.Thumbprint }
    $stampedBy = ''
    if ($s.TimeStamperCertificate) { $stampedBy = $s.TimeStamperCertificate.Subject }
    return [ordered]@{
        Status      = $s.Status
        Present     = [bool]$signer
        Subject     = $subject
        Thumbprint  = $thumbprint
        Timestamped = [bool]$s.TimeStamperCertificate
        TimestampBy = $stampedBy
    }
}

function Get-SmytExposure {
    # What a secret file's ACL actually says. The password file was hardened when it was created
    # and the pfx beside it was not, so on this machine the key was readable and writable by every
    # authenticated user while the password was locked to one account. A claim about the ACL is
    # worth nothing next to a reading of it.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 'missing' }
    # Get-Acl rather than $item.GetAccessControl(): that helper method belongs to .NET Framework and
    # does not exist in the runtime PowerShell 7 runs on, so this line threw "method invocation
    # failed -- [System.IO.FileInfo] does not contain a method named 'GetAccessControl'" there and
    # -Status died partway through. The provider cmdlets exist on both editions, which is why they
    # are the ones used here; the object they return has the same Access and
    # SetAccessRuleProtection API, so nothing else about this function changes.
    $acl = Get-Acl -LiteralPath $Path
    $open = @()
    foreach ($rule in @($acl.Access)) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $id = $rule.IdentityReference.Value
        if ($id -match 'Authenticated Users' -or $id -match 'Everyone' -or
            $id -match '\\Users$' -or $id -match 'INTERACTIVE') {
            $open += ($id + ' ' + $rule.FileSystemRights)
        }
    }
    if ($open.Count -gt 0) { return ('open to ' + (($open | Select-Object -Unique) -join ', ')) }
    $count = @($acl.Access).Count
    return "restricted ($count entr(ies): $((@($acl.Access) | ForEach-Object { $_.IdentityReference.Value }) -join ', '))"
}

function Protect-SmytSecret {
    # Inheritance is dropped rather than edited: the inherited entries are the ones that hand the
    # file to every authenticated user, and re-granting the three principals that should keep
    # access is shorter and easier to audit than removing the rest one at a time.
    param([Parameter(Mandatory)][string]$Path, [switch]$Quiet)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    $acl = Get-Acl -LiteralPath $Path           # see Get-SmytExposure: the .NET helper is absent on 7
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }

    $inheritance = 'None'
    if ($item.PSIsContainer) { $inheritance = 'ContainerInherit, ObjectInherit' }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $added = 0
    foreach ($who in @($me, 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
        try {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $who, 'FullControl', $inheritance, 'None', 'Allow')))
            $added++
        } catch {
            if (-not $Quiet) { Write-Host "  (could not grant $who on $Path)" -ForegroundColor DarkGray }
        }
    }
    # Never write an empty DACL: an ACL with no entries locks the owner out of their own key, and
    # the owner is the only account that can put it back.
    if ($added -eq 0) { throw "refusing to write an empty ACL on $Path" }
    Set-Acl -LiteralPath $Path -AclObject $acl
    if (-not $Quiet) { Write-Host "protected $Path (owner, Administrators, SYSTEM)" }
}

function Read-SmytLedger {
    # The ledger is UTF-8 with no BOM, written by this toolchain. Get-Content without -Encoding
    # decodes it with the machine's ANSI code page instead -- 936 here -- which turns a Chinese
    # note into mojibake and, because the tail byte of the last character pairs with the closing
    # quote, makes the line unparseable: one character costs a whole record. The encoding is
    # pinned on both sides now, and the caller is told how many lines did not parse.
    param([Parameter(Mandatory)][string]$Path)
    $records = New-Object System.Collections.ArrayList
    $raw = New-Object System.Collections.ArrayList
    $broken = 0

    # PowerShell 6.0 and later infer [DateTime] from an ISO-8601 string; 5.1 leaves it a string. The
    # same ledger, read by the two editions, therefore handed back two different types -- and the
    # seven places that format `t` with .Substring(0, 19) worked on one edition and threw on the
    # other, at the first of the seven, with "method invocation failed because [System.DateTime]
    # does not contain a method named 'Substring'". The message is paraphrased in ASCII on purpose:
    # this file must stay pure ASCII, because a .ps1 with no BOM and a non-ASCII byte in it is
    # decoded with the machine's ANSI code page by Windows PowerShell and can stop parsing.
    #
    # Converting the result afterwards is not a fix, and that was measured rather than reasoned
    # about. [string] on a DateTime reformats it with the machine's culture, so
    # 2026-10-05T08:43:25.3340146Z comes back as 10/05/2026 08:43:25: the sub-second part and the Z
    # are gone, and month and day swap on a machine whose culture orders them the other way. The
    # consumers would stop throwing and start printing a date the ledger does not contain, silently,
    # which is worse than throwing.
    #
    # So the parse itself must not infer. -DateKind String says exactly that; it was added in 7.5.
    $parseSwitches = @{}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
        $parseSwitches['DateKind'] = 'String'
    }
    if (Test-Path -LiteralPath $Path) {
        foreach ($line in @(Get-Content -LiteralPath $Path -Encoding UTF8 | Where-Object { $_.Trim() })) {
            try {
                $record = $line | ConvertFrom-Json @parseSwitches
                # An edition between 6.0 and 7.4 has the inference and not the switch. The round-trip
                # format is the one ToString that reproduces the text exactly, and the kind is Utc
                # because the ledger writes Z. Applied to any date-valued field rather than to `t`,
                # because the next field added would otherwise reintroduce this.
                foreach ($property in @($record.PSObject.Properties)) {
                    if ($property.Value -is [datetime]) {
                        $property.Value = $property.Value.ToString('o')
                    }
                }
                [void]$records.Add($record)
                [void]$raw.Add($line)
            } catch { $broken++ }
        }
    }
    return [ordered]@{
        Records = @($records)
        Raw     = @($raw)
        Broken  = $broken
        Count   = $records.Count
    }
}

function Add-SmytLedgerRecord {
    # Appending is the one operation two release processes can collide on, and the chain makes the
    # collision look like tampering: each record names the line before it, so if both signers read
    # the tip and then both write, the second record points at a line that is no longer its
    # predecessor, and the chain reports a fork -- which reads as "someone edited the ledger" when
    # nobody did. Demonstrated before this was fixed: two records sharing a parent produced
    # "broken at line 3" on a ledger nothing had touched.
    #
    # So the tip is not read by the caller. It is read here, inside a handle that excludes other
    # writers, and the line is appended before the handle is released -- one reader, one writer, one
    # moment. Readers are still allowed through, so -Log and -Check are never locked out.
    #
    # The bytes are written with an explicit encoder rather than Add-Content -Encoding UTF8: the
    # writer must not leave the reader guessing, because guessing is what made this file unreadable.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Record)

    if (-not ($Record -is [System.Collections.IDictionary])) {
        throw "a ledger record must be a hashtable, so the chain field can be set on it here"
    }

    $attempt = 0
    while ($true) {
        $attempt++
        $stream = $null
        try {
            $stream = New-Object System.IO.FileStream($Path,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::Read)
        } catch [System.IO.IOException] {
            # Another signing holds the writer's side. Ten seconds of patience, then say so rather
            # than lose the record quietly.
            if ($attempt -ge 40) {
                throw "the ledger $Path stayed locked for $attempt attempts; another signing may be stuck"
            }
            Start-Sleep -Milliseconds 250
            continue
        }

        try {
            $reader = New-Object System.IO.StreamReader($stream,
                (New-Object System.Text.UTF8Encoding($false)), $false, 4096, $true)
            $text = $reader.ReadToEnd()
            $reader.Dispose()

            $tip = ''
            if ($text.Trim()) {
                $lastLine = @($text -split "`r?`n" | Where-Object { $_.Trim() })[-1]
                $tip = Get-SmytTextHash -Text $lastLine
            }
            $Record['prev'] = $tip

            $json = $Record | ConvertTo-Json -Compress
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
            $stream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            $stream.Dispose()
            $stream = $null
        } finally {
            if ($stream) { $stream.Dispose() }
        }
        return
    }
}

function Get-SmytLedgerChain {
    # Each record carries the hash of the line before it. The ledger is the half of a signature
    # that says what was covered, so an edit to it should be visible rather than silent. Records
    # written before the chain existed have no prev field and are reported as unchained.
    param([Parameter(Mandatory)]$Ledger)
    $breaks = New-Object System.Collections.ArrayList
    $chained = 0
    $unchained = 0
    for ($i = 0; $i -lt $Ledger.Records.Count; $i++) {
        $rec = $Ledger.Records[$i]
        $hasField = $null -ne $rec.PSObject.Properties['prev']
        if (-not $hasField) {
            # Written before the chain existed; there is nothing to check it against.
            $unchained++
            continue
        }
        if (-not $rec.prev) {
            # The genesis record: the ledger was empty when it was written, so it links to nothing.
            # That is the start of the chain rather than a hole in it.
            $chained++
            continue
        }
        $previousRaw = ''
        if ($i -gt 0) { $previousRaw = $Ledger.Raw[$i - 1] }
        $expected = Get-SmytTextHash -Text $previousRaw
        if ($rec.prev -ne $expected) { [void]$breaks.Add(($i + 1)) }
        $chained++
    }
    return [ordered]@{ Chained = $chained; Unchained = $unchained; BrokenAt = @($breaks) }
}

function Invoke-SmytNative {
    # Native tools write progress and errors to stderr, and with ErrorActionPreference at Stop
    # PowerShell turns any stderr line into a terminating error -- which is how a PyInstaller
    # deprecation notice once aborted a build that had actually succeeded. The preference is
    # relaxed for the duration of the call and the exit code is what decides.
    param(
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    return [ordered]@{ Code = $code; Output = @($output) }
}

function Assert-SmytOutDir {
    # A recursive delete of a directory that came from a parameter is one typo away from an empty
    # disk, so the parameter has to name a directory it is allowed to name.
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$AllowedRoots = @('D:\DaShaoHuo'),
        [switch]$AllowAnywhere
    )
    if ($AllowAnywhere) { return $Path }
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { throw "not a usable path: $Path" }
    if ($full -match '^[A-Za-z]:\\?$') { throw "refusing to use a drive root as a working directory: $full" }
    foreach ($root in $AllowedRoots) {
        $r = [System.IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
        if ($full.StartsWith($r, [System.StringComparison]::OrdinalIgnoreCase)) { return $full }
    }
    throw ("refusing to write to $full -- it is outside $($AllowedRoots -join ', '). Pass -AllowAnywhere if that " +
           "is deliberate, keeping in mind nothing here should be writing to C:.")
}
