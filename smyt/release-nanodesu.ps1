# release-nanodesu.ps1 -- one command to build, sign and publish Nanodesu
#
# Thin wrapper around smyt-release.ps1 that knows Nanodesu's paths. Everything it does, the general
# tool does too; this exists so a release is one command instead of six arguments.
#
# Usage:
#   .\release-nanodesu.ps1                          build, sign, verify, hash (no upload)
#   .\release-nanodesu.ps1 -Publish -Tag v1.2.0     also upload, and check the published digest
#   .\release-nanodesu.ps1 -SignOnly build\x.exe    sign an artifact that already exists
#
# Note: the splatting hashtable is not called $args. That name is a PowerShell automatic variable
# holding the unbound arguments, and reusing it makes the call behave in ways the code does not
# describe -- which is exactly how this script first failed.

param(
    [switch]$Publish,
    [string]$Tag,
    [string]$SignOnly,
    [string]$Note = '',
    [string]$Repo = 'Nesarf/Nanodesu',
    [string]$SigningDir = '',
    [string]$OutDir = 'D:\DaShaoHuo\build-artifacts\staging-nanodesu'
)

$ErrorActionPreference = 'Stop'

# The toolchain travels with this file, so its location comes from where this file is rather than
# from a path written out in three scripts that would have to be edited together.
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $SigningDir) { $SigningDir = $here }

. (Join-Path $here 'smyt-common.ps1')
Repair-SmytModulePath

# The scripts come from where this file lives; -SigningDir names the key material and the ledger.
# Keeping the two apart is what lets a release be rehearsed against a copied certificate without
# the real record hearing about it.
$release = Join-Path $here 'smyt-release.ps1'
if (-not (Test-Path -LiteralPath $release)) { throw "release tool not found at $release" }

$source = 'E:\~Sayori~Sleeping~\nanodesu-release\nanodesu.py'
# -SigningDir has to travel on to the release script. It did not, so the parameter looked like it
# did something and the release fell back to the real signing directory -- the same silence one
# layer up from the one that put a test record in the real ledger.
$relArgs = @{ OutDir = $OutDir; SigningDir = $SigningDir }

if ($SignOnly) {
    if (-not (Test-Path -LiteralPath $SignOnly)) { throw "no such artifact: $SignOnly" }
    $relArgs.Artifact = $SignOnly
} else {
    if (-not (Test-Path -LiteralPath $source)) { throw "no source at $source" }
    $relArgs.Build = $true
    $relArgs.Source = $source
    $relArgs.Name = 'nanodesu'
}

if ($Note) { $relArgs.Note = $Note }
if ($Publish) {
    if (-not $Tag) { throw "-Publish needs -Tag <tag>" }
    $relArgs.Publish = $true
    $relArgs.Repo = $Repo
    $relArgs.Tag = $Tag
}

# Called directly rather than through a second powershell.exe. Relaying switch parameters across
# the command line turns $true into the string "True", which cannot bind to a [switch] -- so the
# wrapper failed on its own arguments. In-process splatting binds them correctly.
& $release @relArgs
