# What this terminal does to the gate's output.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\terminal-probe.ps1
#
# Run it once in each shell or terminal you care about and keep the output. A machine has only a
# few terminals on it, and none of them can be driven from a script, so the honest way to cover the
# ones that are not installed here is to have the person who has them run one command.
#
# The questions below are the only ones the gate's output depends on. Nothing in this tool branches
# on which terminal it is in -- a table of product names goes stale and is wrong the moment somebody
# uses something not on it. It branches on what the terminal can do, and these are those things.
#
# ASCII only, deliberately: a probe for encoding trouble that is itself encoding trouble is no use.

$ErrorActionPreference = 'Continue'

function Show([string]$label, [string]$value) {
    Write-Host ("  " + $label.PadRight(26) + $value)
}

Write-Host ''
Write-Host 'terminal probe'
Write-Host '--------------'
Show 'PowerShell' $PSVersionTable.PSVersion.ToString()
Show 'stdout is a console' (-not [Console]::IsOutputRedirected)
Show 'stdout encoding' ([Console]::OutputEncoding.WebName)
Show 'code page' ([Console]::OutputEncoding.CodePage)
try { Show 'window (cols x rows)' ($Host.UI.RawUI.WindowSize.Width.ToString() + ' x ' + $Host.UI.RawUI.WindowSize.Height.ToString()) } catch { Show 'window' 'not reported' }
foreach ($name in @('TERM', 'WT_SESSION', 'TERM_PROGRAM', 'COLORTERM')) {
    $value = [Environment]::GetEnvironmentVariable($name)
    Show $name $(if ($value) { $value } else { '(unset)' })
}

Write-Host ''
Write-Host 'sample 1: letters and digits (must line up)'
Write-Host '  +-------------------------+'
Write-Host '  |  B O N F I R E   L I T  |'
Write-Host '  +-------------------------+'

Write-Host ''
Write-Host 'sample 2: the art the notice carries (must not wrap at 100 columns)'
$rule = '-' * 100
Write-Host "  $rule"
Write-Host '  .:-=+*#%@  .:-=+*#%@  .:-=+*#%@  .:-=+*#%@  .:-=+*#%@  .:-=+*#%@  .:-=+*#%@  .:-=+*#'
Write-Host "  $rule"

Write-Host ''
Write-Host 'sample 3: text that is not ASCII, built from code points so this file stays ASCII'
Show 'expected code points' '672C 5DE5 5177 / 8056 5922 5E7D 5EAD / 30AA 30F3 30EA 30FC 30B5 30A4 30F3'
$sample = [string][char]0x672C + [char]0x5DE5 + [char]0x5177 + '  ' +
          [char]0x8056 + [char]0x5922 + [char]0x5E7D + [char]0x5EAD + '  ' +
          [char]0x30AA + [char]0x30F3 + [char]0x30EA + [char]0x30FC + [char]0x30B5 + [char]0x30A4 + [char]0x30F3
Show 'rendered' $sample
            [char]0x8056 + [char]0x5922 + [char]0x5E7D + [char]0x5EAD + '  ' +
            [char]0x30AA + [char]0x30F3 + [char]0x30EA + [char]0x30FC + [char]0x30B5 + [char]0x30A4 + [char]0x30F3
Write-Host ''
Write-Host 'If sample 3 shows boxes or question marks, the notice will too in this terminal.'
Write-Host 'If sample 2 wrapped, the notice art will too: widen the window to 100 columns or more.'
Write-Host ''
