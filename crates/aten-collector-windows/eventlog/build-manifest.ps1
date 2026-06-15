<#
.SYNOPSIS
  Compile aten.man into the resource DLL (aten_events.dll) that the
  Windows Event Log channel needs for its message/template resources.

.DESCRIPTION
  Runs the message compiler -> resource compiler -> linker chain:
      mc.exe -um aten.man            (=> aten.h, aten.rc, *.bin)
      rc.exe /fo aten.res aten.rc
      link.exe /DLL /NOENTRY ...         (=> aten_events.dll)

  This is intentionally NOT wired into 'cargo build' -- it needs the Windows SDK
  plus the MSVC toolchain and only runs on Windows. Run it once (or in CI)
  whenever aten.man changes. The produced DLL is what 'aten install'
  copies to %ProgramData%\aten and registers via 'wevtutil im'.

  After building, register (admin):
      wevtutil im aten.man /rf:<full path to aten_events.dll> /mf:<same>
  Inspect:  wevtutil gl ATEN/Operational
  Remove:   wevtutil um aten.man

.NOTES
  Run from a regular PowerShell; the script locates mc/rc (Windows Kit) and
  link.exe (MSVC via vswhere, or PATH if you are in a VS Developer prompt).
#>
[CmdletBinding()]
param(
    [string]$Arch = "x64"
)
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Find-Latest($root, $name) {
    if (-not (Test-Path $root)) { return $null }
    Get-ChildItem $root -Recurse -Filter $name -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}

# --- locate tools ---
$kitBin = "C:\Program Files (x86)\Windows Kits\10\bin"
$mc = Find-Latest (Join-Path $kitBin "*\$Arch") "mc.exe"
$rc = Find-Latest (Join-Path $kitBin "*\$Arch") "rc.exe"
if (-not $mc) { $mc = Find-Latest $kitBin "mc.exe" }
if (-not $rc) { $rc = Find-Latest $kitBin "rc.exe" }

# Prefer the MSVC linker via vswhere FIRST -- PATH often has Git's
# /usr/bin/link.exe (GNU coreutils 'link'), which is NOT the MSVC linker.
$link = $null
$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vc = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -find "VC\Tools\MSVC\**\bin\Host$Arch\$Arch\link.exe" 2>$null |
        Select-Object -First 1
    if ($vc) { $link = $vc }
}
# Fallback: a link.exe on PATH, but only if it lives under an MSVC dir.
if (-not $link) {
    $cand = (Get-Command link.exe -ErrorAction SilentlyContinue).Source
    if ($cand -and ($cand -match "MSVC|Microsoft Visual Studio")) { $link = $cand }
}

if (-not $mc)   { throw "mc.exe not found under $kitBin. Install the Windows SDK." }
if (-not $rc)   { throw "rc.exe not found under $kitBin. Install the Windows SDK." }
if (-not $link) { throw "link.exe not found. Run from a VS Developer prompt or install VC Build Tools." }

Write-Host "mc:   $mc"
Write-Host "rc:   $rc"
Write-Host "link: $link"

# --- compile ---
Write-Host "==> mc -um aten.man"
& $mc -um aten.man

Write-Host "==> rc aten.rc"
& $rc /nologo /fo aten.res aten.rc

Write-Host "==> link aten_events.dll"
& $link /DLL /NOENTRY /NOLOGO "/MACHINE:$($Arch.ToUpper())" /OUT:aten_events.dll aten.res

if (-not (Test-Path aten_events.dll)) { throw "link did not produce aten_events.dll" }
Write-Host ""
$dll = Resolve-Path aten_events.dll
Write-Host "Built: $dll"
Write-Host "Register (admin):  wevtutil im aten.man /rf:`"$dll`" /mf:`"$dll`""
