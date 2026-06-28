<#
.SYNOPSIS
Installs the latest ATEN Windows release by default.

.DESCRIPTION
Downloads or copies aten.exe, seeds %ProgramData%\aten\config.toml when needed,
then delegates service registration to `aten.exe install`.

.EXAMPLE
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Antonlovesdnb/aten/main/install/install-windows.ps1 | iex"

Installs the latest GitHub release from an elevated PowerShell.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\install\install-windows.ps1 -Version v0.1.0

Pins the install to a specific GitHub release tag.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\install\install-windows.ps1 -LocalBinary .\target\release\aten.exe

Installs a locally built binary.
#>
[CmdletBinding()]
param(
    [string]$Repo = $env:ATEN_REPO,
    [string]$Version = $env:ATEN_VERSION,
    [string]$Asset = $env:ATEN_ASSET,
    [string]$Url = $env:ATEN_URL,
    [string]$LocalArchive = $env:ATEN_LOCAL_ARCHIVE,
    [string]$LocalBinary = $env:ATEN_LOCAL_BINARY,
    [string]$InstallDir = $env:ATEN_INSTALL_DIR,
    [string[]]$Agents,
    [string[]]$WatchDir,
    [string]$Sink = $env:ATEN_SINK,
    [string]$EventsPath = $env:ATEN_EVENTS_PATH,
    [string]$ConfigPath = $env:ATEN_CONFIG_PATH,
    [switch]$ForceConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Repo)) { $Repo = "Antonlovesdnb/aten" }
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = "latest" }
if ([string]::IsNullOrWhiteSpace($Asset)) { $Asset = "aten-windows-x86_64.zip" }
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = Join-Path $env:ProgramFiles "ATEN" }
if (-not $Agents -or $Agents.Count -eq 0) { $Agents = @("claude.exe", "codex.exe") }
if ([string]::IsNullOrWhiteSpace($Sink)) { $Sink = "both" }

$ProgramDataRoot = Join-Path $env:ProgramData "aten"
if ([string]::IsNullOrWhiteSpace($EventsPath)) {
    $EventsPath = Join-Path $ProgramDataRoot "events.jsonl"
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $ProgramDataRoot "config.toml"
}
if (-not $WatchDir -or $WatchDir.Count -eq 0) {
    $WatchDir = @(
        (Join-Path $env:USERPROFILE ".claude\projects"),
        (Join-Path $env:USERPROFILE ".codex\sessions")
    )
}

function Write-Step {
    param([string]$Message)
    Write-Host "[aten install] $Message"
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-TomlString {
    param([string]$Value)
    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

function ConvertTo-TomlArray {
    param([string[]]$Values)
    $items = foreach ($Value in $Values) {
        if (-not [string]::IsNullOrWhiteSpace($Value)) {
            ConvertTo-TomlString $Value
        }
    }
    return "[" + ($items -join ", ") + "]"
}

function Get-DownloadUrl {
    if (-not [string]::IsNullOrWhiteSpace($Url)) {
        return $Url
    }
    if ($Version -eq "latest") {
        return "https://github.com/$Repo/releases/latest/download/$Asset"
    }
    return "https://github.com/$Repo/releases/download/$Version/$Asset"
}

function Get-DownloadName {
    if (-not [string]::IsNullOrWhiteSpace($Url)) {
        $WithoutQuery = ($Url -split '\?')[0]
        $Name = [System.IO.Path]::GetFileName($WithoutQuery)
        if (-not [string]::IsNullOrWhiteSpace($Name)) {
            return $Name
        }
    }
    return $Asset
}

function Find-File {
    param(
        [string]$Root,
        [string]$Name
    )
    return Get-ChildItem -Path $Root -Recurse -File -Filter $Name -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

if (-not (Test-Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

New-Item -ItemType Directory -Force -Path $InstallDir, $ProgramDataRoot | Out-Null

$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("aten-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null

try {
    $AtenExe = Join-Path $InstallDir "aten.exe"

    if (-not [string]::IsNullOrWhiteSpace($LocalBinary)) {
        if (-not (Test-Path -LiteralPath $LocalBinary)) {
            throw "--LocalBinary not found: $LocalBinary"
        }
        Copy-Item -LiteralPath $LocalBinary -Destination $AtenExe -Force

        $SiblingDll = Join-Path (Split-Path -Parent $LocalBinary) "aten_events.dll"
        if (Test-Path -LiteralPath $SiblingDll) {
            Copy-Item -LiteralPath $SiblingDll -Destination (Join-Path $InstallDir "aten_events.dll") -Force
        }
    } else {
        $ArchivePath = $LocalArchive
        if ([string]::IsNullOrWhiteSpace($ArchivePath)) {
            $DownloadUrl = Get-DownloadUrl
            $ArchivePath = Join-Path $TempRoot (Get-DownloadName)
            Write-Step "downloading $DownloadUrl"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $ArchivePath
        }
        if (-not (Test-Path -LiteralPath $ArchivePath)) {
            throw "archive not found: $ArchivePath"
        }

        if ($ArchivePath.EndsWith(".zip", [StringComparison]::OrdinalIgnoreCase)) {
            $ExtractRoot = Join-Path $TempRoot "extract"
            Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExtractRoot -Force
            $FoundExe = Find-File -Root $ExtractRoot -Name "aten.exe"
            if (-not $FoundExe) {
                throw "archive did not contain aten.exe"
            }
            Copy-Item -LiteralPath $FoundExe.FullName -Destination $AtenExe -Force

            $FoundDll = Find-File -Root $ExtractRoot -Name "aten_events.dll"
            if ($FoundDll) {
                Copy-Item -LiteralPath $FoundDll.FullName -Destination (Join-Path $InstallDir "aten_events.dll") -Force
            } else {
                Write-Step "aten_events.dll not found in archive; Event Log registration may be skipped"
            }
        } else {
            Copy-Item -LiteralPath $ArchivePath -Destination $AtenExe -Force
        }
    }

    Write-Step "installed binary to $AtenExe"

    $ConfigDir = Split-Path -Parent $ConfigPath
    $EventsDir = Split-Path -Parent $EventsPath
    New-Item -ItemType Directory -Force -Path $ConfigDir, $EventsDir | Out-Null

    if ($ForceConfig -or -not (Test-Path -LiteralPath $ConfigPath)) {
        $AgentArray = ConvertTo-TomlArray $Agents
        $WatchArray = ConvertTo-TomlArray $WatchDir
        $EscapedEvents = ConvertTo-TomlString $EventsPath
        $Config = @"
# ATEN service config. Edit and restart the service:
#   sc stop atensvc
#   sc start atensvc

[daemon]
agents = $AgentArray

[transcripts]
# Recursively scanned for *.jsonl. Dialect (Claude / Codex) auto-detected per file.
watch_dirs = $WatchArray

[output]
# sink: jsonl | eventlog | both. 'both' writes ATEN/Operational and a JSONL backup.
sink = $(ConvertTo-TomlString $Sink)
file_path = $EscapedEvents
"@
        Set-Content -LiteralPath $ConfigPath -Value $Config -Encoding UTF8
        Write-Step "wrote config to $ConfigPath"
    } else {
        Write-Step "preserved existing config $ConfigPath"
    }

    & $AtenExe install
    if ($LASTEXITCODE -ne 0) {
        throw "aten install failed with exit code $LASTEXITCODE"
    }

    Write-Step "service status"
    Get-Service -Name atensvc -ErrorAction SilentlyContinue | Format-List Name,Status,StartType,ServiceName

    Write-Host ""
    Write-Host "ATEN Windows install complete."
    Write-Host ""
    Write-Host "Useful commands:"
    Write-Host "  Get-Service atensvc"
    Write-Host "  Get-Content `"$ProgramDataRoot\service.log`" -Tail 40"
    Write-Host "  Get-Content `"$EventsPath`" -Wait"
    Write-Host "  Get-WinEvent -LogName `"ATEN/Operational`" -MaxEvents 20"
    Write-Host "  & `"$AtenExe`" uninstall"
} finally {
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
