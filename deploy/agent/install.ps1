<#
.SYNOPSIS
  Installs (or upgrades) the DG SIEM agent on Windows as the "dg-siem-agent" service.

.DESCRIPTION
  Run from the unpacked agent package, as Administrator (or from an RMM as SYSTEM):

    .\install.ps1 -Server https://siem-agents.example.com:9443 -Token dgs1_... [-Name acme-dc01]

  Re-running upgrades the binary and keeps the enrollment, so -Server and -Token are only needed the
  first time. The service runs as LocalSystem, which can read the Security log.

  Files: C:\Program Files\DG SIEM Agent\dg-siem-agent.exe
         C:\ProgramData\DG SIEM\Agent  (key, certificate, config, buffer; SYSTEM and Administrators only)
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string]$Token,
    [string]$Name = $env:COMPUTERNAME.ToLowerInvariant(),
    [string]$Binary
)

$ErrorActionPreference = 'Stop'
if (-not $Binary) {
    # Not a param default: Windows PowerShell 5.1 leaves $PSScriptRoot empty there.
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $Binary = Join-Path $here 'dg-siem-agent.exe'
}
$service = 'dg-siem-agent'
$installDir = Join-Path $env:ProgramFiles 'DG SIEM Agent'
$dataDir = Join-Path $env:ProgramData 'DG SIEM\Agent'
$exe = Join-Path $installDir 'dg-siem-agent.exe'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as Administrator.'
}
if (-not (Test-Path $Binary)) {
    throw "Agent binary not found: $Binary"
}

# Stop the running agent so its binary can be replaced.
$existing = Get-Service -Name $service -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host "Stopping $service"
    Stop-Service -Name $service -Force
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -Force $Binary $exe

# Data folder: the private key lives here. Only SYSTEM and Administrators.
if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
}
& icacls.exe $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

if (-not (Test-Path (Join-Path $dataDir 'state.txt'))) {
    if (-not $Server -or -not $Token) {
        throw 'First install needs -Server and -Token (from Administration > Agents > Enroll agent).'
    }
    Write-Host "Enrolling '$Name' with $Server"
    & $exe enroll --server $Server --token $Token --name $Name --data-dir $dataDir
    if ($LASTEXITCODE -ne 0) {
        throw "Enrollment failed (exit code $LASTEXITCODE)."
    }
}

# Event Viewer shows the agent's own warnings as "The description for Event ID ... cannot be found" unless the
# source has a message file. .NET's generic one ("%1") ships with Windows.
$sourceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$service"
$messages = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll'
if (Test-Path $messages) {
    if (-not (Test-Path $sourceKey)) {
        New-Item -Path $sourceKey | Out-Null
    }
    Set-ItemProperty -Path $sourceKey -Name EventMessageFile -Value $messages
}

if (-not $existing) {
    Write-Host "Creating service $service"
    New-Service -Name $service -BinaryPathName "`"$exe`"" -DisplayName 'DG SIEM Agent' `
        -Description 'Collects Windows event logs and other inputs for DG SIEM.' -StartupType Automatic | Out-Null
    # Restart after a crash: 5s, 5s, then 30s; reset the count after a day.
    & sc.exe failure $service reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
    & sc.exe failureflag $service 1 | Out-Null
}

Start-Service -Name $service
$version = (Get-Item $exe).VersionInfo.ProductVersion
Write-Host "DG SIEM agent $version is running. Logs: Get-WinEvent -ProviderName dg-siem-agent -MaxEvents 20 (or Event Viewer > Application)."
