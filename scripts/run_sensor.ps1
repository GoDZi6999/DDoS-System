<#
.SYNOPSIS
  Run a ArgusAI capture sensor on this Windows machine.

.DESCRIPTION
  Captures this machine's traffic (read-only, via Npcap) and ships flow
  statistics to the stack started with docker-compose.sensor.yml. Creates a
  virtual environment with the sensor's two dependencies on first use and
  reads SENSOR_REDIS_PASSWORD from .env unless SENSOR_REDIS_URL is set.
  Run from an administrator PowerShell; Npcap must be installed.

.EXAMPLE
  .\scripts\run_sensor.ps1 -ListInterfaces
  .\scripts\run_sensor.ps1 -Interface "Wi-Fi" -Name my-laptop
#>
param(
    [string]$Interface,
    [string]$Name = $env:COMPUTERNAME,
    [string]$Filter,
    [string]$StackHost = "localhost",
    [int]$Port = 6379,
    [switch]$ListInterfaces
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $root ".sensor-venv"
$python = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll")) {
    throw "Npcap is not installed. Get it from https://npcap.com (Wireshark installs it too)."
}

if (-not (Test-Path $python)) {
    Write-Host "Creating $venv ..."
    python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "Could not create the virtual environment (is Python 3.11+ installed?)" }
    & $python -m pip install --disable-pip-version-check -q -r (Join-Path $root "engine\requirements-sensor.txt")
    if ($LASTEXITCODE -ne 0) { throw "Could not install the sensor's dependencies" }
}

$env:PYTHONPATH = Join-Path $root "engine"

if ($ListInterfaces) {
    & $python -m sentinel_engine.sensor --list-interfaces
    exit $LASTEXITCODE
}

if (-not $env:SENSOR_REDIS_URL) {
    $envFile = Join-Path $root ".env"
    $password = $null
    if (Test-Path $envFile) {
        $line = Get-Content $envFile | Where-Object { $_ -match '^\s*SENSOR_REDIS_PASSWORD\s*=' } | Select-Object -Last 1
        if ($line) { $password = ($line -split '=', 2)[1].Trim().Trim('"').Trim("'") }
    }
    if (-not $password) {
        throw "Set SENSOR_REDIS_PASSWORD in .env (see .env.example) or set SENSOR_REDIS_URL."
    }
    $env:SENSOR_REDIS_URL = "redis://sensor:${password}@${StackHost}:${Port}/0"
}

# Python logs to stderr; with "Stop", PowerShell would treat that as an error.
$ErrorActionPreference = "Continue"
$arguments = @("-m", "sentinel_engine.sensor", "--name", $Name)
if ($Interface) { $arguments += @("--interface", $Interface) }
if ($Filter) { $arguments += @("--filter", $Filter) }
& $python @arguments
exit $LASTEXITCODE
