#Requires -Version 5.1
<#
.SYNOPSIS
  Launch LTH-Interceptor web UI on http://127.0.0.1:8787

.EXAMPLE
  .\ui.ps1
  .\ui.ps1 -Model 1
  .\ui.ps1 -NoBrowser
#>
param(
    [switch]$NoBrowser,
    [ValidateSet(1, 2)]
    [int]$Model = 0,
    [int]$Port = 8787
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Stop-PortListeners {
    param([int]$Port)
    $conns = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq "Listen" }
    $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($procId in $pids) {
        if (-not $procId) { continue }
        try {
            $p = Get-Process -Id $procId -ErrorAction Stop
            Write-Host "Stopping old process on :$Port (PID $procId / $($p.ProcessName))" -ForegroundColor Yellow
            Stop-Process -Id $procId -Force -ErrorAction Stop
        } catch {
            Write-Host ("Could not stop PID {0}: {1}" -f $procId, $_) -ForegroundColor DarkYellow
        }
    }
    if ($pids) {
        Start-Sleep -Seconds 1
    }
}

$python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    py -3 -m venv .venv
}
& $python -m pip install -q -r requirements.txt

if ($Model -eq 1 -or $Model -eq 2) {
    $env:LTH_MODEL_SLOT = "$Model"
    Write-Host "Model slot $Model (via LTH_MODEL_SLOT)" -ForegroundColor Cyan
}

Stop-PortListeners -Port $Port

Write-Host "LTH-Interceptor UI -> http://127.0.0.1:$Port" -ForegroundColor Cyan
Write-Host "Startup will check SSH, proxies, and Kali curl..." -ForegroundColor DarkGray
if (-not $NoBrowser) {
    Start-Process "http://127.0.0.1:$Port"
}

# Exit code 42 = config Apply & Restart requested from the UI
do {
    & $python -m uvicorn server.app:app --host 127.0.0.1 --port $Port
    $code = $LASTEXITCODE
    if ($code -eq 42) {
        Write-Host "Restarting with updated config..." -ForegroundColor Cyan
        Stop-PortListeners -Port $Port
        Start-Sleep -Seconds 1
    }
} while ($code -eq 42)

exit $code
