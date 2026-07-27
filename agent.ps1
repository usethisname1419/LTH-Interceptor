#Requires -Version 5.1
<#
.SYNOPSIS
  LTH-Interceptor - Windows GPU brain + Kali SSH tools

.EXAMPLE
  .\agent.ps1
  .\agent.ps1 -Model 1
  .\agent.ps1 -Model 2 -VerboseOutput
  .\agent.ps1 -Resume
  .\agent.ps1 "one-shot task"
  .\agent.ps1 -TestSsh
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Task,

    [switch]$Interactive,
    [string]$Config = "",
    [switch]$Setup,
    [switch]$TestSsh,
    [switch]$PullModel,
    [switch]$Resume,
    [switch]$VerboseOutput,
    [ValidateSet(1, 2)]
    [int]$Model = 0,
    [switch]$SkipChecks
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Get-OllamaExe {
    $candidates = @(
        (Get-Command ollama -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe",
        "$env:ProgramFiles\Ollama\ollama.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }

    if ($candidates) {
        return $candidates[0]
    }
    return $null
}

function Ensure-Venv {
    $venvPython = Join-Path $Root ".venv\Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        Write-Host "Creating .venv ..." -ForegroundColor Cyan
        py -3 -m venv .venv
    }
    & $venvPython -m pip install -q --upgrade pip
    & $venvPython -m pip install -q -r requirements.txt
    return $venvPython
}

function Install-OllamaIfNeeded {
    $exe = Get-OllamaExe
    if ($exe) {
        Write-Host "Ollama found: $exe" -ForegroundColor Green
        return $exe
    }

    Write-Host "Ollama not found. Downloading installer..." -ForegroundColor Yellow
    $installer = Join-Path $env:TEMP "OllamaSetup.exe"
    Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile $installer
    Write-Host "Launching Ollama installer (accept defaults, then re-run -Setup / -PullModel)..." -ForegroundColor Cyan
    Start-Process -FilePath $installer -Wait

    $exe = Get-OllamaExe
    if (-not $exe) {
        throw "Ollama still not found after install. Open a new PowerShell and re-run .\agent.ps1 -Setup"
    }
    return $exe
}

function Pull-Model {
    param([string]$Model = "qwen2.5-coder:32b")
    $exe = Install-OllamaIfNeeded
    Write-Host "Pulling model $Model (uses GPU + RAM offload)..." -ForegroundColor Cyan
    & $exe pull $Model
    if ($LASTEXITCODE -ne 0) { throw "ollama pull failed" }
    Write-Host "Model ready." -ForegroundColor Green
}

if ($Setup -or $PullModel) {
    $null = Ensure-Venv
    Pull-Model -Model "qwen2.5-coder:32b"

    $proxiesPath = Join-Path $Root "proxies.txt"
    if (-not (Test-Path $proxiesPath)) {
        Copy-Item (Join-Path $Root "proxies.example.txt") $proxiesPath
        Write-Host "Created proxies.txt - add your SOCKS5 lines." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Next:" -ForegroundColor Cyan
    Write-Host "  1. Edit config.yaml  (scope.domains + ssh.password)"
    Write-Host "  2. Keep Kali running with SSH on port 22"
    Write-Host "  3. .\agent.ps1 -TestSsh"
    Write-Host "  4. .\agent.ps1"

    if ($Setup -and (-not $Task -or $Task.Count -eq 0)) {
        exit 0
    }
}

$python = Ensure-Venv

if ($TestSsh) {
    $testArgs = @("-m", "agent", "--test-ssh")
    if ($Config) {
        $testArgs += @("--config", $Config)
    }
    & $python @testArgs
    exit $LASTEXITCODE
}

$argList = @("-m", "agent")
if ($Config) {
    $argList += @("--config", $Config)
}
if ($Model -eq 1 -or $Model -eq 2) {
    $argList += @("--model-slot", "$Model")
}
if ($Resume) {
    $argList += "--resume"
}
if ($VerboseOutput) {
    $argList += "--verbose"
}
if ($SkipChecks) {
    $argList += "--skip-checks"
}

$startInteractive = $false
if ($Interactive -or $Resume) {
    $startInteractive = $true
}
if (-not $Task -or $Task.Count -eq 0) {
    $startInteractive = $true
}

if ($startInteractive) {
    if (-not $Resume) {
        $argList += "--interactive"
    }
}
else {
    $argList += $Task
}

& $python @argList
exit $LASTEXITCODE
