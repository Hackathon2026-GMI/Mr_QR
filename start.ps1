# Mr QR - Local Startup Script
# Starts the GMI worker, the Rocketride HTTP bridge, and opens the web UI.
# Usage: .\start.ps1

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
$ENV_FILE = Join-Path $ROOT ".env"

# Load .env
if (-not (Test-Path $ENV_FILE)) {
    Write-Error ".env file not found. Copy .env.example to .env and fill in your keys."
    exit 1
}
foreach ($line in Get-Content $ENV_FILE) {
    if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
    $parts = $line -split '=', 2
    [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python not found. Install Python 3.11+ and try again."
    exit 1
}

Write-Host ""
Write-Host "-------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  Mr QR - Starting local stack" -ForegroundColor Cyan
Write-Host "-------------------------------------------------------" -ForegroundColor Cyan

# 1. Start GMI Playwright worker on port 8001
Write-Host ""
Write-Host "[1/2] Starting GMI Playwright worker on port 8001..." -ForegroundColor Yellow
$worker = Start-Process python `
    -ArgumentList "-m uvicorn backend.gmi_worker:app --host 0.0.0.0 --port 8001" `
    -WorkingDirectory $ROOT `
    -PassThru `
    -WindowStyle Minimized

Start-Sleep -Seconds 3
try {
    $h = Invoke-RestMethod -Uri "http://localhost:8001/health" -TimeoutSec 5
    Write-Host "     GMI worker: $($h.status) (PID $($worker.Id))" -ForegroundColor Green
} catch {
    Write-Host "     GMI worker starting up - check its window if issues occur." -ForegroundColor Yellow
}

# 2. Start Rocketride HTTP bridge on port 8000
Write-Host ""
Write-Host "[2/2] Starting Rocketride HTTP bridge on port 8000..." -ForegroundColor Yellow
Write-Host "      (This connects to Rocketride and loads the pipeline - may take 10-20s)" -ForegroundColor Gray
$bridge = Start-Process python `
    -ArgumentList "-u backend/bridge.py" `
    -WorkingDirectory $ROOT `
    -PassThru `
    -WindowStyle Normal

# Give bridge time to start the pipeline
Start-Sleep -Seconds 5

Start-Sleep -Seconds 12
try {
    $h2 = Invoke-RestMethod -Uri "http://localhost:8000/health" -TimeoutSec 8
    Write-Host "     Bridge: $($h2.status) (PID $($bridge.Id))" -ForegroundColor Green
} catch {
    Write-Host "     Bridge still starting - watch the bridge window for status." -ForegroundColor Yellow
}

# 3. Open the web UI
Write-Host ""
Write-Host "-------------------------------------------------------" -ForegroundColor Green
Write-Host "  Web UI: http://localhost:8000" -ForegroundColor Green
Write-Host "-------------------------------------------------------" -ForegroundColor Green
Write-Host ""
Write-Host "  To expose to phone via ngrok:" -ForegroundColor Yellow
Write-Host "    ngrok http 8000" -ForegroundColor Cyan
Write-Host ""

Start-Process "http://localhost:8000"

Write-Host "  Press Ctrl+C to stop all services." -ForegroundColor Gray
Write-Host ""

# Keep script alive
try {
    Wait-Process -Id $bridge.Id -ErrorAction SilentlyContinue
} catch {
    Write-Host "Bridge stopped." -ForegroundColor Red
}
