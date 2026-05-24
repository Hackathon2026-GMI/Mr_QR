# Mr QR — Local Startup Script
# Starts the GMI Playwright worker and prints next steps for Rocketride + ngrok.
# Usage: .\start.ps1

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
$ENV_FILE = Join-Path $ROOT ".env"

# ── Load .env ──────────────────────────────────────────────────────────────────
if (-not (Test-Path $ENV_FILE)) {
    Write-Error ".env file not found. Copy .env.example to .env and fill in your keys."
    exit 1
}
foreach ($line in Get-Content $ENV_FILE) {
    if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
    $parts = $line -split '=', 2
    [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
}

# ── Check dependencies ─────────────────────────────────────────────────────────
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python not found. Install Python 3.11+ and try again."
    exit 1
}

# ── Start GMI Playwright worker on port 8001 ──────────────────────────────────
Write-Host ""
Write-Host "Starting GMI Playwright worker on http://localhost:8001 ..." -ForegroundColor Cyan
$worker = Start-Process python `
    -ArgumentList "-m uvicorn backend.gmi_worker:app --host 0.0.0.0 --port 8001" `
    -WorkingDirectory $ROOT `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 3
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8001/health" -TimeoutSec 5
    Write-Host "  GMI worker: $($health.status) (PID $($worker.Id))" -ForegroundColor Green
} catch {
    Write-Host "  GMI worker starting up... check the worker window for errors." -ForegroundColor Yellow
}

# ── Print next steps ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host "  NEXT STEPS" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host ""
Write-Host "1. Start Rocketride and load:  pipelines\mr_qr_security.pipe" -ForegroundColor Yellow
Write-Host "   Set these env vars in Rocketride before activating:" -ForegroundColor Yellow
Write-Host "     VIRUSTOTAL_API_KEY  = $($env:VIRUSTOTAL_API_KEY.Substring(0,8))..." -ForegroundColor Gray
Write-Host "     ROCKETRIDE_GMI_API_KEY = (set)" -ForegroundColor Gray
Write-Host "     GMI_WORKER_URL      = http://localhost:8001" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Note the Rocketride webhook port, then expose it with ngrok:" -ForegroundColor Yellow
Write-Host "     ngrok http <rocketride-port>" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Give the ngrok HTTPS URL to the frontend team as the API endpoint." -ForegroundColor Yellow
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host "  GMI worker running — press Ctrl+C to stop" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White

# Keep the script alive so the user can see logs
try {
    Wait-Process -Id $worker.Id
} catch {
    Write-Host "GMI worker stopped." -ForegroundColor Red
}
