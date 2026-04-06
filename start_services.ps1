# SwitchGuard Services Startup Script
Write-Host "--- SwitchGuard Service Orchestrator ---" -ForegroundColor Yellow

# 1. Start ZAP
Write-Host "[1/2] Starting OWASP ZAP..." -ForegroundColor Cyan
Set-Location -Path ".\backend"
.\start_zap.ps1

# 2. Wait a bit for ZAP to start opening its port
Start-Sleep -Seconds 3

# 3. Start Backend
Write-Host "[2/2] Starting FastAPI Backend..." -ForegroundColor Cyan
# Using Start-Process to run uvicorn in a new window or background
Start-Process "venv\Scripts\python.exe" -ArgumentList "-m", "uvicorn", "main:app", "--reload", "--host", "localhost", "--port", "8000" -NoNewWindow
Set-Location -Path ".."

Write-Host "--- All services initiated! ---" -ForegroundColor Green
Write-Host "Check backend/zap_stdout.log for ZAP status."
Write-Host "Backend is available at http://localhost:8000"
