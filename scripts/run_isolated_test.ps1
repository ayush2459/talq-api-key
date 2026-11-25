# Start isolated, loopback-only TALQ onboarding test services.
# This script overrides DATABASE_URL only for the two child processes.
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Project virtual environment not found at $Python. Create/activate .venv and install requirements first."
}

Push-Location $ProjectRoot
try {
    $env:APP_ENV = "testing"
    $env:DEMO_MODE = "true"
    $env:DATABASE_URL = "sqlite:///./flowsense_talq_test.db"

    # Both processes inherit the isolated SQLite DATABASE_URL.
    # Bind to loopback: these test endpoints are not exposed to the LAN.
    $admin = Start-Process -FilePath $Python -WorkingDirectory $ProjectRoot -PassThru -ArgumentList @(
        "-m", "uvicorn", "app.admin_app:admin_app",
        "--host", "127.0.0.1", "--port", "8011"
    )

    $partner = Start-Process -FilePath $Python -WorkingDirectory $ProjectRoot -PassThru -ArgumentList @(
        "-m", "uvicorn", "app.partner_app:partner_app",
        "--host", "127.0.0.1", "--port", "8017"
    )

    Start-Sleep -Seconds 2

    if ($admin.HasExited -or $partner.HasExited) {
        throw "A test service exited during startup. Check the opened process windows for its error."
    }

    Write-Host ""
    Write-Host "Isolated test services started." -ForegroundColor Green
    Write-Host "Test database: $ProjectRoot\flowsense_talq_test.db"
    Write-Host "Admin docs:    http://127.0.0.1:8011/docs"
    Write-Host "Partner API:   http://127.0.0.1:8017/v1/ping"
    Write-Host "Admin PID:     $($admin.Id)"
    Write-Host "Partner PID:   $($partner.Id)"
    Write-Host ""
    Write-Host "These test services bind to 127.0.0.1 only; they are not LAN-accessible."
    Write-Host "Close their console windows to stop them."
}
finally {
    Pop-Location
}
