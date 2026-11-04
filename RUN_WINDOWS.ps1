$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.\.venv\Scripts\python.exe')) {
    py -3.11 -m venv .venv
}

if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
    Write-Host 'Created .env from .env.example. Edit .env and set ADMIN_API_KEY, then run this script again.' -ForegroundColor Yellow
    exit 1
}

Get-Content '.env' | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
        $parts = $line.Split('=', 2)
        [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), 'Process')
    }
}

if (-not $env:ADMIN_API_KEY -or $env:ADMIN_API_KEY -eq 'replace-with-a-long-random-admin-secret') {
    throw 'Set a unique ADMIN_API_KEY in .env before starting the service.'
}

& '.\.venv\Scripts\python.exe' -m pip install -r requirements.txt
Write-Host 'Starting backend on all network interfaces (LAN access enabled) at port 8000.' -ForegroundColor Cyan
Write-Host 'Use http://<THIS-PC-LAN-IP>:8000/docs from another device on the same trusted network.' -ForegroundColor Cyan
& '.\.venv\Scripts\python.exe' -m uvicorn app.integrated_main:app --host 0.0.0.0 --port 8000
