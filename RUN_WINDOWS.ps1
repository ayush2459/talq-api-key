$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.\.venv\Scripts\python.exe')) {
    py -3.11 -m venv .venv
}
if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
    Write-Host 'Created .env. Set ADMIN_API_KEY and DATABASE_URL, then rerun.' -ForegroundColor Yellow
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
    throw 'Set a unique ADMIN_API_KEY in the server-only .env before starting.'
}
& '.\.venv\Scripts\python.exe' -m pip install -r requirements.txt

# Start the complete control plane only on loopback. Its Swagger UI is local.
$python = (Resolve-Path '.\.venv\Scripts\python.exe').Path
$adminArgs = '-m uvicorn app.main:app --host 127.0.0.1 --port 8001'
Start-Process -FilePath $python -ArgumentList $adminArgs -WorkingDirectory (Get-Location).Path
Write-Host 'Admin control plane: http://127.0.0.1:8001/docs' -ForegroundColor Yellow

# Partner listener is separate and exposes only the allowlisted Partner API.
if (-not $env:FLOWSENSE_LAN_HOST) {
    $env:FLOWSENSE_LAN_HOST = '192.168.1.10'
}
Write-Host "Partner API listener: http://$($env:FLOWSENSE_LAN_HOST):8000" -ForegroundColor Green
Write-Host 'Restrict TCP 8000 to approved partner IPs. Add private-LAN TLS before production.' -ForegroundColor Yellow
& $python -m uvicorn app.partner_app:partner_app --host $env:FLOWSENSE_LAN_HOST --port 8000
