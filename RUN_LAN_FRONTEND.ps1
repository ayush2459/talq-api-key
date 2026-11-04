$ErrorActionPreference = 'Stop'

$python = Get-Command py -ErrorAction SilentlyContinue
if (-not $python) {
    throw 'Python launcher (py) was not found. Install Python 3.11 or add it to PATH.'
}

Write-Host ''
Write-Host 'FlowSense LAN dashboard frontend' -ForegroundColor Cyan
Write-Host 'This server listens on all network interfaces at port 5500.' -ForegroundColor Gray
Write-Host 'Open locally: http://127.0.0.1:5500/' -ForegroundColor Green

$addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -notlike '127.*' -and
        $_.IPAddress -notlike '169.254.*' -and
        $_.AddressState -eq 'Preferred'
    } |
    Select-Object -ExpandProperty IPAddress -Unique

foreach ($address in $addresses) {
    Write-Host "Open from another device: http://$($address):5500/" -ForegroundColor Green
}

Write-Host ''
Write-Host 'Keep the backend running in a separate PowerShell window using .\RUN_WINDOWS.ps1.' -ForegroundColor Yellow
Write-Host 'Allow Python on Private networks only if Windows Firewall prompts you.' -ForegroundColor Yellow
Write-Host 'Press Ctrl+C to stop this frontend server.' -ForegroundColor Gray
Write-Host ''

py -m http.server 5500 --bind 0.0.0.0 --directory frontend
