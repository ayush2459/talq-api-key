param(
    [Parameter(Mandatory = $true)]
    [string]$PartnerIPv4
)

$ErrorActionPreference = 'Stop'
if (-not [System.Net.IPAddress]::TryParse($PartnerIPv4, [ref]$null)) {
    throw 'PartnerIPv4 must be a valid IPv4 address.'
}

# Run from an elevated PowerShell session on the FlowSense gateway host.
# Keep the Windows Firewall default inbound policy set to Block.
$ruleName = 'FlowSense Partner API - Approved Partner Only'
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$rule = @{
    DisplayName = $ruleName
    Direction = 'Inbound'
    Action = 'Allow'
    Protocol = 'TCP'
    LocalPort = 8000
    RemoteAddress = $PartnerIPv4
    Profile = 'Private'
}
New-NetFirewallRule @rule

Write-Host "Added TCP 8000 allow rule for $PartnerIPv4." -ForegroundColor Green
Write-Host 'Review existing firewall rules for broader inbound allows to TCP 8000; Windows allow rules are additive.' -ForegroundColor Yellow
Write-Host 'Keep the admin service bound to 127.0.0.1:8001. Do not expose it through port forwarding.' -ForegroundColor Yellow
