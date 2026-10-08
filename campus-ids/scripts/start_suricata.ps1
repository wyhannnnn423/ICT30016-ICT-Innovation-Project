<#
Starts Suricata on the network this PC is using right now, so the IP address never has to be typed.

Run it in an ADMINISTRATOR PowerShell, from the project root:
    .\scripts\start_suricata.ps1

Options:
    -ShowOnly                 only show which address would be used, do not start Suricata
    -Ip 192.168.1.20          use this address instead of the detected one
    -SuricataDir "D:\Suricata"   if Suricata is not in C:\Program Files\Suricata

Run it again (after stopping Suricata with Ctrl+C) whenever the PC joins another network.
#>
param(
    [string]$Ip,
    [string]$SuricataDir = "C:\Program Files\Suricata",
    [switch]$ShowOnly
)

# The IPv4 address of the adapter that carries the default route (the one used for the LAN / internet).
function Get-ActiveIPv4 {
    $best = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Sort-Object { $_.RouteMetric + $_.InterfaceMetric } |
        Select-Object -First 1
    if (-not $best) { return $null }
    $addr = Get-NetIPAddress -InterfaceIndex $best.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "169.254.*" } |
        Select-Object -First 1
    if ($addr) { return $addr.IPAddress }
    return $null
}

if (-not $Ip) { $Ip = Get-ActiveIPv4 }
if (-not $Ip) {
    Write-Host "Could not find an active network. Connect to Wi-Fi or Ethernet, or pass the address: -Ip 192.168.x.x" -ForegroundColor Red
    exit 1
}

Write-Host "Network address to monitor: $Ip" -ForegroundColor Green
if ($ShowOnly) { exit 0 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Please run this script in an Administrator PowerShell (Suricata needs it to capture packets)." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path (Join-Path $SuricataDir "suricata.exe"))) {
    Write-Host "suricata.exe not found in $SuricataDir. Use -SuricataDir to point to your Suricata folder." -ForegroundColor Red
    exit 1
}

Set-Location $SuricataDir
Write-Host "Starting Suricata. Press Ctrl+C to stop it." -ForegroundColor Cyan
& .\suricata.exe -c suricata.yaml -i $Ip
