# Initialize-DC01.ps1
# Runs on the fresh Windows Server VM over SSH (as Administrator):
#   .\scripts\host\Invoke-LabCommand.ps1 -ComputerName <dhcp-ip> -User Administrator -ScriptPath .\scripts\windows\Initialize-DC01.ps1
# Sets the time zone, renames the server to DC01 and moves it to its static lab IP.
# The IP change and reboot run from a one-shot SYSTEM task so they survive the SSH session dropping.

$ErrorActionPreference = 'Stop'

$NewName   = 'DC01'
$IPAddress = '192.168.145.10'
$Prefix    = 24
$Gateway   = '192.168.145.2'   # VMware NAT gateway, also its DNS proxy until AD DNS exists

Set-TimeZone -Id 'W. Central Africa Standard Time'   # Tunisia: UTC+1, no DST

if ($env:COMPUTERNAME -ne $NewName) {
    Rename-Computer -NewName $NewName -Force -WarningAction SilentlyContinue
}

$nic = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
if (-not $nic) { throw 'No connected network adapter found.' }
$i = $nic.ifIndex

$stage = @"
Start-Sleep -Seconds 5
Set-NetIPInterface -InterfaceIndex $i -Dhcp Disabled
Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:`$false
Remove-NetRoute -InterfaceIndex $i -DestinationPrefix 0.0.0.0/0 -Confirm:`$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceIndex $i -IPAddress $IPAddress -PrefixLength $Prefix -DefaultGateway $Gateway | Out-Null
Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses $Gateway
Unregister-ScheduledTask -TaskName 'LabStaticIP' -Confirm:`$false
Remove-Item -LiteralPath `$PSCommandPath -Force
Restart-Computer -Force
"@
# Random file name: a predictable name in a folder where users can create files could be pre-created
# by a user, who would then keep control of a script that SYSTEM runs
$stagePath = Join-Path $env:SystemRoot ("Temp\lab-static-ip-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
Set-Content -Path $stagePath -Value $stage -Encoding ascii

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$stagePath`""
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'LabStaticIP' -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'LabStaticIP'

Write-Host "Renamed to $NewName (pending reboot). Switching to $IPAddress/$Prefix and rebooting in ~5 s."
