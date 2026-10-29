# Join-Workstation.ps1
# Joins a lab workstation to ftou7.internal with offline domain join (djoin), run from the host:
#   1. DC01 pre-creates the computer account and writes a provisioning blob
#   2. the blob is copied DC01 -> host -> workstation over SSH
#   3. the workstation points DNS at DC01, consumes the blob and reboots under its new name
# Nobody types domain credentials on the workstation. The blob holds the new machine
# account's secret, so it is deleted from all three machines afterwards.

param(
    [string] $MachineName  = 'WS01',
    [string] $Workstation  = '192.168.145.130',
    [string] $WsUser       = 'fathia',
    [string] $DC           = '192.168.145.10',
    [string] $DcUser       = 'Administrator',
    [string] $Domain       = 'ftou7.internal',
    [string] $MachineOU    = 'OU=Workstations,OU=FTOU7,DC=ftou7,DC=internal'
)
$ErrorActionPreference = 'Stop'

$key     = Join-Path $env:USERPROFILE '.ssh\ftou7_lab'
$invoke  = Join-Path $PSScriptRoot 'Invoke-LabCommand.ps1'
$blobDc  = "C:/LabMedia/$MachineName.odj"
$blobWs  = "C:/Windows/Temp/$MachineName.odj"
$blobLocal = Join-Path $env:TEMP "$MachineName.odj"

Write-Host "[1/4] Provisioning $MachineName on DC01"
& $invoke -ComputerName $DC -User $DcUser -Command @"
djoin /provision /domain $Domain /machine $MachineName /machineou "$MachineOU" /savefile $($blobDc.Replace('/','\')) /reuse
if (`$LASTEXITCODE -ne 0) { throw "djoin /provision failed (`$LASTEXITCODE)" }
"@
if ($LASTEXITCODE -ne 0) { throw 'Provisioning failed.' }

Write-Host '[2/4] Copying the blob DC01 -> host -> workstation'
try {
    scp -i $key -o BatchMode=yes -q "${DcUser}@${DC}:$blobDc" $blobLocal
    if ($LASTEXITCODE -ne 0) { throw 'Copying the blob from DC01 failed.' }
    scp -i $key -o BatchMode=yes -q $blobLocal "${WsUser}@${Workstation}:$blobWs"
    if ($LASTEXITCODE -ne 0) { throw 'Copying the blob to the workstation failed.' }
} finally {
    Remove-Item $blobLocal -Force -ErrorAction SilentlyContinue
}

Write-Host "[3/4] Joining the workstation and rebooting it as $MachineName"
& $invoke -ComputerName $Workstation -User $WsUser -Command @"
`$nic = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex `$nic.ifIndex -ServerAddresses $DC
Clear-DnsClientCache
if (-not (Resolve-DnsName $Domain -ErrorAction SilentlyContinue)) { throw 'Cannot resolve the domain through DC01' }
djoin /requestODJ /loadfile $($blobWs.Replace('/','\')) /windowspath `$env:SystemRoot /localos
`$rc = `$LASTEXITCODE
Remove-Item $($blobWs.Replace('/','\')) -Force
if (`$rc -ne 0) { throw "djoin /requestODJ failed (`$rc)" }
# A reboot started from inside the SSH session does not happen, so a one-shot SYSTEM task does it
`$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -Command "Start-Sleep 5; Unregister-ScheduledTask -TaskName LabJoinReboot -Confirm:`$false; Restart-Computer -Force"'
`$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'LabJoinReboot' -Action `$action -Principal `$principal -Force | Out-Null
Start-ScheduledTask -TaskName 'LabJoinReboot'
'Join staged; rebooting in ~5 s.'
"@
if ($LASTEXITCODE -ne 0) { throw 'Workstation join failed.' }

Write-Host '[4/4] Removing the blob from DC01'
& $invoke -ComputerName $DC -User $DcUser -Command "Remove-Item $($blobDc.Replace('/','\')) -Force; 'blob removed'"
