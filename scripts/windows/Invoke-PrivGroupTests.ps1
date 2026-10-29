# Invoke-PrivGroupTests.ps1
# Live test cases for the privileged-group rules (100500-100505). Run on DC01 as FTOU7\Administrator.
# Every change is reverted within seconds. Steps 9-10 run as SYSTEM through a one-shot scheduled task,
# so the change is logged under the DC's machine account (DC01$), which is not an approved admin.
# Prints a start timestamp (UTC) to pass to scripts/wazuh/check_test_alerts.py.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

"start_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss'))"

$asAdmin = @(
    @('Add',    'Backup Operators', 'omar.chaabane'),
    @('Remove', 'Backup Operators', 'omar.chaabane'),
    @('Add',    'Domain Admins',    'sami.dridi'),
    @('Remove', 'Domain Admins',    'sami.dridi'),
    @('Add',    'DnsAdmins',        'omar.chaabane'),
    @('Remove', 'DnsAdmins',        'omar.chaabane'),
    @('Add',    'GG-Sales',         'omar.chaabane'),
    @('Remove', 'GG-Sales',         'omar.chaabane')
)
$n = 0
foreach ($s in $asAdmin) {
    $n++
    if ($s[0] -eq 'Add') { Add-ADGroupMember -Identity $s[1] -Members $s[2] }
    else { Remove-ADGroupMember -Identity $s[1] -Members $s[2] -Confirm:$false }
    '{0,2}. {1} Administrator {2,-6} {3} -> {4}' -f $n, (Get-Date -Format HH:mm:ss), $s[0], $s[2], $s[1]
    Start-Sleep -Seconds 3
}

# Steps 9-10 as SYSTEM
$cmd = "Import-Module ActiveDirectory; Add-ADGroupMember -Identity 'Backup Operators' -Members omar.chaabane; " +
       "Start-Sleep 3; Remove-ADGroupMember -Identity 'Backup Operators' -Members omar.chaabane -Confirm:`$false"
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command `"$cmd`""
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'LabPrivGroupTest' -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'LabPrivGroupTest'
do { Start-Sleep -Seconds 2 } while ((Get-ScheduledTask -TaskName 'LabPrivGroupTest').State -eq 'Running')
$result = (Get-ScheduledTaskInfo -TaskName 'LabPrivGroupTest').LastTaskResult
Unregister-ScheduledTask -TaskName 'LabPrivGroupTest' -Confirm:$false
' 9-10. {0} SYSTEM (DC01$) Add+Remove omar.chaabane -> Backup Operators (task result {1})' -f (Get-Date -Format HH:mm:ss), $result

# Nothing may be left behind
$left = foreach ($g in 'Backup Operators', 'Domain Admins', 'DnsAdmins', 'GG-Sales') {
    Get-ADGroupMember $g | Where-Object SamAccountName -in 'omar.chaabane', 'sami.dridi' | ForEach-Object { "$($_.SamAccountName) in $g" }
}
if ($left) { "WARNING leftover membership: $($left -join '; ')" } else { 'cleanup verified: no test memberships left' }
