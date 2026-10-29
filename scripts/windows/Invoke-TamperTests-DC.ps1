# Invoke-TamperTests-DC.ps1
# Live test cases for the DC tampering rules (100510, 100514, 100516). Run on DC01 as FTOU7\Administrator.
# Every change is reverted immediately.

$ErrorActionPreference = 'Stop'
function Step($msg) { '{0} {1}' -f (Get-Date -Format HH:mm:ss), $msg }

# 1. Audit policy changed by a user account -> 100510, then restored
auditpol /set /subcategory:"Logoff" /success:disable | Out-Null
auditpol /set /subcategory:"Logoff" /success:enable  | Out-Null
Step 'auditpol: Logoff success disabled and re-enabled by Administrator'

# 2. Same change under the computer account (SYSTEM) -> default 60112 only
$cmd = 'auditpol /set /subcategory:"Logoff" /success:disable; auditpol /set /subcategory:"Logoff" /success:enable'
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command `"$cmd`""
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'LabAuditpolAsSystem' -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'LabAuditpolAsSystem'
do { Start-Sleep -Seconds 2 } while ((Get-ScheduledTask -TaskName 'LabAuditpolAsSystem').State -eq 'Running')
Unregister-ScheduledTask -TaskName 'LabAuditpolAsSystem' -Confirm:$false
Step 'auditpol: same change as SYSTEM (DC01$)'

# 3. Harmless service installed and deleted -> 100514
New-Service -Name 'LabTestSvc' -BinaryPathName 'C:\Windows\System32\cmd.exe /c exit' -StartupType Manual -DisplayName 'Lab detection test service' | Out-Null
sc.exe delete LabTestSvc | Out-Null
Step 'service LabTestSvc installed and deleted'

# 4. Harmless scheduled task registered and removed -> 100516
Register-ScheduledTask -TaskName 'LabTestTask' -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit') -Force | Out-Null
Unregister-ScheduledTask -TaskName 'LabTestTask' -Confirm:$false
Step 'scheduled task LabTestTask registered and removed'

$left = @()
if (Get-Service LabTestSvc -ErrorAction SilentlyContinue) { $left += 'LabTestSvc' }
if (Get-ScheduledTask -TaskName 'Lab*' -ErrorAction SilentlyContinue) { $left += 'Lab* task' }
$logoff = (auditpol /get /subcategory:"Logoff" /r | ConvertFrom-Csv).'Inclusion Setting'
if ($left) { "WARNING leftovers: $($left -join ', ')" } else { "cleanup verified (Logoff auditing: $logoff)" }
