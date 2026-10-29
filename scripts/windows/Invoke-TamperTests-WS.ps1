# Invoke-TamperTests-WS.ps1
# Live test cases for the log-clearing and service rules on a workstation (100512, 100513, 100515).
# Run on WS01 as a local administrator. Logs are backed up to C:\LabBackups before they are cleared,
# and every event was already forwarded to Wazuh, so nothing is lost.

$ErrorActionPreference = 'Stop'
function Step($msg) { '{0} {1}' -f (Get-Date -Format HH:mm:ss), $msg }
$backup = 'C:\LabBackups'
if (-not (Test-Path $backup)) {
    New-Item -ItemType Directory -Force -Path $backup | Out-Null
    # Security log backups must not be readable by ordinary users: Administrators and SYSTEM only
    icacls $backup /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /Q | Out-Null
}
$stamp = Get-Date -Format yyyyMMdd-HHmmss

# 5. Security log cleared (with backup) -> 1102 -> 100512
wevtutil cl Security /bu:"$backup\Security-$stamp.evtx"
Step "Security log cleared, backup $backup\Security-$stamp.evtx"

# 6. Another log cleared (with backup) -> 104 -> 100513
wevtutil cl "Windows PowerShell" /bu:"$backup\WindowsPowerShell-$stamp.evtx"
Step "Windows PowerShell log cleared, backup $backup\WindowsPowerShell-$stamp.evtx"

# 7. Harmless service on a workstation -> 100515 (lower level than on a DC)
New-Service -Name 'LabTestSvc' -BinaryPathName 'C:\Windows\System32\cmd.exe /c exit' -StartupType Manual -DisplayName 'Lab detection test service' | Out-Null
sc.exe delete LabTestSvc | Out-Null
Step 'service LabTestSvc installed and deleted'

# 8. Scheduled task on a workstation -> stays default 60228 (negative test)
Register-ScheduledTask -TaskName 'LabTestTask' -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit') -Force | Out-Null
Unregister-ScheduledTask -TaskName 'LabTestTask' -Confirm:$false
Step 'scheduled task LabTestTask registered and removed'

if ((Get-Service LabTestSvc -ErrorAction SilentlyContinue) -or (Get-ScheduledTask -TaskName 'LabTestTask' -ErrorAction SilentlyContinue)) {
    'WARNING leftovers found'
} else { 'cleanup verified' }
