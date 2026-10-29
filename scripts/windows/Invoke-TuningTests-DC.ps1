# Invoke-TuningTests-DC.ps1
# Live tests for the false-positive tuning rules on DC01 (100531, 100532, 100533), each paired with a
# negative test proving that the same action done another way still alerts at full severity.
# Run on DC01 as FTOU7\Administrator. Everything created here is removed again.

$ErrorActionPreference = 'Stop'
function Step($msg) { '{0} {1}' -f (Get-Date -Format HH:mm:ss), $msg }
function AsSystem([string]$name, [string]$cmd) {
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command `"$cmd`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $name
    do { Start-Sleep -Seconds 2 } while ((Get-ScheduledTask -TaskName $name).State -eq 'Running')
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
}
$defPath = '"C:\ProgramData\Microsoft\Windows Defender\Platform\9.9.9.9-0\LabFake.exe"'

# T1 (positive, 100531): service pointing into the Defender platform folder, created by SYSTEM
AsSystem 'LabTuneSvcSys' "New-Service -Name LabDefPathSys -BinaryPathName '$defPath' -StartupType Manual | Out-Null; sc.exe delete LabDefPathSys | Out-Null"
Step 'T1 service LabDefPathSys (Defender path) created + deleted as SYSTEM'

# T2 (negative): same path, created by an administrator -> must stay 100514 / 12
New-Service -Name LabDefPathAdm -BinaryPathName $defPath -StartupType Manual | Out-Null
sc.exe delete LabDefPathAdm | Out-Null
Step 'T2 service LabDefPathAdm (Defender path) created + deleted by Administrator'

# T3 (negative for 100530): a per-user service TEMPLATE (type 0x50), no hex suffix, created by an admin
sc.exe create LabUserSvcTest type= userown binPath= "C:\Windows\System32\cmd.exe /c exit" | Out-Null
sc.exe delete LabUserSvcTest | Out-Null
Step 'T3 user-service template LabUserSvcTest created + deleted by Administrator'

# T4 (positive, 100532): task under \Microsoft\Windows\ created by SYSTEM
AsSystem 'LabTuneTaskSys' "Register-ScheduledTask -TaskPath '\Microsoft\Windows\' -TaskName 'LabTuneSys' -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c exit') -Force | Out-Null; Unregister-ScheduledTask -TaskPath '\Microsoft\Windows\' -TaskName 'LabTuneSys' -Confirm:`$false"
Step 'T4 task \Microsoft\Windows\LabTuneSys created + removed as SYSTEM'

# T5 (negative): same location, created by an administrator -> must stay 100516 / 12
Register-ScheduledTask -TaskPath '\Microsoft\Windows\' -TaskName 'LabTuneAdm' -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit') -Force | Out-Null
Unregister-ScheduledTask -TaskPath '\Microsoft\Windows\' -TaskName 'LabTuneAdm' -Confirm:$false
Step 'T5 task \Microsoft\Windows\LabTuneAdm created + removed by Administrator'

# T6 (positive, 100533): Explorer's sign-in task with its real action (no trigger, never runs).
# Explorer recreates the real one at the next admin sign-in.
Register-ScheduledTask -TaskName 'CreateExplorerShellUnelevatedTask' -Action (New-ScheduledTaskAction -Execute 'C:\Windows\Explorer.EXE' -Argument '/NoUACCheck') -Force | Out-Null
Unregister-ScheduledTask -TaskName 'CreateExplorerShellUnelevatedTask' -Confirm:$false
Step 'T6 task \CreateExplorerShellUnelevatedTask (Explorer.EXE /NoUACCheck) created + removed'
Start-Sleep -Seconds 2

# T6b (negative): same name, different payload -> must stay 100516 / 12
Register-ScheduledTask -TaskName 'CreateExplorerShellUnelevatedTask' -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit') -Force | Out-Null
Unregister-ScheduledTask -TaskName 'CreateExplorerShellUnelevatedTask' -Confirm:$false
Step 'T6b task \CreateExplorerShellUnelevatedTask with cmd.exe payload created + removed'

$left = @(Get-Service LabDefPath*, LabUserSvcTest -ErrorAction SilentlyContinue) + @(Get-ScheduledTask -TaskName 'LabTune*' -ErrorAction SilentlyContinue)
if ($left) { "WARNING leftovers: $($left.Name + $left.TaskName -join ', ')" } else { 'cleanup verified' }
