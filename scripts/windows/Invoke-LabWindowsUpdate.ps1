# Invoke-LabWindowsUpdate.ps1
# Installs pending Windows software updates (no drivers, no previews) on this machine.
# The Windows Update API refuses to download or install from a remote (SSH/WinRM) session, so this
# script stages the real work in a one-shot SYSTEM scheduled task and returns immediately.
# Progress is written to C:\LabMedia\windowsupdate.log; the last line is "WU-DONE ..." when finished.
#   -Reboot  restarts the machine automatically when an update requires it
# Run it again after each reboot until it reports 0 updates.

param([switch] $Reboot)
$ErrorActionPreference = 'Stop'

$dir = 'C:\LabMedia'
if (-not (Test-Path $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # The job script below runs as SYSTEM, so ordinary users must not be able to write here
    icacls $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /Q | Out-Null
}
$log = Join-Path $dir 'windowsupdate.log'
$job = Join-Path $dir 'windowsupdate-job.ps1'

$worker = @'
$log = 'C:\LabMedia\windowsupdate.log'
function Log($m) { Add-Content -Path $log -Value ('{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) }
try {
    Log 'searching for updates'
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $todo = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $result.Updates) {
        if ($u.Title -match 'Preview') { Log "skip (preview): $($u.Title)"; continue }
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        [void]$todo.Add($u)
        Log ('found: {0} ({1:N0} MB)' -f $u.Title, ($u.MaxDownloadSize / 1MB))
    }
    if ($todo.Count -eq 0) { Log 'WU-DONE updates=0 reboot=False'; return }
    Log "downloading $($todo.Count) update(s)"
    $dl = $session.CreateUpdateDownloader(); $dl.Updates = $todo
    $d = $dl.Download()
    Log "download result code: $($d.ResultCode)"
    Log 'installing'
    $inst = $session.CreateUpdateInstaller(); $inst.Updates = $todo
    $r = $inst.Install()
    for ($i = 0; $i -lt $todo.Count; $i++) {
        Log ('result {0}: {1}' -f $r.GetUpdateResult($i).ResultCode, $todo.Item($i).Title)
    }
    Log "WU-DONE updates=$($todo.Count) result=$($r.ResultCode) reboot=$($r.RebootRequired)"
    if ($r.RebootRequired -and __REBOOT__) { Log 'rebooting'; Restart-Computer -Force }
} catch {
    Log "WU-DONE error: $($_.Exception.Message)"
}
'@
$worker.Replace('__REBOOT__', $(if ($Reboot) { '$true' } else { '$false' })) | Set-Content -Path $job -Encoding utf8

Add-Content -Path $log -Value ('{0} ===== new run (reboot={1})' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), [bool]$Reboot)
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$job`""
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 3)
Register-ScheduledTask -TaskName 'LabWindowsUpdate' -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'LabWindowsUpdate'
"Windows Update started as SYSTEM; follow $log"
