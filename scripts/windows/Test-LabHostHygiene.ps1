# Test-LabHostHygiene.ps1
# Read-only health and hygiene checks for a lab Windows VM (run over SSH as an administrator).

'== host: ' + $env:COMPUTERNAME
"time source : $((w32tm /query /source | Out-String).Trim())"
"time offset : $(((w32tm /stripchart /computer:time.windows.com /samples:1 /dataonly 2>$null | Select-Object -Last 1) -split ',')[-1].Trim())"
$lic = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" | Select-Object -First 1
"license     : $($lic.Name) | status $($lic.LicenseStatus) | grace minutes left $($lic.GracePeriodRemaining) (~$([int]($lic.GracePeriodRemaining/1440)) days)"
"services    : Wazuh=$((Get-Service WazuhSvc -ErrorAction SilentlyContinue).Status) Sysmon=$((Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1).Status)"

'== who can write to the lab folders (anything besides Administrators/SYSTEM is a problem)'
foreach ($d in 'C:\LabScripts', 'C:\LabMedia', 'C:\LabBackups') {
    if (-not (Test-Path $d)) { continue }
    $writers = (Get-Acl $d).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.FileSystemRights -match 'Write|Modify|FullControl|CreateFiles|AppendData' -and
        $_.IdentityReference -notmatch 'Administrators|SYSTEM|TrustedInstaller|CREATOR OWNER'
    } | ForEach-Object { "$($_.IdentityReference) [$($_.FileSystemRights)]" }
    '{0,-14} {1}' -f $d, $(if ($writers) { 'WRITABLE BY: ' + ($writers -join '; ') } else { 'ok (admins/SYSTEM only)' })
}

'== leftovers from lab automation'
Get-ChildItem C:\Windows\Temp -Filter 'lab-*.ps1' -ErrorAction SilentlyContinue | ForEach-Object { "temp script: $($_.FullName)" }
Get-ChildItem C:\LabScripts\run -ErrorAction SilentlyContinue | ForEach-Object { "run dir: $($_.Name)" }
Get-ScheduledTask -TaskName 'Lab*' -ErrorAction SilentlyContinue | ForEach-Object { "task: $($_.TaskName)" }
Get-ChildItem C:\LabMedia -File -ErrorAction SilentlyContinue | Select-Object Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } } | Format-Table -AutoSize | Out-String
