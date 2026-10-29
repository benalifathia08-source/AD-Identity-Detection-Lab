# Invoke-TuningTests-WS.ps1
# Live tests for the false-positive tuning rules on WS01 (100534, 100535) with matching negative tests,
# plus a check that rule 92057 (base64-encoded PowerShell) still fires: the lab tooling was changed,
# not the rule. Run on WS01 as a local administrator.

$ErrorActionPreference = 'Stop'
function Step($msg) { '{0} {1}' -f (Get-Date -Format HH:mm:ss), $msg }

# T7 (control): a person tries to reset the LAPS-managed local Administrator password.
# Windows LAPS must refuse it (STATUS_POLICY_CONTROLLED_ACCOUNT, 0xC000A08B), so no 4724 is produced.
$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^*-_=+'
$bytes = New-Object byte[] 28; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$pw = ConvertTo-SecureString ('Aa1!' + -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })) -AsPlainText -Force
try {
    Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Set-LocalUser -Password $pw -ErrorAction Stop
    throw 'T7 FAILED: manual reset of the LAPS-managed account was allowed'
} catch [Microsoft.PowerShell.Commands.InternalException] {
    Step 'T7 manual reset of the LAPS-managed Administrator was refused by Windows (expected)'
}

# T8 (positive, 100534): Windows LAPS rotates it (as SYSTEM) and stores the new one in AD
Reset-LapsPassword
Step 'T8 Reset-LapsPassword (rotation by SYSTEM)'

# T9 (positive, 100535): any PowerShell start writes __PSScriptPolicyTest_*.ps1 to Temp
powershell.exe -NoProfile -Command 'exit 0'
Step 'T9 started a PowerShell process'

# T10 (negative): a script dropped into Temp under another name -> must stay 92213 / 15
$drop = Join-Path $env:TEMP 'lab-dropper-test.ps1'
Set-Content -Path $drop -Value '# harmless detection test file'
Remove-Item $drop -Force
Step 'T10 lab-dropper-test.ps1 written to and removed from Temp'

# T11 (rule intact): a deliberately encoded, harmless command -> 92057 / 12 must still fire
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("'LabTuneEncoded' | Out-Null"))
powershell.exe -NoProfile -EncodedCommand $enc
Step 'T11 harmless -EncodedCommand run'

Start-Sleep -Seconds 3
(Get-WinEvent -LogName 'Microsoft-Windows-LAPS/Operational' -MaxEvents 5 | Where-Object Id -in 10018, 10020, 10004 |
    Select-Object -First 2 | ForEach-Object { "LAPS event $($_.Id): $(($_.Message -split "`n")[0].Trim())" })
