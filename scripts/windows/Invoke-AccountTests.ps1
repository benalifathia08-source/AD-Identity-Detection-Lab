# Invoke-AccountTests.ps1
# Live test cases for the admin account lifecycle rules (100520-100525). Run on DC01 as FTOU7\Administrator.
# Uses a temporary admin-style account and a temporary normal user; both are deleted at the end.
# Passwords are random and never displayed.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
function Step($msg) { '{0} {1}' -f (Get-Date -Format HH:mm:ss), $msg }
function New-RandomPassword {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+?'
    $bytes = New-Object byte[] 28
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $p = 'Aa1!' + -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    ConvertTo-SecureString $p -AsPlainText -Force
}
$root = "OU=FTOU7,$((Get-ADDomain).DistinguishedName)"

# 1. Admin-style account created (enabled) in the Admins OU -> 5137, 4720, 4724, 4722
New-ADUser -Name 'adm.testops' -SamAccountName 'adm.testops' -Path "OU=Admins,$root" `
    -AccountPassword (New-RandomPassword) -Enabled $true -Description 'Temporary detection test account'
Step 'created adm.testops in OU=Admins (enabled)'
Start-Sleep 2

# 2-3. Disabled, then re-enabled -> 4725 (default), 4722
Disable-ADAccount -Identity 'adm.testops'; Step 'disabled adm.testops'; Start-Sleep 2
Enable-ADAccount  -Identity 'adm.testops'; Step 're-enabled adm.testops'; Start-Sleep 2

# 4. Password reset by another account -> 4724
Set-ADAccountPassword -Identity 'adm.testops' -Reset -NewPassword (New-RandomPassword)
Step 'reset password of adm.testops'; Start-Sleep 2

# 5. Negative: ordinary user in the Users OU -> defaults only
New-ADUser -Name 'test.user' -SamAccountName 'test.user' -Path "OU=Users,$root" `
    -AccountPassword (New-RandomPassword) -Enabled $true -Description 'Temporary detection test account'
Step 'created test.user in OU=Users (negative test)'; Start-Sleep 2

# Cleanup
Remove-ADUser -Identity 'adm.testops' -Confirm:$false
Remove-ADUser -Identity 'test.user'   -Confirm:$false
$left = Get-ADUser -Filter "sAMAccountName -eq 'adm.testops' -or sAMAccountName -eq 'test.user'"
if ($left) { "WARNING leftovers: $($left.SamAccountName -join ', ')" } else { 'cleanup verified: test accounts deleted' }
