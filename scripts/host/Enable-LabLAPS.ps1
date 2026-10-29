# Enable-LabLAPS.ps1
# Deploys Windows LAPS for the lab from the host (DC01 must have the April 2023 or later cumulative update).
#   1. Administrator is added to Schema Admins (session A)
#   2. the LAPS schema extension runs in a NEW session (B), whose token includes Schema Admins
#   3. Administrator is removed from Schema Admins again (session C), so the group is empty except
#      during the change. Steps 1 and 3 raise privileged-group alerts in Wazuh, as they should.
#   4. computers in the Workstations and Servers OUs get permission to write their own password,
#      and the "LAB - Windows LAPS" GPO is linked to those OUs
#   5. WS01 applies the policy and the result is checked from DC01 (metadata only, never the password)

#
# NOTE: Update-LapsADSchema fails over the lab's key-based SSH logon ("insufficient access rights"):
# that logon has no network credentials for the cmdlet's own LDAP connection. Use -SchemaPrep to add
# Administrator to Schema Admins, run Update-LapsADSchema yourself in an interactive DC01 console
# session (signed in after the membership change), then run with -SkipSchema, which removes the
# temporary membership first and finishes the rollout.

param(
    [string] $DC          = '192.168.145.10',
    [string] $Workstation = '192.168.145.130',
    [switch] $SchemaPrep,
    [switch] $SkipSchema
)
$ErrorActionPreference = 'Stop'
$invoke = Join-Path $PSScriptRoot 'Invoke-LabCommand.ps1'
# Remote errors must stop the step, so every command runs with ErrorActionPreference = Stop
function OnDC($cmd) {
    & $invoke -ComputerName $DC -User 'Administrator' -Command "`$ErrorActionPreference = 'Stop'`n$cmd"
    if ($LASTEXITCODE -ne 0) { throw 'Step failed on DC01' }
}

if ($SchemaPrep) {
    OnDC "Add-ADGroupMember 'Schema Admins' -Members Administrator; 'Administrator added to Schema Admins (temporary)'"
    Write-Host 'Now: sign out of DC01, sign back in as FTOU7\Administrator, run Update-LapsADSchema -Verbose, then run this script with -SkipSchema.'
    return
}
if ($SkipSchema) {
    OnDC "Remove-ADGroupMember 'Schema Admins' -Members Administrator -Confirm:`$false -ErrorAction SilentlyContinue; 'Schema Admins members: ' + ((Get-ADGroupMember 'Schema Admins').SamAccountName -join ',')"
}

Write-Host '[0] Prerequisites'
OnDC @'
if (-not (Get-Command Update-LapsADSchema -ErrorAction SilentlyContinue)) { throw 'Windows LAPS module missing: patch DC01 first.' }
"DC01 build $([Environment]::OSVersion.Version.Build).$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR), LAPS module present"
'@

$hasSchema = OnDC '[bool](Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "lDAPDisplayName -eq ''msLAPS-Password''")'
if ($SkipSchema -and "$hasSchema".Trim() -ne 'True') { throw 'LAPS schema attributes not found: run Update-LapsADSchema on DC01 first.' }
if ("$hasSchema".Trim() -ne 'True') {
    Write-Host '[1] Temporarily adding Administrator to Schema Admins'
    OnDC "Add-ADGroupMember 'Schema Admins' -Members Administrator; 'added'"
    try {
        Write-Host '[2] Extending the schema (new session)'
        OnDC "Update-LapsADSchema -Confirm:`$false -Verbose 4>&1 | Select-Object -Last 3; 'schema updated'"
    } finally {
        Write-Host '[3] Removing Administrator from Schema Admins'
        OnDC "Remove-ADGroupMember 'Schema Admins' -Members Administrator -Confirm:`$false; 'Schema Admins members: ' + ((Get-ADGroupMember 'Schema Admins').SamAccountName -join ',')"
    }
} else { Write-Host '[1-3] LAPS schema already present, skipping' }

Write-Host '[4] Permissions and GPO'
OnDC @'
Import-Module LAPS, GroupPolicy
$root = "OU=FTOU7,$((Get-ADDomain).DistinguishedName)"
$ous  = "OU=Workstations,$root", "OU=Servers,$root"
foreach ($ou in $ous) { Set-LapsADComputerSelfPermission -Identity $ou | Out-Null; "self-permission set on $ou" }

$name = 'LAB - Windows LAPS'
$gpo  = Get-GPO -Name $name -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $name -Comment 'Windows LAPS: back up the local Administrator password to AD, encrypted' }
$key = 'HKLM\Software\Microsoft\Policies\LAPS'
$values = [ordered]@{
    BackupDirectory             = 2    # Active Directory
    ADPasswordEncryptionEnabled = 1    # encrypted in AD; only Domain Admins can decrypt (default)
    PasswordComplexity          = 4    # upper + lower + digits + specials
    PasswordLength              = 20
    PasswordAgeDays             = 30
}
foreach ($v in $values.Keys) { Set-GPRegistryValue -Guid $gpo.Id -Key $key -ValueName $v -Type DWord -Value $values[$v] | Out-Null }
foreach ($ou in $ous) {
    if (-not (Get-GPInheritance -Target $ou).GpoLinks.Where({ $_.DisplayName -eq $name })) { New-GPLink -Guid $gpo.Id -Target $ou | Out-Null }
}
"GPO $name {$($gpo.Id)} linked to Workstations and Servers"
'@

Write-Host '[5] Applying on WS01'
& $invoke -ComputerName $Workstation -Command @'
gpupdate /target:computer /force | Out-Null
Invoke-LapsPolicyProcessing
Start-Sleep -Seconds 5
Get-WinEvent -LogName 'Microsoft-Windows-LAPS/Operational' -MaxEvents 8 |
    Select-Object TimeCreated, Id, @{ n = 'Message'; e = { ($_.Message -split "`n")[0].Trim() } } | Format-Table -AutoSize | Out-String -Width 200
'@

Write-Host '[6] Verifying from DC01 (metadata only)'
OnDC @'
Get-LapsADPassword -Identity WS01 | Select-Object ComputerName, Account, PasswordUpdateTime, ExpirationTimestamp, Source, DecryptionStatus, AuthorizedDecryptor | Format-List | Out-String
'@
