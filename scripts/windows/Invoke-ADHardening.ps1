# Invoke-ADHardening.ps1
# M8: fixes PingCastle baseline findings that need no downloads. Run on DC01 as FTOU7\Administrator.
# Idempotent: every step checks the current state first and prints before -> after.
#
# Deliberately NOT changed (reasons in docs/hardening.md):
#   - built-in Administrator stays out of Protected Users (break-glass account; also used for lab automation)
#   - svc_scanner keeps "no Kerberos pre-authentication" (intentional lab content)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain   = Get-ADDomain
$domainDN = $domain.DistinguishedName
function Report($id, $what, $before, $after) { '{0,-18} {1,-55} {2} -> {3}' -f $id, $what, $before, $after }

# --- P-Delegated: privileged accounts must be "sensitive and cannot be delegated" ---
$privGroups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'
$admins = $privGroups | ForEach-Object { Get-ADGroupMember $_ -Recursive } |
    Where-Object objectClass -eq 'user' | Sort-Object SamAccountName -Unique
foreach ($a in $admins) {
    $u = Get-ADUser $a -Properties AccountNotDelegated
    if (-not $u.AccountNotDelegated) { Set-ADUser $u -AccountNotDelegated $true }
    Report 'P-Delegated' "$($u.SamAccountName) not delegable" $u.AccountNotDelegated $true
}

# --- P-ProtectedUsers: named admin accounts into Protected Users (break-glass Administrator excluded) ---
$protected = (Get-ADGroupMember 'Protected Users').SamAccountName
foreach ($a in $admins | Where-Object { $_.SamAccountName -ne 'Administrator' }) {
    $was = $protected -contains $a.SamAccountName
    if (-not $was) { Add-ADGroupMember 'Protected Users' -Members $a.SamAccountName }
    Report 'P-ProtectedUsers' "$($a.SamAccountName) in Protected Users" $was $true
}

# --- P-SchemaAdmin: Schema Admins empty until a schema change is actually needed ---
$schema = @(Get-ADGroupMember 'Schema Admins')
if ($schema) { Remove-ADGroupMember 'Schema Admins' -Members $schema -Confirm:$false }
Report 'P-SchemaAdmin' 'Schema Admins members' ($schema.SamAccountName -join ',') '(empty)'

# --- P-RecycleBin ---
$rb = Get-ADOptionalFeature 'Recycle Bin Feature'
$wasRb = [bool]$rb.EnabledScopes
if (-not $wasRb) {
    Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $domain.Forest -Confirm:$false
}
Report 'P-RecycleBin' 'AD Recycle Bin enabled' $wasRb $true

# --- A-MinPwdLen: domain password policy minimum length 14 (CIS) ---
$pol = Get-ADDefaultDomainPasswordPolicy
if ($pol.MinPasswordLength -lt 14) { Set-ADDefaultDomainPasswordPolicy -Identity $domainDN -MinPasswordLength 14 }
Report 'A-MinPwdLen' 'Default domain policy min length' $pol.MinPasswordLength 14

# --- A-NoServicePolicy: fine-grained policy (PSO) with 20+ characters for service accounts ---
$ouGroups = "OU=Groups,OU=FTOU7,$domainDN"
if (-not (Get-ADGroup -Filter "Name -eq 'GG-ServiceAccounts'")) {
    New-ADGroup -Name 'GG-ServiceAccounts' -GroupScope Global -GroupCategory Security -Path $ouGroups -Description 'Service accounts (PSO-ServiceAccounts applies)'
}
$svc = Get-ADUser -SearchBase "OU=Service Accounts,OU=FTOU7,$domainDN" -Filter *
Add-ADGroupMember 'GG-ServiceAccounts' -Members $svc
if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'PSO-ServiceAccounts'")) {
    New-ADFineGrainedPasswordPolicy -Name 'PSO-ServiceAccounts' -Precedence 10 -MinPasswordLength 20 `
        -ComplexityEnabled $true -PasswordHistoryCount 24 -MinPasswordAge '1.00:00:00' -MaxPasswordAge '365.00:00:00' `
        -LockoutThreshold 0 -LockoutDuration '00:30:00' -LockoutObservationWindow '00:30:00' -ReversibleEncryptionEnabled $false `
        -Description 'Service accounts: 20+ characters'
    Add-ADFineGrainedPasswordPolicySubject 'PSO-ServiceAccounts' -Subjects 'GG-ServiceAccounts'
}
Report 'A-NoServicePolicy' "PSO-ServiceAccounts (min 20) on $($svc.Count) accounts" 'none' 'applied'

# --- S-ADRegistration: only admins may join computers ---
$mq = (Get-ADObject $domainDN -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
if ($mq -ne 0) { Set-ADDomain -Identity $domainDN -Replace @{ 'ms-DS-MachineAccountQuota' = 0 } }
Report 'S-ADRegistration' 'ms-DS-MachineAccountQuota' $mq 0

# --- S-AesNotEnabled: AES only for accounts with SPNs (0x18 = AES128 + AES256) ---
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties 'msDS-SupportedEncryptionTypes', ServicePrincipalName |
    Where-Object SamAccountName -ne 'krbtgt' | ForEach-Object {
        $was = $_.'msDS-SupportedEncryptionTypes'
        if ($was -ne 24) { Set-ADUser $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 } }
        Report 'S-AesNotEnabled' "$($_.SamAccountName) encryption types" $(if ($was) { $was } else { 'not set' }) '24 (AES)'
    }

# --- A-DC-Spooler: no print spooler on domain controllers ---
$sp = Get-Service Spooler
if ($sp.Status -ne 'Stopped') { Stop-Service Spooler -Force }
if ($sp.StartType -ne 'Disabled') { Set-Service Spooler -StartupType Disabled }
Report 'A-DC-Spooler' 'Print Spooler on DC01' "$($sp.Status)/$($sp.StartType)" 'Stopped/Disabled'

# --- S-DC-SubnetMissing: declare the lab subnet in Sites and Services ---
$subnet = '192.168.145.0/24'
$had = [bool](Get-ADReplicationSubnet -Filter "Name -eq '$subnet'")
if (-not $had) { New-ADReplicationSubnet -Name $subnet -Site 'Default-First-Site-Name' -Description 'Lab NAT network' }
Report 'S-DC-SubnetMissing' "subnet $subnet declared" $had $true

# --- P-UnprotectedOU: every OU protected from accidental deletion ---
Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion |
    Where-Object { -not $_.ProtectedFromAccidentalDeletion } | ForEach-Object {
        Set-ADOrganizationalUnit $_ -ProtectedFromAccidentalDeletion $true
        Report 'P-UnprotectedOU' "$($_.DistinguishedName)" $false $true
    }
