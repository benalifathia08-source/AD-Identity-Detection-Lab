# Set-LabDirectorySACL.ps1
# Adds an audit entry (SACL) on OU=FTOU7 and everything below it, so creating or deleting any object
# there is logged as 5137 / 5141 ("Directory Service Changes" must be audited, which the lab GPO does).
# Without it, Windows logs attribute changes (5136) but never object creation in these OUs.
# Run on DC01 as a Domain Admin. Safe to re-run.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$ouDN  = "OU=FTOU7,$((Get-ADDomain).DistinguishedName)"
$path  = "AD:$ouDN"
$acl   = Get-Acl -Path $path -Audit
$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rights   = [System.DirectoryServices.ActiveDirectoryRights]'CreateChild, DeleteChild'
$rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $everyone, $rights, [System.Security.AccessControl.AuditFlags]::Success,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)

$exists = $acl.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
    $_.IdentityReference -eq $everyone -and $_.ActiveDirectoryRights -eq $rights -and
    $_.AuditFlags -eq 'Success' -and $_.InheritanceType -eq 'All'
}
if ($exists) { 'audit entry already present' }
else {
    $acl.AddAuditRule($rule)
    Set-Acl -Path $path -AclObject $acl
    'audit entry added'
}
(Get-Acl -Path $path -Audit).Audit | Where-Object { $_.ActiveDirectoryRights -match 'CreateChild' } |
    Select-Object IdentityReference, AuditFlags, ActiveDirectoryRights, InheritanceType | Format-Table -AutoSize
