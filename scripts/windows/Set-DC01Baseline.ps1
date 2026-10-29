# Set-DC01Baseline.ps1
# Post-promotion baseline for DC01 (run over SSH as FTOU7\Administrator):
#   - NTP: the forest-root PDC emulator syncs from public NTP; every other domain member syncs from it
#   - OU structure for the fictional company "Ftou7 Corp"
#   - New computer accounts land in the Workstations OU instead of the default Computers container

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# --- Time ---
w32tm /config /manualpeerlist:"0.pool.ntp.org,0x8 1.pool.ntp.org,0x8 time.windows.com,0x8" /syncfromflags:manual /reliable:yes /update | Out-Null
Restart-Service w32time
w32tm /resync /force | Out-Null
"Time source: $(w32tm /query /source)"

# --- OUs ---
$domainDN = (Get-ADDomain).DistinguishedName
$rootName = 'FTOU7'
$rootDN   = "OU=$rootName,$domainDN"
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$rootDN'")) {
    New-ADOrganizationalUnit -Name $rootName -Path $domainDN -Description 'Ftou7 Corp (lab)'
}
$children = [ordered]@{
    'Users'            = 'Standard user accounts'
    'Admins'           = 'Privileged accounts (tier 0 / tier 1)'
    'Service Accounts' = 'Accounts used by applications and services'
    'Groups'           = 'Security and distribution groups'
    'Workstations'     = 'Domain-joined client computers'
    'Servers'          = 'Member servers'
}
foreach ($name in $children.Keys) {
    $dn = "OU=$name,$rootDN"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'")) {
        New-ADOrganizationalUnit -Name $name -Path $rootDN -Description $children[$name]
    }
}
Get-ADOrganizationalUnit -SearchBase $rootDN -Filter * | Sort-Object DistinguishedName |
    Select-Object Name, DistinguishedName | Format-Table -AutoSize

# --- Default location for new computer accounts ---
redircmp "OU=Workstations,$rootDN" | Out-Null
"Default computer container: $((Get-ADDomain).ComputersContainer)"
