# New-LabADContent.ps1
# Populates ftou7.internal with fictional, realistic content for detection testing:
#   - department groups and ~25 standard users
#   - one extra privileged account
#   - service accounts with SPNs (the target of Kerberoasting)
#   - one account without Kerberos pre-authentication (the target of AS-REP roasting)
#   - one honeytoken service account that nothing legitimate ever uses
# Every password is random (24 chars), set at runtime on DC01 and never displayed or stored, so
# the lab produces realistic telemetry while none of these accounts is actually crackable.
# Run on DC01 as a Domain Admin. Safe to re-run: existing objects are left as they are.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domain   = Get-ADDomain
$dnsRoot  = $domain.DNSRoot
$root     = "OU=FTOU7,$($domain.DistinguishedName)"
$ouUsers  = "OU=Users,$root"
$ouAdmins = "OU=Admins,$root"
$ouSvc    = "OU=Service Accounts,$root"
$ouGroups = "OU=Groups,$root"

function New-RandomPassword {
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%^&*-_=+?'
    $rng  = [Security.Cryptography.RandomNumberGenerator]::Create()
    $pick = { param($s) $b = New-Object byte[] 4; $rng.GetBytes($b); $s[[BitConverter]::ToUInt32($b, 0) % $s.Length] }
    $chars = foreach ($s in $sets) { & $pick $s }             # at least one of each class
    $all = -join $sets
    $chars += 1..20 | ForEach-Object { & $pick $all }
    $plain = -join ($chars | Sort-Object { $b = New-Object byte[] 4; $rng.GetBytes($b); [BitConverter]::ToUInt32($b, 0) })
    ConvertTo-SecureString $plain -AsPlainText -Force
}

function Ensure-User {
    param([string]$Sam, [string]$Given, [string]$Surname, [string]$Path, [string]$Dept, [string]$Title,
          [string]$Description, [switch]$NeverExpires)
    if (Get-ADUser -Filter "sAMAccountName -eq '$Sam'") { return 'exists' }
    $p = @{
        Name = if ($Given) { "$Given $Surname" } else { $Sam }
        SamAccountName = $Sam; UserPrincipalName = "$Sam@$dnsRoot"; Path = $Path
        AccountPassword = (New-RandomPassword); Enabled = $true
        PasswordNeverExpires = [bool]$NeverExpires
    }
    if ($Given)       { $p.GivenName = $Given; $p.Surname = $Surname; $p.DisplayName = "$Given $Surname" }
    if ($Dept)        { $p.Department = $Dept; $p.Company = 'Ftou7 Corp' }
    if ($Title)       { $p.Title = $Title }
    if ($Description) { $p.Description = $Description }
    New-ADUser @p
    'created'
}

# --- Department groups ---
$departments = 'IT', 'HR', 'Finance', 'Sales', 'Operations'
foreach ($d in $departments) {
    if (-not (Get-ADGroup -Filter "Name -eq 'GG-$d'")) {
        New-ADGroup -Name "GG-$d" -GroupScope Global -GroupCategory Security -Path $ouGroups -Description "$d department"
    }
}

# --- Standard users (fictional) ---
$people = @(
    @('Amira','Ben Salah','IT','Systems Administrator'),    @('Youssef','Trabelsi','IT','Network Engineer'),
    @('Ines','Gharbi','IT','Helpdesk Technician'),          @('Mehdi','Jaziri','IT','Developer'),
    @('Salma','Khelifi','HR','HR Manager'),                 @('Karim','Mansour','HR','Recruiter'),
    @('Nour','Haddad','HR','Payroll Specialist'),           @('Rania','Bouzid','Finance','Finance Director'),
    @('Omar','Chaabane','Finance','Accountant'),            @('Leila','Mejri','Finance','Financial Analyst'),
    @('Sami','Dridi','Finance','Accounts Payable Clerk'),   @('Hela','Saidi','Sales','Sales Manager'),
    @('Anis','Ferchichi','Sales','Account Executive'),      @('Mariem','Zouari','Sales','Account Executive'),
    @('Walid','Hamdi','Sales','Sales Representative'),      @('Ons','Ayari','Sales','Marketing Coordinator'),
    @('Bilel','Masmoudi','Operations','Operations Manager'),@('Sarra','Riahi','Operations','Logistics Coordinator'),
    @('Hamza','Sassi','Operations','Warehouse Supervisor'), @('Asma','Belhadj','Operations','Procurement Officer'),
    @('Fares','Toumi','Operations','Quality Analyst'),      @('Dorra','Kammoun','IT','Security Analyst'),
    @('Aziz','Laabidi','Finance','Treasury Officer'),       @('Yasmine','Ouni','HR','Training Coordinator'),
    @('Tarek','Brahmi','Sales','Pre-sales Engineer')
)
$created = 0
foreach ($p in $people) {
    $sam = ('{0}.{1}' -f $p[0], ($p[1] -replace ' ', '')).ToLower()
    if ((Ensure-User -Sam $sam -Given $p[0] -Surname $p[1] -Path $ouUsers -Dept $p[2] -Title $p[3]) -eq 'created') { $created++ }
    Add-ADGroupMember -Identity "GG-$($p[2])" -Members $sam -ErrorAction SilentlyContinue
}
"standard users created: $created / $($people.Count)"

# --- Extra privileged account (tier 0) ---
Ensure-User -Sam 'adm.amira' -Given 'Amira' -Surname 'Ben Salah (Admin)' -Path $ouAdmins -Dept 'IT' -Title 'Domain administrator account' | Out-Null
Add-ADGroupMember -Identity 'Domain Admins' -Members 'adm.amira' -ErrorAction SilentlyContinue

# --- Service accounts (SPNs make them requestable as Kerberos service tickets) ---
$services = @(
    @{ Sam = 'svc_sql';       Spn = "MSSQLSvc/sql01.$($dnsRoot):1433"; Desc = 'SQL Server service account' },
    @{ Sam = 'svc_web';       Spn = "HTTP/intranet.$dnsRoot";          Desc = 'Intranet IIS application pool' },
    @{ Sam = 'svc_backup';    Spn = $null;                             Desc = 'Backup agent' },
    # Honeytoken: looks like a forgotten legacy service, but no real service uses it.
    # Any Kerberos ticket request for it is suspicious by definition.
    @{ Sam = 'svc_reporting'; Spn = "HTTP/reports-legacy.$dnsRoot";    Desc = 'Legacy reporting service (do not delete)' }
)
foreach ($s in $services) {
    Ensure-User -Sam $s.Sam -Path $ouSvc -Description $s.Desc -NeverExpires | Out-Null
    if ($s.Spn) { Set-ADUser -Identity $s.Sam -ServicePrincipalNames @{ Add = $s.Spn } -ErrorAction SilentlyContinue }
}

# --- One account without Kerberos pre-authentication (a classic misconfiguration) ---
Ensure-User -Sam 'svc_scanner' -Path $ouSvc -Description 'Network scanner integration (legacy, pre-auth disabled)' -NeverExpires | Out-Null
Set-ADAccountControl -Identity 'svc_scanner' -DoesNotRequirePreAuth $true

# --- Summary (names and flags only, never passwords) ---
Get-ADUser -SearchBase $root -Filter * -Properties Department, ServicePrincipalName, DoesNotRequirePreAuth, PasswordNeverExpires, MemberOf |
    Sort-Object DistinguishedName |
    Select-Object SamAccountName,
        @{ n = 'OU';        e = { ($_.DistinguishedName -split ',')[1] -replace 'OU=' } },
        Department,
        @{ n = 'SPN';       e = { $_.ServicePrincipalName -join ';' } },
        @{ n = 'NoPreAuth'; e = { $_.DoesNotRequirePreAuth } },
        @{ n = 'PwdNeverExpires'; e = { $_.PasswordNeverExpires } } |
    ConvertTo-Csv -NoTypeInformation
