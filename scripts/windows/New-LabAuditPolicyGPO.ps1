# New-LabAuditPolicyGPO.ps1
# Creates and links the lab audit GPOs. Run on DC01 as a Domain Admin (over SSH is fine). Safe to re-run.
#
#   "LAB - Security Audit Policy"  linked at the domain root (DC01 and every workstation):
#     - Advanced Audit Policy subcategories needed by the identity detections (audit.csv)
#     - "Force audit policy subcategory settings" so legacy category settings cannot override them
#     - Command line in process creation events (4688)
#     - PowerShell Script Block Logging (4104) and Module Logging (4103)
#     - Security log size 256 MB
#   "LAB - DC Audit Policy"  linked to OU=Domain Controllers (higher precedence on DCs):
#     - Sensitive Privilege Use. PingCastle (A-AuditDC) wants it on DCs; on 2026-10-07/08 it was ~30% of
#       all events (4673/4674) for little value, so workstations get "No Auditing" from the root GPO.
#
# The GroupPolicy module has no cmdlet for Advanced Audit Policy, so audit.csv is written into each
# GPO's SYSVOL folder and the Audit Policy client-side extension is registered on the GPO object.

$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy, ActiveDirectory

$domain   = Get-ADDomain
$domainDN = $domain.DistinguishedName

# Subcategory -> 0 = No Auditing, 1 = Success, 2 = Failure, 3 = Success and Failure
$Desired = [ordered]@{
    # Account Logon (DC side of authentication)
    'Credential Validation'               = 3   # 4776 NTLM validation
    'Kerberos Authentication Service'     = 3   # 4768 TGT requests, 4771 pre-auth failures
    'Kerberos Service Ticket Operations'  = 3   # 4769 service tickets
    'Other Account Logon Events'          = 3
    # Account Management
    'User Account Management'             = 3   # 4720 created, 4738 changed, 4740 locked out
    'Computer Account Management'         = 1
    'Security Group Management'           = 1   # 4728/4732/4756 member added
    'Other Account Management Events'     = 1
    # Detailed Tracking
    'Process Creation'                    = 1   # 4688
    'DPAPI Activity'                      = 1   # 4692 DPAPI backup key export (PingCastle A-AuditDC); quiet
    # Privilege Use: off here, on for DCs via the DC GPO below
    'Sensitive Privilege Use'             = 0
    # DS Access
    'Directory Service Access'            = 3   # 4662 (DCSync replication rights)
    'Directory Service Changes'           = 1   # 5136 object modified, 5137 created
    # Logon/Logoff
    'Logon'                               = 3   # 4624 / 4625
    'Logoff'                              = 1
    'Account Lockout'                     = 1
    'Special Logon'                       = 1   # 4672 admin logons
    'Other Logon/Logoff Events'           = 3
    # Object Access
    'Other Object Access Events'          = 3   # 4698 scheduled task created
    # Policy Change
    'Audit Policy Change'                 = 1   # 4719 someone changed auditing
    'Authentication Policy Change'        = 1
    # System
    'Security State Change'               = 1
    'Security System Extension'           = 1   # 4697 service installed
    'System Integrity'                    = 3
}
$DcDesired = [ordered]@{
    'Sensitive Privilege Use'             = 1   # 4673/4674 e.g. debug privilege (PingCastle A-AuditDC)
}
$InclusionText = @{ 0 = 'No Auditing'; 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }

$guidByName = @{}
foreach ($line in (auditpol /list /subcategory:* /v)) {
    if ($line -match '^\s+(.+?)\s+(\{[0-9A-Fa-f-]{36}\})\s*$') { $guidByName[$Matches[1].Trim()] = $Matches[2].ToUpper() }
}

function Get-LinkedGpo([string]$Name, [string]$Target, [string]$Comment) {
    $g = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $g) { $g = New-GPO -Name $Name -Comment $Comment }
    if (-not (Get-GPInheritance -Target $Target).GpoLinks.Where({ $_.DisplayName -eq $Name })) {
        New-GPLink -Guid $g.Id -Target $Target -LinkEnabled Yes | Out-Null
    }
    $g
}

# Writes audit.csv into the GPO, registers the Audit Policy CSE and bumps the computer version
function Set-GpoAuditCsv($Gpo, $Map) {
    $csv = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($name in $Map.Keys) {
        if (-not $guidByName.ContainsKey($name)) { throw "Audit subcategory not found on this system: $name" }
        $v = $Map[$name]
        $csv += ",System,Audit $name,$($guidByName[$name]),$($InclusionText[$v]),,$v"
    }
    $gpoPath  = "$env:SystemRoot\SYSVOL\domain\Policies\{$($Gpo.Id.ToString().ToUpper())}"
    $auditDir = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\Audit'
    New-Item -ItemType Directory -Force -Path $auditDir | Out-Null
    Set-Content -Path (Join-Path $auditDir 'audit.csv') -Value $csv -Encoding ascii

    $auditCse = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
    $gpoDN    = "CN={$($Gpo.Id)},CN=Policies,CN=System,$domainDN"
    $adGpo    = Get-ADObject -Identity $gpoDN -Properties gPCMachineExtensionNames, versionNumber
    $blocks   = [regex]::Matches([string]$adGpo.gPCMachineExtensionNames, '\[[^\]]+\]') | ForEach-Object Value
    $blocks   = @($blocks) + $auditCse | Select-Object -Unique | Sort-Object { $_.ToUpper() }
    $newVersion = [int]$adGpo.versionNumber + 1        # low 16 bits = computer version
    Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = ($blocks -join ''); versionNumber = $newVersion }
    $gptIni = Join-Path $gpoPath 'GPT.INI'
    (Get-Content $gptIni) -replace '^Version=\d+', "Version=$newVersion" | Set-Content $gptIni -Encoding ascii
    "{0,-30} {{{1}}} version {2}, {3} subcategories" -f $Gpo.DisplayName, $Gpo.Id, $newVersion, $Map.Count
}

# --- Domain-wide GPO ---
$gpo = Get-LinkedGpo 'LAB - Security Audit Policy' $domainDN 'Audit telemetry for the AD identity detection lab'
$reg = @(
    @{ Key = 'HKLM\System\CurrentControlSet\Control\Lsa';                                   Name = 'SCENoApplyLegacyAuditPolicy';         Type = 'DWord';  Value = 1 },
    @{ Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit';       Name = 'ProcessCreationIncludeCmdLine_Enabled'; Type = 'DWord'; Value = 1 },
    @{ Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';     Name = 'EnableScriptBlockLogging';            Type = 'DWord';  Value = 1 },
    # Module logging (4103) for all modules (PingCastle A-AuditPowershell)
    @{ Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging';          Name = 'EnableModuleLogging';                 Type = 'DWord';  Value = 1 },
    @{ Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Name = '*';                                Type = 'String'; Value = '*' },
    @{ Key = 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Security';                 Name = 'MaxSize';                             Type = 'DWord';  Value = 262144 }
)
foreach ($r in $reg) {
    Set-GPRegistryValue -Guid $gpo.Id -Key $r.Key -ValueName $r.Name -Type $r.Type -Value $r.Value | Out-Null
}
Set-GpoAuditCsv $gpo $Desired

# --- Domain controllers only ---
$dcGpo = Get-LinkedGpo 'LAB - DC Audit Policy' "OU=Domain Controllers,$domainDN" 'DC-only audit settings (higher precedence than the domain-wide audit GPO)'
Set-GpoAuditCsv $dcGpo $DcDesired
