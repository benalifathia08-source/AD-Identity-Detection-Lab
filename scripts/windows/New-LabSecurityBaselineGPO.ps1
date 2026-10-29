# New-LabSecurityBaselineGPO.ps1
# Creates and links "LAB - Security Baseline" at the domain root. Run on DC01 as a Domain Admin. Safe to re-run.
#
#   S-OldNtlm        LAN Manager authentication level = 5 (send NTLMv2 only, refuse LM and NTLMv1)
#   A-NoGPOLLMNR     LLMNR (multicast name resolution) disabled
#   A-HardenedPaths  SYSVOL and NETLOGON require mutual authentication and integrity (UNC hardening)
#
# The LM level is a security option, which Windows stores in the GPO's GptTmpl.inf (Security Settings),
# so that file is written directly and the Security client-side extension is registered on the GPO.
# The other two are ordinary registry policies.

$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy, ActiveDirectory

$GpoName  = 'LAB - Security Baseline'
$domainDN = (Get-ADDomain).DistinguishedName

$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $GpoName -Comment 'Domain-wide hardening from PingCastle findings' }
if (-not (Get-GPInheritance -Target $domainDN).GpoLinks.Where({ $_.DisplayName -eq $GpoName })) {
    New-GPLink -Guid $gpo.Id -Target $domainDN -LinkEnabled Yes | Out-Null
}

# --- Registry policies ---
Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' -ValueName 'EnableMulticast' -Type DWord -Value 0 | Out-Null
# PowerShell execution policy RemoteSigned: local scripts run, downloaded scripts must be signed.
# Lets lab automation run script files instead of -EncodedCommand (which looks like attacker tradecraft).
$ps = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell'
Set-GPRegistryValue -Guid $gpo.Id -Key $ps -ValueName 'EnableScripts'   -Type DWord  -Value 1 | Out-Null
Set-GPRegistryValue -Guid $gpo.Id -Key $ps -ValueName 'ExecutionPolicy' -Type String -Value 'RemoteSigned' | Out-Null
$hp = 'HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
foreach ($share in '\\*\NETLOGON', '\\*\SYSVOL') {
    Set-GPRegistryValue -Guid $gpo.Id -Key $hp -ValueName $share -Type String -Value 'RequireMutualAuthentication=1, RequireIntegrity=1' | Out-Null
}

# --- Security option in GptTmpl.inf ---
$gpoPath = "$env:SystemRoot\SYSVOL\domain\Policies\{$($gpo.Id.ToString().ToUpper())}"
$secDir  = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\SecEdit'
New-Item -ItemType Directory -Force -Path $secDir | Out-Null
$inf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
'@
Set-Content -Path (Join-Path $secDir 'GptTmpl.inf') -Value $inf -Encoding Unicode

# --- Register the Security CSE and bump the computer version ---
$securityCse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
$gpoDN  = "CN={$($gpo.Id)},CN=Policies,CN=System,$domainDN"
$adGpo  = Get-ADObject -Identity $gpoDN -Properties gPCMachineExtensionNames, versionNumber
$blocks = [regex]::Matches([string]$adGpo.gPCMachineExtensionNames, '\[[^\]]+\]') | ForEach-Object Value
$blocks = @($blocks) + $securityCse | Select-Object -Unique | Sort-Object { $_.ToUpper() }
$newVersion = [int]$adGpo.versionNumber + 1
Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = ($blocks -join ''); versionNumber = $newVersion }
$gptIni = Join-Path $gpoPath 'GPT.INI'
(Get-Content $gptIni) -replace '^Version=\d+', "Version=$newVersion" | Set-Content $gptIni -Encoding ascii

"GPO       : $GpoName {$($gpo.Id)}"
"Linked to : $domainDN"
"Version   : $newVersion"
