# Test-LabSecurityBaseline.ps1
# Refreshes Group Policy and checks the "LAB - Security Baseline" settings on this machine.

gpupdate /target:computer /force | Out-Null
function Check($name, $actual, $expected) {
    '{0,-4} {1,-40} {2}' -f ($(if ("$actual" -eq "$expected") { 'OK' } else { 'FAIL' })), $name, $actual
}
$lsa = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa'
Check 'LmCompatibilityLevel (5 = NTLMv2 only)' $lsa.LmCompatibilityLevel 5
$dns = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
Check 'LLMNR EnableMulticast (0 = off)' $dns.EnableMulticast 0
$hp = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -ErrorAction SilentlyContinue
Check 'Hardened path \\*\SYSVOL'   $hp.'\\*\SYSVOL'   'RequireMutualAuthentication=1, RequireIntegrity=1'
Check 'Hardened path \\*\NETLOGON' $hp.'\\*\NETLOGON' 'RequireMutualAuthentication=1, RequireIntegrity=1'
$ml = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue
Check 'PowerShell module logging' $ml.EnableModuleLogging 1
