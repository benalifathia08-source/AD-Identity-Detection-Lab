# Test-LabAuditPolicy.ps1
# Refreshes Group Policy and reports whether the lab audit settings are in effect on this machine.
# Run on DC01 or any workstation (over SSH is fine).

gpupdate /target:computer /force | Out-Null

$expected = [ordered]@{
    'Credential Validation'              = 'Success and Failure'
    'Kerberos Authentication Service'    = 'Success and Failure'
    'Kerberos Service Ticket Operations' = 'Success and Failure'
    'User Account Management'            = 'Success and Failure'
    'Security Group Management'          = 'Success'
    'Process Creation'                   = 'Success'
    'DPAPI Activity'                     = 'Success'
    # DCs only (LAB - DC Audit Policy); workstations: No Auditing
    'Sensitive Privilege Use'            = $(if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { 'Success' } else { 'No Auditing' })
    'Directory Service Access'           = 'Success and Failure'
    'Directory Service Changes'          = 'Success'
    'Logon'                              = 'Success and Failure'
    'Special Logon'                      = 'Success'
    'Other Object Access Events'         = 'Success and Failure'
    'Audit Policy Change'                = 'Success'
    'Security System Extension'          = 'Success'
}
# auditpol /r gives CSV: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
$actual = @{}
auditpol /get /category:* /r | ConvertFrom-Csv | ForEach-Object { $actual[$_.Subcategory.Trim()] = $_.'Inclusion Setting'.Trim() }

$fail = 0
foreach ($k in $expected.Keys) {
    $ok = $actual[$k] -eq $expected[$k]
    if (-not $ok) { $fail++ }
    '{0,-4} {1,-36} {2}' -f ($(if ($ok) { 'OK' } else { 'FAIL' })), $k, $actual[$k]
}
$cmd = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
$sbl = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$sce = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
$max = (Get-WinEvent -ListLog Security).MaximumSizeInBytes / 1MB
'{0,-4} {1,-36} {2}' -f ($(if ($cmd -eq 1) { 'OK' } else { 'FAIL' })), '4688 command line', $cmd
'{0,-4} {1,-36} {2}' -f ($(if ($sbl -eq 1) { 'OK' } else { 'FAIL' })), 'Script Block Logging', $sbl
'{0,-4} {1,-36} {2}' -f ($(if ($sce -eq 1) { 'OK' } else { 'FAIL' })), 'Force subcategory settings', $sce
'{0,-4} {1,-36} {2} MB' -f ($(if ($max -ge 256) { 'OK' } else { 'FAIL' })), 'Security log size', $max
"$env:COMPUTERNAME : $fail audit subcategory mismatches"
