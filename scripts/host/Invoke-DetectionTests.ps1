# Invoke-DetectionTests.ps1
# Runs a live detection test suite end to end from the host:
#   1. runs the suite's test scripts on the lab VMs (over SSH)
#   2. copies the checker and the suite's expectations to the Wazuh server
#   3. waits for the alerts and prints PASS/FAIL per expectation
#
#   .\Invoke-DetectionTests.ps1 -Suite privileged_groups
#   .\Invoke-DetectionTests.ps1 -Suite dc_tampering

param(
    [Parameter(Mandatory)] [ValidateSet('privileged_groups', 'dc_tampering', 'account_changes', 'fp_tuning')] [string] $Suite,
    [int]    $WaitSeconds = 45,
    [string] $Server  = '192.168.145.128',
    [string] $KeyPath = (Join-Path $env:USERPROFILE '.ssh\ftou7_lab')
)
$ErrorActionPreference = 'Stop'
$repo   = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$invoke = Join-Path $PSScriptRoot 'Invoke-LabCommand.ps1'

$suites = @{
    privileged_groups = @( @{ Host = '192.168.145.10';  User = 'Administrator'; Script = 'Invoke-PrivGroupTests.ps1' } )
    dc_tampering      = @( @{ Host = '192.168.145.10';  User = 'Administrator'; Script = 'Invoke-TamperTests-DC.ps1' },
                           @{ Host = '192.168.145.130'; User = 'fathia';        Script = 'Invoke-TamperTests-WS.ps1' } )
    account_changes   = @( @{ Host = '192.168.145.10';  User = 'Administrator'; Script = 'Invoke-AccountTests.ps1' } )
    fp_tuning         = @( @{ Host = '192.168.145.10';  User = 'Administrator'; Script = 'Invoke-TuningTests-DC.ps1' },
                           @{ Host = '192.168.145.130'; User = 'fathia';        Script = 'Invoke-TuningTests-WS.ps1' } )
}

$start = (Get-Date).ToUniversalTime().AddSeconds(-2).ToString('yyyy-MM-ddTHH:mm:ss')
Write-Host "Suite $Suite, start $start UTC"
foreach ($step in $suites[$Suite]) {
    Write-Host "--- $($step.Script) on $($step.Host)"
    & $invoke -ComputerName $step.Host -User $step.User -ScriptPath (Join-Path $repo "scripts\windows\$($step.Script)")
    if ($LASTEXITCODE -ne 0) { throw "$($step.Script) failed on $($step.Host)" }
}

scp -i $KeyPath -o BatchMode=yes -q (Join-Path $repo 'scripts\wazuh\check_test_alerts.py') (Join-Path $repo "tests\$Suite.expect.json") "fathia@${Server}:/tmp/"
if ($LASTEXITCODE -ne 0) { throw 'Copy to the Wazuh server failed.' }
Write-Host "--- Wazuh results (waiting $WaitSeconds s for alerts)"
ssh -i $KeyPath -o BatchMode=yes "fathia@$Server" "sudo python3 /tmp/check_test_alerts.py $start /tmp/$Suite.expect.json $WaitSeconds"
exit $LASTEXITCODE
