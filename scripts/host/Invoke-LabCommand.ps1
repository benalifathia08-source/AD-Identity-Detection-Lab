# Invoke-LabCommand.ps1
# Runs PowerShell on a lab Windows VM over SSH with the lab key.
#
#   .\Invoke-LabCommand.ps1 -ComputerName 192.168.145.130 -Command 'hostname'
#   .\Invoke-LabCommand.ps1 -ComputerName 192.168.145.130 -ScriptPath .\check.ps1
#
# The command is written to a script file, copied to C:\LabScripts\run\ on the VM, run directly by the
# SSH session's PowerShell, then deleted. An earlier version passed it with -EncodedCommand, which made
# Sysmon/Wazuh raise "PowerShell executed a base64 encoded command" (rule 92057, level 12) on every call:
# admin tooling should not look like attacker tradecraft. Requires execution policy RemoteSigned
# (set domain-wide by the "LAB - Security Baseline" GPO).

param(
    [Parameter(Mandatory)] [string] $ComputerName,
    [string] $Command,
    [string] $ScriptPath,
    [string] $User    = 'fathia',
    [string] $KeyPath = (Join-Path $env:USERPROFILE '.ssh\ftou7_lab')
)
$ErrorActionPreference = 'Stop'

if ($ScriptPath) { $Command = Get-Content -Raw -Path $ScriptPath }
if (-not $Command) { throw 'Pass -Command or -ScriptPath.' }

# Hide progress bars and merge every output stream into plain text (no CLIXML noise over SSH)
$body = "`$ProgressPreference = 'SilentlyContinue'`r`n& {`r`n$Command`r`n} *>&1 | Out-String -Width 250 -Stream`r`n"

$name   = "lab-$([guid]::NewGuid().ToString('N')).ps1"
$local  = Join-Path $env:TEMP $name
$remote = "C:\LabScripts\run\$name"
[IO.File]::WriteAllText($local, $body, (New-Object Text.UTF8Encoding($true)))   # BOM so PowerShell 5.1 reads UTF-8

$sshOpts = @('-i', $KeyPath, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', '-o', 'StrictHostKeyChecking=accept-new')
try {
    # First use on a host: create the folder locked to Administrators/SYSTEM (C:\ defaults let any
    # signed-in user write there; see scripts/windows/Protect-LabFolders.ps1)
    ssh @sshOpts "$User@$ComputerName" "if (-not (Test-Path C:\LabScripts\run)) { New-Item -ItemType Directory -Force -Path C:\LabScripts\run | Out-Null; icacls C:\LabScripts /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /T /Q | Out-Null }"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    scp @sshOpts -q $local "${User}@${ComputerName}:C:/LabScripts/run/$name"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Remove-Item $local -Force -ErrorAction SilentlyContinue
}

ssh @sshOpts "$User@$ComputerName" "try { & '$remote'; `$rc = [int](-not `$?) } catch { `$_ | Out-String; `$rc = 1 } finally { Remove-Item '$remote' -Force -ErrorAction SilentlyContinue }; exit `$rc"
exit $LASTEXITCODE
