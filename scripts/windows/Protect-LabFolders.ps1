# Protect-LabFolders.ps1
# Locks the lab working folders to Administrators and SYSTEM only. Run on each lab VM as an administrator.
#
# Why: folders created directly under C:\ inherit the root's defaults. On Windows 10, "Authenticated Users"
# get Modify on them; on Server, "Users" can create files. These folders hold scripts that administrators
# and SYSTEM tasks run, plus Security log backups, so an ordinary signed-in user could plant or swap a
# script (privilege escalation, CWE-732) or read the backups. Ownership is reset too, so a file planted
# earlier by a user cannot stay under that user's control.

$ErrorActionPreference = 'Stop'
$admins = '*S-1-5-32-544'   # BUILTIN\Administrators (SID works on any OS language)
$system = '*S-1-5-18'       # NT AUTHORITY\SYSTEM

foreach ($d in 'C:\LabScripts', 'C:\LabMedia', 'C:\LabBackups') {
    if (-not (Test-Path $d)) { continue }
    icacls $d /setowner $admins /T /C /Q | Out-Null
    icacls $d /inheritance:r /grant:r "${admins}:(OI)(CI)F" "${system}:(OI)(CI)F" /Q | Out-Null
    icacls "$d\*" /reset /T /C /Q 2>$null | Out-Null      # children inherit only the locked folder ACL
    "$d locked: " + ((Get-Acl $d).Access | ForEach-Object { "$($_.IdentityReference)=$($_.FileSystemRights)" }) -join ', '
}
