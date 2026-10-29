# Enable-LabSSH.ps1
# One-time setup on each lab Windows VM (Win10, DC01): installs OpenSSH Server and allows
# key-only login from the lab subnet, so lab automation never needs a password.
#
# How to run: open PowerShell as Administrator inside the VM, paste this whole file, press Enter.
# The & { } wrapper makes any error stop the whole script, even when pasted into a console.

& {
    $ErrorActionPreference = 'Stop'

    $PublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGdQyHtaOwvuzT9tPSf05Hh+R7grs1CSLJ6qUDegW20s ftou7-lab-automation'
    $LabSubnet = '192.168.145.0/24'

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw 'Run this in PowerShell opened with "Run as administrator".' }

    # Install OpenSSH Server (Windows optional feature; needs internet through VMware NAT)
    $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
    if ($cap.State -ne 'Installed') {
        Write-Host 'Installing OpenSSH Server (can take a few minutes)...'
        Add-WindowsCapability -Online -Name $cap.Name | Out-Null
    }
    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd

    # Members of Administrators read keys from this file, not from ~\.ssh\authorized_keys.
    # SIDs are used so this works on English and French Windows alike.
    $keyFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    Set-Content -Path $keyFile -Value $PublicKey -Encoding ascii
    icacls $keyFile /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null

    # Key-only login
    $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    (Get-Content $cfg) -replace '^#?\s*PasswordAuthentication\s+.*$', 'PasswordAuthentication no' |
        Set-Content -Path $cfg -Encoding ascii

    # PowerShell as the SSH shell instead of cmd.exe
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
        -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null

    # Only accept SSH from the lab subnet
    $rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
    if ($rule) {
        Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Enabled True -Profile Any -RemoteAddress $LabSubnet
    } else {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (lab subnet)' `
            -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any -RemoteAddress $LabSubnet | Out-Null
    }

    Restart-Service sshd

    $os = Get-CimInstance Win32_OperatingSystem
    Write-Host ''
    Write-Host '=== Lab SSH ready ===' -ForegroundColor Green
    Write-Host ("Computer : {0}" -f $env:COMPUTERNAME)
    Write-Host ("User     : {0}" -f $env:USERNAME)
    Write-Host ("Edition  : {0}" -f $os.Caption)
    Write-Host ("IPv4     : {0}" -f ((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.145.*' }).IPAddress -join ', '))
    if ($os.Caption -match 'Home') {
        Write-Warning 'Windows Home cannot join a domain. The workstation needs a Pro or Enterprise edition.'
    }
}
