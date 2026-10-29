# Install-LabForest.ps1
# Promotes DC01 to the first domain controller of a new forest.
# Run it yourself in the DC01 console (PowerShell as Administrator):  C:\LabScripts\Install-LabForest.ps1
# It asks once for the DSRM password (Directory Services Restore Mode), which only you should know.
# The AD DS role is installed beforehand over SSH, so this is the only step that needs you.

$ErrorActionPreference = 'Stop'

$DomainName  = 'ftou7.internal'   # .internal is reserved for private networks (unlike .local)
$NetbiosName = 'FTOU7'

if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
}
Import-Module ADDSDeployment

$dsrm = Read-Host -AsSecureString 'Choose a DSRM password (store it somewhere safe)'

# WinThreshold = Windows Server 2016 functional level, the highest available for Server 2022
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetbiosName `
    -ForestMode WinThreshold `
    -DomainMode WinThreshold `
    -InstallDns `
    -SafeModeAdministratorPassword $dsrm `
    -Force
# The server reboots automatically when promotion finishes.
