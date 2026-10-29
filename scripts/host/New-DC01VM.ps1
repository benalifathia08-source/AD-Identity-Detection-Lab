# New-DC01VM.ps1
# Creates the DC01 virtual machine (Windows Server 2022 Evaluation) in VMware Workstation.
# Runs on the host. Does not install Windows; it only builds the VM and attaches the ISO.

param(
    [string] $IsoPath,
    [string] $VmRoot   = (Join-Path $env:USERPROFILE 'Documents\Virtual Machines\DC01'),
    [int]    $MemoryMB = 4096,
    [int]    $Cpus     = 2,
    [int]    $DiskGB   = 60
)
$ErrorActionPreference = 'Stop'

$vmwareDir   = 'C:\Program Files\VMware\VMware Workstation'
$vdiskmanager = Join-Path $vmwareDir 'vmware-vdiskmanager.exe'

if (-not $IsoPath) {
    $IsoPath = Get-ChildItem -Path (Join-Path $env:USERPROFILE 'Desktop'), (Join-Path $env:USERPROFILE 'Downloads') `
        -Filter '*SERVER_EVAL*.iso' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $IsoPath -or -not (Test-Path $IsoPath)) {
    throw 'Windows Server 2022 Evaluation ISO not found on Desktop or Downloads. Pass -IsoPath.'
}

$vmx  = Join-Path $VmRoot 'DC01.vmx'
$vmdk = Join-Path $VmRoot 'DC01.vmdk'
if (Test-Path $vmx) { throw "DC01 already exists at $vmx" }

New-Item -ItemType Directory -Force -Path $VmRoot | Out-Null
& $vdiskmanager -c -s "${DiskGB}GB" -a lsilogic -t 0 $vmdk | Out-Null
if ($LASTEXITCODE -ne 0) { throw "vmware-vdiskmanager failed with exit code $LASTEXITCODE" }

# windows2019srvnext-64 is VMware's guest OS id for Windows Server 2022
$config = @"
.encoding = "windows-1252"
config.version = "8"
virtualHW.version = "21"
displayName = "DC01"
guestOS = "windows2019srvnext-64"
firmware = "efi"
uefi.secureBoot.enabled = "TRUE"
memsize = "$MemoryMB"
numvcpus = "$Cpus"
cpuid.coresPerSocket = "$Cpus"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
vmci0.present = "TRUE"
hpet0.present = "TRUE"
nvme0.present = "TRUE"
nvme0:0.present = "TRUE"
nvme0:0.fileName = "DC01.vmdk"
sata0.present = "TRUE"
sata0:1.present = "TRUE"
sata0:1.deviceType = "cdrom-image"
sata0:1.fileName = "$IsoPath"
sata0:1.startConnected = "TRUE"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "e1000e"
ethernet0.addressType = "generated"
usb.present = "TRUE"
ehci.present = "TRUE"
usb_xhci.present = "TRUE"
floppy0.present = "FALSE"
mks.enable3d = "FALSE"
tools.syncTime = "FALSE"
tools.upgrade.policy = "useGlobal"
annotation = "AD Identity Detection Lab - domain controller. Static IP 192.168.145.10."
"@
Set-Content -Path $vmx -Value $config -Encoding ascii

Write-Host "DC01 created: $vmx"
Write-Host "ISO attached: $IsoPath"
