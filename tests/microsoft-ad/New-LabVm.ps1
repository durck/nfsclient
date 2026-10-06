[CmdletBinding()]
param(
    [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'),
    [string]$VmwareRoot = 'C:/Program Files (x86)/VMware/VMware Workstation'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')

# Creates only files for this disposable lab. It does not change host networking.
$runtime = Get-LabRuntimeRoot $RuntimeRoot
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
$manifestPath = Join-Path $runtime 'lab.json'
if (Test-Path -LiteralPath $manifestPath) { throw "Lab already exists: $manifestPath" }
$diskManager = Join-Path $VmwareRoot 'vmware-vdiskmanager.exe'
if (!(Test-Path -LiteralPath $diskManager)) { throw 'VMware disk manager is unavailable.' }
$networkId = [Guid]::NewGuid().ToByteArray()
$networkId[0] = 0x52
$hex = $networkId | ForEach-Object { $_.ToString('x2') }
$pvnId = ($hex[0..7] -join ' ') + '-' + ($hex[8..15] -join ' ')
$segmentName = 'nfs-viewer-msad-' + [Guid]::NewGuid().ToString('N').Substring(0, 10)
$media = Join-Path $runtime 'media/windows-server-2025-eval.iso'
New-Item -ItemType Directory -Path (Split-Path $media) -Force | Out-Null
$machines = @()
foreach ($spec in @(
    @{ Name = 'dc'; Display = 'NFS viewer Microsoft AD lab DC'; Memory = 4096; DiskGB = 64; Guest = 'windows2022srv-64'; Controller = 'lsisas1068' },
    @{ Name = 'nfs'; Display = 'NFS viewer Microsoft AD lab Linux NFS'; Memory = 2048; DiskGB = 24; Guest = 'ubuntu-64'; Controller = 'lsilogic' }
)) {
    $machineDir = Join-Path $runtime $spec.Name
    Assert-LabRegularPath $machineDir
    New-Item -ItemType Directory -Path $machineDir -Force | Out-Null
    $disk = Join-Path $machineDir ($spec.Name + '.vmdk')
    $vmx = Join-Path $machineDir ($spec.Name + '.vmx')
    if (Test-Path -LiteralPath $vmx) { throw "Refusing to replace VM: $vmx" }
    if (Test-Path -LiteralPath $disk) { throw "Refusing to reuse an existing disk: $disk" }
    & $diskManager -c -s ($spec.DiskGB.ToString() + 'GB') -a lsilogic -t 0 $disk
    if ($LASTEXITCODE -ne 0) { throw "Disk creation failed for $($spec.Name)." }
    $iso = if ($spec.Name -eq 'dc') { $media } else { Join-Path $runtime 'media/linux-install.iso' }
    $connected = if (Test-Path -LiteralPath $iso) { 'TRUE' } else { 'FALSE' }
    $config = @"
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "21"
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
displayName = "$($spec.Display)"
guestOS = "$($spec.Guest)"
firmware = "efi"
uefi.secureBoot.enabled = "FALSE"
memsize = "$($spec.Memory)"
numvcpus = "2"
cpuid.coresPerSocket = "2"
scsi0.present = "TRUE"
scsi0.virtualDev = "$($spec.Controller)"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "$($spec.Name).vmdk"
sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.deviceType = "cdrom-image"
sata0:0.fileName = "$($iso.Replace('\', '/'))"
sata0:0.startConnected = "$connected"
ethernet0.present = "FALSE"
ethernet0.connectionType = "pvn"
ethernet0.pvnID = "$pvnId"
ethernet0.virtualDev = "e1000e"
ethernet0.addressType = "generated"
ethernet0.startConnected = "FALSE"
floppy0.present = "FALSE"
usb.present = "FALSE"
sound.present = "FALSE"
printer0.present = "FALSE"
sharedFolder.maxNum = "0"
isolation.tools.hgfs.disable = "TRUE"
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
isolation.tools.dnd.disable = "TRUE"
RemoteDisplay.vnc.enabled = "FALSE"
tools.syncTime = "FALSE"
vmci0.present = "FALSE"
mks.enable3d = "FALSE"
msg.autoAnswer = "FALSE"
"@
    [IO.File]::WriteAllText($vmx, $config + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    $machines += @{ Name = $spec.Name; Vmx = $vmx; Disk = $disk; MemoryMB = $spec.Memory }
}
$manifest = [ordered]@{
    CreatedUtc = [DateTime]::UtcNow.ToString('o')
    RuntimeRoot = $runtime
    SegmentName = $segmentName
    SegmentId = $pvnId
    Domain = 'msad.nfs.test'
    DCAddress = '192.0.2.10'
    NFSAddress = '192.0.2.20'
    PrefixLength = 24
    DefaultGateway = $null
    HostNetworkModified = $false
    NetworkState = 'NICs absent pending private-pvn verification. Never set networkName without a registered VMware name; it can select bridged networking.'
    WindowsLicenseAccepted = $false
    MicrosoftADVerified = $false
    Machines = $machines
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8
$manifest | ConvertTo-Json -Depth 4
