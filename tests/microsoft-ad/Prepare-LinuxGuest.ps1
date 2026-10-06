[CmdletBinding()]
param(
    [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'),
    [string]$VmwareRoot = 'C:/Program Files (x86)/VMware/VMware Workstation'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
Assert-LinuxNotDomainOwned $runtime
$status = & (Join-Path $PSScriptRoot 'Get-LinuxMedia.ps1') -RuntimeRoot $runtime -Status | ConvertFrom-Json
if (!$status.Ready) { throw 'The signed Ubuntu image download and checksum verification must finish first.' }
$manifestPath = Join-Path $runtime 'lab.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$machine = @($manifest.Machines | Where-Object Name -eq 'nfs')
$vmDir = Join-Path $runtime 'nfs'
$vmx = Join-Path $vmDir 'nfs.vmx'
Assert-LabRegularPath $vmDir
Assert-LabRegularPath $vmx
if ($machine.Count -ne 1 -or ![string]::Equals($machine[0].Vmx,$vmx,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected Linux VM manifest path.' }
$running = @(& (Join-Path $VmwareRoot 'vmrun.exe') list)
if ($LASTEXITCODE -ne 0) { throw 'Could not verify VMware power state.' }
if (@($running | Where-Object { [string]::Equals($_,$vmx,[StringComparison]::OrdinalIgnoreCase) }).Count) { throw 'Power off the dedicated Linux VM before preparing its boot disk.' }
$source = Join-Path $runtime 'linux-media/noble-server-cloudimg-amd64.vmdk'
$disk = Join-Path $vmDir 'ubuntu-os.vmdk'
$seed = Join-Path $runtime 'linux-media/seed.iso'
$serial = Join-Path $vmDir 'serial.log'
foreach ($path in @($source,$disk,$seed,$serial)) { Assert-LabRegularPath $path }
if (Test-Path -LiteralPath $disk) { throw 'Refusing to overwrite an existing Ubuntu guest disk.' }
if (!(Test-Path -LiteralPath $seed)) { throw 'Generate and validate the offline NoCloud seed first.' }
$seedProof = Get-Content -LiteralPath (Join-Path $runtime 'linux-media/seed.metadata.json') -Raw | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $seed -Algorithm SHA256).Hash -ne $seedProof.SHA256) { throw 'The seed ISO no longer matches its validated metadata.' }
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'c1655a37ff4141e4f16effb7364a640188cc17ec7dfc869a1283aa724dcd6bc1') { throw 'The Ubuntu source image changed after verification.' }
$config = Get-Content -LiteralPath $vmx -Raw
if ($config -notmatch '(?m)^scsi0:0.fileName = "nfs.vmdk"\s*$') { throw 'The prepared blank Linux disk is no longer attached; refusing replacement.' }
if ($config -notmatch '(?m)^ethernet0.startConnected = "FALSE"\s*$' -or $config -notmatch '(?m)^ethernet0.connectionType = "pvn"\s*$' -or $config -match '(?im)^ethernet\d+\.networkName\s*=') { throw 'Unexpected Linux VM network configuration.' }
$diskManager = Join-Path $VmwareRoot 'vmware-vdiskmanager.exe'
& $diskManager -r $source -t 0 $disk
if ($LASTEXITCODE -ne 0) { throw 'VMware image conversion failed; no VM attachment was changed.' }
& $diskManager -x 24GB $disk
if ($LASTEXITCODE -ne 0) { throw 'Could not expand the dedicated guest disk.' }
$config = $config -replace '(?m)^scsi0:0.fileName = "nfs.vmdk"\s*$', 'scsi0:0.fileName = "ubuntu-os.vmdk"'
$config = [regex]::Replace($config,'(?m)^sata0:0.fileName = .*\r?\n',('sata0:0.fileName = "' + $seed.Replace('\','/') + '"' + [Environment]::NewLine))
$config = $config -replace '(?m)^sata0:0.startConnected = "FALSE"\s*$', 'sata0:0.startConnected = "TRUE"'
$config += @"

serial0.present = "TRUE"
serial0.fileType = "file"
serial0.fileName = "$($serial.Replace('\','/'))"
serial0.startConnected = "TRUE"
serial0.yieldOnMsrRead = "TRUE"
rtc.diffFromUTC = "0"
"@
[IO.File]::WriteAllText($vmx,$config+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
$machine[0].Disk = $disk
$manifest | Add-Member -NotePropertyName LinuxState -NotePropertyValue 'Verified Ubuntu cloud disk and offline seed attached; boot pending; no AD join or NFS configuration.' -Force
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output 'Verified Ubuntu disk and seed attached only to the existing NFS VM. Original blank disk retained; NIC stays disconnected until explicitly verified.'
