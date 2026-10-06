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
$manifest = Get-Content -LiteralPath (Join-Path $runtime 'lab.json') -Raw | ConvertFrom-Json
$vmx = Join-Path $runtime 'nfs/nfs.vmx'
$disk = Join-Path $runtime 'nfs/ubuntu-os.vmdk'
$iso = Join-Path $runtime 'linux-media/packages.iso'
foreach ($path in @((Join-Path $runtime 'nfs'),(Join-Path $runtime 'linux-media'),$vmx,$disk,$iso)) { Assert-LabRegularPath $path }
$entry = @($manifest.Machines | Where-Object Name -eq 'nfs')
if ($entry.Count -ne 1 -or ![string]::Equals($entry[0].Vmx,$vmx,[StringComparison]::OrdinalIgnoreCase) -or ![string]::Equals($entry[0].Disk,$disk,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected Linux guest manifest.' }
$running = @(& (Join-Path $VmwareRoot 'vmrun.exe') list)
if ($LASTEXITCODE -ne 0) { throw 'Could not verify VM power state.' }
if (@($running | Where-Object { [string]::Equals($_,$vmx,[StringComparison]::OrdinalIgnoreCase) }).Count) { throw 'Package media attachment requires the existing Linux VM powered off.' }
$metadata = Get-Content -LiteralPath (Join-Path $runtime 'linux-media/packages.metadata.json') -Raw | ConvertFrom-Json
if (![string]::Equals($metadata.ISO,$iso,[StringComparison]::OrdinalIgnoreCase) -or (Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash -ne $metadata.SHA256) { throw 'Package ISO differs from validated media.' }
$config = Get-Content -LiteralPath $vmx -Raw
if ($config -notmatch '(?m)^scsi0:0.fileName = "ubuntu-os.vmdk"\s*$' -or $config -notmatch '(?m)^ethernet0.startConnected = "FALSE"\s*$' -or $config -notmatch '(?m)^ethernet0.connectionType = "pvn"\s*$' -or $config -notmatch ('(?m)^ethernet0.pvnID = "' + [regex]::Escape([string]$manifest.SegmentId) + '"\s*$') -or $config -match '(?im)^ethernet\d+\.networkName\s*=' -or $config -match '(?im)^ethernet[1-9]\d*\.present = "TRUE"\s*$') { throw 'Unexpected Linux disk or network configuration.' }
if ([regex]::Matches($config,'(?m)^sata0:0.fileName = ').Count -ne 1) { throw 'Expected exactly one existing optical drive.' }
$previous = [regex]::Match($config,'(?m)^sata0:0.fileName = "([^"]+)"').Groups[1].Value
$original = (Join-Path $runtime 'linux-media/seed.iso').Replace('\','/')
if ($previous -ne $original) { throw 'Refusing to replace an unexpected or already attached installation datasource.' }
$backup = Join-Path $runtime 'nfs/before-packages.vmx'
Assert-LabRegularPath $backup
if (Test-Path -LiteralPath $backup) { throw 'Previous package attachment exists; inspect it instead of overwriting the backup.' }
[IO.File]::WriteAllText($backup,$config,[Text.UTF8Encoding]::new($false))
$config = [regex]::Replace($config,'(?m)^sata0:0.fileName = .*$',('sata0:0.fileName = "'+$iso.Replace('\','/')+'"'))
[IO.File]::WriteAllText($vmx,$config,[Text.UTF8Encoding]::new($false))
Write-Output 'Package ISO attached to the existing powered-off Linux VM; original configuration retained. NIC remains disconnected.'
