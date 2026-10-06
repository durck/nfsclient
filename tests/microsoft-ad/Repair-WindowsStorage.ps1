# Repair the prepared, uninstalled DC only. No power, disk or NIC changes.
[CmdletBinding()]
param([string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
$dc = Join-Path $runtime 'dc'
$vmx = Join-Path $dc 'dc.vmx'
$disk = Join-Path $dc 'dc.vmdk'
$manifestPath = Join-Path $runtime 'lab.json'
foreach ($path in @($dc,$vmx,$disk,$manifestPath)) {
    Assert-LabRegularPath $path
    if (!(Test-Path -LiteralPath $path)) { throw "Missing lab path: $path" }
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$entry = @($manifest.Machines | Where-Object Name -eq 'dc')
if ($entry.Count -ne 1 -or $entry[0].Vmx -ine $vmx -or $entry[0].Disk -ine $disk) { throw 'Unexpected DC identity.' }
$vmware = 'C:/Program Files (x86)/VMware/VMware Workstation'
function Assert-DcOff {
    $running = @(& (Join-Path $vmware 'vmrun.exe') list)
    if ($LASTEXITCODE -or @($running | Where-Object { $_ -ieq $vmx }).Count -or (Test-Path -LiteralPath ($vmx + '.lck'))) {
        throw 'DC must be fully powered off and unlocked before changing its storage controller.'
    }
}
Assert-DcOff
$before = Get-Content -LiteralPath $vmx -Raw
function Read-Setting([string]$config, [string]$key) {
    $found = [regex]::Matches($config, '(?m)^' + [regex]::Escape($key) + '\s*=\s*"([^"\r\n]*)"\s*$')
    if ($found.Count -ne 1) { throw "Expected exactly one setting: $key" }
    $found[0].Groups[1].Value
}
foreach ($pair in @{
    'scsi0.present'='TRUE'; 'scsi0:0.present'='TRUE'; 'scsi0:0.fileName'='dc.vmdk'
    'ethernet0.connectionType'='pvn'; 'ethernet0.pvnID'=[string]$manifest.SegmentId
    'ethernet0.startConnected'='FALSE'; 'displayName'='NFS viewer Microsoft AD lab DC'
}.GetEnumerator()) {
    if ((Read-Setting $before $pair.Key) -cne $pair.Value) { throw "Unexpected setting: $($pair.Key)" }
}
$old = Read-Setting $before 'scsi0.virtualDev'
if ($old -cnotin @('lsilogic','lsisas1068')) { throw 'Unexpected controller; manual review required.' }
if ($old -ceq 'lsisas1068') { Write-Output 'DC already uses LSI Logic SAS; no changes.'; return }
$backup = Join-Path $dc ('storage-fix-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $backup | Out-Null
Copy-Item -LiteralPath $vmx -Destination (Join-Path $backup 'before.vmx')
$diskHash = (Get-FileHash -LiteralPath $disk -Algorithm SHA256).Hash
Assert-DcOff
if ((Get-Content -LiteralPath $vmx -Raw) -cne $before) { throw 'VMX changed during verification.' }
& (Join-Path $vmware 'vmcli.exe') ConfigParams SetEntry 'scsi0.virtualDev' 'lsisas1068' $vmx
if ($LASTEXITCODE) { throw 'VMware rejected controller update.' }
Assert-DcOff
$after = Get-Content -LiteralPath $vmx -Raw
$expected = $before.Replace('scsi0.virtualDev = "lsilogic"','scsi0.virtualDev = "lsisas1068"')
if ((($after -split '\r?\n' | Sort-Object -CaseSensitive) -join "`n") -cne
    (($expected -split '\r?\n' | Sort-Object -CaseSensitive) -join "`n")) { throw "Unexpected VMX change; backup: $backup" }
if ((Get-FileHash -LiteralPath $disk -Algorithm SHA256).Hash -cne $diskHash) { throw 'Virtual disk changed during controller repair.' }
Copy-Item -LiteralPath $vmx -Destination (Join-Path $backup 'after.vmx')
$result = [ordered]@{ CheckedUtc=[DateTime]::UtcNow.ToString('o'); Vmx=$vmx; Before=$old; After='lsisas1068'; DiskSHA256Unchanged=$diskHash; OnlyControllerChanged=$true; GuestStarted=$false; InstallerDiskVisible=$null }
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backup 'verification.json') -Encoding utf8
$result | ConvertTo-Json
