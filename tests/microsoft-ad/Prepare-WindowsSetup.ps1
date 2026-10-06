[CmdletBinding()]
param([string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
$dc = Join-Path $runtime 'dc'
$vmx = Join-Path $dc 'dc.vmx'
$disk = Join-Path $dc 'dc.vmdk'
$media = Join-Path $runtime 'media/windows-server-2025-eval.iso'
$manifestPath = Join-Path $runtime 'lab.json'
foreach ($path in @($dc, $vmx, $disk, (Join-Path $runtime 'media'), $media, $manifestPath)) {
    Assert-LabRegularPath $path
    if (!(Test-Path -LiteralPath $path)) { throw "Missing existing lab artifact: $path" }
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$entry = @($manifest.Machines | Where-Object Name -eq 'dc')
if ($entry.Count -ne 1 -or $entry[0].Vmx -ine $vmx -or $entry[0].Disk -ine $disk -or
    $manifest.WindowsLicenseAccepted -ne $false) {
    throw 'Refusing an unknown DC or a lab that has advanced beyond the pending-license stage.'
}
$vmware = 'C:/Program Files (x86)/VMware/VMware Workstation'
$vmrun = Join-Path $vmware 'vmrun.exe'
$vmcli = Join-Path $vmware 'vmcli.exe'
function Assert-DcOff {
    $running = @(& $vmrun list)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot determine VM power state.' }
    if (@($running | Where-Object { $_ -ieq $vmx }).Count -or (Test-Path -LiteralPath ($vmx + '.lck'))) {
        throw 'The exact DC must be powered off and unlocked before media preparation.'
    }
}
function Read-Setting([string]$Config, [string]$Name) {
    $matches = [regex]::Matches($Config, '(?m)^' + [regex]::Escape($Name) + '\s*=\s*"([^"\r\n]*)"\s*$')
    if ($matches.Count -ne 1) { throw "Expected one VMX setting: $Name" }
    return $matches[0].Groups[1].Value
}
Assert-DcOff
$before = Get-Content -LiteralPath $vmx -Raw
$required = @{
    'scsi0:0.present' = 'TRUE'; 'scsi0:0.fileName' = 'dc.vmdk'
    'sata0:0.present' = 'TRUE'; 'sata0:0.deviceType' = 'cdrom-image'
    'ethernet0.connectionType' = 'pvn'; 'ethernet0.pvnID' = [string]$manifest.SegmentId
    'ethernet0.startConnected' = 'FALSE'; 'RemoteDisplay.vnc.enabled' = 'FALSE'
    'msg.autoAnswer' = 'FALSE'; 'sharedFolder.maxNum' = '0'
}
foreach ($name in $required.Keys) {
    if ((Read-Setting $before $name) -cne $required[$name]) { throw "Unexpected VMX setting: $name" }
}
if ([IO.Path]::GetFullPath((Read-Setting $before 'sata0:0.fileName')) -ine $media -or
    $before -match '(?im)^ethernet[1-9]\d*\.' -or $before -match '(?im)^ethernet0\.(networkName|vnet)\s*=' -or
    @([regex]::Matches($before, '(?im)^(?:scsi|sata|ide|nvme)\d+:\d+\.fileName\s*=')).Count -ne 2) {
    throw 'Refusing changed media, extra storage, or an unexpected network configuration.'
}
$oldConnection = Read-Setting $before 'sata0:0.startConnected'
if ($oldConnection -cnotin @('TRUE', 'FALSE')) { throw 'Unknown optical connection setting.' }
function Read-DisconnectedBackend {
    $query = (& $vmcli Ethernet query $vmx) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0) { throw 'Cannot query the DC NIC.' }
    $fields = @{
        label = 'ethernet0'; connectionStatus = 'not_connected'; connectionType = 'pvn'
        pvnID = "'$($manifest.SegmentId)'"; networkName = "''"; vnet = "''"; startConnected = 'false'
    }
    foreach ($field in $fields.Keys) {
        $values = [regex]::Matches($query, '(?m)^\s+' + $field + ': (.*)\r?$')
        if ($values.Count -ne 1 -or $values[0].Groups[1].Value.Trim() -cne $fields[$field]) {
            throw "Unexpected powered-off VMware NIC field: $field"
        }
    }
    return $query
}
$networkBefore = Read-DisconnectedBackend
$expectedHash = '7B052573BA7894C9924E3E87BA732CCD354D18CB75A883EFA9B900EA125BFD51'
if ((Get-Item -LiteralPath $media).Length -ne 8152356864L -or
    (Get-FileHash -LiteralPath $media -Algorithm SHA256).Hash -cne $expectedHash) {
    throw 'The completed Windows ISO differs from the independently verified artifact.'
}
Assert-DcOff
if ((Get-Content -LiteralPath $vmx -Raw) -cne $before) { throw 'DC configuration changed during verification.' }
$evidenceDir = Join-Path $dc ('setup-prep-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $evidenceDir -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $vmx -Destination (Join-Path $evidenceDir 'dc-before.vmx') -ErrorAction Stop
if ($oldConnection -ceq 'FALSE') {
    & $vmcli ConfigParams SetEntry 'sata0:0.startConnected' 'TRUE' $vmx
    if ($LASTEXITCODE -ne 0) { throw 'VMware failed to prepare the optical drive.' }
}
Assert-DcOff
$after = Get-Content -LiteralPath $vmx -Raw
$expectedAfter = $before.Replace('sata0:0.startConnected = "FALSE"', 'sata0:0.startConnected = "TRUE"')
# SetEntry moves the changed key to the end; VMX key order is not significant.
if ((($after -split '\r?\n' | Sort-Object -CaseSensitive) -join "`n") -cne
    (($expectedAfter -split '\r?\n' | Sort-Object -CaseSensitive) -join "`n")) {
    throw 'Unexpected VMX change; inspect the retained backup before continuing.'
}
if ((Read-Setting $after 'sata0:0.startConnected') -cne 'TRUE') { throw 'Optical drive was not prepared.' }
$networkAfter = Read-DisconnectedBackend
$networkBefore | Set-Content -LiteralPath (Join-Path $evidenceDir 'ethernet-before.yaml') -Encoding utf8
$networkAfter | Set-Content -LiteralPath (Join-Path $evidenceDir 'ethernet-off.yaml') -Encoding utf8
$result = [ordered]@{
    CheckedUtc = [DateTime]::UtcNow.ToString('o'); Vmx = $vmx; Disk = $disk
    Media = $media; MediaBytes = 8152356864L; MediaSHA256 = $expectedHash
    PoweredOff = $true; OpticalStartConnected = $true; NicConnected = $false; NicStartConnected = $false
    NetworkEvidenceScope = 'Powered-off configuration/query only; no guest traffic or new live attachment.'
    WindowsSetupBooted = $false; InstallerLicensePageObserved = $false; LicenseAccepted = $false
    Blocker = 'Native installer UI control is unavailable; screenshot endpoints and blind keystrokes are outside this lab scope.'
    NextStep = 'Open this exact VM in VMware, boot from its attached ISO with NIC disconnected, review Applicable notices and license terms personally before Accept.'
}
$result | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $evidenceDir 'evidence.json') -Encoding utf8
$result | ConvertTo-Json -Depth 3
Write-Output "Evidence: $evidenceDir"
