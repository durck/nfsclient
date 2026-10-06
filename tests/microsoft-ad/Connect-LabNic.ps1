[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('dc','nfs')][string]$Machine,
    [Parameter(Mandatory)][ValidateSet('Prepare','Connect')][string]$Action,
    [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'),
    [string]$VmwareRoot = 'C:/Program Files (x86)/VMware/VMware Workstation'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
$manifest = Get-Content -LiteralPath (Join-Path $runtime 'lab.json') -Raw | ConvertFrom-Json
$machineDir = Join-Path $runtime $Machine
Assert-LabRegularPath $machineDir
$vmx = Join-Path $machineDir ($Machine + '.vmx')
Assert-LabRegularPath $vmx
$entry = @($manifest.Machines | Where-Object Name -eq $Machine)
if ($entry.Count -ne 1 -or ![string]::Equals($entry[0].Vmx, $vmx, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The VM path does not match the dedicated lab manifest.'
}
$pvn = [string]$manifest.SegmentId
if ($pvn -notmatch '^[0-9a-f]{2}( [0-9a-f]{2}){7}-[0-9a-f]{2}( [0-9a-f]{2}){7}$') { throw 'Invalid private segment ID.' }
$config = Get-Content -LiteralPath $vmx -Raw
if ($config -match '(?im)^ethernet\d+\.networkName\s*=' -or
    $config -notmatch '(?m)^ethernet0\.connectionType = "pvn"\s*$' -or
    $config -notmatch '(?m)^ethernet0\.startConnected = "FALSE"\s*$' -or
    $config -notmatch ('(?m)^ethernet0\.pvnID = "' + [regex]::Escape($pvn) + '"\s*$') -or
    $config -match '(?im)^ethernet[1-9]\d*\.present = "TRUE"\s*$') {
    throw 'Refusing a VM with an unverified network, named network, extra NIC or automatic connection.'
}
$vmrun = Join-Path $VmwareRoot 'vmrun.exe'
$vmcli = Join-Path $VmwareRoot 'vmcli.exe'
$running = @(& $vmrun list)
if ($LASTEXITCODE -ne 0) { throw 'Could not list running VMs.' }
$isRunning = @($running | Where-Object { [string]::Equals($_, $vmx, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 1
if ($Action -eq 'Prepare') {
    if ($isRunning) { throw 'Power off the dedicated guest before preparing its NIC.' }
    & $vmcli ConfigParams SetEntry ethernet0.present TRUE $vmx
    if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the disconnected NIC.' }
    Write-Output 'Dedicated NIC present, startConnected remains FALSE. Start the guest separately, then use -Action Connect.'
    return
}
if (!$isRunning) { throw 'Start the dedicated VM separately with its NIC disconnected before connecting it.' }
function Assert-PrivateBackend {
    $query = (& $vmcli Ethernet query $vmx) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0 -or $query -notmatch '(?m)^\s+connectionType: pvn\s*$' -or
        $query -notmatch ('(?m)^\s+pvnID: ''' + [regex]::Escape($pvn) + '''\s*$') -or
        $query -notmatch '(?m)^\s+networkName: ''''\s*$' -or $query -notmatch '(?m)^\s+vnet: ''''\s*$') {
        throw 'Running VMware backend is not the expected isolated pvn.'
    }
    return $query
}
Assert-PrivateBackend | Out-Null
& $vmrun connectNamedDevice $vmx ethernet0
if ($LASTEXITCODE -ne 0) { throw 'VMware failed to connect the private NIC.' }
try {
    $evidence = Assert-PrivateBackend
    if ($evidence -notmatch '(?m)^\s+connectionStatus: connected\s*$') { throw 'NIC is not connected.' }
    $evidence | Set-Content -LiteralPath (Join-Path $machineDir 'network-evidence.yaml') -Encoding utf8
    Write-Output "Connected $Machine only to the verified private pvn. startConnected remains FALSE."
} catch {
    & $vmrun disconnectNamedDevice $vmx ethernet0 | Out-Null
    throw
}
