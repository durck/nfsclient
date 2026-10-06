[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')][string]$RunId,
    [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'),
    [string]$VmwareRoot = 'C:/Program Files (x86)/VMware/VMware Workstation'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
Assert-LinuxNotDomainOwned $runtime
$run = Join-Path (Join-Path $runtime 'kernel-runs') $RunId
foreach ($path in @((Join-Path $runtime 'kernel-runs'),$run)) { Assert-LabRegularPath $path }
$metadata = Get-Content -LiteralPath (Join-Path $run 'metadata.json') -Raw | ConvertFrom-Json
$iso = Join-Path $run 'kernel.iso'
Assert-LabRegularPath $iso
if ($metadata.RunId -ne $RunId -or ![string]::Equals($metadata.ISO,$iso,[StringComparison]::OrdinalIgnoreCase) -or (Get-FileHash -LiteralPath $iso).Hash -ne $metadata.ISOSHA256) { throw 'Kernel media metadata/hash mismatch.' }
$manifest = Get-Content -LiteralPath (Join-Path $runtime 'lab.json') -Raw | ConvertFrom-Json
$vmx = Join-Path $runtime 'nfs/nfs.vmx'
$disk = Join-Path $runtime 'nfs/ubuntu-os.vmdk'
$serial = Join-Path $runtime 'nfs/serial.log'
foreach ($path in @((Join-Path $runtime 'nfs'),$vmx,$disk,$serial)) { Assert-LabRegularPath $path }
$entry = @($manifest.Machines | Where-Object Name -eq 'nfs')
if ($entry.Count -ne 1 -or ![string]::Equals($entry[0].Vmx,$vmx,[StringComparison]::OrdinalIgnoreCase) -or ![string]::Equals($entry[0].Disk,$disk,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected Linux VM manifest.' }
$vmrun = Join-Path $VmwareRoot 'vmrun.exe'
function Is-LabRunning {
    $running = @(& $vmrun list)
    if ($LASTEXITCODE) { throw 'Cannot check VMware power state.' }
    return @($running | Where-Object { [string]::Equals($_,$vmx,[StringComparison]::OrdinalIgnoreCase) }).Count -eq 1
}
if (Is-LabRunning) { throw 'Existing Linux VM must be off before attaching a kernel fixture.' }
& (Join-Path $PSScriptRoot 'Connect-LabNic.ps1') -Machine nfs -Action Prepare -RuntimeRoot $runtime -VmwareRoot $VmwareRoot
$config = Get-Content -LiteralPath $vmx -Raw
if ($config -notmatch '(?m)^scsi0:0.fileName = "ubuntu-os.vmdk"\s*$' -or [regex]::Matches($config,'(?m)^sata0:0.fileName = ').Count -ne 1) { throw 'Unexpected existing guest disk or optical media.' }
$previous = [regex]::Match($config,'(?m)^sata0:0.fileName = "([^"]+)"').Groups[1].Value.Replace('/','\')
$packageIso = [IO.Path]::GetFullPath((Join-Path $runtime 'linux-media/packages.iso'))
$allowedPrevious = [string]::Equals($previous,$packageIso,[StringComparison]::OrdinalIgnoreCase)
if (!$allowedPrevious) {
    $known = @(Get-ChildItem -LiteralPath (Join-Path $runtime 'kernel-runs') -Directory | ForEach-Object { Join-Path $_.FullName 'kernel.iso' })
    $allowedPrevious = @($known | Where-Object { [string]::Equals($_,$previous,[StringComparison]::OrdinalIgnoreCase) }).Count -eq 1
}
if (!$allowedPrevious -or [string]::Equals($previous,$iso,[StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing unexpected or already-used guest datasource.' }
$backup = Join-Path $run 'before.vmx'
if (Test-Path -LiteralPath $backup) { throw 'Run already started; inspect existing evidence instead of rerunning it.' }
[IO.File]::WriteAllText($backup,$config,[Text.UTF8Encoding]::new($false))
$config = [regex]::Replace($config,'(?m)^sata0:0.fileName = .*$',('sata0:0.fileName = "'+$iso.Replace('\','/')+'"'))
[IO.File]::WriteAllText($vmx,$config,[Text.UTF8Encoding]::new($false))
$started = $false
try {
    & $vmrun -T ws start $vmx nogui
    if ($LASTEXITCODE) { throw 'Existing Linux guest did not start.' }
    $started = $true
    & (Join-Path $PSScriptRoot 'Connect-LabNic.ps1') -Machine nfs -Action Connect -RuntimeRoot $runtime -VmwareRoot $VmwareRoot
    Copy-Item -LiteralPath (Join-Path $runtime 'nfs/network-evidence.yaml') -Destination (Join-Path $run 'network-evidence.yaml')
    Write-Output "Kernel NFS run $RunId started on verified private pvn; waiting for guest cleanup and poweroff."
    # Include the optional separate six-minute protected-UDP diagnostic, while
    # preserving the original bound for the existing profile family.
    $hasDiagnostic = $metadata.PSObject.Properties.Name -contains 'NFS3UDPDiagnostic' -and $metadata.NFS3UDPDiagnostic
    $deadline = [DateTime]::UtcNow.AddMinutes($(if ($hasDiagnostic) { 36 } else { 29 }))
    while (Is-LabRunning) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Kernel fixture exceeded the bounded guest runtime.' }
        [Threading.Thread]::Sleep(2000)
    }
    $prefix = 'NFS_LAB_KERNEL_EVIDENCE '
    $evidence = @(Get-Content -LiteralPath $serial | Where-Object { $_.StartsWith($prefix) } | ForEach-Object { $_.Substring($prefix.Length) | ConvertFrom-Json } | Where-Object { $_.PSObject.Properties.Name -contains 'run_id' -and $_.run_id -eq $RunId })
    if ($evidence.Count -ne 1) { throw 'Guest powered off without one matching kernel evidence record; inspect serial.log.' }
    $evidence[0] | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $run 'evidence.json') -Encoding utf8NoBOM
    if (!$evidence[0].tests_passed -or !$evidence[0].cleanup.passed -or $evidence[0].PSObject.Properties.Name -contains 'error') { throw "Kernel fixture reported failure; see $run/evidence.json" }
    Write-Output "Kernel tests and cleanup passed; guest is off. Evidence: $run/evidence.json"
    if ($hasDiagnostic) {
        $diagnosticPassed = $evidence[0].PSObject.Properties.Name -contains 'udp_protected_diagnostic' -and $evidence[0].udp_protected_diagnostic.passed
        Write-Output "Separate protected-UDP diagnostic passed: $diagnosticPassed. This does not enable public protected UDP."
    }
} finally {
    if ($started -and (Is-LabRunning)) {
        & $vmrun disconnectNamedDevice $vmx ethernet0 | Out-Null
        & $vmrun -T ws stop $vmx soft
        if ($LASTEXITCODE) { Write-Warning 'Guest soft shutdown failed; it remains isolated with its NIC disconnected. Do not claim clean shutdown.' }
    }
}
