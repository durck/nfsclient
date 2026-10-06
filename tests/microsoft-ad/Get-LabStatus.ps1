[CmdletBinding()]
param([string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
$media = Join-Path $runtime 'media/windows-server-2025-eval.iso'
$partial = $media + '.partial'
$expected = 8152356864L
$ready = $false
$metadataPath = Join-Path $runtime 'media/windows-server-2025-eval.metadata.json'
if ((Test-Path -LiteralPath $media) -and (Test-Path -LiteralPath $metadataPath)) {
    try {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
        $ready = $metadata.Bytes -eq $expected -and $metadata.SHA256 -cmatch '^[A-Fa-f0-9]{64}$' -and
            (Get-Item -LiteralPath $media).Length -eq $expected
    } catch { $ready = $false }
}
$bytes = if (Test-Path -LiteralPath $media) { (Get-Item -LiteralPath $media).Length } elseif (Test-Path -LiteralPath $partial) { (Get-Item -LiteralPath $partial).Length } else { 0L }
$worker = $null
$workerRunning = $false
$lockHeld = $false
$lockPath = Join-Path $runtime 'media/download.lock'
if (Test-Path -LiteralPath $lockPath) {
    try {
        $probe = [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $probe.Dispose()
    } catch [IO.IOException] { $lockHeld = $true }
}
$workerPath = Join-Path $runtime 'download-worker.json'
if (Test-Path -LiteralPath $workerPath) {
    $worker = Get-Content -LiteralPath $workerPath -Raw | ConvertFrom-Json
    $process = Get-Process -Id $worker.ProcessId -ErrorAction SilentlyContinue
    if ($process) {
        $started = ([DateTime]$worker.StartedUtc).ToUniversalTime()
        $workerRunning = [Math]::Abs(($process.StartTime.ToUniversalTime() - $started).TotalSeconds) -lt 10
    }
}
$installedObservation = $null
$installedObservationPath = Join-Path $runtime 'dc/installation-observation.json'
if (Test-Path -LiteralPath $installedObservationPath) {
    Assert-LabRegularPath $installedObservationPath
    $candidate = Get-Content -LiteralPath $installedObservationPath -Raw | ConvertFrom-Json
    if ($candidate.Source -eq 'user-supplied-sconfig-screenshot' -and $candidate.WindowsInstalled -eq $true) {
        $installedObservation = $candidate
    }
}
$dcDeployment = $null
$dcDeploymentPath = Join-Path $runtime 'dc/deployment-verification.json'
if (Test-Path -LiteralPath $dcDeploymentPath) {
    Assert-LabRegularPath $dcDeploymentPath
    $candidate = Get-Content -LiteralPath $dcDeploymentPath -Raw | ConvertFrom-Json
    if ($candidate.DCDeploymentVerified -eq $true -and $candidate.Domain -eq 'msad.nfs.test' -and $candidate.DC -eq 'NFSADDC1') {
        $dcDeployment = $candidate | Select-Object CheckedUtc,DCDeploymentVerified,TestAccountsVerified,Domain,DC,Limitations
    }
}
$linuxDomain = $null
$linuxDomainPath = Join-Path $runtime 'nfs/domain-verification.json'
if (Test-Path -LiteralPath $linuxDomainPath) {
    Assert-LabRegularPath $linuxDomainPath
    $candidate = Get-Content -LiteralPath $linuxDomainPath -Raw | ConvertFrom-Json
    if ($candidate.LinuxDomainIdentityVerified -eq $true -and $candidate.Domain -eq 'msad.nfs.test') {
        $linuxDomain = $candidate | Select-Object CheckedUtc,LinuxDomainIdentityVerified,Domain,Guest,GroupChangeVerified,Limitations
    }
}
$machineKerberos = $null
$machineKerberosPath = Join-Path $runtime 'nfs/machine-kerberos-verification.json'
if (Test-Path -LiteralPath $machineKerberosPath) {
    Assert-LabRegularPath $machineKerberosPath
    $candidate = Get-Content -LiteralPath $machineKerberosPath -Raw | ConvertFrom-Json
    if ($candidate.MachineKerberosVerified -eq $true -and $candidate.Domain -eq 'msad.nfs.test' -and $candidate.Profiles -eq 4) {
        $machineKerberos = $candidate | Select-Object CheckedUtc,MachineKerberosVerified,Domain,Profiles,ClientOS,OrdinaryUserVerified,MicrosoftADNFSVerified,Limitations
    }
}
[ordered]@{
    RuntimeRoot = $runtime
    CheckedUtc = [DateTime]::UtcNow.ToString('o')
    MediaBytes = $bytes
    ExpectedMediaBytes = $expected
    DownloadPercent = [Math]::Round(100.0 * $bytes / $expected, 2)
    MediaReady = ($ready -and $bytes -eq $expected)
    DownloadWorkerRunning = $workerRunning
    DownloadLockHeld = $lockHeld
    DownloadWorker = $worker
    DownloadErrorLog = (Join-Path $runtime 'media-download.stderr.log')
    WindowsInstallationObservation = $installedObservation
    DCDeploymentEvidence = $dcDeployment
    LinuxDomainEvidence = $linuxDomain
    MachineKerberosEvidence = $machineKerberos
    LinuxReservedForAD = (Test-Path -LiteralPath (Join-Path $runtime 'nfs/domain-state.json'))
    LicenseAcceptance = if ($installedObservation) { 'User completed Windows installation; no automated license acceptance performed.' } else { 'Pending user review in Windows Setup; no automatic acceptance.' }
    MicrosoftADValidated = $false
} | ConvertTo-Json -Depth 3
