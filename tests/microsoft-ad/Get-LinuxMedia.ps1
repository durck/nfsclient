[CmdletBinding()]
param(
    [switch]$Background,
    [switch]$Status,
    [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
$mediaDir = Join-Path $runtime 'linux-media'
Assert-LabRegularPath $mediaDir
New-Item -ItemType Directory -Path $mediaDir -Force | Out-Null
$base = 'https://cloud-images.ubuntu.com/noble/20260911'
$name = 'noble-server-cloudimg-amd64.vmdk'
$expectedBytes = 594127360L
$fingerprint = 'D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'
$expectedHash = 'c1655a37ff4141e4f16effb7364a640188cc17ec7dfc869a1283aa724dcd6bc1'
$target = Join-Path $mediaDir $name
$partial = $target + '.partial'
$proofPath = Join-Path $mediaDir 'verified.json'
$lockPath = Join-Path $mediaDir 'download.lock'
$workerPath = Join-Path $mediaDir 'worker.json'
foreach ($path in @($target,$partial,$proofPath,$lockPath,$workerPath)) { Assert-LabRegularPath $path }

function Get-DownloadStatus {
    $bytes = if (Test-Path -LiteralPath $target) { (Get-Item -LiteralPath $target).Length } elseif (Test-Path -LiteralPath $partial) { (Get-Item -LiteralPath $partial).Length } else { 0L }
    $ready = $false
    if ((Test-Path -LiteralPath $proofPath) -and (Test-Path -LiteralPath $target)) {
        try {
            $proof = Get-Content -LiteralPath $proofPath -Raw | ConvertFrom-Json
            $ready = $proof.SHA256 -eq $expectedHash -and $proof.SigningFingerprint -eq $fingerprint -and
                $proof.Bytes -eq $expectedBytes -and $bytes -eq $expectedBytes
        } catch { $ready = $false }
    }
    $locked = $false
    if (Test-Path -LiteralPath $lockPath) {
        try {
            $probe = [IO.File]::Open($lockPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            $probe.Dispose()
        } catch [IO.IOException] { $locked = $true }
    }
    $worker = $null
    $running = $false
    if (Test-Path -LiteralPath $workerPath) {
        $worker = Get-Content -LiteralPath $workerPath -Raw | ConvertFrom-Json
        $process = Get-Process -Id $worker.ProcessId -ErrorAction SilentlyContinue
        if ($process) { $running = [Math]::Abs(($process.StartTime.ToUniversalTime() - ([DateTime]$worker.StartedUtc).ToUniversalTime()).TotalSeconds) -lt 10 }
    }
    return [ordered]@{ Ready=$ready; Bytes=$bytes; ExpectedBytes=$expectedBytes; Percent=[Math]::Round(100.0*$bytes/$expectedBytes,2); LockHeld=$locked; WorkerRunning=$running; Worker=$worker; Media=$target; SignatureFingerprint=$fingerprint }
}
if ($Status) { Get-DownloadStatus | ConvertTo-Json -Depth 3; return }
if ($Background) {
    $launchPath = Join-Path $mediaDir 'launcher.lock'
    Assert-LabRegularPath $launchPath
    $launcher = [IO.File]::Open($launchPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $current = Get-DownloadStatus
        if ($current.Ready -or $current.LockHeld -or $current.WorkerRunning) { $current | ConvertTo-Json -Depth 3; return }
        $workerArguments = '-NoProfile -File "{0}" -RuntimeRoot "{1}"' -f $PSCommandPath, $runtime
        $worker = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $workerArguments -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $mediaDir 'download.stdout.log') -RedirectStandardError (Join-Path $mediaDir 'download.stderr.log') -PassThru
        @{ ProcessId=$worker.Id; StartedUtc=[DateTime]::UtcNow.ToString('o'); Script=$PSCommandPath } | ConvertTo-Json | Set-Content -LiteralPath $workerPath -Encoding utf8
        Write-Output "Ubuntu media worker started (PID $($worker.Id))."
    } finally { $launcher.Dispose() }
    return
}

$lock = [IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    foreach ($leaf in @('SHA256SUMS','SHA256SUMS.gpg','noble-server-cloudimg-amd64.manifest')) {
        $path = Join-Path $mediaDir $leaf
        Assert-LabRegularPath $path
        if (!(Test-Path -LiteralPath $path)) {
            & curl.exe --fail --location --retry 3 --silent --show-error --output $path ($base + '/' + $leaf)
            if ($LASTEXITCODE -ne 0) { throw "Could not download Ubuntu verification artifact: $leaf" }
        }
    }
    $verifierImage = (& docker image inspect ubuntu:24.04 --format '{{.Id}}') -join ''
    if ($LASTEXITCODE -ne 0 -or !$verifierImage.StartsWith('sha256:')) { throw 'The existing official Ubuntu verifier image is unavailable.' }
    $signature = (& docker run --rm --network none --mount "type=bind,source=$mediaDir,target=/media,readonly" $verifierImage `
        gpgv --status-fd 1 --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg /media/SHA256SUMS.gpg /media/SHA256SUMS 2>&1) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0 -or $signature -notmatch ('\[GNUPG:\] VALIDSIG ' + $fingerprint + ' ')) { throw 'Ubuntu checksum signature verification failed.' }
    $signature | Set-Content -LiteralPath (Join-Path $mediaDir 'signature-verification.log') -Encoding utf8
    $checksums = Get-Content -LiteralPath (Join-Path $mediaDir 'SHA256SUMS')
    if (@($checksums | Where-Object { $_ -eq ($expectedHash + ' *' + $name) }).Count -ne 1) { throw 'Signed checksum does not match the pinned Ubuntu VMDK.' }
    $packageManifest = 'noble-server-cloudimg-amd64.manifest'
    $manifestHash = (Get-FileHash -LiteralPath (Join-Path $mediaDir $packageManifest) -Algorithm SHA256).Hash.ToLowerInvariant()
    if (@($checksums | Where-Object { $_ -eq ($manifestHash + ' *' + $packageManifest) }).Count -ne 1) { throw 'Ubuntu package manifest checksum failed.' }
    if (!(Test-Path -LiteralPath $target)) {
        & curl.exe --fail --location --retry 12 --retry-all-errors --retry-delay 10 --connect-timeout 30 --continue-at - --silent --show-error --output $partial ($base + '/' + $name)
        if ($LASTEXITCODE -ne 0) { throw 'Ubuntu image download failed; partial file remains resumable.' }
        if ((Get-Item -LiteralPath $partial).Length -ne $expectedBytes) { throw 'Ubuntu image length mismatch.' }
        if ((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'Ubuntu image checksum mismatch; not publishing.' }
        Move-Item -LiteralPath $partial -Destination $target
    }
    if ((Get-Item -LiteralPath $target).Length -ne $expectedBytes -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'Final Ubuntu image verification failed.' }
    $proofPartial = $proofPath + '.partial'
    Assert-LabRegularPath $proofPartial
    @{ Source=($base+'/'+$name); Bytes=$expectedBytes; SHA256=$expectedHash; SigningFingerprint=$fingerprint; VerifierImage=$verifierImage; VerifiedUtc=[DateTime]::UtcNow.ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath $proofPartial -Encoding utf8
    Move-Item -LiteralPath $proofPartial -Destination $proofPath -Force
    Write-Output 'Ubuntu VMDK and package manifest match the authenticated Canonical SHA256 checksums.'
} finally { $lock.Dispose() }
