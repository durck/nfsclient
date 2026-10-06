[CmdletBinding()]
param([string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
. (Join-Path $PSScriptRoot 'MediaWorker.ps1')
# Source resolved from Microsoft's Evaluation Center on 2026-09-23.
# This downloads media; it does not accept any license or run Windows Setup.
$source = Get-MicrosoftLabSource
$expectedLength = 8152356864L
$mediaDir = Join-Path (Get-LabRuntimeRoot $RuntimeRoot) 'media'
Assert-LabRegularPath $mediaDir
New-Item -ItemType Directory -Path $mediaDir -Force | Out-Null
$target = Join-Path $mediaDir 'windows-server-2025-eval.iso'
$partial = $target + '.partial'
Assert-LabRegularPath $target
Assert-LabRegularPath $partial
$lockPath = Join-Path $mediaDir 'download.lock'
Assert-LabRegularPath $lockPath
$downloadLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
if (!(Test-Path -LiteralPath $target)) {
    & curl.exe --fail --location --retry 12 --retry-all-errors --retry-delay 10 --connect-timeout 30 --speed-limit 1024 --speed-time 60 --continue-at - --silent --show-error --output $partial $source
    if ($LASTEXITCODE -ne 0) { throw "Microsoft media download failed ($LASTEXITCODE); the partial file is resumable." }
    if ((Get-Item -LiteralPath $partial).Length -ne $expectedLength) { throw 'Incomplete or changed Microsoft media; not publishing the ISO.' }
    Move-Item -LiteralPath $partial -Destination $target
}
if ((Get-Item -LiteralPath $target).Length -ne $expectedLength) { throw 'Unexpected ISO length.' }
$hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
$metadataPath = Join-Path $mediaDir 'windows-server-2025-eval.metadata.json'
$metadataPartial = $metadataPath + '.partial'
Assert-LabRegularPath $metadataPath
Assert-LabRegularPath $metadataPartial
@{
    Source = $source
    EvaluationPage = 'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025'
    Bytes = $expectedLength
    SHA256 = $hash
    HashProvenance = 'Locally calculated after HTTPS download; not an independently published vendor checksum.'
    CompletedUtc = [DateTime]::UtcNow.ToString('o')
    LicenseAccepted = $false
} | ConvertTo-Json | Set-Content -LiteralPath $metadataPartial -Encoding utf8
Move-Item -LiteralPath $metadataPartial -Destination $metadataPath -Force
Write-Output "Media ready: $target ($expectedLength bytes; SHA256 $hash)"
} finally {
    $downloadLock.Dispose()
}
