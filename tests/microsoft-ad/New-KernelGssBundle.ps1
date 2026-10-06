[CmdletBinding()]
param([switch]$GssProxy, [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
$baseName = if ($GssProxy) { 'linux-gss-packages' } else { 'linux-acl-packages' }
$bundleName = if ($GssProxy) { 'linux-gssproxy-packages' } else { 'linux-gss-packages' }
$profile = if ($GssProxy) { 'kernel-gssproxy' } else { 'kernel-gss' }
$base = Join-Path $runtime $baseName
$bundle = Join-Path $runtime $bundleName
foreach ($path in @($base, $bundle)) { Assert-LabRegularPath $path }
New-Item -ItemType Directory -Path $bundle -Force | Out-Null
$lockPath = Join-Path $bundle 'download.lock'
Assert-LabRegularPath $lockPath
$lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
try {
    if (Test-Path -LiteralPath (Join-Path $bundle 'verified.json')) { throw 'Reuse the existing authenticated GSS bundle; do not replace its provenance.' }
    foreach ($root in @($base, $bundle)) {
        foreach ($path in @(Get-ChildItem -LiteralPath $root -Recurse -Force)) { Assert-LabRegularPath $path.FullName }
    }
    & docker image inspect nfs-viewer-msad-package-tools --format '{{.Id}}' | Set-Content -LiteralPath (Join-Path $bundle 'tool-image-id.txt')
    if ($LASTEXITCODE) { throw 'The existing package tooling image is required.' }
    & docker run --rm --network none --mount "type=bind,source=$PSScriptRoot,target=/scripts,readonly" --mount "type=bind,source=$base,target=/base,readonly" --mount "type=bind,source=$bundle,target=/bundle" nfs-viewer-msad-package-tools python3 /scripts/prepare-gss-snapshot.py --profile $profile
    if ($LASTEXITCODE) { throw 'Authenticated dependency snapshot preparation failed.' }
    $plan = @(Get-Content -LiteralPath (Join-Path $bundle 'gss-download-plan.json') -Raw | ConvertFrom-Json)
    foreach ($item in $plan) {
        if ($item.filename -notmatch '^[a-zA-Z0-9.+~%-]+_[a-zA-Z0-9.+~%-]+_(amd64|all)\.deb$' -or
            $item.source -notmatch '^https://archive\.ubuntu\.com/ubuntu/pool/(main|universe)/[a-z0-9/+_.~-]+/[a-zA-Z0-9._+~%-]+\.deb$' -or
            !$item.source.EndsWith('/' + $item.filename) -or $item.sha256 -notmatch '^[a-f0-9]{64}$') {
            throw 'Unexpected authenticated package download plan.'
        }
        $deb = Join-Path (Join-Path $bundle 'debs') $item.filename
        Assert-LabRegularPath $deb
        & curl.exe --fail --location --retry 2 --connect-timeout 15 --max-time 120 --silent --show-error --output $deb $item.source
        if ($LASTEXITCODE -or (Get-Item -LiteralPath $deb).Length -ne $item.bytes -or (Get-FileHash -LiteralPath $deb).Hash -ine $item.sha256) { throw 'Package differs from authenticated Ubuntu snapshot.' }
    }
    & docker run --rm --network none --mount "type=bind,source=$PSScriptRoot,target=/scripts,readonly" --mount "type=bind,source=$bundle,target=/bundle" nfs-viewer-msad-package-tools sh -c 'cd /bundle && dpkg-scanpackages debs /dev/null > Packages && python3 /scripts/verify-linux-bundle.py verify /bundle --profile "$1"' sh $profile
    if ($LASTEXITCODE) { throw 'GSS bundle authentication failed.' }
    Write-Output 'Authenticated kernel GSS bundle ready; actual offline dependency installation still required.'
} finally { $lock.Dispose() }
