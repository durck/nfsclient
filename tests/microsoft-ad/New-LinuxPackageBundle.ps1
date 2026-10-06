[CmdletBinding()]
param(
    [ValidateSet('nfs-ad','posix-acl')][string]$Profile='nfs-ad',
    [switch]$FromVerifiedSnapshot,
    [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
if ($FromVerifiedSnapshot -and $Profile -ne 'posix-acl') { throw 'Snapshot reuse is only defined for the acl addition.' }
$bundleName = if ($Profile -eq 'posix-acl') { 'linux-acl-packages' } else { 'linux-packages' }
$containerName = if ($Profile -eq 'posix-acl') { 'nfs-viewer-msad-acl-download' } else { 'nfs-viewer-msad-package-download' }
$bundle = Join-Path $runtime $bundleName
Assert-LabRegularPath $bundle
New-Item -ItemType Directory -Path $bundle -Force | Out-Null
$lockPath = Join-Path $bundle 'download.lock'
Assert-LabRegularPath $lockPath
$lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
try {
    if (Test-Path -LiteralPath (Join-Path $bundle 'verified.json')) { throw 'The authenticated bundle already exists; reuse it rather than replacing its provenance.' }
    foreach ($path in @(Get-ChildItem -LiteralPath $bundle -Recurse -Force)) { Assert-LabRegularPath $path.FullName }
    $repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    & docker build -t nfs-viewer-msad-package-tools -f (Join-Path $PSScriptRoot 'linux-package-tools.Dockerfile') $repo
    if ($LASTEXITCODE -ne 0) { throw 'Package tool image build failed.' }
    & docker image inspect nfs-viewer-msad-package-tools --format '{{.Id}}' | Set-Content -LiteralPath (Join-Path $bundle 'tool-image-id.txt')
    if ($FromVerifiedSnapshot) {
        $base=Join-Path $runtime 'linux-packages'
        Assert-LabRegularPath $base
        foreach ($path in @(Get-ChildItem -LiteralPath $base -Recurse -Force)) { Assert-LabRegularPath $path.FullName }
        & docker run --rm --network none --mount "type=bind,source=$PSScriptRoot,target=/scripts,readonly" --mount "type=bind,source=$base,target=/base,readonly" --mount "type=bind,source=$bundle,target=/bundle" nfs-viewer-msad-package-tools python3 /scripts/prepare-acl-snapshot.py
        if ($LASTEXITCODE) { throw 'Authenticated snapshot preparation failed.' }
        $plan=Get-Content -LiteralPath (Join-Path $bundle 'acl-download-plan.json') -Raw | ConvertFrom-Json
        if ($plan.filename -notmatch '^acl_[a-zA-Z0-9.+~%-]+_amd64\.deb$' -or $plan.source -cne ('https://archive.ubuntu.com/ubuntu/pool/main/a/acl/'+$plan.filename)) { throw 'Unexpected acl download plan.' }
        $deb=Join-Path (Join-Path $bundle 'debs') $plan.filename
        Assert-LabRegularPath $deb
        & curl.exe --fail --location --retry 2 --connect-timeout 15 --max-time 90 --silent --show-error --output $deb $plan.source
        if ($LASTEXITCODE -or (Get-Item -LiteralPath $deb).Length -ne $plan.bytes -or (Get-FileHash -LiteralPath $deb).Hash -ne $plan.sha256) { throw 'Downloaded acl differs from the authenticated Ubuntu snapshot.' }
        & docker run --rm --network none --mount "type=bind,source=$PSScriptRoot,target=/scripts,readonly" --mount "type=bind,source=$bundle,target=/bundle" nfs-viewer-msad-package-tools sh -c 'cd /bundle && dpkg-scanpackages debs /dev/null > Packages && python3 /scripts/verify-linux-bundle.py verify /bundle --profile posix-acl'
        if ($LASTEXITCODE) { throw 'ACL bundle authentication failed.' }
        Write-Output 'Authenticated acl bundle from existing signed snapshot ready; dependency installation remains to be checked.'
        return
    }
    & docker run --rm --name $containerName --mount "type=bind,source=$PSScriptRoot,target=/scripts,readonly" --mount "type=bind,source=$bundle,target=/bundle" nfs-viewer-msad-package-tools sh /scripts/build-linux-bundle.sh $Profile 2>&1 | Tee-Object -FilePath (Join-Path $bundle 'download.log')
    if ($LASTEXITCODE -ne 0) { throw 'Package bundle download/authentication failed; preserve partial data and inspect download.log.' }
    Write-Output 'Authenticated offline package bundle ready; real dependency installation remains to be checked.'
} finally { $lock.Dispose() }
