[CmdletBinding()]
param([string]$RuntimeRoot=(Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime=Get-LabRuntimeRoot $RuntimeRoot
$name='nfs-viewer-msad-download-check'
$run=Join-Path $runtime ('media-check-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
Assert-LabRegularPath $run
if (Test-Path -LiteralPath $run) { throw 'Transfer check output already exists.' }
New-Item -ItemType Directory -Path $run | Out-Null
$fixture=Join-Path $PSScriptRoot 'media-transfer-fixture.py'
$containerId=$null
try {
    $containerId=& docker run --detach --name $name --read-only --cap-drop ALL --security-opt no-new-privileges --publish '127.0.0.1::8080' --mount "type=bind,source=$fixture,target=/fixture.py,readonly" nfs-viewer-msad-package-tools python3 /fixture.py
    if ($LASTEXITCODE) { $containerId=$null; throw 'Could not create the dedicated local transfer fixture.' }
    $containerId=$containerId.Trim()
    $binding=& docker port $containerId 8080/tcp
    if ($LASTEXITCODE -or $binding -notmatch '^127\.0\.0\.1:\d+$') { throw 'Unexpected fixture listener; requires host loopback only.' }
    $url='http://'+$binding
    $deadline=[DateTime]::UtcNow.AddSeconds(15)
    do {
        & curl.exe --silent --fail --noproxy '*' --max-time 1 "$url/ready" 2>$null
        $ready=$LASTEXITCODE -eq 0
        if (!$ready -and [DateTime]::UtcNow -gt $deadline) { throw 'Local fixture readiness timed out.' }
    } until ($ready)
    $partial=Join-Path $run 'fixture.partial'
    $flags=@('--fail','--silent','--show-error','--noproxy','*','--connect-timeout','2','--max-time','15','--speed-limit','1024','--speed-time','2','--continue-at','-','--output',$partial)
    $clock=[Diagnostics.Stopwatch]::StartNew()
    & curl.exe @flags "$url/stall" 2> (Join-Path $run 'timeout.stderr.log')
    $timeoutCode=$LASTEXITCODE
    $clock.Stop()
    $firstBytes=(Get-Item -LiteralPath $partial).Length
    if ($timeoutCode -ne 28 -or $firstBytes -ne 65536 -or $clock.Elapsed.TotalSeconds -ge 12) { throw 'Low-speed timeout did not preserve the expected bounded partial.' }
    $partialHash=(Get-FileHash -LiteralPath $partial).Hash
    & curl.exe @flags "$url/ignore-range" 2> (Join-Path $run 'range.stderr.log')
    $rangeCode=$LASTEXITCODE
    if ($rangeCode -ne 33 -or (Get-FileHash -LiteralPath $partial).Hash -ne $partialHash) { throw 'Non-resumable HTTP response modified the partial or did not fail.' }
    & curl.exe @flags "$url/complete" 2> (Join-Path $run 'resume.stderr.log')
    $resumeCode=$LASTEXITCODE
    $bytes=[byte[]]::new(262144)
    for ($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i]=[byte]($i % 256) }
    $expected=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
    if ($resumeCode -ne 0 -or (Get-Item -LiteralPath $partial).Length -ne $bytes.Length -or (Get-FileHash -LiteralPath $partial).Hash -ne $expected) { throw 'Resumed local content does not match the complete expected bytes.' }
    [ordered]@{ Passed=$true; CheckedUtc=[DateTime]::UtcNow.ToString('o'); CurlVersion=(& curl.exe --version)[0]; LowSpeedExit=$timeoutCode; TimeoutSeconds=$clock.Elapsed.TotalSeconds; RetainedBytes=$firstBytes; RangeRejectedExit=$rangeCode; RangeRejectionPreservedPartial=$true; ResumedBytes=$bytes.Length; ResumedSHA256=$expected; Scope='Native Windows curl; local loopback HTTP; no Windows ISO modified' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'evidence.json') -Encoding utf8
    Write-Output "Low-speed timeout, unsupported range rejection and exact resumed-content checks passed: $run/evidence.json"
} finally {
    if ($containerId) {
        & docker rm --force $containerId | Out-Null
        if ($LASTEXITCODE) { throw "Could not remove the exact transfer fixture container: $containerId" }
    }
}
