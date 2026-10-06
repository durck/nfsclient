[CmdletBinding()]
param(
    [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'),
    [switch]$ResumeStalled,
    [int]$ExpectedWorkerId
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
. (Join-Path $PSScriptRoot 'MediaWorker.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
$launcherPath = Join-Path $runtime 'download-launcher.lock'
Assert-LabRegularPath $launcherPath
$launcherLock = [IO.File]::Open($launcherPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
$status = & (Join-Path $PSScriptRoot 'Get-LabStatus.ps1') -RuntimeRoot $runtime | ConvertFrom-Json
if ($ResumeStalled) {
    if ($ExpectedWorkerId -le 0 -or $status.MediaReady -or !$status.DownloadWorkerRunning -or !$status.DownloadLockHeld -or $status.DownloadWorker.ProcessId -ne $ExpectedWorkerId) { throw 'Controlled resume requires the expected live, locked worker of incomplete media.' }
    $health = & (Join-Path $PSScriptRoot 'Get-MediaDownloadHealth.ps1') -RuntimeRoot $runtime -SampleSeconds 5 | ConvertFrom-Json
    if (!$health.StallSuspected -or $health.WorkerId -ne $ExpectedWorkerId) { throw 'Verified transfer is progressing or not old enough to diagnose a stall.' }
    $owned = Get-VerifiedMediaWorker -Runtime $runtime
    if ($owned.Worker.Id -ne $ExpectedWorkerId -or $owned.Curl.Id -ne $health.CurlId -or (Get-Item -LiteralPath $owned.Partial).Length -ne $health.BytesAfter) { throw 'Writer or progress changed after diagnosis; refusing termination.' }
    # Stop the known native transfer first. Its waiting PowerShell worker then
    # reports failure and releases the download lock in its existing finally.
    $owned.Curl.Kill()
    if (!$owned.Curl.WaitForExit(5000)) { throw 'Owned curl did not exit; no replacement worker started.' }
    if (!$owned.Worker.WaitForExit(15000)) { throw 'Owned worker did not exit; retain partial and diagnose before any replacement.' }
    foreach ($child in $owned.Children) {
        $remaining = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
        if ($remaining -and !$remaining.WaitForExit(5000)) { throw 'Owned process tree has not exited; no replacement worker started.' }
    }
    $probe = [IO.File]::Open((Join-Path $runtime 'media/download.lock'),'Open','ReadWrite','None')
    try {
        $partialProbe = [IO.File]::Open($owned.Partial,'Open','ReadWrite','None')
        try { if ($partialProbe.Length -ne $health.BytesAfter) { throw 'Partial length changed during shutdown; refusing automatic resume.' } } finally { $partialProbe.Dispose() }
    } finally { $probe.Dispose() }
    $history = Join-Path $runtime ('download-resume-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
    foreach ($path in @(($history+'.json'),($history+'.stderr.log'),(Join-Path $runtime 'media-download.stderr.log'))) { Assert-LabRegularPath $path }
    if ((Test-Path -LiteralPath ($history+'.json')) -or (Test-Path -LiteralPath ($history+'.stderr.log'))) { throw 'Resume history already exists; preserve it and leave the transfer stopped.' }
    $health | Add-Member -NotePropertyName PreviousTreeExited -NotePropertyValue $true
    $health | Add-Member -NotePropertyName ExclusiveLockAndPartialProbePassed -NotePropertyValue $true
    $health | ConvertTo-Json | Set-Content -LiteralPath ($history+'.json') -Encoding utf8
    Copy-Item -LiteralPath (Join-Path $runtime 'media-download.stderr.log') -Destination ($history+'.stderr.log')
    $status = & (Join-Path $PSScriptRoot 'Get-LabStatus.ps1') -RuntimeRoot $runtime | ConvertFrom-Json
}
if ($status.MediaReady -or $status.DownloadWorkerRunning -or $status.DownloadLockHeld) {
    $status | ConvertTo-Json -Depth 3
    return
}
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
$workerId = Start-LabMediaWorker -Runtime $runtime
Write-Output "Resumable Microsoft media worker started (PID $workerId)."
} finally {
    $launcherLock.Dispose()
}
