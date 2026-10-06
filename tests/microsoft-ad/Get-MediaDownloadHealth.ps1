[CmdletBinding()]
param(
    [ValidateRange(1,60)][int]$SampleSeconds=5,
    [string]$RuntimeRoot=(Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab')
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
. (Join-Path $PSScriptRoot 'MediaWorker.ps1')
$runtime=Get-LabRuntimeRoot $RuntimeRoot
$owned=Get-VerifiedMediaWorker -Runtime $runtime
Assert-LabRegularPath (Join-Path $runtime 'media')
Assert-LabRegularPath $owned.Partial
$before=(Get-Item -LiteralPath $owned.Partial).Length
$observed=[DateTime]::UtcNow
[Threading.Thread]::Sleep($SampleSeconds*1000)
$after=(Get-Item -LiteralPath $owned.Partial).Length
$fresh=Get-VerifiedMediaWorker -Runtime $runtime
if ($fresh.Worker.Id -ne $owned.Worker.Id -or $fresh.Curl.Id -ne $owned.Curl.Id -or $fresh.StartedUtc -ne $owned.StartedUtc) { throw 'Process tree changed during the observation.' }
$age=([DateTime]::UtcNow-(Get-Item -LiteralPath $owned.Partial).LastWriteTimeUtc).TotalSeconds
[ordered]@{
    CheckedUtc=[DateTime]::UtcNow.ToString('o'); WorkerId=$fresh.Worker.Id; CurlId=$fresh.Curl.Id;
    WorkerStartedUtc=$fresh.StartedUtc.ToString('o'); OwnershipVerified=$true;
    SampleSeconds=([DateTime]::UtcNow-$observed).TotalSeconds; BytesBefore=$before; BytesAfter=$after;
    ByteGrowth=$after-$before; PartialLastWriteAgeSeconds=[Math]::Round($age,1);
    StallSuspected=($after -eq $before -and $age -ge 180);
    Interpretation='Two byte-count observations of the verified owned writer. File timestamp alone is not proof of a stall.'
} | ConvertTo-Json
