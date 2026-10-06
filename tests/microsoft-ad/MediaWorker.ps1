function Get-MicrosoftLabSource {
    return 'https://software-static.download.prss.microsoft.com/dbazure/998969d5-f34g-4e03-ac9d-1f9786c66749/26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso'
}

function Get-VerifiedMediaWorker {
    param([Parameter(Mandatory)][string]$Runtime)
    $recordPath = Join-Path $Runtime 'download-worker.json'
    Assert-LabRegularPath $recordPath
    $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    $expectedScript = Join-Path $PSScriptRoot 'Get-MicrosoftMedia.ps1'
    if (![string]::Equals($record.Script,$expectedScript,[StringComparison]::OrdinalIgnoreCase)) { throw 'Worker record names an unexpected script.' }
    $worker = Get-Process -Id $record.ProcessId -ErrorAction Stop
    $started = $worker.StartTime.ToUniversalTime()
    if ([Math]::Abs(($started-([DateTime]$record.StartedUtc).ToUniversalTime()).TotalSeconds) -ge 10 -or $worker.ProcessName -notin @('pwsh','powershell')) { throw 'Worker PID/start time or executable identity changed.' }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($worker.Id)"
    $commandPattern = '^(?:"' + [regex]::Escape($worker.Path) + '"|' + [regex]::Escape($worker.Path) + ')\s+-NoProfile\s+-File\s+"' + [regex]::Escape($expectedScript) + '"\s+-RuntimeRoot\s+"' + [regex]::Escape($Runtime) + '"\s*$'
    if (!$process -or $process.CommandLine -notmatch $commandPattern) { throw 'Worker command line is not the exact dedicated media command.' }
    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($worker.Id)")
    if (@($children | Where-Object Name -notin @('curl.exe','conhost.exe')).Count -or @($children | Where-Object Name -eq 'curl.exe').Count -ne 1 -or @($children | Where-Object Name -eq 'conhost.exe').Count -gt 1) { throw 'Unexpected worker process tree; refusing ownership assumption.' }
    $curlInfo = @($children | Where-Object Name -eq 'curl.exe')[0]
    $curl = Get-Process -Id $curlInfo.ProcessId -ErrorAction Stop
    $expectedCurl = (Get-Command curl.exe -ErrorAction Stop).Source
    $partial = Join-Path $Runtime 'media/windows-server-2025-eval.iso.partial'
    $outputPattern = '--output\s+(?:"' + [regex]::Escape($partial) + '"|' + [regex]::Escape($partial) + ')(?:\s|$)'
    if (![string]::Equals($curlInfo.ExecutablePath,$expectedCurl,[StringComparison]::OrdinalIgnoreCase) -or $curlInfo.CommandLine -notmatch $outputPattern -or $curlInfo.CommandLine -notmatch '--continue-at\s+-\s' -or !$curlInfo.CommandLine.TrimEnd().EndsWith((Get-MicrosoftLabSource),[StringComparison]::Ordinal)) { throw 'Curl source, output path or executable differs from the dedicated media transfer.' }
    if ($curl.StartTime.ToUniversalTime() -lt $started) { throw 'Curl predates the recorded worker.' }
    foreach ($child in $children) {
        if (@(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($child.ProcessId)").Count) { throw 'Unexpected deeper worker process tree.' }
    }
    return @{ Worker=$worker; Curl=$curl; StartedUtc=$started; Children=$children; Partial=$partial }
}

function Start-LabMediaWorker {
    param([Parameter(Mandatory)][string]$Runtime)
    # Caller must hold download-launcher.lock and prove no current writer.
    $script = Join-Path $PSScriptRoot 'Get-MicrosoftMedia.ps1'
    foreach ($leaf in @('download-worker.json','media-download.stdout.log','media-download.stderr.log')) {
        Assert-LabRegularPath (Join-Path $Runtime $leaf)
    }
    $engine = (Get-Process -Id $PID).Path
    $arguments = '-NoProfile -File "{0}" -RuntimeRoot "{1}"' -f $script, $Runtime
    $worker = Start-Process -FilePath $engine -ArgumentList $arguments -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $Runtime 'media-download.stdout.log') `
        -RedirectStandardError (Join-Path $Runtime 'media-download.stderr.log') -PassThru
    @{ ProcessId=$worker.Id; StartedUtc=$worker.StartTime.ToUniversalTime().ToString('o'); Script=$script } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Runtime 'download-worker.json') -Encoding utf8
    return $worker.Id
}
