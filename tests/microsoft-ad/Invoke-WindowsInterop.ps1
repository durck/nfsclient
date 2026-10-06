param([Parameter(Mandatory)][ValidatePattern('^interop-[a-zA-Z0-9-]+$')][string]$RunId, [switch]$Large)
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'NFSADDC1') { throw 'Run only inside the dedicated Windows lab guest' }
$bridge = 'C:/NfsLab/linux-bridge'
$root = "C:/NfsLab/windows-nfs-runs/$RunId"
if (Test-Path -LiteralPath $root) { throw 'A fresh run directory is required' }
foreach ($dir in @('C:/NfsLab','C:/NfsLab/windows-nfs-runs')) {
    if ((Test-Path -LiteralPath $dir) -and ((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Redirected run parent' }
}
New-Item -ItemType Directory -Path $root | Out-Null
$acl = Get-Acl -LiteralPath $root
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $root -AclObject $acl
$ssh = 'C:/Windows/System32/OpenSSH/ssh.exe'
$scp = 'C:/Windows/System32/OpenSSH/scp.exe'
$sshArgs = @('-F','NUL','-o','StrictHostKeyChecking=yes','-o',"UserKnownHostsFile=$bridge/known_hosts",'-o','GlobalKnownHostsFile=NUL','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-i',"$bridge/identity")
$peer = 'labadmin@192.0.2.20'
$stage = "/home/labadmin/nfs-windows-$RunId"
$run = "/var/lib/nfs-viewer-msad/runs/$RunId"
function Remote([string]$Command) {
    $result = & $ssh -n @sshArgs $peer $Command
    if ($LASTEXITCODE) { throw 'Pinned lab SSH command failed' }
    return $result
}
function Copy-ToLinux([string]$Local, [string]$RemotePath) {
    & $scp @sshArgs $Local "${peer}:$RemotePath"
    if ($LASTEXITCODE) { throw 'Pinned lab SCP upload failed' }
}
function Read-Marker([string]$Name) {
    return ((Remote "sudo -n test -f $run/windows-control/$Name && echo yes || echo no") -eq 'yes')
}
function Run-Test([string]$Pattern, [string]$Log) {
    $p = Start-Process -FilePath "$root/cli-windows.test.exe" -ArgumentList @('-test.v','-test.count=1','-test.timeout=20m',"-test.run=$Pattern") -WindowStyle Hidden -PassThru -RedirectStandardOutput "$root/$Log" -RedirectStandardError "$root/$Log.stderr"
    $null = $p.Handle # PowerShell 5.1 must retain the handle to read ExitCode.
    if (-not $p.WaitForExit(1230000)) { $p.Kill(); throw 'Windows test timeout' }
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "Windows test failed: $Log" }
}
function Run-RestartTest([string]$Pattern, [string]$Prefix, [int]$Seconds) {
    $control = "$root/$Prefix-control"
    New-Item -ItemType Directory -Path $control | Out-Null
    $env:NFS_VIEWER_MSAD_RESTART_CONTROL = $control
    $p = Start-Process -FilePath "$root/cli-windows.test.exe" -ArgumentList @('-test.v','-test.count=1',"-test.timeout=$($Seconds)s","-test.run=$Pattern") -WindowStyle Hidden -PassThru -RedirectStandardOutput "$root/$Prefix.log" -RedirectStandardError "$root/$Prefix.stderr"
    $null = $p.Handle
    try {
        $sent = $false
        $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
        while (-not $p.HasExited) {
            if ([DateTime]::UtcNow -gt $deadline) { throw "$Prefix test timeout" }
            if (-not $sent -and (Test-Path -LiteralPath "$control/request")) {
                Remote "sudo -n touch $run/windows-control/$Prefix-request" | Out-Null
                $sent = $true
            }
            if ($sent -and -not (Test-Path -LiteralPath "$control/done") -and (Read-Marker "$Prefix-done")) {
                [IO.File]::WriteAllText("$control/done", "restarted`n")
            }
            Start-Sleep -Seconds 1
        }
        $p.WaitForExit()
        if ($p.ExitCode -ne 0 -or -not $sent) { throw "$Prefix Windows test failed" }
    } finally {
        if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit() }
    }
}
$server = $null
$restart = $null
$complete = $false
$credentials = "$root/credentials"
$report = [ordered]@{ passed=$false; os='windows'; os_version=[Environment]::OSVersion.VersionString; run=$RunId; host='192.0.2.20'; credentials_removed=$false }
try {
    $remoteTime = [double](Remote 'date -u +%s')
    $skew = [Math]::Abs([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-$remoteTime)
    if ($skew -gt 5) { throw 'Synchronize lab clocks before native cache acquisition' }
    $report.clock_difference_seconds = $skew
    Remote "mkdir -m 700 $stage" | Out-Null
    foreach ($name in @('krb.test','cli.test','cli-windows.test.exe','nfs-viewer-windows-amd64.exe','run-interop-nfs.py','verify-interop-nfs.py')) {
        Copy-ToLinux "$bridge/$name" "$stage/$name"
    }
    foreach ($name in @('cli-windows.test.exe','nfs-viewer-windows-amd64.exe')) { Copy-Item -LiteralPath "$bridge/$name" -Destination "$root/$name" }
    $report.artifacts = @{}
    foreach ($name in @('cli-windows.test.exe','nfs-viewer-windows-amd64.exe')) { $report.artifacts[$name] = (Get-FileHash "$root/$name" -Algorithm SHA256).Hash.ToLowerInvariant() }
    $launch = (@('-n') + $sshArgs + @($peer, "`"sudo -n python3 $stage/run-interop-nfs.py $RunId --windows-client`"")) -join ' '
    $server = Start-Process -FilePath $ssh -ArgumentList $launch -WindowStyle Hidden -PassThru -RedirectStandardOutput "$root/server.log" -RedirectStandardError "$root/server.stderr"
    $null = $server.Handle
    $deadline = [DateTime]::UtcNow.AddMinutes(6)
    while (-not (Read-Marker 'ready')) {
        if ($server.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Linux fixture did not become ready' }
        Start-Sleep -Seconds 2
    }
    New-Item -ItemType Directory -Path $credentials | Out-Null
    foreach ($name in @('krb5.conf','nv-alice.keytab','nv-bob.keytab','nv-alice.ccache','nv-bob.ccache')) {
        & $scp @sshArgs "${peer}:$stage/windows-credentials/$name" "$credentials/$name"
        if ($LASTEXITCODE) { throw 'Ordinary-user credential staging failed' }
    }
    $env:NFS_VIEWER_MSAD_NFS = '1'
    $env:NFS_VIEWER_MSAD_NFS_HOST = '192.0.2.20'
    $env:NFS_VIEWER_MSAD_NFS_CREDENTIALS = $credentials
    $env:NFS_VIEWER_MSAD_UDP_SIZE = '1024'
    $report.udp_size = 1024
    'matrix' | Set-Content "$root/phase.txt"
    Run-Test '^TestMicrosoftADNFS(Locks)?$' 'nfs.log'
    'restart' | Set-Content "$root/phase.txt"
    Run-RestartTest '^TestMicrosoftADNFSServerRestart$' 'restart' 240
    if ($Large) {
        'large' | Set-Content "$root/phase.txt"
        $env:NFS_VIEWER_MSAD_LARGE = '1'
        $env:NFS_VIEWER_MSAD_LARGE_REPORT = "$root/large.json"
        Run-RestartTest '^TestMicrosoftADNFSLarge$' 'large' 1230
        $report.large = Get-Content "$root/large.json" -Raw | ConvertFrom-Json
    }
    'release' | Set-Content "$root/phase.txt"
    [IO.File]::WriteAllBytes("$root/source.bin", [byte[]](0..255))
    $common = @('192.0.2.20','--nfs-version','4.1','--nfs-port','2049','--export','/','--sec','krb5p','--krb5-config',"$credentials/krb5.conf",'--principal','nv-alice@MSAD.NFS.TEST','--spn','nfs/nfs-interop.msad.nfs.test','--auto-escape=false','--no-banner','--color','never','--progress','never')
    foreach ($cred in @('keytab','ccache')) {
        $commands = @('id',"put $root/source.bin data/windows-release-$cred.bin", "lock data/windows-release-$cred.bin read", "get data/windows-release-$cred.bin $root/download-$cred.bin",'unlock 1','reconnect','pwd')
        $commands | Set-Content -Encoding ASCII "$root/commands-$cred.txt"
        $cliArgs = $common + @("--$cred", "$credentials/nv-alice.$cred", '--batch')
        $cli = Start-Process -FilePath "$root/nfs-viewer-windows-amd64.exe" -ArgumentList $cliArgs -WindowStyle Hidden -PassThru -RedirectStandardInput "$root/commands-$cred.txt" -RedirectStandardOutput "$root/release-$cred.log" -RedirectStandardError "$root/release-$cred.stderr"
        $null = $cli.Handle
        if (-not $cli.WaitForExit(60000)) { $cli.Kill(); throw 'Windows release timeout' }
        $cli.WaitForExit()
        if ($cli.ExitCode -ne 0) { throw 'Windows release CLI failed' }
        Get-Content "$root/release-$cred.log" | Out-File -Append -Encoding UTF8 "$root/release.log"
        if ((Get-FileHash "$root/source.bin").Hash -ne (Get-FileHash "$root/download-$cred.bin").Hash) { throw 'Windows release bytes differ' }
    }
    $report.passed = $true
} catch {
    $report.error = $_.Exception.Message
} finally {
    if ($restart -and -not $restart.HasExited) { $restart.Kill(); $restart.WaitForExit() }
    # Remove only the five fixed credential files from the validated fresh root.
    if ([IO.Path]::GetFullPath($credentials) -ne [IO.Path]::GetFullPath("C:/NfsLab/windows-nfs-runs/$RunId/credentials")) { throw 'Credential cleanup path mismatch' }
    if (Test-Path -LiteralPath $credentials) {
        if ((Get-Item -LiteralPath $credentials).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected credential directory' }
        foreach ($name in @('krb5.conf','nv-alice.keytab','nv-bob.keytab','nv-alice.ccache','nv-bob.ccache')) {
            Remove-Item -LiteralPath "$credentials/$name" -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $credentials -Force
    }
    $report.credentials_removed = -not (Test-Path -LiteralPath $credentials)
    $report | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 "$root/windows-client.json"
    if ($server) {
        try {
            if ($report.passed) {
                foreach ($name in @('nfs.log','restart.log','release.log','windows-client.json')) { Copy-ToLinux "$root/$name" "$stage/$name" }
                if ($Large) { foreach ($name in @('large.log','large.json')) { Copy-ToLinux "$root/$name" "$stage/$name" } }
                Remote "sudo -n touch $run/windows-control/complete" | Out-Null
                $complete = $true
            } else { Remote "touch $stage/windows-abort" | Out-Null }
        } catch {
            $report.passed = $false; $report.error = $_.Exception.Message
            Remote "touch $stage/windows-abort" | Out-Null
        }
        if (-not $server.WaitForExit(180000)) { throw 'Linux cleanup still pending; keep its supervisor alive' }
        $server.WaitForExit()
        if ($server.ExitCode -ne 0) { $report.passed = $false }
        if ($report.passed) {
            Remote "sudo -n python3 $stage/verify-interop-nfs.py $run" | Set-Content -Encoding UTF8 "$root/independent.json"
        }
        foreach ($name in @('evidence.json','kerberos.log','lock-readiness.log','lock-readiness-restart.log')) {
            try { Remote "sudo -n cat $run/$name" | Set-Content -Encoding UTF8 "$root/$name" } catch { $report.passed = $false }
        }
    }
    $report | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 "$root/windows-client.json"
}
if (-not $report.passed -or -not $complete) { exit 1 }
