param([Parameter(Mandatory)][ValidatePattern('^interop-[a-zA-Z0-9-]+$')][string]$RunId)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'NFSADDC1'){throw 'Dedicated Windows lab guest only'}
$bridge='C:/NfsLab/linux-bridge'
$root="C:/NfsLab/windows-nfs-runs/$RunId"
if(Test-Path -LiteralPath $root){throw 'Fresh run required'}
foreach($parent in @('C:/NfsLab','C:/NfsLab/windows-nfs-runs')){
    if((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Redirected parent'}
}
New-Item -ItemType Directory -Path $root | Out-Null
$allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
$acl=Get-Acl -LiteralPath $root
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in $allowed){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
Set-Acl -LiteralPath $root -AclObject $acl
$acl=Get-Acl -LiteralPath $root
$actual=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if(-not $acl.AreAccessRulesProtected -or @($actual | Where-Object {$_.IdentityReference.Value -notin $allowed.Value -or $_.AccessControlType -ne 'Allow'}).Count){throw 'Credential root ACL differs'}
$ssh='C:/Windows/System32/OpenSSH/ssh.exe'
$scp='C:/Windows/System32/OpenSSH/scp.exe'
$sshArgs=@('-F','NUL','-o','StrictHostKeyChecking=yes','-o',"UserKnownHostsFile=$bridge/known_hosts",'-o','GlobalKnownHostsFile=NUL','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-i',"$bridge/identity")
$peer='labadmin@192.0.2.20'
$stage="/home/labadmin/nfs-windows-$RunId"
$run="/var/lib/nfs-viewer-msad/runs/$RunId"
function Remote([string]$Command){$result=& $ssh -n @sshArgs $peer $Command;if($LASTEXITCODE){throw 'Pinned SSH failed'};return $result}
function Upload([string]$Local,[string]$Target){& $scp @sshArgs $Local "${peer}:$Target";if($LASTEXITCODE){throw 'Pinned SCP upload failed'}}
$credentials="$root/credentials"
$server=$null;$client=$null
$report=[ordered]@{passed=$false;os='windows';security='krb5p';run=$RunId;credentials_removed=$false;acl_protected=$true;artifacts=@{}}
try{
    Remote "mkdir -m 700 $stage" | Out-Null
    foreach($name in @('krb.test','cli.test','cli-windows.test.exe','nfs-viewer-windows-amd64.exe','run-interop-nfs.py')){Upload "$bridge/$name" "$stage/$name"}
    foreach($name in @('cli-windows.test.exe','nfs-viewer-windows-amd64.exe')){
        Copy-Item -LiteralPath "$bridge/$name" -Destination "$root/$name"
        $report.artifacts[$name]=(Get-FileHash -Algorithm SHA256 "$root/$name").Hash.ToLowerInvariant()
    }
    $server=Start-Process -FilePath $ssh -ArgumentList (@('-n')+$sshArgs+@($peer,"sudo -n python3 $stage/run-interop-nfs.py $RunId --reclaim-windows")) -WindowStyle Hidden -PassThru -RedirectStandardOutput "$root/server.log" -RedirectStandardError "$root/server.stderr"
    $null=$server.Handle
    $deadline=[DateTime]::UtcNow.AddMinutes(6)
    do{
        $ready=Remote "sudo -n test -f $run/windows-control/ready && echo yes || echo no"
        if($ready -eq 'yes'){break}
        if($server.HasExited -or [DateTime]::UtcNow -gt $deadline){throw 'Reclaim fixture readiness failed'}
        Start-Sleep -Seconds 1
    }while($true)
    New-Item -ItemType Directory -Path $credentials | Out-Null
    foreach($name in @('krb5.conf','nv-alice.keytab')){
        & $scp @sshArgs "${peer}:$stage/windows-credentials/$name" "$credentials/$name"
        if($LASTEXITCODE){throw 'Ordinary-user staging failed'}
    }
    $control="$root/reclaim-control"
    New-Item -ItemType Directory -Path $control | Out-Null
    $env:NFS_RECLAIM_HOST='192.0.2.20';$env:NFS_RECLAIM_CONTROL=$control;$env:NFS_RECLAIM_CREDENTIALS=$credentials
    $env:NFS_VIEWER_TEST_BINARY="$root/nfs-viewer-windows-amd64.exe"
    $client=Start-Process -FilePath "$root/cli-windows.test.exe" -ArgumentList @('-test.run=^TestKernelReclaim','-test.v','-test.count=1','-test.timeout=8m','-test.failfast') -WindowStyle Hidden -PassThru -RedirectStandardOutput "$root/reclaim.log" -RedirectStandardError "$root/reclaim.stderr"
    $null=$client.Handle
    $last='';$deadline=[DateTime]::UtcNow.AddMinutes(9)
    while(-not $client.HasExited){
        if([DateTime]::UtcNow -gt $deadline){throw 'Windows reclaim deadline'}
        if(Test-Path -LiteralPath "$control/restart-request"){
            $token=(Get-Content -LiteralPath "$control/restart-request" -Raw).Trim()
            if($token -match '^[1-6]$'){
                if($token -ne $last){Remote "printf '%s' '$token' | sudo -n tee $run/windows-control/restart-request" | Out-Null;$last=$token}
                $ack=Remote "sudo -n cat $run/windows-control/restart-done 2>/dev/null || true"
                if("$ack".Trim() -eq $token){[IO.File]::WriteAllText("$control/restart-done",$token)}
            }
        }
        Start-Sleep -Milliseconds 100
        $client.Refresh()
    }
    $client.WaitForExit()
    if($client.ExitCode -ne 0){throw 'Windows reclaim test failed'}
    $report.passed=$true
}catch{$report.error=$_.Exception.Message}
finally{
    if($client -and -not $client.HasExited){$client.Kill();$client.WaitForExit()}
    if([IO.Path]::GetFullPath($credentials) -ne [IO.Path]::GetFullPath("C:/NfsLab/windows-nfs-runs/$RunId/credentials")){throw 'Credential cleanup path differs'}
    if(Test-Path -LiteralPath $credentials){
        if((Get-Item -LiteralPath $credentials).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Redirected credential path'}
        foreach($name in @('krb5.conf','nv-alice.keytab')){Remove-Item -LiteralPath "$credentials/$name" -Force -ErrorAction SilentlyContinue}
        Remove-Item -LiteralPath $credentials -Force
    }
    $report.credentials_removed=-not (Test-Path -LiteralPath $credentials)
    $report | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 "$root/windows-client.json"
    if($server){
        if($report.passed){
            Upload "$root/reclaim.log" "$stage/reclaim.log"
            Upload "$root/windows-client.json" "$stage/windows-client.json"
            Remote "sudo -n touch $run/windows-control/complete" | Out-Null
        }else{Remote "touch $stage/windows-abort" | Out-Null}
        if(-not $server.WaitForExit(60000)){throw 'Server cleanup deadline'}
        $server.WaitForExit()
        if($server.ExitCode -ne 0){throw 'Server reclaim or restoration failed'}
    }
}
if(-not $report.passed){throw 'Windows reclaim did not pass'}
