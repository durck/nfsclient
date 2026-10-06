# Run inside the dedicated DC, through VMware Tools. No host networking needed.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('preflight','prepare','join','configure','verify','verify-bob-reader')][string]$Action,
    [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9-]{1,60}$')][string]$EvidenceName,
    [Security.SecureString]$JoinPassword
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
if ($env:COMPUTERNAME -ne 'NFSADDC1' -or $computer.Manufacturer -ne 'VMware, Inc.' -or $os.ProductType -ne 2) {
    throw 'Expected the dedicated VMware domain controller NFSADDC1.'
}
Import-Module ActiveDirectory
if ((Get-ADDomain).DNSRoot -ne 'msad.nfs.test') { throw 'Unexpected lab domain.' }
$adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up')
$routes = @(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0'))
$ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '192.0.2.10')
if ($adapters.Count -ne 1 -or $adapters[0].MacAddress -ne '00-0C-29-0E-6A-52' -or $routes.Count -or
    $ips.Count -ne 1 -or $ips[0].PrefixLength -ne 24) { throw 'Unexpected DC private network.' }
$spn = @(Get-ADObject -LDAPFilter '(servicePrincipalName=nfs/nfs.msad.nfs.test)' -Properties servicePrincipalName)
if ($spn.Count -ne 1 -or $spn[0].DistinguishedName -ne 'CN=svc-nfs,OU=NfsViewerLab,DC=msad,DC=nfs,DC=test') {
    throw 'NFS SPN ownership has changed.'
}
if ($Action -in @('prepare','join') -and @(Get-ADComputer -LDAPFilter '(sAMAccountName=NFS$)').Count) {
    throw 'Existing NFS computer account; inspect prior enrollment instead of resetting it.'
}
if ($Action -in @('prepare','join')) {
    foreach ($principal in @('HOST/nfs','HOST/nfs.msad.nfs.test','RestrictedKrbHost/nfs','RestrictedKrbHost/nfs.msad.nfs.test')) {
        if (@(Get-ADObject -LDAPFilter ('(servicePrincipalName=' + $principal + ')')).Count) {
            throw ('Existing machine SPN; refusing to reuse it: ' + $principal)
        }
    }
}
if (($Action -eq 'join') -ne ($null -ne $JoinPassword)) { throw 'Join alone requires the password as SecureString input.' }
$root = 'C:\NfsLab\linux-bridge'
foreach ($path in @($root, "$root\identity", "$root\known_hosts")) {
    $item = Get-Item -LiteralPath $path
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected bridge path redirection.' }
    if (!(Get-Acl -LiteralPath $path).AreAccessRulesProtected) { throw 'Unprotected bridge ACL.' }
}
$output = Join-Path $root ($EvidenceName + '.json')
if (Test-Path -LiteralPath $output) { throw 'Evidence already exists; choose a fresh name.' }
$command = 'sudo -n /usr/bin/python3 /usr/local/lib/nfs-viewer-msad/join-linux-domain.py ' + $Action
if ($Action -in @('preflight','prepare')) { $command += ' ' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
$info = New-Object Diagnostics.ProcessStartInfo
$info.FileName = 'C:\Windows\System32\OpenSSH\ssh.exe'
$info.Arguments = '-F NUL -o StrictHostKeyChecking=yes -o UserKnownHostsFile=C:/NfsLab/linux-bridge/known_hosts -o GlobalKnownHostsFile=NUL -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=10 -i C:/NfsLab/linux-bridge/identity labadmin@192.0.2.20 "' + $command + '"'
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
$info.RedirectStandardInput = $true
$process = New-Object Diagnostics.Process
$process.StartInfo = $info
$started = $process.Start()
if (!$started) { throw 'SSH process did not start.' }
$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()
try {
    if ($Action -eq 'join') {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($JoinPassword)
        try {
            $process.StandardInput.WriteLine([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer))
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
    $process.StandardInput.Close()
    $timedOut = !$process.WaitForExit(180000)
    if ($timedOut) {
        $process.Kill()
        [void]$process.WaitForExit(5000)
    }
    $stdout = if (!$timedOut -or $stdoutTask.IsCompleted) { $stdoutTask.GetAwaiter().GetResult() } else { 'SSH stdout pipe did not close after timeout.' }
    $stderr = if (!$timedOut -or $stderrTask.IsCompleted) { $stderrTask.GetAwaiter().GetResult() } else { 'SSH stderr pipe did not close after timeout.' }
    [IO.File]::WriteAllText((Join-Path $root ($EvidenceName + '.stderr.txt')), $stderr)
    [IO.File]::WriteAllText((Join-Path $root ($EvidenceName + '.stdout.txt')), $stdout)
    if ($timedOut) {
        throw 'SSH timed out; remote enrollment may have completed. Inspect retained output/state; never repeat join automatically.'
    }
    if ($process.ExitCode -ne 0) { throw ('Linux action failed with exit ' + $process.ExitCode + '; inspect retained stdout/stderr.') }
    $value = $stdout | ConvertFrom-Json
    [ordered]@{
        CheckedUtc = [DateTime]::UtcNow.ToString('o')
        Action = $Action
        ExitCode = $process.ExitCode
        Linux = $value
        NfsSpnOwner = $spn[0].DistinguishedName
        MicrosoftADNFSValidated = $false
    } | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $output -Encoding UTF8
    Write-Output ('Linux domain action passed: ' + $Action)
} finally {
    $process.Dispose()
}
