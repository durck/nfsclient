# Dedicated-DC receiver: passwords are RSA-OAEP encrypted in VMware file transfer,
# decrypted only in memory, then forwarded to Linux over pinned SSH stdin.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('^keys-[0-9]{8}-[0-9]{2}$')][string]$RunId)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:COMPUTERNAME -ne 'NFSADDC1' -or (Get-CimInstance Win32_ComputerSystem).Manufacturer -ne 'VMware, Inc.' -or
    (Get-CimInstance Win32_OperatingSystem).ProductType -ne 2) { throw 'Expected the dedicated DC.' }
Import-Module ActiveDirectory
if ((Get-ADDomain).DNSRoot -ne 'msad.nfs.test') { throw 'Unexpected domain.' }
if (@(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0')).Count) { throw 'Unexpected external route.' }
$bridge = 'C:\NfsLab\linux-bridge'
$run = Join-Path $bridge $RunId
if (Test-Path -LiteralPath $run) { throw 'Credential receiver already started; inspect it rather than duplicating it.' }
$directory = New-Item -ItemType Directory -Path $run
Set-Acl -LiteralPath $directory.FullName -AclObject (Get-Acl -LiteralPath $bridge)
function Read-IdentitySnapshot {
    $users = foreach ($name in @('alice','bob','svc-nfs')) {
        $user = Get-ADUser $name -Properties pwdLastSet,'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes',ServicePrincipalName
        if ($user.DistinguishedName -ne ('CN=' + $name + ',OU=NfsViewerLab,DC=msad,DC=nfs,DC=test') -or
            $user.'msDS-KeyVersionNumber' -ne 2 -or $user.'msDS-SupportedEncryptionTypes' -ne 24 -or !$user.Enabled) {
            throw 'Unexpected current test account metadata.'
        }
        $user | Select-Object SamAccountName,DistinguishedName,pwdLastSet,'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes',ServicePrincipalName
    }
    $owners = @(Get-ADObject -LDAPFilter '(servicePrincipalName=nfs/nfs.msad.nfs.test)')
    if ($owners.Count -ne 1 -or $owners[0].DistinguishedName -ne 'CN=svc-nfs,OU=NfsViewerLab,DC=msad,DC=nfs,DC=test') { throw 'NFS SPN owner changed.' }
    $machine = Get-ADComputer NFS -Properties pwdLastSet,'msDS-KeyVersionNumber',ServicePrincipalName
    return [ordered]@{Users=$users;Machine=$machine | Select-Object DistinguishedName,pwdLastSet,'msDS-KeyVersionNumber',ServicePrincipalName;SpnOwner=$owners[0].DistinguishedName}
}
$rsa = New-Object Security.Cryptography.RSACryptoServiceProvider 4096
$rsa.PersistKeyInCsp = $false
try {
    $before = Read-IdentitySnapshot
    $before | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $run 'ad-before.json') -Encoding UTF8
    [IO.File]::WriteAllBytes((Join-Path $run 'receiver-public.csp'), $rsa.ExportCspBlob($false))
    $encrypted = Join-Path $run 'passwords.encrypted.json'
    $deadline = [DateTime]::UtcNow.AddSeconds(180)
    while (!(Test-Path -LiteralPath $encrypted)) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Encrypted credential delivery timed out.' }
        Start-Sleep -Seconds 1
    }
    $packet = Get-Content -LiteralPath $encrypted -Raw | ConvertFrom-Json
    if ($packet.RunId -ne $RunId -or $packet.PublicKeySHA256 -ne (Get-FileHash -LiteralPath (Join-Path $run 'receiver-public.csp')).Hash) {
        throw 'Credential packet is not bound to this receiver.'
    }
    $values = @{}
    foreach ($name in @('alice','bob','svc-nfs')) {
        $bytes = $rsa.Decrypt([Convert]::FromBase64String($packet.Passwords.$name), $true)
        try { $values[$name] = [Text.Encoding]::UTF8.GetString($bytes) } finally { [Array]::Clear($bytes,0,$bytes.Length) }
    }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = 'C:\Windows\System32\OpenSSH\ssh.exe'
    $info.Arguments = '-F NUL -o StrictHostKeyChecking=yes -o UserKnownHostsFile=C:/NfsLab/linux-bridge/known_hosts -o GlobalKnownHostsFile=NUL -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=10 -i C:/NfsLab/linux-bridge/identity labadmin@192.0.2.20 "sudo -n timeout --signal=TERM --kill-after=5s 180s python3 /usr/local/lib/nfs-viewer-msad/provision-linux-keys.py"'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    try {
        $process.StandardInput.WriteLine(($values | ConvertTo-Json -Compress))
        $process.StandardInput.Close()
        $values.Clear()
        if (!$process.WaitForExit(240000)) { $process.Kill(); throw 'Native key preparation timed out; inspect private staging without resetting accounts.' }
        [IO.File]::WriteAllText((Join-Path $run 'native.stdout.json'), $stdout.GetAwaiter().GetResult())
        [IO.File]::WriteAllText((Join-Path $run 'native.stderr.txt'), $stderr.GetAwaiter().GetResult())
        if ($process.ExitCode -ne 0) { throw 'Native key preparation failed; no automatic retry.' }
    } finally { $process.Dispose() }
    $after = Read-IdentitySnapshot
    $after | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $run 'ad-after.json') -Encoding UTF8
    if (($before | ConvertTo-Json -Depth 8 -Compress) -cne ($after | ConvertTo-Json -Depth 8 -Compress)) {
        throw 'Account password version/time or SPN changed during key preparation.'
    }
    [ordered]@{Passed=$true;RunId=$RunId;Utc=[DateTime]::UtcNow.ToString('o');ADAccountsUnchanged=$true;PlaintextPasswordFiles=$false;MicrosoftADNFSValidated=$false} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'receiver-status.json') -Encoding UTF8
} catch {
    # Fixed descriptions only; do not serialize packet, password or key objects.
    [ordered]@{Passed=$false;RunId=$RunId;Utc=[DateTime]::UtcNow.ToString('o');Error=$_.Exception.Message} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'receiver-status.json') -Encoding UTF8
    exit 1
} finally {
    $rsa.Clear()
    if (Test-Path -LiteralPath (Join-Path $run 'passwords.encrypted.json')) { Remove-Item -LiteralPath (Join-Path $run 'passwords.encrypted.json') -Force }
}
