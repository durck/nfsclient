# Run interactively inside NFSADDC1. Never reads the old password store.
# Creates a separate fixture once; an interrupted run requires inspection.
[CmdletBinding()]
param([switch]$CheckOnly)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-DedicatedDC {
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($env:COMPUTERNAME -ne 'NFSADDC1' -or $computer.Manufacturer -ne 'VMware, Inc.' -or
        (Get-CimInstance Win32_OperatingSystem).ProductType -ne 2) { throw 'Expected the dedicated NFSADDC1 guest.' }
    Import-Module ActiveDirectory
    Import-Module DnsServer
    if ((Get-ADDomain).DNSRoot -ne 'msad.nfs.test') { throw 'Unexpected domain.' }
    $adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up')
    $routes = @(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0'))
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '192.0.2.10')
    if ($adapters.Count -ne 1 -or $adapters[0].MacAddress -ne '00-0C-29-0E-6A-52' -or
        $routes.Count -or $ips.Count -ne 1 -or $ips[0].PrefixLength -ne 24) { throw 'Unexpected private network.' }
}

function Get-OriginalState {
    $users = foreach ($name in @('alice','bob','svc-nfs')) {
        Get-ADUser $name -Properties pwdLastSet,'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes',ServicePrincipalName,MemberOf |
            Select-Object SamAccountName,DistinguishedName,pwdLastSet,'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes',ServicePrincipalName,MemberOf
    }
    $machine = Get-ADComputer NFS -Properties pwdLastSet,'msDS-KeyVersionNumber',ServicePrincipalName |
        Select-Object DistinguishedName,pwdLastSet,'msDS-KeyVersionNumber',ServicePrincipalName
    $owners = @(Get-ADObject -LDAPFilter '(servicePrincipalName=nfs/nfs.msad.nfs.test)')
    if ($owners.Count -ne 1 -or $owners[0].DistinguishedName -ne 'CN=svc-nfs,OU=NfsViewerLab,DC=msad,DC=nfs,DC=test') {
        throw 'Original NFS SPN owner changed.'
    }
    return [ordered]@{ Users=$users; Machine=$machine; OriginalSpnOwner=$owners[0].DistinguishedName }
}

function Assert-PrivateBridge {
    foreach ($path in @($script:bridge, "$script:bridge\identity", "$script:bridge\known_hosts")) {
        $item = Get-Item -LiteralPath $path
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected bridge redirection.' }
        $acl = Get-Acl -LiteralPath $path
        if (!$acl.AreAccessRulesProtected) { throw 'Bridge ACL inheritance is not protected.' }
        $allowed = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed) {
                throw 'Bridge ACL grants another identity access.'
            }
        }
    }
    $known = @(Get-Content -LiteralPath "$script:bridge\known_hosts" | Where-Object { $_.Trim() })
    if ($known.Count -ne 1 -or $known[0] -cnotmatch '^192\.0\.2\.20 ssh-ed25519 [A-Za-z0-9+/]+={0,2}$') {
        throw 'Expected one exact Linux host-key entry without other hosts or wildcard keys.'
    }
    $pin = @(& C:\Windows\System32\OpenSSH\ssh-keygen.exe -lf "$script:bridge\known_hosts" -E sha256)
    if ($LASTEXITCODE -ne 0 -or $pin.Count -ne 1 -or $pin[0] -cnotmatch '^256 SHA256:OYmLSHzEhLDKqcXI43vKyVP2ibCshdgUzFs/xS5ywG8 ') { throw 'Linux SSH host-key pin differs.' }
}

function Invoke-NativeProvision([string]$Arguments, [string]$Payload) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = 'C:\Windows\System32\OpenSSH\ssh.exe'
    $info.Arguments = '-F NUL -o StrictHostKeyChecking=yes -o UserKnownHostsFile=C:/NfsLab/linux-bridge/known_hosts -o GlobalKnownHostsFile=NUL -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=10 -i C:/NfsLab/linux-bridge/identity labadmin@192.0.2.20 "sudo -n timeout --signal=TERM --kill-after=5s 300s python3 -B /usr/local/lib/nfs-viewer-msad/provision-linux-keys.py ' + $Arguments + '"'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($Payload) {
            # Windows PowerShell 5 uses the console OEM encoding for WriteLine.
            # The Linux JSON receiver expects UTF-8, independent of host locale.
            $bytes = [Text.Encoding]::UTF8.GetBytes($Payload + "`n")
            try {
                $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
                $process.StandardInput.BaseStream.Flush()
            } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
        }
        $process.StandardInput.Close()
        if (!$process.WaitForExit(330000)) { $process.Kill(); throw 'Linux preparation timed out; do not rerun.' }
        # Do not persist raw native output: errors may contain supplied data.
        if ($process.ExitCode -ne 0) { throw 'Linux preparation failed; preserve the existing attempt for inspection.' }
        try { $result = $stdout.GetAwaiter().GetResult() | ConvertFrom-Json } catch { throw 'Invalid Linux evidence response.' }
        $expectedStage = if ($Arguments -eq '--profile interop --preflight') { 'credential-preflight' } else { 'native-msad-current-keys' }
        if ($result -isnot [Management.Automation.PSCustomObject] -or $result.passed -isnot [bool] -or
            $result.passed -ne $true -or $result.profile -cne 'interop' -or $result.stage -cne $expectedStage) {
            throw 'Linux preparation was not verified for the requested interop stage.'
        }
        if ($expectedStage -eq 'credential-preflight') {
            if ($result.root_absent -isnot [bool] -or !$result.root_absent -or
                $result.stdin_read -isnot [bool] -or $result.stdin_read) { throw 'Invalid read-only preflight evidence.' }
        } elseif ($result.service_principal -cne 'nfs/nfs-interop.msad.nfs.test@MSAD.NFS.TEST') {
            throw 'Unexpected prepared service principal.'
        }
        return $result
    } finally { $process.Dispose() }
}

function Read-NewPassword([string]$Name) {
    $first = Read-Host "NEW password for $Name (16+ characters, mixed case/digits/symbol)" -AsSecureString
    $second = Read-Host "Repeat password for $Name" -AsSecureString
    $a = [IntPtr]::Zero
    $b = [IntPtr]::Zero
    try {
        $a = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($first)
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($second)
        $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($a)
        if ($value -cne [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) -or
            [Globalization.StringInfo]::ParseCombiningCharacters($value).Length -lt 16 -or
            $value.Length -gt 256 -or $value -match '[\r\n\x00]' -or
            $value -cnotmatch '[A-Z]' -or $value -cnotmatch '[a-z]' -or $value -notmatch '[0-9]' -or $value -notmatch '[^A-Za-z0-9]') {
            throw 'Passwords differ or do not meet the stated format. Nothing has been created.'
        }
        return $first
    } finally {
        if ($a -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($a) }
        if ($b -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
        $value = $null
        $second.Dispose()
    }
}

Assert-DedicatedDC
$bridge = 'C:\NfsLab\linux-bridge'
Assert-PrivateBridge
$run = Join-Path $bridge 'interop-manual'
$ou = 'OU=NfsViewerInterop,DC=msad,DC=nfs,DC=test'
$names = @('nv-alice','nv-bob','nv-nfs')
if (Test-Path -LiteralPath $run) { throw 'Manual attempt already exists. Do not repeat; ask for inspection.' }
$collision = '(|(ou=NfsViewerInterop)(sAMAccountName=nv-alice)(sAMAccountName=nv-bob)(sAMAccountName=nv-nfs)(sAMAccountName=nviusers)(sAMAccountName=nvireaders)(uidNumber=25001)(uidNumber=25002)(uidNumber=25004)(gidNumber=25000)(gidNumber=25003)(servicePrincipalName=nfs/nfs-interop.msad.nfs.test)(userPrincipalName=nv-alice@MSAD.NFS.TEST)(userPrincipalName=nv-bob@MSAD.NFS.TEST)(userPrincipalName=nv-nfs@MSAD.NFS.TEST))'
if (@(Get-ADObject -LDAPFilter $collision).Count) { throw 'Interop names, Unix IDs or SPN already exist; refusing reuse.' }
if (@(Get-DnsServerResourceRecord -ZoneName msad.nfs.test | Where-Object HostName -eq 'nfs-interop').Count) {
    throw 'Interop DNS record already exists; refusing reuse.'
}
$before = Get-OriginalState
$preflight = Invoke-NativeProvision '--profile interop --preflight' ''
if ($CheckOnly) { Write-Output 'INTEROP_PREFLIGHT_OK'; exit 0 }

Write-Host 'Creates only nv-alice, nv-bob, nv-nfs and their separate NFS fixture. Original accounts are preserved.'
Write-Host 'Type new lab passwords below. They are never written to source, command arguments or password files.'
$secure = @{}
$plain = @{}
$phase = 'password-input'
$ownsRun = $false
try {
    foreach ($name in $names) { $secure[$name] = Read-NewPassword $name }
    $directory = New-Item -ItemType Directory -Path $run
    $ownsRun = $true
    Set-Acl -LiteralPath $directory.FullName -AclObject (Get-Acl -LiteralPath $bridge)
    $before | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$run\original-before.json" -Encoding UTF8
    $phase = 'create-accounts'
    New-ADOrganizationalUnit -Name NfsViewerInterop -Path 'DC=msad,DC=nfs,DC=test' -ProtectedFromAccidentalDeletion $false
    New-ADGroup -Name nviusers -SamAccountName nviusers -GroupScope Global -GroupCategory Security -Path $ou -OtherAttributes @{ gidNumber=25000 }
    New-ADGroup -Name nvireaders -SamAccountName nvireaders -GroupScope Global -GroupCategory Security -Path $ou -OtherAttributes @{ gidNumber=25003 }
    $ids = @{'nv-alice'=25001; 'nv-bob'=25002; 'nv-nfs'=25004}
    foreach ($name in $names) {
        New-ADUser -Name $name -SamAccountName $name -UserPrincipalName "$name@MSAD.NFS.TEST" -Path $ou `
            -AccountPassword $secure[$name] -Enabled $true -ChangePasswordAtLogon $false -KerberosEncryptionType AES128,AES256 `
            -OtherAttributes @{ uidNumber=$ids[$name]; gidNumber=25000; unixHomeDirectory="/home/$name"; loginShell='/usr/sbin/nologin' }
    }
    Add-ADGroupMember nviusers -Members $names
    Add-ADGroupMember nvireaders -Members nv-alice
    & setspn.exe -S nfs/nfs-interop.msad.nfs.test NFSMSAD\nv-nfs
    if ($LASTEXITCODE -ne 0) { throw 'Interop SPN registration failed.' }
    Add-DnsServerResourceRecordA -ZoneName msad.nfs.test -Name nfs-interop -IPv4Address 192.0.2.20
    $kvnos = @{}
    $accounts = foreach ($name in $names) {
        $user = Get-ADUser $name -Properties 'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes',uidNumber,gidNumber,ServicePrincipalName
        $kvnos[$name] = [int]$user.'msDS-KeyVersionNumber'
        if ($kvnos[$name] -lt 1 -or $kvnos[$name] -gt 255 -or $user.'msDS-SupportedEncryptionTypes' -ne 24 -or !$user.Enabled) {
            throw 'Unexpected new account metadata.'
        }
        $user | Select-Object SamAccountName,DistinguishedName,'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes',uidNumber,gidNumber,ServicePrincipalName
    }
    $accounts | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$run\accounts.json" -Encoding UTF8
    $phase = 'native-keys'
    foreach ($name in $names) {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure[$name])
        try { $plain[$name] = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
    $payload = @{ passwords=$plain; kvnos=$kvnos } | ConvertTo-Json -Compress
    $native = Invoke-NativeProvision '--profile interop' $payload
    $payload = $null
    $plain.Clear()
    $phase = 'verify-originals'
    $after = Get-OriginalState
    $after | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$run\original-after.json" -Encoding UTF8
    if (($before | ConvertTo-Json -Depth 10 -Compress) -cne ($after | ConvertTo-Json -Depth 10 -Compress)) { throw 'Original account metadata changed.' }
    [ordered]@{ Passed=$true; Utc=[DateTime]::UtcNow.ToString('o'); Profile='interop'; OriginalAccountsUnchanged=$true;
        Native=$native; MicrosoftADNFSValidated=$false } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath "$run\status.json" -Encoding UTF8
    Write-Output 'INTEROP_KEYS_READY'
    Write-Host 'Send only INTEROP_KEYS_READY to the test coordinator. Leave both lab VMs running.'
} catch {
    if ($ownsRun) {
        @{ Passed=$false; Phase=$phase; Utc=[DateTime]::UtcNow.ToString('o'); NoAutomaticRetry=$true } |
            ConvertTo-Json | Set-Content -LiteralPath "$run\status.json" -Encoding UTF8
    }
    Write-Host "INTEROP_SETUP_STOPPED phase=$phase. Do not rerun. Send this line to the test coordinator."
    exit 1
} finally {
    $payload = $null
    $plain.Clear()
    foreach ($value in $secure.Values) { $value.Dispose() }
    $secure.Clear()
}
