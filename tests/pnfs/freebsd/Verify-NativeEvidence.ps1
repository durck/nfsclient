[CmdletBinding()]
param([Parameter(Mandatory)][string]$EvidenceRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path -LiteralPath $EvidenceRoot).Path
$mds = @{}
$ds = @{}
foreach ($line in Get-Content -LiteralPath (Join-Path $root 'native-mds.tsv')) {
    $parts = $line.Split("`t")
    if ($parts.Count -ne 5 -or $parts[0] -ne 'MDS' -or $mds.ContainsKey($parts[1])) {
        throw 'Invalid or duplicate native MDS record.'
    }
    $mds[$parts[1]] = $parts
}
foreach ($line in Get-Content -LiteralPath (Join-Path $root 'native-ds.tsv')) {
    $parts = $line.Split("`t")
    if ($parts.Count -ne 4 -or $parts[0] -ne 'DS' -or $ds.ContainsKey($parts[1])) {
        throw 'Invalid or duplicate native DS record.'
    }
    $ds[$parts[1]] = $parts
}
$guests = Get-Content -LiteralPath (Join-Path $root 'guests.json') -Raw | ConvertFrom-Json
$server = @($guests.machines | Where-Object role -eq 'ds')
if ($server.Count -ne 1 -or !$server[0].serial_hostkey_verified) { throw 'DS identity is not verified.' }
$expectedHash = '1a9761df8b9f2bb07582bca30421258fcca4bd966a75ff22c28e20fbffaea306'
$profiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'natural') -Filter '*.json')
if ($profiles.Count -ne 8) { throw 'Expected exactly eight natural recall profiles.' }
$matrix = @{}
$names = @{}
$paths = @{}
$verified = @()
foreach ($file in $profiles) {
    $p = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    if ($p.Platform -notin @('windows','linux') -or $p.Version -notin @('4.1','4.2') -or $p.Held -isnot [bool]) {
        throw 'Unexpected profile identity.'
    }
    $profile = '{0}/{1}/{2}' -f $p.Platform,$p.Version,$p.Held
    if ($matrix.ContainsKey($profile)) { throw 'Duplicate natural recall profile.' }
    $matrix[$profile] = $true
    if ($p.PayloadSHA256 -ne $expectedHash) { throw 'Unexpected test payload.' }
    foreach ($name in @($p.RemoteA,$p.RemoteB)) {
        if ($names.ContainsKey($name) -or !$mds.ContainsKey($name)) { throw "Missing or duplicate native file: $name" }
        $names[$name] = $true
        $m = $mds[$name]
        if ($m[2] -ne '25001 25000 644 0' -or $m[3] -ne $server[0].ip -or
            $m[4] -notmatch '^ds([0-9]|1[0-9])/[0-9a-f]+$' -or !$ds.ContainsKey($m[4])) {
            throw "Native MDS metadata or DS mapping differs: $name"
        }
        if ($paths.ContainsKey($m[4])) { throw 'Two source names unexpectedly share a DS object.' }
        $paths[$m[4]] = $true
        $d = $ds[$m[4]]
        if ($d[2] -ne '25001 25000 644 1048593' -or $d[3] -ne $expectedHash) {
            throw "Native DS metadata or complete payload differs: $name"
        }
        $verified += @{profile=$profile;name=$name;data_path=$m[4];bytes=1048593;sha256=$d[3];uid=25001;gid=25000;mode='644';mds_placeholder_bytes=0}
    }
}
$result = @{ok=$true;profiles=$matrix.Count;native_files=$verified.Count;source='Independent FreeBSD stat, pnfsdsfile and DS sha256';files=$verified}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'native.json') -Encoding utf8
Write-Output "Verified $($matrix.Count) profiles and $($verified.Count) distinct native DS files."
