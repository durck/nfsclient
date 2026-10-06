[CmdletBinding()]
param(
    [string]$RuntimeRoot=(Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'),
    [string]$SevenZip='C:/Program Files/7-Zip/7z.exe'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime=Get-LabRuntimeRoot $RuntimeRoot
$iso=Join-Path $runtime 'media/windows-server-2025-eval.iso'
$metadataPath=Join-Path $runtime 'media/windows-server-2025-eval.metadata.json'
foreach ($path in @((Join-Path $runtime 'media'),$iso,$metadataPath)) { Assert-LabRegularPath $path }
$metadata=Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
if ((Get-Item -LiteralPath $iso).Length -ne 8152356864 -or $metadata.Bytes -ne 8152356864 -or (Get-FileHash -LiteralPath $iso).Hash -ne $metadata.SHA256) { throw 'Completed ISO and locally recorded hash do not agree.' }
if (!(Test-Path -LiteralPath $SevenZip -PathType Leaf)) { throw 'Existing 7-Zip is required; this helper installs no host tools.' }
$out=Join-Path $runtime 'windows-license'
Assert-LabRegularPath $out
if (Test-Path -LiteralPath $out) { throw 'License evidence already exists; inspect it rather than replacing it.' }
$driveName=[IO.Path]::GetPathRoot($runtime).Substring(0,1)
if ((Get-PSDrive $driveName).Free -lt 9000000000) { throw 'Insufficient room for temporary install.wim extraction.' }
New-Item -ItemType Directory -Path $out | Out-Null
$wim=Join-Path $out 'install.wim'
$entry='2/Windows/System32/en-US/Licenses/Eval/ServerStandardEval/license.rtf'
try {
    & $SevenZip e -y -bsp0 ('-o'+$out) $iso 'sources/install.wim' 2>&1 | Set-Content -LiteralPath (Join-Path $out 'iso-extraction.log') -Encoding utf8
    if ($LASTEXITCODE) { throw 'ISO extraction reported an error.' }
    & $SevenZip e -y -bsp0 ('-o'+$out) $wim $entry 2>&1 | Set-Content -LiteralPath (Join-Path $out 'terms-extraction.log') -Encoding utf8
    if ($LASTEXITCODE) { throw 'Terms extraction reported an error; inspect the preserved log.' }
    $rtf=Join-Path $out 'license.rtf'
    $plain=Join-Path $out 'license.txt'
    Add-Type -AssemblyName System.Windows.Forms
    # RichTextBox parses the local RTF without displaying any window or running Setup.
    $reader=[System.Windows.Forms.RichTextBox]::new()
    try {
        $reader.Rtf=[IO.File]::ReadAllText($rtf)
        [IO.File]::WriteAllText($plain,$reader.Text,[Text.UTF8Encoding]::new($false))
    } finally { $reader.Dispose() }
    [ordered]@{
        ISO=(Split-Path -Leaf $iso); ISOBytes=$metadata.Bytes; ISOSHA256=$metadata.SHA256;
        HashProvenance=$metadata.HashProvenance; WIMEntry='sources/install.wim'; LicenseEntry=$entry;
        RTFBytes=(Get-Item -LiteralPath $rtf).Length; RTFSHA256=(Get-FileHash -LiteralPath $rtf).Hash;
        TextSHA256=(Get-FileHash -LiteralPath $plain).Hash;
        ExtractedUtc=[DateTime]::UtcNow.ToString('o'); LicenseAccepted=$false;
        FullTermsLink='https://aka.ms/useterms';
        Limitation='Actual image resource contains a notice linking full terms; not a complete standalone agreement or proof of the exact Setup screen.'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'provenance.json') -Encoding utf8
    Write-Output "Actual ISO license resource ready for review: $rtf and $plain. No Windows installation or acceptance performed."
} finally {
    # Delete only the exact temporary copy inside the verified extraction root.
    if (Test-Path -LiteralPath $wim) {
        Assert-LabRegularPath $out
        Assert-LabRegularPath $wim
        if ([IO.Path]::GetFullPath($wim) -cne (Join-Path $out 'install.wim')) { throw 'Unexpected WIM cleanup path.' }
        Remove-Item -LiteralPath $wim
    }
}
