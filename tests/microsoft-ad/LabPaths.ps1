function Get-LabRuntimeRoot {
    param([Parameter(Mandatory)][string]$Path)
    $repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $allowed = [IO.Path]::GetFullPath((Join-Path $repo 'bin/microsoft-ad-lab'))
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (![string]::Equals($candidate, $allowed, [StringComparison]::OrdinalIgnoreCase)) {
        throw "RuntimeRoot must be the dedicated ignored lab directory: $allowed"
    }
    $current = $candidate
    while ($current.Length -ge $repo.Length) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Lab path must be a regular directory, without redirection: $current"
            }
        }
        if ([string]::Equals($current, $repo, [StringComparison]::OrdinalIgnoreCase)) { break }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    return $candidate
}

function Assert-LabRegularPath {
    param([Parameter(Mandatory)][string]$Path)
    # Call only on a known child of the validated runtime root.
    if ((Test-Path -LiteralPath $Path) -and ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing a redirected lab path: $Path"
    }
}

function Assert-LinuxNotDomainOwned {
    param([Parameter(Mandatory)][string]$RuntimeRoot)
    # Presence is a reservation, not a compatibility claim. Fail before even
    # inspecting/attaching historical media, whose frozen runners lack guards.
    $marker = Join-Path $RuntimeRoot 'nfs/domain-state.json'
    Assert-LabRegularPath $marker
    if (Test-Path -LiteralPath $marker) {
        throw 'Linux guest is reserved for Microsoft AD; refusing bootstrap or synthetic kernel media. Preserve its machine keytab and SSSD state.'
    }
}
