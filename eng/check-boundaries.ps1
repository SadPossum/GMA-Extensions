[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sourceRoot = Join-Path $repositoryRoot 'src'
$errors = [System.Collections.Generic.List[string]]::new()

$allowedModuleReferences = @{
    'Gma.Extensions.Auth.Notifications' = @(
        '$(GmaModuleAuthRoot)Gma.Modules.Auth.Contracts\Gma.Modules.Auth.Contracts.csproj'
        '$(GmaModuleNotificationsRoot)Gma.Modules.Notifications.Adapters.Email\Gma.Modules.Notifications.Adapters.Email.csproj'
        '$(GmaModuleNotificationsRoot)Gma.Modules.Notifications.Application\Gma.Modules.Notifications.Application.csproj'
        '$(GmaModuleNotificationsRoot)Gma.Modules.Notifications.Contracts\Gma.Modules.Notifications.Contracts.csproj'
    )
    'Gma.Extensions.Auth.Organizations' = @(
        '$(GmaModuleAuthRoot)Gma.Modules.Auth.Contracts\Gma.Modules.Auth.Contracts.csproj'
        '$(GmaModuleOrganizationsRoot)Gma.Modules.Organizations.Contracts\Gma.Modules.Organizations.Contracts.csproj'
    )
    'Gma.Extensions.Organizations.AccessControl' = @(
        '$(GmaModuleAccessControlRoot)Gma.Modules.AccessControl.Contracts\Gma.Modules.AccessControl.Contracts.csproj'
        '$(GmaModuleOrganizationsRoot)Gma.Modules.Organizations.Contracts\Gma.Modules.Organizations.Contracts.csproj'
    )
    'Gma.Extensions.Organizations.Tenancy' = @(
        '$(GmaModuleOrganizationsRoot)Gma.Modules.Organizations.Contracts\Gma.Modules.Organizations.Contracts.csproj'
    )
}

$allowedModuleNamespaces = @{
    'Gma.Extensions.Auth.Notifications' = @(
        'Gma.Modules.Auth.Contracts'
        'Gma.Modules.Notifications.Adapters.Email'
        'Gma.Modules.Notifications.Application.Ports'
        'Gma.Modules.Notifications.Contracts'
    )
    'Gma.Extensions.Auth.Organizations' = @(
        'Gma.Modules.Auth.Contracts'
        'Gma.Modules.Organizations.Contracts'
    )
    'Gma.Extensions.Organizations.AccessControl' = @(
        'Gma.Modules.AccessControl.Contracts'
        'Gma.Modules.Organizations.Contracts'
    )
    'Gma.Extensions.Organizations.Tenancy' = @(
        'Gma.Modules.Organizations.Contracts'
    )
}

function Get-RelativePath {
    param([string] $TargetPath)

    $baseUri = [Uri]::new($repositoryRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar)
    $targetUri = [Uri]::new($TargetPath)
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($targetUri).ToString()).Replace('/', '\')
}

function Test-AllowedNamespace {
    param(
        [string] $Candidate,
        [string[]] $Allowed
    )

    foreach ($prefix in $Allowed) {
        if ($prefix.StartsWith('=', [StringComparison]::Ordinal)) {
            if ([string]::Equals($Candidate, $prefix.Substring(1), [StringComparison]::Ordinal)) {
                return $true
            }

            continue
        }

        if ([string]::Equals($Candidate, $prefix, [StringComparison]::Ordinal) -or
            $Candidate.StartsWith($prefix + '.', [StringComparison]::Ordinal)) {
            return $true
        }
    }

    return $false
}

$extensionDirectories = @(Get-ChildItem -LiteralPath $sourceRoot -Directory)
foreach ($extensionDirectory in $extensionDirectories) {
    $extensionName = $extensionDirectory.Name
    if (-not $allowedModuleReferences.ContainsKey($extensionName) -or
        -not $allowedModuleNamespaces.ContainsKey($extensionName)) {
        $errors.Add("$extensionName is missing an explicit module boundary allowlist.")
        continue
    }

    $projectPath = Join-Path $extensionDirectory.FullName "$extensionName.csproj"
    if (-not (Test-Path -LiteralPath $projectPath -PathType Leaf)) {
        $errors.Add("$extensionName is missing its expected project file.")
        continue
    }

    [xml] $project = Get-Content -LiteralPath $projectPath -Raw
    foreach ($reference in $project.SelectNodes('//ProjectReference')) {
        $include = $reference.GetAttribute('Include')
        if ($include -match '^\$\(GmaFrameworkRoot\)') {
            continue
        }

        if ($include -notmatch '^\$\(GmaModule' -or
            $allowedModuleReferences[$extensionName] -notcontains $include) {
            $errors.Add("$extensionName has an undeclared module project reference '$include'.")
        }
    }

    foreach ($reference in $project.SelectNodes('//PackageReference')) {
        $include = $reference.GetAttribute('Include')
        if ($include -match '^(?:Gma\.Modules\.|BunkFy(?:\.|$)|StayQuest(?:\.|$))') {
            $errors.Add("$extensionName has a forbidden module or product package reference '$include'.")
        }
    }

    $sourceFiles = @(Get-ChildItem -LiteralPath $extensionDirectory.FullName -Filter '*.cs' -File)
    foreach ($sourceFile in $sourceFiles) {
        $source = Get-Content -LiteralPath $sourceFile.FullName -Raw
        $relativePath = Get-RelativePath -TargetPath $sourceFile.FullName
        if ($source -match '(?:BunkFy|StayQuest)\.') {
            $errors.Add("$relativePath contains product-specific source.")
        }

        $matches = [regex]::Matches($source, 'Gma\.Modules\.[A-Za-z0-9_.]+')
        foreach ($match in $matches) {
            $candidate = $match.Value.TrimEnd('.')
            if (-not (Test-AllowedNamespace -Candidate $candidate -Allowed $allowedModuleNamespaces[$extensionName])) {
                $errors.Add("$relativePath uses undeclared module surface '$candidate'.")
            }
        }
    }
}

if ($errors.Count -gt 0) {
    throw "Extensions boundary checks failed:`n - $($errors -join "`n - ")"
}

Write-Host 'Extensions boundary checks passed.'
