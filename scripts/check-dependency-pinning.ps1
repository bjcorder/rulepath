$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$failures = New-Object System.Collections.Generic.List[string]

function Add-Failure {
    param([string] $Message)
    $failures.Add($Message)
}

function Resolve-RepoPath {
    param([string] $Path)
    Join-Path $repoRoot $Path
}

$cargoLock = Resolve-RepoPath "Cargo.lock"
if (-not (Test-Path -LiteralPath $cargoLock -PathType Leaf)) {
    Add-Failure "Cargo.lock must be committed at the workspace root."
}

$toolchainPath = Resolve-RepoPath "rust-toolchain.toml"
if (-not (Test-Path -LiteralPath $toolchainPath -PathType Leaf)) {
    Add-Failure "rust-toolchain.toml must be committed."
} else {
    $toolchainContent = Get-Content -LiteralPath $toolchainPath -Raw
    if ($toolchainContent -notmatch '(?m)^\s*channel\s*=\s*"(?<channel>[^"]+)"\s*$') {
        Add-Failure "rust-toolchain.toml must set an exact channel."
    } elseif ($Matches.channel -notmatch '^\d+\.\d+\.\d+$') {
        Add-Failure "rust-toolchain.toml channel must be an exact release, not '$($Matches.channel)'."
    }
}

try {
    $metadataJson = cargo metadata --locked --format-version 1 --no-deps
    $metadata = $metadataJson | ConvertFrom-Json
    foreach ($package in $metadata.packages) {
        foreach ($dependency in $package.dependencies) {
            if ($dependency.source -like "registry+*") {
                if ($dependency.req -notmatch '^=\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
                    Add-Failure "Cargo dependency '$($dependency.name)' in package '$($package.name)' must use an exact '=x.y.z' requirement, found '$($dependency.req)'."
                }
            } elseif ($dependency.source -like "git+*") {
                if ($dependency.source -notmatch '[?#&]rev=[a-fA-F0-9]{40}(?:[&#]|$)') {
                    Add-Failure "Cargo git dependency '$($dependency.name)' in package '$($package.name)' must use rev = '<40-character SHA>'."
                }
            }
        }
    }
} catch {
    Add-Failure "cargo metadata --locked failed: $($_.Exception.Message)"
}

$workflowRoot = Resolve-RepoPath ".github/workflows"
if (Test-Path -LiteralPath $workflowRoot -PathType Container) {
    Get-ChildItem -LiteralPath $workflowRoot -File | Where-Object { $_.Extension -in ".yml", ".yaml" } | ForEach-Object {
        $relative = Resolve-Path -LiteralPath $_.FullName -Relative
        $lines = Get-Content -LiteralPath $_.FullName
        for ($index = 0; $index -lt $lines.Count; $index++) {
            $line = $lines[$index]
            if ($line -match '\b(?:ubuntu|windows|macos)-latest\b') {
                Add-Failure "$relative line $($index + 1) must use a versioned runner label instead of '*-latest'."
            }
            if ($line -match '^\s*uses:\s*[''"]?(?<uses>[^''"\s#]+)') {
                $uses = $Matches.uses
                if ($uses -like "./*" -or $uses -like "../*") {
                    continue
                }
                if ($uses -like "docker://*") {
                    if ($uses -notmatch '@sha256:[a-fA-F0-9]{64}$') {
                        Add-Failure "$relative line $($index + 1) docker action reference must include a sha256 digest."
                    }
                    continue
                }
                if ($uses -notmatch '@[a-fA-F0-9]{40}$') {
                    Add-Failure "$relative line $($index + 1) action reference must be pinned to a full commit SHA."
                }
            }
        }
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    exit 1
}

Write-Host "Dependency pinning contract passed."
