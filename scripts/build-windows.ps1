param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$profileArgs = @()
$profileName = "debug"
if ($Release) {
    $profileArgs += "--release"
    $profileName = "release"
}

function Copy-BuiltBinary {
    param(
        [string]$Name,
        [string]$RootTarget,
        [string]$VendorTarget
    )

    $destination = Join-Path $RootTarget $Name
    $candidates = @(
        (Join-Path $RootTarget $Name),
        (Join-Path $VendorTarget $Name)
    )
    $source = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $source) {
        throw "built binary not found: $Name"
    }

    $sourcePath = (Resolve-Path $source).Path
    $destinationPath = ""
    if (Test-Path $destination) {
        $destinationPath = (Resolve-Path $destination).Path
    }
    if ($sourcePath -ne $destinationPath) {
        Copy-Item -Force $source $destination
    }
}

Push-Location $repoRoot
try {
    cargo build @profileArgs --bin runseal
    cargo build @profileArgs --manifest-path vendor\codex-windows-sandbox\upstream\Cargo.toml --bin runseal-windows-sandbox-setup
    cargo build @profileArgs --manifest-path vendor\codex-windows-sandbox\upstream\Cargo.toml --bin runseal-command-runner

    $rootTarget = Join-Path $repoRoot "target\$profileName"
    $vendorTarget = Join-Path $repoRoot "vendor\codex-windows-sandbox\upstream\target\$profileName"
    Copy-BuiltBinary "runseal-windows-sandbox-setup.exe" $rootTarget $vendorTarget
    Copy-BuiltBinary "runseal-command-runner.exe" $rootTarget $vendorTarget

    Write-Host "Built runseal.exe, runseal-windows-sandbox-setup.exe, and runseal-command-runner.exe in $rootTarget"
} finally {
    Pop-Location
}
