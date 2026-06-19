$IncludeGit = $args -contains "-IncludeGit"
$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$bin = Join-Path $repoRoot "target\debug\runseal.exe"

function Invoke-RunSealJson {
    param(
        [string[]]$RunArgs
    )

    $out = & $bin @RunArgs
    if ($LASTEXITCODE -ne 0) {
        throw "runseal failed ($LASTEXITCODE): $($RunArgs -join ' ')"
    }
    return $out | ConvertFrom-Json
}

Push-Location $repoRoot
try {
    & (Join-Path $PSScriptRoot "build-windows.ps1")

    $setup = Invoke-RunSealJson -RunArgs @("setup", "windows-sandbox", "--json")
    if ($setup.status -ne "ok" -or $setup.setup_status.requires_setup) {
        throw "windows setup is not ready"
    }

    $capabilities = Invoke-RunSealJson -RunArgs @("capabilities")
    foreach ($feature in @("filesystem_policy", "runtime_roots", "runtime_environment", "process_isolation", "process_cleanup", "direct_network_deny", "network_disabled", "network_proxy", "managed_proxy")) {
        if (-not $capabilities.features.$feature) {
            throw "missing Windows feature: $feature"
        }
    }

    $workspace = Join-Path ([System.IO.Path]::GetTempPath()) ("runseal-smoke-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $workspace | Out-Null
    try {
        $identity = Invoke-RunSealJson -RunArgs @(
            "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "5000", "--",
            "whoami.exe"
        )
        if ($identity.exit_code -ne 0 -or $identity.stdout -notmatch "runsealsandbox") {
            throw "sandbox identity smoke failed: $($identity.stderr)"
        }

        $timeoutOut = & $bin @(
            "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "100", "--",
            "cmd", "/C", "ping 127.0.0.1 -n 6 >NUL"
        )
        if ($LASTEXITCODE -eq 0) {
            throw "timeout smoke unexpectedly succeeded"
        }
        $timeout = $timeoutOut | ConvertFrom-Json
        if ($timeout.error.data.code -ne "EXECUTION_TIMEOUT") {
            throw "timeout smoke returned wrong error: $($timeoutOut -join '')"
        }

        if ($IncludeGit -and (Get-Command git -ErrorAction SilentlyContinue)) {
            $git = Invoke-RunSealJson -RunArgs @(
                "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "5000", "--",
                "git", "--version"
            )
            if ($git.exit_code -ne 0 -or $git.stdout -notmatch "git version") {
                throw "git smoke failed: $($git.stderr)"
            }
        }
    } finally {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "Windows smoke ok"
} finally {
    Pop-Location
}
