$IncludeGit = $args -contains "-IncludeGit"
$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$bin = Join-Path $repoRoot "target\debug\runseal.exe"

function Invoke-RunSealJson {
    param(
        [string[]]$RunArgs
    )

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        & $bin @RunArgs > $stdoutFile 2> $stderrFile
        $exitCode = $LASTEXITCODE
        $stdout = Get-Content -LiteralPath $stdoutFile -Raw
        $stderr = Get-Content -LiteralPath $stderrFile -Raw

        if ($exitCode -ne 0) {
            throw @"
runseal failed ($exitCode): $($RunArgs -join ' ')
stdout:
$stdout
stderr:
$stderr
"@
        }

        try {
            return $stdout | ConvertFrom-Json
        } catch {
            throw @"
runseal stdout was not JSON: $($RunArgs -join ' ')
stdout:
$stdout
stderr:
$stderr
"@
        }
    } finally {
        Remove-Item -LiteralPath $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

Push-Location $repoRoot
try {
    & (Join-Path $PSScriptRoot "build-windows.ps1")

    $workspace = $repoRoot

    $setup = Invoke-RunSealJson -RunArgs @("setup", "windows-sandbox", "--json", "--cwd", $workspace)
    if ($setup.status -ne "ok" -or $setup.setup_status.requires_setup) {
        throw "windows setup is not ready"
    }

    $capabilities = Invoke-RunSealJson -RunArgs @("capabilities")
    foreach ($feature in @("filesystem_policy", "runtime_roots", "runtime_environment", "process_isolation", "process_cleanup", "direct_network_deny", "network_disabled", "network_proxy", "managed_proxy")) {
        if (-not $capabilities.features.$feature) {
            throw "missing Windows feature: $feature"
        }
    }

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

    Write-Host "Windows smoke ok"
} finally {
    Pop-Location
}
