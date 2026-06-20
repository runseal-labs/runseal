$IncludeGit = $args -contains "-IncludeGit"
$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$bin = Join-Path $repoRoot "target\debug\runseal.exe"

function Invoke-RunSeal {
    param(
        [string[]]$RunArgs,
        [int]$TimeoutSeconds = 30,
        [switch]$AllowFailure
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $bin
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($arg in $RunArgs) {
        [void]$startInfo.ArgumentList.Add($arg)
    }
    $startInfo.Environment["RUNSEAL_WINDOWS_SANDBOX_SETUP_TIMEOUT_SECONDS"] = "20"

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $process.Kill($true)
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult().Trim()
        $stderr = $stderrTask.GetAwaiter().GetResult().Trim()
        throw "runseal timed out after ${TimeoutSeconds}s: $($RunArgs -join ' ')`nstdout:`n$stdout`nstderr:`n$stderr"
    }

    $stdoutText = $stdoutTask.GetAwaiter().GetResult().Trim()
    $stderrText = $stderrTask.GetAwaiter().GetResult().Trim()
    $exitCode = $process.ExitCode
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "runseal failed ($exitCode): $($RunArgs -join ' ')`nstdout:`n$stdoutText`nstderr:`n$stderrText"
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Stdout = $stdoutText
        Stderr = $stderrText
    }
}

function Convert-RunSealJson {
    param(
        [pscustomobject]$Result
    )

    $payload = $Result.Stdout
    if (-not $payload) {
        $payload = $Result.Stderr
    }
    if (-not $payload) {
        throw "runseal produced no JSON payload"
    }
    return $payload | ConvertFrom-Json
}

function Invoke-RunSealJson {
    param(
        [string[]]$RunArgs,
        [int]$TimeoutSeconds = 30
    )

    return Convert-RunSealJson (Invoke-RunSeal -RunArgs $RunArgs -TimeoutSeconds $TimeoutSeconds)
}

Push-Location $repoRoot
try {
    & (Join-Path $PSScriptRoot "build-windows.ps1")

    $capabilities = Invoke-RunSealJson -RunArgs @("capabilities") -TimeoutSeconds 10
    foreach ($feature in @("filesystem_policy", "runtime_roots", "runtime_environment", "process_isolation", "process_cleanup", "direct_network_deny", "network_disabled", "network_proxy", "managed_proxy")) {
        if (-not $capabilities.features.$feature) {
            throw "missing Windows feature: $feature"
        }
    }

    $workspace = $repoRoot.Path
    $setup = Invoke-RunSealJson -RunArgs @("setup", "windows-sandbox", "--status", "--json", "--cwd", $workspace) -TimeoutSeconds 10
    if ($setup.requires_setup) {
        Write-Host "Windows smoke skipped: setup is not ready for smoke workspace: $($setup | ConvertTo-Json -Compress)"
        exit 0
    }

    $identity = Invoke-RunSealJson -RunArgs @(
        "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "5000", "--",
        "whoami.exe"
    ) -TimeoutSeconds 15
    if ($identity.exit_code -ne 0 -or $identity.stdout -notmatch "runsealsandbox") {
        throw "sandbox identity smoke failed: $($identity.stderr)"
    }

    $timeoutResult = Invoke-RunSeal -RunArgs @(
        "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "100", "--",
        "cmd", "/C", "ping 127.0.0.1 -n 6"
    ) -TimeoutSeconds 15 -AllowFailure
    if ($timeoutResult.ExitCode -eq 0) {
        throw "timeout smoke unexpectedly succeeded"
    }
    $timeout = Convert-RunSealJson $timeoutResult
    if ($timeout.error.data.code -ne "EXECUTION_TIMEOUT") {
        throw "timeout smoke returned wrong error: $($timeoutResult.Stdout)$($timeoutResult.Stderr)"
    }

    if ($IncludeGit -and (Get-Command git -ErrorAction SilentlyContinue)) {
        $git = Invoke-RunSealJson -RunArgs @(
            "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "5000", "--",
            "git", "--version"
        ) -TimeoutSeconds 15
        if ($git.exit_code -ne 0 -or $git.stdout -notmatch "git version") {
            throw "git smoke failed: $($git.stderr)"
        }
    }

    Write-Host "Windows smoke ok"
} finally {
    Pop-Location
}
