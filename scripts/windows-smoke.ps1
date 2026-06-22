param(
    [switch]$AllowElevation,
    [switch]$IncludeGit,
    [switch]$KeepWorkspace
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$bin = Join-Path $repoRoot "target\debug\runseal.exe"
$workspace = Join-Path ([System.IO.Path]::GetTempPath()) "runseal-windows-smoke-$([guid]::NewGuid().ToString('N'))"

function Quote-ProcessArgument {
    param([string]$Value)

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-RunSealJson {
    param(
        [string[]]$RunArgs,
        [switch]$AllowFailure,
        [int]$TimeoutSeconds = 30
    )

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $processInfo.FileName = $bin
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.Arguments = ($RunArgs | ForEach-Object { Quote-ProcessArgument $_ }) -join " "

        $process = [System.Diagnostics.Process]::Start($processInfo)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            throw "runseal timed out after ${TimeoutSeconds}s: $($RunArgs -join ' ')"
        }
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result

        if ($exitCode -ne 0 -and -not $AllowFailure) {
            throw @"
runseal failed ($exitCode): $($RunArgs -join ' ')
stdout:
$stdout
stderr:
$stderr
"@
        }

        try {
            $json = $stdout | ConvertFrom-Json
        } catch {
            throw @"
runseal stdout was not JSON: $($RunArgs -join ' ')
stdout:
$stdout
stderr:
$stderr
"@
        }

        [pscustomobject]@{
            ExitCode = $exitCode
            Json = $json
            Stdout = $stdout
            Stderr = $stderr
        }
    } finally {
        Remove-Item -LiteralPath $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

function Assert-SetupReady {
    param([object]$Payload)

    if ($Payload.status -ne "ok" -or $Payload.setup_status.requires_setup) {
        throw "windows setup is not ready"
    }
    if ($Payload.setup_status.broker -ne "available") {
        throw "windows setup broker is not available after setup"
    }
}

function Assert-SetupRequiredStatus {
    param([object]$SetupStatus)

    if (-not $SetupStatus.requires_setup) {
        throw "fresh Windows setup status did not require setup"
    }
    if ($SetupStatus.can_run_setup_now) {
        if ($SetupStatus.next_action -ne "run_setup") {
            throw "repairable setup status returned wrong next action: $($SetupStatus.next_action)"
        }
        return
    }
    if ($SetupStatus.next_action -ne "open_elevated_shell") {
        throw "non-repairable setup status returned wrong next action: $($SetupStatus.next_action)"
    }
    if ($SetupStatus.next_command -notmatch "--elevate") {
        throw "non-repairable setup status did not document --elevate"
    }
}

function Assert-ExecFailsClosedForSetup {
    param([object]$Run)

    if ($Run.ExitCode -eq 0) {
        throw "sandboxed exec unexpectedly succeeded before setup"
    }
    if ($Run.Json.error.data.code -ne "BACKEND_UNAVAILABLE") {
        throw "sandboxed exec returned wrong setup-missing error: $($Run.Stdout)"
    }
    if (-not $Run.Json.error.data.setup_status.requires_setup) {
        throw "sandboxed exec error did not include setup_status.requires_setup"
    }
}

function Get-ScheduledSetupBrokerLastResult {
    try {
        $info = Get-ScheduledTaskInfo -TaskPath "\RunSeal\" -TaskName "WindowsSandboxSetup" -ErrorAction Stop
        return $info.LastTaskResult
    } catch {
        return $null
    }
}

function Invoke-Setup {
    param([switch]$Elevate)

    $setupArgs = @("setup", "windows-sandbox", "--json", "--cwd", $workspace)
    if ($Elevate) {
        $setupArgs += "--elevate"
    }
    Invoke-RunSealJson -RunArgs $setupArgs -TimeoutSeconds 240
}

function Wait-SetupReady {
    $deadline = (Get-Date).AddMinutes(2)
    do {
        Start-Sleep -Seconds 2
        $status = (Invoke-RunSealJson -RunArgs @("setup", "windows-sandbox", "--status", "--json", "--cwd", $workspace)).Json
        if (-not $status.requires_setup) {
            return
        }
    } while ((Get-Date) -lt $deadline)

    throw "elevated setup did not complete within 2 minutes"
}

Push-Location $repoRoot
try {
    Write-Host "Building Windows binaries"
    & (Join-Path $PSScriptRoot "build-windows.ps1")
    Write-Host "Using runseal binary: $bin"
    New-Item -ItemType Directory -Path $workspace -Force | Out-Null

    Write-Host "Checking setup status before setup"
    $statusBefore = (Invoke-RunSealJson -RunArgs @("setup", "windows-sandbox", "--status", "--json", "--cwd", $workspace)).Json
    Assert-SetupRequiredStatus $statusBefore

    Write-Host "Checking sandboxed exec fails closed before setup"
    $missingExec = Invoke-RunSealJson -AllowFailure -RunArgs @(
        "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "5000", "--",
        "whoami.exe"
    ) -TimeoutSeconds 10
    Assert-ExecFailsClosedForSetup $missingExec

    if (-not $statusBefore.can_run_setup_now) {
        if (-not $AllowElevation) {
            throw "windows setup requires elevation; rerun this smoke from an elevated shell or pass -AllowElevation to request UAC"
        }
        Write-Host "Requesting elevated setup"
        $elevated = Invoke-Setup -Elevate
        if ($elevated.Json.status -ne "elevation_requested") {
            Assert-SetupReady $elevated.Json
        } else {
            Wait-SetupReady
        }
    } else {
        if ($AllowElevation -and $statusBefore.elevated -eq $false) {
            Write-Host "Requesting elevated setup"
            $elevated = Invoke-Setup -Elevate
            if ($elevated.Json.status -eq "elevation_requested") {
                Wait-SetupReady
            } else {
                Assert-SetupReady $elevated.Json
            }
        } else {
            $lastResult = Get-ScheduledSetupBrokerLastResult
            if ($statusBefore.elevated -eq $false -and $statusBefore.broker -eq "available" -and $null -ne $lastResult -and $lastResult -ne 0) {
                $hexResult = "0x{0:X8}" -f ([uint32]$lastResult)
                throw "windows setup broker last result is $lastResult ($hexResult); rerun from an elevated shell or pass -AllowElevation to request UAC"
            }
            Write-Host "Running setup"
            Assert-SetupReady (Invoke-Setup).Json
        }
    }

    Write-Host "Checking setup repair path"
    Assert-SetupReady (Invoke-Setup).Json

    Write-Host "Checking stale setup fails closed"
    $marker = Join-Path $workspace ".runseal\sandbox\.sandbox\setup_marker.json"
    Remove-Item -LiteralPath $marker -Force
    $staleStatus = (Invoke-RunSealJson -RunArgs @("setup", "windows-sandbox", "--status", "--json", "--cwd", $workspace)).Json
    Assert-SetupRequiredStatus $staleStatus

    $staleExec = Invoke-RunSealJson -AllowFailure -RunArgs @(
        "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "5000", "--",
        "whoami.exe"
    ) -TimeoutSeconds 10
    Assert-ExecFailsClosedForSetup $staleExec

    Write-Host "Repairing stale setup"
    if ($AllowElevation -and $staleStatus.elevated -eq $false) {
        $elevated = Invoke-Setup -Elevate
        if ($elevated.Json.status -eq "elevation_requested") {
            Wait-SetupReady
        } else {
            Assert-SetupReady $elevated.Json
        }
    } else {
        Assert-SetupReady (Invoke-Setup).Json
    }

    Write-Host "Checking capabilities"
    $capabilities = (Invoke-RunSealJson -RunArgs @("capabilities")).Json
    foreach ($feature in @("filesystem_policy", "runtime_roots", "runtime_environment", "process_isolation", "process_cleanup", "direct_network_deny", "network_disabled", "network_proxy", "managed_proxy")) {
        if (-not $capabilities.features.$feature) {
            throw "missing Windows feature: $feature"
        }
    }

    Write-Host "Checking sandbox identity"
    $identity = (Invoke-RunSealJson -RunArgs @(
        "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "5000", "--",
        "whoami.exe"
    ) -TimeoutSeconds 10).Json
    if ($identity.exit_code -ne 0 -or $identity.stdout -notmatch "runsealsandbox") {
        throw "sandbox identity smoke failed: $($identity.stderr)"
    }

    Write-Host "Checking execution timeout"
    $timeout = Invoke-RunSealJson -AllowFailure -RunArgs @(
        "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "100", "--",
        "cmd", "/C", "ping 127.0.0.1 -n 6 >NUL"
    ) -TimeoutSeconds 10
    if ($timeout.ExitCode -eq 0) {
        throw "timeout smoke unexpectedly succeeded"
    }
    if ($timeout.Json.error.data.code -ne "EXECUTION_TIMEOUT") {
        throw "timeout smoke returned wrong error: $($timeout.Stdout)"
    }

    if ($IncludeGit -and (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "Checking Git inside sandbox"
        $git = (Invoke-RunSealJson -RunArgs @(
            "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "5000", "--",
            "git", "--version"
        ) -TimeoutSeconds 10).Json
        if ($git.exit_code -ne 0 -or $git.stdout -notmatch "git version") {
            throw "git smoke failed: $($git.stderr)"
        }
    }

    Write-Host "Windows smoke ok"
} finally {
    Pop-Location
    if (-not $KeepWorkspace -and (Test-Path $workspace)) {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
