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

function Assert-BuiltWindowsBinaries {
    $targetDir = Split-Path -Parent $bin
    foreach ($name in @("runseal.exe", "runseal-windows-sandbox-setup.exe", "runseal-command-runner.exe")) {
        $path = Join-Path $targetDir $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "missing Windows helper binary: $path"
        }
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

function Assert-ExecRepairedSetup {
    param(
        [object]$Run,
        [string]$GateStateBefore = "unknown"
    )

    if ($Run.ExitCode -ne 0) {
        $setupStatus = $null
        try {
            $setupStatus = (Invoke-RunSealJson -RunArgs @(
                "setup", "windows-sandbox", "--status", "--json", "--cwd", $workspace
            )).Json
        } catch {
            # Keep the execution failure primary; report status as unavailable below.
        }
        $lastResult = Get-ScheduledSetupBrokerLastResult
        $errorCode = $Run.Json.error.data.code
        $errorReason = $Run.Json.error.data.error.reason
        $cleanupComplete = $Run.Json.error.data.cleanup_complete
        $gateStateAfter = Get-ExecutionGateSummary
        if ($null -eq $setupStatus) {
            throw "sandboxed exec could not repair setup through the broker (code=$errorCode, reason=$errorReason, cleanup_complete=$cleanupComplete, gate_before=$GateStateBefore, gate_after=$gateStateAfter, setup_status=unavailable, broker_last_result=$lastResult)"
        }
        throw "sandboxed exec could not repair setup through the broker (code=$errorCode, reason=$errorReason, cleanup_complete=$cleanupComplete, gate_before=$GateStateBefore, gate_after=$gateStateAfter, setup_requires_setup=$($setupStatus.requires_setup), broker=$($setupStatus.broker), next_action=$($setupStatus.next_action), broker_last_result=$lastResult)"
    }
    if ($Run.Json.exit_code -ne 0 -or $Run.Json.stdout -notmatch "runsealsandbox") {
        throw "sandboxed exec did not run as the sandbox identity after repair: $($Run.Stdout)"
    }
}

function Assert-ExecFailsClosedWithoutSetupBroker {
    param([object]$Run)

    if ($Run.ExitCode -eq 0) {
        throw "sandboxed exec unexpectedly succeeded without setup or a broker"
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

function Get-ExecutionGateSummary {
    $gateDirectory = Join-Path ([Environment]::GetFolderPath("CommonApplicationData")) "RunSeal\execution-gates"
    if (-not (Test-Path -LiteralPath $gateDirectory -PathType Container)) {
        return "state_dir=missing"
    }

    try {
        $files = @(Get-ChildItem -LiteralPath $gateDirectory -File -Force -ErrorAction Stop)
        $stateFiles = @($files | Where-Object { $_.Name -match '^[0-9a-f]{64}\.json$' })
        $cleanupMarkers = @($files | Where-Object { $_.Name -like "*.cleanup-failed" })
        $activeReservations = 0
        $unreadableStateFiles = 0
        foreach ($file in $stateFiles) {
            try {
                $state = [System.IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json
                $activeReservations += @($state.active).Count
            } catch {
                $unreadableStateFiles += 1
            }
        }
        return "state_files=$($stateFiles.Count), active_reservations=$activeReservations, cleanup_markers=$($cleanupMarkers.Count), unreadable_state_files=$unreadableStateFiles"
    } catch {
        return "state=unavailable"
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
    Assert-BuiltWindowsBinaries
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
    Assert-ExecFailsClosedWithoutSetupBroker $missingExec

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

    Write-Host "Checking sandboxed exec after explicit setup"
    $gateBeforeReadyExec = Get-ExecutionGateSummary
    $readyExec = Invoke-RunSealJson -AllowFailure -RunArgs @(
        "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "60000", "--",
        "whoami.exe"
    ) -TimeoutSeconds 120
    if ($readyExec.ExitCode -ne 0) {
        $errorCode = $readyExec.Json.error.data.code
        $errorReason = $readyExec.Json.error.data.error.reason
        $cleanupComplete = $readyExec.Json.error.data.cleanup_complete
        $gateAfterReadyExec = Get-ExecutionGateSummary
        throw "sandboxed exec failed after explicit setup (code=$errorCode, reason=$errorReason, cleanup_complete=$cleanupComplete, gate_before=$gateBeforeReadyExec, gate_after=$gateAfterReadyExec)"
    }
    if ($readyExec.Json.exit_code -ne 0 -or $readyExec.Json.stdout -notmatch "runsealsandbox") {
        throw "sandboxed exec after explicit setup did not run as the sandbox identity: $($readyExec.Stdout)"
    }

    Write-Host "Checking setup status stays read-only when setup is stale"
    $gateBeforeStaleExec = Get-ExecutionGateSummary
    $sandboxHomeOverride = [Environment]::GetEnvironmentVariable("RUNSEAL_WINDOWS_SANDBOX_HOME")
    if ([string]::IsNullOrWhiteSpace($sandboxHomeOverride)) {
        $localAppData = [Environment]::GetEnvironmentVariable("LOCALAPPDATA")
        if ([string]::IsNullOrWhiteSpace($localAppData)) {
            $sandboxHome = Join-Path $workspace ".runseal\sandbox"
        } else {
            $sandboxHome = Join-Path $localAppData "RunSeal\windows-sandbox"
        }
    } else {
        $sandboxHome = [System.IO.Path]::GetFullPath($sandboxHomeOverride)
    }
    $marker = Join-Path $sandboxHome ".sandbox\setup_marker.json"
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw "sandbox setup marker missing after successful setup"
    }
    Remove-Item -LiteralPath $marker -Force
    $staleStatus = (Invoke-RunSealJson -RunArgs @("setup", "windows-sandbox", "--status", "--json", "--cwd", $workspace)).Json
    Assert-SetupRequiredStatus $staleStatus

    $staleExec = Invoke-RunSealJson -AllowFailure -RunArgs @(
        "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "60000", "--",
        "whoami.exe"
    ) -TimeoutSeconds 240
    Assert-ExecRepairedSetup $staleExec $gateBeforeStaleExec
    $repairedStatus = (Invoke-RunSealJson -RunArgs @("setup", "windows-sandbox", "--status", "--json", "--cwd", $workspace)).Json
    if ($repairedStatus.requires_setup) {
        throw "sandboxed exec returned without repairing stale setup"
    }

    Write-Host "Checking setup action after automatic repair"
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

    Write-Host "Checking sandbox runner can write allowed workspace root"
    $writeProbePath = Join-Path $workspace "runner-token-write.txt"
    Remove-Item -LiteralPath $writeProbePath -Force -ErrorAction SilentlyContinue
    $writeProbe = (Invoke-RunSealJson -RunArgs @(
        "exec", "--json", "--policy", "workspace-write", "--network", "disabled", "--cwd", $workspace, "--timeout-ms", "5000", "--",
        "cmd", "/C", "echo runseal-write-ok>runner-token-write.txt"
    ) -TimeoutSeconds 10).Json
    if ($writeProbe.exit_code -ne 0) {
        throw "sandbox write probe failed: $($writeProbe.stderr)"
    }
    if (-not (Test-Path -LiteralPath $writeProbePath -PathType Leaf)) {
        throw "sandbox write probe did not create file in workspace"
    }
    if (((Get-Content -LiteralPath $writeProbePath -Raw).Trim()) -ne "runseal-write-ok") {
        throw "sandbox write probe wrote unexpected file content"
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
