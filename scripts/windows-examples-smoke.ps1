$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$runseal = Resolve-Path (Join-Path $repoRoot "target\debug\runseal.exe")
$python = (Get-Command python -ErrorAction Stop).Source
$node = (Get-Command node -ErrorAction Stop).Source
$workspace = Join-Path $env:RUNNER_TEMP "runseal-third-party-examples-$([guid]::NewGuid().ToString('N'))"

if (-not (Test-Path -LiteralPath $env:RUNNER_TEMP -PathType Container)) {
    throw "RUNNER_TEMP is unavailable"
}

New-Item -ItemType Directory -Path $workspace -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $workspace "python-json-rpc") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $workspace "node-stdio") -Force | Out-Null
$env:RUNSEAL_PYTHON = $python

Push-Location $repoRoot
try {
    Write-Host "Running Python stdio JSON-RPC example with prepared workspace-write/disabled policy"
    & $python "examples\stdio-json-rpc\runseal_stdio_example.py" `
        --runseal $runseal.Path `
        --cwd (Join-Path $workspace "python-json-rpc") `
        --policy workspace-write `
        --network disabled
    if ($LASTEXITCODE -ne 0) {
        throw "Python stdio JSON-RPC example failed with exit code $LASTEXITCODE"
    }

    Write-Host "Running Node stdio, PTY, control, and cancellation example with prepared workspace-write/disabled policy"
    & $node "examples\stdio-json-rpc\runseal_stdio_example.mjs" `
        --runseal $runseal.Path `
        --cwd (Join-Path $workspace "node-stdio") `
        --policy workspace-write `
        --network disabled
    if ($LASTEXITCODE -ne 0) {
        throw "Node stdio integration example failed with exit code $LASTEXITCODE"
    }

    Write-Host "Running Python CLI control-channel example with prepared workspace-write policy"
    & $python "examples\stdio-json-rpc\runseal_control_cli_example.py" `
        --runseal $runseal.Path `
        --policy workspace-write
    if ($LASTEXITCODE -ne 0) {
        throw "Python CLI control example failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
    Remove-Item Env:RUNSEAL_PYTHON -ErrorAction SilentlyContinue
}
