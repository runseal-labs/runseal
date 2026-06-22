# RunSeal

[简体中文](README.zh-CN.md)

RunSeal is an OS-native sandbox layer for AI agents.

It exposes a stable execution protocol for running local commands inside policy-governed filesystem, process, resource, and network boundaries. Enterprise network access is expected to go through a controlled proxy that can enforce routes, inject authentication at the boundary, redact sensitive data, and emit structured audit events.

RunSeal is **not** a cloud VM sandbox, a Docker Desktop replacement, or a microVM platform. It is a local-first execution boundary for agent frameworks.

## Status

`0.1.2` is the current technical-preview release for third-party integration. The repository contains a buildable CLI/RPC shell, standard policy profile normalization, canonical policy hashes, backend capability reporting, a Windows reference backend, `PlatformSandboxPlan` summaries, JSONL audit output, and black-box conformance tests.

Current execution support is intentionally narrow: explicit `danger-full-access` runs as local, non-sandboxed execution. On Windows, sandboxed policies such as `read-only`, `workspace-contained`, and `workspace-write` execute through the reference backend. On macOS and Linux, `read-only` and `workspace-write` with `network.disabled` are experimental. Other portable sandboxed policies still fail closed until a backend can enforce them.

On Windows, sandbox requests include a `PlatformSandboxPlan` for runtime root, synthetic home, profile root, temp root, setup requirements, protected filesystem categories, process boundary state, network guard state, and policy path planning. Runtime root creation/cleanup, runtime environment redirects, process cleanup, filesystem enforcement, process isolation, and direct network deny/proxy guard enforcement are covered by the Windows reference path.

The Windows enforcement baseline lives behind a dedicated Windows sandbox implementation. RunSeal-specific code should stay at the adapter layer: policy normalization, `PlatformSandboxPlan` mapping, audit events, capability reporting, and conformance gates. Low-level OS boundary, setup-helper, and command-runner code should not be reimplemented in the RunSeal adapter.

On macOS and Linux, RunSeal reports experimental `read-only` and `workspace-write` paths while leaving other sandbox levels unsupported. These portable paths enforce write and network boundaries, not workspace containment: host files may remain readable unless `workspace-contained` is implemented and reported separately. Portable process cleanup is experimental and should not be treated as Windows reference cleanup equivalent.

Capability clients should prefer `sandbox_levels`, `network_modes`, and `feature_statuses` for status decisions. The legacy `features` booleans are coarse presence flags; portable capability probes are diagnostic only and do not promote unsupported capabilities.

| Capability | Windows | macOS | Linux |
| --- | --- | --- | --- |
| `danger-full-access` | supported | supported | supported |
| `read-only` | supported | experimental with `network.disabled` | experimental with `network.disabled` |
| `workspace-write` | supported | experimental with `network.disabled` | experimental with `network.disabled` |
| `workspace-contained` | supported | unsupported | unsupported |
| `network.disabled` | supported | experimental | experimental |
| `network.proxy` | supported | unsupported | unsupported |

The protocol and policy version strings are `runseal.protocol/v1` and
`runseal.policy/v1`. The Rust package version remains pre-`1.0`; breaking
changes to provisional CLI flags, JSON fields, and audit shapes can still land
when the RFCs change.

The design lives in the RFC repository:

- https://github.com/runseal-labs/rfcs
- Protocol draft: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0006-stable-execution-protocol.md
- Escape model: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0015-escape-definition-and-adversarial-conformance.md
- Adversarial conformance: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0016-adversarial-conformance-harness-and-case-format.md

## Quickstart

Download the Windows release archive and place the three executables in the
same directory:

- `runseal.exe`
- `runseal-windows-sandbox-setup.exe`
- `runseal-command-runner.exe`

Install or repair the Windows sandbox from an elevated PowerShell session:

```powershell
.\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace
```

Check host capabilities:

```powershell
.\runseal.exe capabilities
```

Run a sandboxed command:

```powershell
.\runseal.exe exec --json --policy workspace-write --network disabled --cwd C:\path\to\workspace -- whoami.exe
```

## Development principle

Tests first.

The initial test suite is intentionally black-box and protocol-oriented. Runtime implementation should make these tests pass without changing their behavioral assertions unless the RFC changes first.

## Intended CLI

```bash
runseal exec --policy workspace-write --network proxy -- python skill.py
runseal explain-policy --policy workspace-write --network proxy
runseal capabilities
```

For explicit unsandboxed local execution:

```bash
runseal exec --policy danger-full-access -- python skill.py
```

When `runseal exec --json` fails, stdout contains a structured `error` object
and the process exits non-zero.
When `runseal exec --events` fails before an event stream can be completed,
stdout contains one structured `error` object line and the process exits non-zero.

## Windows sandbox setup

Build all Windows binaries, including the setup helper and command runner:

```powershell
.\scripts\build-windows.ps1
```

For release artifacts:

```powershell
.\scripts\build-windows.ps1 -Release
```

The script places `runseal.exe`, `runseal-windows-sandbox-setup.exe`, and
`runseal-command-runner.exe` in the selected `target\debug` or
`target\release` directory.

Pushing a `v*` tag runs `.github/workflows/release.yml`, builds native release
archives, and publishes them with SHA-256 checksum files. To rerun packaging
for an existing release, dispatch the workflow manually with the tag input.

Run the first sandbox bootstrap explicitly from an elevated PowerShell session:

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace
```

After the scheduled setup broker exists, the same command can repair workspace
setup state without opening UAC again.

Use `--json` when an agent needs structured setup failure details.
Successful setup also includes `setup_status` so automation can verify readiness
from the same command.

Check setup readiness without changing setup state:

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --status
```

The status payload reports coarse setup readiness only: `broker`, `elevated`,
`can_repair`, `can_run_setup_now`, `requires_setup`, and `next_action`. On
Windows, the same `setup_status` object is included in sandboxed execution
`BACKEND_UNAVAILABLE` errors when setup is missing or stale, in the matching
`execution.failed` audit event, in `runseal capabilities`, and in
`runseal explain-policy` for the requested workspace.
`requires_setup` stays true until setup marker and sandbox user artifacts are
complete; `broker` only reports whether repairs can run without opening an
elevated shell.
`can_repair` is true when the current process is elevated or when the scheduled
setup broker is already available.

Sandboxed `runseal exec` does not invoke UAC directly. It uses the installed
scheduled setup broker; if the broker is missing or stale, execution fails
closed with `windows sandbox setup unavailable` until the setup command above is
run again.

## Intended protocol

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "execute",
  "params": {
    "command": ["python", "skill.py"],
    "cwd": "/workspace",
    "policy": "workspace-write",
    "network": {"mode": "proxy"}
  }
}
```

## Third-party integration

Integrators should start with one of these surfaces:

- CLI: call `runseal exec --json` or `runseal exec --events` and handle structured errors.
- JSON-RPC stdio: launch `runseal rpc --stdio`, call `getVersion`, then `getCapabilities`, then `execute`.
- Service stdio: launch `runseal service --stdio` when one local process should own completed execution state across JSON-RPC requests.
- Conformance: set `RUNSEAL_BIN=/path/to/runseal` and run the black-box tests in `tests/`.

Clients should gate sandboxed execution on `getCapabilities` and fail closed
when a requested feature is unsupported or setup is unavailable. `getSetupStatus`
reports setup readiness without changing setup state. `getServiceStatus` reports
whether the current stdio control plane is direct or stateful service mode. The
stdio service records completed executions for `getExecution`, event replay,
summary listing through `listExecutions`, session disposal, and stable
not-cancellable responses for already-finished executions.

## Running tests

The conformance tests are Rust integration tests. `cargo test` builds and runs the local `runseal` binary.

```bash
cargo fmt --check
cargo clippy --tests -- -D warnings
cargo test
```

On Windows, run the local dogfood smoke after rebuilding helper binaries:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-smoke.ps1
```

On Linux or macOS, run the portable probe smoke after building `runseal`:

```bash
python3 scripts/portable-probe-smoke.py
```

The portable smoke checks diagnostic capability probes, experimental portable
enforcement where available, and structured fail-closed behavior for unsupported
sandboxed policies. It does not promote portable capabilities to supported.

Windows reference-backend readiness requires the smoke check plus the Rust
checks above to pass on a Windows host.

For the managed proxy path specifically:

```powershell
cargo test --test filesystem_conformance network_proxy_allows_http_through_managed_proxy_when_supported_or_fails_closed
```

Add `-IncludeGit` to the Windows smoke command when validating a local Git for
Windows installation inside the sandbox.

To run the same tests against another candidate implementation:

```bash
RUNSEAL_BIN=target/debug/runseal cargo test
```

## Non-goals

- No Docker daemon dependency.
- No unmanaged direct network access as an enterprise default.
- No direct secret injection into sandboxed processes.
- No cloud multi-tenant sandbox control plane in the core runtime.
- No claim that OS-native sandboxing prevents every kernel-level escape.
