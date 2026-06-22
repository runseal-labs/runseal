# RunSeal

[简体中文](README.zh-CN.md)

RunSeal is an OS-native sandbox layer for AI agents.

It exposes a stable execution protocol that runs local commands inside policy-governed filesystem, process, resource, and network boundaries. Enterprise network access routes through a controlled proxy that enforces routes, injects authentication at the boundary, redacts sensitive data, and emits structured audit events.

RunSeal is **not** a cloud VM sandbox, a Docker Desktop replacement, or a microVM platform. It is a local-first execution boundary purpose-built for agent frameworks.

## Status

`0.1.3` is the current technical-preview release for third-party integration. The repository includes a buildable CLI/RPC shell, standard policy profile normalization, canonical policy hashes, backend capability reporting, a first-class Windows reference backend, `PlatformSandboxPlan` summaries, JSONL audit output, and black-box conformance tests.

Execution support is intentionally narrow today: `danger-full-access` runs as local, non-sandboxed execution. Windows is the most complete supported platform: sandboxed policies (`read-only`, `workspace-contained`, `workspace-write`) execute through the reference backend. macOS and Linux already have partial experimental enforcement for `read-only` and `workspace-write` with `network.disabled`, but they are not aligned with the Windows backend yet; remaining parity work is expected to come through community contributions.

On Windows, a sandbox request produces a `PlatformSandboxPlan` covering runtime root, synthetic home, profile root, temp root, setup requirements, protected filesystem categories, process boundary state, network guard state, and policy path planning. The reference backend handles root creation and cleanup, environment redirects, process cleanup, filesystem enforcement, process isolation, and direct network deny-or-proxy guard enforcement.

Low-level OS enforcement lives in a dedicated Windows sandbox implementation. RunSeal-specific code stays at the adapter layer: policy normalization, `PlatformSandboxPlan` mapping, audit events, capability reporting, and conformance gates. Do not reimplement setup-helper, command-runner, or OS-boundary code in the RunSeal adapter.

On macOS and Linux, RunSeal reports experimental `read-only` and `workspace-write` paths while leaving other sandbox levels unsupported. These portable paths enforce write and network boundaries, not workspace containment — host files may remain readable until `workspace-contained` is implemented and separately reported. Portable process cleanup is experimental and should not be treated as equivalent to the Windows reference cleanup.

Capability clients should rely on `sandbox_levels`, `network_modes`, and `feature_statuses` for status decisions. The legacy `features` booleans are coarse presence flags; portable capability probes are diagnostic only and do not promote unsupported capabilities.

| Capability | Windows | macOS | Linux |
| --- | --- | --- | --- |
| `danger-full-access` | supported | supported | supported |
| `read-only` | supported | experimental with `network.disabled` | experimental with `network.disabled` |
| `workspace-write` | supported | experimental with `network.disabled` | experimental with `network.disabled` |
| `workspace-contained` | supported | unsupported | unsupported |
| `network.disabled` | supported | experimental | experimental |
| `network.proxy` | supported | unsupported | unsupported |

### macOS and Linux parity evidence

Windows is the first-class reference backend. macOS and Linux entries below are
contributor work items: a capability should only move toward `supported` after
the listed conformance evidence passes on that platform.

| Area | Windows reference | macOS experimental | Linux experimental | Evidence needed for promotion |
| --- | --- | --- | --- | --- |
| Filesystem levels | `read-only`, `workspace-write`, and `workspace-contained` supported | `read-only` and `workspace-write` experimental; `workspace-contained` unsupported | `read-only` and `workspace-write` experimental; `workspace-contained` unsupported | Shared filesystem conformance plus adversarial external read/write, parent traversal, symlink or junction traversal, protected metadata, and runtime-root cases. |
| Network modes | `network.disabled` and `network.proxy` supported | `network.disabled` experimental; `network.proxy` unsupported | `network.disabled` experimental; `network.proxy` unsupported | Direct socket and HTTP egress denial for `network.disabled`; managed proxy routing, environment override resistance, direct egress bypass denial, audit/event coverage, and public-safe fail-closed output for `network.proxy`. |
| Setup/readiness | Windows setup readiness supported | No platform setup; reports unsupported Windows setup without blocking portable experimental paths | No platform setup; reports unsupported Windows setup without blocking portable experimental paths | Platform-specific setup contract, structured `getSetupStatus`, setup failure audit/events, and fail-closed behavior when setup is unavailable. |
| Runtime roots and synthetic home | Supported | Experimental | Experimental | Runtime root creation, environment redirect, cleanup, marker spoofing, symlink replacement, partial setup failure, and cross-execution contamination conformance. |
| Process cleanup | Supported | Experimental | Experimental | Timeout, cancellation, child process, shell trampoline, nested process tree, and helper reuse conformance without terminating unrelated processes. |
| Audit/events | Supported | Supported for current experimental paths | Supported for current experimental paths | Matching execution, denial, setup failure, and network decision events with JSONL audit records that do not expose backend-private details. |
| Adversarial conformance | Required for reference readiness | Required before promoting experimental claims | Required before promoting experimental claims | RFC-0016 manifest cases must pass with public-safe results for the capability being promoted; unsupported gaps must stay explicit and fail closed. |

The protocol and policy version strings are `runseal.protocol/v1` and `runseal.policy/v1`. The Rust package version remains pre-`1.0`; breaking changes to provisional CLI flags, JSON fields, and audit shapes may still land when the RFCs change.

The design lives in the RFC repository:

- https://github.com/runseal-labs/rfcs
- Protocol draft: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0006-stable-execution-protocol.md
- Escape model: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0015-escape-definition-and-adversarial-conformance.md
- Adversarial conformance: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0016-adversarial-conformance-harness-and-case-format.md

## Quickstart

Download the Windows release archive and place the three executables in the same directory:

- `runseal.exe`
- `runseal-windows-sandbox-setup.exe`
- `runseal-command-runner.exe`

Install or repair the Windows sandbox. Use `--elevate` to request UAC when the
current shell is not already elevated:

```powershell
.\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --elevate
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

The test suite is intentionally black-box and protocol-oriented. Runtime implementation should make these tests pass without changing their behavioral assertions unless the RFC changes first.

## Intended CLI

```bash
runseal exec --policy workspace-write --network proxy --cwd /workspace -- python skill.py
runseal exec --policy workspace-write --network disabled --cwd /workspace --timeout-ms 30000 -- whoami
runseal explain-policy --policy workspace-write --network proxy
runseal capabilities
runseal setup windows-sandbox --cwd C:\path\to\workspace --elevate
runseal rpc --stdio
runseal service --stdio
runseal version
```

For explicit unsandboxed local execution:

```bash
runseal exec --policy danger-full-access -- python skill.py
```

Available `exec` flags: `--json`, `--events`, `--policy`, `--network`, `--cwd`, `--timeout-ms`. Flags must appear before `--`; the command and its arguments follow `--`.

When `runseal exec --json` fails, stdout contains a structured `error` object and the process exits non-zero.
When `runseal exec --events` fails before an event stream completes, stdout contains one structured `error` object line and the process exits non-zero.

## Windows sandbox setup

Build all Windows binaries, including the setup helper and command runner:

```powershell
.\scripts\build-windows.ps1
```

For release artifacts:

```powershell
.\scripts\build-windows.ps1 -Release
```

The script places `runseal.exe`, `runseal-windows-sandbox-setup.exe`, and `runseal-command-runner.exe` in the selected `target\debug` or `target\release` directory.

Pushing a `v*` tag triggers `.github/workflows/release.yml`, builds native release archives, and publishes SHA-256 checksum files, `SHA256SUMS`, and a CycloneDX SBOM. To repackage an existing release, dispatch the workflow manually with the tag input.

Verify a downloaded archive with its checksum file:

```bash
sha256sum -c runseal-v0.1.3-linux-x86_64.tar.gz.sha256
```

Verify GitHub Artifact Attestations for build provenance and the SBOM without custom signing infrastructure:

```bash
gh attestation verify runseal-v0.1.3-linux-x86_64.tar.gz --repo runseal-labs/runseal
```

Run the first sandbox bootstrap. `--elevate` requests UAC when the current shell
cannot run setup directly:

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --elevate
```

Once the scheduled setup broker exists, the same command can repair workspace setup state without opening UAC again.

Use `--json` when an agent needs structured setup failure details.
Successful setup also includes `setup_status` so automation can verify readiness from the same command.

Check setup readiness without changing state:

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --status
```

The status payload reports coarse setup readiness: `broker`, `elevated`, `can_repair`, `can_run_setup_now`, `requires_setup`, and `next_action`. On Windows, the same `setup_status` object is included in sandboxed execution `BACKEND_UNAVAILABLE` errors when setup is missing or stale, in the matching `execution.failed` audit event, in `runseal capabilities`, and in `runseal explain-policy` for the requested workspace.

`requires_setup` stays true until setup marker and sandbox user artifacts are complete; `broker` only reports whether repairs can run without opening an elevated shell. `can_repair` is true when the current process is elevated or when the scheduled setup broker is already available.

Sandboxed `runseal exec` does not invoke UAC directly. It uses the installed scheduled setup broker; if the broker is missing or stale, execution fails closed with `windows sandbox setup unavailable` until the setup command above is run again.

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
    "network": {"mode": "proxy"},
    "timeout_ms": 30000
  }
}
```

The full JSON-RPC method set:

- `getVersion` — package version and protocol/policy version strings
- `getCapabilities` — backend capabilities, sandbox levels, network modes, feature statuses
- `getServiceStatus` — whether the current stdio control plane is direct or stateful service mode
- `explainPolicy` — resolve and explain a policy by name or inline definition
- `getSetupStatus` — query sandbox setup readiness without changing state
- `execute` — run a command under a sandbox policy
- `getExecution` — retrieve a completed execution by ID (service mode)
- `listExecutions` — list known executions (service mode)
- `cancelExecution` — cancel a running execution
- `subscribeEvents` — subscribe to events for a given execution
- `getAuditEvents` — retrieve audit events for a given execution
- `tailAudit` — stream new audit events
- `disposeSession` — release a session and its associated state

Supported `execute` params: `command` (string array; the program name must be path-qualified), `cwd`, `policy`, `network` (string or `{"mode": ...}`), `stdin`, `timeout_ms`, `metadata` (JSON object, max 4096 bytes), `env` (JSON object of key-value pairs).

## Third-party integration

Start with one of these surfaces:

- CLI: call `runseal exec --json` or `runseal exec --events` and handle structured errors.
- JSON-RPC stdio: launch `runseal rpc --stdio`, call `getVersion`, then `getCapabilities`, then `execute`.
- Service stdio: launch `runseal service --stdio` when one local process should own completed execution state across JSON-RPC requests.
- Conformance: set `RUNSEAL_BIN=/path/to/runseal` and run the black-box tests in `tests/`.

A runnable stdio JSON-RPC client is available in [`examples/stdio-json-rpc`](examples/stdio-json-rpc).

Gate sandboxed execution on `getCapabilities` and fail closed when a requested feature is unsupported or setup is unavailable. `getSetupStatus` reports setup readiness without changing state. `getServiceStatus` reports whether the current stdio control plane is direct or stateful service mode. The stdio service records completed executions for `getExecution`, event replay, summary listing through `listExecutions`, session disposal via `disposeSession`, and stable non-cancellable responses for already-finished executions. Running executions can be cancelled through `cancelExecution`. Events and audit trails are available through `subscribeEvents`, `getAuditEvents`, and `tailAudit`.

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

Run it from an elevated shell, or add `-AllowElevation` when validating the documented interactive UAC bootstrap path.

On Linux or macOS, run the portable probe smoke after building `runseal`:

```bash
python3 scripts/portable-probe-smoke.py
```

The portable smoke checks diagnostic capability probes, experimental portable enforcement where available, and structured fail-closed behavior for unsupported sandboxed policies. It does not promote portable capabilities to supported.

Windows reference-backend readiness requires the smoke check plus the Rust checks above to pass on a Windows host.

For the managed proxy path specifically:

```powershell
cargo test --test filesystem_conformance network_proxy_allows_http_through_managed_proxy_when_supported_or_fails_closed
```

Add `-IncludeGit` to the Windows smoke command when validating a local Git for Windows installation inside the sandbox.

To run tests against another candidate implementation:

```bash
RUNSEAL_BIN=target/debug/runseal cargo test
```

## Non-goals

- No Docker daemon dependency.
- No unmanaged direct network access as an enterprise default.
- No direct secret injection into sandboxed processes.
- No cloud multi-tenant sandbox control plane in the core runtime.
- No claim that OS-native sandboxing prevents every kernel-level escape.
