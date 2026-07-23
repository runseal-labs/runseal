# RunSeal

[简体中文](README.zh-CN.md)

RunSeal is an OS-native, policy-governed environment for safe local command execution.

It exposes a stable execution protocol that launches user-provided commands inside enforceable filesystem, process, resource, and network boundaries. Enterprise network access routes through a controlled proxy that enforces routes, injects authentication at the boundary, redacts sensitive data, and emits structured audit events.

RunSeal is **not** an AI governance platform, a tool ecosystem, a cloud VM sandbox, a Docker Desktop replacement, or a microVM platform. It is a local-first execution boundary purpose-built for agent frameworks.

## Status

RunSeal is a technical-preview release for third-party integration. The repository includes a buildable CLI/RPC shell, standard policy profile normalization, canonical policy hashes, backend capability reporting, a first-class Windows reference backend, `PlatformSandboxPlan` summaries, JSONL audit output, and black-box conformance tests.

Execution support is intentionally narrow today: `danger-full-access` runs as local, non-sandboxed execution. `read-only`, `workspace-write`, and `workspace-contained` are supported on Windows, macOS, and Linux. Windows remains the complete reference platform. The experimental macOS and Linux backends also support `network.proxy`, while enforcing contained host reads through deny-by-default platform views.

The product boundary is deliberately simple. RunSeal provides the execution environment: launch a command, apply policy, enforce OS-native boundaries, emit events and audit records, and fail closed when requested controls are unavailable. It does not try to become an AI governance platform or a tool/application ecosystem. Integrations should remain thin adapters over the same command execution contract.

On Windows, a sandbox request produces a `PlatformSandboxPlan` covering runtime root, synthetic home, profile root, temp root, setup requirements, protected filesystem categories, process boundary state, network guard state, and policy path planning. The reference backend handles root creation and cleanup, environment redirects, process cleanup, filesystem enforcement, process isolation, and direct network deny-or-proxy guard enforcement.

Low-level OS enforcement lives in a dedicated Windows sandbox implementation. RunSeal-specific code stays at the adapter layer: policy normalization, `PlatformSandboxPlan` mapping, audit events, capability reporting, and conformance gates. Do not reimplement setup-helper, command-runner, or OS-boundary code in the RunSeal adapter.

On macOS and Linux, RunSeal supports `read-only`, `workspace-write`, and `workspace-contained` with default unmanaged networking. `workspace-contained` exposes the workspace, private runtime roots, explicit policy read roots, and a minimum read-only system execution baseline; other host paths remain unreadable. `network.disabled` is available when callers explicitly want network denial. Both experimental backends also support `network.proxy`: macOS permits only the per-execution managed proxy endpoint, while Linux uses an isolated network namespace and execution-local relay. Direct external, unrelated loopback, and unapproved host IPC connections remain denied.

The macOS and Linux backend status and low-level feature statuses remain `experimental`; the `supported` claims below apply to the public sandbox levels and network modes that execute through the current portable enforcement paths. Capability clients should rely on `sandbox_levels`, `network_modes`, and `feature_statuses` for status decisions. The legacy `features` booleans are coarse presence flags; portable capability probes are diagnostic only and do not promote unsupported capabilities.

| Capability | Windows | macOS | Linux |
| --- | --- | --- | --- |
| `danger-full-access` | supported | supported | supported |
| `read-only` | supported | supported | supported |
| `workspace-write` | supported | supported | supported |
| `workspace-contained` | strict compliance option | supported (experimental backend) | supported (experimental backend) |
| `network.unmanaged` | supported | supported | supported |
| `network.disabled` | supported | supported | supported |
| `network.proxy` | supported | supported (experimental backend) | supported (experimental backend) |

### macOS and Linux hardening evidence

Windows is the first-class reference backend. macOS and Linux entries below track
the extra hardening evidence for capabilities they already claim, including
deny-by-default host-read containment.

| Area | Windows reference | macOS portable | Linux portable | Evidence tracked |
| --- | --- | --- | --- | --- |
| Filesystem levels | `read-only` and `workspace-write` supported; `workspace-contained` available for strict compliance | `read-only`, `workspace-write`, and `workspace-contained` supported on the experimental backend | `read-only`, `workspace-write`, and `workspace-contained` supported on the experimental backend | Shared filesystem conformance plus adversarial external read/write, parent traversal, symlink or junction traversal, protected metadata, and runtime-root cases for claimed capabilities. |
| Network modes | `network.unmanaged`, `network.disabled`, and `network.proxy` supported | `network.unmanaged`, `network.disabled`, and `network.proxy` supported on the experimental backend | `network.unmanaged`, `network.disabled`, and `network.proxy` supported on the experimental backend | Direct pass-through behavior for `network.unmanaged`; direct socket and HTTP egress denial for `network.disabled`; managed proxy routing and `CONNECT` tunneling, environment override resistance, direct TCP/UDP, unrelated-loopback, host-IPC, and inherited-socket bypass denial, credential redaction, audit/event coverage, and public-safe fail-closed output for `network.proxy`. |
| Setup/readiness | Windows setup readiness supported | No platform setup; reports unsupported Windows setup without blocking portable enforcement paths | No platform setup; reports unsupported Windows setup without blocking portable enforcement paths | Platform-specific setup contract, structured `getSetupStatus`, setup failure audit/events, and fail-closed behavior when setup is unavailable. |
| Runtime roots and synthetic home | Supported | Experimental | Experimental | Runtime root creation, environment redirect, cleanup, marker spoofing, symlink replacement, partial setup failure, and cross-execution contamination conformance. |
| Process cleanup | Supported | Experimental | Experimental | Timeout, cancellation, child process, shell trampoline, nested process tree, and helper reuse conformance without terminating unrelated processes. |
| Audit/events | Supported | Supported for current portable paths | Supported for current portable paths | Matching execution, denial, setup failure, and network decision events with JSONL audit records that do not expose backend-private details. |
| Adversarial conformance | Required for reference readiness | Tracked for supported portable claims | Tracked for supported portable claims | RFC-0016 manifest cases must pass with public-safe results for the claimed capability; unsupported gaps must stay explicit and fail closed. |

The protocol and policy version strings are `runseal.protocol/v1` and `runseal.policy/v1`. The Rust package version remains pre-`1.0`; breaking changes to provisional CLI flags, JSON fields, and audit shapes may still land when the RFCs change.

The design lives in the RFC repository:

- https://github.com/runseal-labs/rfcs
- Protocol draft: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0006-stable-execution-protocol.md
- Escape model: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0015-escape-definition-and-adversarial-conformance.md
- Adversarial conformance: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0016-adversarial-conformance-harness-and-case-format.md
- macOS managed proxy: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0019-macos-managed-proxy-network-boundary.md
- Linux managed proxy: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0020-linux-managed-proxy-network-boundary.md

## Quickstart

Download the Windows release archive and place the three executables in the same directory:

- `runseal.exe`
- `runseal-windows-sandbox-setup.exe`
- `runseal-command-runner.exe`

Windows sandbox support requires Windows 10 1809 / build 17763 or newer.

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
runseal exec --policy workspace-write --cwd /workspace -- python skill.py
runseal exec --policy workspace-write --network proxy --cwd /workspace -- python skill.py
runseal exec --policy workspace-write --network disabled --cwd /workspace --timeout-ms 30000 -- whoami
runseal explain-policy --policy workspace-write --network proxy
runseal capabilities
runseal setup windows-sandbox --cwd C:\path\to\workspace --elevate
runseal mcp --stdio --policy workspace-write
runseal rpc --stdio
runseal service --stdio
runseal version
```

For explicit unsandboxed local execution:

```bash
runseal exec --policy danger-full-access -- python skill.py
```

Available `exec` flags: `--json`, `--events`, `--policy`, `--network`, `--cwd`, `--timeout-ms`. Omit `--network` for unmanaged direct networking; use `disabled` or `proxy` only when requesting those network controls. Flags must appear before `--`; the command and its arguments follow `--`.

When `runseal exec --json` fails, stdout contains a structured `error` object and the process exits non-zero.
When `runseal exec --events` fails before an event stream completes, stdout contains one structured `error` object line and the process exits non-zero.

## Windows sandbox setup

Windows sandbox support requires Windows 10 1809 / build 17763 or newer.

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
sha256sum -c runseal-vX.Y.Z-linux-x86_64.tar.gz.sha256
```

Verify GitHub Artifact Attestations for build provenance and the SBOM without custom signing infrastructure:

```bash
gh attestation verify runseal-vX.Y.Z-linux-x86_64.tar.gz --repo runseal-labs/runseal
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
- MCP stdio: launch `runseal mcp --stdio --policy <policy> [--network <mode>]` only when exposing RunSeal's narrow execution adapter directly to an AI agent.
- JSON-RPC stdio: launch `runseal rpc --stdio`, call `getVersion`, then `getCapabilities`, then `execute`.
- Service stdio: launch `runseal service --stdio` when one local process should own completed execution state across JSON-RPC requests.
- Conformance: set `RUNSEAL_BIN=/path/to/runseal` and run the black-box tests in `tests/`.

A runnable stdio JSON-RPC client is available in [`examples/stdio-json-rpc`](examples/stdio-json-rpc).

RunSeal's MCP surface is a narrow execution adapter, not a general-purpose MCP server framework. It exposes exactly one model-controlled tool, `exec`. The server owner fixes `policy` and `network` at startup; the agent cannot call `capabilities`, explain policy, change network mode, change sandbox level, or provide stdin through MCP. Tool calls accept only `command`, required `cwd`, optional `timeout_ms`, and optional `env` string overrides. `env` is still subject to the fixed RunSeal policy scrub rules. This keeps the MCP surface useful for coding agents while preventing the model from granting itself broader execution permissions.

Minimal MCP host config:

```json
{
  "mcpServers": {
    "runseal": {
      "command": "runseal",
      "args": ["mcp", "--stdio", "--policy", "workspace-write"]
    }
  }
}
```

Use the absolute `runseal` binary path when the MCP host does not inherit your shell `PATH`. Restart the host after editing its MCP config, then call the advertised `exec` tool with:

```json
{
  "command": ["/usr/bin/python3", "-c", "print('hello from runseal')"],
  "cwd": "/workspace",
  "timeout_ms": 30000,
  "env": {"PYTHONUNBUFFERED": "1"}
}
```

Omit `--network` for unmanaged direct networking; pass `--network disabled` only when the MCP host should deny network egress. With `--network proxy`, commands should use the injected proxy environment variables such as `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `GIT_HTTP_PROXY`, and `GIT_HTTPS_PROXY` inside the current execution; do not hardcode a proxy host, port, or credential because RunSeal may attach the execution to a shared local managed proxy broker. `RUNSEAL_NETWORK_PROXY_AUTHORIZATION` is a per-execution credential for tools that require an explicit `Proxy-Authorization` header.

Gate sandboxed execution on `getCapabilities` and fail closed when a requested feature is unsupported or setup is unavailable. `getSetupStatus` reports setup readiness without changing state. `getServiceStatus` reports whether the current stdio control plane is direct or stateful service mode. The stdio service records completed executions for `getExecution`, event replay, summary listing through `listExecutions`, session disposal via `disposeSession`, and stable non-cancellable responses for already-finished executions. Running executions can be cancelled through `cancelExecution`. Events and audit trails are available through `subscribeEvents`, `getAuditEvents`, and `tailAudit`.

Every sandboxed execution is bound to a policy epoch derived from the canonical policy and workspace path. Concurrent executions with the same epoch may run together. Stateful clients and future daemon transports must not change the active workspace or global policy while sandboxed executions are running. A concurrent request with a different policy epoch must fail explicitly with `POLICY_TRANSITION_BUSY`; it must not be silently accepted, downgraded, or applied to already-running executions. Boundary-changing fields such as filesystem policy, network mode, workspace, identity, and setup state are epoch inputs; only non-boundary operations such as cancellation and event or audit reads may target running executions. Future different-workspace concurrency must use isolated sandbox workers, identities, and setup state per epoch rather than mutating a shared sandbox in place.

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
The smoke also checks that the Windows helper binaries are present and that the final sandbox runner token can create and write inside the allowed workspace root.

On Linux or macOS, run the portable probe smoke after building `runseal`:

```bash
python3 scripts/portable-probe-smoke.py
```

The portable smoke checks diagnostic capability probes, supported portable enforcement, and structured fail-closed behavior for unsupported sandboxed policies.

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

- No AI governance platform, organization-wide approval workflow, policy dashboard, SIEM product, or compliance reporting system in the core runtime.
- No implementation of general-purpose MCP servers or semantic governance for arbitrary MCP tools.
- No universal MCP gateway, tool registry, or adapter ecosystem in the core runtime.
- No Docker daemon dependency.
- No unmanaged direct network bypass when enterprise network controls are requested.
- No direct secret injection into sandboxed processes.
- No cloud multi-tenant sandbox control plane in the core runtime.
- No claim that OS-native sandboxing prevents every kernel-level escape.
