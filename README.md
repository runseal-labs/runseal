# RunSeal

[简体中文](README.zh-CN.md)

`RUNSEAL_MAX_ACTIVE_EXECUTIONS` sets the RPC/service connection's active execution
limit at startup (decimal 1..64, default 8). `getCapabilities.limits.max_active_executions`
reports the frozen value. A full connection rejects extra executions with
`EXECUTION_LIMIT_EXCEEDED` before launching their targets; queries and cancellation
remain available. Requests still undergoing admission and owned workers awaiting
cleanup consume the same capacity. Admission validation and resource setup run
independently of the connection's control requests. Targets wait for delivery of
the preparing receipt. Invalid configuration is rejected without echoing its value.
`RUNSEAL_CLEANUP_TIMEOUT_MS` sets the host's total cleanup wait at startup
(decimal 100..60000 milliseconds, default 10000). `limits.cleanup_timeout_ms`
reports the frozen value. All host cleanup stages keep the earliest absolute
deadline; a later phase or Drop cannot restart it. Backend stages may impose
earlier deadlines. This wait does not extend a command's execution timeout.
`RUNSEAL_REPLAY_EXECUTION_BYTES` (default 1 MiB, range 64 KiB..64 MiB) and
`RUNSEAL_REPLAY_CONNECTION_BYTES` (default 8 MiB, range 64 KiB..256 MiB) configure
resident replay retention in decimal bytes. The connection budget must cover the
per-execution budget. Both are frozen at startup and reported as
`limits.replay_execution_bytes` and `limits.replay_connection_bytes`. Eviction
advances the available history range without changing live output or policy hashes.

Completed-execution and redacted audit-query retention are configured at startup:

| Environment | Default | Accepted range |
|---|---:|---:|
| `RUNSEAL_COMPLETED_EXECUTIONS` | 1,024 | 1..65,536 |
| `RUNSEAL_COMPLETED_EXECUTION_BYTES` | 8 MiB | 64 KiB..256 MiB |
| `RUNSEAL_AUDIT_CACHE_BYTES` | 8 MiB | 64 KiB..256 MiB |

Byte settings use decimal byte counts. `getCapabilities.limits` reports them as
`completed_executions`, `completed_execution_bytes`, and `audit_cache_bytes`.
Summary count and byte budgets both apply; active executions remain available.
Audit cache eviction reports incomplete history and preserves durable audit files.
These settings do not change execution policy hashes.

`RUNSEAL_STREAM_CHUNK_BYTES` configures decoded stream/input/control chunks
(default 64 KiB, range 8 KiB..64 KiB). `RUNSEAL_INPUT_PENDING_BYTES` configures
each stdin/control pending queue (default 256 KiB, range 8 KiB..16 MiB), including
bytes awaiting actual write confirmation. Pending capacity must cover one chunk.
Both use decimal bytes, freeze at startup, and are reported as
`limits.stream_chunk_bytes` and `limits.input_pending_bytes`. RPC rejects an
oversized decoded chunk before target delivery; output and plain CLI inputs are
split into chunks without changing their bytes or offsets. Policy hashes remain
unchanged. Every deployment limit above is configurable at startup and reported
through `getCapabilities.limits`.

`RUNSEAL_RPC_FRAME_BYTES` bounds incoming and outgoing JSON-RPC lines, including
the newline (default 1 MiB, range 128 KiB..1 MiB). `limits.rpc_frame_bytes`
reports the frozen startup value; `limits.query_response_bytes` reports the
snapshot envelope budget, `min(256 KiB, rpc_frame_bytes)`. Oversized input is
drained to its newline and rejected without starting its target; later requests
can continue. Snapshots retain newest complete records and explicitly report
truncation. An output frame that cannot fit closes the connection and cleans
its active executions. This transport setting does not change policy hashes.

`RUNSEAL_MAX_OUTPUT_BYTES` sets the aggregate stdout/stderr/terminal/control limit
for each execution (default 16 MiB, range 1..16,777,216 decimal bytes).
`limits.max_output_bytes` reports this startup-frozen deployment cap. Normalization
writes the effective `resources.max_output_bytes` into canonical policy JSON:
the deployment cap when omitted, or the smaller requested/deployment value.
An explicit policy value of zero stays zero. Explain output, policy hashes,
admission receipts, execution events, and audit records use that effective policy.
Changing the effective output cap changes its hash; transport-only settings do not.
Exact-budget output can complete normally; exceeding it reports
`OUTPUT_LIMIT_EXCEEDED` and cleans the execution range. The engine rejects an
unnormalized output limit instead of imposing a hidden unhashed fallback.

`runseal exec` reports RunSeal failures as outer exit 125 in plain, JSON, and
event modes, timeout as 124, and cancellation as 130. Plain diagnostics use
`[runseal:<CODE>]` on stderr; pre-start JSON/events failures use one structured
error. Event-mode runtime failures preserve one terminal instead of appending
another error. Successfully obtained child results retain the child's exit in
plain mode and use outer 0 in JSON/events, even for child exit 125. A child's
bytes may contain the diagnostic prefix; use structured results to classify it.
Unknown option, timeout/network value, and policy refusal diagnostics do not
repeat arbitrary rejected argument values.

Once final JSON delivery starts, a failed write or output cleanup returns a
nonzero outer status without retrying or appending another error object. A
durable terminal records execution completion; it does not acknowledge complete
result delivery. Check both the outer status and the complete JSON document.

On Windows, plain-mode console output is forwarded through an owned helper
process. If the console stops reading, cancellation terminates and waits for
that helper before reporting cleanup. The local and sandboxed stalled-console
regressions are `cli_stalled_console_output_cleans_owned_range_and_preserves_peer`
and `sandboxed_stalled_console_output_cleans_owned_range_and_preserves_peer` in
`tests/execution_conformance.rs`.

On Windows, console Ctrl-C and Ctrl-Break received by `exec` request cancellation
through the execution owner. All three output modes return outer 130 after
verified cleanup, preserving the native exit facts and one audit terminal.
Conformance covers actual signals in an isolated console, descendant cleanup,
and a continuing independent peer under `danger-full-access`. Console shutdown
events, portable host signals, and the sandboxed signal matrix still need evidence.

`RUNSEAL_SENDER_BYTES` freezes the per-connection protocol send budget at startup:
default 8 MiB, allowed 5 MiB..64 MiB, reported as `limits.sender_bytes`. Two MiB
remain reserved for controller staging; the remaining writer budget reserves one
MiB for control frames. Encoded frame storage, node charges, and the in-flight
write count against enqueue and event-poll limits. This setting changes transport
backpressure without changing policy hashes or execution output limits. The
complete resident-memory bound still requires evidence beyond these queue charges.

`RUNSEAL_BACKPRESSURE_MS` sets the no-output-progress grace in milliseconds
(default 5,000, range 100..60,000), frozen at startup and reported as
`limits.backpressure_ms`. RPC, CLI output/control, and bounded backend delivery
use this value. Only actual writes reset the transport writer's progress; an
idle connection with no pending output does not expire. Backend queue waits also
stop at the original cleanup deadline. This setting does not change policy hashes
or replace an execution timeout.

Pending stdin/control byte writes are packed into bounded internal buffers;
request boundaries do not become permanent queue nodes. The queue discards unused
caller vector capacity, keeps in-flight bytes charged until actual write ACK,
rejects over-budget requests before copying, and drains accepted bytes before EOF.
Capacity tests cover single-byte saturation and oversized caller allocations;
native stdin/control tests check binary order, rejection, EOF, and metadata-only
audit. These checks bound this queue's retained buffers and nodes. Validation of
the entire connection's resident-memory ceiling remains pending.

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

The protocol and policy version strings are `runseal.protocol/v2` and `runseal.policy/v1`. The v2 implementation is in progress: admission receipts, backend-confirmed start events, live pipe output, streamed stdin, activity queries, cancellation, subscription replacement/replay/unsubscribe, bounded retention, cancellation with a paused protocol reader, queued-notification invalidation, writer-stall cleanup, required-audit admission refusal, numbered live/audit terminal parity, terminal retention-range snapshots, and session disposal that waits for owned process/runtime-root cleanup have targeted Windows pipe conformance evidence. Runtime audit-write failure has a real local-process fault test with a read-only file handle and an explicit missing-durable-record result. Windows local and sandboxed PTY startup, terminal bytes, resize, and foreground interrupt with continued shell/peer liveness have targeted danger-full-access and workspace-write/unmanaged tests. CLI PTY also has real-console input/Unicode, interrupt, resize, exit-code/mode-restoration and input-EOF cleanup tests for those profiles. Control, configurable transport limits, complete cleanup evidence, and the platform/combination conformance matrix remain pending. The Unix protocol writer uses nonblocking output, but that path has not been validated on this Windows host. This checkout is not a completed v2 release candidate.

The standard `read-only` profile permits broad reads and denies workspace writes;
execution-private runtime roots remain writable. Explicit custom read roots are
preserved. Windows permission profiles include those runtime roots before choosing
the isolation mode.

Windows sandboxed pipe executions now verify process-range and runtime-root cleanup
for natural exit, cancellation, timeout, and output limits before reporting
`cleanup_complete:true`. Windows explicit local pipe execution also owns and clears
its process range, with conformance covering natural exit, cancellation, host death,
and isolation from a peer connection. Local output drains after the owned range is
empty, and input/output joins share a cleanup deadline. Real tests retain duplicated
stdout/stdin handles in a foreign peer and verify complete output, prompt completion,
and peer survival. The sandboxed runner now joins its I/O workers before a successful
cleanup acknowledgement and reports the actual process exit code after timeout.
Verified exit facts also survive failed runner cleanup and a later parent input
cleanup failure. Missing exit confirmation remains unknown, and a known exit
does not make incomplete range cleanup successful.
Capture input-source failures use `EXECUTION_INPUT_FAILED` / `input_failed` and
retain verified exit facts. Successful runner, parent, and runtime-root cleanup reports
`cleanup_complete:true`; a cleanup failure takes precedence and keeps the first
accepted termination reason. Native I/O and real local-engine fault regressions
cover the reporting boundary; the full sandbox fault matrix remains pending.
Other runtime management failures use `execution_failed` as their first accepted
cause, preserving the applicable error code. A started backend without trusted
cleanup facts fails closed with `EXECUTION_CLEANUP_FAILED` and an unknown exit;
it cannot be reported as a command that failed to start. Real local-process fault
tests cover range termination, earlier cancellation, and one durable terminal.
The complete sandbox I/O fault matrix and portable cleanup evidence remain
pending. A binding left by a dead host is never cleared automatically: dead
reservations, the native quarantine signal, and the cleanup-failure marker are
released only by the explicit `runseal repair execution-gates` proof described
below.

Windows shared execution state now follows the native machine state directory and
the OS process boundary, rather than caller environment paths or runtime-home
spelling. Real process tests prove admission refusal across caller path overrides,
continued owner heartbeat, and successful admission after complete drain. The
state remains a protected subpath even when its parent is writable; a workspace
inside it is refused before launch. Coordination waits are bounded. Reservations
bind their host PID to its native creation time. Dead or unverifiable hosts do
not acknowledge cleanup: admission fails closed for either policy, and healthy
peers release only their own records. If writing the cleanup-failure marker fails,
the failed owner retains its reservation and a protected native quarantine signal;
another process cannot readmit the binding while that signal remains alive.
The complete shared-state fault matrix across every backend combination remains
pending; a dead host binding is restored only through the explicit
`runseal repair execution-gates` proof.

The Windows capture parent also polls partial IPC frames without blocking on a
peer that keeps its pipe open. Cancellation, execution timeout, or input-worker
failure starts a bounded parent cleanup wait shared with its input-worker join.
An expired wait is not renewed by Drop; unfinished I/O stays owned and prevents
a successful cleanup report. Real pipe and peer-process regressions cover these
paths. The complete cleanup deadline across preparing, runner, and frontend
stages still requires validation and implementation.

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
Plain `exec` forwards child stdout and stderr separately as live binary bytes and preserves the child's exit code. Stdin defaults to empty; use `--stdin inherit` to forward caller input and EOF. Inherit is restricted to plain mode. `--json` returns one final result with `output.stdout` and `output.stderr` objects containing `encoding: "base64"`, `data`, `bytes`, and `truncated`; a child nonzero exit remains in `exit_code` with an outer success status when RunSeal itself completes normally.
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

Sandbox state lives in one machine-level home, `%LOCALAPPDATA%\RunSeal\windows-sandbox`
(overridable through `RUNSEAL_WINDOWS_SANDBOX_HOME`), shared across every
workspace. A single bootstrap therefore covers all current and future
workspaces; switching the active workspace never requires setup again.

Run the first sandbox bootstrap. `--elevate` requests UAC when the current shell
cannot run setup directly:

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --elevate
```

The bootstrap registers a scheduled setup broker. After that, the same
command repairs or recreates setup state without opening UAC again, from any
workspace, and sandboxed `runseal exec` repairs missing or stale setup through
the broker automatically instead of failing.

Use `--json` when an agent needs structured setup failure details.
Successful setup also includes `setup_status` so automation can verify readiness from the same command.

Check setup readiness without changing state:

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --status
```

The status payload reports coarse setup readiness: `broker`, `elevated`, `can_repair`, `can_run_setup_now`, `requires_setup`, and `next_action`. On Windows, the same `setup_status` object is included in sandboxed execution `BACKEND_UNAVAILABLE` errors when setup is missing or stale, in the matching `execution.failed` audit event, in `runseal capabilities`, and in `runseal explain-policy` for the requested workspace.

`requires_setup` stays true until setup marker and sandbox user artifacts are complete; `broker` only reports whether repairs can run without opening an elevated shell. `can_repair` is true when the current process is elevated or when the scheduled setup broker is already available.

Sandboxed `runseal exec` does not invoke UAC directly. It uses the installed scheduled setup broker: missing or stale setup is repaired through the broker automatically before execution. Only when the broker itself is missing does execution fail closed with `windows sandbox setup unavailable` until the setup command above is run again.

If a host dies without acknowledging cleanup, its execution binding stays closed and every later sandboxed admission returns `EXECUTION_CLEANUP_FAILED`. Only an explicit repair restores it:

```powershell
.\target\debug\runseal.exe repair execution-gates --json
```

The repair refuses unless every recorded reservation owner is gone, no process runs under the sandbox identity, and every recorded runtime root is absent or safely removable. It then drops the reservation, the cleanup-failure marker, and the native quarantine signal for the current machine binding. An uninspectable process token or a reservation that predates runtime-root recording is unverified evidence, so the default repair fails closed; `--accept-unverified-release` proceeds and marks exactly what stayed unverified in the JSON report. Normal admission, a `setup --status` read, and a restart never repair a binding.

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
- `getCapabilities` — backend capabilities, sandbox levels, network modes, coarse feature statuses, fine-grained `execution_capabilities`, and `execution_profiles` rows per sandbox level, network mode, and io mode
- `getServiceStatus` — whether the current stdio control plane is direct or stateful service mode
- `explainPolicy` — resolve and explain a policy by name or inline definition
- `getSetupStatus` — query sandbox setup readiness without changing state
- `execute` — run a command under a sandbox policy
- `getExecution` — retrieve activity or a retained final execution by ID
- `listExecutions` — list known executions (service mode)
- `cancelExecution` — cancel a running execution
- `subscribeEvents` — subscribe to events for a given execution
- `getAuditEvents` — retrieve audit events for a given execution
- `tailAudit` — stream new audit events
- `disposeSession` — release a session and its associated state

Supported `execute` params: `command` (string array; the program name must be path-qualified), `cwd`, `policy`, `network` (string or `{"mode": ...}`), `stdin`, `timeout_ms`, `metadata` (JSON object, max 4096 bytes), `env` (JSON object of key-value pairs).

Windows local and sandboxed PTY requests use `io:{"mode":"pty","rows":24,"cols":80}` with `stdin:{"mode":"stream"}`. Output arrives as `execution.terminal`; the final result includes `terminal_bytes` and `stderr_merged:true`. `resizeExecution` accepts an execution ID and dimensions from 1 to 1000, returning a queue-admission receipt. Pipe EOF requests for PTY input are refused. `signalExecution` accepts `signal:"interrupt"` for an active PTY and queues a terminal Ctrl+C without cancelling the Execution. Tests for danger-full-access and workspace-write prove foreground termination, continued execution in the same shell, and peer liveness. The local profile remains explicit unsandboxed execution. Windows plain CLI supports `--pty --stdin inherit`. It forwards terminal output to stdout, tracks console dimensions, restores console modes on return, and cancels/cleans its Execution when inherited input ends. With redirected output it starts at 80 columns and 24 rows. Real-console tests cover Unicode input, Ctrl+C, resize, native exit 7, and mode restoration; redirected-input EOF tests prove range cleanup and peer liveness. The complete fault/platform matrix remains pending.

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

The conformance tests are Rust integration tests. `cargo test` builds and runs the local `runseal` binary. `tests/ACCEPTANCE.md` maps every RFC-0021 acceptance criterion (AC01-28) to its test location, command, platform and mode, expected behavior, and actual result.

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

Targeted Windows RPC control tests now cover fixed child fd 3 in all four standard
profiles: three binary rounds, ordered input half-close with reverse output, separate
stdout/stderr and offsets, cleanup with a live peer, and metadata-only audit records.
Local and workspace-write tests also cover progress with blocked stdin, bounded
control input, cancellation, and the shared output limit. The complete control fault/profile matrix remains pending.

Windows plain CLI supports --control-fd 3 for an existing caller-owned local duplex
endpoint. It forwards binary control independently of stdout/stderr, queues input
half-close, retains the command's exit code, and bounds stalled control output.
Local and workspace-write tests cover three rounds, final reverse output after EOF,
startup refusal for missing endpoints/invalid combinations, and cleanup with a live
peer when the caller stops reading control. A public Windows API example is included
in examples/stdio-json-rpc/runseal_control_cli_example.py. Windows redirected CLI stdout/stderr and event output use nonblocking pipe writes.
Local and workspace-write tests cover paused/closed readers, owned range cleanup,
durable termination causes, peer liveness, and a timeout winning before a writer
stall. Native Windows Console/file output uses bounded cancellable writes with owned
handles. Real tests cover a paused Console reader with range/runtime cleanup and
peer survival, binary file output, and gated one-byte Unicode chunks with an
unchanged caller code page. Console renders UTF-8, replacing invalid or final
incomplete sequences; pipes/files preserve raw bytes. The complete fault/profile
matrix remains pending.

A paced local CLI Console regression keeps execution active while consuming
output, verifies native exit 7 and complete audit counts, and preserves every
supplementary character without changing CP437. The stall timer follows actual
native completions; disabling that refresh falsely reports backpressure.

Plain inherited Windows Console input now has local/workspace-write evidence for
Unicode, native backspace editing, raw input, Ctrl+Z EOF, and early command exit
without a newline. Tests confirm native exit 7, unchanged console modes, and
retained partial caller input. The complete frontend cleanup fault matrix remains pending.

CLI frontend input, terminal modes, and control endpoint cleanup now run before
the lifecycle owner commits the terminal audit event. A retained frontend resource
turns the result into cleanup_failed while preserving the original termination
cause and actual exit facts. Output worker cleanup also runs before this commit;
an unjoined worker prevents success. Local process-range and frontend cleanup
callbacks receive the same host deadline; frontend phases and Drop cannot renew
it, and unfinished I/O workers retain their owners. CLI stdout/stderr and control
delivery also stop when that cleanup deadline expires, even with continuing
progress. A paced local Console test retains native exit 7, reports incomplete
frontend cleanup, and returns wrapper exit 125. Preparing, general observer
delivery, helper and capture-parent coordination, terminal-mode recovery, and the full fault matrix
remain pending.

Windows runner preparation now polls cancellation/timeouts during connections,
request writes, and incremental startup confirmation under one preparation budget.
Native fixtures verify retention of unjoined connect owners and termination of a
suspended process after failed security setup. Capture-parent I/O reuses the host's
absolute cleanup deadline. A failed startup remains unverified cleanup until the
entire execution boundary can be proven released; stopping one runner is
insufficient. Native runner launch now runs in an owned worker under the same
preparation budget. Expired waiting retains that worker; a late suspended process
is stopped without resuming the target. Native setup, late-launch recovery,
the complete helper deadline, and the complete
sandboxed startup fault matrix remain pending.
