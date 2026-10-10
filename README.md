# RunSeal

[简体中文](README.zh-CN.md)

RunSeal is an OS-native, policy-governed environment for local command
execution. A `SandboxPolicy` defines the filesystem, process, resource, and
network controls for each `Execution`; RunSeal emits structured events and
JSONL audit records.

RunSeal is a local execution boundary, not an AI governance platform, tool
registry, cloud VM, or container manager. Integrations should remain thin clients
of the same execution contract.

## Status

RunSeal is a technical preview. Windows is the reference backend. macOS and
Linux report sandbox enforcement as `experimental`; unsupported requests fail
closed. `danger-full-access` is explicit local execution and provides **no
sandbox guarantee**.

| Capability | Windows | macOS | Linux |
| --- | --- | --- | --- |
| `danger-full-access` (unsandboxed) | supported | supported | supported |
| `read-only` | supported | experimental | experimental |
| `workspace-write` | supported | experimental | experimental |
| `workspace-contained` | supported | experimental | experimental |
| `network.unmanaged` | supported | supported | supported |
| `network.disabled` | supported | experimental | experimental |
| `network.proxy` | supported | experimental | experimental |

`experimental` is not a support guarantee. Check `runseal capabilities` or
`getCapabilities` on the target host before relying on a capability. Generic
Windows CI skips tests that require a prepared sandbox identity; skipped cases
are not conformance passes.

## Quick start

Check the capabilities available on this host:

```sh
runseal capabilities
```

Run a command under a policy (flags go before `--`):

```sh
runseal exec --policy workspace-write --cwd /path/to/workspace -- python3 -c "print('hello')"
```

The network default depends on the selected policy. Request managed-proxy or
network-disabled execution explicitly when supported by the host:

```sh
runseal exec --policy workspace-write --network proxy --cwd /path/to/workspace -- python3 -c "print('hello')"
runseal exec --policy workspace-write --network disabled --cwd /path/to/workspace -- python3 -c "print('hello')"
```

For intentional unsandboxed local execution, choose `danger-full-access`
explicitly:

```sh
runseal exec --policy danger-full-access --cwd /path/to/workspace -- python3 -c "print('hello')"
```

Use `runseal explain-policy --policy workspace-write` to inspect a policy
before execution.

### Windows setup

Windows sandbox support requires Windows 10, version 1809 (build 17763) or
newer. Build or obtain `runseal.exe`, `runseal-windows-sandbox-setup.exe`, and
`runseal-command-runner.exe` in the same directory. To build them from source:

```powershell
.\scripts\build-windows.ps1
```

Initialize or repair setup (use `--elevate` to request UAC when needed), then
check readiness:

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\work --elevate
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\work --status
```

After setup, the broker can repair stale setup state for later executions. If a
host dies without confirming cleanup, sandbox admission remains closed. An
administrator can request proof-gated recovery with
`runseal repair execution-gates --json`; if process or runtime-root cleanup
cannot be verified, RunSeal refuses repair and keeps the binding closed.

## CLI and integrations

`runseal exec` supports plain, `--json`, and `--events` output. Plain mode
forwards child stdout and stderr separately and preserves the child's exit code.
RunSeal failures use outer exit code 125, timeout 124, and cancellation 130. In
JSON/events mode, child exit status is reported separately from RunSeal's own
status; streamed output is represented as base64 where applicable.

Available local interfaces:

- **CLI:** `runseal exec`, `runseal explain-policy`, and `runseal capabilities`.
- **JSON-RPC:** `runseal rpc --stdio` for protocol clients.
- **Service:** `runseal service --stdio` when completed execution state should be
  retained across requests.
- **MCP:** `runseal mcp --stdio --policy <policy> [--network <mode>]` exposes one
  narrow `exec` tool. The host fixes policy and network settings at startup; the
  model cannot widen them.

With `--network proxy`, commands use the injected proxy environment variables;
do not hard-code proxy endpoints or credentials. Runnable clients and examples
are in [`examples/`](examples/). The public protocol and policy contract are
defined in the [RFC repository](https://github.com/runseal-labs/rfcs).

## Runtime limits

The following startup settings are frozen for the process and reported through
`getCapabilities.limits`. Byte values are configured as decimal integers; the
table uses binary KiB/MiB units for readability.

| Environment variable | Default | Range | Controls |
| --- | ---: | ---: | --- |
| `RUNSEAL_MAX_ACTIVE_EXECUTIONS` | 8 | 1–64 | Active executions per connection |
| `RUNSEAL_CLEANUP_TIMEOUT_MS` | 10,000 ms | 100–60,000 ms | Host cleanup deadline |
| `RUNSEAL_REPLAY_EXECUTION_BYTES` | 1 MiB | 64 KiB–64 MiB | Replay retention per execution |
| `RUNSEAL_REPLAY_CONNECTION_BYTES` | 8 MiB | 64 KiB–256 MiB | Replay retention per connection |
| `RUNSEAL_COMPLETED_EXECUTIONS` | 1,024 | 1–65,536 | Retained execution summaries |
| `RUNSEAL_COMPLETED_EXECUTION_BYTES` | 8 MiB | 64 KiB–256 MiB | Summary retention budget |
| `RUNSEAL_AUDIT_CACHE_BYTES` | 8 MiB | 64 KiB–256 MiB | Redacted audit-query cache |
| `RUNSEAL_STREAM_CHUNK_BYTES` | 64 KiB | 8 KiB–64 KiB | Decoded stream chunk limit |
| `RUNSEAL_INPUT_PENDING_BYTES` | 256 KiB | 8 KiB–16 MiB | Pending stdin/control data |
| `RUNSEAL_RPC_FRAME_BYTES` | 1 MiB | 128 KiB–1 MiB | JSON-RPC line limit |
| `RUNSEAL_MAX_OUTPUT_BYTES` | 16 MiB | 1–16,777,216 bytes | Aggregate output per execution |
| `RUNSEAL_SENDER_BYTES` | 8 MiB | 5–64 MiB | Protocol send budget per connection |
| `RUNSEAL_BACKPRESSURE_MS` | 5,000 ms | 100–60,000 ms | No-output-progress grace period |

The replay connection budget must be at least the per-execution budget, and the
pending-input budget must cover one stream chunk. The effective output limit is
part of the normalized policy and its hash; other settings constrain runtime or
transport behavior without changing policy hashes. See the RFCs for
protocol-level semantics.

## Development and conformance

```sh
cargo fmt --check
cargo clippy --tests -- -D warnings
cargo test
```

On a prepared Windows reference host, include sandbox-only cases:

```powershell
cargo test --all-targets -- --include-ignored
```

The Windows smoke check requires an elevated shell (or `-AllowElevation` for
the documented UAC path):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-smoke.ps1
```

On Linux and macOS, run the portable probe smoke after building RunSeal:

```sh
python3 scripts/portable-probe-smoke.py
```

See [`tests/ACCEPTANCE.md`](tests/ACCEPTANCE.md) for the conformance evidence
matrix and [`tests/README.md`](tests/README.md) for test setup and platform
notes. An ignored test is skipped, not passed.

## Further reading

- [Stable execution protocol (RFC-0006)](https://github.com/runseal-labs/rfcs/blob/main/rfcs/0006-stable-execution-protocol.md)
- [Escape definition and adversarial conformance (RFC-0015)](https://github.com/runseal-labs/rfcs/blob/main/rfcs/0015-escape-definition-and-adversarial-conformance.md)
- [Adversarial conformance harness (RFC-0016)](https://github.com/runseal-labs/rfcs/blob/main/rfcs/0016-adversarial-conformance-harness-and-case-format.md)
