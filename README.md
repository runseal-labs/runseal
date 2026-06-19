# RunSeal

RunSeal is an OS-native sandbox layer for AI agents.

It exposes a stable execution protocol for running local commands inside policy-governed filesystem, process, resource, and network boundaries. Enterprise network access is expected to go through a controlled proxy that can enforce routes, inject authentication at the boundary, redact sensitive data, and emit structured audit events.

RunSeal is **not** a cloud VM sandbox, a Docker Desktop replacement, or a microVM platform. It is a local-first execution boundary for agent frameworks.

## Status

Phase 0 implementation with the first Phase 1/2 foundations. The repository contains a buildable CLI/RPC shell, standard policy profile normalization, canonical policy hashes, backend capability reporting, a Windows reference backend, `PlatformSandboxPlan` summaries, JSONL audit output, and black-box conformance tests.

Current execution support is intentionally narrow: explicit `danger-full-access` runs as local, non-sandboxed execution. On Windows, sandboxed policies such as `read-only`, `workspace-contained`, and `workspace-write` execute through the reference backend. Other platforms still fail closed for sandboxed policies until a backend can enforce them.

On Windows, sandbox requests include a `PlatformSandboxPlan` for runtime root, synthetic home, profile root, temp root, setup requirements, protected filesystem categories, process boundary state, network guard state, and policy path planning. Runtime root creation/cleanup, runtime environment redirects, process cleanup, filesystem enforcement, process isolation, and direct network deny/proxy guard enforcement are covered by the Windows reference path.

The Windows enforcement baseline lives behind a dedicated Windows sandbox implementation. RunSeal-specific code should stay at the adapter layer: policy normalization, `PlatformSandboxPlan` mapping, audit events, capability reporting, and conformance gates. Low-level OS boundary, setup-helper, and command-runner code should not be reimplemented in the RunSeal adapter.

On macOS and Linux, RunSeal reports explicit experimental/community skeleton backends. They support only explicit `danger-full-access` local execution until contributed backend implementations pass the shared conformance gates.

The design lives in the RFC repository:

- https://github.com/runseal-labs/rfcs
- Protocol draft: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0006-stable-execution-protocol.md

## Development principle

Tests first.

The initial test suite is intentionally black-box and protocol-oriented. Runtime implementation should make these tests pass without changing their behavioral assertions unless the RFC changes first.

## Intended CLI

```bash
runseal exec --policy workspace-write --network proxy -- python skill.py
runseal explain-policy --policy workspace-write --network proxy
runseal capabilities
```

For the Phase 0 local execution baseline:

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
`can_repair`, `can_run_setup_now`, `requires_setup`, and `next_action`. The
same `setup_status` object is included in sandboxed execution
`BACKEND_UNAVAILABLE` errors when setup is missing or stale, and in the matching
`execution.failed` audit event.
`runseal capabilities` also includes this `setup_status` object so support
claims and local readiness can be checked from one response.
`runseal explain-policy` includes it alongside policy support for the requested
workspace.
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

## Running tests

The conformance tests are Rust integration tests. `cargo test` builds and runs the local `runseal` binary.

```bash
cargo fmt --check
cargo clippy --tests -- -D warnings
cargo test
```

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
