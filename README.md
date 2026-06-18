# RunSeal

RunSeal is a Codex-style, OS-native sandbox layer for AI agents.

It exposes a stable execution protocol for running local commands inside policy-governed filesystem, process, resource, and network boundaries. Enterprise network access is expected to go through a controlled proxy that can enforce routes, inject authentication at the boundary, redact sensitive data, and emit structured audit events.

RunSeal is **not** a cloud VM sandbox, a Docker Desktop replacement, or a microVM platform. It is a local-first execution boundary for agent frameworks.

## Status

Phase 0 implementation with the first Phase 1/2 foundations. The repository contains a buildable CLI/RPC shell, standard policy profile normalization, canonical policy hashes, backend capability reporting, Windows reference backend scaffolding, `PlatformSandboxPlan` summaries, JSONL audit output, and black-box conformance tests.

Current execution support is intentionally narrow: only explicit `danger-full-access` runs as local, non-sandboxed execution. Sandboxed policies such as `read-only`, `workspace-contained`, and `workspace-write` must fail closed until a platform backend can enforce them.

On Windows, fail-closed sandbox requests include a `PlatformSandboxPlan` preview for runtime root, synthetic home, profile root, temp root, setup requirements, protected filesystem categories, process boundary state, network guard state, and policy path planning. Runtime root creation/cleanup, runtime environment redirects, and process cleanup are backed by verified Windows paths, but sandboxed policies remain unsupported until every required filesystem, process isolation, and network capability is implemented and covered by conformance tests.

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
