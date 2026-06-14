# RunSeal

RunSeal is a Codex-style, OS-native sandbox layer for AI agents.

It exposes a stable execution protocol for running local commands inside policy-governed filesystem, process, resource, and network boundaries. Enterprise network access is expected to go through a controlled proxy that can enforce routes, inject authentication at the boundary, redact sensitive data, and emit structured audit events.

RunSeal is **not** a cloud VM sandbox, a Docker Desktop replacement, or a microVM platform. It is a local-first execution boundary for agent frameworks.

## Status

Pre-implementation. This repository starts with conformance tests and protocol fixtures before runtime code.

The design lives in the RFC repository:

- https://github.com/runseal-labs/rfcs
- Protocol draft: https://github.com/runseal-labs/rfcs/blob/main/rfcs/0006-stable-execution-protocol.md

## Development principle

Tests first.

The initial test suite is intentionally black-box and protocol-oriented. Runtime implementation should make these tests pass without changing their behavioral assertions unless the RFC changes first.

## Intended CLI

```bash
runseal exec --policy workspace-proxy -- python skill.py
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
    "policy": "workspace-proxy"
  }
}
```

## Running tests

The conformance tests are Rust integration tests. They expect a future RunSeal binary path through `RUNSEAL_BIN`:

```bash
cargo test
```

Until an implementation exists, most CLI/protocol tests should fail with a clear missing-binary error. That is the current RED state.

To run with an implementation:

```bash
RUNSEAL_BIN=target/debug/runseal cargo test
```

## Non-goals

- No Docker daemon dependency.
- No unmanaged direct network access as an enterprise default.
- No direct secret injection into sandboxed processes.
- No cloud multi-tenant sandbox control plane in the core runtime.
- No claim that OS-native sandboxing prevents every kernel-level escape.
