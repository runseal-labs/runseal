# RunSeal conformance tests

These Rust integration tests define the initial public behavior expected from a RunSeal implementation.

They are black-box protocol tests. `cargo test` builds and runs the local binary; use `RUNSEAL_BIN` to point the suite at another candidate implementation:

```bash
RUNSEAL_BIN=/path/to/runseal cargo test --test cli_contract --test protocol_contract
```

The tests are black-box by design:

- CLI behavior through `runseal exec`.
- Capability reporting through `runseal capabilities` and `getCapabilities`.
- Windows hosts select the Windows reference backend scaffold and still fail closed for unsupported sandbox levels.
- Windows fail-closed errors include a `PlatformSandboxPlan` preview for runtime root and synthetic home planning.
- Windows fail-closed setup creates and cleans planned runtime roots before returning unsupported.
- Execution results include a `PlatformSandboxPlan` summary for the selected backend.
- Policy explanation through `runseal explain-policy`.
- JSON-RPC behavior through `runseal rpc --stdio`.
- Filesystem conformance gates that accept explicit fail-closed unsupported responses now, then require behavior once a backend claims support.
- Protected workspace metadata and network conformance gates accept explicit fail-closed unsupported responses now, then require behavior once a backend claims support.
- Protocol vocabulary uses `Execution`, not raw process objects.
- Policy denials use stable error codes.
- Standard profiles materialize to canonical policy JSON and stable hashes.
- Events are structured and align with the RFC event model.
- Executions write JSONL audit events under `.runseal/audit/`.
- Policy denials and backend fail-closed decisions also write JSONL audit events.
- `danger-full-access` is explicit local execution with no sandbox guarantee.
- Sandboxed policies fail closed unless a backend can enforce them.
