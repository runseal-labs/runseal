# RunSeal conformance tests

These Rust integration tests define the initial public behavior expected from a RunSeal implementation.

They are black-box protocol tests. `cargo test` builds and runs the local binary; use `RUNSEAL_BIN` to point the suite at another candidate implementation:

```bash
RUNSEAL_BIN=/path/to/runseal cargo test --test cli_contract --test protocol_contract
```

CI runs the suite on Linux and Windows so platform selection, fail-closed behavior, and the Windows reference backend scaffold stay buildable before any capability is promoted.

The tests are black-box by design:

- CLI behavior through `runseal exec`.
- Capability reporting through `runseal capabilities` and `getCapabilities`.
- Windows hosts select the Windows reference backend scaffold and still fail closed for unsupported sandbox levels.
- macOS and Linux hosts select explicit experimental/community skeleton backends and still fail closed for unsupported sandbox levels.
- Windows fail-closed errors include a `PlatformSandboxPlan` preview for runtime root, synthetic home, setup requirements, protected filesystem categories, process boundary state, and network guard planning.
- Windows fail-closed setup creates and cleans planned runtime roots before returning unsupported.
- Windows fail-closed cleanup goes through a single sandbox setup cleanup path so future filesystem rollback cannot be skipped.
- Windows sandbox setup cleanup carries the setup-time filesystem rollback state through cleanup.
- Windows filesystem ACL setup must bind rules to a single sandbox user restricted process identity before any rule can be applied.
- Windows runtime roots can be reported as a verified single capability without making any sandbox level supported by itself.
- Windows runtime environment redirects can be reported as a verified single capability without making any sandbox level supported by itself.
- Windows process cleanup can be reported as a verified single capability without making any sandbox level supported by itself.
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
