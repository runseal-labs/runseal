# RunSeal conformance tests

These Rust integration tests define the initial public behavior expected from a RunSeal implementation.

They are black-box protocol tests. `cargo test` builds and runs the local binary; use `RUNSEAL_BIN` to point the suite at another candidate implementation:

```bash
RUNSEAL_BIN=/path/to/runseal cargo test --test cli_contract --test protocol_contract --test filesystem_conformance --test adversarial_case_manifest
```

On Windows, the tests serialize shared sandbox setup state internally, so the default `cargo test` path is supported.

Run the suite on Windows before claiming reference-backend readiness. Other
platforms can run the same tests to verify platform selection, experimental
capability gates, and fail-closed behavior until their backends are promoted.

The tests are black-box by design:

- CLI behavior through `runseal exec`.
- Capability reporting through `runseal capabilities` and `getCapabilities`,
  without exposing private Windows account or setup identities.
- Windows hosts select the Windows reference backend and run supported sandbox levels through the shared conformance tests.
- macOS and Linux hosts select explicit experimental/community backends and still fail closed for unsupported sandbox levels.
- Linux hosts report runtime probes but still fail closed for sandboxed policies until promotion.
- Windows sandbox plans include runtime root, synthetic home, setup requirements, protected filesystem categories, process boundary state, and network guard planning.
- Windows filesystem ACL setup must bind rules to a single sandbox user restricted process identity before any rule can be applied.
- Windows single-identity freeze gates cover policy epoch immutability,
  same-policy concurrency, mixed-policy rejection, per-execution runtime
  isolation, process cleanup scope, and legacy dual-user setup artifact
  rejection.
- Windows runtime roots can be reported as a verified single capability without making any sandbox level supported by itself.
- Windows runtime environment redirects can be reported as a verified single capability without making any sandbox level supported by itself.
- Windows process cleanup can be reported as a verified single capability without making any sandbox level supported by itself.
- Windows process cleanup tests verify per-execution Job Object scope and must not terminate unrelated processes.
- Execution results include a `PlatformSandboxPlan` summary for the selected backend.
- Policy explanation through `runseal explain-policy`.
- JSON-RPC behavior through `runseal rpc --stdio`.
- Service-mode JSON-RPC behavior through `runseal service --stdio`,
  including completed execution state, event replay, audit snapshots,
  session disposal, and direct-mode stateless fallback.
- Filesystem, runtime environment, protected workspace metadata, network/proxy,
  and stdin conformance gates accept explicit fail-closed unsupported responses
  now, then require behavior once a backend claims support.
- Conformance fail-closed responses and audit events do not expose private Windows account or setup identities.
- Protocol vocabulary uses `Execution`, not raw process objects.
- Policy denials use stable error codes.
- Standard profiles materialize to canonical policy JSON and stable hashes.
- Events are structured and align with the RFC event model.
- Executions write JSONL audit events under `.runseal/audit/`.
- Policy denials and backend fail-closed decisions also write JSONL audit events.
- `danger-full-access` is explicit local execution with no sandbox guarantee.
- Sandboxed policies fail closed unless a backend can enforce them or explicitly reports an experimental conformance-gated path.

Adversarial conformance follows RFC-0015's escape taxonomy: filesystem,
runtime, process, network, policy, execution injection, and audit. Backend
capabilities may be promoted only when the relevant adversarial cases produce
S0 or S1 outcomes, and public result output remains platform-neutral and
marked public-safe.
RFC-0016 adversarial case manifests live under `adversarial/cases/`; their
public shape and promotion-gate severity rules are validated by
`adversarial_case_manifest`.
