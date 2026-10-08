# codex-windows-sandbox

Source: `openai/codex`, `codex-rs/windows-sandbox-rs`

Imported commit: `3931bc2bde3e89876da5f96335629c71d635bd72`

The snapshot under `upstream/` is intentionally not a main workspace member.
It is a standalone vendor crate that can be checked directly with local,
trimmed `codex-*` dependency crates under `vendor/`.

This vendored implementation intentionally diverges from upstream to implement
RunSeal's single sandbox identity model.

Keep local RunSeal changes outside `upstream/` unless they are deliberately
tracked as vendor patches.

Local vendor patches:

- Preserve a failed runner launch's native error before restoring error mode,
  following upstream commit `f35a0fdc5d5fe591fbb2cad7ca6c491c884c3b4b`.
- Adapt upstream job-first termination and control-disconnect cleanup from
  `9b33613db6` and `21c58c90f2298587c6519e077d0692ce4c563d37`. Retain the
  execution-range owner in control workers and keep RunSeal's bounded cleanup
  confirmation and single-identity model. Verify active job membership before
  issuing another termination request, and keep waiting within the cleanup
  deadline when a concurrent termination request is already in flight.
- Replace the legacy workspace-contained finite deny-read ACL path with an
  AppContainer/LowBox execution boundary. The active workspace and runtime
  roots receive only per-execution capability ACLs; setup or spawn failure
  must not fall back to a restricted-token contained mode.
- Keep the AppContainer package, capability names, helper binaries, setup
  task, WFP identities, and diagnostics in the RunSeal namespace.
- Collapse setup payload, setup marker, and sandbox user secrets to the RunSeal
  single-user schema; guarded by `tests/vendor_boundary.rs`.
- Collapse setup readiness vocabulary from offline/online identities to one
  sandbox identity plus a network guard; guarded by `tests/vendor_boundary.rs`.
- Collapse setup firewall rule names and helper entry points to RunSeal sandbox
  network guard vocabulary; guarded by `tests/vendor_boundary.rs`.
- Move persistent WFP provider, sublayer, and filter identities into the
  RunSeal namespace; guarded by `tests/vendor_boundary.rs`.
- Register the scheduled setup broker with a materialized setup helper under
  the sandbox bin directory instead of the helper process launch path; guarded
  by `tests/vendor_boundary.rs`.
- Fail closed through sandbox-bin helper paths when helper materialization
  fails, instead of falling back to host executable locations; guarded by
  `tests/vendor_boundary.rs`.
- Fail closed through the sandbox-bin setup helper path when the setup helper
  source cannot be resolved; guarded by upstream setup tests and
  `tests/vendor_boundary.rs`.
- Lock both workspace and scheduled-broker sandbox bin directories when setup
  materializes helper binaries; guarded by upstream setup helper tests.
- Treat scheduled setup tasks as usable only when their helper command resolves
  under the active broker sandbox bin directory; guarded by upstream setup
  helper tests.
- Treat scheduled setup tasks as usable only when their XML explicitly carries
  the exact broker home in `--task-run` arguments; guarded by upstream setup
  helper tests.
- Expose `scheduled_setup_broker_available` so adapter code can probe the
  scheduled setup broker without reimplementing task/XML matching; guarded by
  upstream setup helper tests.
- Treat scheduled setup broker environment roots as usable only when absolute,
  so task payload/result paths never depend on the caller working directory;
  guarded by upstream setup tests and `tests/vendor_boundary.rs`.
- Treat setup markers as strict single-user network-guard state; missing
  marker fields fail closed instead of defaulting to a stale schema; guarded by
  upstream setup tests and `tests/vendor_boundary.rs`.
- Reject legacy split-identity setup state even when old identity fields are
  nested inside the on-disk state file; guarded by upstream identity tests.
- Replace upstream workspace/git dependency inheritance with local trimmed
  vendor crates; guarded by `tests/vendor_boundary.rs`.
- Classify a cancellation or execution-deadline expiry that happens before the
  runner receives any spawn request as a clean pre-start abort. No runner was
  launched, or the launched runner is terminated and its exit verified, and no
  execution range was created, so a short timeout during sandbox preparation must
  not quarantine the shared binding. Guarded by the sandboxed short-timeout
  regression in `tests/execution_conformance.rs`.
- Allow the first sandbox-user profile load to finish within a bounded
  60-second runner-preparation window; the execution deadline and cancellation
  budget still take precedence. Guarded by the prepared Windows sandbox smoke.
- Keep a runner `spawn_failed` report as a definitive start failure instead of
  rewriting it into unverified cleanup. The runner never created a process range,
  so the host reports a start failure with confirmed cleanup and must not
  quarantine the shared binding. Guarded by the spawn-event regression in
  `tests/execution_conformance.rs`.

## Upstream file patch manifest

The implementation changes below are the complete RunSeal patch set under
`upstream/`, based on the imported commit above. They are limited to the Windows
runner boundary needed for the single-identity model, live I/O, cancellation,
terminal/control support, and confirmed cleanup. RunSeal-level behavior evidence
is in `tests/execution_conformance.rs`; vendor boundary and setup invariants are
in `tests/vendor_boundary.rs`.

| File | RunSeal patch |
|---|---|
| `upstream/Cargo.toml` | Use the trimmed local vendor dependencies and enable the runner interfaces required by RunSeal. |
| `upstream/bin/command_runner/win.rs` | Apply single-identity setup and process ownership; carry bounded input/output and cleanup state across the runner boundary. |
| `upstream/bin/setup_main/win.rs` | Keep setup binary imports and unsafe-code linting consistent with the vendored build. |
| `upstream/conpty/mod.rs` | Preserve explicit process identity, terminal dimensions, interrupt handling, and argv quoting for terminal launches. |
| `upstream/control.rs` | Add the bounded duplex child control endpoint, half-close behavior, and retained writer ownership. |
| `upstream/elevated/ipc_framed.rs` | Validate the v11 runner frame and carry the frozen cleanup budget and deadline. |
| `upstream/elevated/runner_client.rs` | Allow bounded first-profile initialization, retain process ownership, and confirm termination before releasing startup state. |
| `upstream/elevated_impl.rs` | Bridge live stdin/output, cancellation, terminal results, and cleanup evidence between host and runner. |
| `upstream/host_coordinator.rs` | Add the named host coordination event with a restricted access descriptor. |
| `upstream/lib.rs` | Export the cleanup, control, output, and terminal interfaces used by the RunSeal adapter. |
| `upstream/logging.rs` | Keep raw argv and native error text out of vendor logs. |
| `upstream/output_pipe.rs` | Add cancellable native output workers and owned nonblocking pipe handles with confirmed worker exit. |
| `upstream/process.rs` | Track process identity and execution-range ownership through local/elevated launch, terminal/control, and cleanup; verify active membership before requesting termination again. |
| `upstream/unified_exec/backends/elevated.rs` | Wire cancellation and cleanup ownership into the elevated execution backend. |
| `upstream/unified_exec/backends/legacy.rs` | Set explicit default terminal dimensions for the legacy launch path. |
| `upstream/unified_exec/backends/windows_common.rs` | Carry framed runner and output failures to the shared Windows backend. |
| `upstream/winutil.rs` | Normalize argv[0] and quote Windows command-line arguments at the process boundary. |

Prior non-public integrations may be used as pitfall evidence only after
redaction. Land those lessons as public acceptance criteria, adapter behavior,
or conformance tests; do not copy product-specific names, local paths, account
names, logs, screenshots, or chat-only rationale into this repository.

Integration constraint: the upstream setup helper currently models separate
offline and online sandbox users. RunSeal's Windows backend is specified around
one dedicated sandbox user. Adapter code must preserve the public RunSeal policy
shape while replacing or hiding upstream dual-user assumptions at the vendored
boundary.

Single-user vendor wiring acceptance criteria:

- Setup payloads carry one sandbox identity, not separate offline and online
  identities.
- Setup secrets use only a single-user schema such as `{ version, user }`; do not add readers or migrations for upstream `offline` and `online` records.
- Setup markers use only one sandbox username field and require explicit
  network-guard fields; do not add marker fields for upstream offline/online
  identities.
- Diagnostics and smoke/conformance tests must assert that exactly the expected
  sandbox identity exists and the sandbox group exists before sandboxed
  execution is reported as supported.
- WFP, firewall, proxy, command-runner IPC, restricted-token, and ACL setup must
  all derive from the same single sandbox identity.
- Public protocol, audit, and capability output must keep the account model private and expose only generic process and sandbox boundary terms.

RunSeal's local native output worker joins and retained-worker reaping require
confirmed Windows thread termination. Rust function completion alone cannot prove
native exit callbacks finished. RunSeal native FLS fixtures reproduce that gap
in the general reaper and in output poll, flush, finish, Drop, and retained-worker
reaping after a real pipe write. Console and complete frontend fault injection
remain separate acceptance work.

The duplex control output-close owner follows the same native exit rule. Shared
endpoint clones preserve the earliest close deadline, and polling releases the
state mutex so another clone can shorten that deadline. A failed or expired
close retains its worker through the last endpoint's Drop; reaping joins only
after native exit. The focused fixture runs the actual socket half-close, then
holds its native FLS exit callback. This proves close ownership and deadline
handling, not the complete helper or sandbox cleanup matrix.

Internal runner IPC v11 carries a mandatory cleanup budget validated at frame
decode. RunSeal passes the frozen host setting through its capture token, including
capture without an output sink; querying that budget does not start cleanup.
The runner selects it before process creation and preserves the earliest absolute
deadline on natural exit, disconnect, and explicit termination. Native wait-only
process fixtures cover configured expiry without claiming successful termination.
Full sandbox capture under nondefault budgets remains an acceptance requirement.
