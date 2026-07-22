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
