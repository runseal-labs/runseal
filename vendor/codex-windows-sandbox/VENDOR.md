# codex-windows-sandbox

Source: `openai/codex`, `codex-rs/windows-sandbox-rs`

Imported commit: `3931bc2bde3e89876da5f96335629c71d635bd72`

The snapshot under `upstream/` is intentionally not a main workspace member.
It is a standalone vendor crate that can be checked directly with local,
trimmed `codex-*` dependency crates under `vendor/`.

Keep local RunSeal changes outside `upstream/` unless they are deliberately
tracked as vendor patches.

Local vendor patches:

- Collapse setup payload, setup marker, and sandbox user secrets to the RunSeal
  single-user schema; guarded by `tests/vendor_boundary.rs`.
- Collapse setup readiness vocabulary from offline/online identities to one
  sandbox identity plus a network guard; guarded by `tests/vendor_boundary.rs`.
- Collapse setup firewall rule names and helper entry points to RunSeal sandbox
  network guard vocabulary; guarded by `tests/vendor_boundary.rs`.
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
- Setup secrets use only a single-user schema such as `{ version, user }`; do
  not add readers or migrations for upstream `offline` and `online` records.
- Setup markers use only one sandbox username field; do not add marker fields
  for upstream offline/online identities.
- Diagnostics and smoke/conformance tests must assert that exactly the expected
  sandbox identity exists and the sandbox group exists before sandboxed
  execution is reported as supported.
- WFP, firewall, proxy, command-runner IPC, restricted-token, and ACL setup must
  all derive from the same single sandbox identity.
- Public protocol, audit, and capability output must keep the account model
  private and expose only generic process and sandbox boundary terms.
