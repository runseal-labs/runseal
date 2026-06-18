# codex-windows-sandbox

Source: `openai/codex`, `codex-rs/windows-sandbox-rs`

Imported commit: `3931bc2bde3e89876da5f96335629c71d635bd72`

The snapshot under `upstream/` is intentionally not a workspace member yet.
RunSeal should first adapt its public `SandboxPolicy`, `PlatformSandboxPlan`,
audit, and conformance layers around this upstream boundary, then wire the
vendored crate into the build when the adapter is ready.

Keep local RunSeal changes outside `upstream/` unless they are deliberately
tracked as vendor patches.

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
- Setup secrets use a single-user schema such as `{ version, user }`; legacy
  `offline` and `online` records must be treated as stale state.
- Setup markers use one sandbox username field; legacy offline/online marker
  fields must not be accepted as ready state.
- Diagnostics and smoke/conformance tests must assert that exactly the expected
  sandbox identity exists, the sandbox group exists, and legacy dual-user state
  is absent before sandboxed execution is reported as supported.
- WFP, firewall, proxy, command-runner IPC, restricted-token, and ACL setup must
  all derive from the same single sandbox identity.
- Public protocol, audit, and capability output must keep the account model
  private and expose only generic process and sandbox boundary terms.
