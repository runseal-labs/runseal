# codex-windows-sandbox

Source: `openai/codex`, `codex-rs/windows-sandbox-rs`

Imported commit: `3931bc2bde3e89876da5f96335629c71d635bd72`

The snapshot under `upstream/` is intentionally not a workspace member yet.
RunSeal should first adapt its public `SandboxPolicy`, `PlatformSandboxPlan`,
audit, and conformance layers around this upstream boundary, then wire the
vendored crate into the build when the adapter is ready.

Keep local RunSeal changes outside `upstream/` unless they are deliberately
tracked as vendor patches.

Integration constraint: the upstream setup helper currently models separate
offline and online sandbox users. RunSeal's Windows backend is specified around
one dedicated sandbox user. Adapter code must preserve the public RunSeal policy
shape while replacing or hiding upstream dual-user assumptions at the vendored
boundary.
