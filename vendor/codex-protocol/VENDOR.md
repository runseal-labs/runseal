# codex-protocol

Source: `openai/codex`, `codex-rs/windows-sandbox-rs`

Vendored permission-profile models shared by the Windows sandbox crate.

Local vendor patches:

- `get_writable_roots_with_cwd` no longer records a read entry that equals the
  writable root itself as a `read_only_subpath`. A policy that grants both Read
  and Write on the workspace root (e.g. RunSeal `workspace-contained`) was
  resolved as "workspace root is a read-only subpath of itself", which pushed the
  root into `deny_write_paths` and made setup deny writes to the root.
