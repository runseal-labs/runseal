# RunSeal release notes

## 0.2.1 (2026-10-23)

This version is prepared for release. This entry does not claim that a `v0.2.1`
tag, draft, or downloadable asset already exists; publication is a separate,
reviewed step.

### Compatibility

- `runseal.protocol/v2` and `runseal.policy/v1` are unchanged from 0.2.0.
- 0.2.1 includes the RFC-0022 native control and terminal-identity contract
  added after the `v0.2.0` tag (commits `3a1a74b` and `ee871b0`). The `v0.2.0`
  tag and its draft assets predate that contract; clients that require
  configurable control descriptors, the reported child PID, interrupt delivery
  receipts, or native async pipe semantics must require 0.2.1 or later. The
  0.1.x line remains protocol v1 and is not compatible with v2 clients.

### Added

- RFC-0022 control-descriptor selection: RPC pipe control accepts an explicit
  child descriptor from 3 to 255; the CLI uses descriptor 3.
- Native terminal identity and byte-pipe behavior: startup reports the real
  child PID; interrupt acceptance includes a sequence and
  `execution.signal_delivered` confirms the native Ctrl-C write to the
  identified Windows console root; resize replies acknowledge acceptance only.
- Control mode `pipe` exposes native asynchronous byte I/O (input close seals
  writes without peer EOF); `socket` exposes CRT byte I/O with independent
  half-close.

### Release engineering

- Package version, Cargo lock entry, CLI output, changelog heading, and release
  tag are checked for consistency before a release is built.
- Release assets use the stable per-platform naming contract and per-asset
  SHA-256 files documented in [`RELEASING.md`](RELEASING.md).
- Stable releases are marked latest; SemVer prereleases are marked prerelease
  and are never marked latest.
- The release workflow refuses to overwrite assets on an already published
  release or on a draft that already has assets.

## 0.2.0 (2026-10-23)

This release implements the accepted `runseal.protocol/v2` contract in
[RFC-0021](https://github.com/runseal-labs/rfcs/blob/main/rfcs/0021-realtime-execution-protocol-v2.md).

### Breaking protocol changes

- The protocol changes from `runseal.protocol/v1` in 0.1.x to `runseal.protocol/v2`.
  Clients must support v2 before upgrading; there is no v1 compatibility mode or
  automatic downgrade. The `runseal.policy/v1` schema remains unchanged.
- `execute` returns a `preparing` admission receipt. Clients consume live events
  and query the Execution for its final result instead of treating that receipt
  as completed execution or proof that the command has started.
- Cancellation returns a `canceling` receipt. Only the terminal result with
  `cleanup_complete: true` proves that the owned execution range was cleaned up.
- Capability decisions use the reported execution profiles and limits for the
  requested sandbox, network, and I/O combination. Portable backends remain
  experimental and fail closed for unsupported combinations.

### Added

- One cancellable Execution lifecycle shared by the CLI, JSON-RPC, service, and narrow MCP adapter.
- Live byte output, streaming stdin, PTY resize/interrupt, a duplex control channel, bounded transport limits, replay, and terminal audit records.
- Explicit execution-gate repair with proof checks for abandoned Windows bindings.

### Fixed

- Fail-closed setup and reservation errors use structured public status and preserve `setup_status` in the terminal audit record.
- Pre-start failures release their reservation when no runner spawn was delivered.
- Windows Console output cleanup bounds helper-process and feeder-thread waits
  by the shared deadline, retains unconfirmed native owners, and avoids another
  diagnostic write after delivery has failed.

### Validation

- RFC-0021 was accepted in `runseal-labs/rfcs` at merge commit `5fe5c5b4b6b8553c58e17f325aa99abc75fda4c0`.
- The [three-platform CI matrix](https://github.com/runseal-labs/runseal/actions/runs/39858559608)
  passed, including the prepared Windows sandbox conformance and third-party
  examples. The original stalled-Console case and the native-exit deadline
  regression passed in Windows CI.
- Local Windows prepared validation passed 479 tests, excluding two tests that
  require an elevated token; those checks passed in CI. Local macOS passed 352
  tests and the portable smoke checks.
