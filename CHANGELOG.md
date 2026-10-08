# RunSeal release notes

## 0.2.0-rc.1 (unreleased candidate)

This candidate implements the accepted `runseal.protocol/v2` contract in RFC-0021.

### Added

- One cancellable Execution lifecycle shared by the CLI, JSON-RPC, service, and narrow MCP adapter.
- Live byte output, streaming stdin, PTY resize/interrupt, a duplex control channel, bounded transport limits, replay, and terminal audit records.
- Explicit execution-gate repair with proof checks for abandoned Windows bindings.

### Fixed

- Fail-closed setup and reservation errors use structured public status and preserve `setup_status` in the terminal audit record.
- Pre-start failures release their reservation when no runner spawn was delivered.
- Windows console output cleanup owns and waits for its forwarding helper.

### Validation status

- RFC-0021 was accepted in `runseal-labs/rfcs` at merge commit `5fe5c5b4b6b8553c58e17f325aa99abc75fda4c0`.
- The package candidate is not tagged or published. Prepared Windows sandbox conformance remains incomplete; do not promote this candidate to a release until the required matrix passes.
