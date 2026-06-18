# Agent Rules

This repository is the public Rust implementation of RunSeal.

The public contract lives in `runseal-labs/rfcs`. This repo implements that contract through CLI behavior, JSON-RPC behavior, backend implementations, audit output, and conformance tests.

## Source Of Truth

- Follow the accepted RFCs before inventing behavior.
- When implementation needs to change public protocol, policy shape, event shape, error code, platform status, or conformance semantics, update `runseal-labs/rfcs` first or in the same change.
- Implementation details that do not affect public behavior should stay in this repository.
- Keep README and tests aligned with the current accepted RFCs.
- Treat the current MVP implementation as greenfield. Do not preserve early scaffold behavior, field names, or test expectations for backward compatibility unless an accepted RFC explicitly requires that compatibility.

## Public Terminology And Redaction

Use RunSeal terminology only:

- `RunSeal`
- `Execution`
- `SandboxPolicy`
- `SandboxLevel`
- `NetworkPolicy`
- `BackendCapabilities`
- `SandboxBackend`
- `PlatformSandboxPlan`
- `AuditEvent`
- `runtime root`
- `synthetic home`
- `protected subpath`
- `managed proxy`

Do not include private product names, internal repository names, private issue or MR IDs, customer names, internal codenames, internal filesystem paths, screenshots, logs, or chat-only context in code, tests, docs, comments, fixtures, commit messages, or issue text.

## Implementation Priorities

Work in this order unless an accepted RFC changes it:

1. Minimal buildable CLI/RPC shell.
2. Policy parsing, normalization, profiles, canonical JSON, and policy hashing.
3. Explicit `danger-full-access` local execution with no sandbox guarantee.
4. Audit event writer and execution event streaming.
5. Backend trait and capability reporting.
6. Windows backend scaffolding that fails closed for unsupported capabilities.
7. Windows filesystem enforcement for `read-only`, `workspace-write`, and `workspace-contained`.
8. Windows synthetic home/profile/runtime roots.
9. Windows `network.disabled` and `network.proxy` enforcement.
10. Cleanup, cancellation, setup failure, and repair failure hardening.
11. macOS/Linux backend skeletons that report unsupported or experimental capabilities.

## Windows Reference Backend

- Windows is the MVP reference backend and enterprise security baseline.
- Implement public behavior through platform-neutral traits and RunSeal policy objects.
- Do not expose ACLs, SIDs, token attributes, integrity levels, Job Object handles, firewall rule names, WFP callouts, helper identities, or private profile names as public API.
- Any unsupported or partially enforceable sandbox request must fail closed with a structured error.
- Keep rollback/checkpoint behavior out of the MVP security boundary unless an RFC adds it.

## macOS And Linux

- macOS is experimental until conformance evidence promotes specific capabilities.
- Linux is future/community until a backend is implemented and accepted through conformance evidence.
- Unsupported non-`danger-full-access` requests must return structured unsupported errors, not silently run unrestricted.

## Tests First

- Preserve the black-box contract tests unless the RFC changes first.
- Because the implementation is greenfield, update tests and protocol fixtures to match the correct MVP contract instead of maintaining compatibility with earlier temporary behavior.
- Add conformance tests before broadening backend capability claims.
- Tests should distinguish `supported`, `unsupported`, `experimental`, `denied`, `failed`, and `skipped`.
- `danger-full-access` tests must assert that it is explicit local execution, not sandboxed execution.
- Backend-specific tests should verify behavior rather than implementation details.

## Rust Conventions

- Prefer small modules with explicit data types over ad hoc maps for protocol and policy state.
- Use structured errors with stable public codes.
- Keep public serialization structs stable and versioned.
- Do not log raw secrets, full environments, Authorization headers, cookies, or credential material.
- Avoid shell-string execution by default; prefer argv arrays. Shell mode must be explicit.
- Keep the Rust lint baseline aligned with the local reference implementation style: workspace Clippy denies for common manual/redundant patterns, `expect`/`unwrap` denied outside tests, and Rust 2024 formatting.

## Validation

Before committing:

- Run `cargo fmt --check` when Rust files exist.
- Run `cargo clippy --tests -- -D warnings`.
- Run `cargo test` for contract and unit tests.
- Run `git diff --check`.
- Run `rg -n -i "tailos|tyclaw|myprojects|ferstar|private issue|private MR" .` and ensure matches are only generic redaction guidance or public source URLs.
