# RFC-0021 execution acceptance evidence

This matrix maps every RFC-0021 acceptance criterion (AC01-28) to the black-box
evidence in this repository. It records the test location, the command, the
platform and mode, the expected observable behavior, and the actual result.

Candidate validation results for this revision are recorded after the matrix.

Reproduce a single row with the command in the "Command" column. Windows rows
that require sandbox enforcement need a prepared sandbox identity. Those tests
are marked ignored on generic Windows hosts; ignored cases are skipped, not
passing evidence. Run the full matrix on a prepared Windows reference host with
`cargo test --all-targets -- --include-ignored`. Portable rows run anywhere.

| AC | Scenario | Test location | Command | Platform / mode | Expected | Actual |
|---|---|---|---|---|---|---|
| 01 | READY before input, then exit | `execution_conformance::stream_round_trips`, `local_stream_stdin_three_round_trips_and_ordered_eof`, `windows_sandboxed_stream_stdin_three_round_trips_and_ordered_eof` | `cargo test --test execution_conformance stream_round_trips` | Windows + portable / RPC service | READY observed before any input write; no natural-exit shortcut | portable/local and prepared Windows sandbox stream cases passed in the partial prepared run |
| 02 | getVersion/getExecution during a long run | `execution_conformance::rpc_and_service_query_and_cancel_while_execution_is_running` | `cargo test --test execution_conformance rpc_and_service_query_and_cancel_while_execution_is_running` | Windows / RPC + service | response before the gate releases; preparing/running observed | pass |
| 03 | active execution cancel | `execution_conformance::windows_sandboxed_rpc_and_service_active_cancellation`, `cli_console_cancellation_cleans_range_and_preserves_peer_in_each_output_mode`, `windows_natural_exit_and_cancel_clear_descendants_without_stopping_peer`, `windows_node_client_round_trips_inside_sandbox` | `cargo test --test execution_conformance windows_sandboxed_rpc_and_service_active_cancellation` | Windows / RPC, service, CLI, Node consumer | acceptance then exactly one cancel terminal; process range cleared | local, prepared sandbox cancellation, and sandboxed Node cases passed in the partial prepared run |
| 04 | cancel during preparing | `execution_conformance::preparing_timeout_commits_before_blocked_native_receipt_and_never_launches_after_drain`, `windows_preparation_timeout_aborts_cleanly_without_quarantining_the_binding` | `cargo test --test execution_conformance preparing_timeout_commits_before_blocked_native_receipt_and_never_launches_after_drain` | Windows / RPC + real backend | cancel does not launch the target; startup/cancel race stays consistent | portable and prepared Windows backend cases passed in the partial prepared run |
| 05 | waiting-input and busy-output | `windows_unread_stream_input_does_not_block_cancellation`, `configured_backpressure_grace_cleans_unread_rpc_output_and_keeps_idle_connection_live`, `stalled_protocol_writer_cleans_owned_execution_and_closes_connection`, `cli_stdio_stalled_or_disconnected_caller_cleans_owned_range_and_preserves_peer`, `sandboxed_stalled_console_output_cleans_owned_range_and_preserves_peer` | `cargo test --test execution_conformance` (generic Windows); `cargo test --test execution_conformance -- --include-ignored` (prepared Windows) | Windows / RPC, service, CLI | all targets end within the cleanup deadline; a timeout reports cleanup_failed and never false-passes | all listed local and prepared cases passed in the partial prepared run, including the sandboxed stalled-console review case; full matrix had one unrelated history-test timeout |
| 06 | top-level shell exits, descendants survive | `windows_local_execution_clears_descendants_without_stopping_peer`, `windows_natural_exit_and_cancel_clear_descendants_without_stopping_peer`, `windows_timeout_clears_descendant_range_and_retains_timeout_cause` | `cargo test --test execution_conformance windows_local_execution_clears_descendants_without_stopping_peer` | Windows / RPC + CLI | descendant heartbeat stops; no continued writes; whole range verified | pass |
| 07 | concurrent A/B isolation | `execution_conformance::windows_ac07_cancelling_execution_a_keeps_execution_b_live_and_bound`, `execution_conformance::portable_local_execution_cleans_process_groups_on_exit_and_cancel` | Windows: `cargo test --test execution_conformance windows_ac07_cancelling_execution_a_keeps_execution_b_live_and_bound`; Linux: `cargo test --test execution_conformance portable_local_execution_cleans_process_groups_on_exit_and_cancel` | Windows / service; Linux / service | A exits or is canceled and its process range is gone; B remains running, keeps its policy hash/epoch, responds to `getExecution`, and continues its heartbeat | WSL2 portable A/B case and prepared Windows binding case passed |
| 08 | bytes/file/empty stdin | `sandboxed_binary_bytes_file_and_empty_stdin_deliver_exact_bytes_then_eof` | `cargo test --test execution_conformance sandboxed_binary_bytes_file_and_empty_stdin_deliver_exact_bytes_then_eof` | Windows sandboxed / RPC | exact binary echo and EOF for empty, NUL, large, and cross-chunk input | prepared Windows sandboxed case passed in the partial prepared run |
| 09 | bidirectional stdio round trips | `windows_sandboxed_stream_stdin_three_round_trips_and_ordered_eof`, `cli_control_fd3_forwards_binary_rounds_and_half_close_with_separate_stdio` | `cargo test --test execution_conformance windows_sandboxed_stream_stdin_three_round_trips_and_ordered_eof` | Windows sandboxed / RPC + CLI | three request/response rounds, then an explicit close | prepared Windows sandboxed stream case passed; local CLI control case passed |
| 10 | close/write race | `local_stream_stdin_three_round_trips_and_ordered_eof`, `tiny_input_writes_preserve_binary_order_eof_and_backpressure_on_native_streams` | `cargo test --test execution_conformance tiny_input_writes_preserve_binary_order_eof_and_backpressure_on_native_streams` | portable / RPC | deterministic acceptance order, queued bytes preserved, stable close rejection and idempotent close | pass |
| 11 | output correctness | `cli_native_file_output_preserves_binary_streams_and_child_exit`, `sandboxed_pty_has_real_console_dimensions_and_merged_binary_events`, `cli_console_output_preserves_unicode_without_changing_caller_code_page` | `cargo test --test execution_conformance cli_native_file_output_preserves_binary_streams_and_child_exit` | Windows / CLI + RPC | stdout/stderr bytes and offsets match; split UTF-8, non-UTF-8, and NUL survive | local binary-file and prepared sandbox PTY output cases passed in the partial prepared run |
| 12 | CLI exit and stderr | `configured_output_cap_plain_cli_preserves_child_exit_or_reports_resource_failure`, `partial_cli_json_delivery_does_not_retry_or_append_an_error_frame`, `cli_plain_console_inherit_delivers_unicode_and_stops_on_partial_input_exit` | `cargo test --test execution_conformance configured_output_cap_plain_cli_preserves_child_exit_or_reports_resource_failure` | Windows / plain, JSON | child 0/7/125 and stderr-only forwarded; outer status separated from child exit | generic output/JSON and Windows console inheritance cases passed in the partial prepared run |
| 13 | CLI pipe transparency | `cli_stdio_stalled_or_disconnected_caller_cleans_owned_range_and_preserves_peer`, `cli_pty_forwards_real_console_input_resize_and_restores_modes` | `cargo test --test execution_conformance cli_stdio_stalled_or_disconnected_caller_cleans_owned_range_and_preserves_peer` | Windows / plain | no banner pollution; input reaches the child; early child exit does not wedge the wrapper | both Windows CLI pipe and PTY cases passed in the partial prepared run |
| 14 | PTY | `sandboxed_pty_has_real_console_dimensions_and_merged_binary_events`, `pty_interrupt_stops_foreground_task_and_keeps_shell_and_peer_alive`, `cli_pty_forwards_real_console_input_resize_and_restores_modes`, `windows_node_client_round_trips_inside_sandbox` | `cargo test --test execution_conformance sandboxed_pty_has_real_console_dimensions_and_merged_binary_events` | Windows / RPC + CLI + Node consumer | real terminal, retained cwd/env, observable resize, interrupt keeps the shell, cancel clears the range | prepared Windows sandbox PTY and Node cases passed in the partial prepared run |
| 15 | control channel | `cli_control_fd3_forwards_binary_rounds_and_half_close_with_separate_stdio`, `rpc_control_fd3_three_binary_rounds_and_half_close_preserve_streams_and_audit`, `windows_native_control_fd3_is_duplex_binary_and_half_closeable`, `rpc_control_remains_live_with_blocked_stdin_and_cancels_after_control_backpressure`, `windows_node_client_round_trips_inside_sandbox` | `cargo test --test execution_conformance rpc_control_fd3_three_binary_rounds_and_half_close_preserve_streams_and_audit` | Windows / CLI + RPC + Node consumer | fd 3 duplex binary rounds and half-close without mixing stdio; unsupported combinations rejected before start | local fd3, prepared Windows native fd3, and sandboxed Node cases passed in the partial prepared run |
| 16 | same-policy concurrency | `configured_active_execution_limit_refuses_an_extra_target_while_controls_stay_live`, `cross_process_policy_gate_survives_caller_appdata_override_and_accepts_after_drain` | `cargo test --test execution_conformance configured_active_execution_limit_refuses_an_extra_target_while_controls_stay_live` | Windows / service | two executions share the binding with isolated resources; one cleanup does not revoke shared constraints | generic active-limit and prepared Windows shared-binding cases passed in the partial prepared run |
| 17 | cross-policy / cross-workspace | `cross_process_policy_gate_survives_caller_appdata_override_and_accepts_after_drain` | `cargo test --test execution_conformance cross_process_policy_gate_survives_caller_appdata_override_and_accepts_after_drain` | Windows / service | a transition is refused with POLICY_TRANSITION_BUSY and no side effects | prepared Windows cross-process sandbox case passed in the partial prepared run |
| 18 | admission after drain | `cross_process_policy_gate_survives_caller_appdata_override_and_accepts_after_drain` | `cargo test --test execution_conformance cross_process_policy_gate_survives_caller_appdata_override_and_accepts_after_drain` | Windows / service | new policy admitted after full cleanup; policy_hash/epoch stay constant per execution | prepared Windows cross-process admission case passed in the partial prepared run |
| 19 | network constraints | `filesystem_conformance::network_proxy_blocks_direct_egress_when_supported_or_fails_closed` | `cargo test --test filesystem_conformance network_proxy_blocks_direct_egress_when_supported_or_fails_closed` | Windows / CLI + RPC | disabled blocks direct egress; proxy stays controlled; unsupported combinations do not start | latest non-elevated Windows filesystem suite passed 17/17 after extending two proxy probe startup budgets; prepared network enforcement remains unverified |
| 20 | unsubscribe/resubscribe | `unsubscribe_discards_already_queued_notifications_before_its_receipt`, `sandboxed_unsubscribe_discards_already_queued_notifications_before_its_receipt`, `unsubscribe_replay_and_replacement_are_ordered_without_duplicate_delivery`, `evicted_history_is_reported_and_audit_queries_exclude_live_payloads`, `configured_connection_replay_budget_evicts_old_history_without_erasing_terminal_or_audit` | `cargo test --test execution_conformance unsubscribe_replay_and_replacement_are_ordered_without_duplicate_delivery` | Windows / local and sandboxed service | cursor replay joins the live tail without gaps or duplicates; a gap is explicit; unsubscribing does not stop the execution | latest non-elevated Windows execution suite passed; prepared sandbox unsubscribe passed; the prepared full run had one history-test watchdog failure, followed by four isolated passes |
| 21 | output/input/record limits | `configured_chunks_refuse_one_extra_byte_and_preserve_binary_output_offsets`, `configured_output_cap_matches_effective_policy_hash_and_real_execution_boundaries`, `configured_output_cap_counts_native_control_and_terminal_streams`, `configured_sender_budget_backpressures_real_output_without_blocking_cancel`, `configured_pending_budget_refuses_unread_input_then_drains_every_accepted_byte`, `configured_rpc_frame_boundary_drains_oversize_without_starting_target_or_stopping_peer`, `configured_frame_snapshot_retains_newest_records_and_keeps_connection_live`, `configured_summary_and_audit_retention_preserves_active_targets_and_durable_terminals` | `cargo test --test execution_conformance configured_output_cap_matches_effective_policy_hash_and_real_execution_boundaries` | Windows / RPC + service + CLI | boundary, one-over, tiny chunks, large chunks, and concurrency stay bounded with no deadlock and no hidden truncation | pass |
| 22 | slow consumer, disconnect, host death | `stalled_protocol_writer_cleans_owned_execution_and_closes_connection`, `sandboxed_stalled_protocol_writer_cleans_owned_execution_and_closes_connection`, `paused_protocol_reader_does_not_prevent_cancellation`, `sandboxed_paused_protocol_reader_does_not_prevent_cancellation`, `dropping_protocol_fixture_drains_live_execution_before_host_exit`, `windows_local_host_death_clears_its_range_and_preserves_other_connection`, `cli_stdio_stalled_or_disconnected_caller_cleans_owned_range_and_preserves_peer`, `cli_control_stalled_caller_cleans_owned_range_and_preserves_peer` | `cargo test --test execution_conformance windows_local_host_death_clears_its_range_and_preserves_other_connection` | Windows / local and sandboxed service + CLI | the affected execution is cleaned while an independent connection or process is unharmed | portable, Windows local host-death, and prepared sandboxed writer/reader cases passed in the partial prepared run |
| 23 | timeout/cancel/natural-exit race | `windows_timeout_clears_descendant_range_and_retains_timeout_cause`, `windows_natural_exit_and_cancel_clear_descendants_without_stopping_peer`, `local_completion_drains_output_with_foreign_pipe_handles_without_stopping_peer` | `cargo test --test execution_conformance windows_timeout_clears_descendant_range_and_retains_timeout_cause` | Windows / RPC + CLI | exactly one terminal and one cleanup with the defined cause | portable and Windows local cases pass; prepared sandboxed timeout case pending |
| 24 | setup/spawn/cleanup/audit failure | `windows_spawn_failure_keeps_raw_backend_diagnostics_out_of_audit`, `required_audit_failure_rejects_before_receipt_and_child_spawn`, `invalid_deployment_limit_is_rejected_without_target_or_config_value_disclosure`, `sandboxed_workspace_cannot_cover_protected_execution_state`, `windows_preparation_timeout_aborts_cleanly_without_quarantining_the_binding` | `cargo test --test execution_conformance windows_spawn_failure_keeps_raw_backend_diagnostics_out_of_audit` | Windows / RPC + CLI | whether the command ran is observable; a cleanup failure never claims success, releases unsafe shared state, or silently reuses it | all listed portable, generic, and prepared Windows spawn/protected-state cases passed in the partial prepared run |
| 25 | audit and data safety | `live_event_sequence_and_unique_terminal_match_committed_audit`, `evicted_history_is_reported_and_audit_queries_exclude_live_payloads`, protocol_contract audit assertions, `assert_no_private_windows_setup_terms` | `cargo test --test execution_conformance live_event_sequence_and_unique_terminal_match_committed_audit` | Windows / RPC + service + CLI | canaries never appear in JSONL, audit queries, errors, or summaries; authorized live output stays distinct from default audit content | live audit and protocol checks passed; the history-eviction case passed in the latest full non-elevated Windows execution suite and four isolated reruns, after one prepared full-run watchdog failure |
| 26 | capability consistency | `execution_conformance::execution_capability_profiles_match_live_supported_and_rejected_behavior`, `protocol_contract::execution_capability_profiles_are_complete_and_consistent` | `cargo test --test execution_conformance execution_capability_profiles_match_live_supported_and_rejected_behavior` | Windows + portable / all | every reported supported profile runs the target and completes cleanly; unsupported/unavailable/setup-required profiles fail before admission; portable experimental claims are not counted as supported | all 24 profile rows passed live Windows supported/rejected checks in both the standalone and full non-elevated execution suite; prepared profile checks also passed |
| 27 | narrow MCP adapter regression | `mcp_contract` suite | `cargo test --test mcp_contract` | Windows / MCP | the model cannot widen the fixed policy/network; request, failure, cancel, and resource-close behavior matches the shared engine | pass |
| 28 | plain/RPC/service parity | `partial_cli_json_delivery_does_not_retry_or_append_an_error_frame`, `cli_native_file_output_preserves_binary_streams_and_child_exit`, `rpc_and_service_query_and_cancel_while_execution_is_running`, `activity_query_and_cancel` | `cargo test --test execution_conformance rpc_and_service_query_and_cancel_while_execution_is_running` | Windows / plain + RPC + service | identical argv/policy produce the same side effects, child exit, and effective limits; only presentation differs | local parity and prepared Windows service cancellation cases passed; separate sandboxed parity evidence remains pending |

## Platform notes

- Windows sandboxed rows require a prepared sandbox identity. Run
  `scripts/build-windows.ps1` once, then inspect setup and execution-gate state.
  The proof-gated repair must run from an elevated Administrator token so it
  can enumerate every Windows session. If complete process inspection is
  unavailable, repair stays closed and the sandboxed rows remain pending.
  Run the ignored read-only
  `windows::processes::tests::live_process_census_enumerates_every_session_without_unknown_owners`
  case with `--include-ignored` on that host before counting repair evidence.
  Never use `--accept-unverified-release` as routine test preparation. If the
  gate is stale or quarantined, use only the proof-gated default repair after
  confirming recorded owners are gone and obtaining authorization for that
  host-level state change. If ownership cannot be verified, stop and record the
  sandboxed cases as pending.
- Generic Windows CI marks sandboxed conformance cases as ignored because its
  runner has no prepared identity. Run `cargo test --all-targets -- --include-ignored`
  on a prepared Windows reference host; ignored results do not satisfy an AC.
- Portable rows report `unsupported` or `experimental` for Windows-only
  capabilities and fail closed rather than running unrestricted.
- `danger-full-access` rows assert explicit local execution, not a sandbox.

## Historical candidate evidence at `7a7c2de`

Candidate package version: `0.2.0-rc.1` (unreleased).

Candidate source revision: `7a7c2de5f7cc9e48f91e7576b7b461df68f86842`.

Accepted RFC revision: `runseal-labs/rfcs@5fe5c5b4b6b8553c58e17f325aa99abc75fda4c0`.

- WSL2 Linux at `7a7c2de`: `cargo fmt --check`,
  `cargo clippy --tests -- -D warnings`, `cargo test --all-targets --quiet`, and
  `python3 scripts/portable-probe-smoke.py` passed. The Rust suites reported
  352 passed, 0 failed, and 0 ignored; the portable probe reported success.
- AC07 direct evidence at `7a7c2de`:
  `cargo test --test execution_conformance portable_local_execution_cleans_process_groups_on_exit_and_cancel -- --exact`
  passed in WSL2. The test starts A and B, cancels A, verifies A's descendant
  is gone, and verifies B remains alive and continues its heartbeat. Baseline
  `001b0dd6c833bf58586a276b375b8658291b5a6a` contains no direct AC07 test.
  This proves portable local process isolation; it does not prove the Windows
  sandbox binding, runtime-root, or proxy-lease behavior in AC07.
- Windows local checks at `7a7c2de`: `cargo fmt --check`,
  `cargo clippy --locked --tests -- -D warnings`, `cargo test --locked --lib`
  (215 passed), and
  `cargo test --test execution_conformance configured_output_cap_plain_cli_preserves_child_exit_or_reports_resource_failure -- --exact --nocapture`
  passed. The exact summary/audit-retention test also passed on Windows locally.
  These checks do not run prepared sandbox conformance cases.
- GitHub cross-platform CI for exact source `7a7c2de` is run
  [37839313510](https://github.com/runseal-labs/runseal/actions/runs/37839313510).
  Ubuntu and Windows passed formatting, Clippy, tests, and their configured
  smoke/whitespace/redaction checks. The first macOS attempt failed in
  `configured_summary_and_audit_retention_preserves_active_targets_and_durable_terminals`
  when cancellation reported `cleanup_complete:false`; [the macOS job passed on
  attempt 2 against the same SHA](https://github.com/runseal-labs/runseal/actions/runs/37839313510/attempts/2).
  The generic Windows run reported 35 ignored
  cases (1 in `cli_contract`, 34 in `execution_conformance`) because its runner
  has no prepared sandbox identity; ignored cases do not satisfy an acceptance
  criterion.
- Prepared Windows validation remains pending. Sandbox setup status is ready,
  but the execution gate on the available Windows test host is quarantined; an
  ignored sandbox case was rejected before the target started. No repair or
  `--accept-unverified-release` escape was used. The PRD-required sandboxed
  stdin, cancellation, PTY, control, filesystem, network, and capability-profile
  cases are not counted as passes.
- Windows local examples at `7a7c2de`: the Python JSON-RPC example, Node
  consumer example, and Python control CLI example passed with explicit
  `danger-full-access`. They completed replay/audit/dispose, three control
  round trips with cancellation, and three binary control rounds plus
  half-close and native exit-code propagation, respectively.

## Latest local working-tree verification

These checks ran on the local working tree based on PR revision
`c48076704465f2d97aa7a090af612fcd6895c860`. The Windows repair-census changes
are not committed yet, so this section is not exact-SHA closure evidence.

- Windows: `cargo fmt --check`,
  `cargo clippy --locked --tests -- -D warnings`, and `cargo test --locked --lib`
  passed; the library suite reported 223 passed, 0 failed, and 1 ignored. The
  elevation-check regression passes without Windows error 1309. Process-owner
  tests cover direct token lookup, missing-WTS-SID fallback, and resolving the
  protected PID 4 System process to its well-known SID. On 2026-10-09, the user
  reported that the prepared-host live WTS census and proof-gated
  `repair execution-gates --json` both passed; raw command output was not
  retained. The repair-help and README privacy contract tests passed.
  The new injected repair regression confirms that unavailable process
  inspection preserves the reservation, failure marker, and quarantine even
  when the override flag is set.
- Windows full-target attempt, before the elevation-check regression was added:
  `cargo test --locked --all-targets --quiet`
  passed the library suite (219 passed, 0 failed, 1 ignored) and the CLI contract
  suite (6 passed), then failed 3 cases in `adversarial_harness` with
  `EXECUTION_CLEANUP_FAILED`. At the time, setup status reported
  `elevated:false`; this host run does not count as prepared sandbox evidence.
- Windows repair status: the local CLI returned structured `BACKEND_UNAVAILABLE`
  from the non-elevated process-inspection path; setup status reported
  `elevated:false` during the earlier reproduction. This verified fail-closed
  behavior for that non-elevated run. The user later reported that a
  prepared-host live WTS census and proof-gated repair passed. In a separate
  local run, setup status again reported `elevated:false`, the full-target
  suite's three adversarial groups failed at admission with
  `EXECUTION_CLEANUP_FAILED`, and the proof-gated repair again returned
  `BACKEND_UNAVAILABLE`; this run is not prepared sandbox evidence. The
  prepared sandbox matrix remains unverified. The reported 1309 was
  traced to passing a process primary-token handle to `CheckTokenMembership`;
  the implementation now reuses the vendored effective-token check. A later
  prepared-host census reached the WTS records but found one null owner SID;
  direct primary-token `TokenUser` lookup returned `ERROR_ACCESS_DENIED` (5).
  The candidate now retries that access-denied path with `SeDebugPrivilege` on
  a duplicated impersonation token in a short-lived worker thread. It leaves the
  RunSeal process token unchanged, declines the retry when the calling thread is
  already impersonating, and clears the worker's impersonation before return.
  Microsoft documents that the kernel `System` process is PID 4 and that
  `OpenProcess` denies opening System and CSRSS even with `SeDebugPrivilege`
  ([PID 4](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-performance-problems-in-windows),
  [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)).
  Therefore only PID 4 in Session 0 with a null WTS SID resolves to the
  well-known SYSTEM SID. Other processes require a WTS SID or readable token.
  The access-denied fallback duplicates the caller's primary token, enables the
  privilege on that duplicate, and assigns then clears it on a short-lived
  worker thread. Microsoft documents token duplication and thread-token
  assignment/removal; `AdjustTokenPrivileges` cannot add a privilege absent
  from a token ([DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex),
  [SetThreadToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadtoken),
  [AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)).
  A protected process outside the exact PID 4 case can still deny access;
  repair then remains fail-closed. The user-reported prepared-host census pass
  is recorded above; the complete prepared sandbox matrix is still pending
  and is not counted as passing.
- WSL2 Linux: `cargo clippy --locked --tests -- -D warnings`,
  `cargo test --locked --all-targets --quiet` (354 passed, 0 failed, 0 ignored),
  and `python3 scripts/portable-probe-smoke.py` passed.
- Latest local Windows full-target attempt: `cargo test --locked --all-targets
  --quiet` passed the library suite (223 passed, 1 ignored) and CLI contract
  suite (6 passed), then failed three `adversarial_harness` groups. They were
  rejected at execution admission with `EXECUTION_CLEANUP_FAILED`; the same
  shell reported `elevated:false`, and `repair execution-gates --json` returned
  `BACKEND_UNAVAILABLE`. This is recorded as a non-prepared host failure, not
  as a pass or a sandbox implementation regression.
- After that run, `scripts/build-windows.ps1` built `runseal.exe` and both
  Windows helpers successfully. The exact non-sandboxed regression
  `cargo test --locked --test execution_conformance
  cli_stalled_console_output_cleans_owned_range_and_preserves_peer -- --exact
  --nocapture` passed (1 passed, 49.96s). This verifies local console cleanup;
  the subsequent prepared Windows run also passed the sandboxed stalled-console
  case required by AC05/AC22; see the current evidence below.
- No CI was started for this working tree. In the existing run for exact PR
  head `c480767`, the Ubuntu 24.04 and macOS 15 jobs passed their test, portable
  smoke, whitespace, and redaction steps. The Windows job passed setup and its
  prepared-cleanup prechecks, then the prepared conformance step was cancelled;
  the overall run is [cancelled](https://github.com/runseal-labs/runseal/actions/runs/37897123076).
  These jobs validate `c480767`, not the uncommitted working tree. This
  working-tree delta adds Windows-gated census/repair code and a shared repair
  help-contract change; the latter passed on Windows and WSL2. The prepared
  Windows full matrix on this working tree remains incomplete.

## Latest prepared Windows evidence for the working tree

- On 2026-10-09, the elevated live WTS census passed (1 passed), and
  `cargo run --locked -- repair execution-gates --json` returned
  `{"cleared_cleanup_failed_marker":false,"cleared_executions":4,"cleared_quarantine":false,"removed_runtime_roots":0,"repaired":true,"uninspectable_processes":0,"unverified_runtime_roots":false}`.
  Repair proved there were no uninspectable processes or unverified runtime
  roots before clearing four dead execution records.
- The prepared command
  `cargo test --locked --all-targets -- --include-ignored` passed the library
  suite (224), adversarial manifest suite (6), adversarial harness (7), and CLI
  contract suite (36). `execution_conformance` ran 74 cases: 73 passed and
  `evicted_history_is_reported_and_audit_queries_exclude_live_payloads` failed
  with the protocol-message watchdog. That suite took 643.19 seconds. The
  prepared run passed the AC05/AC22 sandboxed stalled-console case,
  sandboxed stdin/PTY/unsubscribe cases, AC07 process isolation, capability
  profile checks, and the sandboxed cancellation and cleanup cases. Because the
  history/audit case failed, this is partial prepared evidence, not a green
  full-matrix result; later test targets did not run in that command.
- The history/audit case passed one isolated elevated rerun (2.06 seconds) and
  three isolated local reruns (2.18, 2.27, and 2.37 seconds). Its test now adds
  step-specific failure context. These reruns do not replace the failed full
  prepared suite.
- An initial non-elevated `filesystem_conformance` run exposed two Windows
  proxy probes with 3-second startup limits; one warmup and one output-only
  probe timed out while cleanup completed. Their limits are now 15 seconds.
  The exact probes passed, then the full suite passed 17/17 in 78.91 seconds.
  This validates the local/fail-closed path, not prepared network enforcement.
- The latest non-elevated Windows `execution_conformance` run passed 40 tests
  and skipped 34 prepared-only tests in 265.23 seconds. It includes live
  execution of all 24 capability profile rows, local process cleanup, PTY,
  duplex control, backpressure, history/audit, CLI, and service/RPC checks.
  The CLI contract suite passed 35 tests and skipped one prepared-only test.
  `mcp_contract` passed 13 tests and `protocol_contract` passed 75 tests in
  earlier local runs.
- On Windows, real process conformance tests share a process gate. With the
  default test-thread count, many cases queued behind that gate and emitted
  `running for over 60 seconds` notices. A single-thread prepared rerun was
  attempted but did not start, so reduced contention and a green full matrix
  are not verified.
- Latest local checks passed: `cargo fmt --check`,
  `cargo clippy --locked --tests -- -D warnings`, `git diff --check`, and the
  repository redaction scan (only this generic guidance matched).
- The prepared Windows full matrix remains incomplete; no CI was started.
