# RunSeal conformance tests

See [ACCEPTANCE.md](ACCEPTANCE.md) for the AC01-28 evidence matrix: each RFC-0021
acceptance criterion mapped to its test location, command, platform and mode,
expected behavior, and actual result.

`configured_active_execution_limit_refuses_an_extra_target_while_controls_stay_live`
uses real RPC and service processes configured for two active executions. Both
targets report readiness and wait for input; a third target must be rejected
without its marker appearing while version queries and cancellation remain live.
All fixture-owned processes are cleaned before assertions. Reinstating the fixed
limit of eight fails this regression. `invalid_deployment_limit_is_rejected_without_target_or_config_value_disclosure`
covers invalid startup values, plain exit 125/diagnostic, structured error output,
target nonexecution, and a configuration secret canary.

`configured_replay_budget_changes_retention_without_changing_execution_policy`
compares real service/target processes with 64 KiB and 1 MiB replay budgets:
the smaller budget reports a history gap, the larger retains the full history,
while both deliver identical live bytes and policy hashes. Reinstating the fixed
replay budget fails this regression. Invalid-value coverage includes replay size
bounds and a connection budget smaller than its per-execution budget.

`configured_connection_replay_budget_evicts_old_history_without_erasing_terminal_or_audit`
uses two real targets whose separate histories fit but whose combined retention
exceeds the smaller connection budget. Later global eviction changes the first
execution's current replay range without changing its committed snapshot,
terminal summary, or audit history; the larger connection budget preserves it.

`configured_summary_and_audit_retention_preserves_active_targets_and_durable_terminals`
compares count, byte, and audit retention settings with twenty real completed
targets and one live input target. It verifies oldest-summary eviction,
independent active-target query/cancel, redacted cache truncation, and the intact
durable terminal after eviction. Audit type filtering keeps the query inside
the response envelope so response-size truncation cannot masquerade as cache
truncation. Restoring fixed connection, summary, or audit budgets fails the
corresponding regression. Invalid startup coverage includes all retention knobs.

`configured_chunks_refuse_one_extra_byte_and_preserve_binary_output_offsets`
uses an 8 KiB limit with real pipe targets and, on Windows, the local fd 3
control endpoint. It rejects 8,193-byte requests (including the equal encoded
length boundary), accepts exactly 8,192 bytes, verifies binary stdout/stderr/control
output and contiguous offsets, and confirms native cleanup. Reinstating the
fixed 64 KiB validation or omitting output splitting fails this regression.

`configured_pending_budget_refuses_unread_input_then_drains_every_accepted_byte`
holds target reads behind a file gate: 8 KiB pending capacity reaches backpressure,
whereas 256 KiB accepts the tested burst. After release and close, only previously
accepted bytes arrive, in order. Restoring the fixed pending capacity fails it.
The plain inherited-stdin CLI contract also transfers all byte values in a 64 KiB
write with both 8 KiB and 64 KiB chunks; restoring the fixed CLI read size fails.
Startup invalid-value coverage includes chunk/pending bounds and their relation.
These local execution checks do not replace the sandboxed Windows matrix.

`configured_rpc_frame_boundary_drains_oversize_without_starting_target_or_stopping_peer`
uses real RPC and service hosts with a 128 KiB line budget. An exact-size padded
request succeeds; an execute request one byte larger, including newline, returns
a parse error without its target marker. Subsequent version/query/cancel requests
remain live and the existing input target is cleaned. Restoring the fixed 1 MiB
reader fails this regression.

`configured_frame_snapshot_retains_newest_records_and_keeps_connection_live`
creates twenty native completed targets with redacted metadata. Audit snapshots
fit both 128 KiB and default 256 KiB response budgets, retain the newest terminal,
report truncation, and leave version queries usable. Restoring the fixed snapshot
size closes the smaller-frame connection and fails this test.

`configured_outgoing_frame_counts_newline_and_cleans_live_target_on_unrecoverable_response`
calibrates a string response ID to produce an exact 128 KiB serialized frame,
then adds one byte while both requests still fit their input budgets. The exact
response succeeds; the larger response yields observed EOF rather than a timeout.
The host exits and its real waiting target stops before fixture cleanup, leaving
one durable terminal with confirmed cleanup. Restoring the fixed output limit
leaks the oversized response and fails this regression. All are local execution
proofs; the full sandboxed matrix remains required.

`configured_output_cap_matches_effective_policy_hash_and_real_execution_boundaries`
uses real RPC and service binaries/targets at exact and one-byte-over aggregate
stdout/stderr boundaries, with omitted, stricter, looser, and zero policy limits.
It checks actual target/output behavior before JSON policy fields. Canonical JSON
is independently SHA-256 hashed and compared with explain, receipt, every live
and durable event, and the unique terminal; all native target PIDs are gone.
Changing only the effective deployment cap changes the hash, while a request
cannot loosen it. `configured_output_cap_plain_cli_preserves_child_exit_or_reports_resource_failure`
checks plain forwarding/native exit 7 under the larger cap and RunSeal exit 125
with a prefixed resource failure under the smaller cap. Restoring the old hidden
16 MiB cap and unbound policy fails both on real behavior. A policy-only probe
also detects the missing effective field but is not counted as behavior proof.
`configured_output_cap_counts_native_control_and_terminal_streams` also uses
Windows local fd 3 and actual ConPTY targets. An 8,193-byte stdout/stderr/control
aggregate fails under 8,192 bytes and succeeds at exactly 8,193; a real terminal
target detects its tty and exceeds the smaller terminal quota, while the larger
quota preserves native exit 7. Both RPC quota tests observe native target exit
before fixture cleanup, so dropping the host cannot mask a false cleanup claim.
These are local-execution proofs; the sandboxed terminal/control matrix remains
required. Invalid startup coverage includes the
output deployment bounds and redaction.

CLI refusal regressions exercise real binaries in all three output modes,
assert exit 125, plain diagnostic prefixes or exactly one structured error,
marker nonexecution, and secret-canary argument non-disclosure. Runtime output
quota and timeout failures verify 125/124, one terminal/error and one durable
terminal; Windows native process enumeration also verifies that each target is
gone. Child 0/7/125 and spoofed stderr prefixes remain child results, with JSON/
events outer 0 and `--json` after the argv separator treated as a child argument.
Reinstating legacy pre-start exit 1 and machine runtime exit 1 fails the refusal
and runtime regressions on actual process statuses. These local execution checks
leave the required restricted-backend matrix outstanding.

These Rust integration tests define the initial public behavior expected from a RunSeal implementation.

They are black-box protocol tests. `cargo test` builds and runs the local binary; use `RUNSEAL_BIN` to point the suite at another candidate implementation:

```bash
RUNSEAL_BIN=/path/to/runseal cargo test --test cli_contract --test protocol_contract --test filesystem_conformance
```

Windows sandboxed conformance cases require a prepared sandbox identity. The
generic Windows test job marks those cases ignored; ignored cases are not
acceptance evidence. On a prepared Windows reference host, run the complete
suite, including those cases, with:

```powershell
cargo test --all-targets -- --include-ignored
```

Run the suite on Windows before claiming reference-backend readiness. Other
platforms can run the same tests to verify platform selection and fail-closed
behavior until their backends are promoted.

The Windows managed-proxy environment override probe uses Python's
`socket.create_connection(timeout=2)` instead of PowerShell's synchronous
`TcpClient.Connect`, which has no per-call connection timeout. The RPC harness
watchdog is 30 seconds so it cannot kill the host before the probe's bounded
execution and Windows cleanup budgets finish; the probe's connect/read timeouts
and execution timeout remain explicit.

On Linux or macOS, also run the portable probe smoke after building `runseal`:

```bash
python3 scripts/portable-probe-smoke.py
```

This checks diagnostic probe shape, experimentally reported portable sandbox levels,
contained host-read and symlink boundaries, macOS/Linux managed-proxy enforcement,
Linux inherited-socket bypass denial,
and fail-closed behavior when a required sandbox mechanism is unavailable.

The v2 protocol tests preserve the actual admission receipt, wait for the unique terminal event, and read child bytes from numbered stream events. Replay tests explicitly request `after_seq:0` and read the subscription receipt before its declared replay messages. Passing pipe tests does not complete the required PTY/control or platform matrix.

`execution_conformance` includes real Windows local/sandbox process-range, streamed-input, paused-reader cancellation, writer-stall, audit parity, and session-disposal cases. Session disposal checks that the owned descendant and allocated runtime root are gone before success, while another session on the same connection continues its heartbeat. Local pipe tests keep duplicated stdout/stdin handles alive in an unrelated process and verify complete output and completion without stopping that process. The filesystem and adversarial RPC consumers retain their raw admission receipts, wait for unique terminal events before EOF, and decode output chunks with offset and byte-count checks. Deadline state tests verify refusal when cleanup is unproven; they do not replace the remaining real fault and cleanup-failure tests.

The tests are black-box by design:

- CLI behavior through `runseal exec`.
- Capability reporting through `runseal capabilities` and `getCapabilities`,
  without exposing private Windows account or setup identities.
- Capability status decisions should use `sandbox_levels`, `network_modes`,
  and `feature_statuses`; `features` remains a coarse compatibility map.
- Windows hosts select the Windows reference backend and run supported sandbox levels through the shared conformance tests.
- macOS hosts support `read-only`, `workspace-write`, and `workspace-contained` with default unmanaged networking, plus experimental `network.proxy`; unavailable guards still fail closed.
- Linux hosts support `read-only`, `workspace-write`, and `workspace-contained` with default unmanaged networking, plus experimental `network.proxy` through an isolated network namespace and local relay; unavailable guards still fail closed.
- Windows sandbox plans include runtime root, synthetic home, setup requirements, protected filesystem categories, process boundary state, and network guard planning.
- Windows filesystem ACL setup must bind rules to a single sandbox user restricted process identity before any rule can be applied.
- Windows runtime roots can be reported as a verified single capability without making any sandbox level supported by itself.
- Windows runtime environment redirects can be reported as a verified single capability without making any sandbox level supported by itself.
- Windows process cleanup can be reported as a verified single capability without making any sandbox level supported by itself.
- Windows process cleanup tests verify per-execution cleanup scope and must not terminate unrelated processes.
- Execution results include a `PlatformSandboxPlan` summary for the selected backend.
- Policy explanation through `runseal explain-policy`.
- JSON-RPC behavior through `runseal rpc --stdio`.
- Filesystem conformance gates that accept explicit fail-closed unsupported responses now, then require behavior once a backend claims support.
- Protected workspace metadata and network conformance gates accept explicit fail-closed unsupported responses now, then require behavior once a backend claims support.
- Conformance fail-closed responses and audit events do not expose private Windows account or setup identities.
- Protocol vocabulary uses `Execution`, not raw process objects.
- Policy denials use stable error codes.
- Standard profiles materialize to canonical policy JSON and stable hashes.
- Events are structured and align with the RFC event model.
- Executions write JSONL audit events under `.runseal/audit/`.
- Policy denials and backend fail-closed decisions also write JSONL audit events.
- `danger-full-access` is explicit local execution with no sandbox guarantee.
- Sandboxed policies fail closed unless a backend can enforce them.

The real Windows startup case checks local and sandboxed executions: a missing
program must publish neither live nor audit `execution.started`, and its terminal
`started_at` is null. Successful child output follows the unique confirmed start;
its terminal timestamp matches the committed start event. Startup cleanup proofs
remain a separate requirement.

The local and sandboxed Windows PTY cases assert a real console for all three child stdio
handles, initial and resized dimensions, input round-trip, merged stderr, terminal
chunk offsets/counters, pipe-EOF refusal, and natural cleanup. It also queries the
actual start timestamp while the child is waiting for input. Separate foreground
interrupt tests launch a persistent shell and peer, interrupts a foreground task,
then prove that the same shell runs another command and the peer heartbeat
continues. Local tests assert an explicit unsandboxed result. Removing helper Ctrl+C restoration makes that test fail. These cases do
not establish the remaining fault, or combination matrix.

The Windows CLI PTY tests use a real outer ConPTY and a child driver that checks
console modes before and after RunSeal. They forward Unicode keyboard input and
Ctrl+C, resize the outer console, verify the inner console dimensions, and retain
native exit 7. Separate inherited-input EOF cases prove descendant/runtime-root
cleanup and a concurrent peer heartbeat for local and workspace-write profiles.
Invalid CLI PTY mode combinations must fail before the child marker is written.

The Windows native control fixture exercises fixed child fd 3 directly through the
vendored local process boundary: three rounds of 128 KiB binary bytes, ordered
input half-close with a final reverse reply, separate stdout/stderr, native exit 7,
and an independent peer that survives cleanup. It does not establish public RPC,
CLI, or sandboxed control support.

RPC control conformance covers three binary rounds and input half-close in all four
Windows profiles, checks independent stream offsets/counters, preserves a same-policy
peer, and verifies metadata-only durable audit output. The contained fixture copies
the interpreter and standard library into its allowed workspace; any interpreter
startup diagnostic remains in stderr. Local and workspace-write cases also verify
control progress while stdin is blocked, bounded control backpressure, cancellation
of the actual root/descendant range, and an aggregate output limit across all streams.
The remaining control fault combinations are still pending.

CLI control tests use a real caller endpoint at fd 3, exercise three binary rounds
and half-close while stdout/stderr remain separate, preserve native exit 7, and
reject missing/invalid endpoints before child startup. A paused control reader
triggers a durable backpressure terminal, actual descendant/runtime-root cleanup,
and an independent peer heartbeat. These cases cover local and workspace-write;
the full profile/fault matrix remains pending.

Windows redirected CLI stdio tests pause or close stdout/stderr readers, including
`--events`, and check actual root/descendant cleanup, durable termination reasons,
runtime-root removal, and a same-policy peer heartbeat. Timeout cases verify that
the first accepted timeout remains the cause while output is stalled. Console/file
output still requires the complete fault matrix.

Plain CLI inherited-Console tests use a real outer ConPTY for local and
workspace-write execution. They verify Unicode with native backspace editing,
raw-console Unicode without a newline, Ctrl+Z EOF, and early child exit after an
acknowledged partial line. The caller retains the partial characters and original
console modes, and the CLI preserves native exit 7. The complete frontend
cleanup fault matrix remains pending.

The lifecycle owner invokes CLI frontend cleanup before committing its terminal.
A real local execution plus a separately gated process/pipe fixture verifies
successful teardown ordering and cleanup failure with a retained live reader.
The unique live/durable terminal preserves actual exit 7 and the requested cause;
an unreleased frontend reports cleanup_failed and cleanup_complete:false. This
owner test complements the public CLI tests; console/file output fault coverage
and the shared cleanup deadline remain pending.

Runner boundary tests use real Windows pipes and processes to verify buffered
binary output drainage while an external writer reference remains open, a timeout
longer than the native finite-wait range, and the actual exit code after forced
termination. The public timeout test also checks the observed exit code. A lifecycle
owner test closes a real frontend pipe before spawn and verifies a unique durable
disconnect terminal, no command launch, and successful pre-launch cleanup. These
targeted tests do not establish the full public startup or cleanup-failure matrix.

Native CLI output tests cover local and workspace-write execution with a real
paused outer Console, owned root/descendant and runtime-root removal, a unique
durable backpressure terminal, and an independent peer heartbeat. Reinstating
the former synchronous stdio path fails the Console cleanup watchdog; the
candidate passes. Unicode tests use CP437 without changing it, gate every byte
on an audit output record, and verify cross-chunk characters and malformed/final
incomplete sequence rendering. Redirected file tests preserve binary stdout and
stderr separately with child exit 7. Vendor pipe tests prove native cancellation,
retention after an expired join deadline, and successful subsequent join while
the caller keeps both endpoints open. These are targeted Windows cases, not the
complete platform/profile or cleanup-failure matrix.

A paced native pipe fixture consumes one buffered chunk over more than five
seconds. It verifies each actual native write completion before the whole-chunk
ACK and checks all binary bytes after join. Disabling progress publication fails
the regression. A public local CLI Console fixture paces actual consumer reads,
keeps the child active until consumer delivery releases its exit gate, and checks
all distinct supplementary characters, no replacement characters, unchanged
CP437, full audit byte counts, native exit 7, and one verified-cleanup terminal.
Disabling native progress refresh makes the same fixture exit 125 on false
backpressure. Raw ConPTY cursor-repair redraws are not counted as command bytes.
The sandboxed paced Console case remains unverified.

A companion local Console case lets the command exit after producing output.
Continued consumer progress cannot extend its absolute cleanup deadline: the
wrapper exits 125, retains native exit 7, reports incomplete frontend cleanup,
and commits one cleanup-failure terminal. Its host-exit tick is sampled before
probing Console configuration, so subsequent Console queries do not count as
wrapper execution time. The fixture opens the command's real process handle
before releasing its output gate and samples native exit only after that handle
signals; a command's own "about to exit" message is not an exit oracle.

Engine fault tests run real local processes and descendants, then inject an
observer fault or withhold backend result facts. Runtime failure must not become
`failed_to_start`; earlier cancellation remains first. Missing cleanup proof
keeps exit unknown and fails closed, with one durable terminal and no private
fault text. The filesystem audit-write failure test also checks `execution_failed`
and explicitly missing durable history. These are local/fault-injection proofs,
not the full sandboxed backend failure matrix.

A host stdin cleanup fixture retains a real peer's output pipe and gates reader
completion after native I/O. Repeated shutdown and Drop reuse the expired
deadline, return without a new grace period, and retain the worker owner; the
fixture releases and joins only its own reader and confirms the peer's native
exit 7. Restoring deadline renewal fails this regression. A vendored output
fixture likewise retains an owner around an actual blocked write until explicit
release. These prove the host I/O boundaries, not the complete preparing/helper
cleanup deadline or recovery matrix.

The runner cleanup tests also hold real pipe-reader workers alive after a native
read. An expired join and a dropped sibling must retain those workers without a
new grace period. The fixture releases and joins its own workers before assertions;
discarding retention fails this regression. This is worker-ownership evidence,
not a complete helper deadline or sandbox resource-recovery proof. A separate
runner fixture holds the result writer lock or fills a real pipe while retaining
its reader. Cleanup report delivery must fail within the supplied deadline before
either blocker is released. The fixture releases its blockers and joins its own
callers and retained workers before assertions. Synchronous delivery fails this
regression; the full cross-process budget remains unverified.

A startup-reader fixture keeps a native writer open with no bytes, a partial
header, or a partial payload. The runner must refuse the request at its supplied
preparation deadline before that writer closes. Each fixture releases the writer
and joins the reader before assertions. Blocking frame reads fail this regression.
Startup reports share this runner preparation deadline; native setup and actual
partial-spawn cleanup still require conformance evidence.

A runner launch fixture holds the native-launch worker until after the parent's
deadline. It then creates a real current-caller suspended process. The parent
must already have reported unverified cleanup and retained the unfinished worker;
the late process must exit with native code 1 without running its target.
Only fixture threads/processes are released and joined before assertions.
Replacing bounded waiting with an unbounded join fails this regression. This
tests launch ownership, not credential logon or recovery of a permanently stuck
native call.

A runner wait regression uses a real gated process and a duplicated native
wait-only process handle. Termination is refused while the child remains alive;
the established cleanup deadline must remain unchanged and waiting must report
cleanup expiry before the fixture releases the child. The child then exits with
native code 7 and the fixture joins its waiter before assertions. Ignoring the
cleanup deadline fails this regression. This proves runner-local refusal behavior,
not host/helper clock alignment or a complete sandbox termination matrix.

A runner IPC regression assigns a real gated root process to its owned range
before the root launches a child. A framed termination request and input EOF must
both stop the root and child with native exit code 1 while an independent peer's
heartbeat advances. The observed process states are captured before fixture range
cleanup; all fixture workers and processes are released before assertions.
Disabling range-first termination fails this regression. It covers the native
runner control path, not the complete public sandbox/profile termination matrix.

The runner control fixture also sends an already-expired host deadline and verifies
that the runner does not renew it. Ignoring the deadline fails the regression.
A parent input-writer fixture reads its real cancellation frame and verifies that
the supplied host deadline survives encoding. A real Python peer samples the
native monotonic clock after a deliberate delivery delay; the remaining budget
must shrink. These cover delivered cancellation frames, not blocked transport or
the complete natural-completion/setup cleanup chain.

Runner cleanup announcements carry confirmed native exit facts and the current
deadline before the final result. Native runner fixtures verify that a live process
has no exit code, then preserve its actual natural code 7 or forced code 1.
A parent fixture delays a real framed cleanup announcement until its deadline
expires, retains the writer without a final result, and verifies bounded parent
waiting plus host callback and native exit facts. Ignoring announcement deadlines
fails this regression. This covers delivered announcements; the complete public
host/frontend matrix and blocked or lost notification still require evidence.

Vendored runner-client tests exercise preparing cancellation/timeout with real
peer processes that keep empty, partial-header, or partial-payload pipes open.
They require refusal before peer EOF; disabling budget checks fails the test.
An actual native connect remains owned after deadline expiry and is cancelled and
joined only by its fixture. A real suspended process verifies that a security
setup error cannot skip owned-process termination or resume the target; disabling
that cleanup fails while the process is still live, and the fixture terminates it
before asserting. Capture-parent peer tests also pass an already-expired host
deadline; restoring a fresh local grace period fails before peer release.
These are isolated native boundaries and do not establish complete logon/setup
cancellation, command-range cleanup after partial startup, or automatic repair.

The vendored capture-parent input test blocks an actual framed write in an
anonymous pipe, proves bytes have entered the pipe, and retains the reader. An
expired join deadline retains the writer owner; subsequent cancellation joins
the native worker and observes its interrupted write. It verifies the parent I/O
boundary, not the complete public cleanup-failure or helper fault matrix.

Shared-state tests keep a real sandboxed owner heartbeat active and exercise
same-process and separate-process admissions with overridden APPDATA, USERPROFILE,
TEMP/TMP, PROGRAMDATA/ALLUSERSPROFILE, and a runtime-home case alias. Rejection
creates no activity, child marker, audit directory, or runtime root; after verified
owner cancellation/drain, the original rejected caller executes successfully.
The former environment-based state directory admitted a different workspace and
emitted a real started event. A native global-mutex holder test verifies bounded
refusal before its explicit release; reinstating infinite wait fails the test.
Protected-state tests reject a nested workspace before launch, then allow a real
command in the parent workspace while the OS denies its protected-file write.
Only a test-owned probe is touched; actual shared-state records are not overwritten
or removed. An isolated native-process fixture kills its owned host while its
real descendant continues a heartbeat. Healthy peer release must retain that
host's reservation, and both policies must refuse admission without changing it.
Restoring the former dead-host pruning rule fails this regression. A separate
fixture checks a live native PID with a mismatched creation timestamp, including
an identical reservation token, so neither admission nor release treats it as the
original host. A prepared Windows regression also kills the service host during a
live `workspace-write` execution, verifies the descendant stops, confirms a later
admission returns `EXECUTION_CLEANUP_FAILED` without deleting the recorded runtime
root, then runs proof-gated `repair execution-gates` and verifies admission recovers.
It does not use `--accept-unverified-release`. These fixtures use independent test
bindings and remove only their own records and processes. They do not establish
automatic host-death recovery, actual OS PID recycling, or the full shared-state
fault matrix.

A marker-write failure fixture uses an absent test-owned parent directory and an
independent binding. The failed guard must retain its reservation and refuse both
policies; a native peer observes the retained quarantine signal after guard drop.
The former release behavior fails this test. Vendored native tests inspect the
protected host/System-only event DACL and non-inheritable handle, confirm reopen
does not clear the signal, and refuse a conflicting object type without modifying
it. Only the fixture's signal and state are removed. These tests do not establish
different-principal access denial, reboot persistence, or verified recovery.

Protocol client fixtures close their input and wait for transport cancellation
before forcing host termination on a watchdog. A real local execution test checks
that this releases the host and descendant and commits exactly one durable
`client_disconnected` terminal with verified cleanup. Restoring immediate host
kill leaves no terminal and fails the regression. An unverified reservation left
by an earlier killed sandbox host is not deleted to make later tests pass.

Capture-parent tests use real native pipes with an open writer and a real peer
process that supplies no frame, a partial header, or a partial payload. Cancellation
and execution-deadline predicates must expire the response wait before that peer
exits; the fixture releases the peer and joins the reader before asserting so the
former blocking implementation cannot hang the regression. A full native pipe
also proves synchronous write cancellation, retained ownership after expiry,
and subsequent join/handle release. Restoring blocking reads or a fresh Drop
grace period fails these tests. Native framing tests cover one-byte fragments,
adjacent output/ACK/exit frames, binary contents, truncation, and the frame cap.
These tests establish the parent I/O boundary, not actual sandbox-host recovery,
the full public helper-failure matrix, or the complete cross-process cleanup
deadline. Machine sandbox state remains untouched by these isolated fixtures.

Cleanup-result regressions exercise the helper's reporting function with real
gated native processes: a still-live process reports unknown status, natural exit
7 and timed-out/terminated exit 1 report their actual codes with cleanup false.
Capture-parent tests decode those failed-cleanup fields over real pipes and
preserve them after cancelling/joining a blocked input writer or expiring a
retained input owner. Missing exit frames remain unknown even when a test-local
process status is available. Restoring generic cleanup errors or discarded parent
facts fails the regressions. This establishes helper reporting and parent I/O
translation; actual sandbox fault injection and the full public cleanup-failure
matrix remain pending.

Service admission reservations now participate in the lifecycle observer cleanup
before terminal commit. The owner passes confirmed cleanup facts into that phase;
unconfirmed sandbox cleanup keeps the reservation and quarantine instead of
releasing it. Existing native exit-7 fault tests now also verify that confirmed
input failure passes true, cleanup failure and missing confirmation pass false,
and the resource phase observes those facts before the unique durable terminal.
Explicit release removes only the current owner's exact
record; successful release prevents Drop from revisiting the state. Native
release tests hold a real named mutex beyond a 30 ms cleanup deadline and require
failure before unlock, an unchanged deadline on retry, and retained reservation
plus quarantine after Drop. Same-policy and changed-policy admission remain
closed. Restoring the fixed one-second mutex wait fails this regression. The tests
release only their own mutex, signal, and fixture metadata before assertions;
they do not repair or bypass an actual backend binding. Synchronous state-file I/O,
real sandbox reservation faults through public execution/audit, and the complete
setup/logon cleanup chain remain unproven boundaries.

An actual failed input-source worker closes a real child stdin pipe; the child
observes EOF and exits 7. A confirmed-cleanup response followed by that worker's
successful join retains a typed input failure and the actual exit, rather than
inventing cleanup failure. A lifecycle regression delegates to the real local
backend, then injects typed post-exit faults and verifies the engine's final
response and its single durable audit terminal. It covers input/cleanup faults
and preaccepted cancellation or natural-exit causes. Restoring the untyped source
error or the blanket start-failure classification fails these tests. Actual
sandbox fault injection remains separate, pending safe shared-state recovery.

A Windows CLI final-JSON fixture reads a 4096-byte prefix, then keeps its pipe
open without consuming more bytes. The native target has already exited 7; the
host must stop with outer 125 while the pipe remains unread, preserve that
unique durable terminal, and avoid appending an error object to the partial
result. The fixture subsequently drains and joins its own readers and host.
The former error propagation also passes this fixture because the native pipe
refuses another writer. This is conformance evidence, not a reproduced baseline
regression or proof of the complete final-delivery cleanup fault matrix.

A Windows console cancellation fixture starts its driver in an owned ConPTY.
It launches `exec` with redirected output, waits for native target and descendant
activity, then sends actual Ctrl-C or Ctrl-Break only within that isolated console.
For plain/JSON/events it requires outer 130, signaled native process handles before
fixture cleanup, matching real target exit status, one durable cancelled terminal,
and an independent peer's continuing heartbeat. The old default console handling
returned native interruption status instead of 130; its execution range was still
live at observation. The driver subsequently releases only its own processes.
This proves the CLI cancellation boundary for `danger-full-access`; sandboxed
execution, shutdown events, preparing-stage races, portable host signals, and
handler-restoration fault injection remain separate obligations.

A configured sender fixture keeps a real service output pipe open without reader
permits after target readiness. A 12 MiB native output burst makes partial write
progress then stalls under a 5 MiB budget; under 32 MiB it completes while the
protocol reader remains paused. In both cases, a cancel request stops the native
target before reader resumption. The fixture then drains receipts and the unique
terminal, confirms unchanged policy hashes, and joins its owned host and readers.
Restoring the fixed writer budget prevents the larger burst from completing and
fails this regression. It proves configurable writer pressure and cancellation
under `danger-full-access`; full resident-memory, concurrent-execution, tiny-chunk,
and sandboxed budget evidence remains required.

A configured output-grace fixture retains an unread RPC pipe after readiness and
an actual 1 MiB producer burst. With 500 ms grace, the native target stops before
reader resumption and commits one verified backpressure terminal; with 8,000 ms
it remains active and accepts cancellation. An actual response after idle delay
checks that empty connections do not expire. Both cases retain the same policy
hash. The final CLI JSON fixture also covers 500 and 5,000 ms while preserving the
native exit-7 terminal. Restoring each path's fixed five-second timer separately
fails its behavioral test. These tests establish RPC and final-JSON transport
timing for `danger-full-access`; configured native Console/control pressure,
all platform/profile combinations, and the full cleanup-deadline matrix remain
separate requirements.

Input allocation regressions fill the raw-byte budget with single-byte writes
and measure retained Vec/VecDeque capacities, including a polled buffer whose
write has not been acknowledged. A second case supplies a tiny input in a large
caller allocation. The old queue retained 6,553,600 bytes of buffer/node capacity
for the 256 KiB single-byte case and kept the caller's unused capacity; both tests
failed before packing. They also verify exact byte order, ACK accounting, and EOF.
A real Windows stdin/control fixture mixes large writes with 512 one-byte writes,
keeps the target gated until input backpressure, checks live control-plane replies,
then verifies every accepted binary byte, no rejected bytes, EOF, native exit 7,
cleanup before fixture Drop, one terminal, and absence of input canaries in audit.
This establishes queue allocation and native byte-stream behavior under
`danger-full-access`; allocator overhead, whole-process resident memory, every
concurrent execution/profile, and the full helper buffer chain remain pending.

A Windows native-exit fixture registers an FLS callback on an owned thread and
holds that callback after the Rust body returns. It confirms `is_finished()` is
true while the native thread handle is unsignaled, then starts a retained-worker
reaper. The reaper must return before callback release; the fixture releases and
joins only its own threads before asserting. The former Rust-only predicate blocks
and fails this regression. Windows frontend and transport joins now use native
termination checks, and expired transport workers retain their join owner.
The vendored output worker uses the same native predicate. A direct fixture
performs a real native pipe write, verifies the byte and progress count, then
holds its FLS exit callback. Poll, flush, finish, and Drop must return while keeping
the unjoined owner; another retained worker must not make reaping block. Separate
restorations of the old completion and reaper predicates fail these regressions.
All seven output tests pass. Direct FLS injection into Console and every public
frontend, portable thread-exit proof, and one deadline across all cleanup stages
remain separate requirements.

The lifecycle owner explicitly finishes its deadline worker before frontend
cleanup and terminal commit. Failed confirmation becomes
`EXECUTION_CLEANUP_FAILED` with `cleanup_complete:false`, preserving existing
native exit facts and the accepted termination cause. A Windows timer-owner
fixture holds a real FLS exit callback after its receive loop returns: repeated
finish cannot extend the original deadline, and Drop must retain the pending
owner and return before callback release. Restoring the old unconditional Drop
join fails this regression. This proves that worker boundary; direct timer fault
injection through the lifecycle engine additionally uses the actual local backend
to launch a gated target. It observes the target's native handle signaled with
exit 7 while the actual deadline worker remains in its FLS callback. Before
callback release, the owner must return cleanup failure, retain the timer owner,
and commit exactly one durable terminal with native exit 7 and requested reason
`exited`. The observer reads that terminal from disk at delivery time. Removing
the explicit timer finish reports successful cleanup and fails this regression.
The fixture releases and joins only its own timer before assertions. This proves
the local lifecycle/audit boundary; public CLI/RPC timer-fault injection, every
sandbox profile, and the complete cleanup-failure matrix remain pending.

Preparing-time regressions hold a backend plan-compilation gate and observe the
accepted timeout or cancellation before releasing it. Release cannot enter the
execution backend or create the target marker; the unique durable terminal has
no native start/exit facts. Disabling the early deadline worker leaves the cause
unset while compilation is held and fails this test. A delayed worker fixture
uses the frozen accepted instant and verifies that an already-expired execution
cannot restart its budget; restoring a fresh worker timestamp fails it. A separate
admission-barrier fixture keeps the receipt-release sender alive and requires
timeout completion before release, with late release refused and no target
launch. The actual service worker now waits for receipt delivery inside the same
lifecycle owner, with its timer already running. These tests establish controlled
preparing and admission boundaries. Blocked native setup/logon cancellation and
the full startup fault matrix still require their own evidence.

The native receipt-pressure regression runs both RPC and service with a live
waiting-input peer. A 256 KiB control response fills the actual output pipe while
read permits remain withheld; `PeekNamedPipe` confirms an unread partial native
response. A later execution with a 100 ms timeout must commit its unique durable
timeout before any receipt drain, without starting the target. After drain the
delivered terminal must equal the already-committed record, the target marker
must remain absent, and a control response plus the peer's ordered input EOF and
native exit prove that the connection remains usable. Owned host and peer cleanup
finish before assertions. Restoring blocking admission `recv()` fails because
the terminal is missing before drain. This proves native receipt waiting for
`danger-full-access`; blocked native setup/logon and the complete startup fault
matrix remain pending.

The backend worker now owns its backend and request data, reports completion over
a separate channel, and joins only after native thread exit. A real local target
is gated until the fixture opens its native observation handle, then exits 7.
One fault holds the backend worker's FLS exit callback after its result was sent;
another retains the result inside the backend while a real `ReadFile` stays
blocked. Both also retain an output sender. The fixture adopts a short original
cleanup deadline and records worker/native-pipe ownership plus the unique durable
terminal before releasing either native boundary. The first failure preserves
delivered exit 7 and reason `exited`; the second preserves unknown exit status
and reason `cancelled`, despite the fixture knowing the target exited 7.
Restoring Rust-only completion or unconditional join waits until the fixture's
safety watchdog releases the native boundary and fails ownership assertions.
Only fixture threads are released and joined before assertions. Execution policy
reservations remain owned by the lifecycle through worker confirmation and are
quarantined before terminal commit when cleanup is unconfirmed. This proves the
local backend-worker boundary; blocked native setup/logon, pre-admission plan and
state I/O, portable native exit callbacks, and the complete sandbox fault matrix remain
pending.

Controller completion validation preserves the accepted unconfirmed scope before
interpreting completion, even after removal from the active index. Missing/error terminals, empty success events,
execution/session/policy mismatches, stale sequence, nonterminal events, and
conflicting cleanup/status facts cannot release admission. A controller fault
fixture in direct and stateful modes runs a real exit-7 child and retains its
owner thread inside an FLS exit callback; it injects only completion-delivery
faults against that accepted test record. A separate peer uses ordinary RunSeal
admission and streaming input. While the native owner remains pending, cache
removal and disposeSession cannot allow a new target; getVersion and the peer's
ordered input EOF remain usable. Any mistakenly admitted finite target and the
peer finish before releasing fixture threads and assertions. Removing early
scope retention or identity validation admits the target and fails this test.
This proves controller completion/admission behavior with live native ownership;
the accepted fault record is injected, so it does not establish end-to-end public
transport or sandbox cleanup recovery.

The accepted execution's directory validation and plan compilation now run in
an owned preparation worker. Completion uses a separate channel; joining requires
native thread exit. A Windows lifecycle fixture holds either an actual native
pipe read during compilation or an FLS exit callback after delivering a plan.
The original short cleanup deadline must produce one durable cleanup-failed
terminal while preserving the worker and pipe owners, with no target launch or
started/exit facts. The accepted cancellation cause remains `cancelled`; an
unconfirmed preparation exit remains `failed_to_start`. The fixture releases
and reaps only its own resources before assertions. Restoring Rust-only completion
or unconditional join fails after the fixture's safety release, proving that the
new test catches the unbounded wait. Normal successful preparation does not start
the whole execution's cleanup clock. These tests cover the accepted lifecycle
worker; actual blocked pre-admission storage/setup boundaries,
blocked native setup/logon, and the full public sandbox matrix remain pending.

After native execution cleanup is confirmed, the Windows reservation is released
on the active cleanup thread. Release waits for the named mutex within its bounded
window, checks that the state path is a regular file before reading it, and removes
only the matching reservation. A release failure retains the entry and signals
quarantine so later same- or different-policy admission remains closed.
`reservation_release_respects_held_native_mutex_deadline_and_preserves_quarantine`,
`confirmed_reservation_release_finishes_after_execution_deadline`, and
`nonregular_state_path_fails_closed_without_releasing_reservation` cover the
deadline, successful release, and fail-closed paths. The prepared Windows
`sandboxed_stalled_console_output_cleans_owned_range_and_preserves_peer` test
exercises this release path after a real stalled Console execution. Additional
storage/write fault injection and the full host-death recovery matrix remain
outside this focused reservation coverage.

The CLI native-reader deadline fixture now keeps a duplicated native thread
observation handle through release. A parallel retained-worker reaper can join
an exited owner before the fixture attempts to reap it; success therefore
requires both native exit and absence from the retained pool, independent of
which caller joined it. The fixture deterministically reproduces an already
reaped owner after confirming native exit. Restoring the former loop that waits
only for its own `join_finished` success fails, while the same original-deadline
and pre-release ownership assertions remain in place.

RPC/service admission now runs request validation, plan compilation, policy
reservation, and journal preparation in an owned lifecycle worker. The controller
polls typed preparation results, rechecks fail-closed state, freezes acceptance,
and attaches the start permit to delivery of the preparing receipt. Raw pending
requests consume the same configured execution capacity; excess requests are
rejected without a hidden queue. The controller retains worker ownership through
native exit, propagates disconnect to pending and accepted controls, and retains
an unconfirmed worker at its original cleanup deadline. Known accepted scopes
with unverified cleanup remain queryable as structured cleanup failures.

A direct/stateful controller fixture blocks the admission worker in a real
native pipe read before validation. While it remains held, getVersion and an
ordinary admitted peer with actual streaming stdin must progress. After a short
original cleanup deadline, the worker and native pipe must remain owned, new
admission must be refused, and ordered peer EOF must complete its actual native
process. The fixture releases and reaps only its own reader before confirming
that the late preparation never launches the target. A separate held-worker
fixture fills every configured pending slot, verifies immediate excess rejection
and live control, then cancels/releases and confirms all native workers exited
without a target. Removing pending capacity or cleanup expiry fails the respective
regression. These tests inject only the blocking pre-validation boundary; they
do not prove ordinary storage/logon stalls or end-to-end transport fault
injection. Native receipt-pressure and active-capacity black-box cases separately
verify delivery-gated timeout and peer controls for both RPC and service.

Admission acknowledgment is now a checked controller decision. The lifecycle
worker cannot abandon its acceptance receiver merely because a cancellation
arrived; it waits for the controller's rejection or channel closure, and the
engine checks the shared cause before any launch. A closed receiver cannot
publish a preparing receipt or install an active execution/start permit. A
private delivery-fault fixture verifies this in direct and stateful modes;
ignoring the send result falsely publishes preparing and fails the regression.

Rejected preparation starts its cleanup clock in the worker before sending the
error. Native exit confirmation cannot arrive after that original deadline and
restore an ordinary validation response. A real FLS callback holds the actual
rejected admission thread after its Rust body and error delivery. The controller
must withhold the response while the callback is pending, then return cleanup
failure and retain ownership at expiry. Another case releases the callback only
after expiry and confirms native exit before the next controller poll; that late
confirmation must still return cleanup failure. Both direct and stateful modes
keep version control usable and never launch a target. The fixture releases and
reaps only its own native callbacks before assertions. Restoring Rust-only exit
checks or preferring late native completion over expiry fails these tests. This
proves native rejection confirmation and delivery faults, not ordinary storage
blocking or the complete public sandbox startup/cleanup matrix.

The public Windows storage-admission regression uses a real regular input file
held by a fixture-owned process with `FSCTL_REQUEST_OPLOCK_LEVEL_1` on an
overlapped handle. The kernel's completed oplock-break notification confirms
that the ordinary RPC/service file-input path attempted a conflicting open;
the owner withholds acknowledgment until the fixture closes that handle.
See the [Windows API contract](https://learn.microsoft.com/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock_level_1).

Both RPC and service are tested with normal release and with transport EOF while
the file remains held. Before release, getVersion and getExecution for an actual
waiting-input peer must reply, no preparing response for the blocked request may
arrive, and a native process snapshot must contain only that peer under the host.
The target also writes its PID before reading stdin, so missing byte-count and
target markers cannot mask an already-launched waiting target. Normal release
must transmit the real file bytes, permit a gated target, confirm its native
exit 7, and match exactly one terminal to the durable audit. Ordered peer input
EOF completes the peer independently. On transport EOF, the host must exit at
its original cleanup budget while the file owner is still held; releasing the
file afterward cannot launch the target, and the peer's native handle must be
signaled. Only fixture handles/processes are closed before assertions. Restoring
synchronous controller admission blocks version control and fails this test
after those owned resources are cleaned. This establishes public ordinary
file-input admission and disconnect behavior for `danger-full-access`; it does
not establish sandbox profiles, blocked policy-state writes, native credentials
or setup, managed proxy repair, or the complete startup/cleanup matrix.

Host cleanup duration is now frozen from `RUNSEAL_CLEANUP_TIMEOUT_MS` and
reported in capabilities. A public ordinary-file oplock fixture holds file
admission across transport EOF with 500 ms and 1500 ms budgets in both RPC
and service. Host exit must occur while the fixture owner still holds the file,
within the configured bound; the longer budget must produce a correspondingly
longer wait. Releasing the file afterward cannot run the target. Restoring the
former fixed ten-second control clock fails this regression after owned cleanup.
Startup invalid-value tests cover the new setting and preserve rejection before
any target plus non-disclosure of the configuration sentinel. Default control,
preparation confirmation, local process cleanup, session disposal and terminal
retention snapshots use the frozen host duration. The retention callback also
uses bounded send plus the same remaining deadline for reply; it cannot gain a
new full wait. This proves the public host admission cleanup clock; termination
upgrade grace, helper-local ceilings, all sandbox profiles and native setup/repair
remain separate evidence requirements.

The vendored `control::tests` cover the duplex output-close boundary without
setup or sandbox identity changes. A normal real socket pair preserves pending
output bytes and independently delivers input EOF. A second fixture injects an
owned worker that performs the actual output half-close, then holds its native
FLS exit callback after Rust completion. Close must return a timeout within its
original 100 ms budget; a ten-second retry cannot extend it, and the last clone's
Drop must retain the unconfirmed worker. The fixture observes socket EOF and
native pending state before releasing and reaping only its own worker. Restoring
the Rust-only completion predicate blocks in join and fails this test after
fixture cleanup. This is native close-owner evidence, not public sandbox or
helper-process fault coverage. Run it with
`cargo test --manifest-path vendor/codex-windows-sandbox/upstream/Cargo.toml --lib control::tests:: -- --test-threads=1`.

Runner cleanup configuration is tested through actual framed native pipes and
the production request decoder. Missing/out-of-range budgets, non-integer values,
and previous IPC versions are rejected; errors omit the injected string sentinel.
A sixty-second budget is not clamped to the former ten-second default, and a
shorter adopted deadline remains sticky. For 100 ms and 350 ms budgets, native
process fixtures give the runner only a synchronization handle, so its real
termination attempt is denied. The production native wait must expire while
the target still waits for fixture input, for both local and adopted clocks.
Only then does the fixture release/reap that process and confirm exit code 7.
Restoring a fixed ten-second runner budget fails after fixture cleanup. Run
`cargo test --manifest-path vendor/codex-windows-sandbox/upstream/Cargo.toml --bin runseal-command-runner -- --test-threads=1`.
This covers runner decoding and native wait behavior; it does not establish the
complete credential-backed capture chain, all sandbox profiles, termination
upgrade grace, or setup/repair faults under nondefault settings.

The capture parent's configured-wait fixture keeps the real native runner-output
pipe writer open. With no shared cleanup-deadline callback, 100 ms and 350 ms
tokens must still expire frame reception with a typed cleanup error before that
writer is released. This covers the configured fallback path independently of
runner-side waiting, without claiming a complete sandbox capture.

The controlled preparation-timeout regression also requires the configured
`timeout_ms`, the stable timeout reason, and exactly one timeout resource-limit
event before the durable terminal, while the target never starts. An earlier
accepted cancellation must not generate a timeout-limit event. This closes the
pre-spawn path that could omit timeout details and the audit limit record; the
unchanged black-box RPC timeout tests cover the same result and audit fields.

`runseal repair execution-gates` has unit coverage in `backend::policy_epoch::
execution_gate_repair_tests` and CLI coverage in `tests/cli_contract.rs`. A
prepared-host-only `live_process_census_enumerates_every_session_without_unknown_owners`
test exercises the actual WTS and local-group APIs; it runs with
`--include-ignored` and is not generic-host passing evidence. A
recorded owner that is still live must refuse the repair without modifying any
state. A reservation whose owner is provably gone, whose binding has no
sandbox-identity process, and whose runtime roots were recorded and are absent
must clear the reservation, the cleanup-failure marker, and the native quarantine
signal, after which the binding admits again. The live Windows census runs
from an elevated Administrator token, validates the sandbox identity group,
and checks process ownership across every session. If session or identity
enumeration is unavailable, the repair stays closed; `--accept-unverified-release`
cannot bypass that boundary. A reservation without recorded runtime roots or a
process owner that remains uninspectable after complete enumeration is unverified
evidence, so the default repair must refuse it. The explicit override only
accepts those unverified cases and the report marks what stayed unverified. The
CLI help and unknown-argument handling are asserted separately.

`execution_capability_profiles_are_complete_and_consistent` in
`tests/protocol_contract.rs` requires `getCapabilities` to report all 13
fine-grained execution capabilities with valid statuses, to keep
`mixed_policy_concurrency` unsupported, and to enumerate one `execution_profiles`
row per sandbox level, network mode, and io mode. Each row must reject the
capabilities that its io mode does not provide (PTY rows have no `stdin_bytes`,
`stdin_file`, or `control_channel`; pipe rows have no `pty*`), and a row is
requestable exactly when its sandbox level and network mode are supported and its
io mode is available. Removing a field or reusing a single coarse status fails it.

A backend that fails before it reports a real spawn cannot have left a process
range. `adv.filesystem.preexisting-symlinked-runtime-root.v1` is the regression:
the pre-launch setup refusal must report `EXECUTION_FAILED_TO_START` with
`cleanup_complete:true` and `termination_reason:failed_to_start`, must release the
policy reservation, and must leave the binding admissible. Treating that
pre-launch error as unverifiable cleanup quarantines the machine binding, fails
the case, and blocks every later sandboxed execution.

`windows_preparation_timeout_aborts_cleanly_without_quarantining_the_binding` in
`tests/execution_conformance.rs` runs a real service with `timeout_ms:100` on a
Windows sandboxed policy. The deadline expires while the machine sandbox home is
still being prepared, before the vendored runner receives any spawn request. The
terminal must stay `EXECUTION_TIMEOUT` with `termination_reason:timeout` and
`cleanup_complete:true`; a following
sandboxed execution in the same service must admit and finish. The equivalent case
is `adv.process.orphan-child-after-cancel.v1`. Classifying the cancelled
preparation as unverified cleanup instead quarantines the shared binding and
blocks every later sandboxed execution until an explicit repair.

`cli_stalled_console_output_cleans_owned_range_and_preserves_peer` and
`sandboxed_stalled_console_output_cleans_owned_range_and_preserves_peer` cover
stalled plain-console output with local and sandboxed execution. RunSeal forwards
console bytes through an owned helper process; when backpressure or timeout
requires cancellation, cleanup terminates and waits for that process before
reporting completion. The local test runs on generic Windows. The sandboxed test
requires a prepared Windows identity and remains ignored on generic Windows CI;
its result is pending and is not counted as an acceptance pass.
