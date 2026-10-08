# Vendor

This directory is reserved for upstream code that RunSeal vendors instead of
rewriting.

The Windows sandbox enforcement baseline should come from the upstream Windows
sandbox crate. Keep RunSeal-specific code in `src/` focused on protocol, policy
mapping, audit output, capability reporting, and conformance tests.

Do not paste new low-level Windows ACL, restricted-token, WFP, setup-helper, or
command-runner implementations into the main crate. Add them here only as a
tracked upstream vendor import with a small RunSeal adapter.

The real-time Execution adapter extends the vendored capture boundary with
incremental output callbacks, exact bytes/file/stream input, and cancellation.
Internal runner IPC version 11 acknowledges stdin/control only after the child pipe write
completes. Capture callers keep one chunk in flight; the runner uses a bounded
input writer separate from its control reader so blocked stdin cannot prevent
termination. These are backend-private transport details, not public API fields.
The runner verifies that the entire execution range has no active processes before
sending a successful cleanup acknowledgement, including natural top-level exit.
Runtime-root cleanup must also succeed before the adapter reports cleanup complete.
Execution notes omit command contents and arbitrary diagnostic bodies; process-launch
errors and unexpected-frame errors also omit argv, environment values, and payloads.
Public behavior and limits are defined by the Execution protocol contract;
helper and main binaries must be built together.

The initial runner request carries a mandatory, validated cleanup wait budget
from the host's frozen deployment settings. Runner-owned cleanup clocks use that
budget for natural exit, disconnect, and adopted termination deadlines, retaining
the earliest deadline. Missing or invalid budgets and older IPC versions fail
closed before child creation; malformed frame errors omit payload contents.

Explicit local Windows execution uses the current identity through the same process
primitives. Its child starts suspended, joins its owned lifecycle range, and resumes
only after assignment succeeds. This applies no sandbox policy, token restriction,
filesystem mutation, network guard, or setup requirement. Cleanup verifies the range
and the real process exit status before returning; dropping the host's range handle
also terminates its descendants on host death.

Windows local execution exposes buffered pipe availability through the vendored
boundary. The adapter drains available output after verified process-range cleanup
and bounds owned input/output thread joins with one cleanup deadline. It waits for
thread completion after synchronous I/O cancellation; failed joins prevent a
successful cleanup report. The sandboxed runner also drains buffered output after
range cleanup and joins its input, output, control, and terminal-close workers
before acknowledging success, including cancellation and timeout. Its worker
joins share a deadline. Real pipe tests retain an external writer reference and
verify binary output drainage. Runner timeout waits preserve the full duration
and report the actual process exit status after termination. Cross-process
deadline coordination and the complete teardown fault matrix remain pending.

The capture parent owns its input writer and bounds cancellation/join after the
runner result. An expired deadline retains the unfinished owner and prevents a
successful cleanup result. A real full-pipe frame test verifies cancellation
and subsequent join while the read endpoint remains open. A runner exit frame
keeps its verified native status even when range, control, or I/O cleanup fails.
The capture parent preserves that status and timeout flag through a failed or
expired input-worker join. Native process and pipe tests distinguish a live
process with unknown exit status from natural exit 7 and terminated exit 1.
Known exit status never constitutes range-cleanup proof. Missing cleanup confirmation after runner readiness fails
closed and cannot release the shared state as safe. Capture response reads now
poll available native pipe bytes, including incomplete headers and payloads.
Cancellation, a declared execution timeout, or a failed input worker starts the
parent phase's bounded cleanup wait; response waiting and input-worker join use
that same deadline. Drop does not renew an expired deadline, and an unfinished
worker remains owned in quarantine until it can be joined. Native pipe and real
peer-process tests verify refusal while the writer remains open. Preparing,
runner, and frontend coordination into one cross-process cleanup budget, plus
the full teardown fault matrix, remain pending.

A joined input-source failure after confirmed runner cleanup carries a typed
input error with the actual exit code and timeout flag. The adapter retains those
facts and reports `EXECUTION_INPUT_FAILED` after its runtime-root cleanup succeeds;
failed runtime-root cleanup takes precedence and preserves the original cause.
Source and acknowledgement errors notify the lifecycle owner promptly. A real
child-input EOF test and a local-engine fault-injection test cover these reporting
paths without modifying machine sandbox state.

Shared-state admission now uses the same OS execution binding across runtime-home
aliases and resolves a machine state directory with an explicit native token.
The adapter requires the gate before setup/repair and adds that directory to the
vendored write-denial boundary. It does not add a new ACL implementation. Native
state directories and binding identifiers stay private; public failures expose
generic admission or capability errors.

The host reservation includes native process creation time. A dead host,
unverifiable owner, or reused process identifier leaves its reservation in place
and blocks both policies until cleanup can be proven. Healthy peer release never
prunes those records. This does not yet implement explicit recovery or repair.

Cleanup failure retains the reservation before attempting marker persistence.
The vendored host-coordination factory creates a non-inheritable event with a
protected host/System-only DACL, verifies ownership before hardening a reopened
object, and preserves its signaled state. The adapter retains this signal for the
host lifetime, so failed marker writes cannot permit reuse by a healthy peer.
Native fixtures verify the event security descriptor, object-type collision
refusal, and observation by another process after the failed owner guard drops.
Different-principal access, reboot, recovery, and the full fault matrix remain
unverified.

Native CLI output publishes completed native writes separately from whole-chunk
acknowledgements. The frontend resets its stall timer on this progress; bounded
Console writes avoid splitting a UTF-16 surrogate pair. A real pipe fixture drains
one chunk over more than five seconds, verifies intermediate completions and exact
bytes, and fails when progress publication is disabled. A public local CLI
regression retains a real Console consumer and paces its reads during an active
execution. It verifies supplementary characters, unchanged CP437, native exit 7,
complete output counts, and one durable terminal; disabling progress refresh
causes a false backpressure exit. The sandboxed paced case remains unverified.

Local process-range and CLI frontend cleanup callbacks now receive the host
lifecycle's absolute deadline. Output, stdin, resize, and control cleanup consume
one frontend budget capped by that deadline. Drop cannot renew an expired I/O
deadline; unfinished native output and host I/O workers retain their join owners.
Real pipe/peer-process fixtures verify retention and bounded return, then release
and join only their own resources. Preparing and the runner/capture-parent
cross-process deadline, general observer delivery after backend cleanup starts,
failed terminal-mode recovery, and the full fault matrix
still require implementation and conformance evidence.

Runner preparation now uses one bounded budget for both connections, the spawn
request write, and incremental startup confirmation. Cancellation and execution
timeout are checked during waits. Connect/write workers own their pipe handles;
expired cleanup retains unjoined owners. A suspended runner's process and thread
are owned before security setup, so a setup error cannot bypass process cleanup.
Startup failure still reports unverified cleanup: stopping the runner alone does
not prove its descendants or shared resources were released. Preparation I/O and
capture-parent response/input cleanup use the host's supplied absolute deadline.
Native pipe and peer-process fixtures cover incomplete confirmations, cancellation,
retained connect ownership, suspended-process setup failure, and an already-expired
shared deadline. Native setup, the complete helper deadline, explicit repair,
and the full sandboxed startup fault matrix remain pending.

The native runner launch call now runs in an owned worker while the caller polls
the same preparation and cleanup deadlines. Expiry retains the worker, its inputs,
and eventual process/thread ownership. A late suspended process is stopped before
security setup or resume. Parent and worker clones share one cleanup deadline;
Drop cannot grant the late process a fresh grace period. A current-caller native
fixture deliberately creates a suspended process after parent expiry and verifies
native exit 1 without target execution. An unbounded join fails this regression.
This does not exercise credential logon or prove repair of a permanently blocked
native call, complete setup cleanup, or host-death resource recovery.

The runner's output, input, control, and terminal-close workers now have lifecycle
owners. An expired join or an earlier cleanup error retains unfinished sibling
workers rather than detaching them. Joins require the native thread to have ended;
Drop does not start a new grace period. A real pipe fixture covers both paths and
releases and joins its own workers before asserting retention. This does not
prove recovery after the runner exits.

Final cleanup reports now use that cleanup phase's absolute deadline for writer
lock acquisition and native writes. A blocked write is cancelled at expiry;
unfinished report workers remain owned and failed delivery cannot confirm cleanup.
Real held-lock and full-pipe fixtures require the call to return before their
blockers are released. Replacing bounded delivery with synchronous delivery fails
the regression. First-cause clock coordination with the host and the complete
helper cleanup budget still need implementation and evidence.

The runner's startup request reader now polls incomplete frames under one local
preparation deadline. Startup errors and the ready confirmation use bounded
report delivery with that same deadline; process creation and resume refuse an
already-expired preparation budget. A native pipe fixture retains empty, partial
header, and partial payload writers until the reader expires. Restoring blocking
frame reads fails that regression. This does not prove bounded native setup or
partial-spawn cleanup; those require separate lifecycle evidence.

Within the runner, control failure or a termination request starts one cleanup
clock before the native termination attempt. Process waiting and subsequent
cleanup reuse it, including when termination is refused. Cleanup expiry is not
an execution timeout. Terminal-control error delivery follows termination and is
bounded by the same clock. A real gated process with a wait-only handle verifies
that a refused termination cannot renew a previously established deadline or
wait indefinitely for process exit. This runner-local clock still needs host
coordination across preparing and transport delays.

Runner termination requests now terminate the owned execution range first,
falling back to the root process only when the range termination call fails.
Control workers share ownership of the range until they finish. A real framed
termination and a pipe disconnect both stop a native root process and its child
while an independent peer continues writing a heartbeat. Native exit observations
precede fixture cleanup, and disabling range termination fails the regression.
Successful termination requests still require the existing range and I/O cleanup
confirmation; they do not by themselves prove shared-resource recovery.

Cancellation frames carry the host's established cleanup deadline in the native
monotonic clock domain. The runner adopts the earlier of that deadline and its
local deadline, accounting for transport delay; an expired host deadline stays
expired. Missing deadline payloads are rejected, and native clock failure selects
expired cleanup rather than renewing a budget. Real transport, delayed peer-clock,
and runner control fixtures cover these paths. This covers delivered cancellation
frames; blocked or lost transport, natural completion, setup, and recovery still
need end-to-end deadline coordination and conformance evidence.

The runner also announces cleanup after process completion, with its existing
deadline and any confirmed native exit facts. The host adopts the earlier deadline
for parent I/O and frontend cleanup and preserves an already-accepted cause.
Confirmed natural exit is accepted before cleanup delivery can encounter a later
timeout. Missing or duplicate cleanup announcements fail closed; a failed runner
announcement cannot report complete cleanup. Range termination precedes delivery
so a blocked report cannot keep descendants running. Real native process and pipe
fixtures cover known versus unknown exit facts and delayed notification while
the final result remains withheld. Lost or blocked announcements and setup still
require independent deadline coordination and the full sandboxed fault matrix.

CLI Console/byte output and control forwarding poll the host cleanup deadline
during delivery, independently of their no-progress timers. A real paced local
Console case verifies refusal after command exit, native exit facts, retained
unfinished frontend ownership, and a unique cleanup-failure terminal. The full
sandboxed and general observer-delivery matrix remains pending.

The private runner request includes the initial PTY dimensions. ConPTY is created
with those dimensions before command-process creation; later resize commands use
the existing native terminal boundary. Capture maps merged terminal bytes to the
terminal stream. IPC versions must match; stale helper frames are refused.

Terminal interrupt uses the native ConPTY input boundary and does not terminate the
sandbox job. Before spawning a terminal process, the helper restores normal Ctrl+C
processing so it cannot inherit the caller's ignore attribute into the execution.
Interrupt input is not acknowledged as application stdin bytes.

Local terminal executions use the current identity with the same suspended-spawn
and owned-job lifecycle boundary as local pipe executions. They do not apply
sandbox policy enforcement. ConPTY close and I/O joins share the cleanup deadline;
terminal controls use the existing input writer. Hosted stdio cannot inherit the
protocol connection's redirected handles. The shared command-line builder quotes
and normalizes only the program path; argument bytes are preserved.

The local control primitive maps one inherited CRT descriptor at logical fd 3,
using an OS-local duplex byte stream and an explicit child handle list. Both
endpoints are checked against the creating process before launch, and the
transient namespace is removed before the child starts. Parent I/O is nonblocking;
input half-close retains reverse output. The owned process range retains an output
endpoint until verified cleanup, then sends EOF so CRT handle closure cannot discard
unread output. The restricted runner and RPC now use this primitive with separate bounded input
windows and actual-write acknowledgements. CLI fixed descriptor forwarding now uses a validated owned duplicate with nonblocking
I/O; the remaining control fault matrix still requires conformance evidence.

Redirected CLI output uses an owned duplicate of the caller pipe in nonblocking
mode and restores its original wait mode on drop. Real anonymous-pipe tests cover
binary preservation, a full buffer, a closed reader, and wait-mode restoration.
The execution frontend bounds a no-progress interval and observes prior cancellation
causes. Native Console/file output uses independently owned, bounded write workers;
cleanup cancels synchronous I/O and requires a joined worker. Deadline failure
retains the unfinished worker until owner disposal. Console output uses Unicode
writes and a bounded UTF-8 tail; caller code pages stay unchanged. File writes
retain original bytes. Real blocked-pipe, binary-file, and public Console tests
provide targeted evidence; the complete fault matrix remains pending.
