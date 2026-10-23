# macOS native PTY/control owned-process boundary

Status: implemented experimental path and evidence note. This document does not
promote macOS PTY or control-channel support to a supported lifecycle claim, and
it does not claim that every macOS version satisfies this boundary.

## Scope

The native guardian path serves RPC `io.mode: "pty"` and `io.mode: "pipe"` with
`io.control`. Ordinary pipe executions stay on the existing non-guardian path.
The path requires an interactive per-user GUI launchd domain (`gui/<uid>`); it
does not install a persistent agent or daemon and does not use root.

The macOS PTY, resize, interrupt, and control capabilities remain
`experimental`. Their lifecycle evidence is bounded by the platform and test
matrix below; it is not a general macOS support statement.

## Implemented topology

For each native execution RunSeal creates a transient per-user launchd job and a
trusted guardian process:

1. The job label, attempt socket, plist, and recovery manifest live under a
   short per-user protected directory
   `/tmp/runseal-<uid>/<128-bit attempt>/`.
   The parent is created `0700`, owned by the current UID, and rejected if it is
   a symlink or has different ownership/mode.
2. The controller writes a structured `0600` ownership manifest before any
   `LaunchSpec`, with owner birth identity (`pid`, `idversion`, `uniqueid`),
   `kern.bootsessionuuid`, job label, execution id, cwd, runtime root, and an
   explicit admission phase.
3. The controller bootstraps the job through `launchctl bootstrap gui/<uid>`
   with a random label. The plist is temporary and is never written into
   `~/Library/LaunchAgents`; no persistent service is installed.
4. The controller creates a private Unix listener inside the attempt directory.
   The guardian is the only process that spawns the requested command. The
   guardian connects back, authenticates the controller's peer PID and PID
   version plus a per-execution token, verifies its launchd main PID, and then
   receives the private `LaunchSpec`.
5. The guardian spawns the command inside the job's resource coalition. All
   descendants inherit that coalition across `fork`, `exec`, `posix_spawn`,
   `setsid`, double-fork, and reparenting. The guardian is the coalition keeper.
6. PTY/control I/O and control frames are exchanged over the authenticated
   per-execution socket. The guardian, not the RunSeal process, owns the
   execution-side PTY/control endpoints.

The controller is outside the execution coalition. A second process cannot
drive the guardian without matching the peer PID/version and token.

## Cleanup and lifecycle proof

For a native execution, `cleanup_complete: true` is not produced by the guardian
alone and is not inferred from a PID scan. The controller must observe all of
the following:

1. The guardian's `Done` facts show its I/O and child work have settled.
2. The guardian kernel birth identity has actually exited.
3. The execution coalition's kernel counters are readable while the job is
   still registered and show `started == exited` with zero active tasks.
4. That positive zero state is persisted atomically in the ownership manifest as
   a `Drained` phase with the actual `tasks_started`/`tasks_exited` proof,
   before job bootout.
5. The job is booted out and its label is verifiably absent.
6. The plan-validated runtime root is removed.
7. Only then is the ownership record deleted.

Cleanup termination uses the saved coalition resource id and audit-token
signalling for identified members; the guardian keeper is excluded from the kill
set while it performs cleanup. `ESRCH` is never treated as zero. A missing or
unreadable counter, a permission/ABI error, a non-empty coalition, a failed
bootout, or an unsafe runtime-root path leaves cleanup unconfirmed.

On host-kill or disconnect, the client may receive no terminal result. The
guardian still detects the broken controller channel, closes execution admission,
evacuates the coalition, and exits. A later RunSeal instance performs startup
recovery before admitting new work.

## Crash recovery and record protection

The ownership record is protected independently of the sandbox workspace:

- the per-user record parent is `0700`, UID-checked, non-symlink, and is the
  only directory startup recovery scans;
- restricted sandbox profiles deny read, write, and read-metadata for the whole
  record parent, not just the current attempt;
- a `0600` owner lock is held for the lifetime of a normal controller session;
  recovery competes for that lock and skips a live owner;
- the manifest uses `Prepared`, `Admitted`, and `Drained` phases. `Admitted`
  records are only reclaimed when the owner birth identity is dead, the boot
  session UUID matches, the job is still registered, the label/argv/directory
  match, and the saved coalition can be atomically cleaned with a positive
  kernel-zero read;
- manifest commit is `0600` write + file fsync + atomic rename + parent-directory
  fsync. A directory fsync failure is reported as an error; the live controller
  does not claim the `Drained` commit or proceed to bootout/record deletion;
- `Drained` records carry the persisted positive counter proof and may finish
  bootout/runtime cleanup after the job is already gone, without rereading
  counters or treating `ESRCH` as zero;
- an admitted record whose job is already absent is unknown and is not cleaned
  or silently skipped;
- if a recovery scan enumerated a record and another concurrent recovery
  normally removed it, the resulting `ENOENT` is classified as a skip. A
  directory that still exists with an admitted record but a missing, unsafe, or
  mismatched lock/manifest is still unknown and blocks admission;
- unknown, corrupt, permission-denied, or ABI-failing current-boot records are
  retained and block new execution admission; cross-boot records are retained
  and skipped without ever using their saved CIDs;
- capabilities may only report that same-boot recovery is blocked.

This recovery path does not require a daemon, a system launchd job, root, or a
new RunSeal RPC surface.

## Permissions and domain requirements

- **Required domain:** an interactive GUI login session for the current user, so
  `launchctl bootstrap gui/<uid>` is available. Headless/SSH-only contexts
  without that domain are not claimed to work; the path fails closed rather than
  falling back to the old weak lifecycle path.
- **No root or sudo:** the implementation does not install a root helper or a
  privileged LaunchDaemon.
- **No additional entitlements:** it does not use the EndpointSecurity
  entitlement, TCC grants, or private coalition-spawn entitlements.
- **No persistent service:** no LaunchAgent plist is written into
  `~/Library/LaunchAgents`; transient job artifacts and the protected record are
  removed after proof.
- **No system-permission change:** no firewall, account, SIP, or system
  configuration change is performed.
- **Standard kernel reads:** coalition membership and counters use the public
  libproc paths already exercised by the probe.

## Boundaries that remain unproven

- **OS coverage:** verified on macOS 15.7.8 arm64 only. Launchd/coalition
  behavior must be revalidated on other macOS versions; this document does not
  claim all versions.
- **Sandbox-to-coalition escape:** the security argument assumes a restricted
  execution cannot obtain a process in a different launchd job/coalition. The
  current conformance suite does not prove that guarantee for every macOS
  configuration, so this remains an experimental boundary rather than a general
  sandbox-escape proof.
- **Power loss and guardian death:** no cleanup is claimed without a positive
  kernel proof. A `Drained` proof is written and fsynced before bootout; a
  manifest fsync failure is surfaced as an error/retained record rather than a
  successful cleanup claim. In the same boot, unreadable counters or an absent
  registered job for an admitted record are unknown and block new admission. A
  record from another boot is retained and skipped without signalling a
  current-boot process.
- **Headless/multi-user transitions:** only a standard per-user GUI domain was
  exercised. Fast user switching, remote/headless sessions, and multi-user
  concurrency are not claimed.
- **Danger-full-access:** `danger-full-access` PTY/control still uses the cohort
  for lifecycle ownership, but it intentionally has no sandbox; it is explicit
  local execution, not a sandboxed execution.

## Native conformance coverage

`tests/macos_native_io_conformance.rs` covers:

- real PTY identity, dimensions, input, resize with a real child SIGWINCH
  handshake, and raw ETX;
- native foreground-group SIGINT with `target_process_group_id`;
- control descriptor 7 with byte-exact large transfer, segmentation, and
  half-close;
- pipe-mode control close without a false peer EOF;
- explicit cancellation of a live `setsid` escape;
- fast double-fork/reparent cleanup with positive cohort completion;
- danger-full-access PTY and control as explicit local execution;
- capability reporting that keeps native transports experimental.

The unit tests cover manifest parsing, admission phases, protected-record
recovery classification, dead-owner/boot-session checks, and the difference
between skipped, blocked, and removed records. A recovery fixture uses a
queryable PID-reuse birth identity rather than a privileged PID so that owner
death is positively observed without turning `EPERM` into a dead-owner result.

## Verification record

On macOS 15.7.8 arm64, the nine native conformance cases passed both serially
and across nine concurrent test threads. Strict Clippy passed on Windows and
macOS.

The remote owner-hard-kill recovery acceptance suite passed on the same host:
two separate RPC owners were hard-killed while READY; the guardian and child
disappeared and both coalitions reported `tasks_started == tasks_exited == 5`
with zero active tasks; an invalid admitted coalition id blocked a new execution
without a `Started` event; the next instance automatically removed the old job
and record; PTY and control retries passed, including two 98,304-byte control
round trips and cancellation retries. A concurrently live owner kept its
owner/child identities, active coalition count 2, record, and job, and was not
signalled.

These are finite regression results for the tested host and profiles, not a
claim about every macOS version, every scheduling race, or every sandbox escape
route. No supported capability promotion or release follows from them.
