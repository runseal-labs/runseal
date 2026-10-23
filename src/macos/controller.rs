//! Controller side of the macOS guardian execution path.
//!
//! The controller owns a per-attempt record beneath the short per-user parent
//! `/tmp/runseal-<uid>` (0700, owner-validated). It creates the attempt
//! directory, owner lock, structured 0600 ownership manifest, socket, and plist
//! before registering the job, authenticates the guardian through both
//! `LOCAL_PEERTOKEN`s and the job's launchd main PID, sends the private
//! `LaunchSpec`, and bridges the execution's I/O and control frames.
//!
//! Completion requires the guardian's own `Done` facts, the guardian kernel
//! identity actually exiting, the execution coalition counters reaching
//! `started == exited` with zero active tasks while the job is still
//! registered, a verified bootout, plan-validated runtime cleanup, and only
//! then ownership-record removal. Any unproven step keeps the record on disk and
//! reports failure; startup recovery may only reclaim same-boot admitted
//! records after proving a dead owner birth identity and kernel zero.

use crate::backend::{
    BackendExecutionOptions, BackendExecutionOutput, ExecutionEnv, ExecutionInput,
    ExecutionOutputSink, ExecutionStdin, InputPoll, OutputStream, PlatformSandboxPlan,
};
use crate::execution::{ExecutionControl, TerminalCommand, TerminationCause};
use crate::macos::cohort::{self, ProcessIdentity};
use crate::macos::guardian::{self, LaunchdCohortJob};
use crate::macos::process::prepared_environment;
use crate::macos::wire::{
    self, ControllerFrame, GuardianFrame, LaunchSpec, WireInput, WireIo, WireStdin, WireStream,
};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const LOCAL_PEERTOKEN: libc::c_int = 6;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const FRAME_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const TRACK_INTERVAL: Duration = Duration::from_millis(10);
const FRAME_QUEUE: usize = 16;
const MAX_FRAMES_PER_READ: usize = 16;
const MAX_READ_BYTES_PER_CALL: usize = 256 * 1024;
const MAX_READ_TIME_PER_CALL: Duration = Duration::from_millis(10);
const MAX_BUFFERED_BYTES: usize = wire::MAX_FRAME_BYTES + MAX_READ_BYTES_PER_CALL;
const MARKER_BYTES: usize = 256;
const RECORD_ROOT: &str = "/tmp";
const RECORD_PARENT_PREFIX: &str = "runseal-";
const RECORD_ATTEMPT_PREFIX: &str = "rs-";
const LOCK_FILE: &str = "owner.lock";
const MANIFEST_FILE: &str = "ownership.json";
const MANIFEST_TEMP_FILE: &str = "ownership.json.new";
const MANIFEST_VERSION: u32 = 1;
const PLIST_BYTES: usize = 64 * 1024;
const MANIFEST_BYTES: usize = 64 * 1024;
const RECORD_LABEL_PREFIX: &str = "com.runseal.cohort.";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct BirthIdentity {
    pid: i32,
    idversion: u32,
    uniqueid: u64,
}

impl BirthIdentity {
    fn of(identity: &cohort::ProcessIdentity) -> Self {
        Self {
            pid: identity.pid,
            // Both sides hold the same 32-bit kernel pidversion bits.
            idversion: identity.idversion as u32,
            uniqueid: identity.uniqueid,
        }
    }

    fn identity(&self) -> cohort::ProcessIdentity {
        cohort::ProcessIdentity {
            pid: self.pid,
            idversion: self.idversion as i32,
            uniqueid: self.uniqueid,
        }
    }

    /// True only when the exact birth identity (PID + pidversion + unique id)
    /// is still alive. ESRCH means dead; other observation errors are errors.
    fn is_live(&self) -> io::Result<bool> {
        match cohort::snapshot(self.pid) {
            Ok(snapshot) => Ok(snapshot.identity.same_process(&self.identity())),
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardianRecord {
    identity: BirthIdentity,
    resource: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AdmissionPhase {
    Prepared,
    Admitted,
    /// Persisted after a live positive kernel-zero read and before bootout. A
    /// recovery that sees this phase may finish bootout/runtime cleanup without
    /// re-reading counters (especially after the job is already gone).
    Drained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DrainedProof {
    tasks_started: u64,
    tasks_exited: u64,
}

impl DrainedProof {
    fn from_usage(usage: cohort::CohortUsage) -> Self {
        Self {
            tasks_started: usage.tasks_started,
            tasks_exited: usage.tasks_exited,
        }
    }

    fn is_complete(&self) -> bool {
        self.tasks_started == self.tasks_exited
    }
}

/// Structured recovery record written before any `LaunchSpec` is sent. It is
/// the only source of truth for startup recovery; nothing is guessed from /tmp
/// entries, markers, or logs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct OwnershipManifest {
    version: u32,
    phase: AdmissionPhase,
    execution_id: String,
    cwd: String,
    runtime_root: Option<String>,
    job_label: String,
    owner: BirthIdentity,
    boot_session_uuid: String,
    guardian: Option<GuardianRecord>,
    /// Present only in `Drained`: the counter proof read while the job was still
    /// registered. Never inferred from ESRCH.
    drained: Option<DrainedProof>,
}

/// Owns the per-attempt flock for the lifetime of a normal controller session.
/// Dropping the record releases the lock but never deletes recovery evidence.
struct OwnershipRecord {
    directory: PathBuf,
    _lock: fs::File,
}

impl OwnershipRecord {
    fn acquire(directory: &Path) -> io::Result<Self> {
        let lock_path = directory.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)?;
        lock_exclusive_nonblocking(&lock)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            _lock: lock,
        })
    }

    fn write_manifest(&self, manifest: &OwnershipManifest) -> io::Result<()> {
        write_manifest_atomic(&self.directory.join(MANIFEST_FILE), manifest)
    }

    fn remove(&mut self) -> io::Result<()> {
        fs::remove_dir_all(&self.directory)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DoneFacts {
    exit_code: Option<i32>,
    exit_signal: Option<i32>,
    timed_out: bool,
    io_joined: bool,
    children_drained: bool,
}

fn record_parent_path() -> PathBuf {
    Path::new(RECORD_ROOT).join(format!("{RECORD_PARENT_PREFIX}{}", unsafe {
        libc::geteuid()
    }))
}

/// The only directory startup recovery scans: per-user, 0700, owned by us, and
/// never a symlink.
fn ensure_record_parent() -> io::Result<PathBuf> {
    let parent = record_parent_path();
    match fs::symlink_metadata(&parent) {
        Ok(metadata) => {
            validate_owned_directory(&metadata, &parent)?;
            Ok(parent)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&parent) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            let metadata = fs::symlink_metadata(&parent)?;
            validate_owned_directory(&metadata, &parent)?;
            Ok(parent)
        }
        Err(error) => Err(error),
    }
}

fn validate_owned_directory(metadata: &fs::Metadata, path: &Path) -> io::Result<()> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to use an unowned or unsafe guardian record directory: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn lock_exclusive_nonblocking(file: &fs::File) -> io::Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "guardian ownership record is locked by a live owner",
            ));
        }
        return Err(error);
    }
    Ok(())
}

fn write_manifest_atomic(path: &Path, manifest: &OwnershipManifest) -> io::Result<()> {
    let bytes = serde_json::to_vec(manifest).map_err(|error| {
        io::Error::other(format!("ownership manifest encoding failed: {error}"))
    })?;
    let temporary = path.with_file_name(MANIFEST_TEMP_FILE);
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    // The manifest is the durable recovery contract, especially for `Drained`.
    // A failed directory fsync means the rename is not a reliable commit: return
    // the error and let the caller keep the lifecycle unproven.
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ownership manifest path has no parent directory",
        )
    })?;
    let directory = fs::File::open(parent)?;
    directory.sync_all()?;
    Ok(())
}

fn read_owned_file(path: &Path, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Ok(None);
    }
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    let take = u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX);
    file.take(take).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn parse_plist_label(bytes: &[u8]) -> Option<String> {
    const KEY: &str = "<key>Label</key><string>";
    let text = std::str::from_utf8(bytes).ok()?;
    let start = text.find(KEY)? + KEY.len();
    let rest = &text[start..];
    let end = rest.find("</string>")?;
    let label = &rest[..end];
    if label.len() > 128
        || !label.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_'
        })
    {
        return None;
    }
    Some(label.to_string())
}

fn is_attempt_record_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(RECORD_ATTEMPT_PREFIX) else {
        return false;
    };
    suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Spawn one execution through a transient launchd guardian. The old local
/// `sandbox-exec` PTY/control path is never used as a fallback: any failure
/// here is returned to the caller.
pub(crate) fn spawn_guardian_execution(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    base_profile: &str,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    options: BackendExecutionOptions,
) -> io::Result<BackendExecutionOutput> {
    let BackendExecutionOptions { timeout, output } = options;
    let Some(output) = output else {
        return Err(io::Error::other(
            "macOS guardian execution requires an output sink",
        ));
    };
    if !output.io.is_pty() && !output.io.has_control() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "macOS guardian execution requires a PTY or control transport",
        ));
    }
    if output.control.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "execution cancelled before guardian startup",
        ));
    }
    let controller_pid = i32::try_from(std::process::id()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "controller pid is out of range")
    })?;
    let controller_snapshot = cohort::snapshot(controller_pid)?;
    let controller_resource = controller_snapshot.cohort.resource;
    // Audit-token pidversion is a 32-bit kernel bit pattern, not a positive
    // integer; carry the raw value into the guardian argv unchanged.
    let controller_idversion = controller_snapshot.identity.idversion as u32;

    let boot_session_uuid = cohort::boot_session_uuid()?;
    let record_parent = ensure_record_parent()?;
    let mut job = LaunchdCohortJob::prepare(&record_parent)?;
    let private_dir = job.private_dir().to_path_buf();
    let socket_path = private_dir.join("guardian.sock");
    let marker_path = private_dir.join("spawn.marker");
    let mut record = match OwnershipRecord::acquire(&private_dir) {
        Ok(record) => record,
        Err(error) => {
            return Err(retained_failure(
                &job,
                format!("guardian ownership record lock failed: {error}"),
            ));
        }
    };
    let mut manifest = OwnershipManifest {
        version: MANIFEST_VERSION,
        phase: AdmissionPhase::Prepared,
        execution_id: plan.execution_id.clone(),
        cwd: plan.cwd.clone(),
        runtime_root: plan.runtime_root.clone(),
        job_label: job.label().to_string(),
        owner: BirthIdentity::of(&controller_snapshot.identity),
        boot_session_uuid,
        guardian: None,
        drained: None,
    };
    if let Err(error) = record.write_manifest(&manifest) {
        return Err(retained_failure(
            &job,
            format!("guardian ownership manifest write failed: {error}"),
        ));
    }
    let listener = match bind_listener(&socket_path) {
        Ok(listener) => listener,
        Err(error) => {
            return Err(retained_failure(
                &job,
                format!("guardian socket preparation failed: {error}"),
            ));
        }
    };
    let program = match guardian_program(
        &socket_path,
        &marker_path,
        controller_pid,
        controller_idversion,
    ) {
        Ok(program) => program,
        Err(error) => {
            return Err(retained_failure(
                &job,
                format!("guardian job program is invalid: {error}"),
            ));
        }
    };
    if let Err(error) = job.configure(&program, &private_dir, &[]) {
        return Err(retained_failure(
            &job,
            format!("guardian job configuration failed: {error}"),
        ));
    }
    if let Err(error) = job.start() {
        return Err(retained_failure(
            &job,
            format!("guardian job registration failed: {error}"),
        ));
    }

    let mut stream = match accept_guardian(&listener, &output.control) {
        Ok(stream) => stream,
        Err(error) => {
            return Err(retained_failure(
                &job,
                format!("guardian socket accept failed: {error}"),
            ));
        }
    };
    let (guardian_identity, execution_resource) =
        match verify_guardian_peer(&stream, &job, controller_resource, &output.control) {
            Ok(value) => value,
            Err(error) => {
                let _ = stream.shutdown(Shutdown::Both);
                return Err(retained_failure(
                    &job,
                    format!("guardian peer verification failed: {error}"),
                ));
            }
        };
    let expected_marker = format!("{controller_pid}:{controller_idversion}:{execution_resource}");
    if let Err(error) = wait_marker(&marker_path, &expected_marker, &output.control) {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(retained_failure(
            &job,
            format!("guardian spawn marker verification failed: {error}"),
        ));
    }
    if output.control.is_cancelled() {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(retained_failure(
            &job,
            "execution cancelled before the guardian launch spec was sent".to_string(),
        ));
    }
    // Persist the admitted phase with the real guardian identity/resource before
    // any LaunchSpec bytes are sent. Recovery only trusts admitted manifests.
    manifest.phase = AdmissionPhase::Admitted;
    manifest.guardian = Some(GuardianRecord {
        identity: BirthIdentity::of(&guardian_identity),
        resource: execution_resource,
    });
    if let Err(error) = record.write_manifest(&manifest) {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(retained_failure(
            &job,
            format!("guardian admission manifest write failed: {error}"),
        ));
    }
    // Explicit danger-full-access passes an empty profile: the guardian must
    // not add a sandbox that the plan did not request. Ownership SBPL denies
    // cover the whole per-user record parent when a profile exists.
    let protected_profile = if base_profile.is_empty() {
        String::new()
    } else {
        match guardian_protected_profile(base_profile, &record_parent) {
            Ok(profile) => profile,
            Err(error) => {
                let _ = stream.shutdown(Shutdown::Both);
                return Err(retained_failure(
                    &job,
                    format!("guardian sandbox profile is invalid: {error}"),
                ));
            }
        }
    };
    let spec = match launch_spec(
        plan,
        command,
        cwd,
        &protected_profile,
        &stdin,
        env,
        timeout,
        output.io,
    ) {
        Ok(spec) => spec,
        Err(error) => {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(retained_failure(
                &job,
                format!("guardian launch spec is invalid: {error}"),
            ));
        }
    };
    if let Err(error) = stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .and_then(|()| wire::write_frame(&mut stream, &spec))
    {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(retained_failure(
            &job,
            format!("guardian launch spec write failed: {error}"),
        ));
    }

    let control = output.control.clone();
    let bridge = run_guardian_bridge(stream, output, stdin, control.clone(), timeout);
    let deadline = control.begin_cleanup();
    match bridge {
        Ok(done) => match finalize_completed(
            &mut job,
            &mut record,
            &mut manifest,
            plan,
            guardian_identity,
            execution_resource,
            deadline,
        ) {
            Ok(()) => {
                let status = exit_status(done.exit_code, done.exit_signal)?;
                Ok(BackendExecutionOutput {
                    output: Output {
                        status,
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    },
                    timed_out: done.timed_out,
                    cleanup_complete: done.io_joined && done.children_drained,
                    events: Vec::new(),
                })
            }
            Err(error) => Err(retained_failure(
                &job,
                format!(
                    "native execution completed but launchd/coalition cleanup is unconfirmed: {error}"
                ),
            )),
        },
        Err(error) => Err(abort_execution(
            &mut job,
            &mut record,
            &mut manifest,
            plan,
            deadline,
            error,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn launch_spec(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    base_profile: &str,
    stdin: &ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
    io: crate::backend::ExecutionIo,
) -> io::Result<LaunchSpec> {
    if command.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guardian command is empty",
        ));
    }
    let cwd = cwd
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "guardian cwd is not UTF-8"))?;
    let stdin = match stdin {
        ExecutionStdin::Empty => WireStdin::Empty,
        ExecutionStdin::Bytes(bytes) | ExecutionStdin::File(bytes) => {
            WireStdin::Bytes(bytes.clone())
        }
        ExecutionStdin::Stream(_) => WireStdin::Stream,
    };
    Ok(LaunchSpec {
        argv: command.to_vec(),
        cwd: cwd.to_string(),
        env: prepared_environment(plan, env)?,
        base_profile: base_profile.to_string(),
        io: WireIo::from(io),
        stdin,
        timeout_ms: timeout.map(|limit| u64::try_from(limit.as_millis()).unwrap_or(u64::MAX)),
    })
}

/// Extend the controller-built profile with explicit deny rules for the whole
/// per-user guardian record parent directory. The sandboxed execution runs under
/// the same UID, so a broad workspace-write allow (including `/tmp`) must not
/// let it create or rewrite any record, not just its own attempt directory. The
/// deny rules are appended last so they take precedence over a broader allow.
fn guardian_protected_profile(base_profile: &str, record_parent: &Path) -> io::Result<String> {
    // `/tmp` is a symlink to `/private/tmp` on macOS. Deny both the lexical and
    // canonical parent path so a symlink-relative open cannot bypass the rule.
    let mut directories = vec![record_parent.to_path_buf()];
    match fs::canonicalize(record_parent) {
        Ok(canonical) if canonical.as_path() != record_parent => directories.push(canonical),
        Ok(_) => {}
        Err(_) => {}
    }
    let mut profile = base_profile.to_string();
    for directory in directories {
        let directory = directory.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "guardian ownership record parent path is not UTF-8",
            )
        })?;
        let directory = sandbox_literal(directory);
        profile.push_str(&format!(
            "\n(deny file-write* (subpath \"{directory}\"))\n(deny file-read* (subpath \"{directory}\"))\n(deny file-read-metadata (subpath \"{directory}\"))"
        ));
    }
    Ok(profile)
}

fn sandbox_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn bind_listener(path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    guardian::set_cloexec(listener.as_raw_fd())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn guardian_program(
    socket: &Path,
    marker: &Path,
    controller_pid: i32,
    controller_idversion: u32,
) -> io::Result<Vec<String>> {
    let executable = std::env::current_exe()?;
    let executable = executable.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "runseal executable path is not UTF-8",
        )
    })?;
    let socket = socket.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "guardian socket path is not UTF-8",
        )
    })?;
    let marker = marker.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "guardian marker path is not UTF-8",
        )
    })?;
    Ok(vec![
        executable.to_string(),
        "__macos-cohort-guardian".to_string(),
        "--socket".to_string(),
        socket.to_string(),
        "--controller-pid".to_string(),
        controller_pid.to_string(),
        "--controller-idversion".to_string(),
        controller_idversion.to_string(),
        "--marker".to_string(),
        marker.to_string(),
    ])
}

fn accept_guardian(listener: &UnixListener, control: &ExecutionControl) -> io::Result<UnixStream> {
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        if control.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "execution cancelled while waiting for the guardian connection",
            ));
        }
        match listener.accept() {
            Ok((stream, _)) => {
                guardian::set_cloexec(stream.as_raw_fd())?;
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "guardian did not connect before the accept deadline",
                    ));
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PeerToken {
    val: [u32; 8],
}

fn peer_pid(stream: &UnixStream) -> io::Result<i32> {
    let mut pid: libc::pid_t = 0;
    let mut length = size_of::<libc::pid_t>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::pid_t>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected guardian peer PID size",
        ));
    }
    Ok(pid)
}

fn peer_token(stream: &UnixStream) -> io::Result<PeerToken> {
    let mut token = PeerToken::default();
    let mut length = size_of::<PeerToken>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            LOCAL_PEERTOKEN,
            (&mut token as *mut PeerToken).cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<PeerToken>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected guardian peer token size",
        ));
    }
    Ok(token)
}

/// Authenticate the connected guardian as the launchd job's real main process.
/// Both the kernel peer PID and the full `LOCAL_PEERTOKEN` are compared with a
/// paired identity snapshot; a self-reported coalition or ID claim is ignored.
fn verify_guardian_peer(
    stream: &UnixStream,
    job: &LaunchdCohortJob,
    controller_resource: u64,
    control: &ExecutionControl,
) -> io::Result<(ProcessIdentity, u64)> {
    let pid = peer_pid(stream)?;
    let token = peer_token(stream)?;
    if i32::try_from(token.val[5]).ok() != Some(pid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "guardian peer token PID does not match the kernel peer PID",
        ));
    }
    let snapshot = cohort::snapshot(pid)?;
    if snapshot.identity.idversion as u32 != token.val[7] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "guardian peer token idversion does not match the kernel identity",
        ));
    }
    cohort::validate_resource_cohort(snapshot.cohort.resource, controller_resource)?;
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        if control.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "execution cancelled while verifying the guardian job identity",
            ));
        }
        match job.main_pid() {
            Ok(Some(main_pid)) if main_pid == pid => break,
            Ok(Some(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "guardian peer is not the launchd job main process",
                ));
            }
            Ok(None) => {}
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(error);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "launchd did not publish the guardian main PID before the deadline",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
    Ok((snapshot.identity, snapshot.cohort.resource))
}

/// A spawn marker is only complete once the guardian has written the full
/// newline-terminated record. `create_new` publishes an empty file before the
/// record is written, so empty or prefix-only content is waited out inside the
/// bounded deadline; a complete record with different content is rejected.
fn wait_marker(path: &Path, expected: &str, control: &ExecutionControl) -> io::Result<()> {
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        if control.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "execution cancelled while waiting for the guardian spawn marker",
            ));
        }
        if let Some(bytes) = read_marker_record(path)?
            && bytes.last() == Some(&b'\n')
        {
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guardian spawn marker is not UTF-8",
                )
            })?;
            return if text.trim_end() == expected {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "guardian spawn marker content does not match this attempt",
                ))
            };
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guardian spawn marker was not completely written before the deadline",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn read_marker_record(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let limit = u64::try_from(MARKER_BYTES + 1).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > MARKER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guardian spawn marker is oversized",
        ));
    }
    Ok(Some(bytes))
}

struct InputBridge {
    stream: WireInput,
    queue: ExecutionInput,
    in_flight: Option<usize>,
    close_sent: bool,
}

impl InputBridge {
    fn new(stream: WireInput, queue: ExecutionInput) -> Self {
        Self {
            stream,
            queue,
            in_flight: None,
            close_sent: false,
        }
    }

    fn poll_round(
        &mut self,
        frames: &SyncSender<ControllerFrame>,
        deadline: Instant,
        total_in_flight: &mut usize,
    ) -> io::Result<()> {
        if self.in_flight.is_some() || self.close_sent {
            return Ok(());
        }
        match self
            .queue
            .poll()
            .map_err(|_| io::Error::other("execution input unavailable"))?
        {
            InputPoll::Data(data) => {
                let length = data.len();
                if total_in_flight.saturating_add(length) > wire::MAX_IN_FLIGHT_INPUT_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "guardian wire input budget exceeded",
                    ));
                }
                send_controller_frame(
                    frames,
                    ControllerFrame::Input {
                        stream: self.stream,
                        data,
                    },
                    deadline,
                )?;
                *total_in_flight += length;
                self.in_flight = Some(length);
                Ok(())
            }
            InputPoll::Eof => {
                send_controller_frame(
                    frames,
                    ControllerFrame::CloseInput {
                        stream: self.stream,
                    },
                    deadline,
                )?;
                self.close_sent = true;
                Ok(())
            }
            InputPoll::Pending => Ok(()),
        }
    }

    fn acknowledged(&mut self, bytes: u32, total_in_flight: &mut usize) -> io::Result<()> {
        let Some(in_flight) = self.in_flight.take() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guardian acknowledged input that was not sent",
            ));
        };
        if usize::try_from(bytes).ok() != Some(in_flight) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guardian input acknowledgement length mismatch",
            ));
        }
        self.queue
            .acknowledge(in_flight)
            .map_err(|_| io::Error::other("execution input acknowledgement failed"))?;
        *total_in_flight = total_in_flight.saturating_sub(in_flight);
        Ok(())
    }
}

fn deliver_output(
    output: &ExecutionOutputSink,
    stream: WireStream,
    data: Vec<u8>,
) -> io::Result<()> {
    let stream = match stream {
        WireStream::Stdout => OutputStream::Stdout,
        WireStream::Stderr => OutputStream::Stderr,
        WireStream::Terminal => OutputStream::Terminal,
        WireStream::Control => OutputStream::Control,
    };
    output.send(stream, &data)
}

fn send_controller_frame(
    frames: &SyncSender<ControllerFrame>,
    frame: ControllerFrame,
    deadline: Instant,
) -> io::Result<()> {
    let deadline = deadline.min(Instant::now() + FRAME_SEND_TIMEOUT);
    let mut frame = frame;
    loop {
        match frames.try_send(frame) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(pending)) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "guardian controller frame writer stalled",
                    ));
                }
                frame = pending;
                thread::sleep(POLL_INTERVAL);
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "guardian controller frame writer stopped",
                ));
            }
        }
    }
}

fn write_controller_frames(
    mut stream: UnixStream,
    frames: Receiver<ControllerFrame>,
    control: ExecutionControl,
) -> io::Result<()> {
    while let Ok(frame) = frames.recv() {
        if let Err(error) = wire::write_controller_frame(&mut stream, &frame) {
            control.request(TerminationCause::ClientDisconnected);
            return Err(error);
        }
    }
    Ok(())
}

/// Incremental, bounded guardian-frame reader. Batches are capped by frames,
/// bytes, and wall time so sustained output cannot starve cancellation checks.
#[derive(Default)]
struct GuardianFrameReader {
    buffer: Vec<u8>,
    eof: bool,
}

impl GuardianFrameReader {
    fn read_available(&mut self, stream: &mut UnixStream) -> io::Result<Vec<GuardianFrame>> {
        let mut received = Vec::new();
        let mut read_bytes = 0usize;
        let started = Instant::now();
        self.parse_buffered(&mut received)?;
        while received.len() < MAX_FRAMES_PER_READ
            && read_bytes < MAX_READ_BYTES_PER_CALL
            && started.elapsed() < MAX_READ_TIME_PER_CALL
        {
            let mut chunk = [0u8; 16 * 1024];
            match stream.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(count) => {
                    read_bytes += count;
                    self.buffer.extend_from_slice(&chunk[..count]);
                    if self.buffer.len() > MAX_BUFFERED_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "guardian frame buffer exceeded the frame limit",
                        ));
                    }
                    self.parse_buffered(&mut received)?;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(received)
    }

    fn parse_buffered(&mut self, received: &mut Vec<GuardianFrame>) -> io::Result<()> {
        while let Some(frame) = take_guardian_frame(&mut self.buffer)? {
            received.push(frame);
            if received.len() >= MAX_FRAMES_PER_READ {
                break;
            }
        }
        Ok(())
    }
}

fn take_guardian_frame(buffer: &mut Vec<u8>) -> io::Result<Option<GuardianFrame>> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    if length == 0 || length > wire::MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guardian frame length is out of range",
        ));
    }
    let total = 4 + length;
    if buffer.len() < total {
        return Ok(None);
    }
    let mut payload = &buffer[..total];
    let frame = wire::read_frame(&mut payload)?;
    buffer.drain(..total);
    Ok(Some(frame))
}

fn join_thread<T>(handle: JoinHandle<T>, deadline: Instant, label: &str) -> io::Result<T> {
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("guardian {label} did not stop before the cleanup deadline"),
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
    handle
        .join()
        .map_err(|_| io::Error::other(format!("guardian {label} thread failed")))
}

fn run_guardian_bridge(
    mut stream: UnixStream,
    output: ExecutionOutputSink,
    stdin: ExecutionStdin,
    control: ExecutionControl,
    timeout: Option<Duration>,
) -> io::Result<DoneFacts> {
    let mut stdin_bridge = match stdin {
        ExecutionStdin::Stream(queue) => Some(InputBridge::new(WireInput::Stdin, queue)),
        _ => None,
    };
    let mut control_bridge = output
        .control_input
        .clone()
        .map(|queue| InputBridge::new(WireInput::Control, queue));
    let (controller_tx, controller_rx) = mpsc::sync_channel(FRAME_QUEUE);
    let write_stream = stream.try_clone()?;
    write_stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    stream.set_read_timeout(Some(POLL_INTERVAL))?;
    let writer_control = control.clone();
    let writer =
        thread::spawn(move || write_controller_frames(write_stream, controller_rx, writer_control));

    let started = Instant::now();
    let execution_deadline =
        timeout.map(|limit| started + limit + crate::limits::deployment().cleanup_timeout());
    let mut reader = GuardianFrameReader::default();
    let mut cleanup_deadline: Option<Instant> = None;
    let mut done: Option<DoneFacts> = None;
    let mut bridge_error: Option<io::Error> = None;
    let mut total_in_flight = 0usize;
    let mut cancel_sent = false;
    loop {
        if cleanup_deadline.is_none() && control.cause().is_some() {
            cleanup_deadline = Some(control.begin_cleanup());
        }
        if cleanup_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            bridge_error = Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "guardian cleanup budget expired before done",
            ));
            break;
        }
        if execution_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            bridge_error = Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "guardian execution exceeded its timeout and cleanup budget",
            ));
            break;
        }
        let round_deadline =
            cleanup_deadline.unwrap_or_else(|| Instant::now() + FRAME_SEND_TIMEOUT);
        let mut failed = false;
        while let Some(command) = control.take_terminal_command() {
            let frame = match command {
                TerminalCommand::Resize { rows, cols } => ControllerFrame::Resize { rows, cols },
                TerminalCommand::Interrupt { sequence } => ControllerFrame::Interrupt { sequence },
            };
            if let Err(error) = send_controller_frame(&controller_tx, frame, round_deadline) {
                bridge_error = Some(error);
                failed = true;
                break;
            }
        }
        if failed {
            break;
        }
        if control.is_cancelled() && !cancel_sent {
            match send_controller_frame(
                &controller_tx,
                ControllerFrame::Cancel { sequence: None },
                round_deadline,
            ) {
                Ok(()) => cancel_sent = true,
                Err(error) => {
                    bridge_error = Some(error);
                    break;
                }
            }
        }
        for bridge in [stdin_bridge.as_mut(), control_bridge.as_mut()]
            .into_iter()
            .flatten()
        {
            if let Err(error) =
                bridge.poll_round(&controller_tx, round_deadline, &mut total_in_flight)
            {
                bridge_error = Some(error);
                failed = true;
                break;
            }
        }
        if failed {
            break;
        }
        let received = match reader.read_available(&mut stream) {
            Ok(received) => received,
            Err(error) => {
                bridge_error = Some(error);
                break;
            }
        };
        for frame in received {
            match frame {
                GuardianFrame::Started { process_id, .. } => {
                    let _ = output.started(process_id);
                }
                GuardianFrame::SignalDelivered {
                    sequence,
                    process_group_id,
                    ..
                } => {
                    let _ = output.signal_delivered_with_group(sequence, process_group_id);
                }
                GuardianFrame::InputAccepted { stream, bytes } => {
                    let bridge = match stream {
                        WireInput::Stdin => stdin_bridge.as_mut(),
                        WireInput::Control => control_bridge.as_mut(),
                    };
                    match bridge {
                        Some(bridge) => {
                            if let Err(error) = bridge.acknowledged(bytes, &mut total_in_flight) {
                                bridge_error = Some(error);
                                failed = true;
                            }
                        }
                        None => {
                            bridge_error = Some(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "guardian acknowledged a closed input stream",
                            ));
                            failed = true;
                        }
                    }
                }
                GuardianFrame::InputClosed { .. } => {}
                GuardianFrame::Output { stream, data } => {
                    // A cancelled/disconnected execution no longer cares about
                    // output; keep draining so Done/cleanup can finish.
                    if let Err(error) = deliver_output(&output, stream, data)
                        && control.cause().is_none()
                    {
                        bridge_error = Some(error);
                        failed = true;
                    }
                }
                GuardianFrame::Done {
                    exit_code,
                    exit_signal,
                    timed_out,
                    io_joined,
                    children_drained,
                    ..
                } => {
                    done = Some(DoneFacts {
                        exit_code,
                        exit_signal,
                        timed_out,
                        io_joined,
                        children_drained,
                    });
                }
            }
            if failed || done.is_some() {
                break;
            }
        }
        if failed {
            break;
        }
        if done.is_some() {
            break;
        }
        if reader.eof {
            bridge_error = Some(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "guardian socket closed before done",
            ));
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    let finalize_deadline = cleanup_deadline.unwrap_or_else(|| control.begin_cleanup());
    if let Some(error) = bridge_error {
        let _ = stream.shutdown(Shutdown::Both);
        drop(controller_tx);
        let _ = join_thread(writer, finalize_deadline, "controller frame writer");
        return Err(error);
    }
    let Some(done) = done else {
        let _ = stream.shutdown(Shutdown::Both);
        drop(controller_tx);
        let _ = join_thread(writer, finalize_deadline, "controller frame writer");
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "guardian bridge ended without a done frame",
        ));
    };
    drop(controller_tx);
    let writer_result = join_thread(writer, finalize_deadline, "controller frame writer")?;
    writer_result?;
    // The guardian sends Done last and then exits. Reading to EOF proves the
    // guardian socket is gone and that no frame followed Done.
    loop {
        if Instant::now() >= finalize_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guardian socket did not reach EOF before the cleanup deadline",
            ));
        }
        let received = reader.read_available(&mut stream)?;
        if !received.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guardian sent frames after done",
            ));
        }
        if reader.eof {
            return Ok(done);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn finalize_completed(
    job: &mut LaunchdCohortJob,
    record: &mut OwnershipRecord,
    manifest: &mut OwnershipManifest,
    plan: &PlatformSandboxPlan,
    guardian_identity: ProcessIdentity,
    execution_resource: u64,
    deadline: Instant,
) -> io::Result<()> {
    wait_identity_gone(guardian_identity, deadline)?;
    let usage = wait_kernel_zero(execution_resource, deadline)?;
    // Persist the live positive counter proof before bootout: once the job is
    // booted out, the coalition counters can become ESRCH forever. Recovery uses
    // this trusted proof rather than treating ESRCH as zero.
    manifest.phase = AdmissionPhase::Drained;
    manifest.drained = Some(DrainedProof::from_usage(usage));
    record.write_manifest(manifest)?;
    job.unregister()?;
    // The ownership record is the unique recovery evidence; runtime roots are
    // cleaned first and the record is deleted last.
    plan.cleanup_runtime_roots()?;
    record.remove()?;
    Ok(())
}

fn abort_execution(
    job: &mut LaunchdCohortJob,
    record: &mut OwnershipRecord,
    manifest: &mut OwnershipManifest,
    plan: &PlatformSandboxPlan,
    deadline: Instant,
    primary: io::Error,
) -> io::Error {
    let Some(guardian_record) = manifest.guardian else {
        return retained_failure(
            job,
            format!("guardian execution failed ({primary}); admitted guardian record is missing"),
        );
    };
    let guardian_identity = guardian_record.identity.identity();
    let execution_resource = guardian_record.resource;
    let termination = cohort::terminate_cohort_members(execution_resource, None, deadline);
    match termination {
        Ok(report) if report.empty => {
            if let Err(error) = wait_identity_gone(guardian_identity, deadline) {
                return retained_failure(
                    job,
                    format!(
                        "guardian execution failed ({primary}); guardian exit is unconfirmed: {error}"
                    ),
                );
            }
            let usage = match wait_kernel_zero(execution_resource, deadline) {
                Ok(usage) => usage,
                Err(error) => {
                    return retained_failure(
                        job,
                        format!(
                            "guardian execution failed ({primary}); positive kernel zero is unconfirmed: {error}"
                        ),
                    );
                }
            };
            manifest.phase = AdmissionPhase::Drained;
            manifest.drained = Some(DrainedProof::from_usage(usage));
            if let Err(error) = record.write_manifest(manifest) {
                return retained_failure(
                    job,
                    format!(
                        "guardian execution failed ({primary}); drained proof persistence failed: {error}"
                    ),
                );
            }
            if let Err(error) = job.unregister() {
                return retained_failure(
                    job,
                    format!(
                        "guardian execution failed ({primary}); launchd bootout is unconfirmed: {error}"
                    ),
                );
            }
            if let Err(error) = plan.cleanup_runtime_roots() {
                return retained_failure(
                    job,
                    format!(
                        "guardian execution failed ({primary}); runtime root cleanup is unconfirmed: {error}"
                    ),
                );
            }
            match record.remove() {
                Ok(()) => io::Error::other(format!(
                    "guardian execution failed ({primary}); execution coalition drained and launchd ownership removed"
                )),
                Err(error) => retained_failure(
                    job,
                    format!(
                        "guardian execution failed ({primary}); ownership record removal failed: {error}"
                    ),
                ),
            }
        }
        Ok(report) => retained_failure(
            job,
            format!(
                "guardian execution failed ({primary}); execution coalition did not drain (started={}, exited={})",
                report.usage.tasks_started, report.usage.tasks_exited
            ),
        ),
        Err(error) => retained_failure(
            job,
            format!(
                "guardian execution failed ({primary}); execution coalition cleanup failed: {error}"
            ),
        ),
    }
}

/// Any failure that keeps the launchd ownership record must classify as an
/// unverified cleanup, never as a completed pre-launch rollback.
fn retained_failure(job: &LaunchdCohortJob, detail: String) -> io::Error {
    crate::backend::cleanup_unconfirmed(format!(
        "{detail}; launchd job and ownership record retained at {}",
        job.cleanup_record().display()
    ))
}

fn wait_identity_gone(identity: ProcessIdentity, deadline: Instant) -> io::Result<()> {
    loop {
        match cohort::snapshot(identity.pid) {
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(()),
            Ok(snapshot) if !snapshot.identity.same_process(&identity) => return Ok(()),
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guardian kernel identity did not exit before the cleanup deadline",
            ));
        }
        thread::sleep(TRACK_INTERVAL);
    }
}

/// Kernel counters are the only proof of an empty execution coalition. ESRCH
/// must never be interpreted as zero: the launchd job stays registered until the
/// counters are readable at active == 0.
fn wait_kernel_zero(execution_resource: u64, deadline: Instant) -> io::Result<cohort::CohortUsage> {
    loop {
        match cohort::usage(execution_resource) {
            Ok(usage) if usage.active() == Some(0) => return Ok(usage),
            Ok(_) => {}
            Err(error) => {
                return Err(io::Error::other(format!(
                    "execution coalition usage is unavailable; ESRCH is not kernel zero: {error}"
                )));
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "execution coalition did not report started == exited before the cleanup deadline",
            ));
        }
        thread::sleep(TRACK_INTERVAL);
    }
}

fn exit_status(code: Option<i32>, signal: Option<i32>) -> io::Result<ExitStatus> {
    match (code, signal) {
        (Some(code), _) => {
            let code = u8::try_from(code).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guardian exit code is out of range",
                )
            })?;
            Ok(ExitStatus::from_raw(i32::from(code) << 8))
        }
        (None, Some(signal)) => Ok(ExitStatus::from_raw(signal)),
        (None, None) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guardian done frame carries no exit status",
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryOutcome {
    Removed,
    Skipped,
}

#[derive(Clone, Debug)]
enum RecoveryState {
    Clear,
    Blocked(String),
}

static RECOVERY_STATE: OnceLock<RecoveryState> = OnceLock::new();

fn recovery_state() -> &'static RecoveryState {
    RECOVERY_STATE.get_or_init(|| {
        let deadline = Instant::now() + crate::limits::deployment().cleanup_timeout();
        match recover_retained_records(deadline) {
            Ok(()) => RecoveryState::Clear,
            Err(error) => RecoveryState::Blocked(error.to_string()),
        }
    })
}

/// New executions must fail closed while any retained record is unproven.
pub(crate) fn recover_before_execution() -> io::Result<()> {
    match recovery_state() {
        RecoveryState::Clear => Ok(()),
        RecoveryState::Blocked(detail) => Err(crate::backend::cleanup_unconfirmed(format!(
            "startup recovery is blocked: {detail}"
        ))),
    }
}

/// Capability output cannot return `Result`, so it only reports that recovery is
/// blocked; execution admission enforces the refusal.
pub(crate) fn startup_recovery_blocked() -> bool {
    matches!(recovery_state(), RecoveryState::Blocked(_))
}

/// Startup recovery only scans the verified per-user parent. Live owners,
/// explicitly unadmitted records, legacy formats, and other-boot records are
/// skipped and retained. A corrupt admitted/drained record, a missing registered
/// job for an admitted record, CID cleanup failure, or any permission/ABI error
/// blocks all new executions instead of being swallowed.
fn recover_retained_records(deadline: Instant) -> io::Result<()> {
    let parent = record_parent_path();
    let metadata = match fs::symlink_metadata(&parent) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    validate_owned_directory(&metadata, &parent)?;
    let current_boot = cohort::boot_session_uuid()?;
    let controller_pid = i32::try_from(std::process::id()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "controller pid is out of range")
    })?;
    let controller_resource = cohort::snapshot(controller_pid)?.cohort.resource;
    recover_records_in(&parent, &current_boot, controller_resource, deadline)
}

fn recover_records_in(
    parent: &Path,
    current_boot: &str,
    controller_resource: u64,
    deadline: Instant,
) -> io::Result<()> {
    for entry in fs::read_dir(parent)? {
        let entry = entry.map_err(|error| {
            io::Error::other(format!(
                "guardian ownership scan could not read an entry: {error}"
            ))
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_attempt_record_name(name) {
            continue;
        }
        let _outcome =
            recover_attempt_record(&entry.path(), current_boot, controller_resource, deadline)?;
    }
    Ok(())
}

fn record_directory_vanished(directory: &Path) -> bool {
    matches!(
        fs::symlink_metadata(directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound
    )
}

fn recover_attempt_record(
    directory: &Path,
    current_boot: &str,
    controller_resource: u64,
    deadline: Instant,
) -> io::Result<RecoveryOutcome> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Another recovery removed this record after our directory scan.
            return Ok(RecoveryOutcome::Skipped);
        }
        Err(error) => return Err(error),
    };
    validate_owned_directory(&metadata, directory)?;

    // Missing manifest is an old/unadmitted prototype: retain and do not guess
    // an executed range. A present but unsafe manifest is unknown and blocks.
    let manifest_path = directory.join(MANIFEST_FILE);
    let manifest_bytes = match read_owned_file(&manifest_path, MANIFEST_BYTES)? {
        Some(bytes) => bytes,
        None => match fs::symlink_metadata(&manifest_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(RecoveryOutcome::Skipped);
            }
            Ok(_) => {
                return Err(io::Error::other(
                    "ownership manifest is not an owned 0600 regular file",
                ));
            }
            Err(error) => return Err(error),
        },
    };
    let manifest: OwnershipManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ownership manifest is corrupt: {error}"),
        )
    })?;
    if manifest.version != MANIFEST_VERSION {
        // Old prototype format: never guess whether it executed.
        return Ok(RecoveryOutcome::Skipped);
    }
    if manifest.phase == AdmissionPhase::Prepared {
        return Ok(RecoveryOutcome::Skipped);
    }
    if manifest.boot_session_uuid != current_boot {
        // A CID from another boot must never signal a current-boot process.
        return Ok(RecoveryOutcome::Skipped);
    }
    if manifest.owner.is_live()? {
        return Ok(RecoveryOutcome::Skipped);
    }

    // Reclaiming admitted/drained records requires the owner lock. A live lock
    // holder wins; a missing/unsafe lock on a reclaimed record is unknown.
    let lock_path = directory.join(LOCK_FILE);
    let lock_metadata = match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Distinguish a concurrently reclaimed record (the whole directory
            // is gone) from an existing admitted record whose lock is missing.
            if record_directory_vanished(directory) {
                return Ok(RecoveryOutcome::Skipped);
            }
            return Err(io::Error::other(
                "admitted ownership record is missing its owner lock",
            ));
        }
        Err(error) => {
            if record_directory_vanished(directory) {
                return Ok(RecoveryOutcome::Skipped);
            }
            return Err(error);
        }
    };
    if !is_owned_regular_file(&lock_metadata) {
        return Err(io::Error::other(
            "admitted ownership record has an unsafe owner lock",
        ));
    }
    let lock = match OpenOptions::new().read(true).write(true).open(&lock_path) {
        Ok(lock) => lock,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if record_directory_vanished(directory) {
                return Ok(RecoveryOutcome::Skipped);
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    match lock_exclusive_nonblocking(&lock) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return Ok(RecoveryOutcome::Skipped);
        }
        Err(error) => return Err(error),
    }
    if record_directory_vanished(directory) {
        // The other recovery completed between our manifest read and lock
        // acquisition; it owned the lock and removed the record.
        return Ok(RecoveryOutcome::Skipped);
    }

    match manifest.phase {
        AdmissionPhase::Prepared => Ok(RecoveryOutcome::Skipped),
        AdmissionPhase::Admitted => {
            recover_admitted_record(directory, manifest, controller_resource, deadline)?;
            Ok(RecoveryOutcome::Removed)
        }
        AdmissionPhase::Drained => {
            recover_drained_record(directory, &manifest, deadline)?;
            Ok(RecoveryOutcome::Removed)
        }
    }
}

fn recover_admitted_record(
    directory: &Path,
    mut manifest: OwnershipManifest,
    controller_resource: u64,
    deadline: Instant,
) -> io::Result<()> {
    let Some(guardian_record) = manifest.guardian else {
        return Err(io::Error::other(
            "admitted ownership record has no guardian identity/resource",
        ));
    };
    let execution_resource = guardian_record.resource;
    if execution_resource == 0
        || execution_resource == controller_resource
        || cohort::validate_resource_cohort(execution_resource, controller_resource).is_err()
    {
        return Err(io::Error::other(
            "admitted ownership record has an invalid execution resource",
        ));
    }
    let label = verified_record_label(directory, &manifest)?;
    if !guardian::label_registered(&label)? {
        return Err(io::Error::other(
            "admitted ownership record has no registered launchd job; executed range is unproven",
        ));
    }
    let report = cohort::terminate_cohort_members(execution_resource, None, deadline)?;
    if !report.empty {
        return Err(io::Error::other(
            "admitted execution coalition did not reach kernel zero",
        ));
    }
    let usage = wait_kernel_zero(execution_resource, deadline)?;
    // Persist the trusted positive proof before bootout; after bootout the
    // counters may be ESRCH and must not be reinterpreted as zero.
    manifest.phase = AdmissionPhase::Drained;
    manifest.drained = Some(DrainedProof::from_usage(usage));
    write_manifest_atomic(&directory.join(MANIFEST_FILE), &manifest)?;
    // Unified drained finish: registered jobs are booted out and their absence
    // verified before the record is deleted, even when recovery just produced
    // the persisted proof itself.
    recover_drained_record(directory, &manifest, deadline)
}

fn recover_drained_record(
    directory: &Path,
    manifest: &OwnershipManifest,
    deadline: Instant,
) -> io::Result<()> {
    if manifest.guardian.is_none() {
        return Err(io::Error::other(
            "drained ownership record has no guardian identity/resource",
        ));
    }
    let Some(proof) = manifest.drained else {
        return Err(io::Error::other(
            "drained ownership record has no persisted counter proof",
        ));
    };
    if !proof.is_complete() {
        return Err(io::Error::other(
            "drained ownership record has an inconsistent counter proof",
        ));
    }
    let label = verified_record_label(directory, manifest)?;
    if guardian::label_registered(&label)? {
        guardian::unregister_label(&label)?;
    }
    // The record is the only recovery evidence; never delete it while the job
    // label can still be observed as registered.
    if guardian::label_registered(&label)? {
        return Err(io::Error::other(
            "launchd job is still registered; refusing to remove the ownership record",
        ));
    }
    finish_drained_record(directory, manifest, deadline)
}

fn finish_drained_record(
    directory: &Path,
    manifest: &OwnershipManifest,
    _deadline: Instant,
) -> io::Result<()> {
    if let Some(runtime_root) = manifest.runtime_root.as_deref()
        && !runtime_root.is_empty()
    {
        crate::backend::cleanup_recorded_runtime_root(
            &manifest.execution_id,
            &manifest.cwd,
            runtime_root,
        )?;
    }
    fs::remove_dir_all(directory)
}

fn verified_record_label(directory: &Path, manifest: &OwnershipManifest) -> io::Result<String> {
    let Some(plist_bytes) = read_owned_file(&directory.join("job.plist"), PLIST_BYTES)? else {
        return Err(io::Error::other(
            "guardian ownership record is missing its owned plist",
        ));
    };
    let Some(label) = parse_plist_label(&plist_bytes) else {
        return Err(io::Error::other(
            "guardian ownership record plist has no valid label",
        ));
    };
    if label != manifest.job_label || !label.starts_with(RECORD_LABEL_PREFIX) {
        return Err(io::Error::other(
            "guardian ownership record label does not match its manifest",
        ));
    }
    let plist = std::str::from_utf8(&plist_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "guardian plist is not UTF-8"))?;
    for argument in [
        directory.join("guardian.sock"),
        directory.join("spawn.marker"),
    ] {
        let argument = argument.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "guardian record path is not UTF-8",
            )
        })?;
        let expected = format!("<string>{argument}</string>");
        if !plist.contains(expected.as_str()) {
            return Err(io::Error::other(
                "guardian ownership record plist argv does not match its directory",
            ));
        }
    }
    Ok(label)
}

fn is_owned_regular_file(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.mode() & 0o777 == 0o600
        && metadata.uid() == unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn done_exit_status_maps_exit_code() {
        let status = exit_status(Some(7), None).expect("exit code");
        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn done_exit_status_maps_signal() {
        let status = exit_status(None, Some(9)).expect("signal");
        assert_eq!(status.signal(), Some(9));
    }

    #[test]
    fn marker_mismatch_is_rejected() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("spawn.marker");
        fs::write(&path, b"1:2:3\n")?;
        let control = ExecutionControl::default();
        wait_marker(&path, "1:2:3", &control)?;
        assert!(wait_marker(&path, "1:2:4", &control).is_err());
        Ok(())
    }

    #[test]
    fn guardian_profile_denies_the_ownership_record() -> io::Result<()> {
        let profile = guardian_protected_profile(
            "(version 1)(allow default)",
            Path::new("/tmp/runseal-501"),
        )?;
        assert!(profile.contains("(deny file-write* (subpath \"/tmp/runseal-501\"))"));
        assert!(profile.contains("(deny file-read* (subpath \"/tmp/runseal-501\"))"));
        assert!(profile.contains("(deny file-read-metadata (subpath \"/tmp/runseal-501\"))"));
        Ok(())
    }

    #[test]
    fn attempt_record_names_require_the_random_hex_suffix() {
        assert!(is_attempt_record_name(
            "rs-0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_attempt_record_name(
            "rs-0123456789abcdef0123456789abcde"
        ));
        assert!(!is_attempt_record_name(
            "xx-0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn plist_label_is_parsed_with_a_restricted_charset() {
        let plist =
            b"<plist><dict><key>Label</key><string>com.runseal.cohort.123.abcdef</string></dict></plist>";
        assert_eq!(
            parse_plist_label(plist).as_deref(),
            Some("com.runseal.cohort.123.abcdef")
        );
        let bad = b"<key>Label</key><string>bad label</string>";
        assert_eq!(parse_plist_label(bad), None);
    }

    /// A controlled PID-reuse fixture: `snapshot` can query this PID, but the
    /// fabricated birth identity is not the current process, so it is a
    /// positively dead owner. Production EPERM from `snapshot` remains unknown
    /// and must never be treated as a dead owner.
    fn test_dead_owner() -> BirthIdentity {
        let pid = i32::try_from(std::process::id()).expect("test pid is in range");
        let snapshot = cohort::snapshot(pid).expect("test self snapshot");
        BirthIdentity {
            pid,
            idversion: snapshot.identity.idversion.wrapping_add(1) as u32,
            uniqueid: snapshot.identity.uniqueid.wrapping_add(1),
        }
    }

    fn test_manifest(phase: AdmissionPhase) -> OwnershipManifest {
        let owner = test_dead_owner();
        OwnershipManifest {
            version: MANIFEST_VERSION,
            phase,
            execution_id: "exec_test".to_string(),
            cwd: "/tmp".to_string(),
            runtime_root: None,
            job_label: format!("{RECORD_LABEL_PREFIX}123.abcdef"),
            owner,
            boot_session_uuid: "current-boot".to_string(),
            guardian: Some(GuardianRecord {
                identity: owner,
                resource: 1,
            }),
            drained: None,
        }
    }

    fn write_attempt_record(directory: &Path, manifest: &OwnershipManifest) -> io::Result<()> {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        let lock = directory.join(LOCK_FILE);
        fs::write(&lock, b"")?;
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
        let path = directory.join(MANIFEST_FILE);
        fs::write(
            &path,
            serde_json::to_vec(manifest).map_err(|error| {
                io::Error::other(format!("test manifest encoding failed: {error}"))
            })?,
        )?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[test]
    fn legacy_missing_or_other_boot_records_are_skipped_and_retained() -> io::Result<()> {
        // No manifest: an old/unadmitted prototype is retained, not guessed.
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let lock = directory.path().join(LOCK_FILE);
        fs::write(&lock, b"")?;
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            recover_attempt_record(directory.path(), "current-boot", 9_999, Instant::now())?,
            RecoveryOutcome::Skipped
        );
        assert!(directory.path().exists());

        // An admitted record from another boot must never signal this boot.
        let directory = tempfile::tempdir()?;
        let mut manifest = test_manifest(AdmissionPhase::Admitted);
        manifest.boot_session_uuid = "another-boot".to_string();
        write_attempt_record(directory.path(), &manifest)?;
        assert_eq!(
            recover_attempt_record(directory.path(), "current-boot", 9_999, Instant::now())?,
            RecoveryOutcome::Skipped
        );
        assert!(directory.path().exists());
        Ok(())
    }

    #[test]
    fn corrupt_admitted_record_blocks_recovery() -> io::Result<()> {
        let parent = tempfile::tempdir()?;
        let directory = parent.path().join("rs-0123456789abcdef0123456789abcdef");
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let lock = directory.join(LOCK_FILE);
        fs::write(&lock, b"")?;
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
        let manifest = directory.join(MANIFEST_FILE);
        fs::write(&manifest, b"{not valid json")?;
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))?;
        let error = recover_records_in(parent.path(), "current-boot", 9_999, Instant::now())
            .expect_err("a corrupt retained record must block execution admission");
        assert!(error.to_string().contains("corrupt"), "{error}");
        assert!(directory.exists());
        Ok(())
    }

    #[test]
    fn drained_record_requires_a_persisted_complete_proof() -> io::Result<()> {
        assert!(
            DrainedProof {
                tasks_started: 3,
                tasks_exited: 3,
            }
            .is_complete()
        );
        assert!(
            !DrainedProof {
                tasks_started: 2,
                tasks_exited: 3,
            }
            .is_complete()
        );

        let directory = tempfile::tempdir()?;
        write_attempt_record(directory.path(), &test_manifest(AdmissionPhase::Drained))?;
        assert!(
            recover_attempt_record(directory.path(), "current-boot", 9_999, Instant::now())
                .is_err()
        );
        assert!(directory.path().exists());
        Ok(())
    }

    #[test]
    fn concurrently_reclaimed_record_is_skipped_but_missing_lock_is_blocked() -> io::Result<()> {
        let parent = tempfile::tempdir()?;

        // The scan enumerated this path, but another recovery already removed
        // the record before this process opened it: this is a skip, not a block.
        let vanished = parent.path().join("rs-0123456789abcdef0123456789abcdef");
        assert_eq!(
            recover_attempt_record(&vanished, "current-boot", 9_999, Instant::now())?,
            RecoveryOutcome::Skipped
        );

        // The directory still exists with an admitted manifest but no lock:
        // this is unknown and must block admission.
        let directory = parent.path().join("rs-fedcba9876543210fedcba9876543210");
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let manifest_path = directory.join(MANIFEST_FILE);
        fs::write(
            &manifest_path,
            serde_json::to_vec(&test_manifest(AdmissionPhase::Admitted)).map_err(|error| {
                io::Error::other(format!("test manifest encoding failed: {error}"))
            })?,
        )?;
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))?;
        assert!(recover_attempt_record(&directory, "current-boot", 9_999, Instant::now()).is_err());
        assert!(directory.exists());
        Ok(())
    }

    #[test]
    fn drained_record_with_proof_completes_after_the_job_is_already_gone() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut manifest = test_manifest(AdmissionPhase::Drained);
        manifest.drained = Some(DrainedProof {
            tasks_started: 4,
            tasks_exited: 4,
        });
        write_attempt_record(directory.path(), &manifest)?;
        let socket = directory.path().join("guardian.sock");
        let marker = directory.path().join("spawn.marker");
        let plist = format!(
            "<plist><dict><key>Label</key><string>{}</string><key>ProgramArguments</key><array><string>--socket</string><string>{}</string><string>--marker</string><string>{}</string></array></dict></plist>",
            manifest.job_label,
            socket.display(),
            marker.display()
        );
        let plist_path = directory.path().join("job.plist");
        fs::write(&plist_path, plist)?;
        fs::set_permissions(&plist_path, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            recover_attempt_record(directory.path(), "current-boot", 9_999, Instant::now())?,
            RecoveryOutcome::Removed
        );
        assert!(!directory.path().exists());
        Ok(())
    }
}
