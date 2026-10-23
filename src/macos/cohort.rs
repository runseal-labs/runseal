//! macOS cohort and audit-token primitives for the launchd guardian path.
//!
//! The guardian uses kernel coalition membership as the owned-process boundary.
//! Process identity is always a paired BSD/uniqid snapshot (PID + PID version +
//! unique ID); signalling goes through `proc_signal_with_audittoken` so a PID
//! reuse cannot be mistaken for the observed process. These private libproc
//! entry points are loaded with dlsym because they are not stable link-time ABI.

use std::ffi::{c_char, c_int, c_void};
use std::io;
use std::mem::size_of;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDT_BSDINFOWITHUNIQID: c_int = 18;
const PROC_PIDCOALITIONINFO: c_int = 20;
const COALITION_TYPE_RESOURCE: usize = 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct AuditToken {
    val: [u32; 8],
}

/// Full libproc ABI layout. Fields beyond those consumed by ownership identity
/// exist only to preserve the kernel struct size and offsets.
#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ProcBsdInfo {
    flags: u32,
    status: u32,
    xstatus: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    ruid: u32,
    rgid: u32,
    svuid: u32,
    svgid: u32,
    rfu: u32,
    comm: [c_char; 16],
    name: [c_char; 32],
    nfiles: u32,
    pgid: u32,
    pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    nice: i32,
    start_tvsec: u64,
    start_tvusec: u64,
}

/// Full libproc ABI layout; only `uniqueid` and `idversion` are consumed.
#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct UniqIdentifierInfo {
    uuid: [u8; 16],
    uniqueid: u64,
    puniqueid: u64,
    idversion: i32,
    orig_ppidversion: i32,
    reserve2: u64,
    reserve3: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ProcBsdInfoWithUniqId {
    pbsd: ProcBsdInfo,
    uniqid: UniqIdentifierInfo,
}

/// Full libproc ABI layout; only the resource coalition id is consumed.
#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ProcPidCoalitionInfo {
    coalition_id: [u64; 2],
    reserved1: u64,
    reserved2: u64,
    reserved3: u64,
}

type SignalWithAuditToken = unsafe extern "C" fn(*mut AuditToken, c_int) -> c_int;
type CoalitionInfoResourceUsage = unsafe extern "C" fn(u64, *mut c_void, usize) -> c_int;

fn load_symbol(name: &std::ffi::CStr) -> Option<*mut c_void> {
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    (!symbol.is_null()).then_some(symbol)
}

fn signal_with_audittoken() -> Option<SignalWithAuditToken> {
    static SYMBOL: OnceLock<Option<SignalWithAuditToken>> = OnceLock::new();
    *SYMBOL.get_or_init(|| {
        load_symbol(c"proc_signal_with_audittoken").map(|symbol| unsafe {
            std::mem::transmute::<*mut c_void, SignalWithAuditToken>(symbol)
        })
    })
}

fn coalition_usage_fn() -> Option<CoalitionInfoResourceUsage> {
    static SYMBOL: OnceLock<Option<CoalitionInfoResourceUsage>> = OnceLock::new();
    *SYMBOL.get_or_init(|| {
        load_symbol(c"coalition_info_resource_usage").map(|symbol| unsafe {
            std::mem::transmute::<*mut c_void, CoalitionInfoResourceUsage>(symbol)
        })
    })
}

/// Paired identity from one `PROC_PIDT_BSDINFOWITHUNIQID` call.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ProcessIdentity {
    pub(crate) pid: i32,
    pub(crate) uniqueid: u64,
    pub(crate) idversion: i32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CohortIds {
    pub(crate) resource: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CohortSnapshot {
    pub(crate) identity: ProcessIdentity,
    pub(crate) cohort: CohortIds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CohortUsage {
    pub(crate) tasks_started: u64,
    pub(crate) tasks_exited: u64,
}

impl CohortUsage {
    pub(crate) fn active(self) -> Option<u64> {
        self.tasks_started.checked_sub(self.tasks_exited)
    }
}

impl ProcessIdentity {
    /// Identity used for ownership equality.
    pub(crate) fn same_process(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.uniqueid == other.uniqueid
            && self.idversion == other.idversion
    }
}

fn wrapper_error(code: c_int) -> io::Error {
    if code > 0 {
        io::Error::from_raw_os_error(code)
    } else {
        io::Error::last_os_error()
    }
}

fn is_missing(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ESRCH)
}

fn audit_token(identity: &ProcessIdentity) -> AuditToken {
    let mut token = AuditToken::default();
    // audit_token_t: val[5] = pid, val[7] = pidversion.
    token.val[5] = identity.pid as u32;
    token.val[7] = identity.idversion as u32;
    token
}

fn paired_identity(pid: i32) -> io::Result<ProcessIdentity> {
    let mut info = ProcBsdInfoWithUniqId::default();
    let size = size_of::<ProcBsdInfoWithUniqId>() as c_int;
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDT_BSDINFOWITHUNIQID,
            0,
            (&mut info as *mut ProcBsdInfoWithUniqId).cast(),
            size,
        )
    };
    if result != size {
        return Err(io::Error::last_os_error());
    }
    if info.pbsd.pid != pid as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "paired process identity returned a different pid",
        ));
    }
    Ok(ProcessIdentity {
        pid,
        uniqueid: info.uniqid.uniqueid,
        idversion: info.uniqid.idversion,
    })
}

fn coalition_ids(pid: i32) -> io::Result<CohortIds> {
    let mut info = ProcPidCoalitionInfo::default();
    let size = size_of::<ProcPidCoalitionInfo>() as c_int;
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDCOALITIONINFO,
            0,
            (&mut info as *mut ProcPidCoalitionInfo).cast(),
            size,
        )
    };
    if result != size {
        return Err(io::Error::last_os_error());
    }
    Ok(CohortIds {
        resource: info.coalition_id[COALITION_TYPE_RESOURCE],
    })
}

/// Read identity and coalition in a bounded retry loop so a process cannot
/// change identity between the two kernel queries.
pub(crate) fn snapshot(pid: i32) -> io::Result<CohortSnapshot> {
    let mut last_error = None;
    for _ in 0..8 {
        let first = match paired_identity(pid) {
            Ok(identity) => identity,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let cohort = match coalition_ids(pid) {
            Ok(cohort) => cohort,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let second = match paired_identity(pid) {
            Ok(identity) => identity,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        if first == second {
            return Ok(CohortSnapshot {
                identity: second,
                cohort,
            });
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "process identity changed repeatedly",
        )
    }))
}

fn all_pids() -> io::Result<Vec<i32>> {
    let mut capacity = 64 * 1024usize;
    loop {
        let mut buffer = vec![0u8; capacity];
        let result = unsafe {
            libc::proc_listpids(
                PROC_ALL_PIDS,
                0,
                buffer.as_mut_ptr().cast(),
                capacity as c_int,
            )
        };
        if result <= 0 {
            return Err(io::Error::last_os_error());
        }
        let returned = result as usize;
        if returned >= capacity {
            capacity = capacity.saturating_mul(2);
            continue;
        }
        let count = returned / size_of::<i32>();
        let mut pids = Vec::with_capacity(count);
        for index in 0..count {
            let offset = index * size_of::<i32>();
            let pid = i32::from_ne_bytes(
                buffer[offset..offset + size_of::<i32>()]
                    .try_into()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pid"))?,
            );
            if pid > 0 {
                pids.push(pid);
            }
        }
        return Ok(pids);
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MemberScan {
    pub(crate) members: Vec<ProcessIdentity>,
}

/// Enumerate live processes whose resource coalition is `resource`.
pub(crate) fn scan_members(resource: u64) -> io::Result<MemberScan> {
    let mut scan = MemberScan::default();
    for pid in all_pids()? {
        match snapshot(pid) {
            Ok(snapshot) if snapshot.cohort.resource == resource => {
                scan.members.push(snapshot.identity);
            }
            Ok(_) => {}
            Err(error) if is_missing(&error) => {}
            Err(_) => {}
        }
    }
    scan.members.sort_by_key(|identity| identity.pid);
    scan.members.dedup();
    Ok(scan)
}

/// Reject a cohort that is not independently owned. A zero resource ID or the
/// controller's own resource coalition must never be used as an execution
/// cohort, because cleanup would otherwise target shared processes.
pub(crate) fn validate_resource_cohort(resource: u64, controller_resource: u64) -> io::Result<()> {
    if resource == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resource coalition id is zero",
        ));
    }
    if resource == controller_resource {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "execution coalition is shared with the controller",
        ));
    }
    Ok(())
}

pub(crate) fn usage(resource: u64) -> io::Result<CohortUsage> {
    let function = coalition_usage_fn().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "coalition_info_resource_usage is unavailable",
        )
    })?;
    let mut buffer = [0u8; 4096];
    let result = unsafe { function(resource, buffer.as_mut_ptr().cast(), buffer.len()) };
    if result != 0 {
        return Err(wrapper_error(result));
    }
    let started = u64::from_ne_bytes(
        buffer[0..8]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "usage"))?,
    );
    let exited = u64::from_ne_bytes(
        buffer[8..16]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "usage"))?,
    );
    if exited > started {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "coalition usage counters regressed",
        ));
    }
    Ok(CohortUsage {
        tasks_started: started,
        tasks_exited: exited,
    })
}

/// Send a signal to the exact process identity captured in a paired snapshot.
/// The kernel validates pid + pidversion; a reused PID or forged version fails.
pub(crate) fn signal(identity: &ProcessIdentity, sig: c_int) -> io::Result<()> {
    let function = signal_with_audittoken().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "proc_signal_with_audittoken is unavailable",
        )
    })?;
    let mut token = audit_token(identity);
    let result = unsafe { function(&mut token, sig) };
    if result == 0 {
        Ok(())
    } else {
        Err(wrapper_error(result))
    }
}

/// The kernel boot session UUID. Recovery compares this before it ever uses a
/// saved coalition id: a CID from another boot must never signal a process in
/// the current boot.
pub(crate) fn boot_session_uuid() -> io::Result<String> {
    let name = c"kern.bootsessionuuid";
    let mut size = 0usize;
    let result = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if size == 0 || size > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected boot session uuid size",
        ));
    }
    let mut buffer = vec![0u8; size];
    let mut actual = size;
    let result = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut actual,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if actual > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "boot session uuid value overflowed its buffer",
        ));
    }
    buffer.truncate(actual);
    while buffer.last() == Some(&0) {
        buffer.pop();
    }
    let uuid = String::from_utf8(buffer).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "boot session uuid is not UTF-8")
    })?;
    if uuid.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "boot session uuid is empty",
        ));
    }
    Ok(uuid)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CleanupReport {
    pub(crate) usage: CohortUsage,
    pub(crate) empty: bool,
}

/// Stop and kill every member of the resource cohort except `keeper`, then
/// require the kernel counters to show only the keeper is active. `keeper` is
/// the guardian identity; a caller with no keeper requires active == 0.
pub(crate) fn terminate_cohort_members(
    resource: u64,
    keeper: Option<&ProcessIdentity>,
    deadline: Instant,
) -> io::Result<CleanupReport> {
    loop {
        let scan = scan_members(resource)?;
        let live = scan
            .members
            .iter()
            .filter(|identity| !keeper.is_some_and(|keeper| keeper.same_process(identity)))
            .cloned()
            .collect::<Vec<_>>();
        if !live.is_empty() {
            for identity in &live {
                match signal(identity, libc::SIGSTOP) {
                    Ok(()) => {}
                    Err(error) if is_missing(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            for identity in &live {
                match signal(identity, libc::SIGKILL) {
                    Ok(()) => {}
                    Err(error) if is_missing(&error) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        let usage = usage(resource)?;
        let active = usage.active().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "coalition usage has exited > started",
            )
        })?;
        let expected_active = u64::from(keeper.is_some());
        if active <= expected_active {
            let remaining = scan_members(resource)?;
            let observed_keeper = match keeper {
                Some(keeper) => {
                    remaining
                        .members
                        .iter()
                        .filter(|identity| keeper.same_process(identity))
                        .count()
                        == 1
                }
                None => remaining.members.is_empty(),
            };
            let expected_members = usize::try_from(expected_active).unwrap_or(usize::MAX);
            return Ok(CleanupReport {
                usage,
                empty: active == expected_active
                    && observed_keeper
                    && remaining.members.len() == expected_members,
            });
        }
        // A non-zero kernel count with no identified live member may be a
        // transient scan gap (a process between fork and identity publication).
        // Retry within the same deadline instead of declaring incompleteness on
        // the first scan that cannot resolve it.
        if Instant::now() >= deadline {
            return Ok(CleanupReport {
                usage,
                empty: false,
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
