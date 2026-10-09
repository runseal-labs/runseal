use anyhow::{Result, anyhow};
use std::io;
use std::os::windows::io::{AsRawHandle, AsRawSocket, FromRawSocket, OwnedSocket};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Networking::WinSock::*;

struct Winsock;
impl Winsock {
    fn start() -> Result<Arc<Self>> {
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        let code = unsafe { WSAStartup(0x0202, &mut data) };
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code).into());
        }
        Ok(Arc::new(Self))
    }
}
impl Drop for Winsock {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}

struct Socket {
    handle: OwnedSocket,
    _winsock: Arc<Winsock>,
    write_closed: AtomicBool,
}
impl Socket {
    fn new(winsock: &Arc<Winsock>, flags: u32) -> Result<Self> {
        let handle = unsafe {
            WSASocketW(
                i32::from(AF_UNIX),
                SOCK_STREAM,
                0,
                std::ptr::null(),
                0,
                flags | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        if handle == INVALID_SOCKET {
            return Err(socket_error().into());
        }
        Ok(Self::from_raw(handle, winsock))
    }
    fn from_raw(handle: SOCKET, winsock: &Arc<Winsock>) -> Self {
        Self {
            handle: unsafe { OwnedSocket::from_raw_socket(handle as _) },
            _winsock: winsock.clone(),
            write_closed: AtomicBool::new(false),
        }
    }
    fn raw(&self) -> SOCKET {
        self.handle.as_raw_socket() as SOCKET
    }
}

fn socket_error() -> io::Error {
    let code = unsafe { WSAGetLastError() };
    if code == WSAEWOULDBLOCK {
        io::Error::from(io::ErrorKind::WouldBlock)
    } else {
        io::Error::from_raw_os_error(code)
    }
}

/// An owned local byte stream. The parent uses nonblocking socket operations;
/// the child endpoint supports synchronous CRT descriptor reads and writes.
#[derive(Clone)]
pub struct DuplexControl {
    socket: Arc<Socket>,
    output_guard: Arc<Socket>,
    output_finish: Arc<Mutex<OutputCompletion>>,
}
#[derive(Default)]
struct OutputCompletion {
    state: OutputFinish,
    deadline: Option<std::time::Instant>,
}
#[derive(Default)]
enum OutputFinish {
    #[default]
    Idle,
    Pending(std::thread::JoinHandle<io::Result<()>>),
    Finished,
    Failed,
}
pub(crate) struct ChildControl {
    socket: Arc<Socket>,
}
impl ChildControl {
    pub(crate) fn handle(&self) -> HANDLE {
        self.socket.raw() as HANDLE
    }
}

impl DuplexControl {
    pub(crate) fn pair() -> Result<(Self, ChildControl)> {
        let winsock = Winsock::start()?;
        let base = std::env::temp_dir().canonicalize()?;
        let directory = tempfile::Builder::new().prefix("rs").tempdir_in(&base)?;
        let resolved = directory.path().canonicalize()?;
        if !resolved.starts_with(&base) || resolved == base {
            let _ = directory.keep();
            return Err(anyhow!("invalid control namespace"));
        }
        let result = (|| {
            let path = directory.path().join("s");
            let name = path
                .to_str()
                .ok_or_else(|| anyhow!("control namespace is not Unicode"))?
                .as_bytes();
            let mut address: SOCKADDR_UN = unsafe { std::mem::zeroed() };
            address.sun_family = AF_UNIX;
            if name.len() >= address.sun_path.len() {
                return Err(anyhow!("control namespace exceeds platform limit"));
            }
            address.sun_path[..name.len()].copy_from_slice(name);
            let listener = Socket::new(&winsock, WSA_FLAG_OVERLAPPED)?;
            let child = Arc::new(Socket::new(&winsock, 0)?);
            let address_ptr = &address as *const _ as *const SOCKADDR;
            let length = std::mem::size_of_val(&address) as i32;
            if unsafe { bind(listener.raw(), address_ptr, length) } != 0
                || unsafe { listen(listener.raw(), 1) } != 0
            {
                return Err(socket_error().into());
            }
            for endpoint in [&listener, child.as_ref()] {
                let mut nonblocking = 1;
                if unsafe { ioctlsocket(endpoint.raw(), FIONBIO, &mut nonblocking) } != 0 {
                    return Err(socket_error().into());
                }
            }
            if unsafe { connect(child.raw(), address_ptr, length) } != 0 {
                let error = socket_error();
                if error.kind() != io::ErrorKind::WouldBlock {
                    return Err(error.into());
                }
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            let accepted = loop {
                let handle =
                    unsafe { accept(listener.raw(), std::ptr::null_mut(), std::ptr::null_mut()) };
                if handle != INVALID_SOCKET {
                    break handle;
                }
                let error = socket_error();
                if error.kind() != io::ErrorKind::WouldBlock {
                    return Err(error.into());
                }
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::from(io::ErrorKind::TimedOut).into());
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            };
            let parent = Socket::from_raw(accepted, &winsock);
            // Windows SDK afunix.h: _WSAIOR(IOC_VENDOR, 256).
            const GET_PEER_PID: u32 = IOC_OUT | IOC_VENDOR | 256;
            for endpoint in [&parent, child.as_ref()] {
                let mut peer_pid = 0u32;
                let mut returned = 0u32;
                if unsafe {
                    WSAIoctl(
                        endpoint.raw(),
                        GET_PEER_PID,
                        std::ptr::null(),
                        0,
                        &mut peer_pid as *mut _ as *mut _,
                        std::mem::size_of_val(&peer_pid) as u32,
                        &mut returned,
                        std::ptr::null_mut(),
                        None,
                    )
                } != 0
                {
                    return Err(socket_error().into());
                }
                if peer_pid
                    != unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() }
                {
                    return Err(anyhow!("control endpoint peer mismatch"));
                }
            }

            let mut nonblocking = 1;
            if unsafe { ioctlsocket(parent.raw(), FIONBIO, &mut nonblocking) } != 0 {
                return Err(socket_error().into());
            }
            let mut blocking = 0;
            if unsafe { ioctlsocket(child.raw(), FIONBIO, &mut blocking) } != 0 {
                return Err(socket_error().into());
            }
            drop(listener);
            // Connected endpoints retain the stream, not its transient namespace.
            std::fs::remove_file(path)?;
            Ok((
                Self {
                    socket: Arc::new(parent),
                    output_guard: child.clone(),
                    output_finish: Arc::new(Mutex::new(OutputCompletion::default())),
                },
                ChildControl { socket: child },
            ))
        })();
        directory.close().map_err(|_| crate::SandboxCleanupError)?;
        result
    }

    /// Close the retained output endpoint only after the owned process range
    /// has stopped. CRT CloseHandle would otherwise discard unread socket bytes.
    pub fn finish_output(&self, timeout: std::time::Duration) -> io::Result<()> {
        let candidate = std::time::Instant::now() + timeout;
        loop {
            let mut completion = self
                .output_finish
                .lock()
                .map_err(|_| io::Error::other("control output close unavailable"))?;
            let deadline = *completion.deadline.get_or_insert(candidate);
            completion.deadline = Some(deadline.min(candidate));
            let deadline = deadline.min(candidate);
            if matches!(completion.state, OutputFinish::Idle) {
                let socket = self.output_guard.clone();
                completion.state = OutputFinish::Failed;
                completion.state = OutputFinish::Pending(
                    std::thread::Builder::new()
                        .name("runseal-control-output-close".into())
                        .spawn(move || shutdown_send(&socket))?,
                );
            }
            match &completion.state {
                OutputFinish::Finished => return Ok(()),
                OutputFinish::Failed => {
                    return Err(io::Error::other("control output close failed"));
                }
                _ if std::time::Instant::now() >= deadline => {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                OutputFinish::Pending(worker) if output_close_finished(worker) => {
                    let OutputFinish::Pending(worker) =
                        std::mem::replace(&mut completion.state, OutputFinish::Failed)
                    else {
                        return Err(io::Error::other("control output close unavailable"));
                    };
                    worker
                        .join()
                        .map_err(|_| io::Error::other("control output close failed"))??;
                    completion.state = OutputFinish::Finished;
                }
                _ => {}
            }
            drop(completion);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    pub fn close_input(&self) -> io::Result<()> {
        shutdown_send(&self.socket)
    }
}

type OutputCloseWorker = std::thread::JoinHandle<io::Result<()>>;

fn output_close_finished(worker: &OutputCloseWorker) -> bool {
    unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(worker.as_raw_handle() as _, 0)
            == windows_sys::Win32::Foundation::WAIT_OBJECT_0
    }
}

fn retained_output_closers() -> &'static Mutex<Vec<OutputCloseWorker>> {
    static WORKERS: std::sync::OnceLock<Mutex<Vec<OutputCloseWorker>>> = std::sync::OnceLock::new();
    WORKERS.get_or_init(Mutex::default)
}

impl Drop for OutputCompletion {
    fn drop(&mut self) {
        let OutputFinish::Pending(worker) =
            std::mem::replace(&mut self.state, OutputFinish::Failed)
        else {
            return;
        };
        if output_close_finished(&worker) {
            let _ = worker.join();
            return;
        }
        let mut retained = retained_output_closers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut index = 0;
        while index < retained.len() {
            if output_close_finished(&retained[index]) {
                let _ = retained.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        retained.push(worker);
    }
}

fn shutdown_send(socket: &Socket) -> io::Result<()> {
    if socket.write_closed.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    if unsafe { shutdown(socket.raw(), SD_SEND) } != 0 {
        socket.write_closed.store(false, Ordering::Release);
        return Err(socket_error());
    }
    Ok(())
}

impl io::Read for DuplexControl {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = unsafe {
            recv(
                self.socket.raw(),
                bytes.as_mut_ptr(),
                bytes.len().min(i32::MAX as usize) as i32,
                0,
            )
        };
        if count < 0 {
            Err(socket_error())
        } else {
            Ok(count as usize)
        }
    }
}
impl io::Write for DuplexControl {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.socket.write_closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let count = unsafe {
            send(
                self.socket.raw(),
                bytes.as_ptr(),
                bytes.len().min(i32::MAX as usize) as i32,
                0,
            )
        };
        if count < 0 {
            Err(socket_error())
        } else {
            Ok(count as usize)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

type InvalidParameterHandler = unsafe extern "C" fn(*const u16, *const u16, *const u16, u32, usize);
unsafe extern "C" {
    fn _get_osfhandle(descriptor: i32) -> isize;
    fn _set_thread_local_invalid_parameter_handler(
        handler: Option<InvalidParameterHandler>,
    ) -> Option<InvalidParameterHandler>;
}
unsafe extern "C" fn ignore_invalid_descriptor(
    _: *const u16,
    _: *const u16,
    _: *const u16,
    _: u32,
    _: usize,
) {
}

/// Owns a duplicate of the caller's fixed descriptor 3. No descriptor number
/// or raw handle is accepted from the public execution request.
#[derive(Clone)]
pub struct InheritedControlEndpoint {
    socket: Arc<Socket>,
}
impl InheritedControlEndpoint {
    pub fn from_fd3() -> Result<Self> {
        let original = unsafe {
            // Missing descriptors must return an error rather than invoke Watson.
            let previous =
                _set_thread_local_invalid_parameter_handler(Some(ignore_invalid_descriptor));
            let handle = _get_osfhandle(3);
            _set_thread_local_invalid_parameter_handler(previous);
            handle
        };
        if original == -1 || original == -2 {
            return Err(io::Error::from(io::ErrorKind::NotFound).into());
        }
        for stream in [
            windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
            windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE,
            windows_sys::Win32::System::Console::STD_ERROR_HANDLE,
        ] {
            let standard = unsafe { windows_sys::Win32::System::Console::GetStdHandle(stream) };
            if standard != 0
                && standard != -1
                && unsafe {
                    windows_sys::Win32::Foundation::CompareObjectHandles(original, standard)
                } != 0
            {
                return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
            }
        }
        let winsock = Winsock::start()?;
        let mut protocol: WSAPROTOCOL_INFOW = unsafe { std::mem::zeroed() };
        let mut protocol_length = std::mem::size_of_val(&protocol) as i32;
        if unsafe {
            getsockopt(
                original as SOCKET,
                SOL_SOCKET,
                SO_PROTOCOL_INFOW,
                &mut protocol as *mut _ as *mut _,
                &mut protocol_length,
            )
        } != 0
        {
            return Err(io::Error::from(io::ErrorKind::Unsupported).into());
        }
        if protocol.iAddressFamily != i32::from(AF_UNIX) || protocol.iSocketType != SOCK_STREAM {
            return Err(io::Error::from(io::ErrorKind::Unsupported).into());
        }
        let mut address: SOCKADDR_UN = unsafe { std::mem::zeroed() };
        let mut address_length = std::mem::size_of_val(&address) as i32;
        if unsafe {
            getpeername(
                original as SOCKET,
                &mut address as *mut _ as *mut _,
                &mut address_length,
            )
        } != 0
        {
            return Err(io::Error::from(io::ErrorKind::Unsupported).into());
        }
        if unsafe {
            WSADuplicateSocketW(
                original as SOCKET,
                windows_sys::Win32::System::Threading::GetCurrentProcessId(),
                &mut protocol,
            )
        } != 0
        {
            return Err(socket_error().into());
        }
        let raw = unsafe {
            WSASocketW(
                FROM_PROTOCOL_INFO,
                FROM_PROTOCOL_INFO,
                FROM_PROTOCOL_INFO,
                &protocol,
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        if raw == INVALID_SOCKET {
            return Err(socket_error().into());
        }
        let socket = Socket::from_raw(raw, &winsock);
        let mut address: SOCKADDR_UN = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&address) as i32;
        if unsafe { getpeername(socket.raw(), &mut address as *mut _ as *mut _, &mut length) } != 0
        {
            return Err(io::Error::from(io::ErrorKind::Unsupported).into());
        }
        let mut nonblocking = 1;
        if unsafe { ioctlsocket(socket.raw(), FIONBIO, &mut nonblocking) } != 0 {
            return Err(socket_error().into());
        }
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    pub fn close_output(&self) -> io::Result<()> {
        shutdown_send(&self.socket)
    }
}
impl io::Read for InheritedControlEndpoint {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = unsafe {
            recv(
                self.socket.raw(),
                bytes.as_mut_ptr(),
                bytes.len().min(i32::MAX as usize) as i32,
                0,
            )
        };
        if count < 0 {
            Err(socket_error())
        } else {
            Ok(count as usize)
        }
    }
}
impl io::Write for InheritedControlEndpoint {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.socket.write_closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let count = unsafe {
            send(
                self.socket.raw(),
                bytes.as_ptr(),
                bytes.len().min(i32::MAX as usize) as i32,
                0,
            )
        };
        if count < 0 {
            Err(socket_error())
        } else {
            Ok(count as usize)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        FlsAlloc, FlsFree, FlsSetValue, GetCurrentProcess, WaitForSingleObject,
    };

    #[test]
    fn output_close_preserves_bytes_and_independent_input_half_close() -> Result<()> {
        let (mut control, child) = DuplexControl::pair()?;
        let bytes = b"control output";
        assert_eq!(
            unsafe { send(child.socket.raw(), bytes.as_ptr(), bytes.len() as _, 0) },
            bytes.len() as i32
        );
        control.finish_output(Duration::from_secs(1))?;
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let mut buffer = [0; 64];
            match control.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => received.extend_from_slice(&buffer[..count]),
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!(received, bytes);
        control.write_all(b"I")?;
        control.close_input()?;
        let mut byte = [0];
        assert_eq!(
            unsafe { recv(child.socket.raw(), byte.as_mut_ptr(), 1, 0) },
            1
        );
        assert_eq!(byte, [b'I']);
        assert_eq!(
            unsafe { recv(child.socket.raw(), byte.as_mut_ptr(), 1, 0) },
            0
        );
        control.clone().finish_output(Duration::ZERO)?;
        Ok(())
    }

    struct NativeExitGate {
        entered: std::sync::mpsc::Sender<()>,
        release: AtomicBool,
    }

    unsafe extern "system" fn hold_native_exit(value: *const std::ffi::c_void) {
        let gate = unsafe { Arc::from_raw(value.cast::<NativeExitGate>()) };
        let _ = gate.entered.send(());
        while !gate.release.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    struct NativeExitFixture {
        gate: Arc<NativeExitGate>,
        slot: u32,
        thread: Option<OwnedHandle>,
        spawned: bool,
    }

    impl Drop for NativeExitFixture {
        fn drop(&mut self) {
            self.gate.release.store(true, Ordering::Release);
            let ended = self.thread.as_ref().is_some_and(|thread| unsafe {
                WaitForSingleObject(thread.as_raw_handle() as _, 2000) == WAIT_OBJECT_0
            });
            if ended || !self.spawned {
                unsafe { FlsFree(self.slot) };
            }
        }
    }

    #[test]
    fn control_output_close_requires_native_exit_and_retains_owner_at_original_deadline()
    -> Result<()> {
        let (mut control, child) = DuplexControl::pair()?;
        let (entered, ready) = std::sync::mpsc::channel();
        let gate = Arc::new(NativeExitGate {
            entered,
            release: AtomicBool::new(false),
        });
        let slot = unsafe { FlsAlloc(Some(hold_native_exit)) };
        if slot == u32::MAX {
            return Err(io::Error::last_os_error().into());
        }
        let mut fixture = NativeExitFixture {
            gate: gate.clone(),
            slot,
            thread: None,
            spawned: false,
        };
        let socket = control.output_guard.clone();
        let worker_gate = gate.clone();
        // The injected owner runs the actual close; only its native exit is held.
        let worker = std::thread::Builder::new().spawn(move || {
            let value = Arc::into_raw(worker_gate);
            if unsafe { FlsSetValue(slot, value.cast()) } == 0 {
                let error = io::Error::last_os_error();
                drop(unsafe { Arc::from_raw(value) });
                return Err(error);
            }
            shutdown_send(&socket)
        })?;
        fixture.spawned = true;
        let id = worker.thread().id();
        let process = unsafe { GetCurrentProcess() };
        let mut duplicate = 0;
        if unsafe {
            DuplicateHandle(
                process,
                worker.as_raw_handle() as _,
                process,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            // Keep the unconfirmed owner even if the observation handle failed.
            control.output_finish.lock().unwrap().state = OutputFinish::Pending(worker);
            return Err(io::Error::last_os_error().into());
        }
        fixture.thread = Some(unsafe { OwnedHandle::from_raw_handle(duplicate as _) });
        control.output_finish.lock().unwrap().state = OutputFinish::Pending(worker);
        ready.recv_timeout(Duration::from_secs(2))?;
        let rust_finished = matches!(
            &control.output_finish.lock().unwrap().state,
            OutputFinish::Pending(worker) if worker.is_finished()
        );
        let native_pending = unsafe { WaitForSingleObject(duplicate, 0) } == WAIT_TIMEOUT;
        let actual_eof = control.read(&mut [0; 1])? == 0;
        drop(child);
        let (returned, done) = std::sync::mpsc::channel();
        let caller = std::thread::spawn(move || {
            let first = control.finish_output(Duration::from_millis(100));
            let retry_started = Instant::now();
            let retry = control.clone().finish_output(Duration::from_secs(10));
            let retry_elapsed = retry_started.elapsed();
            let deadline_not_extended = first
                .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
                && retry.is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
                && retry_elapsed < Duration::from_millis(100);
            drop(control);
            let _ = returned.send(deadline_not_extended);
            Ok(())
        });
        let timely = done.recv_timeout(Duration::from_millis(500));
        let retained_before_release = retained_output_closers()
            .lock()
            .unwrap()
            .iter()
            .any(|worker| worker.thread().id() == id);
        let still_pending = unsafe { WaitForSingleObject(duplicate, 0) } == WAIT_TIMEOUT;
        // Release and reap only fixture-owned native threads before assertions.
        gate.release.store(true, Ordering::Release);
        let native_ended = unsafe { WaitForSingleObject(duplicate, 2000) } == WAIT_OBJECT_0;
        if timely.is_err() {
            let _ = done.recv_timeout(Duration::from_secs(2));
        }
        let caller_ended =
            unsafe { WaitForSingleObject(caller.as_raw_handle() as _, 2000) } == WAIT_OBJECT_0;
        if caller_ended {
            caller
                .join()
                .map_err(|_| anyhow!("fixture caller failed"))??;
        } else {
            retained_output_closers().lock().unwrap().push(caller);
        }
        if native_ended {
            let mut retained = retained_output_closers().lock().unwrap();
            if let Some(index) = retained
                .iter()
                .position(|worker| worker.thread().id() == id)
            {
                let _ = retained.swap_remove(index).join();
            }
        }
        assert!(rust_finished && native_pending && actual_eof);
        assert_eq!(
            timely.ok(),
            Some(true),
            "close/retry/drop must honor the original native deadline"
        );
        assert!(
            retained_before_release && still_pending,
            "unconfirmed closer must remain owned"
        );
        assert!(native_ended && caller_ended);
        Ok(())
    }
}
