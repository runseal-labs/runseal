//! Inherited Windows byte pipes for native asynchronous child runtimes.
use rand::{Rng, SeedableRng};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::{
    fs::File,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::Pipes::*};

#[derive(Clone)]
pub(crate) struct BytePipe {
    parent: Arc<File>,
    child_guard: Arc<Mutex<Option<File>>>,
    input_closed: Arc<AtomicBool>,
}
impl BytePipe {
    pub(crate) fn pair() -> io::Result<(Self, File)> {
        let nonce: u128 = rand::rngs::SmallRng::from_entropy().r#gen();
        let name = crate::winutil::to_wide(format!(r"\\.\pipe\runseal-control-{nonce:032x}"));
        unsafe {
            let server = CreateNamedPipeW(
                name.as_ptr(),
                3 | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                std::ptr::null(),
            );
            if server == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let parent = File::from_raw_handle(server as _);
            let client = CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                0,
            );
            if client == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let child = File::from_raw_handle(client as _);
            if ConnectNamedPipe(server, std::ptr::null_mut()) == 0
                && GetLastError() != ERROR_PIPE_CONNECTED
            {
                return Err(io::Error::last_os_error());
            }
            let mut pid = 0;
            if GetNamedPipeClientProcessId(server, &mut pid) == 0
                || pid != windows_sys::Win32::System::Threading::GetCurrentProcessId()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "control endpoint peer mismatch",
                ));
            }
            let guard = child.try_clone()?;
            Ok((
                Self {
                    parent: Arc::new(parent),
                    child_guard: Arc::new(Mutex::new(Some(guard))),
                    input_closed: Arc::new(AtomicBool::new(false)),
                },
                child,
            ))
        }
    }
    /// Seal input at the owner. Windows duplex pipes cannot independently send EOF.
    pub(crate) fn close_input(&self) -> io::Result<()> {
        self.input_closed.store(true, Ordering::Release);
        Ok(())
    }
    /// Called after the managed range is empty, allowing the reader to drain to EOF.
    pub(crate) fn finish_output(&self) -> io::Result<()> {
        self.child_guard
            .lock()
            .map_err(|_| io::Error::other("control close unavailable"))?
            .take();
        Ok(())
    }
}
impl io::Read for BytePipe {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut count = 0;
        let ok = unsafe {
            ReadFile(
                self.parent.as_raw_handle() as _,
                bytes.as_mut_ptr(),
                bytes.len().min(u32::MAX as usize) as u32,
                &mut count,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            return Ok(count as usize);
        }
        match unsafe { GetLastError() } {
            ERROR_NO_DATA => Err(io::ErrorKind::WouldBlock.into()),
            ERROR_BROKEN_PIPE => Ok(0),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }
}
impl io::Write for BytePipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.input_closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut count = 0;
        let ok = unsafe {
            WriteFile(
                self.parent.as_raw_handle() as _,
                bytes.as_ptr(),
                bytes.len().min(u32::MAX as usize) as u32,
                &mut count,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(count as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
