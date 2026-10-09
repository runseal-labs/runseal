use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, WriteFile};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeHandleStateW, PIPE_NOWAIT, SetNamedPipeHandleState,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// A bounded native write with an independently owned handle. The caller polls
/// completion and must join a cancelled write before reporting cleanup success.
pub struct CancellableOutput {
    handle: std::sync::Arc<OwnedHandle>,
    worker: Option<std::thread::JoinHandle<io::Result<usize>>>,
    console: bool,
    utf8_tail: Vec<u8>,
    progress: std::sync::Arc<AtomicU64>,
    cleanup_deadline: Option<std::time::Instant>,
}

impl CancellableOutput {
    pub fn stdout() -> io::Result<Self> {
        Self::from_source(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) })
    }

    pub fn stderr() -> io::Result<Self> {
        Self::from_source(unsafe { GetStdHandle(STD_ERROR_HANDLE) })
    }

    fn from_source(source: windows_sys::Win32::Foundation::HANDLE) -> io::Result<Self> {
        let process = unsafe { GetCurrentProcess() };
        let mut duplicate = 0;
        if unsafe {
            DuplicateHandle(
                process,
                source,
                process,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut mode = 0;
        let console =
            unsafe { windows_sys::Win32::System::Console::GetConsoleMode(duplicate, &mut mode) }
                != 0;
        Ok(Self {
            handle: std::sync::Arc::new(unsafe { OwnedHandle::from_raw_handle(duplicate as _) }),
            worker: None,
            console,
            utf8_tail: Vec::new(),
            progress: std::sync::Arc::new(AtomicU64::new(0)),
            cleanup_deadline: None,
        })
    }

    /// Native write completions, independent of the whole buffered chunk's ACK.
    /// This is a progress counter, not a public output-byte statistic.
    pub fn write_progress(&self) -> u64 {
        self.progress.load(Ordering::Acquire)
    }

    pub fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(worker) = &self.worker {
            if !output_worker_finished(worker) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let worker = self.worker.take().ok_or(io::ErrorKind::Other)?;
            return worker
                .join()
                .map_err(|_| io::Error::other("output worker failed"))?;
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let bytes = bytes[..bytes.len().min(64 * 1024)].to_vec();
        if self.console {
            let count = bytes.len();
            let mut combined = std::mem::take(&mut self.utf8_tail);
            combined.extend_from_slice(&bytes);
            let (text, tail) = console_text(&combined);
            self.utf8_tail = tail;
            if text.is_empty() {
                return Ok(count);
            }
            self.start_console_write(text, count)?;
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let handle = self.handle.clone();
        let progress = self.progress.clone();
        self.worker = Some(
            std::thread::Builder::new()
                .name("runseal-output".into())
                .spawn(move || {
                    let mut offset = 0;
                    while offset < bytes.len() {
                        let end = (offset + 4096).min(bytes.len());
                        let mut written = 0;
                        if unsafe {
                            WriteFile(
                                handle.as_raw_handle() as _,
                                bytes[offset..end].as_ptr().cast(),
                                (end - offset) as _,
                                &mut written,
                                std::ptr::null_mut(),
                            )
                        } == 0
                        {
                            return Err(io::Error::last_os_error());
                        }
                        if written == 0 {
                            return Err(io::ErrorKind::WriteZero.into());
                        }
                        offset += written as usize;
                        progress.fetch_add(u64::from(written), Ordering::Release);
                    }
                    Ok(offset)
                })?,
        );
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn start_console_write(&mut self, text: String, count: usize) -> io::Result<()> {
        let handle = self.handle.clone();
        let progress = self.progress.clone();
        self.worker = Some(
            std::thread::Builder::new()
                .name("runseal-console-output".into())
                .spawn(move || {
                    let units: Vec<u16> = text.encode_utf16().collect();
                    let mut offset = 0;
                    while offset < units.len() {
                        let mut end = (offset + 1024).min(units.len());
                        if end < units.len() && (0xd800..=0xdbff).contains(&units[end - 1]) {
                            end -= 1;
                        }
                        let mut written = 0;
                        if unsafe {
                            windows_sys::Win32::System::Console::WriteConsoleW(
                                handle.as_raw_handle() as _,
                                units[offset..end].as_ptr().cast(),
                                (end - offset) as _,
                                &mut written,
                                std::ptr::null(),
                            )
                        } == 0
                        {
                            return Err(io::Error::last_os_error());
                        }
                        if written == 0 {
                            return Err(io::ErrorKind::WriteZero.into());
                        }
                        offset += written as usize;
                        progress.fetch_add(u64::from(written), Ordering::Release);
                    }
                    Ok(count)
                })?,
        );
        Ok(())
    }

    /// Complete a healthy console stream, rendering a final incomplete sequence
    /// as a replacement character without changing caller console configuration.
    pub fn flush(&mut self, deadline: std::time::Instant) -> io::Result<()> {
        self.cleanup_deadline = Some(
            self.cleanup_deadline
                .map_or(deadline, |previous| previous.min(deadline)),
        );
        let deadline = self.cleanup_deadline.ok_or(io::ErrorKind::Other)?;
        if self.worker.is_none() && !self.utf8_tail.is_empty() {
            self.utf8_tail.clear();
            self.start_console_write("\u{fffd}".into(), 0)?;
        }
        while let Some(worker) = &self.worker {
            if output_worker_finished(worker) {
                let worker = self.worker.take().ok_or(io::ErrorKind::Other)?;
                return worker
                    .join()
                    .map_err(|_| io::Error::other("output worker failed"))?
                    .map(|_| ());
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "output flush deadline",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(())
    }

    pub fn finish(&mut self, deadline: std::time::Instant) -> io::Result<()> {
        self.cleanup_deadline = Some(
            self.cleanup_deadline
                .map_or(deadline, |previous| previous.min(deadline)),
        );
        let deadline = self.cleanup_deadline.ok_or(io::ErrorKind::Other)?;
        self.utf8_tail.clear();
        while let Some(worker) = &self.worker {
            if output_worker_finished(worker) {
                let worker = self.worker.take().ok_or(io::ErrorKind::Other)?;
                // An interrupted write is a transport failure, but a joined
                // worker has released all of its owned I/O resources.
                let _ = worker
                    .join()
                    .map_err(|_| io::Error::other("output worker failed"))?;
                return Ok(());
            }
            unsafe {
                windows_sys::Win32::System::IO::CancelSynchronousIo(worker.as_raw_handle() as _);
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "output cleanup deadline",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(())
    }
}

fn console_text(mut bytes: &[u8]) -> (String, Vec<u8>) {
    let mut text = String::new();
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(valid) => {
                text.push_str(valid);
                return (text, Vec::new());
            }
            Err(error) => {
                if let Ok(valid) = std::str::from_utf8(&bytes[..error.valid_up_to()]) {
                    text.push_str(valid);
                }
                bytes = &bytes[error.valid_up_to()..];
                let Some(length) = error.error_len() else {
                    return (text, bytes.to_vec());
                };
                text.push('\u{fffd}');
                bytes = &bytes[length..];
            }
        }
    }
    (text, Vec::new())
}

impl Drop for CancellableOutput {
    fn drop(&mut self) {
        let deadline = self
            .cleanup_deadline
            .unwrap_or_else(|| std::time::Instant::now() + std::time::Duration::from_secs(2));
        let _ = self.finish(deadline);
        if let Some(worker) = self.worker.take() {
            let mut retained = retained_output_workers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut index = 0;
            while index < retained.len() {
                if output_worker_finished(&retained[index]) {
                    let _ = retained.swap_remove(index).join();
                } else {
                    index += 1;
                }
            }
            retained.push(worker);
        }
    }
}

type OutputWorker = std::thread::JoinHandle<io::Result<usize>>;
fn output_worker_finished(worker: &OutputWorker) -> bool {
    unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(worker.as_raw_handle() as _, 0)
            == windows_sys::Win32::Foundation::WAIT_OBJECT_0
    }
}
fn retained_output_workers() -> &'static std::sync::Mutex<Vec<OutputWorker>> {
    static WORKERS: std::sync::OnceLock<std::sync::Mutex<Vec<OutputWorker>>> =
        std::sync::OnceLock::new();
    WORKERS.get_or_init(std::sync::Mutex::default)
}

/// An owned duplicate of a caller's byte output pipe. No writer thread is
/// needed, and the shared endpoint's original wait mode is restored on drop.
pub struct NonblockingOutputPipe {
    handle: OwnedHandle,
    original_mode: u32,
}

impl NonblockingOutputPipe {
    pub fn stdout() -> io::Result<Option<Self>> {
        Self::from_stdio(STD_OUTPUT_HANDLE)
    }

    pub fn stderr() -> io::Result<Option<Self>> {
        Self::from_stdio(STD_ERROR_HANDLE)
    }

    fn from_stdio(stream: u32) -> io::Result<Option<Self>> {
        let source = unsafe { GetStdHandle(stream) };
        Self::from_source(source)
    }

    fn from_source(source: windows_sys::Win32::Foundation::HANDLE) -> io::Result<Option<Self>> {
        if unsafe { GetFileType(source) } != FILE_TYPE_PIPE {
            return Ok(None);
        }
        let mut duplicate = 0;
        let process = unsafe { GetCurrentProcess() };
        if unsafe {
            DuplicateHandle(
                process,
                source,
                process,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(duplicate as _) };
        let mut original_mode = 0;
        if unsafe {
            GetNamedPipeHandleStateW(
                duplicate,
                &mut original_mode,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mode = original_mode | PIPE_NOWAIT;
        if unsafe { SetNamedPipeHandleState(duplicate, &mode, std::ptr::null(), std::ptr::null()) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self {
            handle,
            original_mode,
        }))
    }
}

impl io::Write for NonblockingOutputPipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = bytes.len().min(4096) as u32;
        let mut written = 0;
        if unsafe {
            WriteFile(
                self.handle.as_raw_handle() as _,
                bytes.as_ptr().cast(),
                count,
                &mut written,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(written as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for NonblockingOutputPipe {
    fn drop(&mut self) {
        unsafe {
            SetNamedPipeHandleState(
                self.handle.as_raw_handle() as _,
                &self.original_mode,
                std::ptr::null(),
                std::ptr::null(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    struct NativeExitGate {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::atomic::AtomicBool,
    }

    unsafe extern "system" fn hold_native_exit(value: *const std::ffi::c_void) {
        let gate = unsafe { std::sync::Arc::from_raw(value.cast::<NativeExitGate>()) };
        let _ = gate.entered.send(());
        while !gate.release.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    struct NativeExitFixture {
        gate: std::sync::Arc<NativeExitGate>,
        slot: u32,
        thread: Option<OwnedHandle>,
        spawned: bool,
    }
    impl Drop for NativeExitFixture {
        fn drop(&mut self) {
            self.gate.release.store(true, Ordering::Release);
            let ended = self.thread.as_ref().is_some_and(|thread| unsafe {
                windows_sys::Win32::System::Threading::WaitForSingleObject(
                    thread.as_raw_handle() as _,
                    2000,
                ) == windows_sys::Win32::Foundation::WAIT_OBJECT_0
            });
            if ended || !self.spawned {
                unsafe { windows_sys::Win32::System::Threading::FlsFree(self.slot) };
            }
        }
    }

    fn output_with_held_native_exit() -> io::Result<(CancellableOutput, NativeExitFixture)> {
        use windows_sys::Win32::System::Threading::{FlsAlloc, FlsSetValue};
        let mut reader = 0;
        let mut writer = 0;
        if unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null_mut(), 4096) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let reader = unsafe { OwnedHandle::from_raw_handle(reader as _) };
        let writer = unsafe { OwnedHandle::from_raw_handle(writer as _) };
        let mut output = CancellableOutput::from_source(writer.as_raw_handle() as _)?;
        let (entered, ready) = std::sync::mpsc::channel();
        let gate = std::sync::Arc::new(NativeExitGate {
            entered,
            release: std::sync::atomic::AtomicBool::new(false),
        });
        let slot = unsafe { FlsAlloc(Some(hold_native_exit)) };
        if slot == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        let mut fixture = NativeExitFixture {
            gate: gate.clone(),
            slot,
            thread: None,
            spawned: false,
        };
        let handle = output.handle.clone();
        let progress = output.progress.clone();
        output.worker = Some(std::thread::Builder::new().spawn(move || {
            let value = std::sync::Arc::into_raw(gate);
            if unsafe { FlsSetValue(slot, value.cast()) } == 0 {
                let error = io::Error::last_os_error();
                drop(unsafe { std::sync::Arc::from_raw(value) });
                return Err(error);
            }
            let mut written = 0;
            if unsafe {
                WriteFile(
                    handle.as_raw_handle() as _,
                    b"X".as_ptr().cast(),
                    1,
                    &mut written,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            progress.fetch_add(u64::from(written), Ordering::Release);
            Ok(written as usize)
        })?);
        fixture.spawned = true;
        let worker = output.worker.as_ref().expect("owned native writer");
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
            return Err(io::Error::last_os_error());
        }
        fixture.thread = Some(unsafe { OwnedHandle::from_raw_handle(duplicate as _) });
        ready
            .recv_timeout(std::time::Duration::from_secs(2))
            .map_err(|_| io::Error::other("native exit readiness"))?;
        assert!(worker.is_finished());
        assert_eq!(
            unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(duplicate, 0) },
            windows_sys::Win32::Foundation::WAIT_TIMEOUT
        );
        let mut byte = [0];
        let mut read = 0;
        if unsafe {
            ReadFile(
                reader.as_raw_handle() as _,
                byte.as_mut_ptr().cast(),
                1,
                &mut read,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        assert_eq!((read, byte), (1, [b'X']));
        assert_eq!(output.write_progress(), 1);
        Ok((output, fixture))
    }

    #[test]
    fn completed_native_write_keeps_its_owner_until_native_exit_for_poll_flush_finish_and_drop()
    -> io::Result<()> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        for operation in ["write", "flush", "finish", "drop"] {
            let (mut output, fixture) = output_with_held_native_exit()?;
            let id = output.worker.as_ref().expect("write owner").thread().id();
            let deadline = std::time::Instant::now();
            output.cleanup_deadline = Some(deadline);
            let (entered, active) = std::sync::mpsc::channel();
            let (returned, done) = std::sync::mpsc::channel();
            let caller = std::thread::spawn(move || {
                let _ = entered.send(());
                if operation == "drop" {
                    drop(output);
                    let _ = returned.send((None, None));
                } else {
                    let result = match operation {
                        "write" => output.write(b"X").map(|_| ()),
                        "flush" => output.flush(deadline),
                        _ => output.finish(deadline),
                    };
                    let _ = returned.send((result.err().map(|error| error.kind()), Some(output)));
                }
            });
            active
                .recv_timeout(std::time::Duration::from_secs(2))
                .map_err(|_| io::Error::other("caller readiness"))?;
            let early = done
                .recv_timeout(std::time::Duration::from_millis(500))
                .ok();
            let returned_before_release = early.is_some();
            let owner_preserved = early.as_ref().is_some_and(|(_, output)| {
                output.as_ref().map_or_else(
                    || {
                        retained_output_workers()
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|worker| worker.thread().id() == id)
                    },
                    |output| output.worker.is_some(),
                )
            });
            fixture.gate.release.store(true, Ordering::Release);
            assert_eq!(
                unsafe { WaitForSingleObject(caller.as_raw_handle() as _, 2000) },
                WAIT_OBJECT_0
            );
            caller
                .join()
                .map_err(|_| io::Error::other("output caller panic"))?;
            let (error, output) = match early {
                Some(result) => result,
                None => done
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .map_err(|_| io::Error::other("caller cleanup"))?,
            };
            assert_eq!(
                unsafe {
                    WaitForSingleObject(
                        fixture
                            .thread
                            .as_ref()
                            .expect("native observation")
                            .as_raw_handle() as _,
                        2000,
                    )
                },
                WAIT_OBJECT_0
            );
            if let Some(mut output) = output {
                output.finish(deadline)?;
            } else {
                let mut workers = retained_output_workers().lock().unwrap();
                if let Some(index) = workers.iter().position(|worker| worker.thread().id() == id) {
                    assert!(output_worker_finished(&workers[index]));
                    let _ = workers.swap_remove(index).join();
                }
            }
            assert!(
                returned_before_release,
                "{operation} must not block on pending native exit"
            );
            assert!(
                owner_preserved,
                "{operation} must keep its pending join owner"
            );
            assert_eq!(
                error,
                match operation {
                    "write" => Some(io::ErrorKind::WouldBlock),
                    "drop" => None,
                    _ => Some(io::ErrorKind::TimedOut),
                }
            );
        }
        Ok(())
    }

    #[test]
    fn retained_output_reaping_does_not_join_another_pending_native_exit() -> io::Result<()> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        let (mut first, first_fixture) = output_with_held_native_exit()?;
        let first_id = first.worker.as_ref().expect("first owner").thread().id();
        first.cleanup_deadline = Some(std::time::Instant::now());
        drop(first);
        let (mut second, second_fixture) = output_with_held_native_exit()?;
        let second_id = second.worker.as_ref().expect("second owner").thread().id();
        second.cleanup_deadline = Some(std::time::Instant::now());
        let (entered, active) = std::sync::mpsc::channel();
        let (returned, done) = std::sync::mpsc::channel();
        let caller = std::thread::spawn(move || {
            let _ = entered.send(());
            drop(second);
            let _ = returned.send(());
        });
        active
            .recv_timeout(std::time::Duration::from_secs(2))
            .map_err(|_| io::Error::other("reaper readiness"))?;
        let returned_before_release = done
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_ok();
        let retained_before_release = returned_before_release && {
            let workers = retained_output_workers().lock().unwrap();
            [first_id, second_id]
                .iter()
                .all(|id| workers.iter().any(|worker| worker.thread().id() == *id))
        };
        first_fixture.gate.release.store(true, Ordering::Release);
        second_fixture.gate.release.store(true, Ordering::Release);
        assert_eq!(
            unsafe { WaitForSingleObject(caller.as_raw_handle() as _, 2000) },
            WAIT_OBJECT_0
        );
        caller
            .join()
            .map_err(|_| io::Error::other("reaper caller panic"))?;
        for fixture in [&first_fixture, &second_fixture] {
            assert_eq!(
                unsafe {
                    WaitForSingleObject(
                        fixture
                            .thread
                            .as_ref()
                            .expect("native observation")
                            .as_raw_handle() as _,
                        2000,
                    )
                },
                WAIT_OBJECT_0
            );
        }
        let mut workers = retained_output_workers().lock().unwrap();
        for id in [first_id, second_id] {
            if let Some(index) = workers.iter().position(|worker| worker.thread().id() == id) {
                assert!(output_worker_finished(&workers[index]));
                let _ = workers.swap_remove(index).join();
            }
        }
        assert!(
            returned_before_release,
            "reaping must not block on another native exit"
        );
        assert!(
            retained_before_release,
            "both pending join owners must survive Drop"
        );
        Ok(())
    }

    #[test]
    fn expired_output_drop_retains_the_unjoined_native_write_owner() -> io::Result<()> {
        let mut reader = 0;
        let mut writer = 0;
        if unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null_mut(), 4096) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let reader = unsafe { OwnedHandle::from_raw_handle(reader as _) };
        let writer = unsafe { OwnedHandle::from_raw_handle(writer as _) };
        let mut output = CancellableOutput::from_source(writer.as_raw_handle() as _)?;
        assert_eq!(
            output.write(&[42; 64 * 1024]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut available = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::PeekNamedPipe(
                    reader.as_raw_handle() as _,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if available > 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "native write must enter the retained pipe"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let native = output.worker.take().expect("native output owner");
        let (joined_tx, joined_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        // A controlled owner fault prevents successful join after the actual
        // native write returns; retaining the outer owner also retains native.
        let owner = std::thread::spawn(move || {
            let result = native
                .join()
                .map_err(|_| io::Error::other("native write panic"))?;
            let _ = joined_tx.send(());
            let _ = release_rx.recv();
            result
        });
        let id = owner.thread().id();
        output.worker = Some(owner);
        assert_eq!(
            output.finish(std::time::Instant::now()).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        let start = std::time::Instant::now();
        drop(output);
        let duration = start.elapsed();
        let retained = retained_output_workers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|worker| worker.thread().id() == id);
        drop(reader);
        joined_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .map_err(io::Error::other)?;
        release_tx.send(()).map_err(io::Error::other)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let result = loop {
            let mut workers = retained_output_workers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(index) = workers
                .iter()
                .position(|worker| worker.thread().id() == id && worker.is_finished())
            {
                break workers
                    .swap_remove(index)
                    .join()
                    .map_err(|_| io::Error::other("retained output panic"))?;
            }
            drop(workers);
            assert!(std::time::Instant::now() < deadline, "owned fixture join");
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert!(
            result.is_err(),
            "closed pipe must fail its actual native write"
        );
        assert!(retained, "expired cleanup must retain the owner");
        assert!(
            duration < std::time::Duration::from_millis(500),
            "Drop cannot renew its deadline: {duration:?}"
        );
        Ok(())
    }

    #[test]
    fn slow_native_reader_exposes_progress_before_the_whole_chunk_is_acknowledged() -> io::Result<()>
    {
        let mut reader = 0;
        let mut writer = 0;
        if unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null_mut(), 4096) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let reader = unsafe { OwnedHandle::from_raw_handle(reader as _) };
        let writer = unsafe { OwnedHandle::from_raw_handle(writer as _) };
        let mut output = CancellableOutput::from_source(writer.as_raw_handle() as _)?;
        let payload: Vec<u8> = (0..64 * 1024).map(|index| (index % 251) as u8).collect();
        let start = std::time::Instant::now();
        let deadline = start + std::time::Duration::from_secs(12);
        assert_eq!(
            output.write(&payload).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let mut actual = Vec::new();
        for index in 0..16 {
            let required = (index + 1) * 4096;
            while output.write_progress() < required {
                assert!(
                    std::time::Instant::now() < deadline,
                    "native completion must be observable"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if index < 15 {
                assert!(
                    !output
                        .worker
                        .as_ref()
                        .expect("owned native write")
                        .is_finished()
                );
                assert_eq!(
                    output.write(&payload).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            }
            // Consumer pacing is deliberate; native completions and exact bytes
            // are the oracle, not a sleep followed by assumed progress.
            std::thread::sleep(std::time::Duration::from_millis(350));
            let mut bytes = [0; 4096];
            let mut written = 0;
            if unsafe {
                ReadFile(
                    reader.as_raw_handle() as _,
                    bytes.as_mut_ptr(),
                    bytes.len() as _,
                    &mut written,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            assert_eq!(written, 4096);
            actual.extend_from_slice(&bytes);
        }
        assert!(start.elapsed() > std::time::Duration::from_secs(5));
        loop {
            match output.write(&payload) {
                Ok(count) => {
                    assert_eq!(count, payload.len());
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        }
        output.finish(deadline)?;
        assert_eq!(output.write_progress(), payload.len() as u64);
        assert_eq!(actual, payload);
        Ok(())
    }

    #[test]
    fn real_blocked_native_write_is_cancelled_and_joined_with_reader_still_open() -> io::Result<()>
    {
        let mut reader = 0;
        let mut writer = 0;
        if unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null_mut(), 4096) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let reader = unsafe { OwnedHandle::from_raw_handle(reader as _) };
        let writer = unsafe { OwnedHandle::from_raw_handle(writer as _) };
        let mut output = CancellableOutput::from_source(writer.as_raw_handle() as _)?;
        let payload = vec![42; 64 * 1024];
        assert_eq!(
            output.write(&payload).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut available = 0;
            if unsafe {
                windows_sys::Win32::System::Pipes::PeekNamedPipe(
                    reader.as_raw_handle() as _,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if available > 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "write must enter the actual pipe"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!output.worker.as_ref().expect("write owner").is_finished());
        assert_eq!(
            output.write(&payload).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            output.finish(std::time::Instant::now()).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(
            output.worker.is_some(),
            "a deadline failure retains the real worker owner"
        );
        // A separate fixture repair may join our own worker; it does not renew
        // the failed execution's original lifecycle deadline.
        output.cleanup_deadline = None;
        output.finish(deadline)?;
        assert!(output.worker.is_none(), "joined worker required");
        // The caller endpoints remain valid; cancellation closes only the duplicate.
        assert_ne!(unsafe { GetFileType(reader.as_raw_handle() as _) }, 0);
        assert_ne!(unsafe { GetFileType(writer.as_raw_handle() as _) }, 0);
        Ok(())
    }

    #[test]
    fn real_native_file_output_preserves_all_binary_bytes() -> io::Result<()> {
        let mut file = tempfile::tempfile()?;
        let mut output = CancellableOutput::from_source(file.as_raw_handle() as _)?;
        let payload: Vec<u8> = (0..129 * 1024).map(|index| (index % 256) as u8).collect();
        let mut remaining = payload.as_slice();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !remaining.is_empty() {
            match output.write(remaining) {
                Ok(count) => {
                    assert!(count > 0);
                    remaining = &remaining[count..];
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        }
        output.finish(deadline)?;
        assert!(output.worker.is_none());
        use std::io::{Read, Seek};
        file.rewind()?;
        let mut actual = Vec::new();
        file.read_to_end(&mut actual)?;
        assert_eq!(actual, payload);
        Ok(())
    }

    #[test]
    fn real_output_pipe_preserves_bytes_reports_stall_and_restores_wait_mode() -> io::Result<()> {
        let mut reader = 0;
        let mut writer = 0;
        if unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null_mut(), 4096) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let reader = unsafe { OwnedHandle::from_raw_handle(reader as _) };
        let writer = unsafe { OwnedHandle::from_raw_handle(writer as _) };
        let mut pipe = NonblockingOutputPipe::from_source(writer.as_raw_handle() as _)?
            .expect("anonymous output pipe");
        let payload: Vec<u8> = (0..4096).map(|index| (index % 256) as u8).collect();
        assert_eq!(pipe.write(&payload)?, payload.len());
        assert_eq!(
            pipe.write(&payload).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let mut received = vec![0; payload.len()];
        let mut count = 0;
        if unsafe {
            ReadFile(
                reader.as_raw_handle() as _,
                received.as_mut_ptr(),
                received.len() as _,
                &mut count,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        assert_eq!(count as usize, payload.len());
        assert_eq!(received, payload);
        assert_eq!(pipe.write(b"final")?, 5);
        drop(reader);
        assert!(pipe.write(b"closed").is_err());
        drop(pipe);
        let mut mode = PIPE_NOWAIT;
        if unsafe {
            GetNamedPipeHandleStateW(
                writer.as_raw_handle() as _,
                &mut mode,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        assert_eq!(mode, 0, "caller wait mode must be restored");
        Ok(())
    }
}
