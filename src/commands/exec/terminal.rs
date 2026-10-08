#[cfg(windows)]
mod windows {
    use crate::execution::ExecutionControl;
    use std::io::IsTerminal;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread::JoinHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Console::*;

    pub(crate) struct TerminalFrontend {
        modes: Vec<(usize, u32)>,
        dimensions: (u16, u16),
        stop: Arc<AtomicBool>,
        watcher: Option<JoinHandle<Result<(), String>>>,
        cleanup_deadline: Option<std::time::Instant>,
    }

    fn dimensions(handle: HANDLE) -> Result<(u16, u16), String> {
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } == 0 {
            return Err("terminal size unavailable".to_string());
        }
        let rows = i32::from(info.srWindow.Bottom) - i32::from(info.srWindow.Top) + 1;
        let cols = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
        if !(1..=1000).contains(&rows) || !(1..=1000).contains(&cols) {
            return Err("terminal dimensions must be 1..1000".to_string());
        }
        Ok((rows as u16, cols as u16))
    }

    #[derive(Default)]
    pub(crate) struct ConsoleInput {
        pending_surrogate: Option<u16>,
    }

    impl ConsoleInput {
        pub(crate) fn read(&mut self) -> std::io::Result<Vec<u8>> {
            use std::fmt::Write;
            let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
            let mut available = 0;
            if unsafe { GetNumberOfConsoleInputEvents(handle, &mut available) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            if available == 0 {
                return Ok(Vec::new());
            }
            let mut records: [INPUT_RECORD; 128] = unsafe { std::mem::zeroed() };
            let mut count = 0;
            if unsafe {
                ReadConsoleInputW(handle, records.as_mut_ptr(), available.min(128), &mut count)
            } == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let mut bytes = String::new();
            let mut chars = Vec::new();
            if let Some(pending) = self.pending_surrogate.take() {
                chars.push(pending);
            }
            for record in &records[..count as usize] {
                if record.EventType != KEY_EVENT as u16 {
                    continue;
                }
                let key = unsafe { record.Event.KeyEvent };
                if key.wVirtualKeyCode == 0 && key.wVirtualScanCode == 0 && key.wRepeatCount <= 1 {
                    // With VT input enabled, conhost can return character-only
                    // records containing already encoded terminal sequences.
                    if key.bKeyDown != 0 {
                        chars.push(unsafe { key.uChar.UnicodeChar });
                    }
                    continue;
                }
                bytes.push_str(
                    &String::from_utf16(&chars)
                        .map_err(|_| std::io::Error::other("invalid terminal character input"))?,
                );
                chars.clear();
                // Preserve native key records when no VT character encoding has
                // been applied by the console.
                write!(
                    bytes,
                    "\x1b[{};{};{};{};{};{}_",
                    key.wVirtualKeyCode,
                    key.wVirtualScanCode,
                    unsafe { key.uChar.UnicodeChar },
                    u8::from(key.bKeyDown != 0),
                    key.dwControlKeyState,
                    key.wRepeatCount
                )
                .map_err(|_| std::io::Error::other("terminal input encoding failed"))?;
            }
            if chars
                .last()
                .is_some_and(|ch| (0xd800..=0xdbff).contains(ch))
            {
                self.pending_surrogate = chars.pop();
            }
            bytes.push_str(
                &String::from_utf16(&chars)
                    .map_err(|_| std::io::Error::other("invalid terminal character input"))?,
            );
            Ok(bytes.into_bytes())
        }
    }

    #[derive(Default)]
    pub(crate) struct ConsoleLineInput {
        pending: Vec<u8>,
        draining_line: bool,
        surrogate: Option<u16>,
    }

    impl ConsoleLineInput {
        pub(crate) fn read(&mut self, max_bytes: usize) -> std::io::Result<Option<Vec<u8>>> {
            if !self.pending.is_empty() {
                let count = self.pending.len().min(max_bytes);
                return Ok(Some(self.pending.drain(..count).collect()));
            }
            if max_bytes < 8 {
                return Ok(None);
            }
            let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
            let mut mode = 0;
            if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let line_mode = mode & ENABLE_LINE_INPUT != 0;
            // A UTF-16 code unit expands to at most three UTF-8 bytes; reserve
            // four bytes for a carried surrogate pair across native reads.
            let mut read_chars = if line_mode { (max_bytes - 4) / 3 } else { 1 };
            if !self.draining_line {
                let mut available = 0;
                if unsafe { GetNumberOfConsoleInputEvents(handle, &mut available) } == 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if available == 0 {
                    return Ok(None);
                }
                if available > 64 * 1024 {
                    return Err(std::io::Error::other("console input record limit exceeded"));
                }
                let mut records: Vec<INPUT_RECORD> = (0..available)
                    .map(|_| unsafe { std::mem::zeroed() })
                    .collect();
                let mut count = 0;
                if unsafe { PeekConsoleInputW(handle, records.as_mut_ptr(), available, &mut count) }
                    == 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                let mut characters = records[..count as usize].iter().filter_map(|record| {
                    if record.EventType != KEY_EVENT as u16 {
                        return None;
                    }
                    let key = unsafe { record.Event.KeyEvent };
                    let character = unsafe { key.uChar.UnicodeChar };
                    // Alt composition publishes its character on Alt key-up.
                    ((key.bKeyDown != 0 || key.wVirtualKeyCode == 18) && character != 0)
                        .then_some(character)
                });
                let complete = if line_mode {
                    characters.any(|character| matches!(character, 10 | 13))
                } else {
                    match characters.next() {
                        Some(character) if (0xd800..=0xdbff).contains(&character) => {
                            read_chars = 2;
                            characters
                                .next()
                                .is_some_and(|character| (0xdc00..=0xdfff).contains(&character))
                        }
                        Some(_) => true,
                        None => false,
                    }
                };
                if !complete {
                    return Ok(None);
                }
            }
            // Leave incomplete cooked input in the caller's console buffer.
            // Once a line terminator is queued, the native reader retains its
            // editing/EOF behavior without an idle ReadConsoleW holding stdin.
            let mut chars = vec![0u16; read_chars];
            let mut count = 0;
            if unsafe {
                ReadConsoleW(
                    handle,
                    chars.as_mut_ptr().cast(),
                    chars.len() as _,
                    &mut count,
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if count == 0 || (line_mode && chars.first() == Some(&26)) {
                return Ok(Some(Vec::new()));
            }
            chars.truncate(count as usize);
            self.draining_line = line_mode && !matches!(chars.last(), Some(10 | 13));
            if let Some(surrogate) = self.surrogate.take() {
                chars.insert(0, surrogate);
            }
            if chars
                .last()
                .is_some_and(|ch| (0xd800..=0xdbff).contains(ch))
            {
                self.surrogate = chars.pop();
            }
            self.pending = String::from_utf16(&chars)
                .map_err(|_| std::io::Error::other("invalid console character input"))?
                .into_bytes();
            if self.pending.is_empty() {
                return Ok(None);
            }
            let count = self.pending.len().min(max_bytes);
            Ok(Some(self.pending.drain(..count).collect()))
        }
    }

    impl TerminalFrontend {
        pub(crate) fn new(control: ExecutionControl) -> Result<Self, String> {
            let mut frontend = Self {
                modes: Vec::new(),
                dimensions: (24, 80),
                stop: Arc::new(AtomicBool::new(false)),
                watcher: None,
                cleanup_deadline: None,
            };
            if std::io::stdin().is_terminal() {
                let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
                frontend.set_mode(handle, |mode| {
                    (mode
                        & !(ENABLE_ECHO_INPUT
                            | ENABLE_LINE_INPUT
                            | ENABLE_PROCESSED_INPUT
                            | ENABLE_QUICK_EDIT_MODE))
                        | ENABLE_EXTENDED_FLAGS
                        | ENABLE_VIRTUAL_TERMINAL_INPUT
                })?;
            }
            if std::io::stdout().is_terminal() {
                let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
                frontend.dimensions = dimensions(handle)?;
                frontend.set_mode(handle, |mode| {
                    mode | ENABLE_PROCESSED_OUTPUT
                        | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                        | DISABLE_NEWLINE_AUTO_RETURN
                })?;
                let stop = frontend.stop.clone();
                let initial = frontend.dimensions;
                let handle = handle as usize;
                frontend.watcher = Some(
                    std::thread::Builder::new()
                        .name("terminal-resize".to_string())
                        .spawn(move || {
                            let mut previous = initial;
                            let result = (|| {
                                while !stop.load(Ordering::Acquire) && control.cause().is_none() {
                                    let current = dimensions(handle as HANDLE)?;
                                    if current != previous {
                                        if control.resize(current.0, current.1).is_err() {
                                            if control.cause().is_some() {
                                                break;
                                            }
                                            return Err("terminal resize rejected".to_string());
                                        }
                                        previous = current;
                                    }
                                    std::thread::sleep(std::time::Duration::from_millis(50));
                                }
                                Ok(())
                            })();
                            if result.is_err() {
                                control.cancel();
                            }
                            result
                        })
                        .map_err(|_| "failed to start terminal resize watcher".to_string())?,
                );
            }
            Ok(frontend)
        }

        fn set_mode(
            &mut self,
            handle: HANDLE,
            configure: impl FnOnce(u32) -> u32,
        ) -> Result<(), String> {
            let mut original = 0;
            if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
                return Err("terminal mode unavailable".to_string());
            }
            if unsafe { SetConsoleMode(handle, configure(original)) } == 0 {
                return Err("terminal mode setup failed".to_string());
            }
            self.modes.push((handle as usize, original));
            Ok(())
        }

        pub(crate) fn dimensions(&self) -> (u16, u16) {
            self.dimensions
        }

        fn stop_watcher(&mut self, deadline: std::time::Instant) -> Result<(), String> {
            if let Some(watcher) = self.watcher.as_ref() {
                while !crate::execution::retained::thread_finished(watcher) {
                    if std::time::Instant::now() >= deadline {
                        return Err("terminal resize watcher did not stop".to_string());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
            if let Some(watcher) = self.watcher.take() {
                // Operational errors already requested cancellation; cleanup
                // checks the worker join and mode restoration independently.
                let _ = watcher
                    .join()
                    .map_err(|_| "terminal resize watcher failed".to_string())?;
            }
            Ok(())
        }

        pub(crate) fn finish(&mut self, deadline: std::time::Instant) -> Result<(), String> {
            self.cleanup_deadline = Some(
                self.cleanup_deadline
                    .map_or(deadline, |previous| previous.min(deadline)),
            );
            let deadline = self
                .cleanup_deadline
                .ok_or_else(|| "terminal cleanup deadline unavailable".to_string())?;
            self.stop.store(true, Ordering::Release);
            let watcher_result = self.stop_watcher(deadline);
            let mut restored = true;
            let mut failed_modes = Vec::new();
            for (handle, mode) in self.modes.drain(..).rev() {
                if unsafe { SetConsoleMode(handle as HANDLE, mode) } == 0 {
                    restored = false;
                    failed_modes.push((handle, mode));
                }
            }
            self.modes = failed_modes.into_iter().rev().collect();
            if !restored {
                return Err("terminal mode restoration failed".to_string());
            }
            watcher_result
        }
    }

    impl Drop for TerminalFrontend {
        fn drop(&mut self) {
            let deadline = self
                .cleanup_deadline
                .unwrap_or_else(|| std::time::Instant::now() + std::time::Duration::from_secs(2));
            let _ = self.finish(deadline);
            if let Some(watcher) = self.watcher.take() {
                crate::execution::retained::retain(watcher);
            }
        }
    }
}

#[cfg(windows)]
pub(super) use windows::ConsoleInput;
#[cfg(windows)]
pub(super) use windows::ConsoleLineInput;
#[cfg(windows)]
pub(super) use windows::TerminalFrontend;

#[cfg(not(windows))]
pub(super) struct TerminalFrontend;

#[cfg(not(windows))]
impl TerminalFrontend {
    pub(crate) fn new(_: crate::execution::ExecutionControl) -> Result<Self, String> {
        Err("BACKEND_CAPABILITY_MISSING: CLI PTY unavailable on this platform".to_string())
    }
    pub(crate) fn dimensions(&self) -> (u16, u16) {
        (24, 80)
    }
    pub(crate) fn finish(&mut self, _: std::time::Instant) -> Result<(), String> {
        Ok(())
    }
}
