use super::*;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const HELPER: &str = r#"
import ctypes as c,ctypes.wintypes as w,sys
k=c.WinDLL('kernel32',use_last_error=True)
class O(c.Structure):
    _fields_=[('Internal',c.c_size_t),('InternalHigh',c.c_size_t),('Offset',w.DWORD),('OffsetHigh',w.DWORD),('hEvent',w.HANDLE)]
k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE];k.CreateFileW.restype=w.HANDLE
k.CreateEventW.argtypes=[c.c_void_p,w.BOOL,w.BOOL,w.LPCWSTR];k.CreateEventW.restype=w.HANDLE
k.DeviceIoControl.argtypes=[w.HANDLE,w.DWORD,c.c_void_p,w.DWORD,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.POINTER(O)];k.DeviceIoControl.restype=w.BOOL
k.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];k.WaitForSingleObject.restype=w.DWORD
k.GetOverlappedResult.argtypes=[w.HANDLE,c.POINTER(O),c.POINTER(w.DWORD),w.BOOL];k.GetOverlappedResult.restype=w.BOOL
k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
h=k.CreateFileW(sys.argv[1],0xc0000000,7,None,3,0x40000080,None)
assert h!=c.c_void_p(-1).value,c.get_last_error()
ov=O();ov.hEvent=k.CreateEventW(None,True,False,None);assert ov.hEvent
n=w.DWORD()
r=k.DeviceIoControl(h,0x90000,None,0,None,0,c.byref(n),c.byref(ov))
assert not r and c.get_last_error()==997,c.get_last_error()
print('READY',flush=True)
assert k.WaitForSingleObject(ov.hEvent,10000)==0,'oplock break timeout'
assert k.GetOverlappedResult(h,c.byref(ov),c.byref(n),False),c.get_last_error()
print('BROKEN',flush=True)
assert sys.stdin.buffer.read(1)==b'R'
assert k.CloseHandle(h);assert k.CloseHandle(ov.hEvent)
print('CLOSED',flush=True)
"#;

struct FileReadGate {
    child: Child,
    input: Option<ChildStdin>,
    notices: Receiver<Result<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl FileReadGate {
    fn spawn(path: &std::path::Path) -> Result<Self> {
        let mut child = Command::new(python()?)
            .args(["-u", "-c", HELPER])
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().context("oplock input")?;
        let output = child.stdout.take().context("oplock output")?;
        let (sender, notices) = mpsc::sync_channel(4);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if sender.send(line.map_err(anyhow::Error::from)).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            input: Some(input),
            notices,
            reader: Some(reader),
        })
    }
    fn notice(&self) -> Result<String> {
        self.notices
            .recv_timeout(Duration::from_secs(3))
            .context("oplock notice")?
    }
    fn release(&mut self) -> Result<std::process::ExitStatus> {
        if let Some(mut input) = self.input.take() {
            input.write_all(b"R")?;
            input.flush()?;
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            anyhow::ensure!(Instant::now() < deadline, "oplock helper exit");
            std::thread::sleep(Duration::from_millis(5));
        };
        if let Some(reader) = self.reader.as_ref() {
            anyhow::ensure!(
                unsafe { WaitForSingleObject(reader.as_raw_handle(), 2000) } == WAIT_OBJECT_0,
                "oplock reader native exit"
            );
        }
        if let Some(reader) = self.reader.take() {
            anyhow::ensure!(reader.join().is_ok(), "oplock reader join");
        }
        Ok(status)
    }
}
impl Drop for FileReadGate {
    fn drop(&mut self) {
        if self.release().is_err() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            if unsafe { WaitForSingleObject(reader.as_raw_handle(), 2000) } == WAIT_OBJECT_0 {
                let _ = reader.join();
            } else {
                // Keep an unconfirmed fixture owner instead of detaching it.
                static READERS: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>> =
                    std::sync::Mutex::new(Vec::new());
                READERS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(reader);
            }
        }
    }
}

fn native_children(parent: u32) -> Result<Vec<u32>> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    anyhow::ensure!(snapshot != INVALID_HANDLE_VALUE, "owned process snapshot");
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    anyhow::ensure!(
        unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } != 0,
        "process snapshot first"
    );
    let mut children = Vec::new();
    loop {
        if entry.th32ParentProcessID == parent {
            children.push(entry.th32ProcessID);
        }
        if unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } == 0 {
            anyhow::ensure!(
                unsafe { GetLastError() } == ERROR_NO_MORE_FILES,
                "process snapshot complete"
            );
            return Ok(children);
        }
    }
}

#[test]
fn native_storage_admission_keeps_controls_live_and_disconnect_prevents_late_launch() -> Result<()>
{
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    let _guard = windows_test_gate();
    for mode in ["rpc", "service"] {
        for disconnect in [false, true] {
            let tmp = TempDir::new()?;
            let input_path = tmp.path().join("input.bin");
            let input = b"owned storage input bytes";
            std::fs::write(&input_path, input)?;
            let mut gate = FileReadGate::spawn(&input_path)?;
            let mut client = Client::spawn(mode)?;
            let ready = gate.notice()?;
            client.send(1,"execute",json!({"command":[python()?,"-u","-c","import os,sys; print('READY '+str(os.getpid()),flush=True); sys.stdin.buffer.read()"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}))?;
            let peer_receipt = client.next(Duration::from_secs(3))?;
            let peer = peer_receipt["result"]["execution_id"]
                .as_str()
                .context("peer receipt")?
                .to_owned();
            let peer_pid = wait_ready_pid(&client, &peer)?;
            let peer_handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, peer_pid) };
            anyhow::ensure!(!peer_handle.is_null(), "peer native observation");
            let peer_handle = unsafe { OwnedHandle::from_raw_handle(peer_handle) };
            client.send(2,"execute",json!({"command":[python()?,"-u","-c","import os,pathlib,sys,time; pathlib.Path('target.pid').write_text(str(os.getpid())); data=sys.stdin.buffer.read(); pathlib.Path('input.count').write_text(str(len(data))); print('READY '+str(os.getpid()),flush=True); deadline=time.monotonic()+5\nwhile not pathlib.Path('target.release').exists() and time.monotonic()<deadline: time.sleep(.01)\npathlib.Path('target.ran').write_text('ran'); sys.exit(7)"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"file","path":"input.bin"}}))?;
            let broken = gate.notice()?;
            client.send(3, "getVersion", json!({}))?;
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut version = None;
            let mut premature = false;
            while Instant::now() < deadline {
                match client.messages.recv_timeout(Duration::from_millis(50)) {
                    Ok(Ok(message)) => {
                        if message["id"] == 2 {
                            premature = true;
                        }
                        if message["id"] == 3 {
                            version = Some(message);
                            break;
                        }
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            let mut peer_query = None;
            if version.is_some() {
                client.send(4, "getExecution", json!({"execution_id":peer}))?;
                loop {
                    let message = client.next(Duration::from_secs(2))?;
                    if message["id"] == 2 {
                        premature = true;
                    }
                    if message["id"] == 4 {
                        peer_query = Some(message);
                        break;
                    }
                }
            }
            let held = gate.child.try_wait()?.is_none();
            let no_other_native_child = native_children(client.child.id())?
                .iter()
                .all(|pid| *pid == peer_pid);
            let not_started = !tmp.path().join("target.pid").exists()
                && !tmp.path().join("input.count").exists()
                && !tmp.path().join("target.ran").exists();
            let peer_live =
                unsafe { WaitForSingleObject(peer_handle.as_raw_handle(), 0) } == WAIT_TIMEOUT;
            let mut native_target_exited = true;
            let mut terminal = None;
            let mut host_ended_while_held = true;
            if disconnect || version.is_none() {
                drop(client.input.take());
                if version.is_some() {
                    let deadline = Instant::now() + Duration::from_secs(13);
                    while client.child.try_wait()?.is_none() && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    host_ended_while_held =
                        client.child.try_wait()?.is_some() && gate.child.try_wait()?.is_none();
                } else {
                    host_ended_while_held = false;
                }
                // Release only the fixture file, then let a broken synchronous
                // implementation drain its own EOF before any assertion.
                let helper_status = gate.release()?;
                drop(client);
                anyhow::ensure!(helper_status.success(), "oplock helper result");
            } else {
                client.send(
                    5,
                    "closeExecutionInput",
                    json!({"execution_id":peer,"stream":"stdin"}),
                )?;
                let deadline = Instant::now() + Duration::from_secs(3);
                while unsafe { WaitForSingleObject(peer_handle.as_raw_handle(), 0) }
                    != WAIT_OBJECT_0
                    && Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let helper_status = gate.release()?;
                anyhow::ensure!(helper_status.success(), "oplock helper result");
                let receipt = loop {
                    let message = client.next(Duration::from_secs(3))?;
                    if message["id"] == 2 {
                        break message;
                    }
                };
                let id = receipt["result"]["execution_id"]
                    .as_str()
                    .context("target receipt")?
                    .to_owned();
                let pid = wait_ready_pid(&client, &id)?;
                let handle = unsafe {
                    OpenProcess(
                        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                        0,
                        pid,
                    )
                };
                anyhow::ensure!(!handle.is_null(), "target native observation");
                let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
                std::fs::write(tmp.path().join("target.release"), b"R")?;
                loop {
                    let message = client.next(Duration::from_secs(3))?;
                    if message["params"]["execution_id"] == id
                        && matches!(
                            message["params"]["type"].as_str(),
                            Some("execution.finished" | "execution.failed")
                        )
                    {
                        terminal = Some(message["params"].clone());
                        break;
                    }
                }
                let mut code = 0;
                native_target_exited = unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) }
                    == WAIT_OBJECT_0
                    && unsafe { GetExitCodeProcess(handle.as_raw_handle(), &mut code) } != 0
                    && code == 7;
                drop(client);
            }
            let peer_gone =
                unsafe { WaitForSingleObject(peer_handle.as_raw_handle(), 0) } == WAIT_OBJECT_0;
            assert_eq!(ready, "READY");
            assert_eq!(broken, "BROKEN");
            assert!(
                held && not_started
                    && no_other_native_child
                    && peer_live
                    && !premature
                    && version.is_some()
            );
            assert!(peer_gone && host_ended_while_held && native_target_exited);
            assert_eq!(
                version.as_ref().context("version response")?["result"]["protocol_version"],
                "runseal.protocol/v2"
            );
            assert_eq!(
                peer_query.as_ref().context("peer query")?["result"]["status"],
                "running"
            );
            if disconnect {
                assert!(
                    !tmp.path().join("target.pid").exists()
                        && !tmp.path().join("input.count").exists()
                        && !tmp.path().join("target.ran").exists()
                );
            } else {
                let terminal = terminal.context("target terminal")?;
                assert_eq!(terminal["result"]["exit_code"], 7);
                assert_eq!(terminal["result"]["cleanup_complete"], true);
                assert_eq!(
                    std::fs::read_to_string(tmp.path().join("input.count"))?,
                    input.len().to_string()
                );
                let audit = std::fs::read_to_string(
                    tmp.path()
                        .join(terminal["audit_path"].as_str().context("audit path")?),
                )?;
                let records = audit
                    .lines()
                    .map(serde_json::from_str::<Value>)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                assert_eq!(records.last(), Some(&terminal));
                assert_eq!(
                    records
                        .iter()
                        .filter(|event| matches!(
                            event["type"].as_str(),
                            Some("execution.finished" | "execution.failed")
                        ))
                        .count(),
                    1
                );
            }
        }
    }
    Ok(())
}

#[test]
fn configured_cleanup_deadline_controls_public_blocked_file_admission_on_disconnect() -> Result<()>
{
    let _guard = windows_test_gate();
    let mut elapsed = Vec::new();
    for mode in ["rpc", "service"] {
        for milliseconds in [500u64, 1500] {
            let tmp = TempDir::new()?;
            let path = tmp.path().join("input.bin");
            std::fs::write(&path, b"owned input")?;
            let mut gate = FileReadGate::spawn(&path)?;
            let value = std::ffi::OsString::from(milliseconds.to_string());
            let mut client = Client::spawn_with_env_values(
                mode,
                &[("RUNSEAL_CLEANUP_TIMEOUT_MS", value.as_os_str())],
            )?;
            let ready = gate.notice()?;
            client.send(1, "getCapabilities", json!({}))?;
            let capabilities = client.next(Duration::from_secs(2))?;
            client.send(2,"execute",json!({"command":[python()?,"-c","import pathlib; pathlib.Path('target.ran').write_text('ran')"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"file","path":"input.bin"}}))?;
            let broken = gate.notice()?;
            let start = Instant::now();
            drop(client.input.take());
            let deadline = Instant::now() + Duration::from_secs(3);
            while client.child.try_wait()?.is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let duration = start.elapsed();
            let ended_held = client.child.try_wait()?.is_some() && gate.child.try_wait()?.is_none();
            let helper = gate.release()?;
            drop(client);
            assert!(helper.success() && ended_held);
            assert_eq!(ready, "READY");
            assert_eq!(broken, "BROKEN");
            assert_eq!(
                capabilities["result"]["limits"]["cleanup_timeout_ms"],
                milliseconds
            );
            assert!(
                duration >= Duration::from_millis(milliseconds.saturating_sub(100))
                    && duration < Duration::from_millis(milliseconds + 1000),
                "configured cleanup {milliseconds}: {duration:?}"
            );
            assert!(!tmp.path().join("target.ran").exists());
            elapsed.push(duration);
        }
    }
    assert!(elapsed[1] > elapsed[0] + Duration::from_millis(600));
    assert!(elapsed[3] > elapsed[2] + Duration::from_millis(600));
    Ok(())
}
