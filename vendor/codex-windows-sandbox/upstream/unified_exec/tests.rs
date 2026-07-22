#![cfg(target_os = "windows")]

use super::spawn_windows_sandbox_session_elevated_for_permission_profile;
use super::spawn_windows_sandbox_session_legacy;
use crate::WindowsSandboxCancellationToken;
use crate::ipc_framed::Message;
use crate::ipc_framed::decode_bytes;
use crate::ipc_framed::read_frame;
use crate::run_windows_sandbox_capture;
use codex_protocol::models::ManagedFileSystemPermissions;
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_utils_pty::ProcessDriver;
use pretty_assertions::assert_eq;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use tempfile::TempDir;
use tokio::runtime::Builder;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::timeout;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Security::TOKEN_DUPLICATE;
use windows_sys::Win32::Security::TOKEN_IMPERSONATE;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::DataExchange::CloseClipboard;
use windows_sys::Win32::System::DataExchange::EmptyClipboard;
use windows_sys::Win32::System::DataExchange::GetClipboardData;
use windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber;
use windows_sys::Win32::System::DataExchange::OpenClipboard;
use windows_sys::Win32::System::Diagnostics::Debug::GetErrorMode;
use windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Process32FirstW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Process32NextW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use windows_sys::Win32::System::StationsAndDesktops::CloseWindowStation;
use windows_sys::Win32::System::StationsAndDesktops::GetProcessWindowStation;
use windows_sys::Win32::System::StationsAndDesktops::GetThreadDesktop;
use windows_sys::Win32::System::StationsAndDesktops::GetUserObjectInformationW;
use windows_sys::Win32::System::StationsAndDesktops::OpenWindowStationW;
use windows_sys::Win32::System::StationsAndDesktops::SetProcessWindowStation;
use windows_sys::Win32::System::StationsAndDesktops::UOI_NAME;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::System::Threading::OpenProcess;
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_ACCESSCLIPBOARD;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_ENUMDESKTOPS;
use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_READATTRIBUTES;

static TEST_HOME_COUNTER: AtomicU64 = AtomicU64::new(0);
static LEGACY_PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());
const REQUIRED_NONINTERACTIVE_ERROR_MODE: u32 = 0x0001 | 0x0002 | 0x8000;

fn legacy_process_test_guard() -> MutexGuard<'static, ()> {
    LEGACY_PROCESS_TEST_LOCK
        .lock()
        .expect("legacy Windows sandbox process test lock poisoned")
}

fn current_thread_runtime() -> tokio::runtime::Runtime {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
}

fn pwsh_path() -> Option<PathBuf> {
    let program_files = std::env::var_os("ProgramFiles")?;
    let path = PathBuf::from(program_files).join("PowerShell\\7\\pwsh.exe");
    path.is_file().then_some(path)
}

fn executable_on_path(file_name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(file_name))
        .find(|candidate| candidate.is_file())
}

fn workspace_contained_profile(workspace_root: &Path) -> PermissionProfile {
    let root = AbsolutePathBuf::from_absolute_path(workspace_root)
        .expect("workspace root must be absolute");
    let file_system = FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
        path: FileSystemPath::Path { path: root },
        access: FileSystemAccessMode::Write,
    }]);
    PermissionProfile::Managed {
        file_system: ManagedFileSystemPermissions::from_sandbox_policy(&file_system),
        network: NetworkSandboxPolicy::Restricted,
    }
}

fn windows_runtime_environment() -> HashMap<String, String> {
    const KEYS: &[&str] = &[
        "PATH",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PATHEXT",
    ];
    KEYS.iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| ((*key).to_string(), value))
        })
        .collect()
}

fn sandbox_cwd() -> PathBuf {
    if let Ok(workspace_root) = std::env::var("INSTA_WORKSPACE_ROOT") {
        return PathBuf::from(workspace_root);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn sandbox_home(name: &str) -> TempDir {
    let id = TEST_HOME_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("codex-windows-sandbox-{name}-{id}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create sandbox home");
    tempfile::TempDir::new_in(&path).expect("create sandbox home tempdir")
}

fn sandbox_log(codex_home: &Path) -> String {
    let log_path = crate::current_log_file_path(&codex_home.join(".sandbox"));
    fs::read_to_string(&log_path)
        .unwrap_or_else(|err| format!("failed to read {}: {err}", log_path.display()))
}

fn workspace_roots_for(root: &Path) -> Vec<AbsolutePathBuf> {
    vec![AbsolutePathBuf::from_absolute_path(root).expect("absolute workspace root")]
}

unsafe fn window_object_name(handle: isize) -> String {
    assert_ne!(handle, 0, "window object handle is unavailable");
    let mut required_bytes = 0;
    let _ = GetUserObjectInformationW(
        handle,
        UOI_NAME,
        std::ptr::null_mut(),
        0,
        &mut required_bytes,
    );
    assert!(required_bytes >= 2, "window object name is unavailable");
    let mut buffer = vec![0u16; required_bytes.div_ceil(2) as usize];
    assert_ne!(
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            buffer.as_mut_ptr().cast(),
            required_bytes,
            &mut required_bytes,
        ),
        0,
        "GetUserObjectInformationW failed"
    );
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

unsafe fn parent_process_id() -> u32 {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    assert_ne!(snapshot, INVALID_HANDLE_VALUE, "process snapshot failed");
    let mut entry: PROCESSENTRY32W = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let current_process_id = GetCurrentProcessId();
    let mut parent_process_id = 0;
    if Process32FirstW(snapshot, &mut entry) != 0 {
        loop {
            if entry.th32ProcessID == current_process_id {
                parent_process_id = entry.th32ParentProcessID;
                break;
            }
            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }
    }
    let _ = CloseHandle(snapshot);
    assert_ne!(parent_process_id, 0, "runner parent process was not found");
    parent_process_id
}

fn wait_for_frame_count(frames_path: &Path, expected_frames: usize) -> Vec<Message> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut reader = OpenOptions::new()
            .read(true)
            .open(frames_path)
            .expect("open frame file for read");
        reader
            .seek(SeekFrom::Start(0))
            .expect("seek to start of frame file");

        let mut frames = Vec::new();
        loop {
            match read_frame(&mut reader) {
                Ok(Some(frame)) => frames.push(frame.message),
                Ok(None) => break,
                Err(_) => break,
            }
        }

        if frames.len() >= expected_frames {
            return frames;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {expected_frames} frames, saw {}",
            frames.len()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn collect_stdout_and_exit(
    spawned: codex_utils_pty::SpawnedProcess,
    codex_home: &Path,
    timeout_duration: Duration,
) -> (Vec<u8>, i32) {
    let codex_utils_pty::SpawnedProcess {
        session: _session,
        mut stdout_rx,
        stderr_rx: _stderr_rx,
        exit_rx,
    } = spawned;
    let stdout_task = tokio::spawn(async move {
        let mut stdout = Vec::new();
        while let Some(chunk) = stdout_rx.recv().await {
            stdout.extend(chunk);
        }
        stdout
    });
    let exit_code = timeout(timeout_duration, exit_rx)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for exit\n{}", sandbox_log(codex_home)))
        .unwrap_or(-1);
    let stdout = timeout(timeout_duration, stdout_task)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "timed out waiting for stdout task\n{}",
                sandbox_log(codex_home)
            )
        })
        .expect("stdout task join");
    (stdout, exit_code)
}

#[test]
fn legacy_non_tty_cmd_emits_output() {
    let _guard = legacy_process_test_guard();
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let cwd = sandbox_cwd();
        let codex_home = sandbox_home("legacy-non-tty-cmd");
        println!("cmd codex_home={}", codex_home.path().display());
        let permission_profile = PermissionProfile::workspace_write();
        let spawned = spawn_windows_sandbox_session_legacy(
            &permission_profile,
            workspace_roots_for(cwd.as_path()).as_slice(),
            codex_home.path(),
            vec![
                "C:\\Windows\\System32\\cmd.exe".to_string(),
                "/c".to_string(),
                "echo LEGACY-NONTTY-CMD".to_string(),
            ],
            cwd.as_path(),
            HashMap::new(),
            Some(5_000),
            &[],
            /*tty*/ false,
            /*stdin_open*/ false,
            /*use_private_desktop*/ true,
        )
        .await
        .expect("spawn legacy non-tty cmd session");
        println!("cmd spawn returned");
        let (stdout, exit_code) =
            collect_stdout_and_exit(spawned, codex_home.path(), Duration::from_secs(10)).await;
        println!("cmd collect returned exit_code={exit_code}");
        let stdout = String::from_utf8_lossy(&stdout);
        assert_eq!(exit_code, 0, "stdout={stdout:?}");
        assert!(stdout.contains("LEGACY-NONTTY-CMD"), "stdout={stdout:?}");
    });
}

#[test]
fn elevated_non_tty_commands_emit_output_when_enabled() {
    if std::env::var_os("RUNSEAL_RUN_ELEVATED_SANDBOX_TESTS").is_none() {
        return;
    }
    let Some(codex_home) = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_HOME").map(PathBuf::from)
    else {
        eprintln!("set RUNSEAL_ELEVATED_SANDBOX_HOME to run elevated sandbox smoke test");
        return;
    };
    let cwd = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_CWD")
        .map(PathBuf::from)
        .unwrap_or_else(sandbox_cwd);
    assert!(
        codex_home.is_dir(),
        "RUNSEAL_ELEVATED_SANDBOX_HOME does not exist: {}",
        codex_home.display()
    );
    assert!(
        cwd.is_dir(),
        "RUNSEAL_ELEVATED_SANDBOX_CWD does not exist: {}",
        cwd.display()
    );
    let mut cases = vec![(
        "cmd",
        vec![
            "C:\\Windows\\System32\\cmd.exe".to_string(),
            "/c".to_string(),
            "echo ELEVATED-NONTTY-CMD".to_string(),
        ],
        "ELEVATED-NONTTY-CMD",
    )];
    if let Some(python) = executable_on_path("python.exe") {
        cases.push((
            "Python",
            vec![
                python.to_string_lossy().to_string(),
                "-c".to_string(),
                "print('ELEVATED-NONTTY-PYTHON')".to_string(),
            ],
            "ELEVATED-NONTTY-PYTHON",
        ));
    }
    if let Some(pwsh) = pwsh_path() {
        cases.push((
            "PowerShell",
            vec![
                pwsh.to_string_lossy().to_string(),
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "Write-Output ELEVATED-NONTTY-POWERSHELL".to_string(),
            ],
            "ELEVATED-NONTTY-POWERSHELL",
        ));
    }
    if let Some(uv) = executable_on_path("uv.exe") {
        cases.push((
            "uv",
            vec![uv.to_string_lossy().to_string(), "--version".to_string()],
            "uv ",
        ));
    }
    if let Some(git) = executable_on_path("git.exe") {
        if let Some(git_root) = git.parent().and_then(Path::parent) {
            let direct_git = git_root.join("mingw64\\bin\\git.exe");
            if direct_git.is_file() {
                cases.push((
                    "git-direct",
                    vec![
                        direct_git.to_string_lossy().to_string(),
                        "--version".to_string(),
                    ],
                    "git version",
                ));
            }
        }
        cases.push((
            "git-shim",
            vec![git.to_string_lossy().to_string(), "--version".to_string()],
            "git version",
        ));
    }
    let _guard = legacy_process_test_guard();
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        for (profile_name, permission_profile) in [
            ("workspace-write", PermissionProfile::workspace_write()),
            ("workspace-contained", workspace_contained_profile(&cwd)),
        ] {
            let profile_cases = if profile_name == "workspace-contained" {
                &cases[..1]
            } else {
                cases.as_slice()
            };
            for (name, command, marker) in profile_cases {
                let spawned = spawn_windows_sandbox_session_elevated_for_permission_profile(
                    &permission_profile,
                    workspace_roots_for(cwd.as_path()).as_slice(),
                    codex_home.as_path(),
                    command.clone(),
                    cwd.as_path(),
                    windows_runtime_environment(),
                    Some(10_000),
                    /*read_roots_override*/ None,
                    /*read_roots_include_platform_defaults*/ true,
                    /*write_roots_override*/ None,
                    &[],
                    /*tty*/ false,
                    /*stdin_open*/ false,
                    /*use_private_desktop*/ true,
                )
                .await
                .unwrap_or_else(|error| {
                    panic!("spawn elevated {profile_name} non-tty {name}: {error:#}")
                });
                let (stdout, exit_code) =
                    collect_stdout_and_exit(spawned, codex_home.as_path(), Duration::from_secs(15))
                        .await;
                let stdout = String::from_utf8_lossy(&stdout);
                assert_ne!(
                    exit_code, -1_073_741_502,
                    "{profile_name} {name} hit 0xc0000142"
                );
                assert_eq!(exit_code, 0, "{profile_name} {name} stdout={stdout:?}");
                assert!(
                    stdout.contains(marker),
                    "{profile_name} {name} stdout={stdout:?}"
                );
            }
        }
    });
}

#[test]
fn elevated_single_identity_blocks_direct_external_traffic_when_enabled() {
    if std::env::var_os("RUNSEAL_RUN_ELEVATED_SANDBOX_TESTS").is_none() {
        return;
    }
    let Some(codex_home) = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_HOME").map(PathBuf::from)
    else {
        return;
    };
    let cwd = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_CWD")
        .map(PathBuf::from)
        .unwrap_or_else(sandbox_cwd);
    let _guard = legacy_process_test_guard();
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let probes = [(
            "tcp",
            vec![
                "C:\\Windows\\System32\\curl.exe".to_string(),
                "--connect-timeout".to_string(),
                "2".to_string(),
                "--noproxy".to_string(),
                "*".to_string(),
                "http://1.1.1.1".to_string(),
            ],
        )];
        for (profile_name, permission_profile) in [
            ("workspace-write", PermissionProfile::workspace_write()),
            ("workspace-contained", workspace_contained_profile(&cwd)),
        ] {
            let identity = spawn_windows_sandbox_session_elevated_for_permission_profile(
                &permission_profile,
                workspace_roots_for(cwd.as_path()).as_slice(),
                codex_home.as_path(),
                vec!["C:\\Windows\\System32\\whoami.exe".to_string()],
                cwd.as_path(),
                windows_runtime_environment(),
                Some(5_000),
                /*read_roots_override*/ None,
                /*read_roots_include_platform_defaults*/ true,
                /*write_roots_override*/ None,
                &[],
                /*tty*/ false,
                /*stdin_open*/ false,
                /*use_private_desktop*/ true,
            )
            .await
            .unwrap_or_else(|error| {
                panic!("spawn elevated {profile_name} identity probe: {error:#}")
            });
            let (identity_stdout, identity_exit_code) =
                collect_stdout_and_exit(identity, codex_home.as_path(), Duration::from_secs(10))
                    .await;
            let identity_stdout = String::from_utf8_lossy(&identity_stdout).to_ascii_lowercase();
            assert_eq!(
                identity_exit_code, 0,
                "{profile_name} identity probe failed: {identity_stdout}"
            );
            assert!(
                identity_stdout.contains("\\runsealsandbox"),
                "{profile_name} ran under the wrong identity: {identity_stdout}"
            );
            for (probe_name, command) in &probes {
                let spawned = spawn_windows_sandbox_session_elevated_for_permission_profile(
                    &permission_profile,
                    workspace_roots_for(cwd.as_path()).as_slice(),
                    codex_home.as_path(),
                    command.clone(),
                    cwd.as_path(),
                    windows_runtime_environment(),
                    Some(5_000),
                    /*read_roots_override*/ None,
                    /*read_roots_include_platform_defaults*/ true,
                    /*write_roots_override*/ None,
                    &[],
                    /*tty*/ false,
                    /*stdin_open*/ false,
                    /*use_private_desktop*/ true,
                )
                .await
                .unwrap_or_else(|error| {
                    panic!("spawn elevated {profile_name} {probe_name} probe: {error:#}")
                });
                let (stdout, exit_code) =
                    collect_stdout_and_exit(spawned, codex_home.as_path(), Duration::from_secs(10))
                        .await;
                assert_ne!(
                    exit_code, -1_073_741_502,
                    "{profile_name} {probe_name} failed during DLL initialization"
                );
                assert_ne!(
                    exit_code,
                    0,
                    "{profile_name} {probe_name} unexpectedly reached the external network: {}",
                    String::from_utf8_lossy(&stdout)
                );
            }
        }
    });
}

#[test]
fn elevated_single_identity_allows_only_configured_loopback_proxy_when_enabled() {
    if std::env::var_os("RUNSEAL_RUN_ELEVATED_SANDBOX_TESTS").is_none() {
        return;
    }
    let Some(codex_home) = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_HOME").map(PathBuf::from)
    else {
        return;
    };
    let cwd = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_CWD")
        .map(PathBuf::from)
        .unwrap_or_else(sandbox_cwd);
    let _guard = legacy_process_test_guard();
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        for (profile_name, permission_profile) in [
            ("workspace-write", PermissionProfile::workspace_write()),
            ("workspace-contained", workspace_contained_profile(&cwd)),
        ] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback test proxy");
            listener
                .set_nonblocking(true)
                .expect("set proxy listener nonblocking");
            let port = listener.local_addr().expect("read proxy address").port();
            let proxy_server = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .expect("set proxy read timeout");
                            let mut request = [0u8; 2048];
                            let _ = stream.read(&mut request);
                            stream
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nproxy-ok",
                                )
                                .expect("write proxy response");
                            return;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "sandbox did not connect to configured proxy"
                            );
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => panic!("accept proxy connection: {error}"),
                    }
                }
            });

            let proxy_url = format!("http://127.0.0.1:{port}");
            let mut env = windows_runtime_environment();
            env.insert("HTTP_PROXY".to_string(), proxy_url.clone());
            env.insert("http_proxy".to_string(), proxy_url);
            env.insert("NO_PROXY".to_string(), String::new());
            env.insert("no_proxy".to_string(), String::new());

            let proxied = spawn_windows_sandbox_session_elevated_for_permission_profile(
                &permission_profile,
                workspace_roots_for(cwd.as_path()).as_slice(),
                codex_home.as_path(),
                vec![
                    "C:\\Windows\\System32\\curl.exe".to_string(),
                    "-sS".to_string(),
                    "--max-time".to_string(),
                    "3".to_string(),
                    "http://example.invalid/".to_string(),
                ],
                cwd.as_path(),
                env.clone(),
                Some(5_000),
                None,
                true,
                None,
                &[],
                false,
                false,
                true,
            )
            .await
            .unwrap_or_else(|error| panic!("spawn elevated {profile_name} proxy probe: {error:#}"));
            let (stdout, exit_code) =
                collect_stdout_and_exit(proxied, codex_home.as_path(), Duration::from_secs(10))
                    .await;
            proxy_server.join().expect("join proxy server");
            assert_eq!(
                exit_code,
                0,
                "{profile_name} proxy probe failed: {}",
                String::from_utf8_lossy(&stdout)
            );
            assert_eq!(String::from_utf8_lossy(&stdout), "proxy-ok");

            let direct = spawn_windows_sandbox_session_elevated_for_permission_profile(
                &permission_profile,
                workspace_roots_for(cwd.as_path()).as_slice(),
                codex_home.as_path(),
                vec![
                    "C:\\Windows\\System32\\curl.exe".to_string(),
                    "--connect-timeout".to_string(),
                    "2".to_string(),
                    "--noproxy".to_string(),
                    "*".to_string(),
                    "http://1.1.1.1".to_string(),
                ],
                cwd.as_path(),
                env,
                Some(5_000),
                None,
                true,
                None,
                &[],
                false,
                false,
                true,
            )
            .await
            .unwrap_or_else(|error| panic!("spawn elevated {profile_name} direct probe: {error:#}"));
            let (_, exit_code) =
                collect_stdout_and_exit(direct, codex_home.as_path(), Duration::from_secs(10)).await;
            assert_ne!(exit_code, -1_073_741_502, "{profile_name} direct probe hit 0xC0000142");
            assert_ne!(exit_code, 0, "{profile_name} bypassed the configured proxy");
        }
    });
}

#[test]
fn elevated_tty_cmd_emits_output_when_enabled() {
    if std::env::var_os("RUNSEAL_RUN_ELEVATED_SANDBOX_TESTS").is_none() {
        return;
    }
    let Some(codex_home) = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_HOME").map(PathBuf::from)
    else {
        return;
    };
    let cwd = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_CWD")
        .map(PathBuf::from)
        .unwrap_or_else(sandbox_cwd);
    let _guard = legacy_process_test_guard();
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let permission_profile = PermissionProfile::workspace_write();
        let spawned = spawn_windows_sandbox_session_elevated_for_permission_profile(
            &permission_profile,
            workspace_roots_for(cwd.as_path()).as_slice(),
            codex_home.as_path(),
            vec![
                "C:\\Windows\\System32\\cmd.exe".to_string(),
                "/c".to_string(),
                "echo ELEVATED-TTY-CMD".to_string(),
            ],
            cwd.as_path(),
            HashMap::new(),
            Some(10_000),
            /*read_roots_override*/ None,
            /*read_roots_include_platform_defaults*/ true,
            /*write_roots_override*/ None,
            &[],
            /*tty*/ true,
            /*stdin_open*/ true,
            /*use_private_desktop*/ true,
        )
        .await
        .expect("spawn elevated TTY cmd session");
        let (stdout, exit_code) =
            collect_stdout_and_exit(spawned, codex_home.as_path(), Duration::from_secs(15)).await;
        let stdout = String::from_utf8_lossy(&stdout);
        assert_eq!(exit_code, 0, "cmd TTY stdout={stdout:?}");
        assert!(
            stdout.contains("ELEVATED-TTY-CMD"),
            "cmd TTY stdout={stdout:?}"
        );
    });
}

#[test]
fn elevated_tty_workspace_contained_cmd_emits_output_when_enabled() {
    if std::env::var_os("RUNSEAL_RUN_ELEVATED_SANDBOX_TESTS").is_none() {
        return;
    }
    let Some(codex_home) = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_HOME").map(PathBuf::from)
    else {
        return;
    };
    let cwd = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_CWD")
        .map(PathBuf::from)
        .unwrap_or_else(sandbox_cwd);
    let _guard = legacy_process_test_guard();
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let permission_profile = workspace_contained_profile(cwd.as_path());
        let spawned = spawn_windows_sandbox_session_elevated_for_permission_profile(
            &permission_profile,
            workspace_roots_for(cwd.as_path()).as_slice(),
            codex_home.as_path(),
            vec![
                "C:\\Windows\\System32\\cmd.exe".to_string(),
                "/c".to_string(),
                "echo ELEVATED-CONTAINED-TTY-CMD".to_string(),
            ],
            cwd.as_path(),
            windows_runtime_environment(),
            Some(10_000),
            /*read_roots_override*/ None,
            /*read_roots_include_platform_defaults*/ true,
            /*write_roots_override*/ None,
            &[],
            /*tty*/ true,
            /*stdin_open*/ true,
            /*use_private_desktop*/ true,
        )
        .await
        .expect("spawn elevated workspace-contained TTY cmd session");
        let (stdout, exit_code) =
            collect_stdout_and_exit(spawned, codex_home.as_path(), Duration::from_secs(15)).await;
        let stdout = String::from_utf8_lossy(&stdout);
        assert_eq!(exit_code, 0, "contained cmd TTY stdout={stdout:?}");
        assert!(
            stdout.contains("ELEVATED-CONTAINED-TTY-CMD"),
            "contained cmd TTY stdout={stdout:?}"
        );
    });
}

#[test]
fn elevated_runner_enforces_noninteractive_ui_boundary_when_enabled() {
    if std::env::var_os("RUNSEAL_RUN_ELEVATED_SANDBOX_TESTS").is_none() {
        return;
    }
    let Some(codex_home) = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_HOME").map(PathBuf::from)
    else {
        return;
    };
    let cwd = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_CWD")
        .map(PathBuf::from)
        .unwrap_or_else(sandbox_cwd);
    let test_exe = std::env::current_exe().expect("current test executable");
    let _guard = legacy_process_test_guard();
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let mut env_map = windows_runtime_environment();
        env_map.insert("RUNSEAL_UI_ISOLATION_CHILD".to_string(), "1".to_string());
        let spawned = spawn_windows_sandbox_session_elevated_for_permission_profile(
            &PermissionProfile::workspace_write(),
            workspace_roots_for(cwd.as_path()).as_slice(),
            codex_home.as_path(),
            vec![
                test_exe.to_string_lossy().to_string(),
                "unified_exec::tests::sandbox_ui_isolation_child_probe".to_string(),
                "--exact".to_string(),
                "--nocapture".to_string(),
            ],
            cwd.as_path(),
            env_map,
            Some(10_000),
            /*read_roots_override*/ None,
            /*read_roots_include_platform_defaults*/ true,
            /*write_roots_override*/ None,
            &[],
            /*tty*/ false,
            /*stdin_open*/ false,
            /*use_private_desktop*/ true,
        )
        .await
        .expect("spawn elevated UI-boundary probe");
        let (stdout, exit_code) =
            collect_stdout_and_exit(spawned, codex_home.as_path(), Duration::from_secs(15)).await;
        let stdout = String::from_utf8_lossy(&stdout);
        assert_eq!(exit_code, 0, "UI-boundary probe failed; stdout={stdout:?}");
        assert!(
            stdout.contains("RUNSEAL_UI_ISOLATION_OK"),
            "UI-boundary probe did not report success; stdout={stdout:?}"
        );
    });
}

#[test]
fn elevated_runner_isolates_desktop_and_clipboard_when_enabled() {
    if std::env::var_os("RUNSEAL_RUN_ELEVATED_SANDBOX_TESTS").is_none() {
        return;
    }
    let Some(codex_home) = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_HOME").map(PathBuf::from)
    else {
        eprintln!("set RUNSEAL_ELEVATED_SANDBOX_HOME to run elevated sandbox smoke test");
        return;
    };
    if std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_CLIPBOARD_SENTINEL").is_none() {
        eprintln!(
            "set RUNSEAL_ELEVATED_SANDBOX_CLIPBOARD_SENTINEL after safely backing up the host clipboard"
        );
        return;
    }
    let cwd = std::env::var_os("RUNSEAL_ELEVATED_SANDBOX_CWD")
        .map(PathBuf::from)
        .unwrap_or_else(sandbox_cwd);
    assert!(codex_home.is_dir(), "sandbox home must exist");
    assert!(cwd.is_dir(), "sandbox cwd must exist");
    unsafe {
        assert_ne!(OpenClipboard(0), 0, "failed to open host clipboard");
        let clipboard_data = GetClipboardData(CF_UNICODETEXT as u32);
        let _ = CloseClipboard();
        assert_ne!(
            clipboard_data, 0,
            "host clipboard sentinel is not available as Unicode text"
        );
    }
    let host_clipboard_sequence = unsafe { GetClipboardSequenceNumber() };

    let test_exe = std::env::current_exe().expect("current test executable");
    let _guard = legacy_process_test_guard();
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        for (profile_name, permission_profile) in [
            ("workspace-write", PermissionProfile::workspace_write()),
            ("workspace-contained", workspace_contained_profile(&cwd)),
            ("read-only", PermissionProfile::read_only()),
        ] {
            let mut env_map = HashMap::new();
            env_map.insert("RUNSEAL_UI_ISOLATION_CHILD".to_string(), "1".to_string());
            let spawned = spawn_windows_sandbox_session_elevated_for_permission_profile(
                &permission_profile,
                workspace_roots_for(cwd.as_path()).as_slice(),
                codex_home.as_path(),
                vec![
                    test_exe.to_string_lossy().to_string(),
                    "unified_exec::tests::sandbox_ui_isolation_child_probe".to_string(),
                    "--exact".to_string(),
                    "--nocapture".to_string(),
                ],
                cwd.as_path(),
                env_map,
                Some(10_000),
                /*read_roots_override*/ None,
                /*read_roots_include_platform_defaults*/ true,
                /*write_roots_override*/ None,
                &[],
                /*tty*/ false,
                /*stdin_open*/ false,
                /*use_private_desktop*/ true,
            )
            .await
            .unwrap_or_else(|error| {
                panic!("spawn elevated {profile_name} UI isolation probe: {error:#}")
            });
            let (stdout, exit_code) =
                collect_stdout_and_exit(spawned, codex_home.as_path(), Duration::from_secs(15))
                    .await;
            let stdout = String::from_utf8_lossy(&stdout);
            assert_eq!(
                unsafe { GetClipboardSequenceNumber() },
                host_clipboard_sequence,
                "{profile_name} sandbox child changed the host clipboard"
            );
            assert_eq!(
                exit_code, 0,
                "{profile_name} sandbox UI isolation probe failed; stdout={stdout:?}"
            );
            assert!(
                stdout.contains("RUNSEAL_UI_ISOLATION_OK"),
                "{profile_name} sandbox UI isolation probe did not report success"
            );
        }
    });
}

#[test]
fn sandbox_ui_isolation_child_probe() {
    if std::env::var_os("RUNSEAL_UI_ISOLATION_CHILD").is_none() {
        return;
    }

    let error_mode = unsafe { GetErrorMode() };
    let private_window_station = unsafe { GetProcessWindowStation() };
    let window_station_name = unsafe { window_object_name(private_window_station) };
    let desktop_name = unsafe { window_object_name(GetThreadDesktop(GetCurrentThreadId())) };
    let isolated_window_station = !window_station_name.eq_ignore_ascii_case("Winsta0");
    let private_desktop = desktop_name.starts_with("RunSealSandboxDesktop-");
    let host_window_station_switch_blocked = unsafe {
        let winsta0 = crate::to_wide("Winsta0");
        let host_window_station = OpenWindowStationW(
            winsta0.as_ptr(),
            0,
            (WINSTA_ACCESSCLIPBOARD | WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES) as u32,
        );
        if host_window_station == 0 {
            true
        } else {
            let switched = SetProcessWindowStation(host_window_station) != 0;
            if switched {
                let _ = SetProcessWindowStation(private_window_station);
            }
            let _ = CloseWindowStation(host_window_station);
            !switched
        }
    };
    let runner_process_id = unsafe { parent_process_id() };
    let runner_token_access_blocked = unsafe {
        let runner_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, runner_process_id);
        if runner_process == 0 {
            true
        } else {
            let mut runner_token = 0;
            let token_opened = OpenProcessToken(
                runner_process,
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                &mut runner_token,
            ) != 0;
            if runner_token != 0 {
                let _ = CloseHandle(runner_token);
            }
            let _ = CloseHandle(runner_process);
            !token_opened
        }
    };

    let (clipboard_read_blocked, clipboard_clear_succeeded) = unsafe {
        if OpenClipboard(0) != 0 {
            let clipboard_data = GetClipboardData(CF_UNICODETEXT as u32);
            let empty_result = EmptyClipboard();
            let _ = CloseClipboard();
            (clipboard_data == 0, empty_result != 0)
        } else {
            (true, false)
        }
    };

    println!("RUNSEAL_UI_ISOLATED_WINDOW_STATION={isolated_window_station}");
    println!("RUNSEAL_UI_HOST_WINDOW_STATION_BLOCKED={host_window_station_switch_blocked}");
    println!("RUNSEAL_UI_RUNNER_TOKEN_BLOCKED={runner_token_access_blocked}");
    println!("RUNSEAL_UI_PRIVATE_DESKTOP={private_desktop}");
    println!("RUNSEAL_UI_CLIPBOARD_READ_BLOCKED={clipboard_read_blocked}");
    println!("RUNSEAL_UI_PRIVATE_CLIPBOARD_CLEARED={clipboard_clear_succeeded}");
    println!("RUNSEAL_NONINTERACTIVE_ERROR_MODE={error_mode:#x}");
    assert_eq!(
        error_mode & REQUIRED_NONINTERACTIVE_ERROR_MODE,
        REQUIRED_NONINTERACTIVE_ERROR_MODE,
        "sandbox child may display a system error dialog"
    );
    assert!(
        isolated_window_station,
        "sandbox child still uses the interactive window station"
    );
    assert!(
        host_window_station_switch_blocked,
        "sandbox child switched back to the interactive window station"
    );
    assert!(
        runner_token_access_blocked,
        "sandbox child opened the unrestricted command-runner token"
    );
    assert!(
        private_desktop,
        "sandbox child is attached to an unexpected desktop"
    );
    assert!(
        clipboard_read_blocked,
        "sandbox child read the host clipboard"
    );

    println!("RUNSEAL_UI_ISOLATION_OK");
}

#[test]
fn legacy_non_tty_powershell_emits_output() {
    let Some(pwsh) = pwsh_path() else {
        return;
    };
    let _guard = legacy_process_test_guard();
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let cwd = sandbox_cwd();
        let codex_home = sandbox_home("legacy-non-tty-pwsh");
        println!("pwsh codex_home={}", codex_home.path().display());
        let permission_profile = PermissionProfile::workspace_write();
        let spawned = spawn_windows_sandbox_session_legacy(
            &permission_profile,
            workspace_roots_for(cwd.as_path()).as_slice(),
            codex_home.path(),
            vec![
                pwsh.display().to_string(),
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "Write-Output LEGACY-NONTTY-DIRECT".to_string(),
            ],
            cwd.as_path(),
            HashMap::new(),
            Some(5_000),
            &[],
            /*tty*/ false,
            /*stdin_open*/ false,
            /*use_private_desktop*/ true,
        )
        .await
        .expect("spawn legacy non-tty powershell session");
        println!("pwsh spawn returned");
        let (stdout, exit_code) =
            collect_stdout_and_exit(spawned, codex_home.path(), Duration::from_secs(10)).await;
        println!("pwsh collect returned exit_code={exit_code}");
        let stdout = String::from_utf8_lossy(&stdout);
        assert_eq!(exit_code, 0, "stdout={stdout:?}");
        assert!(stdout.contains("LEGACY-NONTTY-DIRECT"), "stdout={stdout:?}");
    });
}

#[test]
fn finish_driver_spawn_keeps_stdin_open_when_requested() {
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Vec<u8>>(1);
        let (_stdout_tx, stdout_rx) = broadcast::channel::<Vec<u8>>(1);
        let (exit_tx, exit_rx) = oneshot::channel::<i32>();
        drop(exit_tx);

        let spawned = super::finish_driver_spawn(
            ProcessDriver {
                writer_tx,
                stdout_rx,
                stderr_rx: None,
                exit_rx,
                terminator: None,
                writer_handle: None,
                resizer: None,
            },
            /*stdin_open*/ true,
        );

        spawned
            .session
            .writer_sender()
            .send(b"open".to_vec())
            .await
            .expect("stdin should stay open");
        assert_eq!(writer_rx.recv().await, Some(b"open".to_vec()));
    });
}

#[test]
fn finish_driver_spawn_closes_stdin_when_not_requested() {
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let (writer_tx, _writer_rx) = mpsc::channel::<Vec<u8>>(1);
        let (_stdout_tx, stdout_rx) = broadcast::channel::<Vec<u8>>(1);
        let (exit_tx, exit_rx) = oneshot::channel::<i32>();
        drop(exit_tx);

        let spawned = super::finish_driver_spawn(
            ProcessDriver {
                writer_tx,
                stdout_rx,
                stderr_rx: None,
                exit_rx,
                terminator: None,
                writer_handle: None,
                resizer: None,
            },
            /*stdin_open*/ false,
        );

        assert!(
            spawned
                .session
                .writer_sender()
                .send(b"closed".to_vec())
                .await
                .is_err(),
            "stdin should be closed when streaming input is disabled"
        );
    });
}

#[test]
fn runner_stdin_writer_sends_close_stdin_after_input_eof() {
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let tempdir = TempDir::new().expect("create tempdir");
        let frames_path = tempdir.path().join("runner-stdin-frames.bin");
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&frames_path)
            .expect("create frame file");
        let outbound_tx = super::start_runner_pipe_writer(file);
        let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(1);
        let writer_handle = super::start_runner_stdin_writer(
            writer_rx,
            outbound_tx,
            /*normalize_newlines*/ false,
            /*stdin_open*/ true,
        );

        writer_tx
            .send(b"hello".to_vec())
            .await
            .expect("send stdin bytes");
        drop(writer_tx);
        writer_handle.await.expect("join stdin writer");

        let frames = wait_for_frame_count(&frames_path, 2);

        match &frames[0] {
            Message::Stdin { payload } => {
                let bytes = decode_bytes(&payload.data_b64).expect("decode stdin payload");
                assert_eq!(bytes, b"hello".to_vec());
            }
            other => panic!("expected stdin frame, got {other:?}"),
        }

        match &frames[1] {
            Message::CloseStdin { .. } => {}
            other => panic!("expected close-stdin frame, got {other:?}"),
        }
    });
}

#[test]
fn runner_resizer_sends_resize_frame() {
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let tempdir = TempDir::new().expect("create tempdir");
        let frames_path = tempdir.path().join("runner-resize-frames.bin");
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&frames_path)
            .expect("create frame file");
        let outbound_tx = super::start_runner_pipe_writer(file);
        let mut resizer = super::make_runner_resizer(outbound_tx);

        resizer(codex_utils_pty::TerminalSize {
            rows: 45,
            cols: 132,
        })
        .expect("send resize frame");

        let frames = wait_for_frame_count(&frames_path, 1);
        match &frames[0] {
            Message::Resize { payload } => {
                assert_eq!(payload.rows, 45);
                assert_eq!(payload.cols, 132);
            }
            other => panic!("expected resize frame, got {other:?}"),
        }
    });
}

#[test]
fn legacy_capture_powershell_emits_output() {
    let Some(pwsh) = pwsh_path() else {
        return;
    };
    let _guard = legacy_process_test_guard();
    let cwd = sandbox_cwd();
    let codex_home = sandbox_home("legacy-capture-pwsh");
    println!("capture pwsh codex_home={}", codex_home.path().display());
    let permission_profile = PermissionProfile::workspace_write();
    let result = run_windows_sandbox_capture(
        &permission_profile,
        workspace_roots_for(cwd.as_path()).as_slice(),
        codex_home.path(),
        vec![
            pwsh.display().to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "Write-Output LEGACY-CAPTURE-DIRECT".to_string(),
        ],
        cwd.as_path(),
        HashMap::new(),
        Some(10_000),
        /*cancellation*/ None,
        /*use_private_desktop*/ true,
    )
    .expect("run legacy capture powershell");
    println!("capture pwsh exit_code={}", result.exit_code);
    println!("capture pwsh timed_out={}", result.timed_out);
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    println!("capture pwsh stderr={stderr:?}");
    assert_eq!(result.exit_code, 0, "stdout={stdout:?} stderr={stderr:?}");
    assert!(
        stdout.contains("LEGACY-CAPTURE-DIRECT"),
        "stdout={stdout:?}"
    );
}

#[test]
fn legacy_capture_cancellation_is_not_reported_as_timeout() {
    let Some(pwsh) = pwsh_path() else {
        eprintln!("skipping cancellation regression test: PowerShell 7 is not installed");
        return;
    };
    let _guard = legacy_process_test_guard();
    let cwd = sandbox_cwd();
    let codex_home = sandbox_home("legacy-capture-cancel");
    let permission_profile = PermissionProfile::workspace_write();
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancelled_for_token = Arc::clone(&cancelled);
    let cancellation =
        WindowsSandboxCancellationToken::new(move || cancelled_for_token.load(Ordering::SeqCst));
    let cancelled_for_thread = Arc::clone(&cancelled);
    let cancel_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        cancelled_for_thread.store(true, Ordering::SeqCst);
    });

    let started_at = Instant::now();
    let result = run_windows_sandbox_capture(
        &permission_profile,
        workspace_roots_for(cwd.as_path()).as_slice(),
        codex_home.path(),
        vec![
            pwsh.display().to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "Start-Sleep -Seconds 30".to_string(),
        ],
        cwd.as_path(),
        HashMap::new(),
        Some(30_000),
        /*cancellation*/ Some(cancellation),
        /*use_private_desktop*/ true,
    )
    .expect("run legacy capture powershell with cancellation");
    cancel_thread.join().expect("cancel thread should finish");

    assert!(
        started_at.elapsed() < Duration::from_secs(10),
        "cancellation should end capture before the timeout"
    );
    assert!(
        !result.timed_out,
        "cancellation should not be reported as a timeout"
    );
    assert_ne!(result.exit_code, 0);
}

#[test]
fn legacy_tty_powershell_emits_output_and_accepts_input() {
    let Some(pwsh) = pwsh_path() else {
        return;
    };
    let _guard = legacy_process_test_guard();
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let cwd = sandbox_cwd();
        let codex_home = sandbox_home("legacy-tty-pwsh");
        println!("tty pwsh codex_home={}", codex_home.path().display());
        let permission_profile = PermissionProfile::workspace_write();
        let spawned = spawn_windows_sandbox_session_legacy(
            &permission_profile,
            workspace_roots_for(cwd.as_path()).as_slice(),
            codex_home.path(),
            vec![
                pwsh.display().to_string(),
                "-NoLogo".to_string(),
                "-NoProfile".to_string(),
                "-NoExit".to_string(),
                "-Command".to_string(),
                "$PID; Write-Output ready".to_string(),
            ],
            cwd.as_path(),
            HashMap::new(),
            Some(10_000),
            &[],
            /*tty*/ true,
            /*stdin_open*/ true,
            /*use_private_desktop*/ true,
        )
        .await
        .expect("spawn legacy tty powershell session");
        println!("tty pwsh spawn returned");

        let writer = spawned.session.writer_sender();
        writer
            .send(b"Write-Output second\n".to_vec())
            .await
            .expect("send second command");
        writer
            .send(b"exit\n".to_vec())
            .await
            .expect("send exit command");
        spawned.session.close_stdin();

        let (stdout, exit_code) =
            collect_stdout_and_exit(spawned, codex_home.path(), Duration::from_secs(15)).await;
        let stdout = String::from_utf8_lossy(&stdout);
        assert_eq!(exit_code, 0, "stdout={stdout:?}");
        assert!(stdout.contains("ready"), "stdout={stdout:?}");
        assert!(stdout.contains("second"), "stdout={stdout:?}");
    });
}

#[test]
#[ignore = "TODO: legacy ConPTY cmd.exe exits with STATUS_DLL_INIT_FAILED in CI"]
fn legacy_tty_cmd_emits_output_and_accepts_input() {
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let cwd = sandbox_cwd();
        let codex_home = sandbox_home("legacy-tty-cmd");
        println!("tty cmd codex_home={}", codex_home.path().display());
        let permission_profile = PermissionProfile::workspace_write();
        let spawned = spawn_windows_sandbox_session_legacy(
            &permission_profile,
            workspace_roots_for(cwd.as_path()).as_slice(),
            codex_home.path(),
            vec![
                "C:\\Windows\\System32\\cmd.exe".to_string(),
                "/K".to_string(),
                "echo ready".to_string(),
            ],
            cwd.as_path(),
            HashMap::new(),
            Some(10_000),
            &[],
            /*tty*/ true,
            /*stdin_open*/ true,
            /*use_private_desktop*/ true,
        )
        .await
        .expect("spawn legacy tty cmd session");
        println!("tty cmd spawn returned");

        let writer = spawned.session.writer_sender();
        writer
            .send(b"echo second\n".to_vec())
            .await
            .expect("send second command");
        writer
            .send(b"exit\n".to_vec())
            .await
            .expect("send exit command");
        spawned.session.close_stdin();

        let (stdout, exit_code) =
            collect_stdout_and_exit(spawned, codex_home.path(), Duration::from_secs(15)).await;
        let stdout = String::from_utf8_lossy(&stdout);
        assert_eq!(exit_code, 0, "stdout={stdout:?}");
        assert!(stdout.contains("ready"), "stdout={stdout:?}");
        assert!(stdout.contains("second"), "stdout={stdout:?}");
    });
}

#[test]
#[ignore = "TODO: legacy ConPTY cmd.exe exits with STATUS_DLL_INIT_FAILED in CI"]
fn legacy_tty_cmd_default_desktop_emits_output_and_accepts_input() {
    let runtime = current_thread_runtime();
    runtime.block_on(async move {
        let cwd = sandbox_cwd();
        let codex_home = sandbox_home("legacy-tty-cmd-default-desktop");
        println!(
            "tty cmd default desktop codex_home={}",
            codex_home.path().display()
        );
        let permission_profile = PermissionProfile::workspace_write();
        let spawned = spawn_windows_sandbox_session_legacy(
            &permission_profile,
            workspace_roots_for(cwd.as_path()).as_slice(),
            codex_home.path(),
            vec![
                "C:\\Windows\\System32\\cmd.exe".to_string(),
                "/K".to_string(),
                "echo ready".to_string(),
            ],
            cwd.as_path(),
            HashMap::new(),
            Some(10_000),
            &[],
            /*tty*/ true,
            /*stdin_open*/ true,
            /*use_private_desktop*/ false,
        )
        .await
        .expect("spawn legacy tty cmd session");
        println!("tty cmd default desktop spawn returned");

        let writer = spawned.session.writer_sender();
        writer
            .send(b"echo second\n".to_vec())
            .await
            .expect("send second command");
        writer
            .send(b"exit\n".to_vec())
            .await
            .expect("send exit command");
        spawned.session.close_stdin();

        let (stdout, exit_code) =
            collect_stdout_and_exit(spawned, codex_home.path(), Duration::from_secs(15)).await;
        let stdout = String::from_utf8_lossy(&stdout);
        assert_eq!(exit_code, 0, "stdout={stdout:?}");
        assert!(stdout.contains("ready"), "stdout={stdout:?}");
        assert!(stdout.contains("second"), "stdout={stdout:?}");
    });
}
