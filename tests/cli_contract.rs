use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;
use tempfile::TempDir;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn runseal_bin() -> PathBuf {
    env::var_os("RUNSEAL_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_runseal").map(PathBuf::from))
        .unwrap_or_else(|| {
            let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/runseal");
            if cfg!(windows) {
                path.set_extension("exe");
            }
            path
        })
}

fn require_runseal_bin() -> Result<PathBuf> {
    let bin = runseal_bin();
    if !bin.exists() {
        bail!(
            "RunSeal binary not found at {}. Set RUNSEAL_BIN to a candidate implementation to run conformance tests.",
            bin.display()
        );
    }
    Ok(bin)
}

fn run_cli(args: &[&str]) -> Result<Output> {
    #[cfg(windows)]
    let _guard = windows_cli_lock();
    let bin = require_runseal_bin()?;
    Command::new(bin)
        .args(args)
        .output()
        .context("failed to spawn runseal")
}

#[cfg(windows)]
fn windows_cli_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn python_bin() -> &'static str {
    static PYTHON: OnceLock<String> = OnceLock::new();
    PYTHON.get_or_init(resolve_python_bin)
}

fn resolve_python_bin() -> String {
    if let Some(path) = env::var_os("RUNSEAL_TEST_PYTHON") {
        return PathBuf::from(path).to_string_lossy().into_owned();
    }
    let output = match if cfg!(windows) {
        Command::new("where.exe").arg("python").output()
    } else {
        Command::new("sh")
            .args(["-c", "command -v python3"])
            .output()
    } {
        Ok(output) => output,
        Err(err) => panic!("failed to locate python: {err}"),
    };
    let stdout = match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout,
        Err(err) => panic!("python path must be utf-8: {err}"),
    };
    match stdout.lines().next() {
        Some(path) => path.to_string(),
        None => panic!("python must exist"),
    }
}

fn stdout_json(output: &Output) -> Result<Value> {
    serde_json::from_slice(&output.stdout).context("stdout was not valid JSON")
}

fn stdout_json_lines(output: &Output) -> Result<Vec<Value>> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("stdout line was not valid JSON"))
        .collect()
}

#[test]
fn plain_inherited_stdin_delivers_binary_and_eof() -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;
    for chunk in ["8192", "65536"] {
        let tmp = TempDir::new()?;
        let mut child = Command::new(require_runseal_bin()?)
            .env("RUNSEAL_STREAM_CHUNK_BYTES", chunk)
            .env("RUNSEAL_INPUT_PENDING_BYTES", "65536")
            .args(["exec", "--policy", "danger-full-access", "--stdin", "inherit", "--timeout-ms", "10000", "--cwd"])
            .arg(tmp.path())
            .args(["--", python_bin(), "-c", "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.buffer.write(b'EOF')"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let bytes: Vec<u8> = (0..65536).map(|index| (index % 256) as u8).collect();
        let mut input = child.stdin.take().context("stdin")?;
        let written = input.write_all(&bytes);
        drop(input);
        let output = child.wait_with_output()?;
        written?;
        assert!(
            output.status.success(),
            "chunk={chunk}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, bytes);
        assert_eq!(output.stderr, b"EOF");
    }
    Ok(())
}

#[cfg(windows)]
fn execution_process_present(pid: u32) -> Result<bool> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let result = (|| -> Result<bool> {
            if Process32FirstW(snapshot, &mut entry) == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            loop {
                if entry.th32ProcessID == pid {
                    return Ok(true);
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    if GetLastError() != ERROR_NO_MORE_FILES {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    return Ok(false);
                }
            }
        })();
        CloseHandle(snapshot);
        result
    }
}

#[test]
fn exec_refusals_have_stable_exit_and_format_before_target_without_argument_disclosure()
-> Result<()> {
    for mode in ["plain", "--json", "--events"] {
        for (flags, code) in [
            (vec!["--secret-argument-canary"], "INVALID_REQUEST"),
            (
                vec!["--timeout-ms", "secret-argument-canary"],
                "INVALID_REQUEST",
            ),
            (
                vec!["--network", "secret-argument-canary"],
                "INVALID_REQUEST",
            ),
            (vec!["--policy", "secret-argument-canary"], "POLICY_INVALID"),
            (vec!["--control-fd", "4"], "INVALID_REQUEST"),
            (
                vec!["--control-fd", "3"],
                if mode != "plain" || cfg!(windows) {
                    "INVALID_REQUEST"
                } else {
                    "BACKEND_CAPABILITY_MISSING"
                },
            ),
            (vec!["--pty"], "INVALID_REQUEST"),
        ] {
            let tmp = TempDir::new()?;
            let marker = tmp.path().join("target.ran");
            let mut command = Command::new(require_runseal_bin()?);
            command.arg("exec");
            if mode != "plain" {
                command.arg(mode);
            }
            let output = command
                .args(flags)
                .args(["--cwd"])
                .arg(tmp.path())
                .args([
                    "--",
                    python_bin(),
                    "-c",
                    "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('RAN')",
                ])
                .arg(&marker)
                .output()?;
            assert!(!marker.exists());
            assert_eq!(output.status.code(), Some(125));
            assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-argument-canary"));
            assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-argument-canary"));
            if mode == "plain" {
                assert!(output.stdout.is_empty());
                assert!(
                    String::from_utf8_lossy(&output.stderr)
                        .starts_with(&format!("[runseal:{code}]"))
                );
            } else {
                assert!(output.stderr.is_empty());
                let messages = stdout_json_lines(&output)?;
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0]["error"]["data"]["code"], code);
            }
        }
        let tmp = TempDir::new()?;
        let mut command = Command::new(require_runseal_bin()?);
        command.arg("exec");
        if mode != "plain" {
            command.arg(mode);
        }
        let output = command
            .args(["--policy", "danger-full-access", "--cwd"])
            .arg(tmp.path().join("missing"))
            .args(["--", python_bin(), "-c", "print('MUST_NOT_RUN')"])
            .output()?;
        assert_eq!(output.status.code(), Some(125));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("MUST_NOT_RUN"));
        if mode == "plain" {
            assert!(output.stdout.is_empty());
            assert!(
                String::from_utf8_lossy(&output.stderr).starts_with("[runseal:INVALID_REQUEST]")
            );
        } else {
            let messages = stdout_json_lines(&output)?;
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0]["error"]["data"]["code"], "INVALID_REQUEST");
            assert!(output.stderr.is_empty());
        }
    }
    Ok(())
}

#[test]
fn exec_runtime_failures_use_outer_status_and_one_structured_terminal() -> Result<()> {
    for mode in ["plain", "--json", "--events"] {
        for (timeout, code, exit) in [
            (false, "OUTPUT_LIMIT_EXCEEDED", 125),
            (true, "EXECUTION_TIMEOUT", 124),
        ] {
            let tmp = TempDir::new()?;
            let target = if timeout {
                "import os,pathlib,time; pathlib.Path('target.pid').write_text(str(os.getpid())); time.sleep(120)"
            } else {
                "import os,pathlib; pathlib.Path('target.pid').write_text(str(os.getpid())); os.write(1,b'X'*8193)"
            };
            let mut command = Command::new(require_runseal_bin()?);
            command.env("RUNSEAL_MAX_OUTPUT_BYTES", "8192").arg("exec");
            if mode != "plain" {
                command.arg(mode);
            }
            let output = command
                .args([
                    "--policy",
                    "danger-full-access",
                    "--timeout-ms",
                    "1000",
                    "--cwd",
                ])
                .arg(tmp.path())
                .args(["--", python_bin(), "-u", "-c", target])
                .output()?;
            assert!(
                tmp.path().join("target.pid").exists(),
                "real target must start before runtime failure"
            );
            #[cfg(windows)]
            {
                let pid = fs::read_to_string(tmp.path().join("target.pid"))?.parse::<u32>()?;
                assert!(
                    !execution_process_present(pid)?,
                    "real target must be gone after runtime failure"
                );
            }
            assert_eq!(output.status.code(), Some(exit));
            if mode == "plain" {
                assert!(
                    String::from_utf8_lossy(&output.stderr)
                        .starts_with(&format!("[runseal:{code}]"))
                );
            } else {
                assert!(output.stderr.is_empty());
                let messages = stdout_json_lines(&output)?;
                if mode == "--json" {
                    assert_eq!(messages.len(), 1);
                    assert_eq!(messages[0]["error"]["data"]["code"], code);
                    assert_eq!(messages[0]["error"]["data"]["cleanup_complete"], true);
                } else {
                    assert!(messages.iter().all(|message| message["type"].is_string()));
                    let terminals = messages
                        .iter()
                        .filter(|message| {
                            matches!(
                                message["type"].as_str(),
                                Some("execution.failed" | "execution.finished")
                            )
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(terminals.len(), 1);
                    assert_eq!(terminals[0]["result"]["error"]["code"], code);
                    assert_eq!(terminals[0]["result"]["cleanup_complete"], true);
                }
            }
            let mut terminal_count = 0;
            for entry in fs::read_dir(tmp.path().join(".runseal/audit"))? {
                for line in fs::read_to_string(entry?.path())?.lines() {
                    let event: Value = serde_json::from_str(line)?;
                    if event["type"] == "execution.failed" {
                        terminal_count += 1;
                        assert_eq!(event["result"]["error"]["code"], code);
                        assert_eq!(event["result"]["cleanup_complete"], true);
                    }
                }
            }
            assert_eq!(terminal_count, 1);
        }
    }
    Ok(())
}

#[test]
fn child_exit_125_and_spoofed_diagnostic_remain_child_results_in_each_cli_mode() -> Result<()> {
    for mode in ["plain", "--json", "--events"] {
        for exit in [0, 7, 125] {
            let tmp = TempDir::new()?;
            let mut command = Command::new(require_runseal_bin()?);
            command.arg("exec");
            if mode != "plain" {
                command.arg(mode);
            }
            let output=command.args(["--policy","danger-full-access","--cwd"]).arg(tmp.path())
                .args(["--",python_bin(),"-u","-c","import os,sys; assert sys.argv[2]=='--json'; os.write(1,b'CHILD'); os.write(2,b'[runseal:INVALID_REQUEST] child bytes'); sys.exit(int(sys.argv[1]))",&exit.to_string(),"--json"]).output()?;
            if mode == "plain" {
                assert_eq!(output.status.code(), Some(exit));
                assert_eq!(output.stdout, b"CHILD");
                assert_eq!(output.stderr, b"[runseal:INVALID_REQUEST] child bytes");
            } else {
                assert_eq!(output.status.code(), Some(0));
                assert!(output.stderr.is_empty());
                let messages = stdout_json_lines(&output)?;
                if mode == "--json" {
                    assert_eq!(messages.len(), 1);
                    assert_eq!(messages[0]["exit_code"], exit);
                    assert!(messages[0].get("error").is_none());
                } else {
                    let terminal = messages
                        .iter()
                        .filter(|message| message["type"] == "execution.finished")
                        .collect::<Vec<_>>();
                    assert_eq!(terminal.len(), 1);
                    assert_eq!(terminal[0]["result"]["exit_code"], exit);
                    assert!(terminal[0]["result"].get("error").is_none());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn cli_pty_rejects_invalid_modes_before_child_start() -> Result<()> {
    for flags in [
        vec!["--pty"],
        vec!["--pty", "--stdin", "empty"],
        vec!["--pty", "--stdin", "inherit", "--json"],
        vec!["--pty", "--stdin", "inherit", "--events"],
    ] {
        let tmp = TempDir::new()?;
        let marker = tmp.path().join("started");
        let output = Command::new(require_runseal_bin()?)
            .arg("exec")
            .args(flags)
            .args(["--policy", "danger-full-access", "--"])
            .args([
                python_bin(),
                "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('started')",
            ])
            .arg(&marker)
            .output()?;
        assert!(!output.status.success());
        assert!(!marker.exists());
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            text.contains("--pty requires --stdin inherit and plain output"),
            "{text}"
        );
    }
    Ok(())
}

#[test]
fn plain_inherited_stdin_does_not_wait_for_input_after_child_exit() -> Result<()> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let tmp = TempDir::new()?;
    let mut child = Command::new(require_runseal_bin()?)
        .args([
            "exec",
            "--policy",
            "danger-full-access",
            "--stdin",
            "inherit",
            "--cwd",
        ])
        .arg(tmp.path())
        .args(["--", python_bin(), "-c", "import sys; sys.exit(11)"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let input = child.stdin.take().context("stdin")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(input);
    child.wait()?;
    assert_eq!(
        status
            .context("wrapper must exit while caller stdin remains open")?
            .code(),
        Some(11)
    );
    Ok(())
}

#[test]
fn inherited_stdin_is_rejected_for_machine_output_before_child_start() -> Result<()> {
    for mode in ["--json", "--events"] {
        let tmp = TempDir::new()?;
        let marker = tmp.path().join("started");
        let output = Command::new(require_runseal_bin()?)
            .args([
                "exec",
                mode,
                "--stdin",
                "inherit",
                "--policy",
                "danger-full-access",
                "--cwd",
            ])
            .arg(tmp.path())
            .args([
                "--",
                python_bin(),
                "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('started')",
            ])
            .arg(&marker)
            .output()?;
        assert!(!output.status.success());
        assert_eq!(
            stdout_json(&output)?["error"]["data"]["code"],
            "INVALID_REQUEST"
        );
        assert!(!marker.exists());
    }
    Ok(())
}

#[test]
fn plain_pipe_is_live_binary_separated_and_preserves_child_exit() -> Result<()> {
    use std::io::Read;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Duration;
    let tmp = TempDir::new()?;
    let gate = tmp.path().join("release");
    let mut child = Command::new(require_runseal_bin()?).args(["exec","--policy","danger-full-access","--timeout-ms","10000","--cwd"]).arg(tmp.path()).args(["--",python_bin(),"-u","-c","import os,pathlib,sys,time; os.write(1,b'\\x00\\xffREADY'); os.write(2,b'\\xfeERR\\x00'); gate=pathlib.Path(sys.argv[1]);\nwhile not gate.exists(): time.sleep(0.01)\nos.write(1,b'END'); sys.exit(7)"]).arg(&gate).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let mut stdout = child.stdout.take().context("stdout")?;
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut ready = [0; 7];
        let result = stdout.read_exact(&mut ready).map(|()| ready);
        let _ = sender.send(result);
        let mut rest = Vec::new();
        stdout.read_to_end(&mut rest).map(|_| rest)
    });
    let ready = receiver.recv_timeout(Duration::from_secs(3));
    let alive = child.try_wait()?.is_none();
    fs::write(&gate, b"release")?;
    let output = child.wait_with_output()?;
    let rest = reader
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader panicked"))??;
    assert_eq!(
        ready.context("live output before gate release")??,
        *b"\x00\xffREADY"
    );
    assert!(alive);
    assert_eq!(rest, b"END");
    assert_eq!(output.stderr, b"\xfeERR\x00");
    assert_eq!(output.status.code(), Some(7));
    Ok(())
}

#[test]
fn cli_json_preserves_binary_output_and_uses_outer_success_for_child_failure() -> Result<()> {
    let output = run_cli(&[
        "exec",
        "--json",
        "--policy",
        "danger-full-access",
        "--",
        python_bin(),
        "-c",
        "import os,sys; os.write(1,b'\\x00\\xff'); os.write(2,b'\\xfe\\x00'); sys.exit(9)",
    ])?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let result = stdout_json(&output)?;
    assert_eq!(result["exit_code"], 9);
    assert!(result.get("stdout").is_none());
    assert!(result.get("stderr").is_none());
    for (stream, bytes) in [("stdout", b"\x00\xff"), ("stderr", b"\xfe\x00")] {
        let item = &result["output"][stream];
        assert_eq!(item["encoding"], "base64");
        assert_eq!(item["bytes"], 2);
        assert_eq!(item["truncated"], false);
        assert_eq!(
            STANDARD.decode(
                item["data"]
                    .as_str()
                    .context("data")?
                    .strip_prefix("base64:")
                    .context("base64 prefix")?
            )?,
            bytes
        );
    }
    Ok(())
}

#[test]
fn exec_events_delivers_ready_before_child_gate_is_released() -> Result<()> {
    assert_exec_events_ready_before_gate("danger-full-access")
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn sandboxed_exec_events_delivers_ready_before_child_gate_is_released() -> Result<()> {
    assert_exec_events_ready_before_gate("workspace-write")
}

fn assert_exec_events_ready_before_gate(policy: &str) -> Result<()> {
    #[cfg(windows)]
    let _guard = windows_cli_lock();
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    let tmp = TempDir::new()?;
    let gate = tmp.path().join("release");
    let mut child = Command::new(require_runseal_bin()?)
        .args(["exec", "--events", "--policy", policy, "--timeout-ms", "10000", "--cwd"])
        .arg(tmp.path()).args(["--", python_bin(), "-u", "-c",
            "import pathlib,sys,time; print('READY',flush=True); gate=pathlib.Path(sys.argv[1]);\nwhile not gate.exists(): time.sleep(0.01)\nprint('DONE',flush=True)"])
        .arg(&gate).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let stdout = child.stdout.take().context("event stdout")?;
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let mut deadline = Instant::now() + Duration::from_secs(10);
    let mut ready = false;
    while let Ok(line) = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        let event: Value = serde_json::from_str(&line?)?;
        if event["type"] == "execution.started" {
            deadline = Instant::now() + Duration::from_secs(2);
        }
        if event["type"] == "execution.stdout" {
            let encoded = event["data"]
                .as_str()
                .context("event data")?
                .strip_prefix("base64:")
                .context("base64")?;
            ready = STANDARD
                .decode(encoded)?
                .windows(5)
                .any(|bytes| bytes == b"READY");
            if ready {
                break;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    let alive_before_release = child.try_wait()?.is_none();
    fs::write(&gate, b"release")?;
    let output = child.wait_with_output()?;
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("event reader panicked"))?;
    assert!(
        ready,
        "READY must be received while the child waits on the test gate"
    );
    assert!(
        alive_before_release,
        "child must still be running before gate release"
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = receiver
        .into_iter()
        .map(|line| -> Result<Value> { Ok(serde_json::from_str(&line?)?) })
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(
        events
            .iter()
            .filter(|event| event["type"] == "execution.finished")
            .count(),
        1
    );
    Ok(())
}

fn decode_stream_event(event: &Value) -> Result<String> {
    assert_rfc3339_timestamp(&event["time"])?;
    assert_eq!(event["encoding"], "base64");
    assert_eq!(event["stream_offset"], 0);
    assert!(event.get("text").is_none());
    let encoded = event["data"]
        .as_str()
        .and_then(|data| data.strip_prefix("base64:"))
        .context("stream event must include base64-prefixed data")?;
    let bytes = STANDARD
        .decode(encoded)
        .context("stream data must decode")?;
    String::from_utf8(bytes).context("stream data must be UTF-8 for this test")
}

fn assert_rfc3339_timestamp(value: &Value) -> Result<()> {
    let timestamp = value.as_str().context("timestamp must be a string")?;
    OffsetDateTime::parse(timestamp, &Rfc3339)
        .with_context(|| format!("timestamp must be RFC3339 UTC: {timestamp}"))?;
    Ok(())
}

fn assert_event_envelope(event: &Value) -> Result<()> {
    assert!(event["type"].as_str().is_some());
    assert_rfc3339_timestamp(&event["time"])?;
    assert!(
        event["execution_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("exec_")
    );
    assert!(
        event["session_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sess_")
    );
    assert!(
        event["seal_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("seal_")
    );
    assert!(event["policy_id"].as_str().is_some());
    assert!(
        event["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert!(event["policy_epoch"].as_str().is_some());
    assert!(event["runseal_version"].as_str().is_some());
    assert!(
        event["audit_path"]
            .as_str()
            .unwrap_or_default()
            .starts_with(".runseal/audit/sess_")
    );
    assert!(event["backend"]["name"].as_str().is_some());
    assert!(event["backend"]["status"].as_str().is_some());
    assert!(event["backend"]["platform"].as_str().is_some());
    Ok(())
}

fn expected_backend_name() -> &'static str {
    if cfg!(windows) {
        "runseal-windows-reference"
    } else if cfg!(target_os = "macos") {
        "runseal-macos-experimental"
    } else if cfg!(target_os = "linux") {
        "runseal-linux-community"
    } else {
        "runseal-local"
    }
}

fn expected_backend_status() -> &'static str {
    if cfg!(windows) {
        "reference"
    } else if cfg!(any(target_os = "macos", target_os = "linux")) {
        "experimental"
    } else {
        "local-baseline"
    }
}

fn expected_backend_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

fn expected_disabled_feature_reported() -> bool {
    cfg!(any(windows, target_os = "macos", target_os = "linux"))
}

fn expected_disabled_feature_status() -> &'static str {
    if cfg!(windows) {
        "supported"
    } else if cfg!(any(target_os = "macos", target_os = "linux")) {
        "experimental"
    } else {
        "unsupported"
    }
}

fn expected_windows_sandbox_supported() -> bool {
    cfg!(windows)
}

fn expected_proxy_feature_reported() -> bool {
    cfg!(any(windows, target_os = "macos", target_os = "linux"))
}

fn expected_proxy_feature_status() -> &'static str {
    if cfg!(windows) {
        "supported"
    } else if cfg!(any(target_os = "macos", target_os = "linux")) {
        "experimental"
    } else {
        "unsupported"
    }
}

fn expected_network_proxy_status() -> &'static str {
    expected_proxy_feature_status()
}

fn expected_resource_limits_supported() -> bool {
    false
}

fn expected_status(supported: bool) -> &'static str {
    if supported {
        "supported"
    } else {
        "unsupported"
    }
}

fn expected_read_only_status() -> &'static str {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        "experimental"
    } else {
        expected_status(expected_windows_sandbox_supported())
    }
}

fn expected_sandbox_levels_status(payload: &Value) -> &'static str {
    if !cfg!(windows) {
        return expected_read_only_status();
    }

    match (
        payload["setup_status"]["platform_supported"].as_bool(),
        payload["setup_status"]["requires_setup"].as_bool(),
    ) {
        (Some(false), _) => "unsupported",
        (Some(true), Some(true)) => "requires_setup",
        (Some(true), Some(false)) => "supported",
        _ => "unavailable",
    }
}

fn expected_network_disabled_status() -> &'static str {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        "experimental"
    } else {
        expected_status(expected_windows_sandbox_supported())
    }
}

fn assert_no_private_windows_setup_terms(text: &str) {
    for private_term in [
        "single-sandbox-user",
        "RunSealSandbox",
        "RunSealSandboxUsers",
        "restricted-token",
        "kill-on-close-job",
        "orchestrator_",
        "helper_",
        "vendored",
        "upstream",
        "WindowsSandboxSetup",
        "scheduled task",
        "sandbox account",
        "local user",
        "profile account",
        "SID",
        "ACL",
        "WFP",
        "firewall",
        "Job Object",
        "Codex",
        "OpenAI",
        "WindowsApps",
        "offline",
        "online",
        "dual",
        "two users",
    ] {
        assert!(
            !text.contains(private_term),
            "CLI output must not expose private Windows setup term {private_term}"
        );
    }
}

fn assert_portable_fail_closed_preview(plan: &Value) {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }

    assert_eq!(plan["backend"]["name"], expected_backend_name());
    assert_eq!(plan["backend"]["status"], expected_backend_status());
    assert_eq!(plan["backend"]["platform"], expected_backend_platform());
    assert_eq!(plan["sandbox_level"], "read-only");
    assert_eq!(plan["enforcement"], "fail-closed-preview");
    assert_eq!(plan["cwd"], "workspace");
    assert_eq!(plan["runtime_root"], "runtime_root");
    assert_eq!(plan["profile_root"], "profile_root");
    assert_eq!(plan["synthetic_home"], "synthetic_home");
    assert_eq!(plan["temp_root"], "temp_root");
    assert_eq!(plan["filesystem"]["read"], json!(["workspace"]));
    assert_eq!(
        plan["filesystem"]["write"],
        json!([
            "runtime_root",
            "profile_root",
            "synthetic_home",
            "temp_root"
        ])
    );
    assert_eq!(plan["process"]["boundary"], "platform-sandbox");
    assert_eq!(plan["process"]["identity"], "current-user");
    assert_eq!(plan["process"]["cleanup"], "process-tree");
    assert_eq!(plan["network"]["direct_egress"], "deny");
    assert_eq!(plan["network"]["managed_proxy"], "none");
    assert_eq!(
        plan["required_backend_features"],
        json!([
            "filesystem_policy",
            "runtime_roots",
            "runtime_environment",
            "process_isolation",
            "process_cleanup",
            "direct_network_deny",
            "network_disabled"
        ])
    );
    let plan_text = plan.to_string();
    for private_term in [
        "bubblewrap",
        "landlock",
        "namespace",
        "seccomp",
        "sandbox_exec",
        "seatbelt",
        "profile fragment",
    ] {
        assert!(
            !plan_text.contains(private_term),
            "portable preview must not expose private mechanism term {private_term}"
        );
    }
}

fn assert_portable_capability_probe_contract(payload: &Value) {
    #[cfg(windows)]
    assert!(payload.get("capability_probes").is_none());

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let Some(probes) = payload["capability_probes"].as_array() else {
            panic!("portable backend must report diagnostic capability probes");
        };
        assert!(!probes.is_empty());
        let mut mechanisms = Vec::with_capacity(probes.len());
        for probe in probes {
            assert!(probe["capability"].as_str().is_some());
            let Some(mechanism) = probe["mechanism"].as_str() else {
                panic!("portable backend probe must report mechanism");
            };
            assert!(
                [
                    "supported",
                    "experimental",
                    "unsupported",
                    "unavailable",
                    "requires_setup",
                ]
                .iter()
                .any(|status| probe["status"] == *status)
            );
            assert_eq!(probe["diagnostic_only"], true);
            assert!(probe["available"].is_boolean());
            mechanisms.push(mechanism);
        }
        #[cfg(target_os = "linux")]
        assert_eq!(
            mechanisms,
            vec![
                "landlock",
                "landlock_abi_version",
                "user_namespaces",
                "user_namespace_quota",
                "mount_namespaces",
                "pid_namespaces",
                "network_namespaces",
                "seccomp",
                "bubblewrap",
                "unprivileged_user_namespaces",
            ]
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            mechanisms,
            vec![
                "sandbox_exec",
                "sandbox_exec_executable",
                "macos_version",
                "temporary_profile",
                "canonical_paths",
                "symlink_path_model",
            ]
        );
    }
}

#[test]
fn missing_binary_is_explicit_red_state() {
    if runseal_bin().exists() {
        return;
    }
    let error = run_cli(&["--version"]).expect_err("missing implementation should be RED");
    let message = error.to_string();
    assert!(message.contains("RunSeal binary not found"), "{message}");
    assert!(message.contains("RUNSEAL_BIN"), "{message}");
}

#[test]
fn help_lists_core_commands() -> Result<()> {
    let output = run_cli(&["--help"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Usage: runseal <command> [options]"));
    assert!(stdout.contains("exec --policy <policy>"));
    assert!(stdout.contains("mcp --stdio"));
    assert!(stdout.contains("setup windows-sandbox [--cwd <path>]"));
    assert!(stdout.contains("capabilities"));
    assert_no_private_windows_setup_terms(&stdout);
    Ok(())
}

#[test]
fn service_local_ipc_modes_fail_closed() -> Result<()> {
    for flag in ["--pipe", "--socket"] {
        let output = run_cli(&["service", flag])?;

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("local service transport RFC"), "{stderr}");
        assert_no_private_windows_setup_terms(&stderr);

        let output = run_cli(&["service", flag, "runseal-test"])?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("local service transport RFC"), "{stderr}");
        assert_no_private_windows_setup_terms(&stderr);
    }
    Ok(())
}

#[test]
fn service_remote_transport_modes_fail_closed() -> Result<()> {
    for flag in ["--tcp", "--http"] {
        let output = run_cli(&["service", flag])?;

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("remote transport RFC"), "{stderr}");
        assert_no_private_windows_setup_terms(&stderr);

        let output = run_cli(&["service", flag, "127.0.0.1:0"])?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("remote transport RFC"), "{stderr}");
        assert_no_private_windows_setup_terms(&stderr);
    }
    Ok(())
}

#[test]
fn setup_help_describes_explicit_windows_setup() -> Result<()> {
    for args in [
        &["setup", "--help"][..],
        &["setup", "windows-sandbox", "--help"][..],
    ] {
        let output = run_cli(args)?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.contains("Usage: runseal setup windows-sandbox [--cwd <path>]"));
        assert!(stdout.contains("Use --elevate to request UAC"));
        assert!(stdout.contains("Later repairs reuse the sandbox broker"));
        assert!(stdout.contains("fails closed"));
        assert!(stdout.contains("--status"));
        assert!(stdout.contains("--json"));
        assert!(stdout.contains("--elevate"));
        assert_no_private_windows_setup_terms(&stdout);
    }
    Ok(())
}

#[test]
fn readme_does_not_expose_private_windows_setup_terms() {
    assert_no_private_windows_setup_terms(include_str!("../README.md"));
}

#[test]
fn setup_status_reports_setup_readiness_without_running_setup() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    for args in [
        vec!["setup", "windows-sandbox", "--cwd", &cwd, "--status"],
        vec![
            "setup",
            "windows-sandbox",
            "--cwd",
            &cwd,
            "--status",
            "--json",
        ],
    ] {
        let output = run_cli(&args)?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let payload = stdout_json(&output)?;
        assert_eq!(payload["setup"], "windows-sandbox");
        assert_eq!(payload["platform_supported"], cfg!(windows));
        if cfg!(windows) {
            assert!(payload["elevated"].is_boolean(), "{payload}");
            let elevated = payload["elevated"].as_bool().unwrap_or(false);
            let broker_available = payload["broker"] == "available";
            assert_eq!(
                payload["can_repair"].as_bool(),
                Some(elevated || broker_available),
                "{payload}"
            );
            assert_eq!(
                payload["can_run_setup_now"].as_bool(),
                Some(elevated || broker_available),
                "{payload}"
            );
        } else {
            assert!(payload["elevated"].is_null(), "{payload}");
            assert_eq!(payload["can_repair"], false, "{payload}");
            assert_eq!(payload["can_run_setup_now"], false, "{payload}");
        }
        assert!(
            matches!(
                payload["broker"].as_str(),
                Some("available" | "unavailable")
            ),
            "{payload}"
        );
        assert!(payload["requires_setup"].is_boolean(), "{payload}");
        assert!(
            matches!(
                payload["next_action"].as_str(),
                Some("none" | "run_setup" | "open_elevated_shell" | "unsupported")
            ),
            "{payload}"
        );
        match payload["next_action"].as_str() {
            Some("run_setup") => {
                assert_eq!(payload["requires_setup"], true, "{payload}");
                assert_eq!(
                    payload["next_command"],
                    "runseal setup windows-sandbox --cwd <absolute-workspace-path> --json",
                    "{payload}"
                );
            }
            Some("open_elevated_shell") => {
                assert_eq!(payload["requires_setup"], true, "{payload}");
                assert_eq!(
                    payload["next_command"],
                    "runseal setup windows-sandbox --cwd <absolute-workspace-path> --json --elevate",
                    "{payload}"
                );
            }
            Some("none" | "unsupported") => {
                assert_eq!(payload["requires_setup"], false, "{payload}");
                assert!(payload["next_command"].is_null(), "{payload}");
            }
            _ => unreachable!("{payload}"),
        }
        assert_no_private_windows_setup_terms(&payload.to_string());
    }
    Ok(())
}

#[test]
fn command_help_describes_policy_entrypoints() -> Result<()> {
    for (args, usage) in [
        (
            &["exec", "--help"][..],
            "Usage: runseal exec [--json|--events]",
        ),
        (
            &["explain-policy", "--help"][..],
            "Usage: runseal explain-policy [--policy <policy>]",
        ),
        (
            &["mcp", "--help"][..],
            "Usage: runseal mcp --stdio [--policy <policy>]",
        ),
    ] {
        let output = run_cli(args)?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.contains(usage));
        assert!(stdout.contains("--policy"));
        if args[0] != "mcp" {
            assert!(stdout.contains("--network"));
            assert!(stdout.contains("--cwd"));
        }
        assert_no_private_windows_setup_terms(&stdout);
    }
    Ok(())
}

#[test]
fn setup_rejects_invalid_cwd_before_windows_setup() -> Result<()> {
    let tmp = TempDir::new()?;
    let missing = tmp.path().join("missing").to_string_lossy().to_string();
    let file = tmp.path().join("not-a-directory");
    fs::write(&file, "not a directory")?;
    let file = file.to_string_lossy().to_string();

    for args in [
        vec!["setup", "windows-sandbox", "--cwd", &missing],
        vec!["setup", "windows-sandbox", "--cwd", &file],
        vec!["setup", "windows-sandbox", "--cwd", &missing, "--status"],
        vec!["setup", "windows-sandbox", "--cwd", &file, "--status"],
    ] {
        let output = run_cli(&args)?;

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("params.cwd must be an existing directory"),
            "{stderr}"
        );
        assert!(!stderr.contains("windows sandbox setup failed"), "{stderr}");
        assert_no_private_windows_setup_terms(&stderr);
    }
    Ok(())
}

#[test]
fn setup_json_reports_invalid_cwd_as_json_error() -> Result<()> {
    let tmp = TempDir::new()?;
    let missing = tmp.path().join("missing").to_string_lossy().to_string();

    for args in [
        vec!["setup", "windows-sandbox", "--json", "--cwd", &missing],
        vec![
            "setup",
            "windows-sandbox",
            "--json",
            "--cwd",
            &missing,
            "--status",
        ],
    ] {
        let output = run_cli(&args)?;

        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let payload = stdout_json(&output)?;
        assert_eq!(payload["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            payload["error"]["data"]["reason"]
                .as_str()
                .expect("reason")
                .contains("params.cwd must be an existing directory")
        );
        assert_no_private_windows_setup_terms(&payload.to_string());
    }
    Ok(())
}

#[test]
fn setup_json_reports_parse_errors_as_json_error() -> Result<()> {
    for args in [
        vec!["setup", "--json"],
        vec!["setup", "unknown", "--json"],
        vec!["setup", "windows-sandbox", "--json", "--cwd"],
        vec!["setup", "windows-sandbox", "--json", "--unknown"],
    ] {
        let output = run_cli(&args)?;

        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let payload = stdout_json(&output)?;
        assert_eq!(payload["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            payload["error"]["data"]["reason"]
                .as_str()
                .expect("reason")
                .contains("usage: runseal setup windows-sandbox")
        );
        assert_no_private_windows_setup_terms(&payload.to_string());
    }
    Ok(())
}

#[test]
fn version_reports_protocol_and_runtime_versions() -> Result<()> {
    let output = run_cli(&["--json", "version"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert!(payload["runseal_version"].as_str().is_some());
    assert_eq!(payload["protocol_version"], "runseal.protocol/v2");
    assert!(
        payload["policy_versions"]
            .as_array()
            .expect("policy_versions must be an array")
            .iter()
            .any(|version| version == "runseal.policy/v1")
    );
    Ok(())
}

#[test]
fn capabilities_cli_reports_active_backend_baseline() -> Result<()> {
    let output = run_cli(&["capabilities"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    let sandbox_levels_status = expected_sandbox_levels_status(&payload);
    assert_eq!(payload["backend"], expected_backend_name());
    assert_eq!(payload["backend_status"], expected_backend_status());
    assert!(payload["platform"].as_str().is_some());
    assert_eq!(
        payload["capability_statuses"],
        json!([
            "supported",
            "experimental",
            "unsupported",
            "unavailable",
            "requires_setup"
        ])
    );
    assert_eq!(payload["features"]["local_execution"], true);
    assert_eq!(
        payload["features"]["filesystem_policy"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["runtime_roots"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["runtime_environment"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["process_isolation"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["process_cleanup"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["direct_network_deny"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["managed_proxy"],
        expected_proxy_feature_reported()
    );
    assert_eq!(
        payload["features"]["network_proxy"],
        expected_proxy_feature_reported()
    );
    assert_eq!(
        payload["features"]["network_disabled"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["policy_epoch"],
        expected_disabled_feature_reported()
    );
    for feature in [
        "filesystem_policy",
        "runtime_roots",
        "runtime_environment",
        "process_isolation",
        "process_cleanup",
        "direct_network_deny",
        "network_disabled",
        "policy_epoch",
    ] {
        assert_eq!(
            payload["feature_statuses"][feature],
            expected_disabled_feature_status()
        );
    }
    assert_eq!(
        payload["feature_statuses"]["network_proxy"],
        expected_proxy_feature_status()
    );
    assert_eq!(
        payload["feature_statuses"]["managed_proxy"],
        expected_proxy_feature_status()
    );
    assert_eq!(payload["features"]["setup_readiness"], true);
    assert_eq!(payload["features"]["stdin_bytes"], true);
    assert_eq!(payload["features"]["stdin_file"], true);
    assert_eq!(
        payload["features"]["resource_limits"],
        expected_resource_limits_supported()
    );
    assert_eq!(payload["features"]["audit_jsonl"], true);
    assert_eq!(payload["features"]["otel_export"], false);
    assert_eq!(payload["sandbox_levels"]["danger-full-access"], "supported");
    assert_eq!(
        payload["sandbox_levels"]["read-only"],
        sandbox_levels_status
    );
    assert_eq!(
        payload["sandbox_levels"]["workspace-write"],
        sandbox_levels_status
    );
    assert_eq!(
        payload["sandbox_levels"]["workspace-contained"],
        sandbox_levels_status
    );
    assert_eq!(
        payload["network_modes"]["proxy"],
        expected_network_proxy_status()
    );
    assert_eq!(
        payload["network_modes"]["disabled"],
        expected_network_disabled_status()
    );
    assert_eq!(payload["network_modes"]["unmanaged"], "supported");
    if cfg!(windows) {
        assert_eq!(payload["setup_status"]["setup"], "windows-sandbox");
        assert!(payload["setup_status"]["next_action"].as_str().is_some());
    } else {
        assert!(payload.get("setup_status").is_none());
    }
    assert_portable_capability_probe_contract(&payload);
    assert_no_private_windows_setup_terms(&payload.to_string());
    Ok(())
}

#[test]
fn explain_policy_cli_materializes_standard_profile() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "explain-policy",
        "--policy",
        "workspace-write",
        "--network",
        "disabled",
        "--cwd",
        &cwd,
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert_eq!(payload["policy_id"], "workspace-write");
    assert_eq!(payload["sandbox_level"], "workspace-write");
    assert_eq!(payload["network"]["mode"], "disabled");
    assert_eq!(payload["environment"]["inherit"], "minimal");
    assert_eq!(payload["backend_requirement"], "sandbox-backend");
    assert_eq!(
        payload["support"],
        expected_status(expected_windows_sandbox_supported())
    );
    if cfg!(windows) {
        assert_eq!(payload["setup_status"]["setup"], "windows-sandbox");
        assert!(payload["setup_status"]["can_run_setup_now"].is_boolean());
    } else {
        assert!(payload.get("setup_status").is_none());
    }
    assert_eq!(
        payload["required_backend_features"],
        serde_json::json!([
            "filesystem_policy",
            "runtime_roots",
            "runtime_environment",
            "process_isolation",
            "process_cleanup",
            "direct_network_deny",
            "network_disabled"
        ])
    );
    let expected_missing_features = if expected_windows_sandbox_supported() {
        serde_json::json!([])
    } else {
        payload["required_backend_features"].clone()
    };
    assert_eq!(payload["missing_features"], expected_missing_features);
    assert_eq!(
        payload["canonical_policy"]["filesystem"]["protect_vcs"],
        true
    );
    assert!(
        payload["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert_no_private_windows_setup_terms(&payload.to_string());
    Ok(())
}

#[test]
fn explain_policy_cli_normalizes_relative_cwd() -> Result<()> {
    let output = run_cli(&[
        "explain-policy",
        "--policy",
        "workspace-write",
        "--cwd",
        ".",
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    let cwd = std::env::current_dir()?.to_string_lossy().to_string();
    assert_eq!(payload["canonical_policy"]["filesystem"]["write"][0], cwd);
    assert_ne!(payload["canonical_policy"]["filesystem"]["write"][0], ".");
    Ok(())
}

#[test]
fn exec_events_stream_uses_execution_vocabulary() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "exec",
        "--events",
        "--policy",
        "danger-full-access",
        "--cwd",
        &cwd,
        "--",
        python_bin(),
        "-c",
        "print('hello from runseal')",
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = stdout_json_lines(&output)?;
    let event_types: Vec<_> = events
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();

    assert!(event_types.contains(&"execution.requested"));
    assert!(event_types.contains(&"policy.resolved"));
    assert!(event_types.contains(&"policy.allowed"));
    assert!(event_types.contains(&"execution.started"));
    assert!(event_types.contains(&"execution.stdout"));
    assert!(event_types.contains(&"execution.resource.sample"));
    assert!(event_types.contains(&"execution.finished"));
    for event in &events {
        assert_event_envelope(event)?;
    }
    let first_event = events
        .first()
        .context("exec --events must emit at least one event")?;
    for event in &events {
        assert_eq!(event["execution_id"], first_event["execution_id"]);
        assert_eq!(event["policy_hash"], first_event["policy_hash"]);
        assert_eq!(event["policy_epoch"], first_event["policy_epoch"]);
        assert_eq!(event["policy_epoch"], event["policy_hash"]);
    }
    let stdout_event = events
        .iter()
        .find(|event| event["type"] == "execution.stdout")
        .context("execution.stdout event must exist")?;
    assert!(decode_stream_event(stdout_event)?.contains("hello from runseal"));
    assert!(
        events
            .iter()
            .filter(|event| event["type"]
                .as_str()
                .unwrap_or_default()
                .starts_with("execution."))
            .all(|event| event.get("execution_id").is_some())
    );
    assert!(events.iter().all(|event| event.get("process_id").is_none()));
    Ok(())
}

#[test]
fn exec_events_reports_policy_errors_as_json_line() -> Result<()> {
    let output = run_cli(&[
        "exec",
        "--events",
        "--policy",
        "workspace-proxy",
        "--",
        python_bin(),
        "-c",
        "print('must not run')",
    ])?;

    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let messages = stdout_json_lines(&output)?;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["error"]["data"]["code"], "POLICY_INVALID");
    assert!(
        messages[0]["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("unknown policy profile"),
        "{}",
        messages[0]
    );
    Ok(())
}

#[test]
fn exec_json_returns_execution_result() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "exec",
        "--json",
        "--policy",
        "danger-full-access",
        "--cwd",
        &cwd,
        "--",
        python_bin(),
        "-c",
        "print(42)",
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert_eq!(payload["status"], "finished");
    assert_eq!(payload["exit_code"], 0);
    assert_eq!(payload["signal"], Value::Null);
    assert_rfc3339_timestamp(&payload["started_at"])?;
    assert_rfc3339_timestamp(&payload["finished_at"])?;
    assert!(
        payload["execution_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("exec_")
    );
    let session_id = payload["session_id"]
        .as_str()
        .expect("ExecutionResult must include session_id");
    let seal_id = payload["seal_id"]
        .as_str()
        .expect("ExecutionResult must include seal_id");
    assert!(session_id.starts_with("sess_"));
    assert!(seal_id.starts_with("seal_"));
    assert_eq!(payload["policy_id"], "danger-full-access");
    assert_eq!(payload["sandbox"]["enforced"], false);
    assert_eq!(payload["platform_plan"]["enforcement"], "local-execution");
    assert_eq!(
        payload["platform_plan"]["backend"]["name"],
        expected_backend_name()
    );
    assert_eq!(payload["platform_plan"]["filesystem"]["write"][0], "*");
    assert!(
        payload["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert_eq!(payload["policy_epoch"], payload["policy_hash"]);
    let audit_path = payload["audit_path"]
        .as_str()
        .expect("ExecutionResult must include audit_path");
    assert_eq!(audit_path, format!(".runseal/audit/{session_id}.jsonl"));
    let audit_file = tmp.path().join(audit_path);
    let audit_jsonl = fs::read_to_string(&audit_file)
        .with_context(|| format!("audit file must exist at {}", audit_file.display()))?;
    let audit_events: Vec<Value> = audit_jsonl
        .lines()
        .map(|line| serde_json::from_str(line).context("audit line must be JSON"))
        .collect::<Result<_>>()?;
    let audit_event_types: Vec<_> = audit_events
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();
    assert!(audit_event_types.contains(&"execution.started"));
    assert!(audit_event_types.contains(&"execution.stdout"));
    assert!(audit_event_types.contains(&"execution.finished"));
    for event in &audit_events {
        assert_event_envelope(event)?;
        assert_eq!(event["session_id"], session_id);
        assert_eq!(event["seal_id"], seal_id);
        assert_eq!(event["policy_epoch"], payload["policy_epoch"]);
    }
    let audit_stdout = audit_events
        .iter()
        .find(|event| event["type"] == "execution.stdout")
        .context("execution.stdout audit event must exist")?;
    assert_eq!(audit_stdout["encoding"], "base64");
    assert_eq!(audit_stdout["stream_offset"], 0);
    assert!(audit_stdout["bytes"].as_u64().unwrap_or_default() > 0);
    assert!(audit_stdout.get("data").is_none());
    assert!(audit_stdout.get("text").is_none());
    assert!(payload["stdout_bytes"].as_u64().unwrap_or_default() > 0);
    assert_eq!(payload["output_truncated"], false);
    assert!(payload["resource_usage"]["duration_ms"].as_u64().is_some());
    Ok(())
}

#[test]
fn sandboxed_exec_cli_uses_backend_or_reports_unavailable() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let mut args = vec![
        "exec",
        "--json",
        "--policy",
        "read-only",
        "--cwd",
        &cwd,
        "--",
    ];
    if cfg!(windows) {
        args.extend(["cmd", "/d", "/c", "echo sandbox-ok"]);
    } else if cfg!(any(target_os = "linux", target_os = "macos")) {
        args.extend([python_bin(), "-c", "print('sandbox-ok')"]);
    } else {
        args.extend([python_bin(), "-c", "print('must not run')"]);
    }
    let output = run_cli(&args)?;

    if cfg!(windows) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_no_private_windows_setup_terms(&stderr);
        if output.status.success() {
            let payload = stdout_json(&output)?;
            assert_eq!(payload["sandbox"]["enforced"], true);
            assert_eq!(payload["platform_plan"]["enforcement"], "windows-sandbox");
            assert_no_private_windows_setup_terms(&payload.to_string());
            let audit_path = payload["audit_path"]
                .as_str()
                .context("ExecutionResult must include audit_path")?;
            let audit_jsonl = fs::read_to_string(tmp.path().join(audit_path))?;
            assert_no_private_windows_setup_terms(&audit_jsonl);
        } else {
            assert!(stderr.is_empty(), "{stderr}");
            let payload = stdout_json(&output)?;
            assert_eq!(payload["error"]["data"]["code"], "BACKEND_UNAVAILABLE");
            assert!(
                payload["error"]["data"]["reason"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("windows sandbox setup unavailable"),
                "{payload}"
            );
            if let Some(setup_status) = payload["error"]["data"].get("setup_status") {
                assert_eq!(setup_status["setup"], "windows-sandbox");
            }
            assert_no_private_windows_setup_terms(&payload.to_string());
            let audit_dir = tmp.path().join(".runseal").join("audit");
            let audit_files = fs::read_dir(&audit_dir)
                .with_context(|| format!("audit dir must exist at {}", audit_dir.display()))?
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(audit_files.len(), 1);
            let audit_jsonl = fs::read_to_string(audit_files[0].path())?;
            assert_no_private_windows_setup_terms(&audit_jsonl);
        }
        let runtime_dir = tmp.path().join(".runseal").join("runtime");
        if runtime_dir.exists() {
            let runtime_entries = fs::read_dir(&runtime_dir)
                .with_context(|| {
                    format!("runtime dir must be readable at {}", runtime_dir.display())
                })?
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(runtime_entries.len(), 0);
        }
        return Ok(());
    }

    if cfg!(any(target_os = "linux", target_os = "macos")) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.is_empty(), "{stderr}");
        let payload = stdout_json(&output)?;
        let expected_enforcement = if cfg!(target_os = "macos") {
            "macos-experimental"
        } else {
            "linux-experimental"
        };
        if output.status.success() {
            assert_eq!(payload["status"], "finished");
            assert_eq!(payload["exit_code"], 0);
            assert_eq!(payload["sandbox"]["enforced"], true);
            assert_eq!(
                payload["platform_plan"]["enforcement"],
                expected_enforcement
            );
        } else {
            assert!(
                matches!(
                    payload["error"]["data"]["code"].as_str(),
                    Some("BACKEND_UNAVAILABLE" | "EXECUTION_FAILED_TO_START")
                ),
                "{payload}"
            );
            assert_eq!(
                payload["error"]["data"]["backend"]["name"],
                expected_backend_name()
            );
            assert_eq!(
                payload["error"]["data"]["backend"]["status"],
                expected_backend_status()
            );
            assert_eq!(
                payload["error"]["data"]["backend"]["platform"],
                expected_backend_platform()
            );
        }
        assert_no_private_windows_setup_terms(&payload.to_string());
        return Ok(());
    }

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.is_empty(), "{stderr}");
    let payload = stdout_json(&output)?;
    assert_eq!(
        payload["error"]["data"]["code"],
        "BACKEND_CAPABILITY_MISSING"
    );
    assert_eq!(payload["error"]["data"]["support"], "unsupported");
    assert_eq!(
        payload["error"]["data"]["backend"]["name"],
        expected_backend_name()
    );
    assert_eq!(
        payload["error"]["data"]["backend"]["status"],
        expected_backend_status()
    );
    assert_eq!(
        payload["error"]["data"]["backend"]["platform"],
        expected_backend_platform()
    );
    assert_eq!(
        payload["error"]["data"]["missing_features"],
        json!([
            "filesystem_policy",
            "runtime_roots",
            "runtime_environment",
            "process_isolation",
            "process_cleanup",
            "direct_network_deny",
            "network_disabled"
        ])
    );
    assert!(
        payload["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot enforce policy read-only"),
        "{payload}"
    );
    assert_portable_fail_closed_preview(&payload["error"]["data"]["platform_plan"]);
    assert_no_private_windows_setup_terms(&payload.to_string());

    let audit_dir = tmp.path().join(".runseal").join("audit");
    let audit_files = fs::read_dir(&audit_dir)
        .with_context(|| format!("audit dir must exist at {}", audit_dir.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(audit_files.len(), 1);
    let audit_jsonl = fs::read_to_string(audit_files[0].path())?;
    assert_no_private_windows_setup_terms(&audit_jsonl);
    Ok(())
}

#[test]
fn exec_cli_enforces_timeout_ms() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "exec",
        "--json",
        "--policy",
        "danger-full-access",
        "--timeout-ms",
        "10",
        "--cwd",
        &cwd,
        "--",
        python_bin(),
        "-c",
        "import time; time.sleep(1)",
    ])?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.is_empty(), "{stderr}");
    let payload = stdout_json(&output)?;
    let result = &payload["error"]["data"];
    assert_eq!(result["code"], "EXECUTION_TIMEOUT", "{payload}");
    assert_eq!(result["termination_reason"], "timeout", "{payload}");
    assert_eq!(result["status"], "failed", "{payload}");
    assert_eq!(result["cleanup_complete"], true, "{payload}");
    // The accepted timeout includes preparation, so native start is optional.
    if result["started_at"].is_null() {
        assert!(result["exit_code"].is_null(), "{payload}");
    }
    Ok(())
}

#[test]
fn exec_cli_rejects_invalid_timeout_ms() -> Result<()> {
    let output = run_cli(&[
        "exec",
        "--policy",
        "danger-full-access",
        "--timeout-ms",
        "soon",
        "--",
        python_bin(),
        "-c",
        "print('must not run')",
    ])?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timeout must be an integer in milliseconds"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn exec_machine_readable_modes_report_parse_errors_as_json() -> Result<()> {
    for mode in ["--json", "--events"] {
        let output = run_cli(&[
            "exec",
            mode,
            "--policy",
            "danger-full-access",
            "--timeout-ms",
            "soon",
            "--",
            python_bin(),
            "-c",
            "print('must not run')",
        ])?;

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.is_empty(), "{stderr}");
        let messages = stdout_json_lines(&output)?;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            messages[0]["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("timeout must be an integer in milliseconds"),
            "{}",
            messages[0]
        );
    }
    Ok(())
}

#[test]
fn cli_control_rejects_invalid_modes_and_missing_endpoint_before_child_start() -> Result<()> {
    for flags in [
        vec!["--control-fd", "4"],
        vec!["--control-fd", "3", "--json"],
        vec!["--control-fd", "3", "--events"],
        vec!["--control-fd", "3", "--pty", "--stdin", "inherit"],
        vec!["--control-fd", "3"],
    ] {
        let tmp = TempDir::new()?;
        let marker = tmp.path().join("started");
        let mut command = Command::new(env!("CARGO_BIN_EXE_runseal"));
        command
            .arg("exec")
            .args(flags)
            .args(["--policy", "danger-full-access", "--cwd"])
            .arg(tmp.path())
            .args([
                "--",
                python_bin(),
                "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('started')",
            ])
            .arg(&marker);
        let output = command.output()?;
        assert!(!output.status.success());
        assert!(!marker.exists(), "invalid control request launched child");
        assert!(!output.stdout.is_empty() || !output.stderr.is_empty());
    }
    Ok(())
}

#[test]
fn repair_execution_gates_help_describes_the_explicit_release_only() -> Result<()> {
    let help = run_cli(&["repair", "execution-gates", "--help"])?;
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("runseal repair execution-gates"));
    assert!(text.contains("--accept-unverified-release"));
    assert!(text.contains("normal admission"));
    Ok(())
}

#[test]
fn repair_execution_gates_rejects_unknown_arguments_as_json() -> Result<()> {
    let output = run_cli(&["repair", "execution-gates", "--json", "--not-a-flag"])?;
    assert!(!output.status.success());
    let payload = stdout_json(&output)?;
    assert_eq!(payload["error"]["data"]["code"], "INVALID_REQUEST");
    Ok(())
}
