#![cfg(target_os = "macos")]

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct Client {
    child: Child,
    input: Option<ChildStdin>,
    messages: Receiver<Result<Value>>,
}

impl Client {
    fn spawn() -> Result<Self> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_runseal"))
            .args(["service", "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().context("service stdin")?;
        let output = child.stdout.take().context("service stdout")?;
        let (sender, messages) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let value = line
                    .map_err(anyhow::Error::from)
                    .and_then(|line| Ok(serde_json::from_str(&line)?));
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            input: Some(input),
            messages,
        })
    }

    fn send(&mut self, id: u64, method: &str, params: Value) -> Result<()> {
        let input = self.input.as_mut().context("service input closed")?;
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
        )?;
        input.flush()?;
        Ok(())
    }

    fn next(&self, timeout: Duration) -> Result<Value> {
        self.messages
            .recv_timeout(timeout)
            .context("service message watchdog")?
    }

    fn response(&mut self, id: u64) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let message = self.next(deadline.saturating_duration_since(Instant::now()))?;
            if message["id"] == id {
                return Ok(message);
            }
        }
    }

    fn response_with_events(&mut self, id: u64, events: &mut Vec<Value>) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let message = self.next(deadline.saturating_duration_since(Instant::now()))?;
            if message["id"] == id {
                return Ok(message);
            }
            if let Some(event) = message.get("params") {
                events.push(event.clone());
            }
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Closing the service's protocol stdin is a real disconnect request.
        // Wait for its bounded cleanup before using the fixture-only kill as a
        // last resort, so a failed assertion does not strand child processes.
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn python() -> Result<String> {
    let output = Command::new("sh")
        .args(["-c", "command -v python3"])
        .output()?;
    String::from_utf8(output.stdout)?
        .lines()
        .next()
        .map(str::to_owned)
        .context("Python executable")
}

fn payload(bytes: &[u8]) -> String {
    format!("base64:{}", STANDARD.encode(bytes))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn wait_identity(path: &std::path::Path, fields: &[&str]) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(value) = serde_json::from_str::<Value>(&text)
            && fields
                .iter()
                .all(|field| value.get(*field).and_then(Value::as_u64).is_some())
        {
            return Ok(value);
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "identity handshake did not publish a complete JSON object at {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_started_pid(client: &mut Client, execution_id: &str, timeout: Duration) -> Result<u32> {
    let deadline = Instant::now() + timeout;
    loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let Some(event) = message.get("params") else {
            continue;
        };
        if event["execution_id"] != execution_id {
            continue;
        }
        if event["type"] == "execution.started" {
            return Ok(u32::try_from(
                event["process_id"].as_u64().context("started pid")?,
            )?);
        }
        anyhow::ensure!(
            !matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ),
            "execution ended before started observation: {event}"
        );
    }
}

fn wait_terminal_marker(
    client: &mut Client,
    execution_id: &str,
    marker: &[u8],
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut observed = Vec::new();
    loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let Some(event) = message.get("params") else {
            continue;
        };
        if event["execution_id"] != execution_id {
            continue;
        }
        if event["type"] == "execution.terminal" {
            observed.extend(terminal_bytes(std::slice::from_ref(event))?);
            if contains_bytes(&observed, marker) {
                return Ok(());
            }
        }
        anyhow::ensure!(
            !matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ),
            "execution ended before marker {:?}; observed={:?}",
            String::from_utf8_lossy(marker),
            String::from_utf8_lossy(&observed)
        );
    }
}

fn stream_bytes(events: &[Value], event_type: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for event in events
        .iter()
        .filter(|event| event["type"].as_str() == Some(event_type))
    {
        let chunk = STANDARD.decode(
            event["data"]
                .as_str()
                .and_then(|data| data.strip_prefix("base64:"))
                .context("stream chunk")?,
        )?;
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn terminal_bytes(events: &[Value]) -> Result<Vec<u8>> {
    stream_bytes(events, "execution.terminal")
}

fn stdout_bytes(events: &[Value]) -> Result<Vec<u8>> {
    stream_bytes(events, "execution.stdout")
}

fn control_bytes(events: &[Value]) -> Result<Vec<u8>> {
    stream_bytes(events, "execution.control")
}

fn collect_until_terminal(
    client: &mut Client,
    execution_id: &str,
    mut on_event: impl FnMut(&mut Client, &Value) -> Result<()>,
) -> Result<(Vec<Value>, Value)> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut events = Vec::new();
    loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let Some(event) = message.get("params") else {
            continue;
        };
        if event["execution_id"] != execution_id {
            continue;
        }
        events.push(event.clone());
        on_event(client, event)?;
        if matches!(
            event["type"].as_str(),
            Some("execution.finished" | "execution.failed")
        ) {
            return Ok((events, event.clone()));
        }
    }
}

fn process_present(pid: u32) -> Result<bool> {
    let pid = i32::try_from(pid).context("process id out of range")?;
    if unsafe { libc::kill(pid, 0) } == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM) => Ok(true),
        Some(libc::ESRCH) => Ok(false),
        _ => Err(std::io::Error::last_os_error().into()),
    }
}

fn wait_process_gone(pid: u32) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while process_present(pid)? {
        anyhow::ensure!(Instant::now() < deadline, "owned process {pid} survived");
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn assert_cleanup_completed(terminal: &Value) {
    assert_eq!(terminal["result"]["cleanup_complete"], true, "{terminal}");
}

/// A naturally exited execution must report `exited` and carry no error object.
fn assert_exited_cleanly(terminal: &Value) {
    assert_cleanup_completed(terminal);
    assert_eq!(
        terminal["result"]["termination_reason"], "exited",
        "{terminal}"
    );
    assert!(
        terminal["result"].get("error").is_none(),
        "natural exit carried an error: {terminal}"
    );
}

/// A cancelled execution must report `cancelled` with the stable cancellation
/// error code; cleanup must still be complete.
fn assert_cancelled_cleanly(terminal: &Value) {
    assert_cleanup_completed(terminal);
    assert_eq!(
        terminal["result"]["termination_reason"], "cancelled",
        "{terminal}"
    );
    assert_eq!(
        terminal["result"]["error"]["code"], "EXECUTION_CANCELLED",
        "{terminal}"
    );
}

#[test]
fn macos_rpc_pty_real_terminal_input_resize_and_raw_etx() -> Result<()> {
    let tmp = TempDir::new()?;
    let code = concat!(
        "import os,signal,sys,tty\n",
        "assert all(os.isatty(fd) for fd in (0,1,2))\n",
        "size=os.get_terminal_size(1)\n",
        "print('PTY_READY:%d:%d'%(size.columns,size.lines),flush=True)\n",
        "def on_winch(signum,frame):\n",
        " size=os.get_terminal_size(1)\n",
        " print('PTY_RESIZED:%d:%d'%(size.columns,size.lines),flush=True)\n",
        "signal.signal(signal.SIGWINCH,on_winch)\n",
        "print('WINCH_READY',flush=True)\n",
        "line=sys.stdin.readline()\n",
        "tty.setraw(0)\n",
        "print('RAW_READY',flush=True)\n",
        "byte=os.read(0,1)\n",
        "print('RAW_BYTE:%d'%byte[0],flush=True)\n",
    );
    let mut client = Client::spawn()?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":"workspace-write","stdin":{"mode":"stream"},"io":{"mode":"pty","rows":17,"cols":101}}))?;
    let receipt = client.next(Duration::from_secs(10))?;
    let execution = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?
        .to_owned();

    let mut saw_initial = false;
    let mut winch_ready = false;
    let mut wrote_resize = false;
    let mut wrote_input = false;
    let mut wrote_etx = false;
    let mut observed = Vec::new();
    let mut events = Vec::new();
    let mut stage = "waiting_for_start";
    let deadline = Instant::now() + Duration::from_secs(30);
    let terminal = loop {
        let message = match client.next(deadline.saturating_duration_since(Instant::now())) {
            Ok(message) => message,
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "PTY stage '{stage}' timed out: {error}; saw_initial={saw_initial}, winch_ready={winch_ready}, wrote_resize={wrote_resize}, wrote_input={wrote_input}, wrote_etx={wrote_etx}; terminal_so_far={:?}",
                    String::from_utf8_lossy(&observed)
                ));
            }
        };
        if let Some(id) = message["id"].as_u64() {
            if message.get("error").is_some() {
                return Err(anyhow::anyhow!(
                    "PTY command id={id} failed at stage '{stage}': {message}"
                ));
            }
            continue;
        }
        let Some(event) = message.get("params") else {
            continue;
        };
        if event["execution_id"] != execution {
            continue;
        }
        events.push(event.clone());
        match event["type"].as_str() {
            Some("execution.started") if stage == "waiting_for_start" => {
                stage = "waiting_for_initial_terminal";
            }
            Some("execution.terminal") => {
                observed.extend(terminal_bytes(std::slice::from_ref(event))?);
                if !saw_initial && contains_bytes(&observed, b"PTY_READY:101:17") {
                    saw_initial = true;
                    stage = "waiting_for_winch_ready";
                }
                if saw_initial && !winch_ready && contains_bytes(&observed, b"WINCH_READY") {
                    // The handler is installed; only now can a real WINCH
                    // deliver the new dimensions instead of being ignored.
                    client.send(
                        2,
                        "resizeExecution",
                        json!({"execution_id":execution,"rows":41,"cols":123}),
                    )?;
                    winch_ready = true;
                    wrote_resize = true;
                    stage = "waiting_for_resize_confirmation";
                }
                if wrote_resize
                    && !wrote_input
                    && stage == "waiting_for_resize_confirmation"
                    && contains_bytes(&observed, b"PTY_RESIZED:123:41")
                {
                    // RFC resize receipts accept the request; this waits for
                    // the child's real SIGWINCH dimensions before typing.
                    client.send(3,"writeExecutionInput",json!({"execution_id":execution,"stream":"stdin","encoding":"base64","data":payload(b"go\n")}))?;
                    wrote_input = true;
                    stage = "waiting_for_raw_ready";
                }
                if wrote_input
                    && !wrote_etx
                    && stage == "waiting_for_raw_ready"
                    && contains_bytes(&observed, b"RAW_READY")
                {
                    client.send(4,"writeExecutionInput",json!({"execution_id":execution,"stream":"stdin","encoding":"base64","data":payload(&[3])}))?;
                    wrote_etx = true;
                    stage = "waiting_for_raw_byte_and_terminal";
                }
                if wrote_etx
                    && stage == "waiting_for_raw_byte_and_terminal"
                    && contains_bytes(&observed, b"RAW_BYTE:3")
                {
                    stage = "waiting_for_terminal";
                }
            }
            Some("execution.finished" | "execution.failed") => break event.clone(),
            _ => {}
        }
    };

    let bytes = terminal_bytes(&events)?;
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("PTY_READY:101:17"), "{text}");
    assert!(text.contains("PTY_RESIZED:123:41"), "{text}");
    assert!(text.contains("RAW_BYTE:3"), "{text}");
    assert!(!events.iter().any(|event| matches!(
        event["type"].as_str(),
        Some("execution.stdout" | "execution.stderr")
    )));
    assert_eq!(terminal["result"]["stderr_merged"], true);
    assert_eq!(terminal["result"]["stdout_bytes"], 0);
    assert_eq!(terminal["result"]["stderr_bytes"], 0);
    assert_eq!(terminal["result"]["sandbox"]["enforced"], true);
    assert_exited_cleanly(&terminal);
    Ok(())
}

#[test]
fn macos_rpc_signal_reports_native_foreground_group() -> Result<()> {
    let tmp = TempDir::new()?;
    let python = python()?;
    let mut client = Client::spawn()?;
    client.send(1,"execute",json!({"command":["/bin/zsh","-f","-i"],"cwd":tmp.path(),"policy":"workspace-write","stdin":{"mode":"stream"},"io":{"mode":"pty","rows":30,"cols":120}}))?;
    let receipt = client.next(Duration::from_secs(10))?;
    let shell = receipt["result"]["execution_id"]
        .as_str()
        .context("shell id")?
        .to_owned();
    client.send(2,"writeExecutionInput",json!({"execution_id":shell,"stream":"stdin","encoding":"base64","data":payload(b"printf 'SHELL''_READY:%s\\n' $$\n")}))?;
    wait_terminal_marker(
        &mut client,
        &shell,
        b"SHELL_READY:",
        Duration::from_secs(10),
    )?;
    let command = format!(
        "{python} -u -c \"import json,os,pathlib,time\ndef publish(name):\n p=pathlib.Path(name); tmp=p.with_suffix('.tmp'); tmp.write_text(json.dumps(dict(pid=os.getpid(),pgid=os.getpgid(0),shell_pid=os.getppid()))); os.replace(tmp,p)\npublish('fg.json'); print('FG_READY',flush=True); time.sleep(60)\"\n"
    );
    client.send(3,"writeExecutionInput",json!({"execution_id":shell,"stream":"stdin","encoding":"base64","data":payload(command.as_bytes())}))?;
    let identity = wait_identity(&tmp.path().join("fg.json"), &["pid", "pgid", "shell_pid"])?;
    let fg_pid = u32::try_from(identity["pid"].as_u64().context("fg pid")?)?;
    let fg_pgid = u32::try_from(identity["pgid"].as_u64().context("fg pgid")?)?;
    let shell_pid = u32::try_from(identity["shell_pid"].as_u64().context("shell pid")?)?;
    client.send(
        4,
        "signalExecution",
        json!({"execution_id":shell,"signal":"interrupt"}),
    )?;

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut accepted = false;
    let mut delivered = None;
    while !accepted || delivered.is_none() || process_present(fg_pid)? {
        anyhow::ensure!(
            Instant::now() < deadline,
            "foreground survived native SIGINT"
        );
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        if message["id"] == 4 {
            assert_eq!(message["result"]["accepted"], true, "{message}");
            accepted = true;
        }
        if message["params"]["type"] == "execution.signal_delivered" {
            delivered = Some(message["params"].clone());
        }
    }
    let delivered = delivered.context("signal delivery event")?;
    assert_eq!(delivered["sequence"], 1);
    assert_eq!(
        delivered["target_process_id"].as_u64(),
        Some(u64::from(shell_pid))
    );
    assert_eq!(
        delivered["target_process_group_id"].as_u64(),
        Some(u64::from(fg_pgid))
    );
    assert!(
        process_present(shell_pid)?,
        "shell was terminated by interrupt"
    );

    client.send(5,"writeExecutionInput",json!({"execution_id":shell,"stream":"stdin","encoding":"base64","data":payload(b"exit 0\n")}))?;
    let (_, terminal) = collect_until_terminal(&mut client, &shell, |_, _| Ok(()))?;
    assert_exited_cleanly(&terminal);
    Ok(())
}

#[test]
fn macos_rpc_control_fd7_socket_large_segmented_round_trip_and_half_close() -> Result<()> {
    let tmp = TempDir::new()?;
    let code = concat!(
        "import socket\n",
        "s=socket.socket(fileno=7)\n",
        "s.sendall(b'READY')\n",
        "total=0\n",
        "while total < 98304:\n",
        " data=s.recv(65536)\n",
        " if not data: break\n",
        " total += len(data)\n",
        " s.sendall(data)\n",
        "s.sendall(('DONE:%d'%total).encode())\n",
        "while True:\n",
        " data=s.recv(65536)\n",
        " if not data: break\n",
        "print('CONTROL_EXIT',flush=True)\n",
    );
    let mut client = Client::spawn()?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":"workspace-write","io":{"mode":"pipe","control":{"mode":"socket","child_fd":7}}}))?;
    let receipt = client.next(Duration::from_secs(10))?;
    let execution = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?
        .to_owned();

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut events = Vec::new();
    let mut ready = false;
    while !ready {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let Some(event) = message.get("params") else {
            continue;
        };
        if event["execution_id"] != execution {
            continue;
        }
        if event["type"] == "execution.control" {
            events.push(event.clone());
            if control_bytes(&events)?.starts_with(b"READY".as_slice()) {
                ready = true;
            }
        }
    }

    let block = vec![b'C'; 32768];
    for id in [10_u64, 11, 12] {
        client.send(id,"writeExecutionInput",json!({"execution_id":execution,"stream":"control","encoding":"base64","data":payload(&block)}))?;
        let response = client.response_with_events(id, &mut events)?;
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["accepted_bytes"], 32768);
    }
    client.send(
        20,
        "closeExecutionInput",
        json!({"execution_id":execution,"stream":"control"}),
    )?;

    let (all_events, terminal) = {
        let mut on_event = |_client: &mut Client, event: &Value| -> Result<()> {
            if event["type"] == "execution.control" {
                events.push(event.clone());
            }
            Ok(())
        };
        collect_until_terminal(&mut client, &execution, &mut on_event)?
    };
    let control = control_bytes(&events)?;
    let payload_bytes = vec![b'C'; 98304];
    let mut expected = b"READY".to_vec();
    expected.extend_from_slice(&payload_bytes);
    expected.extend_from_slice(b"DONE:98304");
    assert_eq!(
        control,
        expected,
        "control byte stream mismatch (received {} bytes)",
        control.len()
    );
    let stdout = stdout_bytes(&all_events)?;
    assert_eq!(
        stdout, b"CONTROL_EXIT\n",
        "control child did not report exit after half-close"
    );
    assert_exited_cleanly(&terminal);
    Ok(())
}

#[test]
fn macos_rpc_control_pipe_close_does_not_claim_peer_eof() -> Result<()> {
    let tmp = TempDir::new()?;
    let code = concat!(
        "import socket,select\n",
        "s=socket.socket(fileno=7)\n",
        "s.sendall(b'READY')\n",
        "r,_,_=select.select([s],[],[],1.5)\n",
        "s.sendall(b'SAW_EOF' if r else b'NO_EOF')\n",
        "while True:\n",
        " data=s.recv(4096)\n",
        " if not data: break\n",
    );
    let mut client = Client::spawn()?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":"workspace-write","io":{"mode":"pipe","control":{"mode":"pipe","child_fd":7}}}))?;
    let receipt = client.next(Duration::from_secs(10))?;
    let execution = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?
        .to_owned();

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut events = Vec::new();
    loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let Some(event) = message.get("params") else {
            continue;
        };
        if event["execution_id"] != execution || event["type"] != "execution.control" {
            continue;
        }
        events.push(event.clone());
        if control_bytes(&events)?.starts_with(b"READY".as_slice()) {
            break;
        }
    }
    client.send(
        2,
        "closeExecutionInput",
        json!({"execution_id":execution,"stream":"control"}),
    )?;
    loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let Some(event) = message.get("params") else {
            continue;
        };
        if event["execution_id"] != execution || event["type"] != "execution.control" {
            continue;
        }
        events.push(event.clone());
        if contains_bytes(&control_bytes(&events)?, b"NO_EOF") {
            break;
        }
        anyhow::ensure!(
            !contains_bytes(&control_bytes(&events)?, b"SAW_EOF"),
            "pipe-mode close produced peer EOF"
        );
    }
    client.send(3, "cancelExecution", json!({"execution_id":execution}))?;
    let (_, terminal) = collect_until_terminal(&mut client, &execution, |_, _| Ok(()))?;
    assert_cancelled_cleanly(&terminal);
    Ok(())
}

#[test]
fn macos_rpc_cancel_terminates_observed_setsid_escape() -> Result<()> {
    let tmp = TempDir::new()?;
    let python = python()?;
    let mut client = Client::spawn()?;
    client.send(1,"execute",json!({"command":["/bin/zsh","-f","-i"],"cwd":tmp.path(),"policy":"workspace-write","stdin":{"mode":"stream"},"io":{"mode":"pty","rows":30,"cols":120}}))?;
    let receipt = client.next(Duration::from_secs(10))?;
    let shell = receipt["result"]["execution_id"]
        .as_str()
        .context("shell id")?
        .to_owned();
    client.send(2,"writeExecutionInput",json!({"execution_id":shell,"stream":"stdin","encoding":"base64","data":payload(b"printf 'SHELL''_READY:%s\\n' $$\n")}))?;
    wait_terminal_marker(
        &mut client,
        &shell,
        b"SHELL_READY:",
        Duration::from_secs(10),
    )?;
    let command = format!(
        "{python} -u -c \"import json,os,pathlib,time\ndef publish(name):\n p=pathlib.Path(name); tmp=p.with_suffix('.tmp'); tmp.write_text(json.dumps(dict(pid=os.getpid(),pgid=os.getpgid(0),sid=os.getsid(0)))); os.replace(tmp,p)\nif os.fork()==0:\n os.setsid(); publish('daemon.json'); count=0\n while True:\n  count+=1; pathlib.Path('daemon.beat').write_text(str(count)); time.sleep(0.02)\nelse:\n time.sleep(60)\n\" &\n"
    );
    client.send(3,"writeExecutionInput",json!({"execution_id":shell,"stream":"stdin","encoding":"base64","data":payload(command.as_bytes())}))?;
    let identity = wait_identity(&tmp.path().join("daemon.json"), &["pid", "pgid", "sid"])?;
    let daemon_pid = u32::try_from(identity["pid"].as_u64().context("daemon pid")?)?;
    // The forked parent stays alive and keeps the ancestor chain stable, so the
    // first cleanup enumeration can attribute the setsid child by ppid without
    // relying on a polling tracker having observed an earlier instant.
    client.send(4, "cancelExecution", json!({"execution_id":shell}))?;
    let (_, terminal) = collect_until_terminal(&mut client, &shell, |_, _| Ok(()))?;
    assert_cancelled_cleanly(&terminal);
    wait_process_gone(daemon_pid)?;
    // Writes that raced with termination are valid; only writes observed after
    // the process is confirmed gone prove a cleanup failure.
    let settled = std::fs::read_to_string(tmp.path().join("daemon.beat")).unwrap_or_default();
    std::thread::sleep(Duration::from_millis(100));
    let later = std::fs::read_to_string(tmp.path().join("daemon.beat")).unwrap_or_default();
    assert_eq!(
        later, settled,
        "setsid child kept writing after terminate was confirmed"
    );
    Ok(())
}

#[test]
fn macos_rpc_danger_full_access_pty_is_explicit_local_execution() -> Result<()> {
    let tmp = TempDir::new()?;
    let code = concat!(
        "import os,sys\n",
        "assert os.isatty(1)\n",
        "print('LOCAL_PTY_READY',flush=True)\n",
        "line=sys.stdin.readline()\n",
        "print('LOCAL_PTY_GOT:'+line.strip(),flush=True)\n",
    );
    let mut client = Client::spawn()?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"},"io":{"mode":"pty","rows":20,"cols":90}}))?;
    let receipt = client.next(Duration::from_secs(10))?;
    let execution = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?
        .to_owned();
    wait_terminal_marker(
        &mut client,
        &execution,
        b"LOCAL_PTY_READY",
        Duration::from_secs(10),
    )?;
    client.send(2,"writeExecutionInput",json!({"execution_id":execution,"stream":"stdin","encoding":"base64","data":payload(b"ok\n")}))?;
    let (events, terminal) = collect_until_terminal(&mut client, &execution, |_, _| Ok(()))?;
    let text = String::from_utf8_lossy(&terminal_bytes(&events)?).into_owned();
    assert!(text.contains("LOCAL_PTY_GOT:ok"), "{text}");
    assert_eq!(
        terminal["result"]["sandbox"]["enforced"], false,
        "{terminal}"
    );
    assert_exited_cleanly(&terminal);
    Ok(())
}

#[test]
fn macos_rpc_danger_full_access_control_is_explicit_local_execution() -> Result<()> {
    let tmp = TempDir::new()?;
    let code = concat!(
        "import socket\n",
        "s=socket.socket(fileno=7)\n",
        "s.sendall(b'LOCAL_READY')\n",
        "total=0\n",
        "while total < 65536:\n",
        " data=s.recv(65536)\n",
        " if not data: break\n",
        " total += len(data)\n",
        " s.sendall(data)\n",
        "s.sendall(('LOCAL_DONE:%d'%total).encode())\n",
        "while True:\n",
        " data=s.recv(65536)\n",
        " if not data: break\n",
        "print('LOCAL_CONTROL_EXIT',flush=True)\n",
    );
    let mut client = Client::spawn()?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":"danger-full-access","io":{"mode":"pipe","control":{"mode":"socket","child_fd":7}}}))?;
    let receipt = client.next(Duration::from_secs(10))?;
    let execution = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?
        .to_owned();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut events = Vec::new();
    loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let Some(event) = message.get("params") else {
            continue;
        };
        if event["execution_id"] != execution || event["type"] != "execution.control" {
            continue;
        }
        events.push(event.clone());
        if control_bytes(&events)?.starts_with(b"LOCAL_READY".as_slice()) {
            break;
        }
    }
    let block = vec![b'L'; 65536];
    client.send(2,"writeExecutionInput",json!({"execution_id":execution,"stream":"control","encoding":"base64","data":payload(&block)}))?;
    let response = client.response_with_events(2, &mut events)?;
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["result"]["accepted_bytes"], 65536);
    client.send(
        3,
        "closeExecutionInput",
        json!({"execution_id":execution,"stream":"control"}),
    )?;
    let (all_events, terminal) = {
        let mut on_event = |_client: &mut Client, event: &Value| -> Result<()> {
            if event["type"] == "execution.control" {
                events.push(event.clone());
            }
            Ok(())
        };
        collect_until_terminal(&mut client, &execution, &mut on_event)?
    };
    let control = control_bytes(&events)?;
    let mut expected = b"LOCAL_READY".to_vec();
    expected.extend_from_slice(&block);
    expected.extend_from_slice(b"LOCAL_DONE:65536");
    assert_eq!(control, expected);
    assert_eq!(stdout_bytes(&all_events)?, b"LOCAL_CONTROL_EXIT\n");
    assert_eq!(
        terminal["result"]["sandbox"]["enforced"], false,
        "{terminal}"
    );
    assert_exited_cleanly(&terminal);
    Ok(())
}

#[test]
fn macos_fast_double_fork_reparent_cleanup_is_complete() -> Result<()> {
    let tmp = TempDir::new()?;
    let code = concat!(
        "import json,os,pathlib,time\n",
        "def publish():\n",
        " p=pathlib.Path('escape.json'); tmp=p.with_suffix('.tmp'); tmp.write_text(json.dumps(dict(pid=os.getpid(),ppid=os.getppid(),sid=os.getsid(0)))); os.replace(tmp,p); pathlib.Path('escape.ready').write_text('ready')\n",
        "if os.fork()==0:\n",
        " os.setsid()\n",
        " if os.fork()==0:\n",
        "  deadline=time.time()+3.0\n",
        "  while os.getppid()!=1 and time.time()<deadline: time.sleep(0.01)\n",
        "  if os.getppid()!=1: os._exit(2)\n",
        "  publish(); time.sleep(60.0); os._exit(0)\n",
        " os._exit(0)\n",
        "deadline=time.time()+3.0\n",
        "while not pathlib.Path('escape.ready').exists() and time.time()<deadline: time.sleep(0.01)\n",
        "os._exit(0)\n",
    );
    let mut client = Client::spawn()?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":"workspace-write","stdin":{"mode":"stream"},"io":{"mode":"pty","rows":24,"cols":80}}))?;
    let receipt = client.next(Duration::from_secs(10))?;
    let execution = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?
        .to_owned();
    let root_pid = wait_started_pid(&mut client, &execution, Duration::from_secs(10))?;
    let identity = wait_identity(&tmp.path().join("escape.json"), &["pid", "ppid", "sid"])?;
    let escape_pid = u32::try_from(identity["pid"].as_u64().context("escape pid")?)?;
    let session_leader_pid = u32::try_from(identity["sid"].as_u64().context("escape sid")?)?;
    assert_eq!(
        identity["ppid"].as_u64(),
        Some(1),
        "counterexample child must be reparented to launchd"
    );
    assert_ne!(
        session_leader_pid, root_pid,
        "counterexample child must leave the original execution session"
    );
    assert_ne!(
        session_leader_pid, escape_pid,
        "grandchild inherits the first child's session; it does not own a new session"
    );
    let (_, terminal) = collect_until_terminal(&mut client, &execution, |_, _| Ok(()))?;
    assert_exited_cleanly(&terminal);
    // The escaped grandchild keeps running for 60 seconds, so a natural exit
    // cannot make this pass; only the cohort cleanup can make it disappear.
    wait_process_gone(escape_pid)?;
    Ok(())
}

#[test]
fn macos_capabilities_keep_native_transports_experimental() -> Result<()> {
    let mut client = Client::spawn()?;
    client.send(1, "getCapabilities", json!({}))?;
    let response = client.response(1)?;
    let capabilities = &response["result"];
    assert_eq!(
        capabilities["execution_capabilities"]["pty"],
        "experimental"
    );
    assert_eq!(
        capabilities["execution_capabilities"]["control_channel"],
        "experimental"
    );
    let notes = capabilities["notes"]
        .as_array()
        .context("capability notes")?;
    assert!(
        notes.iter().any(|note| note
            .as_str()
            .is_some_and(|note| note.contains("launchd cohort"))),
        "{capabilities}"
    );
    assert!(
        !notes.iter().any(|note| note
            .as_str()
            .is_some_and(|note| note.contains("cleanup_complete=false"))),
        "capability notes must not claim native cleanup is permanently incomplete: {capabilities}"
    );
    Ok(())
}
