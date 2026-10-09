use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn process_test_gate() -> std::sync::MutexGuard<'static, ()> {
    static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    GATE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn configured_active_execution_limit_refuses_an_extra_target_while_controls_stay_live() -> Result<()>
{
    let _guard = process_test_gate();
    for mode in ["rpc", "service"] {
        let tmp = TempDir::new()?;
        let configured = std::ffi::OsString::from("2");
        let mut client = Client::spawn_with_env_values(
            mode,
            &[("RUNSEAL_MAX_ACTIVE_EXECUTIONS", configured.as_os_str())],
        )?;
        client.send(1, "getCapabilities", json!({}))?;
        let capabilities = client.next(Duration::from_secs(2))?;
        let mut active = Vec::new();
        for id in [2, 3] {
            client.send(id, "execute", json!({"command":[python()?,"-u","-c","import os,sys; print('READY '+str(os.getpid()),flush=True); sys.stdin.buffer.read(1)"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}))?;
            let receipt = client.next(Duration::from_secs(2))?;
            let execution = receipt["result"]["execution_id"]
                .as_str()
                .context("execution ID")?
                .to_owned();
            let pid = wait_ready_pid(&client, &execution)?;
            active.push((execution, pid));
        }
        let rejected_marker = tmp.path().join("extra.ran");
        client.send(4, "execute", json!({"command":[python()?,"-c","import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('RAN')",rejected_marker],"cwd":tmp.path(),"policy":"danger-full-access"}))?;
        let rejected = client.next(Duration::from_secs(2))?;
        client.send(5, "getVersion", json!({}))?;
        let control_response = loop {
            let response = client.next(Duration::from_secs(2))?;
            if response["id"] == 5 {
                break response;
            }
        };
        let mut terminals = Vec::new();
        for (index, (execution, _)) in active.iter().enumerate() {
            client.send(
                6 + index as u64,
                "cancelExecution",
                json!({"execution_id":execution}),
            )?;
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
                if message["params"]["execution_id"] == execution.as_str()
                    && message["params"]["type"] == "execution.failed"
                {
                    terminals.push(message["params"]["result"].clone());
                    break;
                }
            }
        }
        // EOF closes every fixture-owned execution before checking a broken admission implementation.
        drop(client);
        assert_eq!(capabilities["result"]["limits"]["max_active_executions"], 2);
        assert_eq!(
            rejected["error"]["data"]["code"], "EXECUTION_LIMIT_EXCEEDED",
            "{rejected}"
        );
        assert_eq!(
            control_response["result"]["protocol_version"],
            "runseal.protocol/v2"
        );
        assert!(
            !rejected_marker.exists(),
            "a rejected target must not execute"
        );
        for ((_, pid), terminal) in active.iter().zip(terminals) {
            assert_eq!(terminal["cleanup_complete"], true, "{terminal}");
            assert!(!process_present(*pid)?);
        }
    }
    Ok(())
}

#[test]
fn configured_replay_budget_changes_retention_without_changing_execution_policy() -> Result<()> {
    let _guard = process_test_gate();
    let mut results = Vec::new();
    let tmp = TempDir::new()?;
    for budget in ["65536", "1048576"] {
        let mut client = Client::spawn_with_env_values(
            "service",
            &[
                (
                    "RUNSEAL_REPLAY_EXECUTION_BYTES",
                    std::ffi::OsStr::new(budget),
                ),
                (
                    "RUNSEAL_REPLAY_CONNECTION_BYTES",
                    std::ffi::OsStr::new(budget),
                ),
            ],
        )?;
        client.send(1, "getCapabilities", json!({}))?;
        let capabilities = client.next(Duration::from_secs(2))?;
        client.send(2, "execute", json!({"command":[python()?,"-u","-c","import sys; sys.stdout.buffer.write(b'R'*131072); sys.stdout.buffer.flush()"],"cwd":tmp.path(),"policy":"danger-full-access"}))?;
        let receipt = client.next(Duration::from_secs(2))?;
        let execution = receipt["result"]["execution_id"]
            .as_str()
            .context("execution ID")?
            .to_owned();
        let mut output = Vec::new();
        let terminal = loop {
            let message = client.next(Duration::from_secs(10))?;
            let event = &message["params"];
            if event["type"] == "execution.stdout" {
                let data = event["data"]
                    .as_str()
                    .context("output data")?
                    .strip_prefix("base64:")
                    .context("base64 output")?;
                output.extend(STANDARD.decode(data)?);
            }
            if event["type"] == "execution.finished" || event["type"] == "execution.failed" {
                break event.clone();
            }
        };
        client.send(
            3,
            "subscribeEvents",
            json!({"execution_id":execution,"after_seq":0}),
        )?;
        let replay = client.next(Duration::from_secs(2))?;
        drop(client);
        assert_eq!(
            capabilities["result"]["limits"]["replay_execution_bytes"],
            budget.parse::<u64>()?
        );
        assert_eq!(
            capabilities["result"]["limits"]["replay_connection_bytes"],
            budget.parse::<u64>()?
        );
        assert_eq!(output, vec![b'R'; 131072]);
        assert_eq!(terminal["type"], "execution.finished", "{terminal}");
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        if budget == "65536" {
            assert_eq!(
                replay["error"]["data"]["code"], "EVENT_HISTORY_UNAVAILABLE",
                "{replay}"
            );
            assert!(
                terminal["result"]["earliest_available_seq"]
                    .as_u64()
                    .context("earliest seq")?
                    > 1
            );
        } else {
            assert!(
                replay["result"]["event_count"]
                    .as_u64()
                    .context("replay count")?
                    > 0
            );
            assert_eq!(terminal["result"]["earliest_available_seq"], 1);
        }
        results.push(terminal["result"]["policy_hash"].clone());
    }
    assert_eq!(results[0], results[1]);
    Ok(())
}

#[test]
fn configured_connection_replay_budget_evicts_old_history_without_erasing_terminal_or_audit()
-> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    for connection in ["1048576", "8388608"] {
        let mut client = Client::spawn_with_env_values(
            "service",
            &[
                (
                    "RUNSEAL_REPLAY_EXECUTION_BYTES",
                    std::ffi::OsStr::new("1048576"),
                ),
                (
                    "RUNSEAL_REPLAY_CONNECTION_BYTES",
                    std::ffi::OsStr::new(connection),
                ),
            ],
        )?;
        let mut executions = Vec::new();
        for id in [1, 2] {
            client.send(id, "execute", json!({"command":[python()?,"-u","-c","import sys; sys.stdout.buffer.write(b'C'*524288); sys.stdout.buffer.flush()"],"cwd":tmp.path(),"policy":"danger-full-access"}))?;
            let receipt = client.next(Duration::from_secs(2))?;
            let execution = receipt["result"]["execution_id"]
                .as_str()
                .context("execution ID")?
                .to_owned();
            let mut count = 0;
            let terminal = loop {
                let message = client.next(Duration::from_secs(10))?;
                let event = &message["params"];
                if event["type"] == "execution.stdout" {
                    let data = event["data"]
                        .as_str()
                        .context("output data")?
                        .strip_prefix("base64:")
                        .context("base64 output")?;
                    let bytes = STANDARD.decode(data)?;
                    assert!(bytes.iter().all(|byte| *byte == b'C'));
                    count += bytes.len();
                }
                if event["type"] == "execution.finished" || event["type"] == "execution.failed" {
                    break event.clone();
                }
            };
            executions.push((execution, count, terminal));
        }
        client.send(3, "getExecution", json!({"execution_id":executions[0].0}))?;
        let first = client.next(Duration::from_secs(2))?;
        client.send(4, "getAuditEvents", json!({"execution_id":executions[0].0}))?;
        let audit = client.next(Duration::from_secs(2))?;
        client.send(
            5,
            "subscribeEvents",
            json!({"execution_id":executions[0].0,"after_seq":0}),
        )?;
        let replay = client.next(Duration::from_secs(2))?;
        drop(client);
        for (_, count, terminal) in &executions {
            assert_eq!(*count, 524288);
            assert_eq!(terminal["type"], "execution.finished");
            assert_eq!(terminal["result"]["cleanup_complete"], true);
            assert_eq!(
                terminal["result"]["earliest_available_seq"], 1,
                "each execution fits its own budget at commitment"
            );
        }
        assert_eq!(first["result"]["status"], "finished");
        assert_eq!(audit["result"]["truncated"], false);
        assert!(
            !audit["result"]["events"]
                .as_array()
                .context("audit events")?
                .is_empty()
        );
        if connection == "1048576" {
            assert_eq!(
                replay["error"]["data"]["code"], "EVENT_HISTORY_UNAVAILABLE",
                "{replay}"
            );
            assert!(
                first["result"]["earliest_available_seq"]
                    .as_u64()
                    .context("earliest seq")?
                    > 1
            );
        } else {
            assert!(
                replay["result"]["event_count"]
                    .as_u64()
                    .context("replay count")?
                    > 0
            );
            assert_eq!(first["result"]["earliest_available_seq"], 1);
        }
    }
    Ok(())
}

#[test]
fn configured_summary_and_audit_retention_preserves_active_targets_and_durable_terminals()
-> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    for (count_limit, summary_bytes, audit_bytes) in [
        ("2", "8388608", "8388608"),
        ("1024", "65536", "65536"),
        ("1024", "8388608", "8388608"),
    ] {
        let mut client = Client::spawn_with_env_values(
            "service",
            &[
                (
                    "RUNSEAL_COMPLETED_EXECUTIONS",
                    std::ffi::OsStr::new(count_limit),
                ),
                (
                    "RUNSEAL_COMPLETED_EXECUTION_BYTES",
                    std::ffi::OsStr::new(summary_bytes),
                ),
                (
                    "RUNSEAL_AUDIT_CACHE_BYTES",
                    std::ffi::OsStr::new(audit_bytes),
                ),
            ],
        )?;
        client.send(1, "execute", json!({"command":[python()?,"-u","-c","import os,sys; print('READY '+str(os.getpid()),flush=True); sys.stdin.buffer.read()"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}))?;
        let receipt = client.next(Duration::from_secs(2))?;
        let peer = receipt["result"]["execution_id"]
            .as_str()
            .context("peer execution")?
            .to_owned();
        let peer_pid = wait_ready_pid(&client, &peer)?;
        let mut completed = Vec::new();
        for id in 2..22 {
            client.send(id, "execute", json!({"command":[python()?,"-u","-c","print('DONE',flush=True)"],"cwd":tmp.path(),"policy":"danger-full-access","metadata":{"note":"N".repeat(2048),"token":"retention-secret-canary"}}))?;
            let receipt = client.next(Duration::from_secs(2))?;
            let execution = receipt["result"]["execution_id"]
                .as_str()
                .context("execution ID")?
                .to_owned();
            let terminal = loop {
                let message = client.next(Duration::from_secs(10))?;
                if message["params"]["execution_id"] == execution
                    && matches!(
                        message["params"]["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    )
                {
                    break message["params"].clone();
                }
            };
            completed.push((execution, terminal));
        }
        client.send(32, "getExecution", json!({"execution_id":completed[0].0}))?;
        let oldest = client.next(Duration::from_secs(2))?;
        client.send(33, "listExecutions", json!({}))?;
        let summaries = client.next(Duration::from_secs(2))?;
        client.send(34, "tailAudit", json!({"types":["execution.stdout"]}))?;
        let audit = client.next(Duration::from_secs(2))?;
        client.send(35, "getCapabilities", json!({}))?;
        let capabilities = client.next(Duration::from_secs(2))?;
        client.send(36, "getExecution", json!({"execution_id":peer}))?;
        let active = client.next(Duration::from_secs(2))?;
        let peer_alive = process_present(peer_pid)?;
        client.send(37, "cancelExecution", json!({"execution_id":peer}))?;
        let peer_terminal = loop {
            let message = client.next(Duration::from_secs(10))?;
            if message["params"]["execution_id"] == peer
                && message["params"]["type"] == "execution.failed"
            {
                break message["params"].clone();
            }
        };
        drop(client);
        for (_, terminal) in &completed {
            assert_eq!(terminal["type"], "execution.finished");
            assert_eq!(terminal["result"]["cleanup_complete"], true);
        }
        let disk = std::fs::read_to_string(
            tmp.path().join(
                completed[0].1["audit_path"]
                    .as_str()
                    .context("audit path")?,
            ),
        )?;
        let terminals = disk
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(
            terminals
                .iter()
                .filter(|event| event["type"] == "execution.finished")
                .count(),
            1
        );
        assert!(!disk.contains("retention-secret-canary"));
        assert!(peer_alive);
        assert_eq!(active["result"]["status"], "running");
        assert_eq!(peer_terminal["result"]["cleanup_complete"], true);
        assert!(!process_present(peer_pid)?);
        assert!(!audit.to_string().contains("retention-secret-canary"));
        let limits = &capabilities["result"]["limits"];
        assert_eq!(limits["completed_executions"], count_limit.parse::<u64>()?);
        assert_eq!(
            limits["completed_execution_bytes"],
            summary_bytes.parse::<u64>()?
        );
        assert_eq!(limits["audit_cache_bytes"], audit_bytes.parse::<u64>()?);
        let evicted = count_limit == "2" || summary_bytes == "65536";
        assert_eq!(summaries["result"]["truncated"], evicted, "{summaries}");
        if evicted {
            assert_eq!(
                oldest["error"]["data"]["code"], "EXECUTION_NOT_FOUND",
                "{oldest}"
            );
        } else {
            assert_eq!(oldest["result"]["status"], "finished");
        }
        let records = summaries["result"]["executions"]
            .as_array()
            .context("summaries")?;
        assert!(records.iter().any(|record| record["execution_id"] == peer));
        let last = &completed.last().context("last")?.0;
        assert!(records.iter().any(|record| record["execution_id"] == *last));
        if count_limit == "2" {
            assert_eq!(
                records.len(),
                3,
                "two completed records plus the active target"
            );
            assert_eq!(audit["result"]["truncated"], false);
        } else if audit_bytes == "65536" {
            assert_eq!(audit["result"]["truncated"], true);
        } else {
            assert_eq!(records.len(), 21);
            assert_eq!(audit["result"]["truncated"], false);
        }
    }
    Ok(())
}

#[test]
fn configured_chunks_refuse_one_extra_byte_and_preserve_binary_output_offsets() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut modes = vec![false];
    if cfg!(windows) {
        modes.push(true);
    }
    for control_enabled in modes {
        let mut client = Client::spawn_with_env_values(
            "service",
            &[
                ("RUNSEAL_STREAM_CHUNK_BYTES", std::ffi::OsStr::new("8192")),
                ("RUNSEAL_INPUT_PENDING_BYTES", std::ffi::OsStr::new("16384")),
            ],
        )?;
        client.send(0, "getCapabilities", json!({}))?;
        let capabilities = client.next(Duration::from_secs(2))?;
        let mut code = "import os,sys; os.write(1,('READY '+str(os.getpid())+'\\n').encode()); data=sys.stdin.buffer.read(); os.write(1,data*8); os.write(2,data[::-1]*8)".to_owned();
        if control_enabled {
            code.push_str("; data=bytearray()\nwhile True:\n chunk=os.read(3,65536)\n if not chunk: break\n data.extend(chunk)\nos.write(3,bytes(data)*8)");
        }
        let mut params = json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}});
        if control_enabled {
            params["io"] = json!({"mode":"pipe","control":{"mode":"pipe","child_fd":3}});
        }
        client.send(1, "execute", params)?;
        let receipt = client.next(Duration::from_secs(2))?;
        let execution = receipt["result"]["execution_id"]
            .as_str()
            .context("execution")?
            .to_owned();
        let pid = wait_ready_pid(&client, &execution)?;
        let payload: Vec<u8> = (0..8192).map(|index| (index % 256) as u8).collect();
        let mut rejected = Vec::new();
        let mut accepted = Vec::new();
        let mut request = 2;
        for stream in ["stdin", "control"]
            .into_iter()
            .take(if control_enabled { 2 } else { 1 })
        {
            client.send(request, "writeExecutionInput", json!({"execution_id":execution,"stream":stream,"encoding":"base64","data":format!("base64:{}",STANDARD.encode(vec![b'X';8193]))}))?;
            rejected.push(client.next(Duration::from_secs(2))?);
            request += 1;
            client.send(request, "writeExecutionInput", json!({"execution_id":execution,"stream":stream,"encoding":"base64","data":format!("base64:{}",STANDARD.encode(&payload))}))?;
            accepted.push(client.next(Duration::from_secs(2))?);
            request += 1;
        }
        // Close control first while the target is still waiting for stdin EOF.
        if control_enabled {
            client.send(
                request,
                "closeExecutionInput",
                json!({"execution_id":execution,"stream":"control"}),
            )?;
            let _ = client.next(Duration::from_secs(2))?;
            request += 1;
        }
        client.send(
            request,
            "closeExecutionInput",
            json!({"execution_id":execution,"stream":"stdin"}),
        )?;
        let mut outputs = [Vec::new(), Vec::new(), Vec::new()];
        let mut offsets = [format!("READY {pid}\n").len() as u64, 0, 0];
        let mut valid_chunks = true;
        let terminal = loop {
            let message = client.next(Duration::from_secs(10))?;
            let event = &message["params"];
            let stream = match event["type"].as_str() {
                Some("execution.stdout") => Some(0),
                Some("execution.stderr") => Some(1),
                Some("execution.control") => Some(2),
                _ => None,
            };
            if let Some(stream) = stream {
                let bytes = STANDARD.decode(
                    event["data"]
                        .as_str()
                        .context("data")?
                        .strip_prefix("base64:")
                        .context("base64")?,
                )?;
                valid_chunks &= bytes.len() <= 8192 && event["stream_offset"] == offsets[stream];
                offsets[stream] += bytes.len() as u64;
                outputs[stream].extend(bytes);
            }
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                break event.clone();
            }
        };
        drop(client);
        assert_eq!(capabilities["result"]["limits"]["stream_chunk_bytes"], 8192);
        assert_eq!(
            capabilities["result"]["limits"]["input_pending_bytes"],
            16384
        );
        for response in rejected {
            assert_eq!(
                response["error"]["data"]["code"], "INVALID_REQUEST",
                "{response}"
            );
        }
        for response in accepted {
            assert_eq!(response["result"]["accepted_bytes"], 8192, "{response}");
        }
        assert!(
            valid_chunks,
            "configured output chunks and contiguous offsets"
        );
        assert_eq!(outputs[0], payload.repeat(8));
        assert_eq!(
            outputs[1],
            payload.iter().rev().copied().collect::<Vec<_>>().repeat(8)
        );
        assert_eq!(
            outputs[2],
            if control_enabled {
                payload.repeat(8)
            } else {
                Vec::new()
            }
        );
        assert_eq!(terminal["type"], "execution.finished", "{terminal}");
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        assert!(!process_present(pid)?);
    }
    Ok(())
}

#[test]
fn configured_pending_budget_refuses_unread_input_then_drains_every_accepted_byte() -> Result<()> {
    let _guard = process_test_gate();
    for pending in ["8192", "262144"] {
        let tmp = TempDir::new()?;
        let mut client = Client::spawn_with_env_values(
            "service",
            &[
                ("RUNSEAL_STREAM_CHUNK_BYTES", std::ffi::OsStr::new("8192")),
                ("RUNSEAL_INPUT_PENDING_BYTES", std::ffi::OsStr::new(pending)),
            ],
        )?;
        client.send(1,"execute",json!({"command":[python()?,"-u","-c","import os,pathlib,sys,time; os.write(1,('READY '+str(os.getpid())+'\\n').encode())\nwhile not pathlib.Path('read-input').exists(): time.sleep(0.005)\ndata=sys.stdin.buffer.read(); os.write(1,data)"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}))?;
        let receipt = client.next(Duration::from_secs(2))?;
        let execution = receipt["result"]["execution_id"]
            .as_str()
            .context("execution")?
            .to_owned();
        let pid = wait_ready_pid(&client, &execution)?;
        let mut expected = Vec::new();
        let mut backpressure = None;
        for id in 2..18 {
            let data = vec![id as u8; 8192];
            client.send(id, "writeExecutionInput", json!({"execution_id":execution,"stream":"stdin","encoding":"base64","data":format!("base64:{}",STANDARD.encode(&data))}))?;
            let response = client.next(Duration::from_secs(2))?;
            if response["error"]["data"]["code"] == "INPUT_BACKPRESSURE" {
                backpressure = Some(response);
                break;
            }
            if response["result"]["accepted_bytes"] != 8192 {
                anyhow::bail!("input admission: {response}");
            }
            expected.extend(data);
        }
        std::fs::write(tmp.path().join("read-input"), b"G")?;
        client.send(
            20,
            "closeExecutionInput",
            json!({"execution_id":execution,"stream":"stdin"}),
        )?;
        let mut actual = Vec::new();
        let terminal = loop {
            let message = client.next(Duration::from_secs(10))?;
            let event = &message["params"];
            if event["type"] == "execution.stdout" {
                actual.extend(
                    STANDARD.decode(
                        event["data"]
                            .as_str()
                            .context("data")?
                            .strip_prefix("base64:")
                            .context("base64")?,
                    )?,
                );
            }
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                break event.clone();
            }
        };
        drop(client);
        assert_eq!(backpressure.is_some(), pending == "8192");
        assert!(!expected.is_empty());
        assert_eq!(
            actual, expected,
            "rejected requests contribute no bytes and close preserves all accepted writes"
        );
        assert_eq!(terminal["type"], "execution.finished");
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        assert!(!process_present(pid)?);
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn tiny_input_writes_preserve_binary_order_eof_and_backpressure_on_native_streams() -> Result<()> {
    let _guard = process_test_gate();
    for control in [false, true] {
        let tmp = TempDir::new()?;
        let mut client = Client::spawn_with_env_values(
            "service",
            &[
                ("RUNSEAL_STREAM_CHUNK_BYTES", std::ffi::OsStr::new("8192")),
                ("RUNSEAL_INPUT_PENDING_BYTES", std::ffi::OsStr::new("32768")),
            ],
        )?;
        let fd = if control { 3 } else { 0 };
        let out = if control { 3 } else { 1 };
        let code = format!(
            "import os,pathlib,time; os.write(1,('READY '+str(os.getpid())+'\\n').encode())\nwhile not pathlib.Path('read-input').exists(): time.sleep(.005)\ndata=bytearray()\nwhile True:\n chunk=os.read({fd},8192)\n if not chunk: break\n data.extend(chunk)\nposition=0\nwhile position<len(data): position+=os.write({out},data[position:])\nos.write(2,b'EOF'); raise SystemExit(7)"
        );
        let mut params = json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":"danger-full-access"});
        if control {
            params["io"] = json!({"mode":"pipe","control":{"mode":"pipe","child_fd":3}});
        } else {
            params["stdin"] = json!({"mode":"stream"});
        }
        client.send(1, "execute", params)?;
        let receipt = client.next(Duration::from_secs(2))?;
        let execution = receipt["result"]["execution_id"]
            .as_str()
            .context("execution")?
            .to_owned();
        let pid = wait_ready_pid(&client, &execution)?;
        let stream = if control { "control" } else { "stdin" };
        let canary = b"tiny-input-secret-canary";
        let mut prefix: Vec<u8> = (0..8192).map(|index| (index % 256) as u8).collect();
        prefix[..canary.len()].copy_from_slice(canary);
        let mut expected = Vec::new();
        let mut request = 2;
        for data in std::iter::once(prefix)
            .chain((0..512).map(|index| vec![(index % 256) as u8]))
            .chain(std::iter::once(vec![b'B'; 8192]))
        {
            client.send(request,"writeExecutionInput",json!({"execution_id":execution,"stream":stream,"encoding":"base64","data":format!("base64:{}",STANDARD.encode(&data))}))?;
            let response = client.next(Duration::from_secs(2))?;
            assert_eq!(
                response["result"]["accepted_bytes"],
                data.len(),
                "{response}"
            );
            expected.extend(data);
            request += 1;
        }
        let mut backpressure = None;
        for _ in 0..64 {
            let data = vec![request as u8; 8192];
            client.send(request,"writeExecutionInput",json!({"execution_id":execution,"stream":stream,"encoding":"base64","data":format!("base64:{}",STANDARD.encode(&data))}))?;
            let response = client.next(Duration::from_secs(2))?;
            request += 1;
            if response["error"]["data"]["code"] == "INPUT_BACKPRESSURE" {
                backpressure = Some(response);
                break;
            }
            assert_eq!(response["result"]["accepted_bytes"], 8192, "{response}");
            expected.extend(data);
        }
        let alive_before_release = process_present(pid)?;
        client.send(request, "getVersion", json!({}))?;
        let version = client.next(Duration::from_secs(2))?;
        request += 1;
        std::fs::write(tmp.path().join("read-input"), b"G")?;
        client.send(
            request,
            "closeExecutionInput",
            json!({"execution_id":execution,"stream":stream}),
        )?;
        let mut actual = Vec::new();
        let mut diagnostics = Vec::new();
        let terminal = loop {
            let message = client.next(Duration::from_secs(10))?;
            let event = &message["params"];
            if event["type"]
                == if control {
                    "execution.control"
                } else {
                    "execution.stdout"
                }
            {
                actual.extend(
                    STANDARD.decode(
                        event["data"]
                            .as_str()
                            .and_then(|text| text.strip_prefix("base64:"))
                            .context("output bytes")?,
                    )?,
                );
            } else if event["type"] == "execution.stderr" {
                diagnostics.extend(
                    STANDARD.decode(
                        event["data"]
                            .as_str()
                            .and_then(|text| text.strip_prefix("base64:"))
                            .context("diagnostic bytes")?,
                    )?,
                );
            }
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                break event.clone();
            }
        };
        let gone_before_fixture_cleanup = !process_present(pid)?;
        drop(client);
        assert!(alive_before_release && gone_before_fixture_cleanup);
        assert!(
            backpressure.is_some(),
            "unread native input must enforce its pending budget"
        );
        assert!(
            version["result"].is_object(),
            "control plane remains responsive: {version}"
        );
        assert_eq!(
            actual, expected,
            "coalescing may not lose, reorder, or deliver rejected bytes"
        );
        assert_eq!(diagnostics, b"EOF");
        assert_eq!(terminal["type"], "execution.finished", "{terminal}");
        assert_eq!(terminal["result"]["exit_code"], 7);
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        let mut durable = Vec::new();
        for entry in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
            let audit = std::fs::read_to_string(entry?.path())?;
            assert!(!audit.contains(std::str::from_utf8(canary)?));
            assert!(!audit.contains(&STANDARD.encode(canary)));
            for line in audit.lines() {
                let event: Value = serde_json::from_str(line)?;
                if matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ) {
                    durable.push(event);
                }
            }
        }
        assert_eq!(durable, vec![terminal]);
    }
    Ok(())
}

#[test]
fn configured_rpc_frame_boundary_drains_oversize_without_starting_target_or_stopping_peer()
-> Result<()> {
    let _guard = process_test_gate();
    for mode in ["rpc", "service"] {
        let tmp = TempDir::new()?;
        let mut client = Client::spawn_with_env_values(
            mode,
            &[("RUNSEAL_RPC_FRAME_BYTES", std::ffi::OsStr::new("131072"))],
        )?;
        let mut exact = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":1,"method":"getCapabilities","params":{}}),
        )?;
        exact.resize(131071, b' ');
        exact.push(b'\n');
        client.input.as_mut().context("stdin")?.write_all(&exact)?;
        client.input.as_mut().context("stdin")?.flush()?;
        let capabilities = client.next(Duration::from_secs(2))?;
        client.send(2, "execute", json!({"command":[python()?,"-u","-c","import os,sys; print('READY '+str(os.getpid()),flush=True); sys.stdin.buffer.read()"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}))?;
        let receipt = client.next(Duration::from_secs(2))?;
        let execution = receipt["result"]["execution_id"]
            .as_str()
            .context("execution")?
            .to_owned();
        let pid = wait_ready_pid(&client, &execution)?;
        let marker = tmp.path().join("oversized.ran");
        let mut oversized = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":3,"method":"execute","params":{"command":[python()?,"-c","import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('RAN')",marker],"cwd":tmp.path(),"policy":"danger-full-access"}}),
        )?;
        oversized.resize(131072, b' ');
        oversized.push(b'\n');
        client
            .input
            .as_mut()
            .context("stdin")?
            .write_all(&oversized)?;
        client.input.as_mut().context("stdin")?.flush()?;
        let refused = client.next(Duration::from_secs(2))?;
        client.send(4, "getVersion", json!({}))?;
        let version = loop {
            let message = client.next(Duration::from_secs(2))?;
            if message["id"] == 4 {
                break message;
            }
        };
        client.send(5, "getExecution", json!({"execution_id":execution}))?;
        let active = loop {
            let message = client.next(Duration::from_secs(2))?;
            if message["id"] == 5 {
                break message;
            }
        };
        let peer_alive = process_present(pid)?;
        client.send(6, "cancelExecution", json!({"execution_id":execution}))?;
        let terminal = loop {
            let message = client.next(Duration::from_secs(10))?;
            if message["params"]["execution_id"] == execution
                && message["params"]["type"] == "execution.failed"
            {
                break message["params"].clone();
            }
        };
        drop(client);
        assert_eq!(capabilities["result"]["limits"]["rpc_frame_bytes"], 131072);
        assert_eq!(
            capabilities["result"]["limits"]["query_response_bytes"],
            131072
        );
        assert_eq!(refused["error"]["code"], -32700, "{refused}");
        assert_eq!(refused["id"], Value::Null);
        assert_eq!(version["result"]["protocol_version"], "runseal.protocol/v2");
        assert_eq!(active["result"]["status"], "running");
        assert!(peer_alive);
        assert!(!marker.exists());
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        assert!(!process_present(pid)?);
    }
    Ok(())
}

#[test]
fn configured_frame_snapshot_retains_newest_records_and_keeps_connection_live() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    for frame_bytes in ["131072", "1048576"] {
        let mut client = Client::spawn_with_env_values(
            "service",
            &[("RUNSEAL_RPC_FRAME_BYTES", std::ffi::OsStr::new(frame_bytes))],
        )?;
        let mut terminals = Vec::new();
        for id in 1..21 {
            client.send(id,"execute",json!({"command":[python()?,"-u","-c","print('DONE',flush=True)"],"cwd":tmp.path(),"policy":"danger-full-access","metadata":{"note":"N".repeat(2048),"token":"frame-secret-canary"}}))?;
            let receipt = client.next(Duration::from_secs(2))?;
            let execution = receipt["result"]["execution_id"]
                .as_str()
                .context("execution")?
                .to_owned();
            loop {
                let message = client.next(Duration::from_secs(10))?;
                if message["params"]["execution_id"] == execution
                    && matches!(
                        message["params"]["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    )
                {
                    terminals.push(message["params"].clone());
                    break;
                }
            }
        }
        client.send(21, "tailAudit", json!({}))?;
        let audit = client.next(Duration::from_secs(2))?;
        client.send(22, "getVersion", json!({}))?;
        let version = client.next(Duration::from_secs(2))?;
        drop(client);
        assert_eq!(version["result"]["protocol_version"], "runseal.protocol/v2");
        for terminal in &terminals {
            assert_eq!(terminal["type"], "execution.finished");
            assert_eq!(terminal["result"]["cleanup_complete"], true);
        }
        let bound = frame_bytes.parse::<usize>()?.min(256 * 1024);
        assert!(serde_json::to_vec(&audit)?.len() < bound);
        assert_eq!(audit["result"]["truncated"], true);
        let events = audit["result"]["events"]
            .as_array()
            .context("audit events")?;
        assert!(!events.is_empty());
        let last = events.last().context("last event")?;
        assert_eq!(last["type"], "execution.finished");
        assert_eq!(
            last["execution_id"],
            terminals.last().context("last terminal")?["execution_id"]
        );
        assert!(!audit.to_string().contains("frame-secret-canary"));
    }
    Ok(())
}

#[test]
fn configured_outgoing_frame_counts_newline_and_cleans_live_target_on_unrecoverable_response()
-> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn_with_env_values(
        "service",
        &[("RUNSEAL_RPC_FRAME_BYTES", std::ffi::OsStr::new("131072"))],
    )?;
    client.send(1, "getVersion", json!({}))?;
    let mut template = client.next(Duration::from_secs(2))?;
    template["id"] = json!("");
    let overhead = serde_json::to_vec(&template)?.len();
    client.send(2,"execute",json!({"command":[python()?,"-u","-c","import os,sys; print('READY '+str(os.getpid()),flush=True); sys.stdin.buffer.read()"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}))?;
    let receipt = client.next(Duration::from_secs(2))?;
    let execution = receipt["result"]["execution_id"]
        .as_str()
        .context("execution")?
        .to_owned();
    let pid = wait_ready_pid(&client, &execution)?;
    let exact_id = "I".repeat(131072 - overhead - 1);
    let mut request = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":exact_id,"method":"getVersion","params":{}}),
    )?;
    request.push(b'\n');
    if request.len() > 131072 {
        anyhow::bail!("fixture request must fit the input frame");
    }
    client
        .input
        .as_mut()
        .context("stdin")?
        .write_all(&request)?;
    client.input.as_mut().context("stdin")?.flush()?;
    let exact_response = client.next(Duration::from_secs(2))?;
    let mut request = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":format!("{exact_id}I"),"method":"getVersion","params":{}}),
    )?;
    request.push(b'\n');
    if request.len() > 131072 {
        anyhow::bail!("fixture request must fit the input frame");
    }
    client
        .input
        .as_mut()
        .context("stdin")?
        .write_all(&request)?;
    client.input.as_mut().context("stdin")?.flush()?;
    let response = client.messages.recv_timeout(Duration::from_secs(12));
    let deadline = Instant::now() + Duration::from_secs(2);
    let finished = loop {
        if client.child.try_wait()?.is_some() {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let target_gone = !process_present(pid)?;
    drop(client);
    assert_eq!(exact_response["id"], exact_id);
    assert_eq!(serde_json::to_vec(&exact_response)?.len() + 1, 131072);
    assert!(
        matches!(response, Err(mpsc::RecvTimeoutError::Disconnected)),
        "oversized output must close rather than leak a frame or merely time out"
    );
    assert!(finished, "host must finish without fixture termination");
    assert!(target_gone, "target must stop before fixture cleanup");
    let mut terminals = Vec::new();
    for entry in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
        for line in std::fs::read_to_string(entry?.path())?.lines() {
            let event: Value = serde_json::from_str(line)?;
            if event["execution_id"] == execution
                && matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                )
            {
                terminals.push(event);
            }
        }
    }
    assert_eq!(terminals.len(), 1);
    assert_eq!(terminals[0]["result"]["cleanup_complete"], true);
    Ok(())
}

#[test]
fn configured_output_cap_matches_effective_policy_hash_and_real_execution_boundaries() -> Result<()>
{
    use sha2::{Digest, Sha256};
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let cases = [
        ("8192", None, 8192, 8192),
        ("8192", None, 8193, 8192),
        ("16384", None, 8193, 16384),
        ("16384", Some(4096), 4096, 4096),
        ("16384", Some(4096), 4097, 4096),
        ("8192", Some(32768), 8193, 8192),
        ("8192", Some(0), 0, 0),
    ];
    let mut named_hashes = Vec::new();
    for mode in ["rpc", "service"] {
        let mut observations = Vec::new();
        for (index, (deployment, requested, total, effective)) in cases.iter().enumerate() {
            let directory = TempDir::new_in(tmp.path())?;
            let mut client = Client::spawn_with_env_values(
                mode,
                &[("RUNSEAL_MAX_OUTPUT_BYTES", std::ffi::OsStr::new(deployment))],
            )?;
            let policy = requested.map_or_else(||json!("danger-full-access"),|value|json!({"version":"runseal.policy/v1","id":"danger-full-access","sandbox_level":"danger-full-access","resources":{"max_output_bytes":value}}));
            client.send(
                1,
                "explainPolicy",
                json!({"policy":policy,"cwd":directory.path()}),
            )?;
            let explanation = client.next(Duration::from_secs(2))?;
            client.send(2, "getCapabilities", json!({}))?;
            let capabilities = client.next(Duration::from_secs(2))?;
            client.send(3,"execute",json!({"command":[python()?,"-u","-c","import os,pathlib,sys,time; pathlib.Path('target.pid').write_text(str(os.getpid())); count=int(sys.argv[1]); limit=int(sys.argv[2]); first=min(count,8192); os.write(1,b'X'*first); os.write(2,b'E'*(count-first));\nif count>limit: time.sleep(120)\nsys.exit(7)",total.to_string(),effective.to_string()],"cwd":directory.path(),"policy":policy}))?;
            let receipt = client.next(Duration::from_secs(2))?;
            let execution = receipt["result"]["execution_id"]
                .as_str()
                .context("execution")?
                .to_owned();
            let mut events = Vec::new();
            let mut bytes = 0;
            let terminal = loop {
                let message = client.next(Duration::from_secs(10))?;
                let event = &message["params"];
                if event["execution_id"] != execution {
                    continue;
                }
                if matches!(
                    event["type"].as_str(),
                    Some("execution.stdout" | "execution.stderr")
                ) {
                    bytes += STANDARD
                        .decode(
                            event["data"]
                                .as_str()
                                .context("data")?
                                .strip_prefix("base64:")
                                .context("base64")?,
                        )?
                        .len();
                }
                events.push(event.clone());
                if matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ) {
                    break event.clone();
                }
            };
            let pid =
                std::fs::read_to_string(directory.path().join("target.pid"))?.parse::<u32>()?;
            let gone = !process_present(pid)?;
            drop(client);
            let audit = std::fs::read_to_string(
                directory
                    .path()
                    .join(terminal["audit_path"].as_str().context("audit path")?),
            )?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
            observations.push((
                index,
                *total,
                *effective,
                explanation,
                capabilities,
                receipt,
                events,
                bytes,
                terminal,
                audit,
                gone,
            ));
        }
        // Check actual target/output behavior before policy fields, so the baseline
        // must demonstrate enforcement failure rather than only a changed JSON field.
        for (index, total, effective, _, _, _, _, bytes, terminal, _, gone) in &observations {
            assert!(*gone, "case {index}: target process must be gone");
            assert_eq!(
                terminal["result"]["cleanup_complete"], true,
                "case {index} (output={total}, effective={effective}): {terminal}"
            );
            if total > effective {
                assert_eq!(terminal["type"], "execution.failed", "{terminal}");
                assert_eq!(terminal["result"]["error"]["code"], "OUTPUT_LIMIT_EXCEEDED");
                assert!(*bytes <= *effective);
                assert_eq!(terminal["result"]["output_truncated"], true);
            } else {
                assert_eq!(terminal["type"], "execution.finished", "{terminal}");
                assert_eq!(terminal["result"]["exit_code"], 7);
                assert_eq!(*bytes, *total);
            }
        }
        let mut hashes = Vec::new();
        for (
            index,
            _,
            effective,
            explanation,
            capabilities,
            receipt,
            events,
            _,
            terminal,
            audit,
            _,
        ) in observations
        {
            let explained = &explanation["result"];
            assert_eq!(explained["resources"]["max_output_bytes"], effective);
            assert_eq!(
                explained["canonical_policy"]["resources"]["max_output_bytes"],
                effective
            );
            assert_eq!(
                capabilities["result"]["limits"]["max_output_bytes"],
                cases[index].0.parse::<u64>()?
            );
            let hash = format!(
                "sha256:{:x}",
                Sha256::digest(explained["canonical_policy"].to_string().as_bytes())
            );
            assert_eq!(explained["policy_hash"], hash);
            assert_eq!(receipt["result"]["policy_hash"], hash);
            assert_eq!(terminal["result"]["policy_hash"], hash);
            for event in events.iter().chain(&audit) {
                assert_eq!(event["policy_hash"], hash);
                assert_eq!(event["policy_epoch"], hash);
            }
            assert_eq!(
                audit
                    .iter()
                    .filter(|event| matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    ))
                    .count(),
                1
            );
            hashes.push(hash);
        }
        assert_eq!(hashes[0], hashes[1]);
        assert_ne!(
            hashes[0], hashes[2],
            "different effective deployment caps must change the policy hash"
        );
        assert_eq!(
            hashes[3], hashes[4],
            "command output size does not change the policy"
        );
        assert_eq!(
            hashes[0], hashes[5],
            "request cannot loosen the deployment cap"
        );
        assert_ne!(hashes[0], hashes[6]);
        named_hashes.push(hashes);
    }
    assert_eq!(named_hashes[0], named_hashes[1]);
    Ok(())
}

#[test]
fn configured_output_cap_plain_cli_preserves_child_exit_or_reports_resource_failure() -> Result<()>
{
    let _guard = process_test_gate();
    for deployment in ["8192", "16384"] {
        let tmp = TempDir::new()?;
        let explained = Command::new(env!("CARGO_BIN_EXE_runseal"))
            .env("RUNSEAL_MAX_OUTPUT_BYTES", deployment)
            .args(["explain-policy", "--policy", "danger-full-access", "--cwd"])
            .arg(tmp.path())
            .output()?;
        let policy: Value = serde_json::from_slice(&explained.stdout)?;
        let output=Command::new(env!("CARGO_BIN_EXE_runseal")).env("RUNSEAL_MAX_OUTPUT_BYTES",deployment)
            .args(["exec","--policy","danger-full-access","--cwd"]).arg(tmp.path())
            .args(["--", &python()?, "-u","-c","import os,pathlib,sys; pathlib.Path('target.pid').write_text(str(os.getpid())); os.write(1,b'X'*8193); sys.exit(7)"]).output()?;
        let pid = std::fs::read_to_string(tmp.path().join("target.pid"))?.parse::<u32>()?;
        assert!(!process_present(pid)?);
        if deployment == "8192" {
            assert_eq!(output.status.code(), Some(125));
            assert!(output.stdout.len() <= 8192);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let observed_code = stderr
                .strip_prefix("[runseal:")
                .and_then(|message| message.split(']').next())
                .unwrap_or("none");
            assert!(
                stderr.starts_with("[runseal:OUTPUT_LIMIT_EXCEEDED]"),
                "deployment={deployment}, observed_code={observed_code}, stdout_bytes={}, stderr_bytes={}, outer_exit={:?}",
                output.stdout.len(),
                output.stderr.len(),
                output.status.code()
            );
        } else {
            assert_eq!(output.status.code(), Some(7));
            assert_eq!(output.stdout, vec![b'X'; 8193]);
            assert!(output.stderr.is_empty());
        }
        assert_eq!(
            policy["resources"]["max_output_bytes"],
            deployment.parse::<u64>()?
        );
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn configured_output_cap_counts_native_control_and_terminal_streams() -> Result<()> {
    let _guard = process_test_gate();
    for (pty, deployment, exceeded) in [
        (false, "8192", true),
        (false, "8193", false),
        (true, "1024", true),
        (true, "262144", false),
    ] {
        let tmp = TempDir::new()?;
        let mut client = Client::spawn_with_env_values(
            "service",
            &[("RUNSEAL_MAX_OUTPUT_BYTES", std::ffi::OsStr::new(deployment))],
        )?;
        let code = if pty {
            "import os,pathlib,sys; assert os.isatty(0) and os.isatty(1); pathlib.Path('target.pid').write_text(str(os.getpid())); os.write(1,b'X'*131072); sys.exit(7)"
        } else {
            "import os,pathlib,sys; pathlib.Path('target.pid').write_text(str(os.getpid())); os.write(1,b'X'*4096); os.write(2,b'E'*4096); os.write(3,b'C'); sys.exit(7)"
        };
        let io = if pty {
            json!({"mode":"pty","rows":24,"cols":80})
        } else {
            json!({"mode":"pipe","control":{"mode":"pipe","child_fd":3}})
        };
        client.send(1,"execute",json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"},"io":io}))?;
        let receipt = client.next(Duration::from_secs(2))?;
        let execution = receipt["result"]["execution_id"]
            .as_str()
            .context("execution")?
            .to_owned();
        let mut counts = [0usize; 4];
        let terminal = loop {
            let message = client.next(Duration::from_secs(10))?;
            let event = &message["params"];
            if event["execution_id"] != execution {
                continue;
            }
            let stream = match event["type"].as_str() {
                Some("execution.stdout") => Some(0),
                Some("execution.stderr") => Some(1),
                Some("execution.control") => Some(2),
                Some("execution.terminal") => Some(3),
                _ => None,
            };
            if let Some(stream) = stream {
                counts[stream] += STANDARD
                    .decode(
                        event["data"]
                            .as_str()
                            .context("data")?
                            .strip_prefix("base64:")
                            .context("base64")?,
                    )?
                    .len();
            }
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                break event.clone();
            }
        };
        let pid = std::fs::read_to_string(tmp.path().join("target.pid"))?.parse::<u32>()?;
        let gone = !process_present(pid)?;
        drop(client);
        assert!(gone, "target must stop before fixture cleanup");
        assert_eq!(terminal["result"]["cleanup_complete"], true, "{terminal}");
        assert!(counts.iter().sum::<usize>() <= deployment.parse::<usize>()?);
        if exceeded {
            assert_eq!(terminal["type"], "execution.failed", "{terminal}");
            assert_eq!(terminal["result"]["error"]["code"], "OUTPUT_LIMIT_EXCEEDED");
            assert_eq!(terminal["result"]["output_truncated"], true);
        } else {
            assert_eq!(terminal["type"], "execution.finished", "{terminal}");
            assert_eq!(terminal["result"]["exit_code"], 7);
            if pty {
                assert!(counts[3] > 1024);
                assert_eq!(counts[..3], [0, 0, 0]);
                assert_eq!(terminal["result"]["stderr_merged"], true);
            } else {
                assert_eq!(counts, [4096, 4096, 1, 0]);
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn configured_backpressure_grace_cleans_unread_rpc_output_and_keeps_idle_connection_live()
-> Result<()> {
    use std::io::Read;
    let _guard = process_test_gate();
    let mut hashes = Vec::new();
    for grace in [500, 8000] {
        let tmp = TempDir::new()?;
        let mut environment: std::collections::HashMap<String, String> = std::env::vars().collect();
        environment.insert("RUNSEAL_BACKPRESSURE_MS".into(), grace.to_string());
        let mut host = codex_windows_sandbox::LocalExecutionProcess::spawn(
            &[
                env!("CARGO_BIN_EXE_runseal").into(),
                "service".into(),
                "--stdio".into(),
            ],
            tmp.path(),
            &environment,
            true,
        )?;
        let mut input = host.stdin.take().context("protocol input")?;
        let output = host.stdout.take().context("protocol output")?;
        let errors = host.stderr.take().map(|mut errors| {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                errors.read_to_end(&mut bytes).map(|_| bytes)
            })
        });
        let (permit, reads) = mpsc::sync_channel::<()>(1);
        let (sender, messages) = mpsc::sync_channel::<Result<Value>>(1);
        let reader = std::thread::spawn(move || {
            let mut output = BufReader::new(output);
            while reads.recv().is_ok() {
                let mut line = String::new();
                let result = output
                    .read_line(&mut line)
                    .map_err(anyhow::Error::from)
                    .and_then(|count| {
                        anyhow::ensure!(count > 0, "protocol EOF");
                        Ok(serde_json::from_str(&line)?)
                    });
                if sender.send(result).is_err() {
                    break;
                }
            }
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes)
        });
        let next = || -> Result<Value> {
            permit.send(())?;
            messages
                .recv_timeout(Duration::from_secs(10))
                .context("protocol read watchdog")?
        };
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":1,"method":"getCapabilities"})
        )?;
        input.flush()?;
        let capabilities = next()?;
        if grace == 500 {
            // An idle writer has no outstanding bytes. Require a real response
            // after the configured interval, rather than expiring idle sessions.
            std::thread::sleep(Duration::from_millis(650));
            writeln!(
                input,
                "{}",
                json!({"jsonrpc":"2.0","id":2,"method":"getVersion"})
            )?;
            input.flush()?;
            let version = next()?;
            assert_eq!(version["id"], 2);
            assert!(version["result"].is_object());
        }
        let target = "import os,pathlib,time; pathlib.Path('target.pid').write_text(str(os.getpid())); print('READY',flush=True)\nwhile not pathlib.Path('burst.go').exists(): time.sleep(.005)\nn=0\nwhile n<16:\n data=b'X'*65536\n while data:\n  count=os.write(1,data); data=data[count:]\n n+=1; pathlib.Path('burst.count').write_text(str(n))\nwhile True: time.sleep(.01)";
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":3,"method":"execute","params":{"command":[python()?,"-u","-c",target],"cwd":tmp.path(),"policy":"danger-full-access"}})
        )?;
        input.flush()?;
        let receipt = next()?;
        let id = receipt["result"]["execution_id"]
            .as_str()
            .context("execution receipt")?
            .to_owned();
        let mut ready = Vec::new();
        while !ready.windows(5).any(|bytes| bytes == b"READY") {
            let message = next()?;
            if message["params"]["type"] == "execution.stdout" {
                ready.extend(
                    STANDARD.decode(
                        message["params"]["data"]
                            .as_str()
                            .and_then(|data| data.strip_prefix("base64:"))
                            .context("ready bytes")?,
                    )?,
                );
            }
        }
        let pid = std::fs::read_to_string(tmp.path().join("target.pid"))?.parse::<u32>()?;
        std::fs::write(tmp.path().join("burst.go"), b"G")?;
        // Retain both transport endpoints. Check actual native write progress
        // and target state while no protocol reads or transport EOF can occur.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut progress = 0;
        while Instant::now() < deadline && process_present(pid)? {
            progress = progress.max(
                std::fs::read_to_string(tmp.path().join("burst.count"))
                    .ok()
                    .and_then(|text| text.parse::<usize>().ok())
                    .unwrap_or(0),
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let gone_while_unread = !process_present(pid)?;
        if !gone_while_unread {
            writeln!(
                input,
                "{}",
                json!({"jsonrpc":"2.0","id":4,"method":"cancelExecution","params":{"execution_id":id}})
            )?;
            input.flush()?;
        }
        // Resume and release on failed implementations too, then join only this
        // fixture before assertions so the oracle cannot be supplied by Drop.
        drop(input);
        drop(permit);
        let deadline = Instant::now() + Duration::from_secs(10);
        while host.try_wait()?.is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let completed = host.try_wait()?.is_some();
        let exit = host.finish(Duration::from_secs(2))?;
        reader
            .join()
            .map_err(|_| anyhow::anyhow!("protocol reader panic"))??;
        let errors = errors
            .map(|reader| {
                reader
                    .join()
                    .map_err(|_| anyhow::anyhow!("error reader panic"))
            })
            .transpose()?
            .transpose()?
            .unwrap_or_default();
        assert!(completed, "host must stop before forced fixture cleanup");
        assert!(progress > 0, "native output progress required");
        assert_eq!(
            gone_while_unread,
            grace == 500,
            "grace {grace}, native writes {progress}"
        );
        assert_eq!(
            exit,
            if grace == 500 { 1 } else { 0 },
            "{}",
            String::from_utf8_lossy(&errors)
        );
        assert_eq!(capabilities["result"]["limits"]["backpressure_ms"], grace);
        let mut terminals = Vec::new();
        for entry in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
            for line in std::fs::read_to_string(entry?.path())?.lines() {
                let event: Value = serde_json::from_str(line)?;
                if matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ) {
                    terminals.push(event);
                }
            }
        }
        assert_eq!(terminals.len(), 1);
        let terminal = &terminals[0]["result"];
        assert_eq!(terminal["cleanup_complete"], true);
        assert_eq!(
            terminal["termination_reason"],
            if grace == 500 {
                "backpressure"
            } else {
                "cancelled"
            },
            "{terminal}"
        );
        assert_eq!(
            terminal["error"]["code"],
            if grace == 500 {
                "CLIENT_BACKPRESSURE"
            } else {
                "EXECUTION_CANCELLED"
            }
        );
        hashes.push(terminals[0]["policy_hash"].clone());
    }
    assert!(hashes[0].is_string());
    assert_eq!(hashes[0], hashes[1]);
    Ok(())
}

#[cfg(windows)]
#[test]
fn preparing_timeout_commits_before_blocked_native_receipt_and_never_launches_after_drain()
-> Result<()> {
    use std::io::Read;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let _guard = process_test_gate();
    for mode in ["rpc", "service"] {
        let tmp = TempDir::new()?;
        let mut environment: std::collections::HashMap<String, String> = std::env::vars().collect();
        environment.insert("RUNSEAL_BACKPRESSURE_MS".into(), "8000".into());
        let mut host = codex_windows_sandbox::LocalExecutionProcess::spawn(
            &[
                env!("CARGO_BIN_EXE_runseal").into(),
                mode.into(),
                "--stdio".into(),
            ],
            tmp.path(),
            &environment,
            true,
        )?;
        let mut input = host.stdin.take().context("protocol input")?;
        let output = host.stdout.take().context("protocol output")?;
        let output_handle = output.as_raw_handle();
        let errors = host.stderr.take().map(|mut errors| {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                errors.read_to_end(&mut bytes).map(|_| bytes)
            })
        });
        let (permit, reads) = mpsc::sync_channel::<()>(1);
        let (sender, messages) = mpsc::sync_channel::<Result<Value>>(1);
        let reader = std::thread::spawn(move || {
            let mut output = BufReader::new(output);
            while reads.recv().is_ok() {
                let mut line = String::new();
                let result = output
                    .read_line(&mut line)
                    .map_err(anyhow::Error::from)
                    .and_then(|count| {
                        anyhow::ensure!(count > 0, "protocol EOF");
                        Ok(serde_json::from_str(&line)?)
                    });
                if sender.send(result).is_err() {
                    break;
                }
            }
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes)
        });
        let next = || -> Result<Value> {
            permit.send(())?;
            messages
                .recv_timeout(Duration::from_secs(10))
                .context("protocol read watchdog")?
        };
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":1,"method":"execute","params":{
            "command":[python()?,"-u","-c","import os,sys; print('READY '+str(os.getpid()),flush=True); sys.stdin.buffer.read()"],
            "cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}})
        )?;
        input.flush()?;
        let peer_receipt = next()?;
        let peer = peer_receipt["result"]["execution_id"]
            .as_str()
            .context("peer receipt")?
            .to_owned();
        let mut ready = Vec::new();
        while !ready.contains(&b'\n') {
            let message = next()?;
            if message["params"]["execution_id"] == peer
                && message["params"]["type"] == "execution.stdout"
            {
                ready.extend(
                    STANDARD.decode(
                        message["params"]["data"]
                            .as_str()
                            .and_then(|data| data.strip_prefix("base64:"))
                            .context("peer ready bytes")?,
                    )?,
                );
            }
        }
        let peer_pid = std::str::from_utf8(&ready)?
            .trim()
            .strip_prefix("READY ")
            .context("peer ready PID")?
            .parse::<u32>()?;
        // This control response exceeds the real native pipe capacity. No read
        // permit follows until the execution's durable timeout is observed.
        let blocked_id = "R".repeat(256 * 1024);
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":blocked_id,"method":"getVersion"})
        )?;
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":3,"method":"execute","params":{
            "command":[python()?,"-c","import pathlib; pathlib.Path('must-not-run').write_text('ran')"],
            "cwd":tmp.path(),"policy":"danger-full-access","timeout_ms":100}})
        )?;
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":4,"method":"getVersion"})
        )?;
        input.flush()?;
        let watchdog = Instant::now() + Duration::from_secs(2);
        let mut available = 0u32;
        let mut terminal_before_drain = None;
        while Instant::now() < watchdog {
            anyhow::ensure!(
                unsafe {
                    PeekNamedPipe(
                        output_handle,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                } != 0,
                "native output observation"
            );
            let audit_root = tmp.path().join(".runseal/audit");
            if let Ok(entries) = std::fs::read_dir(audit_root) {
                for entry in entries {
                    if let Ok(audit) = std::fs::read_to_string(entry?.path()) {
                        for line in audit.lines() {
                            if let Ok(event) = serde_json::from_str::<Value>(line)
                                && event["execution_id"] != peer
                                && matches!(
                                    event["type"].as_str(),
                                    Some("execution.finished" | "execution.failed")
                                )
                            {
                                terminal_before_drain = Some(event);
                            }
                        }
                    }
                }
            }
            if terminal_before_drain.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let native_prefix_blocked = available > 0 && (available as usize) < blocked_id.len();
        let target_absent_before_drain = !tmp.path().join("must-not-run").exists();
        let peer_alive_before_drain = process_present(peer_pid)?;
        let host_alive_before_drain = host.try_wait()?.is_none();
        // Drain and clean this fixture even on an incorrect implementation.
        // The held receipt can no longer start its timed-out execution.
        let first = next()?;
        let mut target_receipt = None;
        let mut target_terminal = None;
        let mut control_response = None;
        let deadline = Instant::now() + Duration::from_secs(10);
        while target_receipt.is_none() || target_terminal.is_none() || control_response.is_none() {
            anyhow::ensure!(Instant::now() < deadline, "drain watchdog");
            let message = next()?;
            if message["id"] == 3 {
                target_receipt = Some(message.clone());
            }
            if message["id"] == 4 {
                control_response = Some(message.clone());
            }
            if message["params"]["execution_id"] != peer
                && matches!(
                    message["params"]["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                )
            {
                target_terminal = Some(message["params"].clone());
            }
        }
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":5,"method":"closeExecutionInput",
            "params":{"execution_id":peer,"stream":"stdin"}})
        )?;
        input.flush()?;
        let peer_terminal = loop {
            let message = next()?;
            if message["params"]["execution_id"] == peer
                && matches!(
                    message["params"]["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                )
            {
                break message["params"].clone();
            }
        };
        let peer_gone_before_cleanup = !process_present(peer_pid)?;
        let target_absent_after_drain = !tmp.path().join("must-not-run").exists();
        drop(input);
        drop(permit);
        let deadline = Instant::now() + Duration::from_secs(10);
        while host.try_wait()?.is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let completed = host.try_wait()?.is_some();
        let exit = host.finish(Duration::from_secs(2))?;
        reader
            .join()
            .map_err(|_| anyhow::anyhow!("protocol reader panic"))??;
        let errors = errors
            .map(|reader| {
                reader
                    .join()
                    .map_err(|_| anyhow::anyhow!("error reader panic"))
            })
            .transpose()?
            .transpose()?
            .unwrap_or_default();
        assert!(
            completed && host_alive_before_drain,
            "host must remain live until orderly EOF"
        );
        assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&errors));
        assert!(
            native_prefix_blocked,
            "actual partial native response must remain unread"
        );
        assert_eq!(first["id"], blocked_id);
        assert!(peer_alive_before_drain && peer_gone_before_cleanup);
        assert_eq!(peer_terminal["result"]["cleanup_complete"], true);
        assert_eq!(peer_terminal["result"]["termination_reason"], "exited");
        assert!(target_absent_before_drain && target_absent_after_drain);
        assert!(control_response.context("control response")?["result"].is_object());
        let receipt = target_receipt.context("target receipt")?;
        assert_eq!(receipt["result"]["status"], "preparing");
        let committed =
            terminal_before_drain.context("timeout must commit before native receipt drains")?;
        let delivered = target_terminal.context("target terminal")?;
        assert_eq!(committed, delivered);
        assert_eq!(committed["execution_id"], receipt["result"]["execution_id"]);
        assert_eq!(committed["result"]["termination_reason"], "timeout");
        assert_eq!(committed["result"]["error"]["code"], "EXECUTION_TIMEOUT");
        assert_eq!(committed["result"]["cleanup_complete"], true);
        assert!(committed["result"]["started_at"].is_null());
        assert!(committed["result"]["exit_code"].is_null());
        let audit = std::fs::read_to_string(
            tmp.path()
                .join(committed["audit_path"].as_str().context("audit path")?),
        )?;
        let records: Vec<Value> = audit
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(records.last(), Some(&committed));
        assert!(
            !records
                .iter()
                .any(|event| event["type"] == "execution.started")
        );
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
    Ok(())
}

#[cfg(windows)]
#[test]
fn configured_sender_budget_backpressures_real_output_without_blocking_cancel() -> Result<()> {
    use std::io::Read;
    let _guard = process_test_gate();
    let mut hashes = Vec::new();
    for budget in [5 * 1024 * 1024, 32 * 1024 * 1024] {
        let tmp = TempDir::new()?;
        let mut environment: std::collections::HashMap<String, String> = std::env::vars().collect();
        environment.insert("RUNSEAL_SENDER_BYTES".into(), budget.to_string());
        let mut host = codex_windows_sandbox::LocalExecutionProcess::spawn(
            &[
                env!("CARGO_BIN_EXE_runseal").into(),
                "service".into(),
                "--stdio".into(),
            ],
            tmp.path(),
            &environment,
            true,
        )?;
        let mut input = host.stdin.take().context("service input")?;
        let output = host.stdout.take().context("controlled output")?;
        let errors = host.stderr.take().map(|mut errors| {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                errors.read_to_end(&mut bytes).map(|_| bytes)
            })
        });
        let (permit, reads) = mpsc::sync_channel::<()>(1);
        let (sender, messages) = mpsc::sync_channel::<Result<Value>>(1);
        let reader = std::thread::spawn(move || {
            let mut output = BufReader::new(output);
            while reads.recv().is_ok() {
                let mut line = String::new();
                let result = output
                    .read_line(&mut line)
                    .map_err(anyhow::Error::from)
                    .and_then(|count| {
                        anyhow::ensure!(count > 0, "protocol EOF");
                        Ok(serde_json::from_str(&line)?)
                    });
                if sender.send(result).is_err() {
                    break;
                }
            }
            let mut remaining = Vec::new();
            output.read_to_end(&mut remaining)
        });
        let next = || -> Result<Value> {
            permit.send(())?;
            messages
                .recv_timeout(Duration::from_secs(10))
                .context("controlled sender reader")?
        };
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":1,"method":"getCapabilities"})
        )?;
        input.flush()?;
        let capabilities = next()?;
        let target = "import os,pathlib,time; pathlib.Path('target.pid').write_text(str(os.getpid())); print('READY',flush=True)\nwhile not pathlib.Path('burst.go').exists(): time.sleep(.005)\nfor n in range(100):\n data=b'X'*65536\n while data:\n  count=os.write(1,data); data=data[count:]\n pathlib.Path('burst.count').write_text(str(n+1))\npathlib.Path('burst.done').write_text('done')\nwhile True: time.sleep(.01)";
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":2,"method":"execute","params":{"command":[python()?,"-u","-c",target],"cwd":tmp.path(),"policy":"danger-full-access"}})
        )?;
        input.flush()?;
        let receipt = next()?;
        let id = receipt["result"]["execution_id"]
            .as_str()
            .context("execution receipt")?
            .to_owned();
        let mut ready = Vec::new();
        while !ready.windows(5).any(|bytes| bytes == b"READY") {
            let message = next()?;
            if message["params"]["type"] == "execution.stdout" {
                ready.extend(
                    STANDARD.decode(
                        message["params"]["data"]
                            .as_str()
                            .and_then(|data| data.strip_prefix("base64:"))
                            .context("ready bytes")?,
                    )?,
                );
            }
        }
        let target_pid = std::fs::read_to_string(tmp.path().join("target.pid"))?.parse::<u32>()?;
        std::fs::write(tmp.path().join("burst.go"), b"G")?;
        // Keep the protocol pipe open, with no reader permits. Native producer
        // write acknowledgements establish progress and then actual backpressure.
        let observation_window = if budget == 32 * 1024 * 1024 {
            Duration::from_secs(10)
        } else {
            Duration::from_secs(2)
        };
        let deadline = Instant::now() + observation_window;
        let mut progress = 0;
        let mut unchanged = Instant::now();
        while Instant::now() < deadline && !tmp.path().join("burst.done").exists() {
            let count = std::fs::read_to_string(tmp.path().join("burst.count"))
                .ok()
                .and_then(|text| text.parse::<usize>().ok())
                .unwrap_or(0);
            if count > progress {
                progress = count;
                unchanged = Instant::now();
            }
            if budget == 5 * 1024 * 1024
                && progress > 0
                && unchanged.elapsed() >= Duration::from_millis(200)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let completed_burst = tmp.path().join("burst.done").exists();
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":3,"method":"cancelExecution","params":{"execution_id":id}})
        )?;
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":4,"method":"getVersion"})
        )?;
        input.flush()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while process_present(target_pid)? && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let stopped_while_unread = !process_present(target_pid)?;
        // Resume even for a failed candidate, then clean only this fixture before
        // assertions. No state/binding change is used to make admission succeed.
        let mut terminal = None;
        let mut cancelled = false;
        let mut version = false;
        while terminal.is_none() || !cancelled || !version {
            let message = next()?;
            cancelled |= message["id"] == 3 && message["result"]["status"] == "canceling";
            version |= message["id"] == 4 && message["result"].is_object();
            if matches!(
                message["params"]["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                terminal = Some(message["params"].clone());
            }
        }
        drop(input);
        drop(permit);
        let deadline = Instant::now() + Duration::from_secs(5);
        while host.try_wait()?.is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let finished = host.try_wait()?.is_some();
        let exit = host.finish(Duration::from_secs(2))?;
        reader
            .join()
            .map_err(|_| anyhow::anyhow!("controlled reader panic"))??;
        let errors = errors
            .map(|reader| {
                reader
                    .join()
                    .map_err(|_| anyhow::anyhow!("error reader panic"))
            })
            .transpose()?
            .transpose()?
            .unwrap_or_default();
        assert!(
            finished && exit == 0,
            "host cleanup: {exit} {}",
            String::from_utf8_lossy(&errors)
        );
        assert_eq!(
            completed_burst,
            budget == 32 * 1024 * 1024,
            "actual burst progress {progress}, budget {budget}"
        );
        assert!(progress > 0, "actual native write progress required");
        assert!(
            stopped_while_unread,
            "cancel must terminate target before reader resumes"
        );
        assert_eq!(capabilities["result"]["limits"]["sender_bytes"], budget);
        let terminal = terminal.context("terminal")?;
        assert_eq!(
            terminal["result"]["termination_reason"], "cancelled",
            "{terminal}"
        );
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        hashes.push(terminal["policy_hash"].clone());
        let mut durable = Vec::new();
        for entry in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
            for line in std::fs::read_to_string(entry?.path())?.lines() {
                let event: Value = serde_json::from_str(line)?;
                if matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ) {
                    durable.push(event);
                }
            }
        }
        assert_eq!(durable.len(), 1);
        assert_eq!(durable[0], terminal);
    }
    assert!(hashes[0].is_string());
    assert_eq!(
        hashes[0], hashes[1],
        "sender budget cannot change execution policy"
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn cli_console_cancellation_cleans_range_and_preserves_peer_in_each_output_mode() -> Result<()> {
    use std::io::Read;
    let _guard = process_test_gate();
    let driver_code = r#"
import base64,ctypes,json,pathlib,subprocess,sys,time
from ctypes import wintypes as w
k=ctypes.WinDLL('kernel32',use_last_error=True)
k.GenerateConsoleCtrlEvent.argtypes=[w.DWORD,w.DWORD]; k.GenerateConsoleCtrlEvent.restype=w.BOOL
k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD]; k.OpenProcess.restype=w.HANDLE
k.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD]; k.WaitForSingleObject.restype=w.DWORD
k.GetExitCodeProcess.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)]; k.GetExitCodeProcess.restype=w.BOOL
k.CloseHandle.argtypes=[w.HANDLE]; k.CloseHandle.restype=w.BOOL
HANDLER=ctypes.WINFUNCTYPE(w.BOOL,w.DWORD)
@HANDLER
def ignore_driver_control(event): return event in (0,1)
k.SetConsoleCtrlHandler.argtypes=[HANDLER,w.BOOL]; k.SetConsoleCtrlHandler.restype=w.BOOL
assert k.SetConsoleCtrlHandler(ignore_driver_control,True)
mode,event=sys.argv[1],int(sys.argv[2]); command=sys.argv[3:]
flags=subprocess.CREATE_NEW_PROCESS_GROUP if event==1 else 0
handles=[]; host=None; peer=None
def until(check,seconds=10):
    end=time.monotonic()+seconds
    while not check():
        if time.monotonic()>=end: raise RuntimeError('fixture readiness watchdog')
        time.sleep(.005)
def open_pid(path):
    pid=int(pathlib.Path(path).read_text()); handle=k.OpenProcess(0x100000|0x1000,False,pid)
    assert handle,ctypes.get_last_error(); handles.append(handle); return handle
try:
    peer=subprocess.Popen([sys.executable,'-u','-c',"import pathlib,time\np=pathlib.Path('peer.beat'); n=0\nwhile True:\n n+=1; p.write_text(str(n)); time.sleep(.01)"],creationflags=subprocess.CREATE_NO_WINDOW,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    with open('host.stdout','wb') as out,open('host.stderr','wb') as err:
        host=subprocess.Popen(command,creationflags=flags,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
        until(lambda: pathlib.Path('target.pid').exists() and pathlib.Path('descendant.pid').exists() and pathlib.Path('descendant.beat').exists() and pathlib.Path('peer.beat').exists())
        root=open_pid('target.pid'); descendant=open_pid('descendant.pid')
        assert k.WaitForSingleObject(root,0)==258 and k.WaitForSingleObject(descendant,0)==258
        generated=bool(k.GenerateConsoleCtrlEvent(event,host.pid if event==1 else 0))
        assert generated,ctypes.get_last_error()
        repeated=bool(k.GenerateConsoleCtrlEvent(event,host.pid if event==1 else 0))
        assert repeated,ctypes.get_last_error()
        outer=host.wait(10)
        gone=[k.WaitForSingleObject(handle,0)==0 for handle in (root,descendant)]
        codes=[]
        for handle,stopped in zip((root,descendant),gone):
            code=w.DWORD(); codes.append(code.value if stopped and k.GetExitCodeProcess(handle,ctypes.byref(code)) else None)
        before=pathlib.Path('peer.beat').read_text()
        until(lambda: pathlib.Path('peer.beat').read_text() not in ('',before),2)
        peer_alive=peer.poll() is None
    pathlib.Path('driver.result').write_text(json.dumps(dict(mode=mode,event=event,outer=outer,range_gone=gone,native_codes=codes,peer_alive=peer_alive,stdout=base64.b64encode(pathlib.Path('host.stdout').read_bytes()).decode(),stderr=base64.b64encode(pathlib.Path('host.stderr').read_bytes()).decode())))
finally:
    if host is not None and host.poll() is None: host.kill(); host.wait(2)
    if peer is not None and peer.poll() is None: peer.terminate(); peer.wait(2)
    for handle in handles: k.CloseHandle(handle)
"#;
    let target_code = r#"import os,pathlib,subprocess,sys,time
pathlib.Path('target.pid').write_text(str(os.getpid()))
child="import os,pathlib,time\npathlib.Path('descendant.pid').write_text(str(os.getpid()))\np=pathlib.Path('descendant.beat'); n=0\nwhile True:\n n+=1; p.write_text(str(n)); time.sleep(.01)"
subprocess.Popen([sys.executable,'-u','-c',child])
while True: time.sleep(.01)
"#;
    for mode in ["plain", "json", "events"] {
        for event in [0, 1] {
            let tmp = TempDir::new()?;
            let mut command = vec![
                python()?,
                "-u".into(),
                "-c".into(),
                driver_code.into(),
                mode.into(),
                event.to_string(),
                env!("CARGO_BIN_EXE_runseal").into(),
                "exec".into(),
            ];
            if mode != "plain" {
                command.push(format!("--{mode}"));
            }
            command.extend([
                "--policy".into(),
                "danger-full-access".into(),
                "--cwd".into(),
                tmp.path().to_string_lossy().into_owned(),
                "--".into(),
                python()?,
                "-u".into(),
                "-c".into(),
                target_code.into(),
            ]);
            let mut driver = codex_windows_sandbox::LocalExecutionProcess::spawn_with_terminal(
                &command,
                tmp.path(),
                &std::env::vars().collect(),
                true,
                Some((24, 80)),
            )?;
            let mut output = driver.stdout.take().context("isolated console output")?;
            let reader = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                output.read_to_end(&mut bytes).map(|_| bytes)
            });
            let errors = driver.stderr.take().map(|mut errors| {
                std::thread::spawn(move || {
                    let mut bytes = Vec::new();
                    errors.read_to_end(&mut bytes).map(|_| bytes)
                })
            });
            let deadline = Instant::now() + Duration::from_secs(20);
            while driver.try_wait()?.is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let completed = driver.try_wait()?.is_some();
            let exit = driver.finish(Duration::from_secs(2))?;
            drop(driver.stdin.take());
            if let Some(close) = driver.close_terminal() {
                close
                    .join()
                    .map_err(|_| anyhow::anyhow!("fixture console close panic"))??;
            }
            let diagnostics = reader
                .join()
                .map_err(|_| anyhow::anyhow!("fixture reader panic"))??;
            let errors = errors
                .map(|errors| {
                    errors
                        .join()
                        .map_err(|_| anyhow::anyhow!("fixture error reader panic"))
                })
                .transpose()?
                .transpose()?
                .unwrap_or_default();
            assert!(completed, "isolated console fixture watchdog");
            assert_eq!(
                exit,
                0,
                "mode={mode}, event={event}: {} {}",
                String::from_utf8_lossy(&diagnostics),
                String::from_utf8_lossy(&errors)
            );
            let result: Value =
                serde_json::from_str(&std::fs::read_to_string(tmp.path().join("driver.result"))?)?;
            assert_eq!(result["outer"], 130, "mode={mode}, event={event}: {result}");
            assert_eq!(result["range_gone"], json!([true, true]), "{result}");
            assert_eq!(result["peer_alive"], true);
            let stdout = STANDARD.decode(result["stdout"].as_str().context("stdout")?)?;
            let stderr = STANDARD.decode(result["stderr"].as_str().context("stderr")?)?;
            if mode == "plain" {
                assert!(stdout.is_empty());
                assert!(
                    stderr.starts_with(b"[runseal:EXECUTION_CANCELLED]"),
                    "mode={mode}, event={event}: {result}, stderr={:?}",
                    String::from_utf8_lossy(&stderr)
                );
            } else if mode == "json" {
                assert!(stderr.is_empty());
                let error: Value = serde_json::from_slice(&stdout)?;
                assert_eq!(
                    error["error"]["data"]["code"], "EXECUTION_CANCELLED",
                    "{error}"
                );
            } else {
                assert!(stderr.is_empty());
                let frames: Vec<Value> = String::from_utf8(stdout)?
                    .lines()
                    .map(serde_json::from_str)
                    .collect::<std::result::Result<_, _>>()?;
                assert!(frames.iter().all(|frame| frame["type"].is_string()));
                assert_eq!(
                    frames
                        .iter()
                        .filter(|frame| matches!(
                            frame["type"].as_str(),
                            Some("execution.finished" | "execution.failed")
                        ))
                        .count(),
                    1
                );
            }
            let mut terminals = Vec::new();
            for entry in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
                for line in std::fs::read_to_string(entry?.path())?.lines() {
                    let frame: Value = serde_json::from_str(line)?;
                    if matches!(
                        frame["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    ) {
                        terminals.push(frame);
                    }
                }
            }
            assert_eq!(terminals.len(), 1, "{terminals:?}");
            let terminal = &terminals[0]["result"];
            assert_eq!(terminal["termination_reason"], "cancelled");
            assert_eq!(terminal["cleanup_complete"], true);
            assert_eq!(terminal["error"]["code"], "EXECUTION_CANCELLED");
            assert_eq!(terminal["exit_code"], result["native_codes"][0]);
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn partial_cli_json_delivery_does_not_retry_or_append_an_error_frame() -> Result<()> {
    use std::io::Read;
    let _guard = process_test_gate();
    for grace in [5000, 500] {
        let tmp = TempDir::new()?;
        let command=vec![
        env!("CARGO_BIN_EXE_runseal").into(),"exec".into(),"--json".into(),
        "--policy".into(),"danger-full-access".into(),"--cwd".into(),tmp.path().to_string_lossy().into_owned(),
        "--".into(),python()?,"-u".into(),"-c".into(),
        "import os,pathlib,sys; pathlib.Path('target.pid').write_text(str(os.getpid())); os.write(1,b'X'*2097152); sys.exit(7)".into(),
    ];
        let mut environment: std::collections::HashMap<String, String> = std::env::vars().collect();
        environment.insert("RUNSEAL_BACKPRESSURE_MS".into(), grace.to_string());
        let mut host = codex_windows_sandbox::LocalExecutionProcess::spawn(
            &command,
            tmp.path(),
            &environment,
            false,
        )?;
        let mut stdout = host.stdout.take().context("stdout")?;
        let mut stderr = host.stderr.take().context("stderr")?;
        // Reading the prefix proves that the target result exists and final delivery
        // has actually begun. Keep the caller's read end open but unread afterward.
        let (sender, receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut prefix = vec![0; 4096];
            let result = stdout.read_exact(&mut prefix).map(|()| prefix);
            let _ = sender.send((stdout, result));
        });
        let (mut stdout, prefix) = receiver
            .recv_timeout(Duration::from_secs(10))
            .context("JSON delivery readiness")?;
        reader
            .join()
            .map_err(|_| anyhow::anyhow!("prefix reader panicked"))?;
        let prefix = prefix?;
        let target_pid = std::fs::read_to_string(tmp.path().join("target.pid"))?.parse::<u32>()?;
        let target_gone = !process_present(target_pid)?;
        let deadline = Instant::now() + Duration::from_millis(grace + 1500);
        let stopped_while_unread = loop {
            if host.try_wait()?.is_some() {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        // Release the fixture reader even on a broken implementation, then wait for
        // its own host before assertions. This cannot mask the observed stalled state.
        let mut bytes = prefix;
        stdout.read_to_end(&mut bytes)?;
        let mut diagnostics = Vec::new();
        stderr.read_to_end(&mut diagnostics)?;
        let exit = host.finish(Duration::from_secs(10))?;
        assert!(
            target_gone,
            "native target must already be gone at final JSON delivery"
        );
        assert!(
            stopped_while_unread,
            "a failed result write must stop within its configured grace {grace}"
        );
        assert_eq!(exit, 125);
        assert!(bytes.starts_with(b"{"));
        assert!(
            serde_json::from_slice::<Value>(&bytes).is_err(),
            "a partial result must not look complete"
        );
        assert!(
            !bytes
                .windows(b"{\"error\":".len())
                .any(|window| window == b"{\"error\":"),
            "no appended error object"
        );
        assert!(
            diagnostics.is_empty(),
            "unexpected diagnostics: {}",
            String::from_utf8_lossy(&diagnostics)
        );
        let mut terminals = Vec::new();
        for entry in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
            for line in std::fs::read_to_string(entry?.path())?.lines() {
                let event: Value = serde_json::from_str(line)?;
                if matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ) {
                    terminals.push(event);
                }
            }
        }
        assert_eq!(
            terminals.len(),
            1,
            "delivery failure cannot rewrite the immutable execution terminal"
        );
        assert_eq!(terminals[0]["result"]["exit_code"], 7);
        assert_eq!(terminals[0]["result"]["cleanup_complete"], true);
    }
    Ok(())
}

#[test]
fn invalid_deployment_limit_is_rejected_without_target_or_config_value_disclosure() -> Result<()> {
    let tmp = TempDir::new()?;
    let marker = tmp.path().join("target.ran");
    for (name, values) in [
        (
            "RUNSEAL_MAX_ACTIVE_EXECUTIONS",
            vec!["", "0", "65", "-1", "1.5", "secret-limit-canary"],
        ),
        (
            "RUNSEAL_MAX_OUTPUT_BYTES",
            vec!["", "0", "16777217", "-1", "1.5", "secret-limit-canary"],
        ),
        (
            "RUNSEAL_SENDER_BYTES",
            vec![
                "",
                "5242879",
                "67108865",
                "-1",
                "1.5",
                "secret-limit-canary",
            ],
        ),
        (
            "RUNSEAL_CLEANUP_TIMEOUT_MS",
            vec!["", "99", "60001", "-1", "1.5", "secret-limit-canary"],
        ),
        (
            "RUNSEAL_BACKPRESSURE_MS",
            vec!["", "99", "60001", "-1", "1.5", "secret-limit-canary"],
        ),
        (
            "RUNSEAL_RPC_FRAME_BYTES",
            vec!["", "131071", "1048577", "-1", "1.5", "secret-limit-canary"],
        ),
        (
            "RUNSEAL_STREAM_CHUNK_BYTES",
            vec!["", "8191", "65537", "-1", "1.5", "secret-limit-canary"],
        ),
        (
            "RUNSEAL_INPUT_PENDING_BYTES",
            vec![
                "",
                "8191",
                "16777217",
                "-1",
                "1.5",
                "secret-limit-canary",
                "8192",
            ],
        ),
        (
            "RUNSEAL_COMPLETED_EXECUTIONS",
            vec!["", "0", "65537", "-1", "1.5", "secret-limit-canary"],
        ),
        (
            "RUNSEAL_COMPLETED_EXECUTION_BYTES",
            vec!["", "65535", "268435457", "-1", "1.5", "secret-limit-canary"],
        ),
        (
            "RUNSEAL_AUDIT_CACHE_BYTES",
            vec!["", "65535", "268435457", "-1", "1.5", "secret-limit-canary"],
        ),
        (
            "RUNSEAL_REPLAY_EXECUTION_BYTES",
            vec!["", "65535", "67108865", "-1", "1.5", "secret-limit-canary"],
        ),
        (
            "RUNSEAL_REPLAY_CONNECTION_BYTES",
            vec![
                "",
                "65535",
                "268435457",
                "-1",
                "1.5",
                "secret-limit-canary",
                "65536",
            ],
        ),
    ] {
        for value in values {
            for structured in [false, true] {
                let mut command = Command::new(env!("CARGO_BIN_EXE_runseal"));
                command.env(name, value).arg("exec");
                if structured {
                    command.arg("--json");
                }
                let output = command
                    .args(["--policy", "danger-full-access", "--"])
                    .arg(python()?)
                    .args([
                        "-c",
                        "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('RAN')",
                    ])
                    .arg(&marker)
                    .output()?;
                assert_eq!(output.status.code(), Some(125));
                if structured {
                    let payload: Value = serde_json::from_slice(&output.stdout)?;
                    assert_eq!(payload["error"]["data"]["code"], "INVALID_REQUEST");
                    assert!(output.stderr.is_empty());
                } else {
                    assert!(output.stdout.is_empty());
                    assert!(
                        String::from_utf8_lossy(&output.stderr)
                            .starts_with("[runseal:INVALID_REQUEST]")
                    );
                }
                assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-limit-canary"));
                assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-limit-canary"));
                assert!(!marker.exists());
            }
        }
    }
    Ok(())
}

struct Client {
    child: Child,
    input: Option<ChildStdin>,
    messages: Receiver<Result<Value>>,
}

impl Client {
    fn spawn(mode: &str) -> Result<Self> {
        Self::spawn_with_env(mode, &[])
    }
    fn spawn_with_env(mode: &str, overrides: &[(&str, &std::path::Path)]) -> Result<Self> {
        let values: Vec<_> = overrides
            .iter()
            .map(|(key, path)| (*key, path.as_os_str()))
            .collect();
        Self::spawn_with_env_values(mode, &values)
    }
    fn spawn_with_env_values(mode: &str, overrides: &[(&str, &std::ffi::OsStr)]) -> Result<Self> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_runseal"));
        for (key, value) in overrides {
            command.env(key, value);
        }
        let mut child = command
            .args([mode, "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().context("protocol stdin")?;
        let output = child.stdout.take().context("protocol stdout")?;
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
        let input = self.input.as_mut().context("protocol input closed")?;
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
            .context("protocol message watchdog")?
    }
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn sandboxed_workspace_cannot_cover_protected_execution_state() -> Result<()> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};
    let _guard = process_test_gate();
    let mut pointer = std::ptr::null_mut();
    let status = unsafe {
        SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut pointer)
    };
    assert!(
        status >= 0 && !pointer.is_null(),
        "native common data directory required"
    );
    let mut length = 0;
    while length < 32768 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    assert!(length < 32768);
    let root = std::path::PathBuf::from(unsafe {
        OsString::from_wide(std::slice::from_raw_parts(pointer, length))
    });
    unsafe {
        windows_sys::Win32::System::Com::CoTaskMemFree(pointer.cast());
    }
    let root = root.join("RunSeal/execution-gates");
    assert!(root.is_absolute());
    std::fs::create_dir_all(&root)?;
    let probe = TempDir::new_in(&root)?;
    assert!(probe.path().starts_with(&root));
    let target = probe.path().join("owned-probe");
    std::fs::write(&target, b"unchanged")?;
    let mut client = Client::spawn("service")?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c","import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'changed'); pathlib.Path('command.ran').write_text('ran')",target],"cwd":probe.path(),"policy":"workspace-write"}))?;
    let rejected = client.next(Duration::from_secs(2))?;
    assert_eq!(
        rejected["error"]["data"]["code"], "BACKEND_CAPABILITY_MISSING",
        "{rejected}"
    );
    assert!(rejected.get("result").is_none());
    assert_eq!(std::fs::read(&target)?, b"unchanged");
    assert!(!probe.path().join("command.ran").exists());
    assert!(!probe.path().join(".runseal").exists());
    client.send(2, "listExecutions", json!({}))?;
    let listed = client.next(Duration::from_secs(2))?;
    assert_eq!(listed["result"]["executions"], json!([]));
    let parent = root.parent().context("state parent")?;
    let marker = parent.join(format!(
        "owned-probe-{}",
        probe
            .path()
            .file_name()
            .context("probe name")?
            .to_string_lossy()
    ));
    client.send(3,"execute",json!({"command":[python()?,"-u","-c","import os,pathlib,sys\ntry: pathlib.Path(sys.argv[1]).write_bytes(b'changed')\nexcept PermissionError: os.write(1,b'DENIED')\nelse: os.write(1,b'WRITABLE')\npathlib.Path(sys.argv[2]).write_text('ran')",target,marker],"cwd":parent,"policy":"workspace-write"}))?;
    let receipt = client.next(Duration::from_secs(2))?;
    assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    let terminal = loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        if message["params"]["type"] == "execution.stdout" {
            output.extend(
                STANDARD.decode(
                    message["params"]["data"]
                        .as_str()
                        .context("bytes")?
                        .strip_prefix("base64:")
                        .context("encoding")?,
                )?,
            );
        }
        if matches!(
            message["params"]["type"].as_str(),
            Some("execution.finished" | "execution.failed")
        ) {
            break message["params"].clone();
        }
    };
    assert_eq!(terminal["result"]["exit_code"], 0, "{terminal}");
    assert_eq!(terminal["result"]["cleanup_complete"], true);
    assert_eq!(output, b"DENIED");
    assert_eq!(std::fs::read(&target)?, b"unchanged");
    assert_eq!(std::fs::read_to_string(&marker)?, "ran");
    std::fs::remove_file(marker)?;
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn cross_process_policy_gate_survives_caller_appdata_override_and_accepts_after_drain() -> Result<()>
{
    let _guard = process_test_gate();
    let first = TempDir::new()?;
    let second = TempDir::new()?;
    let alternate_appdata = TempDir::new()?;
    let mut owner = Client::spawn("service")?;
    owner.send(1,"execute",json!({"command":[python()?,"-u","-c","import os,pathlib,time; print('READY '+str(os.getpid()),flush=True); count=0\nwhile True:\n count+=1; pathlib.Path('gate-peer.beat').write_text(str(count)); time.sleep(0.01)"],"cwd":first.path(),"policy":"workspace-write"}))?;
    let receipt = owner.next(Duration::from_secs(2))?;
    let id = receipt["result"]["execution_id"]
        .as_str()
        .context("owner ID")?
        .to_owned();
    let pid = wait_ready_pid(&owner, &id)?;
    let _fixture = HeartbeatFixture {
        directory: first.path().to_owned(),
        pids: vec![pid],
    };
    let request = json!({"command":[python()?,"-u","-c","import pathlib,sys; pathlib.Path('gate-command.ran').write_text('ran'); sys.exit(7)"],"cwd":second.path(),"policy":"workspace-write"});
    owner.send(2, "execute", request.clone())?;
    let rejected = owner.next(Duration::from_secs(2))?;
    assert_eq!(
        rejected["error"]["data"]["code"], "POLICY_TRANSITION_BUSY",
        "{rejected}"
    );
    let home = std::env::var_os("RUNSEAL_WINDOWS_SANDBOX_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default())
                .join("RunSeal/windows-sandbox")
        });
    let home_alias = std::path::PathBuf::from(home.to_string_lossy().to_ascii_uppercase());
    assert!(
        home_alias.is_dir(),
        "case alias must identify the configured runtime home"
    );
    let variants = [
        vec![],
        vec![("APPDATA", alternate_appdata.path())],
        vec![
            ("APPDATA", alternate_appdata.path()),
            ("USERPROFILE", alternate_appdata.path()),
        ],
        vec![
            ("APPDATA", alternate_appdata.path()),
            ("TEMP", alternate_appdata.path()),
            ("TMP", alternate_appdata.path()),
        ],
        vec![
            ("PROGRAMDATA", alternate_appdata.path()),
            ("ALLUSERSPROFILE", alternate_appdata.path()),
        ],
        vec![("RUNSEAL_WINDOWS_SANDBOX_HOME", home_alias.as_path())],
    ];
    let mut contenders = Vec::new();
    for overrides in variants {
        let mut contender = Client::spawn_with_env("service", &overrides)?;
        contender.send(1, "execute", request.clone())?;
        let rejected = contender.next(Duration::from_secs(2))?;
        assert_eq!(
            rejected["error"]["data"]["code"],
            "POLICY_TRANSITION_BUSY",
            "override keys {:?}: {rejected}",
            overrides.iter().map(|(key, _)| *key).collect::<Vec<_>>()
        );
        assert!(rejected.get("result").is_none());
        contender.send(99, "listExecutions", json!({}))?;
        let listed = contender.next(Duration::from_secs(2))?;
        assert_eq!(
            listed["result"]["executions"],
            json!([]),
            "rejection must not create an activity: {listed}"
        );
        contenders.push(contender);
    }
    let mut contender = contenders.remove(1);
    assert!(!second.path().join("gate-command.ran").exists());
    assert!(!second.path().join(".runseal").exists());
    assert!(process_present(pid)?);
    let before = std::fs::read_to_string(first.path().join("gate-peer.beat")).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(2);
    while std::fs::read_to_string(first.path().join("gate-peer.beat")).unwrap_or_default() == before
    {
        assert!(Instant::now() < deadline, "original execution heartbeat");
        std::thread::sleep(Duration::from_millis(5));
    }
    owner.send(9, "cancelExecution", json!({"execution_id":id}))?;
    loop {
        let message = owner.next(Duration::from_secs(10))?;
        if message["params"]["execution_id"] == id
            && message["params"]["type"] == "execution.failed"
        {
            assert_eq!(message["params"]["result"]["cleanup_complete"], true);
            break;
        }
    }
    assert!(!process_present(pid)?);
    contender.send(2, "execute", request)?;
    let receipt = contender.next(Duration::from_secs(2))?;
    assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
    let deadline = Instant::now() + Duration::from_secs(15);
    let completed = loop {
        let message = contender.next(deadline.saturating_duration_since(Instant::now()))?;
        if matches!(
            message["params"]["type"].as_str(),
            Some("execution.finished" | "execution.failed")
        ) {
            break message["params"].clone();
        }
    };
    assert_eq!(completed["result"]["exit_code"], 7, "{completed}");
    assert_eq!(completed["result"]["cleanup_complete"], true);
    assert_eq!(
        std::fs::read_to_string(second.path().join("gate-command.ran"))?,
        "ran"
    );
    Ok(())
}

impl Drop for Client {
    fn drop(&mut self) {
        // EOF requests transport cancellation. Keep draining stdout while the
        // service releases its process range and shared reservation, including
        // when a test assertion or watchdog fails.
        drop(self.input.take());
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(windows)]
#[test]
fn nul_in_argv_and_environment_is_rejected_before_admission() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let marker = tmp.path().join("started");
    let base = json!({"command":[python()?,"-c","import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('started')",marker],"cwd":tmp.path(),"policy":"danger-full-access"});
    let mut client = Client::spawn("service")?;
    for (id, field, expected_code) in [
        (1, "argv", "INVALID_REQUEST"),
        (2, "env", "INVALID_REQUEST"),
        (3, "policy", "POLICY_INVALID"),
    ] {
        let mut request = base.clone();
        match field {
            "argv" => {
                request["command"]
                    .as_array_mut()
                    .context("command")?
                    .push(json!("secret-canary\0hidden"));
            }
            "env" => {
                request["env"] = json!({"VALUE":"secret-canary\0INJECTED=value"});
            }
            _ => {
                request["policy"] = json!({"version":"runseal.policy/v1","sandbox_level":"danger-full-access","environment":{"set":{"VALUE":"secret-canary\0INJECTED=value"}}});
            }
        }
        client.send(id, "execute", request)?;
        let response = client.next(Duration::from_secs(2))?;
        assert_eq!(response["id"], id);
        assert_eq!(
            response["error"]["data"]["code"], expected_code,
            "{response}"
        );
        assert!(response.get("result").is_none());
        assert!(!response.to_string().contains("secret-canary"));
        assert!(!marker.exists());
    }
    Ok(())
}

fn python() -> Result<String> {
    if let Ok(path) = std::env::var("RUNSEAL_TEST_PYTHON") {
        return Ok(path);
    }
    let output = if cfg!(windows) {
        Command::new("where.exe").arg("python").output()?
    } else {
        Command::new("sh")
            .args(["-c", "command -v python3"])
            .output()?
    };
    String::from_utf8(output.stdout)?
        .lines()
        .next()
        .map(str::to_owned)
        .context("Python executable")
}

#[cfg(unix)]
fn unix_process_present(pid: u32) -> Result<bool> {
    let pid = i32::try_from(pid).context("process id out of range")?;
    if unsafe { libc::kill(pid, 0) } == 0 {
        #[cfg(target_os = "linux")]
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            && let Some((_, fields)) = stat.rsplit_once(") ")
            && fields.starts_with('Z')
        {
            return Ok(false);
        }
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM) => Ok(true),
        Some(libc::ESRCH) => Ok(false),
        _ => Err(std::io::Error::last_os_error().into()),
    }
}

#[cfg(unix)]
fn process_present(pid: u32) -> Result<bool> {
    unix_process_present(pid)
}

#[cfg(unix)]
fn wait_terminal_unix(client: &Client, id: &str) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let event = &message["params"];
        if event["execution_id"] == id
            && matches!(
                event["type"].as_str(),
                Some("execution.failed" | "execution.finished")
            )
        {
            return Ok(event.clone());
        }
    }
}

#[cfg(unix)]
fn wait_response_unix(client: &Client, id: u64) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        if message["id"] == id {
            return Ok(message);
        }
    }
}

#[cfg(unix)]
fn wait_process_exit_unix(pid: u32) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while unix_process_present(pid)? {
        assert!(Instant::now() < deadline, "process {pid} survived cleanup");
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn portable_local_execution_cleans_process_groups_on_exit_and_cancel() -> Result<()> {
    let _guard = process_test_gate();
    for cancel in [false, true] {
        let tmp = TempDir::new()?;
        let mut client = Client::spawn("service")?;
        let child_code = "import pathlib,sys,time; path=pathlib.Path(sys.argv[1]); n=0\nwhile True:\n n+=1; path.write_text(str(n)); time.sleep(0.01)";
        let root_code = "import subprocess,sys; child=subprocess.Popen([sys.executable,'-u','-c',sys.argv[1],sys.argv[2]]); print('READY '+str(child.pid),flush=True)\nif sys.argv[3]=='wait': sys.stdin.buffer.read()";
        let mut start = |request_id: u64,
                         path: &std::path::Path,
                         hold: bool|
         -> Result<(String, u32)> {
            client.send(request_id, "execute", json!({
                "command": [python()?, "-u", "-c", root_code, child_code, path, if hold { "wait" } else { "exit" }],
                "cwd": tmp.path(),
                "policy": "danger-full-access",
                "stdin": {"mode":"stream"}
            }))?;
            let receipt = client.next(Duration::from_secs(2))?;
            assert_eq!(receipt["id"], request_id, "{receipt}");
            assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
            let id = receipt["result"]["execution_id"]
                .as_str()
                .context("execution id")?
                .to_owned();
            let pid = wait_ready_pid(&client, &id)?;
            Ok((id, pid))
        };

        let (peer_id, peer_pid) = start(1, &tmp.path().join("peer.beat"), true)?;
        let (owned_id, owned_pid) = start(2, &tmp.path().join("owned.beat"), cancel)?;
        assert!(unix_process_present(peer_pid)?);
        if cancel {
            assert!(unix_process_present(owned_pid)?);
            client.send(3, "cancelExecution", json!({"execution_id":owned_id}))?;
            assert_eq!(wait_response_unix(&client, 3)?["id"], 3);
        }
        let owned_terminal = wait_terminal_unix(&client, &owned_id)?;
        assert_eq!(
            owned_terminal["type"],
            if cancel {
                "execution.failed"
            } else {
                "execution.finished"
            },
            "{owned_terminal}"
        );
        assert_eq!(owned_terminal["result"]["cleanup_complete"], true);
        assert_eq!(
            owned_terminal["result"]["termination_reason"],
            if cancel { "cancelled" } else { "exited" }
        );
        wait_process_exit_unix(owned_pid)?;

        assert!(
            unix_process_present(peer_pid)?,
            "peer group must remain live"
        );
        let heartbeat_before = std::fs::read_to_string(tmp.path().join("peer.beat"))?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while std::fs::read_to_string(tmp.path().join("peer.beat"))? == heartbeat_before {
            assert!(Instant::now() < deadline, "peer heartbeat stopped");
            std::thread::sleep(Duration::from_millis(10));
        }
        client.send(4, "cancelExecution", json!({"execution_id":peer_id}))?;
        assert_eq!(wait_response_unix(&client, 4)?["id"], 4);
        let peer_terminal = wait_terminal_unix(&client, &peer_id)?;
        assert_eq!(peer_terminal["result"]["cleanup_complete"], true);
        wait_process_exit_unix(peer_pid)?;
        drop(client.input.take());
        assert!(client.child.wait()?.success());
    }
    Ok(())
}

#[test]
fn execution_capability_profiles_match_live_supported_and_rejected_behavior() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn("service")?;
    client.send(1, "getCapabilities", json!({}))?;
    let capabilities = client.next(Duration::from_secs(5))?;
    let profiles = capabilities["result"]["execution_profiles"]
        .as_array()
        .context("execution profiles")?;
    assert_eq!(profiles.len(), 24, "all public profiles must be reported");

    let mut supported_profiles = 0;
    let mut rejected_profiles = 0;
    let mut request_id = 2;
    for profile in profiles {
        let status = profile["status"].as_str().context("profile status")?;
        let sandbox_level = profile["sandbox_level"].as_str().context("sandbox level")?;
        let network_mode = profile["network_mode"].as_str().context("network mode")?;
        let io_mode = profile["io_mode"].as_str().context("I/O mode")?;
        if status == "experimental" {
            continue;
        }

        #[cfg(windows)]
        let interpreter = if sandbox_level == "workspace-contained" {
            contained_python_fixture(tmp.path())?
        } else {
            python()?
        };
        #[cfg(not(windows))]
        let interpreter = python()?;
        let command = [
            interpreter,
            "-u".to_string(),
            "-c".to_string(),
            "import os,sys; expected=sys.argv[1]=='pty'; assert all(os.isatty(fd)==expected for fd in (0,1,2)); print('AC26_PROFILE_OK',flush=True)".to_string(),
            io_mode.to_string(),
        ];
        let mut request = json!({
            "command": command,
            "cwd": tmp.path(),
            "policy": sandbox_level,
            "network": network_mode,
            "stdin": {"mode": if io_mode == "pty" { "stream" } else { "empty" }},
        });
        request["io"] = if io_mode == "pty" {
            json!({"mode":"pty","rows":24,"cols":80})
        } else {
            json!({"mode":"pipe"})
        };
        client.send(request_id, "execute", request)?;

        if matches!(status, "unsupported" | "unavailable" | "requires_setup") {
            let rejected = client.next(Duration::from_secs(5))?;
            assert_eq!(rejected["id"], request_id, "{profile}: {rejected}");
            assert!(rejected.get("result").is_none(), "{profile}: {rejected}");
            assert!(
                matches!(
                    rejected["error"]["data"]["code"].as_str(),
                    Some("BACKEND_CAPABILITY_MISSING" | "BACKEND_UNAVAILABLE")
                ),
                "unsupported profile must fail before admission: {profile}: {rejected}"
            );
            rejected_profiles += 1;
        } else if status == "supported" {
            let receipt = client.next(Duration::from_secs(15))?;
            assert_eq!(receipt["id"], request_id, "{profile}: {receipt}");
            assert_eq!(receipt["result"]["status"], "preparing", "{profile}");
            let execution_id = receipt["result"]["execution_id"]
                .as_str()
                .context("execution ID")?
                .to_owned();
            let mut output = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(30);
            let terminal = loop {
                let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
                let event = &message["params"];
                if event["execution_id"] != execution_id {
                    continue;
                }
                if matches!(
                    event["type"].as_str(),
                    Some("execution.stdout" | "execution.stderr" | "execution.terminal")
                ) {
                    let data = event["data"].as_str().context("output data")?;
                    output.extend(
                        STANDARD.decode(data.strip_prefix("base64:").context("base64 prefix")?)?,
                    );
                }
                if matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ) {
                    break event.clone();
                }
            };
            assert_eq!(
                terminal["type"], "execution.finished",
                "{profile}: {terminal}"
            );
            assert_eq!(terminal["result"]["exit_code"], 0, "{profile}: {terminal}");
            assert_eq!(terminal["result"]["cleanup_complete"], true, "{profile}");
            assert!(
                output
                    .windows(b"AC26_PROFILE_OK".len())
                    .any(|window| window == b"AC26_PROFILE_OK"),
                "supported profile did not run the target: {profile}"
            );
            supported_profiles += 1;
        } else {
            anyhow::bail!("unknown profile status {status:?}: {profile}");
        }
        request_id += 2;
    }
    assert!(supported_profiles > 0, "test must execute claimed profiles");
    #[cfg(not(windows))]
    assert!(
        rejected_profiles > 0,
        "portable PTY profiles must fail closed"
    );
    #[cfg(windows)]
    let _ = rejected_profiles;
    Ok(())
}

fn activity_query_and_cancel(mode: &str, policy: &str) -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn(mode)?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c","import time; print('READY',flush=True); time.sleep(60)"],"cwd":tmp.path(),"policy":policy,"stdin":{"mode":"empty"}}))?;
    let receipt = client.next(Duration::from_secs(2))?;
    assert_eq!(receipt["id"], 1, "receipt must precede execution events");
    assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
    let execution_id = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?
        .to_owned();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut ready_bytes = Vec::new();
    loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        if message["params"]["type"] == "execution.stdout" {
            let data = message["params"]["data"]
                .as_str()
                .context("output")?
                .strip_prefix("base64:")
                .context("encoding")?;
            ready_bytes.extend(STANDARD.decode(data)?);
            if ready_bytes.ends_with(b"\n") {
                assert!(ready_bytes.starts_with(b"READY"));
                break;
            }
        }
        assert_ne!(message["params"]["type"], "execution.failed", "{message}");
    }
    client.send(2, "getVersion", json!({}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["result"]["protocol_version"],
        "runseal.protocol/v2"
    );
    client.send(3, "getExecution", json!({"execution_id":execution_id}))?;
    let active = client.next(Duration::from_secs(2))?;
    assert_eq!(active["result"]["status"], "running", "{active}");
    client.send(4, "cancelExecution", json!({"execution_id":execution_id}))?;
    let accepted = client.next(Duration::from_secs(2))?;
    assert_eq!(accepted["id"], 4, "cancel receipt precedes terminal event");
    assert_eq!(accepted["result"]["status"], "canceling");
    let terminal = client.next(Duration::from_secs(10))?;
    assert_eq!(terminal["params"]["type"], "execution.failed", "{terminal}");
    assert_eq!(
        terminal["params"]["result"]["termination_reason"],
        "cancelled"
    );
    assert_eq!(
        terminal["params"]["result"]["error"]["code"],
        "EXECUTION_CANCELLED"
    );
    assert!(terminal["params"]["result"].get("stdout").is_none());
    assert!(terminal["params"]["result"].get("stderr").is_none());
    Ok(())
}

#[test]
fn rpc_and_service_query_and_cancel_while_execution_is_running() -> Result<()> {
    for mode in ["rpc", "service"] {
        activity_query_and_cancel(mode, "danger-full-access")?;
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn windows_node_client_round_trips_inside_sandbox() -> Result<()> {
    let _guard = process_test_gate();
    let node = if let Ok(path) = std::env::var("RUNSEAL_TEST_NODE") {
        path
    } else {
        String::from_utf8(Command::new("where.exe").arg("node").output()?.stdout)?
            .lines()
            .next()
            .context("Node.js executable required for integration conformance")?
            .to_owned()
    };
    for network in ["disabled", "unmanaged"] {
        let tmp = TempDir::new()?;
        let output = Command::new(&node)
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("examples/stdio-json-rpc/runseal_stdio_example.mjs"),
            )
            .args(["--runseal", env!("CARGO_BIN_EXE_runseal"), "--cwd"])
            .arg(tmp.path())
            .args(["--network", network])
            .output()?;
        assert!(
            output.status.success(),
            "Node.js sandbox integration failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(summary["command"]["status"], "finished");
        assert_eq!(summary["command"]["stdout_bytes"], 32);
        assert_eq!(summary["pty"]["resized"], true);
        assert_eq!(summary["control"]["control_round_trips"], 3);
        assert_eq!(summary["cancellation"]["termination_reason"], "cancelled");
        assert_eq!(summary["cancellation"]["cleanup_complete"], true);
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn windows_sandboxed_rpc_and_service_active_cancellation() -> Result<()> {
    for mode in ["rpc", "service"] {
        activity_query_and_cancel(mode, "workspace-write")?;
    }
    Ok(())
}

#[cfg(windows)]
fn process_present(pid: u32) -> Result<bool> {
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

fn wait_ready_pid(client: &Client, id: &str) -> Result<u32> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut output = Vec::new();
    loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let event = &message["params"];
        if event["execution_id"] != id {
            continue;
        }
        assert!(
            !matches!(
                event["type"].as_str(),
                Some("execution.failed" | "execution.finished")
            ),
            "execution must remain live until released: {message}"
        );
        if event["type"] == "execution.stdout" {
            output.extend(
                STANDARD.decode(
                    event["data"]
                        .as_str()
                        .context("output data")?
                        .strip_prefix("base64:")
                        .context("base64 prefix")?,
                )?,
            );
            if output.ends_with(b"\n") {
                let text = String::from_utf8(output)?;
                return Ok(text
                    .trim()
                    .strip_prefix("READY ")
                    .context("READY with descendant PID")?
                    .parse()?);
            }
        }
    }
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn windows_ac07_cancelling_execution_a_keeps_execution_b_live_and_bound() -> Result<()> {
    verify_natural_exit_and_cancel_range("workspace-write", Some("proxy"))
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn windows_environment_override_is_case_insensitive_for_local_and_sandbox_execution() -> Result<()>
{
    let _guard = process_test_gate();
    for level in ["danger-full-access", "workspace-write"] {
        for (configured_key, requested_key) in [("PATH", "Path"), ("Path", "PATH")] {
            let tmp = TempDir::new()?;
            let mut client = Client::spawn("service")?;
            let mut configured = serde_json::Map::new();
            configured.insert(configured_key.to_string(), json!("policy-value"));
            let mut requested = serde_json::Map::new();
            requested.insert(requested_key.to_string(), json!("requested-value"));
            client.send(1,"execute",json!({"command":[python()?,"-c","import os,sys; sys.stdout.buffer.write(os.environ['PATH'].encode())"],"cwd":tmp.path(),"policy":{"version":"runseal.policy/v1","sandbox_level":level,"environment":{"set":configured}},"env":requested}))?;
            let receipt = client.next(Duration::from_secs(2))?;
            assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
            receive_bytes_with_timeout(&client, b"requested-value", Duration::from_secs(10))?;
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
                if matches!(
                    message["params"]["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ) {
                    assert_eq!(message["params"]["result"]["exit_code"], 0, "{message}");
                    assert_eq!(message["params"]["result"]["cleanup_complete"], true);
                    break;
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_local_execution_clears_descendants_without_stopping_peer() -> Result<()> {
    verify_natural_exit_and_cancel_range("danger-full-access", None)
}

#[cfg(windows)]
#[test]
fn dropping_protocol_fixture_drains_live_execution_before_host_exit() -> Result<()> {
    let tmp = TempDir::new()?;
    let mut client = Client::spawn("service")?;
    client.send(1, "execute", json!({
        "command":[python()?, "-u", "-c", "import subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); print('READY '+str(child.pid),flush=True); time.sleep(60)"],
        "cwd":tmp.path(), "policy":"danger-full-access"
    }))?;
    let receipt = client.next(Duration::from_secs(2))?;
    let id = receipt["result"]["execution_id"]
        .as_str()
        .context("execution ID")?;
    let descendant = wait_ready_pid(&client, id)?;
    let host = client.child.id();
    assert!(process_present(host)? && process_present(descendant)?);
    drop(client);
    assert!(
        !process_present(host)?,
        "fixture must wait for host shutdown"
    );
    assert!(
        !process_present(descendant)?,
        "transport EOF must drain the owned process range"
    );
    let mut terminals = Vec::new();
    for file in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
        for line in std::fs::read_to_string(file?.path())?.lines() {
            let event: Value = serde_json::from_str(line)?;
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                terminals.push(event);
            }
        }
    }
    assert_eq!(
        terminals.len(),
        1,
        "fixture shutdown must commit one cleanup terminal"
    );
    assert_eq!(terminals[0]["result"]["cleanup_complete"], true);
    assert_eq!(
        terminals[0]["result"]["termination_reason"],
        "client_disconnected"
    );
    assert_eq!(
        terminals[0]["result"]["error"]["code"],
        "CLIENT_DISCONNECTED"
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn paused_protocol_reader_does_not_prevent_cancellation() -> Result<()> {
    verify_paused_protocol_reader("danger-full-access", true, false)
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn sandboxed_paused_protocol_reader_does_not_prevent_cancellation() -> Result<()> {
    verify_paused_protocol_reader("workspace-write", true, false)
}

#[cfg(windows)]
#[test]
fn stalled_protocol_writer_cleans_owned_execution_and_closes_connection() -> Result<()> {
    verify_paused_protocol_reader("danger-full-access", false, false)
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn sandboxed_stalled_protocol_writer_cleans_owned_execution_and_closes_connection() -> Result<()> {
    verify_paused_protocol_reader("workspace-write", false, false)
}

#[cfg(windows)]
#[test]
fn unsubscribe_discards_already_queued_notifications_before_its_receipt() -> Result<()> {
    verify_paused_protocol_reader("danger-full-access", true, true)
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn sandboxed_unsubscribe_discards_already_queued_notifications_before_its_receipt() -> Result<()> {
    verify_paused_protocol_reader("workspace-write", true, true)
}

#[cfg(windows)]
fn verify_paused_protocol_reader(policy: &str, cancel: bool, unsubscribe: bool) -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut host = Command::new(env!("CARGO_BIN_EXE_runseal"))
        .args(["service", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut input = host.stdin.take().context("stdin")?;
    let output = host.stdout.take().context("stdout")?;
    let (permit, reads) = mpsc::sync_channel::<()>(1);
    let (sender, messages) = mpsc::sync_channel::<Result<Value>>(1);
    let reader = std::thread::spawn(move || {
        let mut output = BufReader::new(output);
        while reads.recv().is_ok() {
            let mut line = String::new();
            let result = output
                .read_line(&mut line)
                .map_err(anyhow::Error::from)
                .and_then(|count| {
                    anyhow::ensure!(count > 0, "protocol EOF");
                    Ok(serde_json::from_str(&line)?)
                });
            if sender.send(result).is_err() {
                break;
            }
        }
    });
    struct HostFixture(Child);
    impl Drop for HostFixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut host = HostFixture(host);
    let mut fixture = HeartbeatFixture {
        directory: tmp.path().to_owned(),
        pids: Vec::new(),
    };
    let child_code = "import pathlib,time; target=pathlib.Path('first'); stop=pathlib.Path('first.stop'); count=0\nwhile not stop.exists():\n count+=1; target.write_text(str(count)); time.sleep(0.01)";
    let root_code = "import os,pathlib,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-u','-c',sys.argv[1]]);\nwhile not pathlib.Path('first').exists(): time.sleep(0.01)\nprint('READY '+str(child.pid),flush=True)\nwhile not pathlib.Path('burst').exists(): time.sleep(0.01)\nfor _ in range(8): os.write(1,b'X'*65536)\npathlib.Path('burst-started').write_text('started')\nwhile True: os.write(1,b'X'*65536)";
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"execute","params":{"command":[python()?,"-u","-c",root_code,child_code],"cwd":tmp.path(),"policy":policy}})
    )?;
    input.flush()?;
    let next = || -> Result<Value> {
        permit.send(())?;
        messages
            .recv_timeout(Duration::from_secs(10))
            .context("controlled reader watchdog")?
    };
    let receipt = next()?;
    assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
    let id = receipt["result"]["execution_id"]
        .as_str()
        .context("execution ID")?;
    let mut ready = Vec::new();
    let mut audit_path = None;
    loop {
        let message = next()?;
        let event = &message["params"];
        if let Some(path) = event["audit_path"].as_str() {
            audit_path = Some(path.to_owned());
        }
        if event["type"] == "execution.stdout" {
            ready.extend(
                STANDARD.decode(
                    event["data"]
                        .as_str()
                        .context("data")?
                        .strip_prefix("base64:")
                        .context("base64 prefix")?,
                )?,
            );
            if ready.ends_with(b"\n") {
                break;
            }
        }
        assert_ne!(event["type"], "execution.failed", "{message}");
    }
    let descendant: u32 = String::from_utf8(ready)?
        .trim()
        .strip_prefix("READY ")
        .context("READY PID")?
        .parse()?;
    fixture.pids.push(descendant);
    std::fs::write(tmp.path().join("burst"), b"release")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !tmp.path().join("burst-started").exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(tmp.path().join("burst-started").exists());
    if !cancel {
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = host.0.try_wait()? {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            !status
                .context("writer stall must close the connection within cleanup watchdog")?
                .success()
        );
        assert!(!process_present(descendant)?);
        let audit = std::fs::read_to_string(tmp.path().join(audit_path.context("audit path")?))?;
        let events = audit
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert!(
            events
                .iter()
                .any(|event| event["type"] == "execution.failed"
                    && event["error"]["code"] == "CLIENT_BACKPRESSURE")
        );
        assert!(events.iter().all(|event| event.get("data").is_none()));
        drop(permit);
        drop(input);
        reader
            .join()
            .map_err(|_| anyhow::anyhow!("reader panicked"))?;
        return Ok(());
    }
    if unsubscribe {
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":3,"method":"unsubscribeEvents","params":{"execution_id":id}})
        )?;
        input.flush()?;
    }
    // No further read permit: stdout fills while the controller must still accept cancel.
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":2,"method":"cancelExecution","params":{"execution_id":id}})
    )?;
    input.flush()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while process_present(descendant)? && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !process_present(descendant)?,
        "cancel must clear its range while the client is not reading output"
    );
    assert!(host.0.try_wait()?.is_none());
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut acknowledged = false;
    let mut unsubscribed = false;
    let terminal = 'drain: loop {
        anyhow::ensure!(Instant::now() < deadline, "resume drain watchdog");
        let message = next()?;
        if message["id"] == 3 {
            assert_eq!(message["result"]["unsubscribed"], true);
            unsubscribed = true;
        }
        if unsubscribed {
            assert_ne!(
                message["method"], "event",
                "queued notifications must be invalidated before unsubscribe receipt: {message}"
            );
        }
        if message["id"] == 2 {
            assert_eq!(message["result"]["status"], "canceling");
            acknowledged = true;
            if unsubscribe {
                assert!(unsubscribed);
                let mut request_id = 4;
                loop {
                    writeln!(
                        input,
                        "{}",
                        json!({"jsonrpc":"2.0","id":request_id,"method":"getExecution","params":{"execution_id":id}})
                    )?;
                    input.flush()?;
                    let snapshot = next()?;
                    assert_eq!(
                        snapshot["id"], request_id,
                        "no stale notification may follow unsubscribe: {snapshot}"
                    );
                    if snapshot["result"]["status"] == "failed" {
                        break 'drain snapshot["result"].clone();
                    }
                    anyhow::ensure!(Instant::now() < deadline, "completion query watchdog");
                    request_id += 1;
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }

        if message["params"]["type"] == "execution.failed" {
            break message["params"]["result"].clone();
        }
    };
    assert!(acknowledged);
    assert_eq!(terminal["error"]["code"], "EXECUTION_CANCELLED");
    assert_eq!(terminal["cleanup_complete"], true);
    drop(permit);
    drop(input);
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("reader panicked"))?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_local_host_death_clears_its_range_and_preserves_other_connection() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut owner = Client::spawn("service")?;
    let mut peer = Client::spawn("service")?;
    let mut fixture = HeartbeatFixture {
        directory: tmp.path().to_owned(),
        pids: Vec::new(),
    };
    let root_code = "import pathlib,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-u','-c',sys.argv[1],sys.argv[2]]); target=pathlib.Path(sys.argv[2]);\nwhile not target.exists(): time.sleep(0.01)\nprint('READY '+str(child.pid),flush=True); sys.stdin.buffer.read()";
    let child_code = "import pathlib,sys,time; target=pathlib.Path(sys.argv[1]); stop=pathlib.Path(sys.argv[1]+'.stop'); count=0\nwhile not stop.exists():\n count+=1; target.write_text(str(count)); time.sleep(0.01)";
    for (client, name) in [(&mut owner, "first"), (&mut peer, "peer")] {
        client.send(1,"execute",json!({"command":[python()?,"-u","-c",root_code,child_code,name],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}))?;
        let receipt = client.next(Duration::from_secs(2))?;
        assert_eq!(receipt["result"]["status"], "preparing");
        let pid = wait_ready_pid(
            client,
            receipt["result"]["execution_id"]
                .as_str()
                .context("execution ID")?,
        )?;
        assert!(process_present(pid)?);
        fixture.pids.push(pid);
    }
    owner.child.kill()?;
    owner.child.wait()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while process_present(fixture.pids[0])? && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !process_present(fixture.pids[0])?,
        "owned descendant must exit after host death"
    );
    assert!(
        process_present(fixture.pids[1])?,
        "other connection must remain live"
    );
    let before = std::fs::read(tmp.path().join("peer"))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while std::fs::read(tmp.path().join("peer"))? == before && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_ne!(std::fs::read(tmp.path().join("peer"))?, before);
    peer.send(2, "getVersion", json!({}))?;
    assert_eq!(peer.next(Duration::from_secs(2))?["id"], 2);
    Ok(())
}

#[cfg(windows)]
struct HeartbeatFixture {
    directory: std::path::PathBuf,
    pids: Vec<u32>,
}
#[cfg(windows)]
impl Drop for HeartbeatFixture {
    fn drop(&mut self) {
        for name in ["first.stop", "peer.stop"] {
            let _ = std::fs::write(self.directory.join(name), b"stop");
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while self
            .pids
            .iter()
            .any(|pid| process_present(*pid).unwrap_or(true))
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(windows)]
fn verify_natural_exit_and_cancel_range(policy: &str, network_mode: Option<&str>) -> Result<()> {
    let _guard = process_test_gate();
    for cancel in [false, true] {
        let tmp = TempDir::new()?;
        let (proxy_port, proxy_upstream) = if network_mode.is_some() {
            let (port, upstream) = start_ac07_proxy_upstream()?;
            (port, Some(upstream))
        } else {
            (0, None)
        };
        let mut client = Client::spawn("service")?;
        let mut fixture = HeartbeatFixture {
            directory: tmp.path().to_owned(),
            pids: Vec::new(),
        };
        let child_code = "import os,pathlib,socket,sys,time,urllib.parse; target=pathlib.Path(sys.argv[1]); name=target.name; port=sys.argv[2]; stop=pathlib.Path(str(target)+'.stop'); count=0\nif 'RUNSEAL_HOME' in os.environ: pathlib.Path(name+'.runtime').write_text(os.environ['RUNSEAL_HOME'])\nproxy_done=False\nwhile not stop.exists():\n count+=1; target.write_text(str(count))\n if pathlib.Path(name+'.proxy-request').exists() and not proxy_done:\n  proxy_done=True\n  try:\n   proxy=urllib.parse.urlparse(os.environ['HTTP_PROXY']); auth=os.environ['RUNSEAL_NETWORK_PROXY_AUTHORIZATION']; request=f'GET http://127.0.0.1:{port}/proxy-ok HTTP/1.1\\r\\nHost: 127.0.0.1:{port}\\r\\nProxy-Authorization: {auth}\\r\\nConnection: close\\r\\n\\r\\n'.encode('ascii')\n   with socket.create_connection((proxy.hostname,proxy.port),timeout=3) as connection:\n    connection.settimeout(3); connection.sendall(request); response=b''\n    while True:\n     chunk=connection.recv(4096)\n     if not chunk: break\n     response+=chunk\n   pathlib.Path(name+'.proxy-result').write_text('ok' if b'proxy-ok' in response else 'failed')\n  except Exception:\n   pathlib.Path(name+'.proxy-result').write_text('failed')\n time.sleep(0.01)";
        let root_code = "import pathlib,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-u','-c',sys.argv[1],sys.argv[2],sys.argv[3]]); target=pathlib.Path(sys.argv[2]);\nwhile not target.exists():\n if child.poll() is not None: sys.exit(2)\n time.sleep(0.01)\nprint('READY '+str(child.pid),flush=True); sys.stdin.buffer.read()";
        let mut executions = Vec::new();
        let mut peer_policy_hash = Value::Null;
        let mut peer_policy_epoch = Value::Null;
        for (request_id, name) in [(1, "first"), (2, "peer")] {
            let mut request = json!({"command":[python()?,"-u","-c",root_code,child_code,name,proxy_port.to_string()],"cwd":tmp.path(),"policy":policy,"stdin":{"mode":"stream"}});
            if let Some(network_mode) = network_mode {
                request["network"] = json!(network_mode);
            }
            client.send(request_id, "execute", request)?;
            let receipt = client.next(Duration::from_secs(2))?;
            assert_eq!(receipt["id"], request_id, "{receipt}");
            assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
            let id = receipt["result"]["execution_id"]
                .as_str()
                .context("execution ID")?
                .to_owned();
            if request_id == 2 {
                peer_policy_hash = receipt["result"]["policy_hash"].clone();
                peer_policy_epoch = receipt["result"]["policy_epoch"].clone();
            }
            let pid = wait_ready_pid(&client, &id)?;
            assert!(process_present(pid)?);
            fixture.pids.push(pid);
            executions.push((id, pid));
        }
        let first_runtime = if network_mode.is_some() {
            let home = std::path::PathBuf::from(std::fs::read_to_string(
                tmp.path().join("first.runtime"),
            )?);
            assert!(
                home.exists(),
                "execution A runtime home must exist while active"
            );
            Some(home)
        } else {
            None
        };
        let peer_runtime = if network_mode.is_some() {
            let home =
                std::path::PathBuf::from(std::fs::read_to_string(tmp.path().join("peer.runtime"))?);
            assert!(
                home.exists(),
                "execution B runtime home must exist while active"
            );
            Some(home)
        } else {
            None
        };
        client.send(
            3,
            if cancel {
                "cancelExecution"
            } else {
                "closeExecutionInput"
            },
            if cancel {
                json!({"execution_id":executions[0].0})
            } else {
                json!({"execution_id":executions[0].0,"stream":"stdin"})
            },
        )?;
        assert_eq!(client.next(Duration::from_secs(2))?["id"], 3);
        let deadline = Instant::now() + Duration::from_secs(10);
        let terminal = loop {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            if message["params"]["execution_id"] == executions[0].0
                && matches!(
                    message["params"]["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                )
            {
                break message["params"]["result"].clone();
            }
        };
        assert_eq!(terminal["cleanup_complete"], true, "{terminal}");
        assert_eq!(
            terminal["termination_reason"],
            if cancel { "cancelled" } else { "exited" }
        );
        assert!(
            !process_present(executions[0].1)?,
            "descendant must be absent before cleanup success"
        );
        if let Some(home) = first_runtime {
            assert!(!home.exists(), "execution A runtime home must be cleaned");
        }
        assert!(
            process_present(executions[1].1)?,
            "peer descendant must remain live"
        );
        if let Some(home) = &peer_runtime {
            assert!(
                home.exists(),
                "execution B runtime home must survive A cleanup"
            );
            assert!(
                home.parent().is_some_and(std::path::Path::exists),
                "execution B runtime root must survive A cleanup"
            );
        }
        client.send(4, "getExecution", json!({"execution_id":executions[1].0}))?;
        let peer_state = loop {
            let message = client.next(Duration::from_secs(2))?;
            if message["id"] == 4 {
                break message;
            }
        };
        assert_eq!(peer_state["result"]["status"], "running", "{peer_state}");
        assert_eq!(peer_state["result"]["policy_hash"], peer_policy_hash);
        assert_eq!(peer_state["result"]["policy_epoch"], peer_policy_epoch);
        let previous = std::fs::read(tmp.path().join("peer"))?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while std::fs::read(tmp.path().join("peer"))? == previous && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_ne!(
            std::fs::read(tmp.path().join("peer"))?,
            previous,
            "peer heartbeat must continue"
        );
        if let Some(upstream) = proxy_upstream {
            std::fs::write(tmp.path().join("peer.proxy-request"), b"request")?;
            let deadline = Instant::now() + Duration::from_secs(10);
            while !tmp.path().join("peer.proxy-result").exists() {
                assert!(
                    Instant::now() < deadline,
                    "peer proxy lease request watchdog"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                std::fs::read_to_string(tmp.path().join("peer.proxy-result"))?,
                "ok",
                "execution B proxy lease must remain usable after A cleanup"
            );
            upstream
                .join()
                .map_err(|_| anyhow::anyhow!("proxy upstream panicked"))??;
        }
        client.send(
            5,
            "cancelExecution",
            json!({"execution_id":executions[1].0}),
        )?;
        assert_eq!(client.next(Duration::from_secs(2))?["id"], 5);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            if message["params"]["execution_id"] == executions[1].0
                && message["params"]["type"] == "execution.failed"
            {
                assert_eq!(message["params"]["result"]["cleanup_complete"], true);
                break;
            }
        }
        assert!(!process_present(executions[1].1)?);
        if let Some(home) = peer_runtime {
            assert!(!home.exists(), "execution B runtime home must be cleaned");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn start_ac07_proxy_upstream() -> Result<(u16, std::thread::JoinHandle<Result<()>>)> {
    use std::io::Read;

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let upstream = std::thread::spawn(move || -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    anyhow::ensure!(Instant::now() < deadline, "proxy upstream request watchdog");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut buffer = [0_u8; 1024];
            let count = stream.read(&mut buffer)?;
            anyhow::ensure!(count > 0, "proxy upstream request ended before headers");
            request.extend_from_slice(&buffer[..count]);
            anyhow::ensure!(request.len() <= 8192, "proxy upstream headers too large");
        }
        anyhow::ensure!(
            String::from_utf8_lossy(&request).starts_with("GET /proxy-ok HTTP/1.1\r\n"),
            "proxy upstream received an unexpected request"
        );
        stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nproxy-ok",
        )?;
        Ok(())
    });
    Ok((port, upstream))
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn windows_timeout_clears_descendant_range_and_retains_timeout_cause() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn("service")?;
    // This scenario needs a live descendant before the request deadline;
    // native sandbox setup is included in the total timeout.
    client.send(1,"execute",json!({"command":[python()?,"-u","-c","import subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); print('READY '+str(child.pid),flush=True); time.sleep(60)"],"cwd":tmp.path(),"policy":"workspace-write","timeout_ms":10000}))?;
    let receipt = client.next(Duration::from_secs(2))?;
    assert_eq!(receipt["result"]["status"], "preparing");
    let id = receipt["result"]["execution_id"]
        .as_str()
        .context("execution ID")?;
    let descendant = wait_ready_pid(&client, id)?;
    assert!(process_present(descendant)?);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut timeout_event = false;
    let result = loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let event = &message["params"];
        if event["type"] == "execution.resource.limit_exceeded" {
            assert_eq!(event["resource"], "timeout_ms");
            timeout_event = true;
        }
        if event["type"] == "execution.failed" {
            break event["result"].clone();
        }
    };
    assert!(timeout_event);
    assert_eq!(result["error"]["code"], "EXECUTION_TIMEOUT");
    assert_eq!(result["timeout_ms"], 10000);
    assert_eq!(result["termination_reason"], "timeout");
    assert_eq!(result["requested_termination_reason"], "timeout");
    assert_eq!(result["cleanup_complete"], true);
    assert_eq!(
        result["exit_code"], 1,
        "must retain the actual terminated process status"
    );
    assert!(!process_present(descendant)?);
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn windows_preparation_timeout_aborts_cleanly_without_quarantining_the_binding() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn("service")?;
    // The request deadline expires while the Windows sandbox is still being
    // prepared, before the runner receives any spawn request. That is a clean
    // pre-start abort: the terminal must keep the timeout cause and confirmed
    // cleanup, and the shared binding must remain admissible.
    client.send(
        1,
        "execute",
        json!({"command":[python()?,"-c","import time; time.sleep(60)"],"cwd":tmp.path(),"policy":"workspace-write","network":"disabled","timeout_ms":100}),
    )?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut receipt = None;
    let terminal = loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        if message["id"] == 1 {
            receipt = Some(message["result"].clone());
        }
        if message["params"]["type"] == "execution.failed" {
            break message["params"]["result"].clone();
        }
    };
    assert_eq!(terminal["error"]["code"], "EXECUTION_TIMEOUT", "{terminal}");
    assert_eq!(terminal["termination_reason"], "timeout", "{terminal}");
    assert_eq!(
        terminal["requested_termination_reason"], "timeout",
        "{terminal}"
    );
    assert_eq!(terminal["cleanup_complete"], true, "{terminal}");
    assert_eq!(terminal["exit_code"], Value::Null, "{terminal}");
    if let Some(receipt) = receipt {
        assert_eq!(receipt["status"], "preparing", "{receipt}");
    }
    // A following sandboxed execution in the same service must still admit and
    // complete; a false cleanup failure would have quarantined this binding.
    client.send(
        2,
        "execute",
        json!({"command":[python()?,"-c","print('recovered')"],"cwd":tmp.path(),"policy":"workspace-write","network":"disabled","timeout_ms":20000}),
    )?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let recovered = loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        if message["params"]["type"] == "execution.finished" {
            break message["params"]["result"].clone();
        }
        if message["params"]["type"] == "execution.failed" {
            anyhow::bail!("binding stayed unusable after the timeout: {message}");
        }
    };
    assert_eq!(recovered["status"], "finished", "{recovered}");
    assert_eq!(recovered["exit_code"], 0, "{recovered}");
    assert_eq!(recovered["cleanup_complete"], true, "{recovered}");
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn windows_spawn_failure_keeps_raw_backend_diagnostics_out_of_audit() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn("service")?;
    let argument_canary = "argument-secret-canary";
    client.send(1,"execute",json!({"command":[tmp.path().join("missing-program.exe"), argument_canary],"cwd":tmp.path(),"policy":"workspace-write","env":{"TOKEN":"environment-secret-canary"},"metadata":{"authorization":"metadata-secret-canary"}}))?;
    let receipt = client.next(Duration::from_secs(2))?;
    assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
    let deadline = Instant::now() + Duration::from_secs(10);
    let result = loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        if message["params"]["type"] == "execution.failed" {
            break message["params"]["result"].clone();
        }
    };
    assert_eq!(result["error"]["code"], "EXECUTION_FAILED_TO_START");
    let path = result["audit_path"].as_str().context("audit path")?;
    let audit = std::fs::read_to_string(tmp.path().join(path))?;
    for secret in [
        argument_canary,
        "environment-secret-canary",
        "metadata-secret-canary",
    ] {
        assert!(
            !audit.contains(secret),
            "raw backend diagnostics must not expose the secret canary"
        );
        assert!(!result.to_string().contains(secret));
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn windows_output_limit_terminates_with_verified_cleanup_and_correct_cause() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn("service")?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c","import os,time;\nwhile True: os.write(1,b'Z'*65536)"],"cwd":tmp.path(),"policy":{"version":"runseal.policy/v1","sandbox_level":"workspace-write","resources":{"max_output_bytes":131072}}}))?;
    let receipt = client.next(Duration::from_secs(2))?;
    assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut bytes = 0;
    let result = loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        let event = &message["params"];
        if event["type"] == "execution.stdout" {
            let chunk = STANDARD.decode(
                event["data"]
                    .as_str()
                    .context("data")?
                    .strip_prefix("base64:")
                    .context("encoding")?,
            )?;
            assert!(chunk.len() <= 65536);
            bytes += chunk.len();
        }
        if event["type"] == "execution.failed" {
            break event["result"].clone();
        }
    };
    assert!(bytes <= 131072);
    assert_eq!(result["error"]["code"], "OUTPUT_LIMIT_EXCEEDED");
    assert_eq!(result["termination_reason"], "output_limit");
    assert_eq!(result["cleanup_complete"], true);
    Ok(())
}

fn receive_bytes(client: &Client, expected: &[u8]) -> Result<()> {
    receive_bytes_with_timeout(client, expected, Duration::from_secs(2))
}

fn receive_bytes_with_timeout(client: &Client, expected: &[u8], timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    while bytes.len() < expected.len() {
        let message = client
            .next(deadline.saturating_duration_since(Instant::now()))
            .with_context(|| format!("received stream bytes: {bytes:?}"))?;
        assert_ne!(message["params"]["type"], "execution.failed", "{message}");
        if message["params"]["type"] == "execution.stdout" {
            let data = message["params"]["data"]
                .as_str()
                .context("stream data")?
                .strip_prefix("base64:")
                .context("base64 prefix")?;
            bytes.extend(STANDARD.decode(data)?);
        }
    }
    assert_eq!(bytes, expected);
    Ok(())
}

fn stream_round_trips(policy: &str) -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn("service")?;
    client.send(1,"execute", json!({"command":[python()?,"-u","-c",
        "import sys,time,pathlib; out=sys.stdout.buffer; out.write(b'READY\\n'); out.flush();\nwhile True:\n data=sys.stdin.buffer.readline()\n if not data: break\n out.write(data); out.flush()\npathlib.Path('eof-ready').write_text('ready')\nwhile not pathlib.Path('release').exists(): time.sleep(0.01)"],
        "cwd":tmp.path(),"policy":policy,"stdin":{"mode":"stream"},"timeout_ms":10000}))?;
    let receipt = client.next(Duration::from_secs(2))?;
    assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
    let execution_id = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?;
    receive_bytes_with_timeout(&client, b"READY\n", Duration::from_secs(10))
        .context("stream child readiness")?;
    for (id, data) in [
        (2, b"first\n".as_slice()),
        (3, b"\0\xff\xc3\xa9\n".as_slice()),
        (4, b"stream-secret-canary\n".as_slice()),
    ] {
        client.send(id,"writeExecutionInput",json!({"execution_id":execution_id,"stream":"stdin","encoding":"base64","data":format!("base64:{}",STANDARD.encode(data))}))?;
        let accepted = client.next(Duration::from_secs(2))?;
        assert_eq!(accepted["id"], id, "{accepted}");
        assert_eq!(accepted["result"]["accepted_bytes"], data.len());
        receive_bytes(&client, data).with_context(|| format!("stream round {id}"))?;
    }
    for id in [5, 6] {
        client.send(
            id,
            "closeExecutionInput",
            json!({"execution_id":execution_id,"stream":"stdin"}),
        )?;
        assert_eq!(
            client.next(Duration::from_secs(2))?["result"]["closed"],
            true
        );
    }
    client.send(7,"writeExecutionInput",json!({"execution_id":execution_id,"stream":"stdin","encoding":"base64","data":"base64:YQ=="}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["error"]["data"]["code"],
        "EXECUTION_INPUT_CLOSED"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while !tmp.path().join("eof-ready").exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        tmp.path().join("eof-ready").exists(),
        "child must observe EOF"
    );
    std::fs::write(tmp.path().join("release"), b"release")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let terminal = loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        if matches!(
            message["params"]["type"].as_str(),
            Some("execution.finished" | "execution.failed")
        ) {
            break message;
        }
    };
    assert_eq!(
        terminal["params"]["type"], "execution.finished",
        "{terminal}"
    );
    assert_eq!(terminal["params"]["result"]["exit_code"], 0);
    let audit_path = terminal["params"]["result"]["audit_path"]
        .as_str()
        .context("audit path")?;
    let audit = std::fs::read_to_string(tmp.path().join(audit_path))?;
    assert!(!audit.contains("stream-secret-canary"));
    assert!(!audit.contains(&STANDARD.encode(b"stream-secret-canary\n")));
    Ok(())
}

#[test]
fn local_stream_stdin_three_round_trips_and_ordered_eof() -> Result<()> {
    stream_round_trips("danger-full-access")
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn windows_sandboxed_stream_stdin_three_round_trips_and_ordered_eof() -> Result<()> {
    stream_round_trips("workspace-write")
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn windows_unread_stream_input_does_not_block_cancellation() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn("service")?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c","import sys,time; print('READY',flush=True); sys.stdin.buffer.read(1); print('INPUT_STARTED',flush=True); time.sleep(15)"],"cwd":tmp.path(),"policy":"workspace-write","stdin":{"mode":"stream"}}))?;
    let receipt = client.next(Duration::from_secs(2))?;
    let execution_id = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?;
    receive_bytes_with_timeout(&client, b"READY\r\n", Duration::from_secs(10))?;
    client.send(2,"writeExecutionInput",json!({"execution_id":execution_id,"stream":"stdin","encoding":"base64","data":format!("base64:{}",STANDARD.encode(vec![0u8;64*1024]))}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["result"]["accepted_bytes"],
        64 * 1024
    );
    receive_bytes_with_timeout(&client, b"INPUT_STARTED\r\n", Duration::from_secs(10))?;
    let mut saw_backpressure = false;
    for id in 3..67 {
        client.send(id,"writeExecutionInput",json!({"execution_id":execution_id,"stream":"stdin","encoding":"base64","data":format!("base64:{}",STANDARD.encode(vec![0u8;64*1024]))}))?;
        let response = client.next(Duration::from_secs(2))?;
        if response["error"]["data"]["code"] == "INPUT_BACKPRESSURE" {
            saw_backpressure = true;
            break;
        }
        assert_eq!(
            response["result"]["accepted_bytes"],
            64 * 1024,
            "{response}"
        );
    }
    assert!(saw_backpressure, "unread input must reach a bounded queue");
    client.send(70, "cancelExecution", json!({"execution_id":execution_id}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["result"]["status"],
        "canceling"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let event = client.next(deadline.saturating_duration_since(Instant::now()))?;
        if event["params"]["type"] == "execution.failed" {
            assert_eq!(
                event["params"]["result"]["error"]["code"],
                "EXECUTION_CANCELLED"
            );
            break;
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn sandboxed_binary_bytes_file_and_empty_stdin_deliver_exact_bytes_then_eof() -> Result<()> {
    let _guard = process_test_gate();
    for (mode, size) in [("empty", 0), ("bytes", 64 * 1024), ("file", 192 * 1024)] {
        let tmp = TempDir::new()?;
        let expected: Vec<u8> = (0..size).map(|index| (index % 256) as u8).collect();
        let stdin = match mode {
            "bytes" => {
                json!({"mode":mode,"encoding":"base64","data":format!("base64:{}",STANDARD.encode(&expected))})
            }
            "file" => {
                std::fs::write(tmp.path().join("input.bin"), &expected)?;
                json!({"mode":mode,"path":"input.bin"})
            }
            _ => json!({"mode":mode}),
        };
        let mut client = Client::spawn("service")?;
        client.send(1,"execute",json!({"command":[python()?,"-c","import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],"cwd":tmp.path(),"policy":"workspace-write","network":"disabled","stdin":stdin,"timeout_ms":10000}))?;
        let receipt = client.next(Duration::from_secs(2))?;
        assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut actual = Vec::new();
        let terminal = loop {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            let event = &message["params"];
            assert_eq!(event["execution_id"], receipt["result"]["execution_id"]);
            assert_eq!(event["policy_hash"], receipt["result"]["policy_hash"]);
            if event["type"] == "execution.stdout" {
                assert_eq!(event["stream_offset"], actual.len());
                let encoded = event["data"]
                    .as_str()
                    .context("output data")?
                    .strip_prefix("base64:")
                    .context("encoding")?;
                actual.extend(STANDARD.decode(encoded)?);
            }
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                break message;
            }
        };
        assert_eq!(terminal["params"]["result"]["exit_code"], 0, "{terminal}");
        assert_eq!(actual, expected, "{mode}");
        let audit_path = terminal["params"]["result"]["audit_path"]
            .as_str()
            .context("audit path")?;
        let audit = std::fs::read_to_string(tmp.path().join(audit_path))?;
        assert!(!audit.contains("input.bin"));
        if size > 0 {
            assert!(!audit.contains(&STANDARD.encode(&expected)));
        }
    }
    Ok(())
}

#[test]
fn unsubscribe_replay_and_replacement_are_ordered_without_duplicate_delivery() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn("service")?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c","import sys; out=sys.stdout.buffer; out.write(b'READY\\n'); out.flush();\nfor line in sys.stdin.buffer: out.write(line); out.flush()"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}))?;
    let receipt = client.next(Duration::from_secs(2))?;
    let execution_id = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?;
    let mut cursor = 0;
    let mut ready = Vec::new();
    while !ready.ends_with(b"\n") {
        let message = client.next(Duration::from_secs(2))?;
        let event = &message["params"];
        let sequence = event["event_seq"].as_u64().context("sequence")?;
        assert_eq!(sequence, cursor + 1);
        cursor = sequence;
        if event["type"] == "execution.stdout" {
            ready.extend(
                STANDARD.decode(
                    event["data"]
                        .as_str()
                        .context("data")?
                        .strip_prefix("base64:")
                        .context("prefix")?,
                )?,
            );
        }
    }
    for id in [2, 3] {
        client.send(
            id,
            "unsubscribeEvents",
            json!({"execution_id":execution_id}),
        )?;
        assert_eq!(
            client.next(Duration::from_secs(2))?["result"]["unsubscribed"],
            true
        );
    }
    client.send(4,"writeExecutionInput",json!({"execution_id":execution_id,"stream":"stdin","encoding":"base64","data":format!("base64:{}",STANDARD.encode(b"hidden\n"))}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["result"]["accepted_bytes"],
        7
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        client.send(5, "getExecution", json!({"execution_id":execution_id}))?;
        let query = client.next(deadline.saturating_duration_since(Instant::now()))?;
        assert_eq!(query["id"], 5, "unsubscribe must suppress live delivery");
        assert_eq!(query["result"]["status"], "running");
        if query["result"]["latest_seq"]
            .as_u64()
            .is_some_and(|seq| seq > cursor)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    client.send(
        6,
        "subscribeEvents",
        json!({"execution_id":execution_id,"after_seq":cursor}),
    )?;
    let subscribed = client.next(Duration::from_secs(2))?;
    let count = subscribed["result"]["event_count"]
        .as_u64()
        .context("replay count")?;
    assert!(count > 0);
    let mut replay = Vec::new();
    for _ in 0..count {
        let event = client.next(Duration::from_secs(2))?;
        let seq = event["params"]["event_seq"]
            .as_u64()
            .context("replay sequence")?;
        assert_eq!(seq, cursor + 1);
        cursor = seq;
        let data = event["params"]["data"]
            .as_str()
            .context("replay data")?
            .strip_prefix("base64:")
            .context("base64")?;
        replay.extend(STANDARD.decode(data)?);
    }
    assert_eq!(replay, b"hidden\n");
    for id in [7, 8] {
        client.send(id, "subscribeEvents", json!({"execution_id":execution_id}))?;
        assert_eq!(
            client.next(Duration::from_secs(2))?["result"]["event_count"],
            0
        );
    }
    client.send(9,"writeExecutionInput",json!({"execution_id":execution_id,"stream":"stdin","encoding":"base64","data":format!("base64:{}",STANDARD.encode(b"visible\n"))}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["result"]["accepted_bytes"],
        8
    );
    receive_bytes(&client, b"visible\n")?;
    client.send(10, "getVersion", json!({}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["id"],
        10,
        "replacement must not duplicate live events"
    );
    client.send(11, "cancelExecution", json!({"execution_id":execution_id}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["result"]["status"],
        "canceling"
    );
    assert_eq!(
        client.next(Duration::from_secs(10))?["params"]["type"],
        "execution.failed"
    );
    Ok(())
}

#[test]
fn evicted_history_is_reported_and_audit_queries_exclude_live_payloads() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let mut client = Client::spawn("service")?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c","import sys; out=sys.stdout.buffer; out.write(b'READY\\n'); out.flush(); sys.stdin.buffer.readline(); out.write(b'replay-secret-canary'*120000); out.flush(); sys.stdin.buffer.read()"],"cwd":tmp.path(),"policy":"danger-full-access","stdin":{"mode":"stream"}}))?;
    let receipt = client.next(Duration::from_secs(2))?;
    let execution_id = receipt["result"]["execution_id"]
        .as_str()
        .context("execution id")?;
    receive_bytes(&client, b"READY\n")?;
    client.send(2, "unsubscribeEvents", json!({"execution_id":execution_id}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["result"]["unsubscribed"],
        true
    );
    client.send(3,"writeExecutionInput",json!({"execution_id":execution_id,"stream":"stdin","encoding":"base64","data":"base64:Z28K"}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["result"]["accepted_bytes"],
        3
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        client.send(4, "getExecution", json!({"execution_id":execution_id}))?;
        let result = client.next(deadline.saturating_duration_since(Instant::now()))?;
        assert_eq!(result["id"], 4);
        if result["result"]["earliest_available_seq"]
            .as_u64()
            .is_some_and(|seq| seq > 1)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    client.send(
        5,
        "subscribeEvents",
        json!({"execution_id":execution_id,"after_seq":0}),
    )?;
    let gap = client.next(Duration::from_secs(2))?;
    assert_eq!(gap["error"]["data"]["code"], "EVENT_HISTORY_UNAVAILABLE");
    assert!(
        gap["error"]["data"]["earliest_available_seq"]
            .as_u64()
            .is_some_and(|seq| seq > 1)
    );
    client.send(
        6,
        "subscribeEvents",
        json!({"execution_id":execution_id,"after_seq":u64::MAX}),
    )?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["error"]["data"]["code"],
        "INVALID_REQUEST"
    );
    client.send(7, "getAuditEvents", json!({"execution_id":execution_id}))?;
    let audit = client.next(Duration::from_secs(2))?;
    assert!(audit.to_string().len() <= 256 * 1024);
    assert_eq!(
        audit["result"]["truncated"], false,
        "output replay eviction must not erase independently retained audit metadata"
    );
    for event in audit["result"]["events"]
        .as_array()
        .context("audit events")?
    {
        assert!(event.get("data").is_none());
    }
    assert!(!audit.to_string().contains("replay-secret-canary"));
    client.send(
        8,
        "subscribeEvents",
        json!({"execution_id":execution_id,"types":["execution.failed"]}),
    )?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["result"]["event_count"],
        0
    );
    client.send(9, "cancelExecution", json!({"execution_id":execution_id}))?;
    assert_eq!(
        client.next(Duration::from_secs(2))?["result"]["status"],
        "canceling"
    );
    let terminal = client.next(Duration::from_secs(10))?["params"].clone();
    assert_eq!(terminal["type"], "execution.failed");
    assert!(
        terminal["result"]["earliest_available_seq"]
            .as_u64()
            .is_some_and(|seq| seq > 1)
    );
    client.send(10, "getExecution", json!({"execution_id":execution_id}))?;
    let current = client.next(Duration::from_secs(2))?["result"].clone();
    assert_eq!(
        current, terminal["result"],
        "without intervening eviction, query and committed snapshot agree"
    );
    let disk = std::fs::read_to_string(
        tmp.path()
            .join(terminal["audit_path"].as_str().context("audit path")?),
    )?;
    let committed = disk
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(committed.last().context("committed terminal")?, &terminal);

    Ok(())
}

#[test]
fn required_audit_failure_rejects_before_receipt_and_child_spawn() -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    std::fs::create_dir(tmp.path().join(".runseal"))?;
    std::fs::write(tmp.path().join(".runseal/audit"), b"not a directory")?;
    let marker = tmp.path().join("started");
    let mut client = Client::spawn("service")?;
    client.send(1, "execute", json!({"command":[python()?,"-c","import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('started')",marker],"cwd":tmp.path(),"policy":"danger-full-access"}))?;
    let response = client.next(Duration::from_secs(2))?;
    assert_eq!(response["id"], 1);
    assert_eq!(response["error"]["data"]["code"], "INTERNAL_ERROR");
    assert_eq!(
        response["error"]["data"]["durable_record_missing"], true,
        "{response}"
    );
    assert!(response.get("result").is_none());
    assert!(
        !response
            .to_string()
            .contains(&tmp.path().to_string_lossy().to_string())
    );
    client.send(2, "getVersion", json!({}))?;
    assert_eq!(client.next(Duration::from_secs(2))?["id"], 2);
    assert!(!marker.exists());
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn live_event_sequence_and_unique_terminal_match_committed_audit() -> Result<()> {
    let _guard = process_test_gate();
    for (policy, cancel) in [
        ("danger-full-access", false),
        ("workspace-write", false),
        ("danger-full-access", true),
        ("workspace-write", true),
    ] {
        let tmp = TempDir::new()?;
        let mut client = Client::spawn("service")?;
        let command = if cancel {
            "import os,time; os.write(1,b'live-secret-canary'); time.sleep(60)"
        } else {
            "import os; os.write(1,b'live-secret-canary'); os.write(2,b'other-secret-canary')"
        };
        client.send(
            1,
            "execute",
            json!({"command":[python()?,"-u","-c",command],"cwd":tmp.path(),"policy":policy,"metadata":{"authorization":"metadata-secret-canary","client":"conformance"}}),
        )?;
        let receipt = client.next(Duration::from_secs(2))?;
        assert_eq!(receipt["result"]["status"], "preparing");
        let id = receipt["result"]["execution_id"]
            .as_str()
            .context("execution ID")?;
        let mut live = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let terminal = loop {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            if message["id"] == 2 {
                assert_eq!(message["result"]["status"], "canceling");
                continue;
            }
            let event = message["params"].clone();
            assert_eq!(
                event["event_seq"],
                live.len() + 1,
                "owner sequence must be contiguous: {event}"
            );
            live.push(event.clone());
            if cancel && event["type"] == "execution.stdout" {
                client.send(2, "cancelExecution", json!({"execution_id":id}))?;
            }

            if event["type"] == "execution.finished" || event["type"] == "execution.failed" {
                break event;
            }
        };
        assert_eq!(
            terminal["type"],
            if cancel {
                "execution.failed"
            } else {
                "execution.finished"
            },
            "{terminal}"
        );
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        assert_eq!(terminal["result"]["latest_seq"], terminal["event_seq"]);
        let audit = std::fs::read_to_string(
            tmp.path()
                .join(terminal["audit_path"].as_str().context("audit path")?),
        )?;
        assert!(!audit.contains("secret-canary"));
        let committed = audit
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(committed.len(), live.len());
        for (event, audit_event) in live.iter_mut().zip(&committed) {
            if let Some(object) = event.as_object_mut() {
                object.remove("data");
                object.remove("text");
            }
            assert!(event.get("metadata").is_none());
            assert_eq!(audit_event["metadata"]["authorization"], "[REDACTED]");
            let mut common = audit_event.clone();
            common
                .as_object_mut()
                .context("audit event")?
                .remove("metadata");
            assert_eq!(
                event, &common,
                "live and audit must describe the same numbered event"
            );
        }
        assert_eq!(
            committed
                .iter()
                .filter(|event| matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ))
                .count(),
            1
        );
        client.send(3, "getExecution", json!({"execution_id":id}))?;
        let queried = client.next(Duration::from_secs(2))?["result"].clone();
        assert_eq!(queried, terminal["result"]);
        client.send(4, "getAuditEvents", json!({"execution_id":id}))?;
        let audit_query = client.next(Duration::from_secs(2))?;
        assert_eq!(
            audit_query["result"]["events"],
            json!(committed),
            "audit query must include the same redacted metadata and committed terminal as disk"
        );
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn dispose_session_waits_for_owned_range_and_runtime_cleanup_without_stopping_peer() -> Result<()> {
    let _guard = process_test_gate();
    for (mode, policy) in [
        ("service", "danger-full-access"),
        ("service", "workspace-write"),
        ("rpc", "danger-full-access"),
        ("rpc", "workspace-write"),
    ] {
        let tmp = TempDir::new()?;
        let mut client = Client::spawn(mode)?;
        let mut fixture = HeartbeatFixture {
            directory: tmp.path().to_owned(),
            pids: Vec::new(),
        };
        let child_code = "import pathlib,sys,time; target=pathlib.Path(sys.argv[1]); stop=pathlib.Path(sys.argv[1]+'.stop'); count=0\nwhile not stop.exists():\n count+=1; target.write_text(str(count)); time.sleep(0.01)";
        let root_code = "import pathlib,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-u','-c',sys.argv[1],sys.argv[2]]); target=pathlib.Path(sys.argv[2]);\nwhile not target.exists():\n if child.poll() is not None: sys.exit(2)\n time.sleep(0.01)\nprint('READY '+str(child.pid),flush=True); sys.stdin.buffer.read()";
        let mut executions = Vec::new();
        for (request_id, name) in [(1, "first"), (2, "peer")] {
            client.send(request_id,"execute",json!({"command":[python()?,"-u","-c",root_code,child_code,name],"cwd":tmp.path(),"policy":policy,"stdin":{"mode":"stream"}}))?;
            let receipt = client.next(Duration::from_secs(2))?;
            assert_eq!(receipt["id"], request_id);
            let id = receipt["result"]["execution_id"]
                .as_str()
                .context("execution ID")?
                .to_owned();
            let session = receipt["result"]["session_id"]
                .as_str()
                .context("session ID")?
                .to_owned();
            let pid = wait_ready_pid(&client, &id)?;
            fixture.pids.push(pid);
            executions.push((id, session, pid));
        }
        let runtime = tmp.path().join(".runseal/runtime").join(&executions[0].0);
        if policy == "workspace-write" {
            assert!(runtime.exists(), "sandbox runtime was actually allocated");
        }
        let counter = || {
            std::fs::read_to_string(tmp.path().join("peer"))
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
        };
        let before = counter();
        client.send(3, "disposeSession", json!({"session_id":executions[0].1}))?;
        client.send(4,"writeExecutionInput",json!({"execution_id":executions[0].0,"stream":"stdin","encoding":"base64","data":"base64:eA=="}))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut disposed = false;
        let mut rejected_input = false;
        while !disposed || !rejected_input {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            if message["id"] == 3 {
                assert_eq!(message["result"]["cleanup_complete"], true, "{message}");
                assert_eq!(message["result"]["released_executions"], 1);
                assert!(
                    !process_present(executions[0].2)?,
                    "cleanup success must follow actual range removal"
                );
                assert!(
                    !runtime.exists(),
                    "cleanup success must follow runtime-root removal"
                );
                disposed = true;
            }
            if message["id"] == 4 {
                assert!(
                    matches!(
                        message["error"]["data"]["code"].as_str(),
                        Some("EXECUTION_NOT_RUNNING" | "EXECUTION_NOT_FOUND")
                    ),
                    "disposal stops accepting input: {message}"
                );
                rejected_input = true;
            }
        }
        assert!(
            process_present(executions[1].2)?,
            "another session on this connection remains live"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        let after = loop {
            let observed = counter();
            if observed > before || Instant::now() >= deadline {
                break observed;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            after > before,
            "peer heartbeat continues after session disposal"
        );
        client.send(5, "disposeSession", json!({"session_id":executions[0].1}))?;
        let repeated = client.next(Duration::from_secs(2))?;
        assert_eq!(
            repeated["id"], 5,
            "released subscription cannot deliver stale events"
        );
        assert_eq!(repeated["result"]["cleanup_complete"], true);
        assert_eq!(repeated["result"]["released_executions"], 0);
        client.send(
            6,
            "cancelExecution",
            json!({"execution_id":executions[1].0}),
        )?;
        assert_eq!(client.next(Duration::from_secs(2))?["id"], 6);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            if message["params"]["execution_id"] == executions[1].0
                && message["params"]["type"] == "execution.failed"
            {
                assert_eq!(message["params"]["result"]["cleanup_complete"], true);
                break;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn local_completion_drains_output_with_foreign_pipe_handles_without_stopping_peer() -> Result<()> {
    let _guard = process_test_gate();
    for stdin_mode in ["empty", "file"] {
        let tmp = TempDir::new()?;
        struct Peer(std::process::Child);
        impl Drop for Peer {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut peer = Peer(
            Command::new(python()?)
                .args(["-u", "-c", "import sys; sys.stdin.buffer.read()"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        let code = "import ctypes,ctypes.wintypes as w,os,sys; k=ctypes.WinDLL('kernel32',use_last_error=True); k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD]; k.OpenProcess.restype=w.HANDLE; k.GetCurrentProcess.restype=w.HANDLE; k.GetStdHandle.argtypes=[w.DWORD]; k.GetStdHandle.restype=w.HANDLE; k.DuplicateHandle.argtypes=[w.HANDLE,w.HANDLE,w.HANDLE,ctypes.POINTER(w.HANDLE),w.DWORD,w.BOOL,w.DWORD]; k.DuplicateHandle.restype=w.BOOL; k.CloseHandle.argtypes=[w.HANDLE]; target=k.OpenProcess(0x40,False,int(sys.argv[1])); duplicate=w.HANDLE(); assert target,ctypes.get_last_error(); assert k.DuplicateHandle(k.GetCurrentProcess(),k.GetStdHandle(int(sys.argv[2])),target,ctypes.byref(duplicate),0,False,2),ctypes.get_last_error(); k.CloseHandle(target); os.write(1,b'P'*131072)";
        let file = tmp.path().join("input.bin");
        std::fs::write(&file, vec![b'I'; 131072])?;
        let stdin = if stdin_mode == "file" {
            json!({"mode":"file","path":file})
        } else {
            json!({"mode":"empty"})
        };
        let mut client = Client::spawn("service")?;
        client.send(1,"execute",json!({"command":[python()?,"-u","-c",code,peer.0.id().to_string(),if stdin_mode=="file" {"-10"} else {"-11"}],"cwd":tmp.path(),"policy":"danger-full-access","stdin":stdin}))?;
        let receipt = client.next(Duration::from_secs(2))?;
        assert_eq!(receipt["result"]["status"], "preparing");
        let mut bytes = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let terminal = loop {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            let event = &message["params"];
            if event["type"] == "execution.stdout" {
                assert_eq!(event["stream_offset"], bytes.len());
                bytes.extend(
                    STANDARD.decode(
                        event["data"]
                            .as_str()
                            .and_then(|data| data.strip_prefix("base64:"))
                            .context("output bytes")?,
                    )?,
                );
            }
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                break event["result"].clone();
            }
        };
        assert_eq!(terminal["status"], "finished", "{terminal}");
        assert_eq!(terminal["cleanup_complete"], true);
        assert_eq!(terminal["exit_code"], 0);
        assert_eq!(bytes, vec![b'P'; 131072]);
        assert_eq!(terminal["stdout_bytes"], bytes.len());
        assert!(
            peer.0.try_wait()?.is_none(),
            "foreign process remains live and keeps its duplicated pipe reference"
        );
        assert!(process_present(peer.0.id())?);
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn started_event_requires_real_spawn_and_precedes_child_output() -> Result<()> {
    let _guard = process_test_gate();
    for policy in ["danger-full-access", "workspace-write"] {
        for launches in [false, true] {
            let tmp = TempDir::new()?;
            let command = if launches {
                json!([python()?, "-u", "-c", "print('real-start', flush=True)"])
            } else {
                json!([tmp.path().join("absent-command.exe")])
            };
            let mut client = Client::spawn("service")?;
            client.send(
                1,
                "execute",
                json!({"command":command,"cwd":tmp.path(),"policy":policy}),
            )?;
            let receipt = client.next(Duration::from_secs(10))?;
            assert_eq!(receipt["id"], 1, "{receipt}");
            assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
            let execution_id = receipt["result"]["execution_id"].clone();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut started = None;
            let mut output = Vec::new();
            let terminal = loop {
                let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
                let event = &message["params"];
                assert_eq!(event["execution_id"], execution_id);
                match event["type"].as_str() {
                    Some("execution.started") => {
                        assert!(started.is_none(), "duplicate started event");
                        started = Some(event.clone());
                    }
                    Some("execution.stdout") => {
                        assert!(
                            started.is_some(),
                            "child output preceded start confirmation: {policy}, {message}"
                        );
                        assert_eq!(event["stream_offset"], output.len());
                        output.extend(
                            STANDARD.decode(
                                event["data"]
                                    .as_str()
                                    .and_then(|data| data.strip_prefix("base64:"))
                                    .context("output bytes")?,
                            )?,
                        );
                    }
                    Some("execution.finished" | "execution.failed") => break event.clone(),
                    _ => {}
                }
            };
            let audit_path = terminal["result"]["audit_path"]
                .as_str()
                .context("audit path")?;
            let audit = std::fs::read_to_string(tmp.path().join(audit_path))?
                .lines()
                .map(serde_json::from_str::<Value>)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let audit_started: Vec<_> = audit
                .iter()
                .filter(|event| event["type"] == "execution.started")
                .collect();
            if launches {
                let started = started.context("confirmed start")?;
                assert_eq!(terminal["result"]["status"], "finished", "{terminal}");
                assert_eq!(terminal["result"]["exit_code"], 0);
                assert_eq!(terminal["result"]["started_at"], started["time"]);
                assert_eq!(output, b"real-start\r\n");
                assert_eq!(audit_started, vec![&started]);
            } else {
                assert!(started.is_none(), "start failure published started");
                assert!(audit_started.is_empty(), "start failure committed started");
                assert!(terminal["result"]["started_at"].is_null());
                assert!(terminal["result"]["exit_code"].is_null());
                assert_eq!(
                    terminal["result"]["error"]["code"],
                    "EXECUTION_FAILED_TO_START"
                );
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn sandboxed_pty_has_real_console_dimensions_and_merged_binary_events() -> Result<()> {
    pty_console_case("workspace-write")
}

#[cfg(windows)]
#[test]
fn local_pty_has_real_console_dimensions_and_merged_binary_events() -> Result<()> {
    pty_console_case("danger-full-access")
}

#[cfg(windows)]
fn pty_console_case(policy: &str) -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let code = "import os,sys; assert os.isatty(0) and os.isatty(1) and os.isatty(2); size=os.get_terminal_size(1); print('PTY_READY:%s:%s'%(size.columns,size.lines),flush=True); print('PTY_STDERR',file=sys.stderr,flush=True); line=sys.stdin.readline(); size=os.get_terminal_size(1); print('PTY_RESIZED:%s:%s'%(size.columns,size.lines),flush=True); print('PTY_ACK:'+line.strip(),flush=True)";
    let mut client = Client::spawn("service")?;
    client.send(1,"execute",json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":policy,"stdin":{"mode":"stream"},"io":{"mode":"pty","rows":17,"cols":101}}))?;
    let receipt = client.next(Duration::from_secs(15))?;
    assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
    let execution_id = receipt["result"]["execution_id"].clone();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut bytes = Vec::new();
    let mut wrote = false;
    let mut start_time = Value::Null;
    let mut query_seen = false;
    let mut resize_seen = false;
    let mut eof_refused = false;
    let terminal = loop {
        let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
        if message.get("id").is_some() {
            if message["id"] == 5 {
                assert_eq!(
                    message["error"]["data"]["code"],
                    "BACKEND_CAPABILITY_MISSING"
                );
                eof_refused = true;
                continue;
            }
            assert!(message.get("error").is_none(), "{message}");
            if message["id"] == 4 {
                assert_eq!(message["result"]["accepted"], true);
                resize_seen = true;
            }
            if message["id"] == 3 {
                assert_eq!(message["result"]["status"], "running");
                assert_eq!(message["result"]["started_at"], start_time);
                query_seen = true;
            }
            continue;
        }
        let event = &message["params"];
        assert_eq!(event["execution_id"], execution_id);
        match event["type"].as_str() {
            Some("execution.started") => {
                start_time = event["time"].clone();
            }
            Some("execution.terminal") => {
                assert!(!start_time.is_null());
                assert_eq!(event["stream_offset"], bytes.len());
                let chunk = STANDARD.decode(
                    event["data"]
                        .as_str()
                        .and_then(|data| data.strip_prefix("base64:"))
                        .context("terminal bytes")?,
                )?;
                assert_eq!(event["bytes"], chunk.len());
                bytes.extend(chunk);
                if !wrote && String::from_utf8_lossy(&bytes).contains("PTY_READY:101:17") {
                    client.send(
                        5,
                        "closeExecutionInput",
                        json!({"execution_id":execution_id,"stream":"stdin"}),
                    )?;
                    client.send(3, "getExecution", json!({"execution_id":execution_id}))?;
                    client.send(
                        4,
                        "resizeExecution",
                        json!({"execution_id":execution_id,"rows":41,"cols":123}),
                    )?;
                    client.send(2,"writeExecutionInput",json!({"execution_id":execution_id,"stream":"stdin","encoding":"base64","data":"base64:aGVsbG8NCg=="}))?;
                    wrote = true;
                }
            }
            Some("execution.stdout" | "execution.stderr") => {
                panic!("PTY output was split into pipe streams: {event}")
            }
            Some("execution.finished" | "execution.failed") => break event.clone(),
            _ => {}
        }
    };
    assert!(query_seen && resize_seen && eof_refused);
    assert!(
        wrote,
        "PTY never became ready: {}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(terminal["result"]["status"], "finished", "{terminal}");
    assert_eq!(terminal["result"]["exit_code"], 0);
    assert_eq!(terminal["result"]["cleanup_complete"], true);
    assert_eq!(
        terminal["result"]["sandbox"]["enforced"],
        policy != "danger-full-access"
    );
    assert_eq!(terminal["result"]["stderr_merged"], true);
    assert_eq!(terminal["result"]["terminal_bytes"], bytes.len());
    assert_eq!(terminal["result"]["stdout_bytes"], 0);
    assert_eq!(terminal["result"]["stderr_bytes"], 0);
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("PTY_STDERR"), "{text}");
    assert!(text.contains("PTY_ACK:hello"), "{text}");
    assert!(text.contains("PTY_RESIZED:123:41"), "{text}");
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn pty_interrupt_stops_foreground_task_and_keeps_shell_and_peer_alive() -> Result<()> {
    pty_interrupt_case("workspace-write")
}

#[cfg(windows)]
#[test]
fn local_pty_interrupt_keeps_shell_and_peer_alive() -> Result<()> {
    pty_interrupt_case("danger-full-access")
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn cli_native_file_output_preserves_binary_streams_and_child_exit() -> Result<()> {
    use std::io::{Read, Seek};
    let _guard = process_test_gate();
    for policy in ["danger-full-access", "workspace-write"] {
        let tmp = TempDir::new()?;
        let mut stdout = tempfile::tempfile()?;
        let mut stderr = tempfile::tempfile()?;
        let status = Command::new(env!("CARGO_BIN_EXE_runseal"))
            .args(["exec", "--policy", policy, "--cwd"])
            .arg(tmp.path())
            .args(["--", &python()?, "-u", "-c", "import os,sys; data=bytes(range(256)); os.write(1,data*516); os.write(2,data[::-1]*260); sys.exit(7)"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone()?))
            .stderr(Stdio::from(stderr.try_clone()?))
            .status()?;
        assert_eq!(status.code(), Some(7));
        stdout.rewind()?;
        stderr.rewind()?;
        let mut actual_stdout = Vec::new();
        let mut actual_stderr = Vec::new();
        stdout.read_to_end(&mut actual_stdout)?;
        stderr.read_to_end(&mut actual_stderr)?;
        assert_eq!(actual_stdout, (0..=255u8).collect::<Vec<_>>().repeat(516));
        assert_eq!(
            actual_stderr,
            (0..=255u8).rev().collect::<Vec<_>>().repeat(260)
        );
        let files = std::fs::read_dir(tmp.path().join(".runseal/audit"))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(files.len(), 1);
        let events = std::fs::read_to_string(files[0].path())?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ))
                .count(),
            1
        );
        let terminal = events.last().context("file output terminal")?;
        assert_eq!(terminal["result"]["exit_code"], 7);
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        assert_eq!(terminal["result"]["stdout_bytes"], actual_stdout.len());
        assert_eq!(terminal["result"]["stderr_bytes"], actual_stderr.len());
        assert_eq!(
            terminal["result"]["sandbox"]["enforced"],
            policy != "danger-full-access"
        );
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn sandboxed_stalled_console_output_cleans_owned_range_and_preserves_peer() -> Result<()> {
    cli_stalled_console_output_for_policy("workspace-write")
}

#[cfg(windows)]
#[test]
fn cli_stalled_console_output_cleans_owned_range_and_preserves_peer() -> Result<()> {
    cli_stalled_console_output_for_policy("danger-full-access")
}

#[cfg(windows)]
fn cli_stalled_console_output_for_policy(policy: &str) -> Result<()> {
    use std::io::Read;
    let _guard = process_test_gate();
    for (stream, timeout) in [1, 2]
        .into_iter()
        .flat_map(|stream| [false, true].map(move |timeout| (stream, timeout)))
    {
        let tmp = TempDir::new()?;
        let runner_log_offset = console_runner_log_offset(tmp.path());
        let mut peer_client = Client::spawn("service")?;
        peer_client.send(1,"execute",json!({"command":[python()?,"-u","-c","import os,pathlib,time; print('READY '+str(os.getpid()),flush=True); count=0\nwhile True:\n count+=1; pathlib.Path('console-peer.beat').write_text(str(count)); time.sleep(0.01)"],"cwd":tmp.path(),"policy":policy}))?;
        let receipt = peer_client.next(Duration::from_secs(2))?;
        let peer = receipt["result"]["execution_id"]
            .as_str()
            .with_context(|| format!("peer receipt: {receipt}"))?
            .to_owned();
        let peer_pid = wait_ready_pid(&peer_client, &peer)?;
        let child_code = format!(
            "import os,pathlib,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']); pathlib.Path('console.ready.tmp').write_text(str(os.getpid())+' '+str(child.pid)); pathlib.Path('console.ready.tmp').replace('console.ready')\nwhile not pathlib.Path('console.go').exists(): time.sleep(0.005)\nwhile True: os.write({stream},b'Z'*65536)"
        );
        let driver_code = "import json,pathlib,subprocess,sys; child=subprocess.Popen(sys.argv[1:]); started=pathlib.Path('console.cli.tmp'); started.write_text(str(child.pid)); started.replace('console.cli'); code=child.wait(); path=pathlib.Path('console.done.tmp'); path.write_text(json.dumps({'pid':child.pid,'exit':code})); path.replace('console.done'); sys.exit(0)";
        let command = vec![
            python()?,
            "-u".into(),
            "-c".into(),
            driver_code.into(),
            env!("CARGO_BIN_EXE_runseal").into(),
            "exec".into(),
            "--timeout-ms".into(),
            if timeout { "10000" } else { "20000" }.into(),
            "--policy".into(),
            policy.into(),
            "--cwd".into(),
            tmp.path().to_string_lossy().into_owned(),
            "--".into(),
            python()?,
            "-u".into(),
            "-c".into(),
            child_code,
        ];
        let mut environment = std::env::vars().collect::<std::collections::HashMap<_, _>>();
        environment.insert(
            "RUNSEAL_BACKPRESSURE_MS".into(),
            if timeout { "15000" } else { "3000" }.into(),
        );
        let mut driver = codex_windows_sandbox::LocalExecutionProcess::spawn_with_terminal(
            &command,
            tmp.path(),
            &environment,
            true,
            Some((24, 80)),
        )?;
        let mut output = driver.stdout.take().context("console output")?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !tmp.path().join("console.ready").exists() {
            assert!(Instant::now() < deadline, "console execution readiness");
            std::thread::sleep(Duration::from_millis(5));
        }
        let pids = std::fs::read_to_string(tmp.path().join("console.ready"))?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(pids.len(), 2);
        let _fixture = HeartbeatFixture {
            directory: tmp.path().to_owned(),
            pids: [pids.clone(), vec![peer_pid]].concat(),
        };
        assert!(
            pids.iter()
                .all(|pid| process_present(*pid).unwrap_or(false))
        );
        std::fs::write(tmp.path().join("console.go"), b"G")?;
        // Retain the outer terminal read endpoint without consuming any output.
        let deadline = Instant::now() + Duration::from_secs(30);
        while !tmp.path().join("console.done").exists() {
            if Instant::now() >= deadline {
                let driver_exited = driver.try_wait()?.is_some();
                let command_running = std::fs::read_to_string(tmp.path().join("console.cli"))
                    .ok()
                    .and_then(|pid| pid.parse::<u32>().ok())
                    .is_some_and(|pid| process_present(pid).unwrap_or(false));
                let sandbox_processes_running = pids
                    .iter()
                    .filter(|pid| process_present(**pid).unwrap_or(false))
                    .count();
                let terminals = read_console_terminal_summary(tmp.path());
                let runner_stage = read_console_runner_cleanup_stage(tmp.path(), runner_log_offset);
                anyhow::bail!(
                    "stalled Console CLI cleanup did not finish for {policy} (driver_exited={driver_exited}, command_running={command_running}, sandbox_processes_running={sandbox_processes_running}, terminal={terminals}, runner_stage={runner_stage})"
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let done: Value =
            serde_json::from_str(&std::fs::read_to_string(tmp.path().join("console.done"))?)?;
        assert!(!process_present(
            done["pid"].as_u64().context("CLI PID")? as u32
        )?);
        for pid in pids {
            assert!(!process_present(pid)?);
        }
        let mut terminals = Vec::new();
        for file in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
            for event in std::fs::read_to_string(file?.path())?
                .lines()
                .map(serde_json::from_str::<Value>)
            {
                let event = event?;
                if matches!(
                    event["type"].as_str(),
                    Some("execution.failed" | "execution.finished")
                ) {
                    terminals.push(event);
                }
            }
        }
        assert_eq!(terminals.len(), 1, "expected one terminal audit event");
        let terminal = &terminals[0];
        assert_eq!(
            done["exit"],
            if timeout { 124 } else { 125 },
            "unexpected CLI exit code for {policy}"
        );
        assert_eq!(
            terminal["result"]["error"]["code"],
            if timeout {
                "EXECUTION_TIMEOUT"
            } else {
                "CLIENT_BACKPRESSURE"
            },
            "unexpected terminal error for {policy}"
        );
        assert_eq!(
            terminal["result"]["termination_reason"],
            if timeout { "timeout" } else { "backpressure" },
            "unexpected termination reason for {policy}"
        );
        assert_eq!(
            terminal["result"]["cleanup_complete"], true,
            "cleanup should complete for {policy}"
        );
        assert!(
            !tmp.path()
                .join(".runseal/runtime")
                .join(terminal["execution_id"].as_str().context("execution")?)
                .exists()
        );
        assert!(process_present(peer_pid)?);
        let before =
            std::fs::read_to_string(tmp.path().join("console-peer.beat")).unwrap_or_default();
        let deadline = Instant::now() + Duration::from_secs(2);
        while std::fs::read_to_string(tmp.path().join("console-peer.beat")).unwrap_or_default()
            == before
        {
            assert!(Instant::now() < deadline, "console peer heartbeat");
            std::thread::sleep(Duration::from_millis(5));
        }
        // Once the result is proven, drain the fixture's terminal to close it.
        let close = driver.close_terminal();
        let deadline = Instant::now() + Duration::from_secs(5);
        while driver.try_wait()?.is_none()
            || close.as_ref().is_some_and(|worker| !worker.is_finished())
        {
            if let Some(available) = codex_windows_sandbox::available_pipe_bytes(&output)?
                && available > 0
            {
                let mut chunk = vec![0; available.min(64 * 1024)];
                let _ = output.read(&mut chunk)?;
            }
            assert!(Instant::now() < deadline, "console fixture shutdown");
            std::thread::sleep(Duration::from_millis(5));
        }
        if let Some(close) = close {
            close
                .join()
                .map_err(|_| anyhow::anyhow!("console close panic"))??;
        }
        assert_eq!(driver.finish(Duration::from_secs(2))?, 0);
        peer_client.send(9, "cancelExecution", json!({"execution_id":peer}))?;
        loop {
            let message = peer_client.next(Duration::from_secs(10))?;
            if message["params"]["execution_id"] == peer
                && message["params"]["type"] == "execution.failed"
            {
                assert_eq!(message["params"]["result"]["cleanup_complete"], true);
                break;
            }
        }
        assert!(!process_present(peer_pid)?);
    }
    Ok(())
}

#[cfg(windows)]
fn read_console_terminal_summary(workspace: &std::path::Path) -> String {
    let Ok(files) = std::fs::read_dir(workspace.join(".runseal/audit")) else {
        return "unavailable".to_string();
    };
    let mut results = Vec::new();
    for file in files.flatten() {
        let Ok(contents) = std::fs::read_to_string(file.path()) else {
            continue;
        };
        for event in contents
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        {
            if matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                results.push(format!(
                    "{}:{}:{}:exit={}:timed_out={}",
                    event["result"]["termination_reason"]
                        .as_str()
                        .unwrap_or("unknown"),
                    event["result"]["error"]["code"].as_str().unwrap_or("none"),
                    event["result"]["cleanup_complete"]
                        .as_bool()
                        .map_or("unknown", |complete| if complete {
                            "true"
                        } else {
                            "false"
                        }),
                    event["result"]["exit_code"],
                    event["result"]["timed_out"]
                ));
            }
        }
    }
    if results.is_empty() {
        "none".to_string()
    } else {
        results.join(",")
    }
}

#[cfg(windows)]
fn console_runner_log_path(workspace: &std::path::Path) -> std::path::PathBuf {
    let sandbox_home = std::env::var_os("RUNSEAL_WINDOWS_SANDBOX_HOME")
        .map(|home| {
            let home = std::path::PathBuf::from(home);
            if home.is_absolute() {
                home
            } else {
                workspace.join(home)
            }
        })
        .or_else(|| {
            std::env::var_os("LOCALAPPDATA").map(|root| {
                std::path::PathBuf::from(root)
                    .join("RunSeal")
                    .join("windows-sandbox")
            })
        })
        .unwrap_or_else(|| workspace.join(".runseal").join("sandbox"));
    codex_windows_sandbox::current_log_file_path_for_codex_home(&sandbox_home)
}

#[cfg(windows)]
fn console_runner_log_offset(workspace: &std::path::Path) -> u64 {
    std::fs::metadata(console_runner_log_path(workspace))
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

#[cfg(windows)]
fn read_console_runner_cleanup_stage(workspace: &std::path::Path, offset: u64) -> String {
    let Ok(contents) = std::fs::read(console_runner_log_path(workspace)) else {
        return "unavailable".to_owned();
    };
    let fresh = contents.get(offset as usize..).unwrap_or(&contents);
    let prefix = "runner cleanup failed at stage: ";
    for line in fresh.rsplit(|byte| *byte == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        let Some((_, stage)) = line.split_once(prefix) else {
            continue;
        };
        let stage = stage.trim();
        return match stage {
            "cleanup_announcement"
            | "control_workers"
            | "runner_report"
            | "parent_input_writer"
            | "process_range"
            | "exit_status"
            | "conpty_close"
            | "controls_reader"
            | "stdin_writer"
            | "stdout_reader"
            | "stderr_reader" => stage.to_owned(),
            _ => "unknown".to_owned(),
        };
    }
    "none".to_owned()
}

#[cfg(windows)]
#[test]
fn cli_local_console_slow_progress_preserves_surrogate_boundaries_and_native_exit() -> Result<()> {
    cli_console_paced_case(true)
}

#[cfg(windows)]
#[test]
fn cli_local_console_cleanup_deadline_bounds_delivery_after_native_exit() -> Result<()> {
    cli_console_paced_case(false)
}

#[cfg(windows)]
fn cli_console_paced_case(hold_until_consumed: bool) -> Result<()> {
    use std::io::Read;
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let driver_code = r#"import ctypes,json,pathlib,subprocess,sys,threading,time
k=ctypes.WinDLL('kernel32',use_last_error=True)
k.GetTickCount64.restype=ctypes.c_uint64
k.OpenProcess.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong]
k.OpenProcess.restype=ctypes.c_void_p
k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_ulong]
k.GetExitCodeProcess.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ulong)]
k.CloseHandle.argtypes=[ctypes.c_void_p]
assert k.SetConsoleOutputCP(437)
before=k.GetConsoleOutputCP()
state={}
def observe_exit():
 while not pathlib.Path('paced.ready').exists(): time.sleep(0.005)
 handle=k.OpenProcess(0x100000|0x1000,False,int(pathlib.Path('paced.ready').read_text()))
 assert handle
 pathlib.Path('paced.watch.ready').write_text('READY')
 try:
  assert k.WaitForSingleObject(handle,60000)==0
  state['native_exit_tick']=k.GetTickCount64()
  code=ctypes.c_ulong()
  assert k.GetExitCodeProcess(handle,ctypes.byref(code))
  state['native_exit_code']=code.value
 finally: k.CloseHandle(handle)
watcher=threading.Thread(target=observe_exit,daemon=True)
watcher.start()
result=subprocess.run(sys.argv[1:])
finished_tick=k.GetTickCount64()
watcher.join(2)
assert not watcher.is_alive()
pathlib.Path('paced.done').write_text(json.dumps(dict(state,exit=result.returncode,before=before,after=k.GetConsoleOutputCP(),finished_tick=finished_tick)))
sys.exit(result.returncode)
"#;
    let child_code = r#"import os,pathlib,sys,time
ready=pathlib.Path('paced.ready.tmp')
ready.write_text(str(os.getpid()))
ready.replace('paced.ready')
while not pathlib.Path('paced.go').exists(): time.sleep(0.005)
count=24 if sys.argv[1]=='hold' else 4096
data=''.join('X'*1023+chr(0x1f600+i) for i in range(count))+'END'
if sys.argv[1]=='hold':
 os.write(1,data.encode('utf-8'))
else:
 os.set_blocking(1,False)
 try: os.write(1,data.encode('utf-8'))
 except OSError: pass
while sys.argv[1]=='hold' and not pathlib.Path('paced.release').exists(): time.sleep(0.005)
os._exit(7)
"#;
    let command = vec![
        python()?,
        "-u".into(),
        "-c".into(),
        driver_code.into(),
        env!("CARGO_BIN_EXE_runseal").into(),
        "exec".into(),
        "--policy".into(),
        "danger-full-access".into(),
        "--cwd".into(),
        tmp.path().to_string_lossy().into_owned(),
        "--".into(),
        python()?,
        "-u".into(),
        "-c".into(),
        child_code.into(),
        if hold_until_consumed { "hold" } else { "exit" }.into(),
    ];
    let mut environment = std::env::vars().collect::<std::collections::HashMap<_, _>>();
    if !hold_until_consumed {
        environment.insert("RUNSEAL_BACKPRESSURE_MS".into(), "500".into());
    }
    let mut driver = codex_windows_sandbox::LocalExecutionProcess::spawn_with_terminal(
        &command,
        tmp.path(),
        &environment,
        true,
        Some((24, 80)),
    )?;
    let mut output = driver.stdout.take().context("paced Console output")?;
    let ready_deadline = Instant::now() + Duration::from_secs(10);
    while !tmp.path().join("paced.ready").exists() || !tmp.path().join("paced.watch.ready").exists()
    {
        assert!(Instant::now() < ready_deadline, "paced Console readiness");
        std::thread::sleep(Duration::from_millis(5));
    }
    let child_pid: u32 = std::fs::read_to_string(tmp.path().join("paced.ready"))?.parse()?;
    let _fixture = HeartbeatFixture {
        directory: tmp.path().to_owned(),
        pids: vec![child_pid],
    };
    let start = Instant::now();
    std::fs::write(tmp.path().join("paced.go"), b"G")?;
    let deadline = start + Duration::from_secs(80);
    let mut bytes = Vec::new();
    let mut pulses = 0;
    while driver.try_wait()?.is_none() {
        if let Some(available) = codex_windows_sandbox::available_pipe_bytes(&output)?
            && available > 0
        {
            let mut buffer = vec![0; available.min(1024)];
            let count = output.read(&mut buffer)?;
            assert!(count > 0, "retained consumer must receive actual bytes");
            bytes.extend_from_slice(&buffer[..count]);
            if bytes.windows(3).any(|window| window == b"END") {
                // Keep execution active during paced transfer; only confirmed
                // consumer delivery releases the child's natural exit gate.
                std::fs::write(tmp.path().join("paced.release"), b"G")?;
            }
            pulses += 1;
            std::thread::sleep(Duration::from_millis(1500));
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            Instant::now() < deadline,
            "paced Console execution watchdog"
        );
    }
    let exit = driver.finish(Duration::from_secs(2))?;
    drop(driver.stdin.take());
    if let Some(close) = driver.close_terminal() {
        let close_deadline = Instant::now() + Duration::from_secs(2);
        while !close.is_finished() {
            if let Some(available) = codex_windows_sandbox::available_pipe_bytes(&output)?
                && available > 0
            {
                let mut buffer = vec![0; available.min(64 * 1024)];
                let count = output.read(&mut buffer)?;
                bytes.extend_from_slice(&buffer[..count]);
            }
            assert!(
                Instant::now() < close_deadline,
                "paced Console close watchdog"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        close
            .join()
            .map_err(|_| anyhow::anyhow!("paced Console close panic"))??;
    }
    output.read_to_end(&mut bytes)?;
    if hold_until_consumed {
        assert_eq!(exit, 7);
        assert!(
            pulses >= 4 && start.elapsed() > Duration::from_secs(5),
            "actual paced reads required"
        );
    } else {
        assert!(
            matches!(exit, 7 | 125),
            "unexpected bounded-delivery exit: {exit}, pulses={pulses}, elapsed={:?}, bytes={}",
            start.elapsed(),
            bytes.len()
        );
        assert!(pulses > 0, "actual console output required");
    }
    let rendered = String::from_utf8_lossy(&bytes);
    // ConPTY may repeat cells for cursor repair. Distinct supplementary
    // characters prove none disappeared without mistaking redraws for bytes.
    if hold_until_consumed {
        for codepoint in 0x1f600..0x1f618 {
            assert!(rendered.contains(char::from_u32(codepoint).context("fixture character")?));
        }
        assert!(rendered.matches('X').count() >= 1023 * 24);
        assert!(
            !rendered.contains('\u{fffd}'),
            "native chunk boundaries must preserve Unicode"
        );
    }
    let modes: Value =
        serde_json::from_str(&std::fs::read_to_string(tmp.path().join("paced.done"))?)?;
    assert_eq!(
        modes["exit"], exit,
        "hold_until_consumed={hold_until_consumed}: {modes}"
    );
    assert_eq!(modes["before"], 437);
    assert_eq!(modes["after"], 437);
    assert_eq!(
        modes["native_exit_code"], 7,
        "hold_until_consumed={hold_until_consumed}: {modes}"
    );
    if !hold_until_consumed {
        let native_exit_tick = modes["native_exit_tick"]
            .as_u64()
            .context("native signaled exit tick")?;
        let finished_tick = modes["finished_tick"]
            .as_u64()
            .context("host finish tick")?;
        assert!(
            finished_tick >= native_exit_tick && finished_tick - native_exit_tick <= 10500,
            "host output must not extend the ten-second cleanup deadline: elapsed={} exit_tick={native_exit_tick} done={modes}",
            finished_tick - native_exit_tick
        );
    }
    let files = std::fs::read_dir(tmp.path().join(".runseal/audit"))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(files.len(), 1);
    let events = std::fs::read_to_string(files[0].path())?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let terminals: Vec<_> = events
        .iter()
        .filter(|event| {
            matches!(
                event["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            )
        })
        .collect();
    assert_eq!(terminals.len(), 1);
    let result = &terminals[0]["result"];
    assert_eq!(result["exit_code"], 7);
    if hold_until_consumed {
        assert_eq!(result["cleanup_complete"], true);
        assert_eq!(result["termination_reason"], "exited");
    } else if result["error"]["code"] == "EXECUTION_CLEANUP_FAILED" {
        assert_eq!(result["cleanup_complete"], false, "{result}");
        assert_eq!(result["termination_reason"], "cleanup_failed");
        assert_eq!(result["requested_termination_reason"], "execution_failed");
    } else {
        assert_eq!(result["cleanup_complete"], true, "{result}");
        assert!(
            matches!(
                result["termination_reason"].as_str(),
                Some("exited" | "backpressure")
            ),
            "unexpected terminal reason: {result}"
        );
    }
    if hold_until_consumed {
        assert_eq!(result["stdout_bytes"], 24 * 1027 + 3);
    } else {
        assert!(result["stdout_bytes"].as_u64().unwrap_or(0) > 0);
        assert!(result["stdout_bytes"].as_u64().unwrap_or(0) <= 4096 * 1027 + 3);
    }
    assert_eq!(result["sandbox"]["enforced"], false);
    assert!(!process_present(child_pid)?);
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn cli_console_output_preserves_unicode_without_changing_caller_code_page() -> Result<()> {
    use std::io::Read;
    let _guard = process_test_gate();
    for policy in ["danger-full-access", "workspace-write"] {
        let tmp = TempDir::new()?;
        let driver_code = "import ctypes,json,pathlib,subprocess,sys; k=ctypes.WinDLL('kernel32',use_last_error=True); assert k.SetConsoleOutputCP(437); before=k.GetConsoleOutputCP(); result=subprocess.run(sys.argv[1:]); after=k.GetConsoleOutputCP(); pathlib.Path('console.result').write_text(json.dumps({'before':before,'after':after,'exit':result.returncode})); sys.exit(result.returncode)";
        let child_code = "import os,pathlib,sys,time; data='UNICODE_界🙂_END'.encode('utf-8')+b'\\xff\\xe7'\nfor stream in (1,2):\n for index,byte in enumerate(data):\n  os.write(stream,bytes([byte]))\n  while not pathlib.Path('unicode-'+str(stream)+'-'+str(index)).exists(): time.sleep(0.001)\nsys.exit(7)";
        let command = vec![
            python()?,
            "-u".into(),
            "-c".into(),
            driver_code.into(),
            env!("CARGO_BIN_EXE_runseal").into(),
            "exec".into(),
            "--policy".into(),
            policy.into(),
            "--cwd".into(),
            tmp.path().to_string_lossy().into_owned(),
            "--".into(),
            python()?,
            "-u".into(),
            "-c".into(),
            child_code.into(),
        ];
        let mut driver = codex_windows_sandbox::LocalExecutionProcess::spawn_with_terminal(
            &command,
            tmp.path(),
            &std::env::vars().collect(),
            true,
            Some((24, 80)),
        )?;
        let mut output = driver.stdout.take().context("console output")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut bytes = Vec::new();
        while driver.try_wait()?.is_none() {
            if tmp.path().join(".runseal/audit").exists() {
                for file in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
                    for event in std::fs::read_to_string(file?.path())?
                        .lines()
                        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    {
                        let stream = match event["type"].as_str() {
                            Some("execution.stdout") => 1,
                            Some("execution.stderr") => 2,
                            _ => continue,
                        };
                        assert_eq!(event["bytes"], 1, "gated byte must form one observed chunk");
                        let index = event["stream_offset"].as_u64().context("stream offset")?;
                        std::fs::write(tmp.path().join(format!("unicode-{stream}-{index}")), b"G")?;
                    }
                }
            }
            if let Some(available) = codex_windows_sandbox::available_pipe_bytes(&output)?
                && available > 0
            {
                let mut chunk = vec![0; available.min(64 * 1024)];
                let count = output.read(&mut chunk)?;
                bytes.extend_from_slice(&chunk[..count]);
            }
            assert!(Instant::now() < deadline, "console output watchdog");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(driver.finish(Duration::from_secs(2))?, 7);
        drop(driver.stdin.take());
        if let Some(close) = driver.close_terminal() {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !close.is_finished() {
                if let Some(available) = codex_windows_sandbox::available_pipe_bytes(&output)?
                    && available > 0
                {
                    let mut chunk = vec![0; available.min(64 * 1024)];
                    let count = output.read(&mut chunk)?;
                    bytes.extend_from_slice(&chunk[..count]);
                }
                assert!(Instant::now() < deadline, "console close watchdog");
                std::thread::sleep(Duration::from_millis(5));
            }
            close
                .join()
                .map_err(|_| anyhow::anyhow!("console close panic"))??;
        }
        output.read_to_end(&mut bytes)?;
        let result: Value =
            serde_json::from_str(&std::fs::read_to_string(tmp.path().join("console.result"))?)?;
        assert_eq!(result, json!({"before":437,"after":437,"exit":7}));
        let raw_text = String::from_utf8(bytes)?;
        // ConPTY can insert title/initial screen control sequences between
        // separately acknowledged bytes; compare the rendered character stream.
        let mut text = String::new();
        let mut chars = raw_text.chars();
        while let Some(character) = chars.next() {
            if character != '\u{1b}' {
                text.push(character);
                continue;
            }
            match chars.next() {
                Some('[') => {
                    for character in chars.by_ref() {
                        if ('@'..='~').contains(&character) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    let mut escape = false;
                    for character in chars.by_ref() {
                        if character == '\u{7}' || (escape && character == '\\') {
                            break;
                        }
                        escape = character == '\u{1b}';
                    }
                }
                _ => {}
            }
        }
        assert_eq!(
            text.matches("UNICODE_界🙂_END").count(),
            2,
            "{policy}: {text}"
        );
        assert_eq!(
            text.matches('\u{fffd}').count(),
            4,
            "invalid byte and final incomplete sequence on each stream: {text}"
        );
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn cli_pty_forwards_real_console_input_resize_and_restores_modes() -> Result<()> {
    use std::io::Read;
    let _guard = process_test_gate();
    for policy in ["danger-full-access", "workspace-write"] {
        let tmp = TempDir::new()?;
        let child_code = "import os,pathlib,sys,time; assert all(os.isatty(fd) for fd in (0,1,2)); size=os.get_terminal_size(1); assert (size.columns,size.lines)==(97,27),size; print('FRONT_READY',flush=True); pathlib.Path('front.ready').write_text('ready'); line=sys.stdin.readline(); assert line.strip()=='hello界🙂'; print('FRONT_INPUT',flush=True); pathlib.Path('front.foreground').write_text('ready')\ntry:\n while True: time.sleep(0.02)\nexcept KeyboardInterrupt: print('FRONT_INTERRUPTED',flush=True)\npathlib.Path('front.interrupted').write_text('ready')\nwhile (os.get_terminal_size(1).columns,os.get_terminal_size(1).lines)!=(119,39): time.sleep(0.02)\nprint('FRONT_RESIZED',flush=True); pathlib.Path('front.resized').write_text('ready'); assert sys.stdin.readline().strip()=='quit'; sys.exit(7)";
        let driver_code = "import ctypes,json,pathlib,subprocess,sys; k=ctypes.WinDLL('kernel32',use_last_error=True); k.GetStdHandle.restype=ctypes.c_void_p\ndef modes():\n values=[]\n for fd in (-10,-11):\n  value=ctypes.c_ulong(); assert k.GetConsoleMode(ctypes.c_void_p(k.GetStdHandle(fd)),ctypes.byref(value)); values.append(value.value)\n return values\nbefore=modes(); result=subprocess.run(sys.argv[1:]); after=modes(); pathlib.Path('front.modes').write_text(json.dumps({'before':before,'after':after,'exit':result.returncode})); print('FRONT_RESTORED',flush=True); sys.exit(result.returncode)";
        let command = vec![
            python()?,
            "-u".into(),
            "-c".into(),
            driver_code.into(),
            env!("CARGO_BIN_EXE_runseal").into(),
            "exec".into(),
            "--pty".into(),
            "--stdin".into(),
            "inherit".into(),
            "--policy".into(),
            policy.into(),
            "--cwd".into(),
            tmp.path().to_string_lossy().into_owned(),
            "--".into(),
            python()?,
            "-u".into(),
            "-c".into(),
            child_code.into(),
        ];
        let mut driver = codex_windows_sandbox::LocalExecutionProcess::spawn_with_terminal(
            &command,
            tmp.path(),
            &std::env::vars().collect(),
            true,
            Some((27, 97)),
        )?;
        let terminal = driver.terminal().context("outer terminal")?;
        let mut input = driver.stdin.take().context("outer input")?;
        let mut output = driver.stdout.take().context("outer output")?;
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut bytes = Vec::new();
        let mut sent_line = false;
        let mut sent_interrupt = false;
        let mut resized = false;
        let mut sent_quit = false;
        loop {
            assert!(
                Instant::now() < deadline,
                "CLI terminal watchdog: {policy}, {}",
                String::from_utf8_lossy(&bytes)
            );
            if let Some(available) = codex_windows_sandbox::available_pipe_bytes(&output)?
                && available > 0
            {
                let mut chunk = vec![0; available.min(64 * 1024)];
                let count = output.read(&mut chunk)?;
                bytes.extend_from_slice(&chunk[..count]);
            }
            if !sent_line
                && tmp.path().join("front.ready").exists()
                && String::from_utf8_lossy(&bytes).contains("FRONT_READY")
            {
                input.write_all("hello界🙂\r".as_bytes())?;
                sent_line = true;
            }
            if !sent_interrupt && tmp.path().join("front.foreground").exists() {
                input.write_all(&[3])?;
                sent_interrupt = true;
            }
            if !resized && tmp.path().join("front.interrupted").exists() {
                terminal.resize(39, 119)?;
                resized = true;
            }
            if !sent_quit && tmp.path().join("front.resized").exists() {
                input.write_all(b"quit\r")?;
                sent_quit = true;
            }
            if driver.try_wait()?.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(sent_line && sent_interrupt && resized && sent_quit);
        assert_eq!(driver.finish(Duration::from_secs(2))?, 7);
        drop(input);
        drop(terminal);
        if let Some(close) = driver.close_terminal() {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !close.is_finished() {
                if let Some(available) = codex_windows_sandbox::available_pipe_bytes(&output)?
                    && available > 0
                {
                    let mut chunk = vec![0; available.min(64 * 1024)];
                    let count = output.read(&mut chunk)?;
                    bytes.extend_from_slice(&chunk[..count]);
                }
                assert!(Instant::now() < deadline, "outer terminal cleanup watchdog");
                std::thread::sleep(Duration::from_millis(5));
            }
            close
                .join()
                .map_err(|_| anyhow::anyhow!("outer terminal cleanup panic"))??;
        }
        output.read_to_end(&mut bytes)?;
        let modes: Value =
            serde_json::from_str(&std::fs::read_to_string(tmp.path().join("front.modes"))?)?;
        assert_eq!(
            modes["before"], modes["after"],
            "terminal modes were not restored: {policy}, {modes}"
        );
        assert_eq!(modes["exit"], 7);
        let text = String::from_utf8_lossy(&bytes);
        for marker in [
            "FRONT_INPUT",
            "FRONT_INTERRUPTED",
            "FRONT_RESIZED",
            "FRONT_RESTORED",
        ] {
            assert!(text.contains(marker), "missing {marker}: {text}");
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn cli_plain_console_inherit_delivers_unicode_and_stops_on_partial_input_exit() -> Result<()> {
    use std::io::Read;
    let _guard = process_test_gate();
    for (policy, mode) in ["danger-full-access", "workspace-write"]
        .into_iter()
        .flat_map(|policy| {
            ["line", "partial", "raw", "eof"]
                .into_iter()
                .map(move |mode| (policy, mode))
        })
    {
        let partial = mode == "partial";
        let tmp = TempDir::new()?;
        let code = if mode == "raw" {
            "import os,pathlib,sys; assert not os.isatty(0); print('PLAIN_READY',flush=True); pathlib.Path('plain.ready').write_text('ready'); data=sys.stdin.buffer.read(len('hello界🙂'.encode('utf-8'))); assert data.decode('utf-8')=='hello界🙂',repr(data); print('PLAIN_INPUT',flush=True); sys.exit(7)"
        } else if mode == "eof" {
            "import pathlib,sys; print('PLAIN_READY',flush=True); pathlib.Path('plain.ready').write_text('ready'); assert sys.stdin.buffer.read()==b''; print('PLAIN_EOF',flush=True); sys.exit(7)"
        } else if partial {
            "import pathlib,sys,time; print('PLAIN_READY',flush=True); pathlib.Path('plain.ready').write_text('ready')\nwhile not pathlib.Path('plain.exit').exists(): time.sleep(0.005)\nsys.exit(7)"
        } else {
            "import os,pathlib,sys; assert not os.isatty(0); print('PLAIN_READY',flush=True); pathlib.Path('plain.ready').write_text('ready'); line=sys.stdin.buffer.readline(); assert line.decode('utf-8').strip()=='hello界🙂',repr(line); print('PLAIN_INPUT',flush=True); sys.exit(7)"
        };
        let driver_code = r#"import ctypes,json,pathlib,subprocess,sys,threading
k=ctypes.WinDLL('kernel32',use_last_error=True)
k.GetStdHandle.restype=ctypes.c_void_p
k.GetConsoleMode.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ulong)]
k.SetConsoleMode.argtypes=[ctypes.c_void_p,ctypes.c_ulong]
class Key(ctypes.Structure):
 _fields_=[('down',ctypes.c_int),('repeat',ctypes.c_ushort),('virtual',ctypes.c_ushort),('scan',ctypes.c_ushort),('char',ctypes.c_ushort),('state',ctypes.c_ulong)]
class Event(ctypes.Union):
 _fields_=[('key',Key),('raw',ctypes.c_byte*16)]
class Record(ctypes.Structure):
 _fields_=[('type',ctypes.c_ushort),('event',Event)]
assert ctypes.sizeof(Record)==20
k.PeekConsoleInputW.argtypes=[ctypes.c_void_p,ctypes.POINTER(Record),ctypes.c_ulong,ctypes.POINTER(ctypes.c_ulong)]
def pending():
 records=(Record*1024)(); count=ctypes.c_ulong()
 assert k.PeekConsoleInputW(k.GetStdHandle(-10),records,1024,ctypes.byref(count))
 chars=''.join(chr(item.event.key.char) for item in records[:count.value] if item.type==1 and (item.event.key.down or item.event.key.virtual==18) and item.event.key.char)
 try: return chars.encode('utf-16-le','surrogatepass').decode('utf-16-le')
 except UnicodeDecodeError: return ''
def modes():
 values=[]
 for fd in (-10,-11):
  value=ctypes.c_ulong(); assert k.GetConsoleMode(k.GetStdHandle(fd),ctypes.byref(value)); values.append(value.value)
 return values
mode=sys.argv[1]
if mode=='raw':
 value=ctypes.c_ulong(); assert k.GetConsoleMode(k.GetStdHandle(-10),ctypes.byref(value)); assert k.SetConsoleMode(k.GetStdHandle(-10),value.value & ~6)
before=modes(); stop=threading.Event()
def watch():
 while not stop.wait(0.005):
  if 'partial界🙂' in pending(): pathlib.Path('plain.pending').write_text('ready'); return
worker=threading.Thread(target=watch) if mode=='partial' else None
if worker: worker.start()
result=subprocess.run(sys.argv[2:]); stop.set()
if worker: worker.join(2); assert not worker.is_alive()
after=modes(); remaining=pending() if mode=='partial' else ''
pathlib.Path('plain.modes').write_text(json.dumps({'before':before,'after':after,'exit':result.returncode,'pending':remaining}))
print('PLAIN_RESTORED',flush=True); sys.exit(result.returncode)
"#;
        let command = vec![
            python()?,
            "-u".into(),
            "-c".into(),
            driver_code.into(),
            mode.into(),
            env!("CARGO_BIN_EXE_runseal").into(),
            "exec".into(),
            "--stdin".into(),
            "inherit".into(),
            "--policy".into(),
            policy.into(),
            "--cwd".into(),
            tmp.path().to_string_lossy().into_owned(),
            "--".into(),
            python()?,
            "-u".into(),
            "-c".into(),
            code.into(),
        ];
        let mut driver = codex_windows_sandbox::LocalExecutionProcess::spawn_with_terminal(
            &command,
            tmp.path(),
            &std::env::vars().collect(),
            true,
            Some((27, 97)),
        )?;
        let terminal = driver.terminal().context("outer console")?;
        let mut input = driver.stdin.take().context("outer input")?;
        let mut output = driver.stdout.take().context("outer output")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut bytes = Vec::new();
        let mut sent = false;
        loop {
            if let Some(available) = codex_windows_sandbox::available_pipe_bytes(&output)?
                && available > 0
            {
                let mut chunk = vec![0; available.min(64 * 1024)];
                let count = output.read(&mut chunk)?;
                bytes.extend_from_slice(&chunk[..count]);
            }
            if !sent
                && tmp.path().join("plain.ready").exists()
                && String::from_utf8_lossy(&bytes).contains("PLAIN_READY")
            {
                let text = match mode {
                    "partial" => "partial界🙂",
                    "raw" => "hello界🙂",
                    "eof" => "\x1a\r",
                    _ => "bad\x08\x08\x08hello界🙂\r",
                };
                input.write_all(text.as_bytes())?;
                sent = true;
            }
            if partial
                && sent
                && tmp.path().join("plain.pending").exists()
                && !tmp.path().join("plain.exit").exists()
            {
                std::fs::write(tmp.path().join("plain.exit"), b"exit")?;
            }
            if driver.try_wait()?.is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "plain Console watchdog {policy} mode={mode}: {}",
                String::from_utf8_lossy(&bytes)
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(sent);
        assert_eq!(
            driver.finish(Duration::from_secs(2))?,
            7,
            "plain Console exit {policy} mode={mode}: {}",
            String::from_utf8_lossy(&bytes)
        );
        drop(input);
        drop(terminal);
        if let Some(close) = driver.close_terminal() {
            while !close.is_finished() {
                if let Some(available) = codex_windows_sandbox::available_pipe_bytes(&output)?
                    && available > 0
                {
                    let mut chunk = vec![0; available.min(64 * 1024)];
                    let count = output.read(&mut chunk)?;
                    bytes.extend_from_slice(&chunk[..count]);
                }
                assert!(Instant::now() < deadline, "outer plain Console shutdown");
                std::thread::sleep(Duration::from_millis(5));
            }
            close
                .join()
                .map_err(|_| anyhow::anyhow!("outer console close panic"))??;
        }
        output.read_to_end(&mut bytes)?;
        let modes: Value =
            serde_json::from_str(&std::fs::read_to_string(tmp.path().join("plain.modes"))?)?;
        assert_eq!(
            modes["before"], modes["after"],
            "plain Console modes {modes}"
        );
        assert_eq!(modes["exit"], 7);
        let audit_files = std::fs::read_dir(tmp.path().join(".runseal/audit"))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(audit_files.len(), 1);
        let audit = std::fs::read_to_string(audit_files[0].path())?;
        let records: Vec<Value> = audit
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        let terminal = records.last().context("Console terminal")?;
        assert_eq!(terminal["type"], "execution.finished");
        assert_eq!(terminal["result"]["sandbox"]["level"], policy);
        assert_eq!(
            terminal["result"]["sandbox"]["enforced"],
            policy != "danger-full-access"
        );
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        if partial {
            assert!(
                modes["pending"]
                    .as_str()
                    .context("pending input")?
                    .contains("partial界🙂"),
                "{modes}"
            );
        } else {
            assert!(String::from_utf8_lossy(&bytes).contains(if mode == "eof" {
                "PLAIN_EOF"
            } else {
                "PLAIN_INPUT"
            }));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn cli_pty_input_eof_cancels_range_and_keeps_peer_alive() -> Result<()> {
    use std::io::Read;
    struct OwnedCli(std::process::Child);
    impl Drop for OwnedCli {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _guard = process_test_gate();
    for policy in ["danger-full-access", "workspace-write"] {
        let tmp = TempDir::new()?;
        let mut peer = Client::spawn("service")?;
        peer.send(1,"execute",json!({"command":[python()?,"-u","-c","import os,pathlib,time; pathlib.Path('peer.pid').write_text(str(os.getpid())); print('PEER_READY',flush=True)\nwhile True: pathlib.Path('peer.beat').write_text(str(time.monotonic())); time.sleep(0.02)"],"cwd":tmp.path(),"policy":policy}))?;
        let receipt = peer.next(Duration::from_secs(15))?;
        assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
        let peer_id = receipt["result"]["execution_id"].clone();
        let deadline = Instant::now() + Duration::from_secs(15);
        while !tmp.path().join("peer.beat").exists() {
            assert!(Instant::now() < deadline, "peer startup watchdog");
            std::thread::sleep(Duration::from_millis(10));
        }
        let peer_pid: u32 = std::fs::read_to_string(tmp.path().join("peer.pid"))?.parse()?;
        let beat = std::fs::read_to_string(tmp.path().join("peer.beat"))?;
        let code = "import os,pathlib,subprocess,sys; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(300)']); pathlib.Path('cli.root').write_text(str(os.getpid())); pathlib.Path('cli.child').write_text(str(child.pid)); print('EOF_READY',flush=True); sys.stdin.readline()";
        let mut cli = OwnedCli(
            Command::new(env!("CARGO_BIN_EXE_runseal"))
                .args([
                    "exec", "--pty", "--stdin", "inherit", "--policy", policy, "--cwd",
                ])
                .arg(tmp.path())
                .args(["--", &python()?, "-u", "-c", code])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        let input = cli.0.stdin.take().context("CLI input")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while !tmp.path().join("cli.child").exists() {
            assert!(Instant::now() < deadline, "CLI startup watchdog");
            assert!(cli.0.try_wait()?.is_none(), "CLI ended before task started");
            std::thread::sleep(Duration::from_millis(10));
        }
        let root: u32 = std::fs::read_to_string(tmp.path().join("cli.root"))?.parse()?;
        let child: u32 = std::fs::read_to_string(tmp.path().join("cli.child"))?.parse()?;
        assert!(process_present(root)? && process_present(child)?);
        drop(input);
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = cli.0.try_wait()? {
                break status;
            }
            assert!(Instant::now() < deadline, "CLI EOF cleanup watchdog");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(!status.success());
        assert!(!process_present(root)? && !process_present(child)?);
        assert!(process_present(peer_pid)?);
        assert_ne!(std::fs::read_to_string(tmp.path().join("peer.beat"))?, beat);
        let mut errors = String::new();
        cli.0
            .stderr
            .take()
            .context("CLI error output")?
            .read_to_string(&mut errors)?;
        let mut terminal = None;
        for file in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
            for line in std::fs::read_to_string(file?.path())?.lines() {
                let event: Value = serde_json::from_str(line)?;
                if event["execution_id"] != peer_id
                    && matches!(
                        event["type"].as_str(),
                        Some("execution.finished" | "execution.failed")
                    )
                {
                    assert!(terminal.is_none(), "duplicate CLI terminal");
                    terminal = Some(event);
                }
            }
        }
        let terminal = terminal.context(format!("CLI audit terminal: {errors}"))?;
        assert_eq!(
            terminal["result"]["termination_reason"], "cancelled",
            "{terminal}"
        );
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        if let Some(root) = terminal["result"]["platform_plan"]["runtime_root"].as_str() {
            assert!(
                !std::path::Path::new(root).exists(),
                "runtime root retained after EOF"
            );
        }
        peer.send(2, "cancelExecution", json!({"execution_id":peer_id}))?;
        loop {
            let message = peer.next(Duration::from_secs(15))?;
            if message["params"]["execution_id"] == peer_id
                && message["params"]["type"] == "execution.failed"
            {
                assert_eq!(message["params"]["result"]["cleanup_complete"], true);
                break;
            }
        }
        assert!(!process_present(peer_pid)?);
    }
    Ok(())
}

#[cfg(windows)]
fn pty_interrupt_case(policy: &str) -> Result<()> {
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let python = python()?;
    let cmd = std::path::PathBuf::from(std::env::var_os("SystemRoot").context("system root")?)
        .join("System32/cmd.exe");
    let mut client = Client::spawn("service")?;
    client.send(1,"execute",json!({"command":[cmd,"/D","/Q"],"cwd":tmp.path(),"policy":policy,"stdin":{"mode":"stream"},"io":{"mode":"pty","rows":30,"cols":160}}))?;
    let receipt = client.next(Duration::from_secs(15))?;
    assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
    let shell = receipt["result"]["execution_id"].clone();
    let mut prompt = Vec::new();
    loop {
        let message = client.next(Duration::from_secs(15))?;
        if message["params"]["type"] == "execution.terminal" {
            prompt.extend(
                STANDARD.decode(
                    message["params"]["data"]
                        .as_str()
                        .and_then(|data| data.strip_prefix("base64:"))
                        .context("shell prompt")?,
                )?,
            );
            if prompt.contains(&b'>') {
                break;
            }
        }
        assert!(
            !matches!(
                message["params"]["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ),
            "shell ended before prompt: {}, {message}",
            String::from_utf8_lossy(&prompt)
        );
    }
    let foreground = format!(
        "\"{python}\" -u -c \"import os,pathlib,time; pathlib.Path('fg.pid').write_text(str(os.getpid())); pathlib.Path('shell.pid').write_text(str(os.getppid())); print('FG_READY',flush=True); exec('while True: time.sleep(0.05)')\"\r\n"
    );
    client.send(3,"writeExecutionInput",json!({"execution_id":shell,"stream":"stdin","encoding":"base64","data":format!("base64:{}",STANDARD.encode(foreground))}))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut startup_trace: Vec<String> = Vec::new();
    while !tmp.path().join("fg.pid").exists() || !tmp.path().join("shell.pid").exists() {
        assert!(
            Instant::now() < deadline,
            "foreground did not start: {startup_trace:?}"
        );
        let message = match client.messages.recv_timeout(Duration::from_millis(100)) {
            Ok(message) => message?,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(error) => return Err(error.into()),
        };
        if startup_trace.len() < 20 {
            if message["params"]["type"] == "execution.terminal" {
                let data = STANDARD.decode(
                    message["params"]["data"]
                        .as_str()
                        .and_then(|data| data.strip_prefix("base64:"))
                        .context("terminal trace")?,
                )?;
                startup_trace.push(String::from_utf8_lossy(&data).into_owned());
            } else if message.get("id").is_some() {
                startup_trace.push(message.to_string());
            }
        }
        assert!(message["params"]["type"] != "execution.failed", "{message}");
    }
    let fg_pid: u32 = std::fs::read_to_string(tmp.path().join("fg.pid"))?.parse()?;
    let shell_pid: u32 = std::fs::read_to_string(tmp.path().join("shell.pid"))?.parse()?;
    assert!(process_present(fg_pid)? && process_present(shell_pid)?);
    client.send(2,"execute",json!({"command":[python,"-u","-c","import os,pathlib,time; pathlib.Path('peer.pid').write_text(str(os.getpid())); print('PEER_READY',flush=True)\nwhile True: pathlib.Path('peer.beat').write_text(str(time.monotonic())); time.sleep(0.05)"],"cwd":tmp.path(),"policy":policy}))?;
    let mut peer = Value::Null;
    while peer.is_null() || !tmp.path().join("peer.beat").exists() {
        let message = client.next(Duration::from_secs(15))?;
        if message["id"] == 2 {
            assert_eq!(message["result"]["status"], "preparing", "{message}");
            peer = message["result"]["execution_id"].clone();
        }
        assert!(message["params"]["type"] != "execution.failed", "{message}");
    }
    let peer_pid: u32 = std::fs::read_to_string(tmp.path().join("peer.pid"))?.parse()?;
    let old_beat = std::fs::read_to_string(tmp.path().join("peer.beat"))?;
    client.send(
        4,
        "signalExecution",
        json!({"execution_id":shell,"signal":"interrupt"}),
    )?;
    let mut accepted = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !accepted || process_present(fg_pid)? {
        assert!(
            Instant::now() < deadline,
            "foreground survived interrupt: {startup_trace:?}"
        );
        let message = match client.messages.recv_timeout(Duration::from_millis(100)) {
            Ok(message) => message?,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(error) => return Err(error.into()),
        };
        if message["params"]["type"] == "execution.terminal" {
            let data = STANDARD.decode(
                message["params"]["data"]
                    .as_str()
                    .and_then(|data| data.strip_prefix("base64:"))
                    .context("interrupt trace")?,
            )?;
            if startup_trace.len() < 30 {
                startup_trace.push(String::from_utf8_lossy(&data).into_owned());
            }
        }
        if message["id"] == 4 {
            assert_eq!(message["result"]["accepted"], true, "{message}");
            accepted = true;
        }
        assert!(
            !matches!(
                message["params"]["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ),
            "interrupt ended an execution: {message}"
        );
    }
    assert!(process_present(shell_pid)? && process_present(peer_pid)?);
    let after = format!(
        "\"{python}\" -u -c \"import os,pathlib; pathlib.Path('after.pid').write_text(str(os.getppid())); print('AFTER_INTERRUPT',flush=True)\"\r\nexit 0\r\n"
    );
    client.send(5,"writeExecutionInput",json!({"execution_id":shell,"stream":"stdin","encoding":"base64","data":format!("base64:{}",STANDARD.encode(after))}))?;
    let shell_terminal = loop {
        let message = client.next(Duration::from_secs(15))?;
        if message["params"]["execution_id"] == shell
            && matches!(
                message["params"]["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            )
        {
            break message["params"].clone();
        }
        assert!(
            message["params"]["execution_id"] != peer
                || !matches!(
                    message["params"]["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ),
            "interrupt ended peer: {message}"
        );
    };
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("after.pid"))?.parse::<u32>()?,
        shell_pid,
        "continued command used another shell"
    );
    assert_eq!(shell_terminal["result"]["exit_code"], 0, "{shell_terminal}");
    assert_eq!(shell_terminal["result"]["termination_reason"], "exited");
    assert_eq!(shell_terminal["result"]["cleanup_complete"], true);
    assert_eq!(
        shell_terminal["result"]["sandbox"]["enforced"],
        policy != "danger-full-access"
    );
    assert!(!process_present(shell_pid)?);
    assert!(process_present(peer_pid)?);
    assert_ne!(
        std::fs::read_to_string(tmp.path().join("peer.beat"))?,
        old_beat
    );
    client.send(6, "cancelExecution", json!({"execution_id":peer}))?;
    loop {
        let message = client.next(Duration::from_secs(15))?;
        if message["params"]["execution_id"] == peer
            && message["params"]["type"] == "execution.failed"
        {
            assert_eq!(
                message["params"]["result"]["termination_reason"],
                "cancelled"
            );
            assert_eq!(message["params"]["result"]["cleanup_complete"], true);
            break;
        }
    }
    assert!(!process_present(peer_pid)?);
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_native_control_fd3_is_duplex_binary_and_half_closeable() -> Result<()> {
    use std::io::{Read, Write};
    let _guard = process_test_gate();
    let tmp = TempDir::new()?;
    let child_code = r#"import os,sys
os.write(3,b'READY')
try:
 os.fstat(4)
 raise AssertionError('unexpected descriptor 4')
except OSError:
 pass
data=b''
for round_index in range(3):
 chunk_data=b''
 while len(chunk_data)<128*1024:
  chunk=os.read(3,min(8192,128*1024-len(chunk_data)))
  assert chunk
  chunk_data+=chunk
 os.write(3,b'ROUND'+bytes([round_index])+chunk_data)
 data+=chunk_data
assert os.read(3,8192)==b''
os.write(1,b'OUT:'+data)
os.write(2,b'ERR:'+data)
os.write(3,b'REPLY:'+data)
sys.exit(7)
"#;
    let mut child = codex_windows_sandbox::LocalExecutionProcess::spawn_with_control(
        &[python()?, "-u".into(), "-c".into(), child_code.into()],
        tmp.path(),
        &std::env::vars().collect(),
        false,
    )?;
    let peer = codex_windows_sandbox::LocalExecutionProcess::spawn(
        &[python()?, "-c".into(), "import time;time.sleep(30)".into()],
        tmp.path(),
        &std::env::vars().collect(),
        false,
    )?;
    let mut control = child.control.take().context("control endpoint")?;
    let mut received = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while received.len() < 5 {
        let mut chunk = [0; 8192];
        match control.read(&mut chunk) {
            Ok(0) => anyhow::bail!("control EOF before readiness"),
            Ok(count) => received.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "fd 3 readiness watchdog");
                if let Some(code) = child.try_wait()? {
                    anyhow::bail!("child exited before fd 3 readiness: {code}");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                child.finish(Duration::from_secs(5))?;
                let mut errors = Vec::new();
                child
                    .stderr
                    .take()
                    .context("stderr")?
                    .read_to_end(&mut errors)?;
                anyhow::bail!(
                    "control readiness: {error}; {}",
                    String::from_utf8_lossy(&errors[..errors.len().min(1024)])
                );
            }
        }
    }
    assert_eq!(received, b"READY");
    let payload: Vec<u8> = (0..128 * 1024).map(|index| (index % 256) as u8).collect();
    for round_index in 0..3 {
        let mut written = 0;
        while written < payload.len() {
            match control.write(&payload[written..]) {
                Ok(count) => {
                    assert!(count > 0);
                    written += count;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "control write watchdog");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => {
                    child.finish(Duration::from_secs(5))?;
                    let mut errors = Vec::new();
                    child
                        .stderr
                        .take()
                        .context("stderr")?
                        .read_to_end(&mut errors)?;
                    anyhow::bail!(
                        "control transfer: {error}; {}",
                        String::from_utf8_lossy(&errors[..errors.len().min(1024)])
                    );
                }
            }
        }
        let expected = [b"ROUND".as_slice(), &[round_index], &payload].concat();
        let mut round_reply = Vec::new();
        while round_reply.len() < expected.len() {
            let mut chunk = [0; 8192];
            match control.read(&mut chunk) {
                Ok(count) => {
                    assert!(count > 0, "control round EOF");
                    round_reply.extend_from_slice(&chunk[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "control round watchdog");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert!(
            round_reply == expected,
            "control round {round_index} mismatch"
        );
    }
    let payload = payload.repeat(3);
    if let Err(error) = control.close_input() {
        child.finish(Duration::from_secs(5))?;
        let mut errors = Vec::new();
        child
            .stderr
            .take()
            .context("stderr")?
            .read_to_end(&mut errors)?;
        anyhow::bail!(
            "control EOF: {error}; {}",
            String::from_utf8_lossy(&errors[..errors.len().min(1024)])
        );
    }
    control.close_input()?;
    // Drain all streams concurrently: a full stdout pipe must not block control.
    let stdout = child.stdout.take().context("stdout")?;
    let stderr = child.stderr.take().context("stderr")?;
    let output_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut stdout = stdout;
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let error_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut stderr = stderr;
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    received.clear();
    let mut range_finished = false;
    loop {
        if !range_finished && child.try_wait()?.is_some() {
            assert_eq!(child.finish(Duration::from_secs(5))?, 7);
            range_finished = true;
        }
        let mut chunk = [0; 8192];
        match control.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => received.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "reverse control watchdog");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                child.finish(Duration::from_secs(5))?;
                let errors = error_reader.join().expect("stderr reader")?;
                anyhow::bail!(
                    "reverse control: {error}; received {}; stderr {}",
                    received.len(),
                    String::from_utf8_lossy(&errors[..errors.len().min(1024)])
                );
            }
        }
    }
    assert!(
        received == [b"REPLY:".as_slice(), &payload].concat(),
        "control reply mismatch: {} bytes",
        received.len()
    );
    while child.try_wait()?.is_none() {
        assert!(Instant::now() < deadline, "child exit watchdog");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(child.finish(Duration::from_secs(5))?, 7);
    assert_eq!(
        output_reader.join().expect("stdout reader")?,
        [b"OUT:".as_slice(), &payload].concat()
    );
    assert_eq!(
        error_reader.join().expect("stderr reader")?,
        [b"ERR:".as_slice(), &payload].concat()
    );
    assert!(peer.try_wait()?.is_none(), "control cleanup affected peer");
    peer.finish(Duration::from_secs(5))?;
    Ok(())
}

#[cfg(windows)]
fn contained_python_fixture(workspace: &std::path::Path) -> Result<String> {
    fn copy_library(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(destination)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let name = entry.file_name();
            if kind.is_dir() {
                if ["site-packages", "__pycache__", "test", "tkinter", "idlelib"]
                    .iter()
                    .any(|excluded| name == *excluded)
                {
                    continue;
                }
                copy_library(&entry.path(), &destination.join(name))?;
            } else if kind.is_file()
                && entry.path().extension().is_some_and(|extension| {
                    ["py", "pyd", "dll"]
                        .iter()
                        .any(|allowed| extension.eq_ignore_ascii_case(allowed))
                })
            {
                std::fs::copy(entry.path(), destination.join(name))?;
            }
        }
        Ok(())
    }
    let executable = std::path::PathBuf::from(python()?);
    let source = executable.parent().context("interpreter directory")?;
    let destination = workspace.join("interpreter");
    std::fs::create_dir_all(&destination)?;
    let name = executable.file_name().context("interpreter file")?;
    std::fs::copy(&executable, destination.join(name))?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))
        {
            std::fs::copy(entry.path(), destination.join(entry.file_name()))?;
        }
    }
    copy_library(&source.join("Lib"), &destination.join("Lib"))?;
    copy_library(&source.join("DLLs"), &destination.join("DLLs"))?;
    Ok(destination.join(name).to_string_lossy().into_owned())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn rpc_control_fd3_three_binary_rounds_and_half_close_preserve_streams_and_audit() -> Result<()> {
    let _guard = process_test_gate();
    for policy in [
        "danger-full-access",
        "read-only",
        "workspace-write",
        "workspace-contained",
    ] {
        let tmp = TempDir::new()?;
        let python_executable = if policy == "workspace-contained" {
            contained_python_fixture(tmp.path())?
        } else {
            python()?
        };
        let mut client = Client::spawn("service")?;
        let child_code = r#"import os,sys
os.write(3,b'READY')
data=b''
for index in range(3):
 assert os.read(0,1)==bytes([65+index])
 chunk_data=b''
 while len(chunk_data)<128*1024:
  chunk=os.read(3,min(8192,128*1024-len(chunk_data)))
  assert chunk
  chunk_data+=chunk
 os.write(1,b'OUT'+bytes([65+index]))
 os.write(2,b'ERR'+bytes([65+index]))
 os.write(3,chunk_data)
 data+=chunk_data
assert os.read(3,8192)==b''
assert os.read(0,1)==b''
os.write(3,b'FINAL:'+data)
sys.exit(7)
"#;
        client.send(1, "execute", json!({
            "command":[python_executable,"-I","-S","-u","-c",child_code], "cwd":tmp.path(), "policy":policy,
            "stdin":{"mode":"stream"}, "io":{"mode":"pipe","control":{"mode":"pipe","child_fd":3}}
        }))?;
        let receipt = client.next(Duration::from_secs(2))?;
        assert_eq!(
            receipt["result"]["status"], "preparing",
            "{policy}: {receipt}"
        );
        let id = receipt["result"]["execution_id"]
            .as_str()
            .context("execution ID")?
            .to_owned();
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut control = Vec::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut audit_path = None;
        let mut offsets = [0u64; 3];
        let consume = |message: &Value,
                       control: &mut Vec<u8>,
                       stdout: &mut Vec<u8>,
                       stderr: &mut Vec<u8>,
                       offsets: &mut [u64; 3],
                       audit_path: &mut Option<String>|
         -> Result<()> {
            let event = &message["params"];
            if event["execution_id"] != id {
                return Ok(());
            }
            if let Some(path) = event["audit_path"].as_str() {
                *audit_path = Some(path.to_owned());
            }
            let (index, target) = match event["type"].as_str() {
                Some("execution.control") => (0, control),
                Some("execution.stdout") => (1, stdout),
                Some("execution.stderr") => (2, stderr),
                _ => return Ok(()),
            };
            assert_eq!(event["stream_offset"], offsets[index], "{event}");
            let bytes = STANDARD.decode(
                event["data"]
                    .as_str()
                    .context("data")?
                    .strip_prefix("base64:")
                    .context("base64")?,
            )?;
            assert!(bytes.len() <= 64 * 1024);
            offsets[index] += bytes.len() as u64;
            target.extend_from_slice(&bytes);
            Ok(())
        };
        while control.len() < 5 {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            assert!(
                !matches!(
                    message["params"]["type"].as_str(),
                    Some("execution.failed" | "execution.finished")
                ),
                "early control exit {policy}: code {}, stderr {}",
                message["params"]["result"]["exit_code"],
                String::from_utf8_lossy(&stderr)
            );
            consume(
                &message,
                &mut control,
                &mut stdout,
                &mut stderr,
                &mut offsets,
                &mut audit_path,
            )?;
        }
        assert_eq!(control, b"READY");
        client.send(2, "execute", json!({"command":[python_executable,"-I","-S","-u","-c","import os,sys,time; target=os.path.join(os.getcwd() if sys.argv[1]=='local' else os.environ['TEMP'],'control-peer.beat'); print('READY '+str(os.getpid()),flush=True); count=0\nwhile True:\n count+=1; fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o666); os.write(fd,str(count).encode()); os.close(fd); time.sleep(0.01)",if policy=="read-only" {"sandbox"} else {"local"}],"cwd":tmp.path(),"policy":policy}))?;
        let peer_receipt = client.next(Duration::from_secs(2))?;
        assert_eq!(
            peer_receipt["result"]["status"], "preparing",
            "{peer_receipt}"
        );
        let peer = peer_receipt["result"]["execution_id"]
            .as_str()
            .context("peer")?
            .to_owned();
        let peer_pid = wait_ready_pid(&client, &peer)?;
        let peer_beat = if policy != "read-only" {
            tmp.path().join("control-peer.beat")
        } else {
            tmp.path()
                .join(".runseal/runtime")
                .join(&peer)
                .join("temp/control-peer.beat")
        };

        let _fixture = HeartbeatFixture {
            directory: tmp.path().to_owned(),
            pids: vec![peer_pid],
        };

        let mut payload: Vec<u8> = (0..128 * 1024).map(|index| (index % 256) as u8).collect();
        let canary = b"control-secret-canary";
        payload[..canary.len()].copy_from_slice(canary);
        let mut request_id = 10;
        for round_index in 0..3 {
            let mut writes = Vec::new();
            for (stream, bytes) in std::iter::once(("stdin", vec![65 + round_index])).chain(
                payload
                    .chunks(64 * 1024)
                    .map(|bytes| ("control", bytes.to_vec())),
            ) {
                client.send(request_id, "writeExecutionInput", json!({"execution_id":id,"stream":stream,"encoding":"base64","data":format!("base64:{}",STANDARD.encode(&bytes))}))?;
                writes.push((request_id, bytes.len()));
                request_id += 1;
            }
            let expected_count = 5 + (round_index as usize + 1) * payload.len();
            while !writes.is_empty() || control.len() < expected_count {
                let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
                if let Some(index) = writes
                    .iter()
                    .position(|(request_id, _)| message["id"] == *request_id)
                {
                    let (_, count) = writes.remove(index);
                    assert_eq!(message["result"]["accepted_bytes"], count, "{message}");
                }
                assert_ne!(message["params"]["type"], "execution.failed", "{message}");
                consume(
                    &message,
                    &mut control,
                    &mut stdout,
                    &mut stderr,
                    &mut offsets,
                    &mut audit_path,
                )?;
            }
            assert!(
                control[5 + round_index as usize * payload.len()..] == payload,
                "round {round_index}"
            );
        }
        for (request_id, stream) in [(40, "control"), (41, "control"), (42, "stdin")] {
            client.send(
                request_id,
                "closeExecutionInput",
                json!({"execution_id":id,"stream":stream}),
            )?;
        }
        let mut closed = Vec::new();
        let terminal = loop {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            if let Some(request_id) = message["id"].as_u64()
                && (40..=42).contains(&request_id)
            {
                assert_eq!(message["result"]["closed"], true, "{message}");
                closed.push(request_id);
            }
            consume(
                &message,
                &mut control,
                &mut stdout,
                &mut stderr,
                &mut offsets,
                &mut audit_path,
            )?;
            if matches!(
                message["params"]["type"].as_str(),
                Some("execution.finished" | "execution.failed")
            ) {
                break message["params"].clone();
            }
        };
        assert_eq!(closed.len(), 3);
        assert!(
            process_present(peer_pid)?,
            "control cleanup stopped peer: {policy}"
        );
        let before = std::fs::read_to_string(peer_beat.clone()).unwrap_or_default();
        let heartbeat_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let after = std::fs::read_to_string(peer_beat.clone()).unwrap_or_default();
            if !after.is_empty() && after != before {
                break;
            }
            assert!(
                Instant::now() < heartbeat_deadline,
                "control peer heartbeat"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let expected = [
            b"READY".as_slice(),
            &payload.repeat(3),
            b"FINAL:",
            &payload.repeat(3),
        ]
        .concat();
        assert!(
            control == expected,
            "control byte mismatch {policy}: {}",
            control.len()
        );
        assert_eq!(stdout, b"OUTAOUTBOUTC");
        let interpreter_warning = format!("Failed to find real location of {python_executable}\n");
        let expected_stderr = b"ERRAERRBERRC";
        assert!(
            stderr == expected_stderr
                || (policy == "workspace-contained"
                    && stderr == [interpreter_warning.as_bytes(), expected_stderr].concat()),
            "stderr separation {policy}: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(terminal["result"]["exit_code"], 7, "{terminal}");
        assert_eq!(terminal["result"]["cleanup_complete"], true, "{terminal}");
        assert_eq!(terminal["result"]["control_bytes"], control.len());
        assert_eq!(terminal["result"]["stdout_bytes"], stdout.len());
        assert_eq!(terminal["result"]["stderr_bytes"], stderr.len());
        assert_eq!(
            terminal["result"]["sandbox"]["enforced"],
            policy != "danger-full-access"
        );
        let audit = std::fs::read_to_string(tmp.path().join(audit_path.context("audit path")?))?;
        assert!(!audit.contains(std::str::from_utf8(canary)?));
        assert!(!audit.contains(&STANDARD.encode(&payload[..canary.len()])));
        let events = audit
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert!(events.iter().all(|event| event.get("data").is_none()));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                ))
                .count(),
            1
        );
        client.send(50, "cancelExecution", json!({"execution_id":peer}))?;
        let mut accepted = false;
        loop {
            let message = client.next(Duration::from_secs(10))?;
            if message["id"] == 50 {
                assert_eq!(message["result"]["status"], "canceling", "{message}");
                accepted = true;
            }
            if message["params"]["execution_id"] == peer
                && message["params"]["type"] == "execution.failed"
            {
                assert_eq!(
                    message["params"]["result"]["cleanup_complete"], true,
                    "{message}"
                );
                break;
            }
        }
        assert!(accepted);
        assert!(!process_present(peer_pid)?);
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn rpc_control_remains_live_with_blocked_stdin_and_cancels_after_control_backpressure() -> Result<()>
{
    let _guard = process_test_gate();
    for policy in ["danger-full-access", "workspace-write"] {
        let tmp = TempDir::new()?;
        let mut client = Client::spawn("service")?;
        let code = "import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']); print('READY '+str(os.getpid())+' '+str(child.pid),flush=True); data=b''\nwhile len(data)<5: data+=os.read(3,5-len(data))\nos.write(3,data); print('FROZEN',flush=True); time.sleep(120)";
        client.send(1,"execute",json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":policy,"stdin":{"mode":"stream"},"io":{"mode":"pipe","control":{"mode":"pipe","child_fd":3}}}))?;
        let receipt = client.next(Duration::from_secs(2))?;
        assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
        let id = receipt["result"]["execution_id"]
            .as_str()
            .context("ID")?
            .to_owned();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut ready = Vec::new();
        while !ready.ends_with(b"\n") {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            assert_ne!(message["params"]["type"], "execution.failed", "{message}");
            if message["params"]["type"] == "execution.stdout" {
                ready.extend(
                    STANDARD.decode(
                        message["params"]["data"]
                            .as_str()
                            .context("data")?
                            .strip_prefix("base64:")
                            .context("prefix")?,
                    )?,
                );
            }
        }
        let pids: Vec<u32> = std::str::from_utf8(&ready)?
            .trim()
            .strip_prefix("READY ")
            .context("ready")?
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<_, _>>()?;
        assert_eq!(pids.len(), 2);
        let _fixture = HeartbeatFixture {
            directory: tmp.path().to_owned(),
            pids: pids.clone(),
        };
        client.send(2,"writeExecutionInput",json!({"execution_id":id,"stream":"stdin","encoding":"base64","data":format!("base64:{}",STANDARD.encode(vec![0;64*1024]))}))?;
        assert_eq!(
            client.next(Duration::from_secs(2))?["result"]["accepted_bytes"],
            64 * 1024
        );
        client.send(3,"writeExecutionInput",json!({"execution_id":id,"stream":"control","encoding":"base64","data":format!("base64:{}",STANDARD.encode(b"PING!"))}))?;
        let mut echo = Vec::new();
        let mut accepted = false;
        let mut frozen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while echo.len() < 5 || !accepted || !frozen.ends_with(b"\n") {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            if message["id"] == 3 {
                assert_eq!(message["result"]["accepted_bytes"], 5, "{message}");
                accepted = true;
            }
            let event = &message["params"];
            if event["type"] == "execution.control" {
                echo.extend(
                    STANDARD.decode(
                        event["data"]
                            .as_str()
                            .context("data")?
                            .strip_prefix("base64:")
                            .context("prefix")?,
                    )?,
                );
            }
            if event["type"] == "execution.stdout" {
                let bytes = STANDARD.decode(
                    event["data"]
                        .as_str()
                        .context("data")?
                        .strip_prefix("base64:")
                        .context("prefix")?,
                )?;
                frozen.extend_from_slice(&bytes);
            }
            assert_ne!(event["type"], "execution.failed", "{message}");
        }
        assert_eq!(echo, b"PING!");
        assert_eq!(frozen, b"FROZEN\r\n");
        let mut backpressure = false;
        for request_id in 10..74 {
            client.send(request_id,"writeExecutionInput",json!({"execution_id":id,"stream":"control","encoding":"base64","data":format!("base64:{}",STANDARD.encode(vec![0;64*1024]))}))?;
            let response = client.next(Duration::from_secs(2))?;
            assert_eq!(response["id"], request_id, "{response}");
            if response["error"]["data"]["code"] == "INPUT_BACKPRESSURE" {
                backpressure = true;
                break;
            }
            assert_eq!(
                response["result"]["accepted_bytes"],
                64 * 1024,
                "{response}"
            );
        }
        assert!(
            backpressure,
            "control must bound pending and in-flight bytes"
        );
        client.send(80, "cancelExecution", json!({"execution_id":id}))?;
        assert_eq!(
            client.next(Duration::from_secs(2))?["result"]["status"],
            "canceling"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let terminal = loop {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            if message["params"]["type"] == "execution.failed" {
                break message["params"]["result"].clone();
            }
        };
        assert_eq!(terminal["termination_reason"], "cancelled", "{terminal}");
        assert_eq!(terminal["cleanup_complete"], true, "{terminal}");
        for pid in pids {
            assert!(!process_present(pid)?, "owned control process survived");
        }
        assert!(!tmp.path().join(".runseal/runtime").join(id).exists());
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn rpc_control_output_shares_the_execution_output_limit() -> Result<()> {
    let _guard = process_test_gate();
    for policy in ["danger-full-access", "workspace-write"] {
        let tmp = TempDir::new()?;
        let mut client = Client::spawn("service")?;
        let code = "import os,time; os.write(1,b'A'*65536); os.write(2,b'B'*65536)\nwhile True: os.write(3,b'C'*65536)";
        client.send(1,"execute",json!({"command":[python()?,"-u","-c",code],"cwd":tmp.path(),"policy":{"version":"runseal.policy/v1","sandbox_level":policy,"resources":{"max_output_bytes":196608}},"io":{"mode":"pipe","control":{"mode":"pipe","child_fd":3}}}))?;
        let receipt = client.next(Duration::from_secs(2))?;
        assert_eq!(receipt["result"]["status"], "preparing", "{receipt}");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut bytes = 0usize;
        let mut saw_control = false;
        let terminal = loop {
            let message = client.next(deadline.saturating_duration_since(Instant::now()))?;
            let event = &message["params"];
            if matches!(
                event["type"].as_str(),
                Some("execution.stdout" | "execution.stderr" | "execution.control")
            ) {
                bytes += STANDARD
                    .decode(
                        event["data"]
                            .as_str()
                            .context("data")?
                            .strip_prefix("base64:")
                            .context("prefix")?,
                    )?
                    .len();
                saw_control |= event["type"] == "execution.control";
            }
            if event["type"] == "execution.failed" {
                break event["result"].clone();
            }
        };
        assert!(saw_control);
        assert!(bytes <= 196608);
        assert_eq!(
            terminal["error"]["code"], "OUTPUT_LIMIT_EXCEEDED",
            "{terminal}"
        );
        assert_eq!(terminal["termination_reason"], "output_limit", "{terminal}");
        assert_eq!(terminal["cleanup_complete"], true, "{terminal}");
        assert_eq!(terminal["output_truncated"], true, "{terminal}");
        assert!(
            terminal["control_bytes"]
                .as_u64()
                .context("control count")?
                > 0
        );
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn cli_control_fd3_forwards_binary_rounds_and_half_close_with_separate_stdio() -> Result<()> {
    use std::io::{Read, Write};
    let _guard = process_test_gate();
    for policy in ["danger-full-access", "workspace-write"] {
        let tmp = TempDir::new()?;
        let code = r#"import os,sys
os.write(3,b'READY')
all_data=b''
for _ in range(3):
 data=b''
 while len(data)<128*1024:
  chunk=os.read(3,min(8192,128*1024-len(data)))
  assert chunk
  data+=chunk
 os.write(3,data)
 all_data+=data
assert os.read(3,1)==b''
os.write(1,b'OUT:'+all_data)
os.write(2,b'ERR:'+all_data)
os.write(3,b'FINAL:'+all_data)
sys.exit(7)
"#;
        let mut cli = codex_windows_sandbox::LocalExecutionProcess::spawn_with_control(
            &[
                env!("CARGO_BIN_EXE_runseal").into(),
                "exec".into(),
                "--control-fd".into(),
                "3".into(),
                "--policy".into(),
                policy.into(),
                "--cwd".into(),
                tmp.path().to_string_lossy().into_owned(),
                "--".into(),
                python()?,
                "-u".into(),
                "-c".into(),
                code.into(),
            ],
            tmp.path(),
            &std::env::vars().collect(),
            false,
        )?;
        let mut control = cli.control.take().context("caller control")?;
        let mut stdout = cli.stdout.take().context("stdout")?;
        let mut stderr = cli.stderr.take().context("stderr")?;
        let output_reader = std::thread::spawn(move || {
            let mut data = Vec::new();
            stdout.read_to_end(&mut data).map(|_| data)
        });
        let error_reader = std::thread::spawn(move || {
            let mut data = Vec::new();
            stderr.read_to_end(&mut data).map(|_| data)
        });
        let deadline = Instant::now() + Duration::from_secs(20);
        let receive = |control: &mut codex_windows_sandbox::DuplexControl,
                       expected: usize|
         -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            while bytes.len() < expected {
                let mut buffer = vec![0; (expected - bytes.len()).min(64 * 1024)];
                match control.read(&mut buffer) {
                    Ok(0) => anyhow::bail!("CLI control premature EOF"),
                    Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "CLI control read watchdog {policy}"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(bytes)
        };
        assert_eq!(
            receive(&mut control, 5)
                .with_context(|| format!("CLI control readiness failed for {policy}"))?,
            b"READY"
        );
        let payload: Vec<u8> = (0..128 * 1024).map(|index| (index % 256) as u8).collect();
        for _ in 0..3 {
            let mut offset = 0;
            while offset < payload.len() {
                match control.write(&payload[offset..]) {
                    Ok(count) => {
                        assert!(count > 0);
                        offset += count;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "CLI control write watchdog");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            assert!(
                receive(&mut control, payload.len())? == payload,
                "binary round"
            );
        }
        control.close_input()?;
        let all_data = payload.repeat(3);
        let expected = [b"FINAL:".as_slice(), &all_data].concat();
        assert!(
            receive(&mut control, expected.len())? == expected,
            "final reverse bytes"
        );
        while cli.try_wait()?.is_none() {
            assert!(Instant::now() < deadline, "CLI exit watchdog");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(cli.finish(Duration::from_secs(5))?, 7);
        assert!(
            output_reader.join().expect("stdout reader")?
                == [b"OUT:".as_slice(), &all_data].concat()
        );
        assert!(
            error_reader.join().expect("stderr reader")?
                == [b"ERR:".as_slice(), &all_data].concat()
        );
        let events = std::fs::read_dir(tmp.path().join(".runseal/audit"))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(events.len(), 1);
        let audit = std::fs::read_to_string(events[0].path())?;
        let terminal = audit
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .find(|event| event["type"] == "execution.finished")
            .context("terminal")?;
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        assert_eq!(
            terminal["result"]["control_bytes"],
            5 + payload.len() * 3 + expected.len()
        );
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn cli_control_stalled_caller_cleans_owned_range_and_preserves_peer() -> Result<()> {
    use std::io::{Read, Write};
    let _guard = process_test_gate();
    for policy in ["danger-full-access", "workspace-write"] {
        let tmp = TempDir::new()?;
        let mut peer_client = Client::spawn("service")?;
        peer_client.send(1,"execute",json!({"command":[python()?,"-u","-c","import os,pathlib,time; print('READY '+str(os.getpid()),flush=True); count=0\nwhile True:\n count+=1; pathlib.Path('cli-control-peer.beat').write_text(str(count)); time.sleep(0.01)"],"cwd":tmp.path(),"policy":policy}))?;
        let receipt = peer_client.next(Duration::from_secs(2))?;
        let peer = receipt["result"]["execution_id"]
            .as_str()
            .context("peer")?
            .to_owned();
        let peer_pid = wait_ready_pid(&peer_client, &peer)?;
        let code = "import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']); print('READY '+str(os.getpid())+' '+str(child.pid),flush=True); assert os.read(3,1)==b'G'\nwhile True: os.write(3,b'Z'*65536)";
        let mut cli = codex_windows_sandbox::LocalExecutionProcess::spawn_with_control(
            &[
                env!("CARGO_BIN_EXE_runseal").into(),
                "exec".into(),
                "--control-fd".into(),
                "3".into(),
                "--policy".into(),
                policy.into(),
                "--cwd".into(),
                tmp.path().to_string_lossy().into_owned(),
                "--".into(),
                python()?,
                "-u".into(),
                "-c".into(),
                code.into(),
            ],
            tmp.path(),
            &std::env::vars().collect(),
            false,
        )?;
        let mut unread_control = cli.control.take().context("caller control")?;
        let mut stdout = cli.stdout.take().context("stdout")?;
        let mut ready = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.ends_with(b"\n") {
            if let Some(count) = codex_windows_sandbox::available_pipe_bytes(&stdout)?
                && count > 0
            {
                let mut bytes = vec![0; count.min(8192)];
                let count = stdout.read(&mut bytes)?;
                ready.extend_from_slice(&bytes[..count]);
            }
            assert!(Instant::now() < deadline, "CLI control readiness");
            std::thread::sleep(Duration::from_millis(5));
        }
        let pids = std::str::from_utf8(&ready)?
            .trim()
            .strip_prefix("READY ")
            .context("READY")?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(pids.len(), 2);
        unread_control.write_all(b"G")?;
        let mut fixture_pids = pids.clone();
        fixture_pids.push(peer_pid);
        let _fixture = HeartbeatFixture {
            directory: tmp.path().to_owned(),
            pids: fixture_pids,
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        while cli.try_wait()?.is_none() {
            assert!(Instant::now() < deadline, "CLI stalled control watchdog");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_ne!(cli.finish(Duration::from_secs(5))?, 0);
        for pid in pids {
            assert!(!process_present(pid)?);
        }
        let mut terminal = None;
        let mut audit_summaries = Vec::new();
        for file in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
            let audit = std::fs::read_to_string(file?.path())?;
            for event in audit.lines().map(serde_json::from_str::<Value>) {
                let event = event?;
                if event["type"] == "execution.failed"
                    && event["result"]["error"]["code"] == "CLIENT_BACKPRESSURE"
                {
                    terminal = Some(event);
                } else {
                    audit_summaries.push(json!({
                        "type":event["type"],
                        "error_code":event["result"]["error"]["code"],
                        "termination_reason":event["result"]["termination_reason"],
                        "cleanup_complete":event["result"]["cleanup_complete"],
                    }));
                }
            }
        }
        let terminal = terminal.ok_or_else(|| {
            anyhow::anyhow!(
                "durable backpressure terminal missing; safe audit summaries: {audit_summaries:?}"
            )
        })?;
        assert_eq!(
            terminal["result"]["termination_reason"], "backpressure",
            "{terminal}"
        );
        assert_eq!(terminal["result"]["cleanup_complete"], true, "{terminal}");
        assert!(
            !tmp.path()
                .join(".runseal/runtime")
                .join(terminal["execution_id"].as_str().context("execution")?)
                .exists()
        );
        assert!(process_present(peer_pid)?);
        let before =
            std::fs::read_to_string(tmp.path().join("cli-control-peer.beat")).unwrap_or_default();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let after = std::fs::read_to_string(tmp.path().join("cli-control-peer.beat"))
                .unwrap_or_default();
            if !after.is_empty() && after != before {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "peer heartbeat after stalled control"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        peer_client.send(9, "cancelExecution", json!({"execution_id":peer}))?;
        loop {
            let message = peer_client.next(Duration::from_secs(10))?;
            if message["params"]["execution_id"] == peer
                && message["params"]["type"] == "execution.failed"
            {
                assert_eq!(message["params"]["result"]["cleanup_complete"], true);
                break;
            }
        }
        assert!(!process_present(peer_pid)?);
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires a prepared Windows sandbox identity; run with --include-ignored"]
fn cli_stdio_stalled_or_disconnected_caller_cleans_owned_range_and_preserves_peer() -> Result<()> {
    use std::io::Read;
    let _guard = process_test_gate();
    for (policy, events, stream, failure) in ["danger-full-access", "workspace-write"]
        .into_iter()
        .flat_map(|policy| {
            [
                (false, 1, "paused"),
                (false, 2, "paused"),
                (false, 1, "closed"),
                (false, 2, "closed"),
                (false, 1, "timeout"),
                (false, 2, "timeout"),
                (true, 1, "paused"),
                (true, 1, "closed"),
                (true, 1, "timeout"),
            ]
            .into_iter()
            .map(move |(events, stream, failure)| (policy, events, stream, failure))
        })
    {
        eprintln!("stdio case {policy} events={events} stream={stream} failure={failure}");
        let disconnect = failure == "closed";
        let tmp = TempDir::new()?;
        let mut peer_client = Client::spawn("service")?;
        peer_client.send(1,"execute",json!({"command":[python()?,"-u","-c","import os,pathlib,time; print('READY '+str(os.getpid()),flush=True); count=0\nwhile not pathlib.Path('peer.stop').exists():\n count+=1; pathlib.Path('cli-control-peer.beat').write_text(str(count)); time.sleep(0.01)"],"cwd":tmp.path(),"policy":policy}))?;
        let receipt = peer_client.next(Duration::from_secs(2))?;
        let peer = receipt["result"]["execution_id"]
            .as_str()
            .context("peer")?
            .to_owned();
        let peer_pid = wait_ready_pid(&peer_client, &peer)?;
        let mut fixture = HeartbeatFixture {
            directory: tmp.path().to_owned(),
            pids: vec![peer_pid],
        };
        let code = format!(
            "import os,pathlib,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']); ready='READY '+str(os.getpid())+' '+str(child.pid); print(ready,flush=True); pathlib.Path('stdio-ready.txt').write_text(ready)\nwhile not pathlib.Path('stdio-go.txt').exists(): time.sleep(0.005)\nwhile True: os.write({stream},b'Z'*65536)"
        );
        let mut command = vec![
            env!("CARGO_BIN_EXE_runseal").into(),
            "exec".into(),
            "--policy".into(),
            policy.into(),
            "--cwd".into(),
            tmp.path().to_string_lossy().into_owned(),
            "--timeout-ms".into(),
            if failure == "timeout" {
                "4000"
            } else {
                "20000"
            }
            .into(),
        ];
        if events {
            command.push("--events".into());
        }
        command.extend(["--".into(), python()?, "-u".into(), "-c".into(), code]);
        let mut cli = codex_windows_sandbox::LocalExecutionProcess::spawn(
            &command,
            tmp.path(),
            &std::env::vars().collect(),
            false,
        )?;
        let mut stdout = cli.stdout.take().context("stdout")?;
        let ready_path = tmp.path().join("stdio-ready.txt");
        let mut ready_contents = String::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let pids = loop {
            if let Ok(contents) = std::fs::read_to_string(&ready_path) {
                ready_contents = contents;
                if let Some(pids) = ready_contents
                    .trim()
                    .strip_prefix("READY ")
                    .and_then(|pids| {
                        let pids = pids
                            .split_whitespace()
                            .map(str::parse::<u32>)
                            .collect::<std::result::Result<Vec<_>, _>>()
                            .ok()?;
                        (pids.len() == 2).then_some(pids)
                    })
                {
                    break pids;
                }
            }
            if let Some(count) = codex_windows_sandbox::available_pipe_bytes(&stdout)?
                && count > 0
            {
                let mut bytes = vec![0; count.min(8192)];
                stdout.read_exact(&mut bytes)?;
            }
            assert!(
                Instant::now() < deadline,
                "CLI control readiness: {ready_contents:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        fixture.pids.extend(pids.iter().copied());
        let held_output = if stream == 1 {
            Some(stdout)
        } else {
            cli.stderr.take()
        };
        let held_output = if disconnect {
            drop(held_output);
            None
        } else {
            held_output
        };
        std::fs::write(tmp.path().join("stdio-go.txt"), b"G")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while cli.try_wait()?.is_none() {
            assert!(
                Instant::now() < deadline,
                "CLI stdio watchdog {policy} events={events} stream={stream} failure={failure}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let exit = cli.finish(Duration::from_secs(5))?;
        if events {
            assert_ne!(exit, 0);
        } else {
            assert_eq!(exit, if failure == "timeout" { 124 } else { 125 });
        }
        for pid in pids {
            assert!(!process_present(pid)?);
        }
        drop(held_output);
        let expected_code = if disconnect {
            "CLIENT_DISCONNECTED"
        } else if failure == "timeout" {
            "EXECUTION_TIMEOUT"
        } else {
            "CLIENT_BACKPRESSURE"
        };
        let expected_reason = if disconnect {
            "client_disconnected"
        } else if failure == "timeout" {
            "timeout"
        } else {
            "backpressure"
        };
        let mut terminal = None;
        let mut terminal_count = 0;
        let mut observed_terminals = Vec::new();
        for file in std::fs::read_dir(tmp.path().join(".runseal/audit"))? {
            let audit = std::fs::read_to_string(file?.path())?;
            for event in audit.lines().map(serde_json::from_str::<Value>) {
                let event = event?;
                if matches!(
                    event["type"].as_str(),
                    Some("execution.failed" | "execution.finished")
                ) {
                    observed_terminals.push(event.clone());
                }
                if event["type"] == "execution.failed"
                    && event["result"]["error"]["code"] == expected_code
                {
                    terminal_count += 1;
                    terminal = Some(event);
                }
            }
        }
        assert_eq!(
            terminal_count, 1,
            "unique durable terminal: {observed_terminals:?}"
        );
        let terminal = terminal.context(format!("durable stdio terminal {policy} events={events} stream={stream} failure={failure}: {observed_terminals:?}"))?;
        assert!(!terminal["result"]["started_at"].is_null(), "{terminal}");
        assert_eq!(
            terminal["result"]["termination_reason"], expected_reason,
            "{terminal}"
        );
        assert_eq!(terminal["result"]["cleanup_complete"], true, "{terminal}");
        assert!(
            !tmp.path()
                .join(".runseal/runtime")
                .join(terminal["execution_id"].as_str().context("execution")?)
                .exists()
        );
        assert!(process_present(peer_pid)?);
        let before =
            std::fs::read_to_string(tmp.path().join("cli-control-peer.beat")).unwrap_or_default();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let after = std::fs::read_to_string(tmp.path().join("cli-control-peer.beat"))
                .unwrap_or_default();
            if !after.is_empty() && after != before {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "peer heartbeat after stalled control"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        peer_client.send(9, "cancelExecution", json!({"execution_id":peer}))?;
        loop {
            let message = peer_client.next(Duration::from_secs(10))?;
            if message["params"]["execution_id"] == peer
                && message["params"]["type"] == "execution.failed"
            {
                assert_eq!(message["params"]["result"]["cleanup_complete"], true);
                break;
            }
        }
        assert!(!process_present(peer_pid)?);
    }
    Ok(())
}

#[cfg(windows)]
#[path = "support/storage_oplock.rs"]
mod storage_oplock;
