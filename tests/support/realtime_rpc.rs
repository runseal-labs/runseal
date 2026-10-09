use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Output};
use std::time::Duration;

pub fn collect_rpc_with_watchdog(
    mut child: Child,
    message: &str,
    watchdog: Duration,
) -> Result<Output> {
    struct OwnedRpc(std::process::Child);
    impl Drop for OwnedRpc {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut input = child.stdin.take().context("stdin unavailable")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let stderr = child.stderr.take().context("stderr unavailable")?;
    let diagnostics = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut BufReader::new(stderr), &mut bytes)?;
        Ok(bytes)
    });
    let mut child = OwnedRpc(child);
    let (sender, lines) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        loop {
            let mut line = Vec::new();
            match stdout.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if sender.send(Ok(line)).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    let _ = sender.send(Err(err));
                    break;
                }
            }
        }
    });
    input.write_all(message.as_bytes())?;
    input.flush()?;
    let expected = message
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter(|line| {
            !serde_json::from_str::<Value>(line)
                .ok()
                .is_some_and(|request| {
                    request["jsonrpc"] == "2.0"
                        && request["method"].is_string()
                        && request.get("id").is_none()
                })
        })
        .count();
    let mut responses = 0;
    let mut active = std::collections::BTreeSet::new();
    let mut transcript = Vec::new();
    let mut observed_events = Vec::new();
    // The receipt remains a receipt in this raw transcript. Hold the connection open
    // until every admitted execution publishes its own terminal; EOF would cancel it.
    while responses < expected || !active.is_empty() {
        let line = lines
            .recv_timeout(watchdog)
            .with_context(|| {
                format!(
                    "RPC response/terminal watchdog (responses={responses}/{expected}, active_executions={}, observed={})",
                    active.len(),
                    observed_events.join(" -> ")
                )
            })??;
        let value: Value = serde_json::from_slice(&line)?;
        if value.get("id").is_some() {
            responses += 1;
            if value["result"]["status"] == "preparing" {
                active.insert(
                    value["result"]["execution_id"]
                        .as_str()
                        .context("receipt execution ID")?
                        .to_owned(),
                );
            }
        }
        if matches!(
            value["params"]["type"].as_str(),
            Some("execution.finished" | "execution.failed")
        ) {
            active.remove(
                value["params"]["execution_id"]
                    .as_str()
                    .context("terminal execution ID")?,
            );
        }
        let summary = if value.get("id").is_some() {
            let status = value["result"]["status"].as_str();
            let code = value["error"]["data"]["code"].as_str();
            format!("response(status={status:?},code={code:?})")
        } else {
            let event_type = value["params"]["type"].as_str().unwrap_or("notification");
            let sequence = value["params"]["event_seq"].as_u64();
            let code = value["params"]["result"]["error"]["code"].as_str();
            format!("event(type={event_type},seq={sequence:?},code={code:?})")
        };
        observed_events.push(summary);
        if observed_events.len() > 16 {
            observed_events.remove(0);
        }
        transcript.extend_from_slice(&line);
    }
    drop(input);
    let status = child.0.wait()?;
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("RPC reader panicked"))?;
    for line in lines {
        transcript.extend_from_slice(&line?);
    }
    let stderr = diagnostics
        .join()
        .map_err(|_| anyhow::anyhow!("RPC diagnostic reader panicked"))??;
    Ok(Output {
        status,
        stdout: transcript,
        stderr,
    })
}

pub fn terminal_or_response(messages: &[Value]) -> Result<&Value> {
    let receipt = messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .context("RPC response with id 1")?;
    if receipt["result"]["status"] != "preparing" {
        return Ok(receipt);
    }
    let id = receipt["result"]["execution_id"]
        .as_str()
        .context("receipt execution ID")?;
    let terminals: Vec<_> = messages
        .iter()
        .filter_map(|message| message.get("params"))
        .filter(|event| {
            event["execution_id"] == id
                && matches!(
                    event["type"].as_str(),
                    Some("execution.finished" | "execution.failed")
                )
        })
        .collect();
    if terminals.len() != 1 {
        bail!("expected one terminal for {id}, got {}", terminals.len());
    }
    Ok(terminals[0])
}

pub fn stream_bytes(messages: &[Value], event_type: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for event in messages
        .iter()
        .filter_map(|message| message.get("params"))
        .filter(|event| event["type"] == event_type)
    {
        assert_eq!(event["stream_offset"].as_u64(), Some(bytes.len() as u64));
        let chunk = STANDARD.decode(
            event["data"]
                .as_str()
                .and_then(|data| data.strip_prefix("base64:"))
                .context("base64 output chunk")?,
        )?;
        assert_eq!(event["bytes"].as_u64(), Some(chunk.len() as u64));
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
