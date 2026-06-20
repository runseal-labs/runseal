use serde_json::Value;
use std::io::{self, BufRead, Write};
use std::sync::mpsc;
use std::thread;

use crate::rpc;

pub(crate) fn run_rpc_stdio() -> Result<(), String> {
    run_stdio(false)
}

pub(crate) fn run_service_stdio() -> Result<(), String> {
    run_stdio(true)
}

fn run_stdio(stateful: bool) -> Result<(), String> {
    if stateful {
        return run_stateful_stdio();
    }

    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(|err| format!("failed to read stdin: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(err) => {
                let message = rpc::parse_error(format!("invalid JSON-RPC request: {err}"));
                writeln!(stdout, "{message}")
                    .map_err(|err| format!("failed to write stdout: {err}"))?;
                stdout
                    .flush()
                    .map_err(|err| format!("failed to flush stdout: {err}"))?;
                continue;
            }
        };
        write_messages(
            &mut stdout,
            crate::service::Service::direct().handle_rpc_request(&request),
        )?;
    }
    Ok(())
}

fn run_stateful_stdio() -> Result<(), String> {
    let stdin = io::stdin();
    let service = crate::service::Service::stateful();
    let (sender, receiver) = mpsc::channel::<Vec<Value>>();
    let writer = thread::spawn(move || {
        let mut stdout = io::stdout().lock();
        for messages in receiver {
            write_messages(&mut stdout, messages)?;
        }
        Ok::<(), String>(())
    });

    for line in stdin.lock().lines() {
        let line = line.map_err(|err| format!("failed to read stdin: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(err) => {
                sender
                    .send(vec![rpc::parse_error(format!(
                        "invalid JSON-RPC request: {err}"
                    ))])
                    .map_err(|err| format!("failed to queue parse error: {err}"))?;
                continue;
            }
        };
        let messages = service.handle_rpc_request_with_sender(&request, Some(sender.clone()));
        if !messages.is_empty() {
            sender
                .send(messages)
                .map_err(|err| format!("failed to queue response: {err}"))?;
        }
    }

    service.shutdown();
    drop(sender);
    writer
        .join()
        .map_err(|_| "service writer thread panicked".to_string())?
}

fn write_messages(stdout: &mut impl Write, messages: Vec<Value>) -> Result<(), String> {
    for message in messages {
        writeln!(stdout, "{message}").map_err(|err| format!("failed to write stdout: {err}"))?;
        stdout
            .flush()
            .map_err(|err| format!("failed to flush stdout: {err}"))?;
    }
    Ok(())
}
