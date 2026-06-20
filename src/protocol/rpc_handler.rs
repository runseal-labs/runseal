use serde_json::Value;
use std::io::{self, BufRead, Write};

pub(crate) fn run_rpc_stdio() -> Result<(), String> {
    run_stdio(false)
}

pub(crate) fn run_service_stdio() -> Result<(), String> {
    run_stdio(true)
}

fn run_stdio(stateful: bool) -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut service = stateful.then(crate::service::Service::default);
    for line in stdin.lock().lines() {
        let line = line.map_err(|err| format!("failed to read stdin: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = serde_json::from_str(&line)
            .map_err(|err| format!("invalid JSON-RPC request: {err}"))?;
        let messages = match service.as_mut() {
            Some(service) => service.handle_rpc_request(&request),
            None => crate::service::Service::default().handle_rpc_request(&request),
        };
        for message in messages {
            writeln!(stdout, "{message}")
                .map_err(|err| format!("failed to write stdout: {err}"))?;
            stdout
                .flush()
                .map_err(|err| format!("failed to flush stdout: {err}"))?;
        }
    }
    Ok(())
}
