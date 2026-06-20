use serde_json::Value;
use std::io::{self, BufRead, Write};

pub(crate) fn run_rpc_stdio() -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut service = crate::service::Service::default();
    for line in stdin.lock().lines() {
        let line = line.map_err(|err| format!("failed to read stdin: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = serde_json::from_str(&line)
            .map_err(|err| format!("invalid JSON-RPC request: {err}"))?;
        for message in service.handle_rpc_request(&request) {
            writeln!(stdout, "{message}")
                .map_err(|err| format!("failed to write stdout: {err}"))?;
            stdout
                .flush()
                .map_err(|err| format!("failed to flush stdout: {err}"))?;
        }
    }
    Ok(())
}
