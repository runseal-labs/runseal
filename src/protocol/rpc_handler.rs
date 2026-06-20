use serde_json::Value;
use std::io::{self, BufRead, Write};

use crate::{error::RunSealError, rpc};

pub(crate) fn run_rpc_stdio() -> Result<(), String> {
    run_stdio(false)
}

pub(crate) fn run_service_stdio() -> Result<(), String> {
    run_stdio(true)
}

fn run_stdio(stateful: bool) -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut service = stateful.then(crate::service::Service::stateful);
    for line in stdin.lock().lines() {
        let line = line.map_err(|err| format!("failed to read stdin: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(err) => {
                let message = rpc::error(
                    Value::Null,
                    RunSealError::new(
                        "INVALID_REQUEST",
                        format!("invalid JSON-RPC request: {err}"),
                    ),
                );
                writeln!(stdout, "{message}")
                    .map_err(|err| format!("failed to write stdout: {err}"))?;
                stdout
                    .flush()
                    .map_err(|err| format!("failed to flush stdout: {err}"))?;
                continue;
            }
        };
        let messages = match service.as_mut() {
            Some(service) => service.handle_rpc_request(&request),
            None => crate::service::Service::direct().handle_rpc_request(&request),
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
