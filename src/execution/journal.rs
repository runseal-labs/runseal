use super::ExecutionRequest;
use crate::audit::{AuditWriter, create_audit_writer, write_audit_event_with_metadata};
use crate::backend::SandboxBackend;
use crate::error::RunSealError;
use crate::events::{backend_event_json, timestamp_now};
use serde_json::{Value, json};

/// The execution worker alone commits sequence numbers and the unique terminal record.
type TerminalRange = Box<dyn FnMut(&Value) -> Result<u64, RunSealError> + Send>;

pub(crate) struct ExecutionJournal {
    audit: AuditWriter,
    metadata: Option<Value>,
    binding: Value,
    sequence: u64,
    prepared_requested: Option<Value>,
    durable_record_missing: bool,
    started_at: Option<Value>,
    pty: bool,
    terminal_range: Option<TerminalRange>,
}

impl ExecutionJournal {
    pub(crate) fn prepare(request: &ExecutionRequest) -> Result<Self, RunSealError> {
        let audit = create_audit_writer(&request.cwd, &request.ids.session_id)?;
        let backend = crate::backend::active_backend();
        let hash = request.policy.hash();
        let binding = json!({
            "execution_id": request.ids.execution_id, "session_id": request.ids.session_id,
            "seal_id": request.ids.seal_id, "policy_id": request.policy.id,
            "policy_hash": hash, "policy_epoch": hash,
            "backend": backend_event_json(backend.name(), backend.status(), backend.platform()),
            "audit_path": audit.relative_path(), "runseal_version": env!("CARGO_PKG_VERSION"),
        });
        let mut journal = Self {
            audit,
            metadata: request
                .metadata
                .as_ref()
                .map(crate::audit::redact_audit_value),
            binding,
            sequence: 0,
            prepared_requested: None,
            durable_record_missing: false,
            started_at: None,
            pty: request.io.is_pty(),
            terminal_range: None,
        };
        // Establish the required durable record before returning an admission receipt.
        let requested = journal.emit(&json!({"type":"execution.requested","decision":"requested","command_args":request.command.len()}), &mut |_| Ok(()))?;
        journal.prepared_requested = Some(requested);
        Ok(journal)
    }

    pub(crate) fn reject(mut self, code: &str, reason: &str) -> RunSealError {
        let approval = code == "APPROVAL_REQUIRED";
        if let Err(err) = self.emit(&json!({"type":if approval {"policy.requires_approval"} else {"policy.denied"},"decision":if approval {"requires_approval"} else {"denied"},"reason":reason}), &mut |_| Ok(())) { return err; }
        let mut details = self.binding.clone();
        details["cleanup_complete"] = json!(true);
        RunSealError::with_details(code, reason, details)
    }

    pub(crate) fn set_terminal_range(
        &mut self,
        range: impl FnMut(&Value) -> Result<u64, RunSealError> + Send + 'static,
    ) {
        self.terminal_range = Some(Box::new(range));
    }

    pub(crate) fn audit_path(&self) -> &str {
        self.audit.relative_path()
    }

    fn envelope(&self, payload: &Value) -> Value {
        let mut event = self.binding.clone();
        if let (Some(object), Some(payload)) = (event.as_object_mut(), payload.as_object()) {
            object.extend(payload.clone());
        }
        event["event_seq"] = json!(self.sequence);
        if event.get("time").is_none() {
            event["time"] = json!(timestamp_now());
        }
        event
    }

    pub(crate) fn emit(
        &mut self,
        payload: &Value,
        observer: &mut dyn FnMut(&Value) -> Result<(), RunSealError>,
    ) -> Result<Value, RunSealError> {
        if payload["type"] == "execution.requested"
            && let Some(requested) = self.prepared_requested.take()
        {
            observer(&requested)?;
            return Ok(requested);
        }
        self.sequence += 1;
        let event = self.envelope(payload);
        if event["type"] == "execution.started" {
            self.started_at = Some(event["time"].clone());
        }
        let audit_event = super::output::audit_stream_event_metadata(&event);
        if let Err(err) =
            write_audit_event_with_metadata(&mut self.audit, &audit_event, &self.metadata)
        {
            self.durable_record_missing = true;
            return Err(err);
        }
        observer(&event)?;
        Ok(event)
    }

    pub(crate) fn finish(
        mut self,
        outcome: Result<Value, RunSealError>,
        control: &super::ExecutionControl,
        observer: &mut dyn FnMut(&Value) -> Result<(), RunSealError>,
    ) -> Result<(Vec<Value>, Value), RunSealError> {
        let (mut result, mut error) = match outcome {
            Ok(result) => (result, None),
            Err(err) => {
                let mut result = self.binding.clone();
                if let (Some(object), Some(details)) = (
                    result.as_object_mut(),
                    err.details.as_ref().and_then(Value::as_object),
                ) {
                    object.extend(details.clone());
                }
                result["status"] = json!("failed");
                result["error"] = json!({"code":err.code,"reason":err.reason});
                (result, Some(err))
            }
        };
        result["termination_reason"] =
            json!(if result["error"]["code"] == "EXECUTION_CLEANUP_FAILED" {
                "cleanup_failed"
            } else {
                control
                    .cause()
                    .map_or("failed_to_start", super::TerminationCause::as_str)
            });
        if result["error"]["code"] == "EXECUTION_CLEANUP_FAILED" {
            result["requested_termination_reason"] =
                serde_json::json!(control.cause().map(super::TerminationCause::as_str));
        }
        result["stderr_merged"] = json!(self.pty);
        if result.get("terminal_bytes").is_none() {
            result["terminal_bytes"] = json!(0);
        }
        result["finished_at"] = json!(timestamp_now());
        if result.get("started_at").is_none() {
            result["started_at"] = self.started_at.clone().unwrap_or(Value::Null);
        }
        for (key, default) in [
            ("exit_code", Value::Null),
            ("signal", Value::Null),
            ("stdout_bytes", json!(0)),
            ("stderr_bytes", json!(0)),
            ("output_truncated", json!(false)),
            ("cleanup_complete", json!(false)),
        ] {
            if result.get(key).is_none() {
                result[key] = default;
            }
        }
        if result["error"]["code"] == "OUTPUT_LIMIT_EXCEEDED" {
            result["output_truncated"] = json!(true);
        }
        self.sequence += 1;
        result["latest_seq"] = json!(self.sequence);
        let mut summary = result.clone();
        if let Some(object) = summary.as_object_mut() {
            object.remove("stdout");
            object.remove("stderr");
        }
        summary["durable_record_missing"] = json!(self.durable_record_missing);
        let mut terminal = self.envelope(&json!({"type":if summary["status"] == "finished" {"execution.finished"} else {"execution.failed"},"result":summary}));
        if let Some(failure) = summary.get("error") {
            terminal["error"] = failure.clone();
        }
        // The transport samples insertion/eviction before the owner commits the immutable terminal.
        // Entry points without event replay expose an empty transport-retention range.
        let earliest = if let Some(range) = &mut self.terminal_range {
            terminal["result"]["earliest_available_seq"] = json!(0);
            match range(&terminal) {
                Ok(earliest) => earliest,
                Err(_) => self.sequence + 1,
            }
        } else {
            self.sequence + 1
        };
        summary["earliest_available_seq"] = json!(earliest);
        result["earliest_available_seq"] = json!(earliest);
        terminal["result"] = summary.clone();
        if let Err(audit_error) =
            write_audit_event_with_metadata(&mut self.audit, &terminal, &self.metadata)
        {
            self.durable_record_missing = true;
            summary["durable_record_missing"] = json!(true);
            summary["status"] = json!("failed");
            if summary["error"]["code"] != "EXECUTION_CLEANUP_FAILED" {
                summary["error"] = json!({"code":audit_error.code,"reason":audit_error.reason});
                error = Some(audit_error);
            }
            terminal["type"] = json!("execution.failed");
            terminal["result"] = summary.clone();
            terminal["error"] = summary["error"].clone();
        }
        result["durable_record_missing"] = json!(self.durable_record_missing);
        let delivery = observer(&terminal);
        if let Some(mut err) = error {
            err.details = Some(summary);
            err.terminal_event = Some(terminal);
            return Err(err);
        }
        if let Err(mut err) = delivery {
            err.details = Some(summary);
            err.terminal_event = Some(terminal);
            return Err(err);
        }
        Ok((vec![terminal], result))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::process::Command;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

    #[test]
    fn required_audit_write_failure_stops_real_process_and_reports_missing_terminal_record()
    -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let python = String::from_utf8(Command::new("where.exe").arg("python").output()?.stdout)?
            .lines()
            .next()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("Python required"))?;
        let request = ExecutionRequest {
            control_input: None,
            io: crate::backend::ExecutionIo::Pipe,
        ids: crate::events::new_execution_ids(), control: super::super::ExecutionControl::default(),
            command: vec![python,"-u".to_string(),"-c".to_string(),"import os,pathlib,time; pathlib.Path('owned.pid').write_text(str(os.getpid())); print('READY',flush=True)
while True: pathlib.Path('heartbeat').write_text(str(time.monotonic())); time.sleep(0.01)".to_string()],
            cwd:tmp.path().to_owned(), policy:crate::policy::normalize_policy(&json!("danger-full-access"),tmp.path(),None).map_err(|err|anyhow::anyhow!(err.reason))?,
            stdin:crate::backend::ExecutionStdin::Empty, env:crate::backend::ExecutionEnv::default(), metadata:None, timeout:Some(std::time::Duration::from_secs(10)),
        };
        let mut journal =
            ExecutionJournal::prepare(&request).map_err(|err| anyhow::anyhow!(err.message))?;
        let audit_path = journal.audit_path().to_owned();
        // Replace the actual file with a read-only handle after resolved/allowed/started.
        // The next write fails through the filesystem while the real process is active.
        journal.audit.deny_writes_after(tmp.path(), 3)?;
        let mut events = Vec::new();
        let outcome = super::super::execute_prepared_with_events(request, journal, &mut |event| {
            events.push(event.clone());
            Ok(())
        });
        let err = outcome
            .err()
            .ok_or_else(|| anyhow::anyhow!("audit failure must fail execution"))?;
        assert_eq!(err.code, "INTERNAL_ERROR");
        let terminal = err
            .terminal_event
            .ok_or_else(|| anyhow::anyhow!("structured terminal required"))?;
        assert_eq!(terminal["result"]["durable_record_missing"], true);
        assert_eq!(terminal["result"]["cleanup_complete"], true);
        assert_eq!(terminal["result"]["termination_reason"], "execution_failed");
        assert_eq!(
            events
                .iter()
                .filter(|event| event["type"] == "execution.failed")
                .count(),
            1
        );
        let pid: u32 = std::fs::read_to_string(tmp.path().join("owned.pid"))?.parse()?;
        let process = unsafe { OpenProcess(0x0010_0000, 0, pid) };
        if process.is_null() {
            assert_eq!(
                unsafe { GetLastError() },
                87,
                "only absent PID proves removal"
            );
        } else {
            let state = unsafe { WaitForSingleObject(process, 0) };
            unsafe { CloseHandle(process) };
            assert_eq!(
                state, WAIT_OBJECT_0,
                "audit failure must stop the actual owned process"
            );
        }
        let audit = std::fs::read_to_string(tmp.path().join(audit_path))?;
        assert!(!audit.contains("execution.finished"));
        assert!(
            !audit.contains("execution.failed"),
            "failed durable write cannot be reported as persisted"
        );
        assert!(!audit.contains("READY"));
        Ok(())
    }
}
