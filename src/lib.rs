mod audit;
mod backend;
mod cli;
mod commands;
mod error;
mod events;
mod policy;
mod process_output;
mod protocol;
mod rpc;
mod stdin;
mod windows;

#[cfg(windows)]
use crate::windows::vendor_adapter::WindowsVendorSandboxProfile;
use audit::{create_audit_writer, write_audit_event_with_metadata};
use backend::{
    ExecutionEnv, ExecutionStdin, SandboxBackend, active_backend, backend_unavailable_reason,
    policy_transition_busy_reason,
};
use cli::{parse_exec_args, parse_policy_args};
#[cfg(all(test, not(windows)))]
use commands::setup::{windows_sandbox_setup_failed_error, windows_sandbox_setup_status_payload};
#[cfg(all(test, windows))]
use commands::setup::{
    windows_sandbox_setup_failed_error, windows_sandbox_setup_status_payload,
    windows_sandbox_setup_success_payload,
};
use error::RunSealError;
use events::{
    ExecutionEventContext, backend_event_json, execution_event_at, execution_event_now,
    new_execution_ids, stream_event, timestamp_now,
};
use policy::{
    NetworkMode, POLICY_VERSION, SandboxPolicy, matches_environment_scrub_pattern, normalize_policy,
};
use process_output::decode_process_output;
use protocol::request_validation::duration_millis_u64;
use serde_json::{Map, Value, json};
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};
use stdin::{stdin_audit_json, stdin_from_params};

const PROTOCOL_VERSION: &str = "runseal.protocol/v1";
const MAX_METADATA_BYTES: usize = 4096;
const MAX_PROTOCOL_ID_BYTES: usize = 128;
const MAX_ENV_ENTRIES: usize = 64;
const MAX_ENV_KEY_BYTES: usize = 128;
const MAX_ENV_VALUE_BYTES: usize = 4096;
const WINDOWS_SANDBOX_SETUP_FAILED: &str = "windows sandbox setup failed; first install requires an elevated shell; later repairs can reuse the setup broker";
const WINDOWS_SANDBOX_UNSUPPORTED: &str = "windows sandbox setup is only supported on Windows";

pub fn run_cli() {
    if let Err(err) = run() {
        if !err.is_empty() {
            eprintln!("{err}");
        }
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--help" || flag == "-h" => commands::print_help(),
        [command] if command == "help" => commands::print_help(),
        [flag] if flag == "--version" => commands::version::print_plain(),
        [json_flag, command] if json_flag == "--json" && command == "version" => {
            commands::version::print_json()
        }
        [command, json_flag] if command == "version" && json_flag == "--json" => {
            commands::version::print_json()
        }
        [command] if command == "version" => commands::version::print_plain(),
        [command] if command == "capabilities" => commands::capabilities::run(),
        [command, flag] if command == "rpc" && flag == "--stdio" => {
            protocol::rpc_handler::run_rpc_stdio()
        }
        [command, rest @ ..] if command == "setup" => commands::setup::run(rest),
        [command, rest @ ..] if command == "explain-policy" => commands::explain_policy::run(rest),
        [command, rest @ ..] if command == "exec" => commands::exec::run(rest),
        [] => Err("missing command".to_string()),
        _ => Err(format!("unknown command: {}", args.join(" "))),
    }
}

fn execute_command(
    command: &[String],
    cwd: &Path,
    policy: &SandboxPolicy,
    stdin: ExecutionStdin,
    env: ExecutionEnv,
    metadata: Option<Value>,
    timeout: Option<Duration>,
) -> Result<(Vec<Value>, Value), RunSealError> {
    if command.is_empty() {
        return Err(RunSealError::new("INVALID_REQUEST", "command is empty"));
    }
    validate_execution_cwd(cwd)?;

    let ids = new_execution_ids();
    let policy_id = policy.id.clone();
    let policy_hash = policy.hash();
    // ponytail: stdio MVP has no mutable daemon epoch; promote to a real epoch store when concurrent policy transitions exist.
    let policy_epoch = policy_hash.clone();
    let stdin_audit = stdin_audit_json(&stdin);
    let env_keys = env.keys();
    let mut audit = create_audit_writer(cwd, &ids.session_id)?;
    let audit_path = audit.relative_path().to_string();
    let backend = active_backend();
    let event_context = ExecutionEventContext {
        ids: &ids,
        policy_id: &policy_id,
        policy_hash: &policy_hash,
        policy_epoch: &policy_epoch,
        audit_path: &audit_path,
        backend: backend_event_json(backend.name(), backend.status(), backend.platform()),
    };

    let requested = execution_event_now(
        json!({
            "type": "execution.requested",
            "decision": "requested",
            "command_args": command.len(),
        }),
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &requested, &metadata)?;
    let resolved = execution_event_now(
        json!({
            "type": "policy.resolved",
            "decision": "resolved",
            "sandbox_level": policy.sandbox_level.as_str(),
            "network": network_audit_json(policy),
            "backend_requirement": if policy.allows_local_execution() {
                "local-execution"
            } else {
                "sandbox-backend"
            },
            "required_backend_features": policy.required_backend_feature_names(),
        }),
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &resolved, &metadata)?;

    if policy.requires_broad_write_approval() {
        let reason = "filesystem broad write requires approval";
        let event = execution_event_now(
            json!({
                "type": "policy.requires_approval",
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "decision": "requires_approval",
                "reason": reason,
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

        return Err(RunSealError::with_details(
            "APPROVAL_REQUIRED",
            reason,
            json!({
                "execution_id": ids.execution_id,
                "session_id": ids.session_id,
                "seal_id": ids.seal_id,
                "audit_path": audit_path,
            }),
        ));
    }

    if policy.denies_execution_without_backend() {
        let reason = "filesystem write denied by policy";
        let requires_approval = policy.approval.on_violation == "request";
        let event_type = if requires_approval {
            "policy.requires_approval"
        } else {
            "policy.denied"
        };
        let decision = if requires_approval {
            "requires_approval"
        } else {
            "denied"
        };
        let event = execution_event_now(
            json!({
                "type": event_type,
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "decision": decision,
                "reason": reason,
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

        return Err(RunSealError::with_details(
            if requires_approval {
                "APPROVAL_REQUIRED"
            } else {
                "POLICY_DENIED"
            },
            reason,
            json!({
                "execution_id": ids.execution_id,
                "session_id": ids.session_id,
                "seal_id": ids.seal_id,
                "audit_path": audit_path,
            }),
        ));
    }

    let plan = match backend.compile_plan(&ids.execution_id, cwd, policy) {
        Ok(plan) => plan,
        Err(err) => {
            let details = err.details_json();
            let mut prepared_setup = None;
            if let Some(plan) = err.plan.as_deref() {
                match plan.prepare_sandbox_setup() {
                    Ok(setup) => {
                        let event = execution_event_now(
                            json!({
                                "type": "sandbox.prepared",
                                "execution_id": ids.execution_id,
                                "policy_id": policy_id,
                                "policy_hash": policy_hash,
                                "audit_path": audit_path,
                                "decision": "prepared",
                                "prepared_roots": setup.prepared_roots(),
                                "platform_plan": plan.json(),
                            }),
                            &event_context,
                        );
                        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;
                        prepared_setup = Some(setup);
                    }
                    Err(setup_err) => {
                        let event = execution_event_now(
                            json!({
                                "type": "sandbox.setup_failed",
                                "execution_id": ids.execution_id,
                                "policy_id": policy_id,
                                "policy_hash": policy_hash,
                                "audit_path": audit_path,
                                "decision": "failed",
                                "reason": setup_err.to_string(),
                                "platform_plan": plan.json(),
                            }),
                            &event_context,
                        );
                        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

                        let mut details = details;
                        if let Some(details) = details.as_object_mut() {
                            details.insert("execution_id".to_string(), json!(ids.execution_id));
                            details.insert("session_id".to_string(), json!(ids.session_id));
                            details.insert("seal_id".to_string(), json!(ids.seal_id));
                            details.insert("audit_path".to_string(), json!(audit_path));
                            details.insert("setup_error".to_string(), json!(setup_err.to_string()));
                        }

                        return Err(RunSealError::with_details(
                            "INTERNAL_ERROR",
                            "failed to prepare sandbox setup",
                            details,
                        ));
                    }
                }
            }

            let event = execution_event_now(
                json!({
                    "type": "sandbox.backend_capability",
                    "execution_id": ids.execution_id,
                    "policy_id": policy_id,
                    "policy_hash": policy_hash,
                    "audit_path": audit_path,
                    "decision": "unsupported",
                    "reason": err.reason,
                    "backend": details.get("backend").cloned().unwrap_or_else(|| json!({})),
                    "support": details.get("support").cloned().unwrap_or_else(|| json!("unsupported")),
                    "missing_features": details.get("missing_features").cloned().unwrap_or_else(|| json!([])),
                    "platform_plan": details.get("platform_plan").cloned().unwrap_or(Value::Null),
                }),
                &event_context,
            );
            write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

            if let (Some(plan), Some(setup)) = (err.plan.as_deref(), prepared_setup) {
                match setup.cleanup(plan) {
                    Ok(cleaned_roots) => {
                        let event = execution_event_now(
                            json!({
                                "type": "sandbox.cleanup",
                                "execution_id": ids.execution_id,
                                "policy_id": policy_id,
                                "policy_hash": policy_hash,
                                "audit_path": audit_path,
                                "decision": "cleaned",
                                "cleaned_roots": cleaned_roots,
                                "platform_plan": plan.json(),
                            }),
                            &event_context,
                        );
                        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;
                    }
                    Err(cleanup_err) => {
                        let event = execution_event_now(
                            json!({
                                "type": "sandbox.cleanup",
                                "execution_id": ids.execution_id,
                                "policy_id": policy_id,
                                "policy_hash": policy_hash,
                                "audit_path": audit_path,
                                "decision": "failed",
                                "reason": cleanup_err.to_string(),
                                "platform_plan": plan.json(),
                            }),
                            &event_context,
                        );
                        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;

                        let mut details = details;
                        if let Some(details) = details.as_object_mut() {
                            details.insert("execution_id".to_string(), json!(ids.execution_id));
                            details.insert("session_id".to_string(), json!(ids.session_id));
                            details.insert("seal_id".to_string(), json!(ids.seal_id));
                            details.insert("audit_path".to_string(), json!(audit_path));
                            details.insert(
                                "cleanup_error".to_string(),
                                json!(cleanup_err.to_string()),
                            );
                        }

                        return Err(RunSealError::with_details(
                            "INTERNAL_ERROR",
                            "failed to clean sandbox runtime roots",
                            details,
                        ));
                    }
                }
            }

            let mut details = details;
            if let Some(details) = details.as_object_mut() {
                details.insert("execution_id".to_string(), json!(ids.execution_id));
                details.insert("session_id".to_string(), json!(ids.session_id));
                details.insert("seal_id".to_string(), json!(ids.seal_id));
                details.insert("audit_path".to_string(), json!(audit_path));
            }

            return Err(RunSealError::with_details(err.code, err.reason, details));
        }
    };

    let sandbox_enforced = plan.is_sandbox_enforced();
    let allowed = execution_event_now(
        json!({
            "type": "policy.allowed",
            "decision": "allowed",
            "sandbox": {
                "level": policy.sandbox_level.as_str(),
                "enforced": sandbox_enforced,
            },
            "network": network_audit_json(policy),
        }),
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &allowed, &metadata)?;
    let started_at = timestamp_now();
    let started = execution_event_at(
        json!({
            "type": "execution.started",
            "execution_id": ids.execution_id,
            "policy_id": policy_id,
            "policy_hash": policy_hash,
            "audit_path": audit_path,
            "sandbox": {
                "level": policy.sandbox_level.as_str(),
                "enforced": sandbox_enforced,
            },
            "network": network_audit_json(policy),
            "backend": {
                "name": plan.backend,
                "status": plan.backend_status,
                "platform": plan.platform,
            },
            "platform_plan": plan.json(),
            "stdin": stdin_audit,
            "environment": {
                "requested_keys": env_keys,
            },
        }),
        &started_at,
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &started, &metadata)?;

    let timer = Instant::now();
    let execution_output = match backend.execute_plan(&plan, command, cwd, stdin, &env, timeout) {
        Ok(output) => output,
        Err(err) => {
            let backend_error = backend_execution_error(&err, sandbox_enforced, cwd);
            let failure_reason = backend_error
                .as_ref()
                .map(|(_, reason, _)| reason.as_str())
                .unwrap_or("execution failed to start");
            let setup_status = backend_error
                .as_ref()
                .and_then(|(_, _, setup_status)| setup_status.clone());
            let mut failed_payload = json!({
                "type": "execution.failed",
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "status": "failed",
                "reason": failure_reason,
                "error": err.to_string(),
            });
            if let (Some(failed_payload), Some(setup_status)) =
                (failed_payload.as_object_mut(), setup_status)
            {
                failed_payload.insert("setup_status".to_string(), setup_status);
            }
            let failed = execution_event_now(failed_payload, &event_context);
            write_audit_event_with_metadata(&mut audit, &failed, &metadata)?;

            if let Some((code, reason, setup_status)) = backend_error {
                let mut details = json!({
                    "execution_id": ids.execution_id,
                    "session_id": ids.session_id,
                    "seal_id": ids.seal_id,
                    "audit_path": audit_path,
                    "backend": {
                        "name": plan.backend,
                        "status": plan.backend_status,
                        "platform": plan.platform,
                    },
                    "platform_plan": plan.json(),
                });
                if let (Some(details), Some(setup_status)) = (details.as_object_mut(), setup_status)
                {
                    details.insert("setup_status".to_string(), setup_status);
                }
                return Err(RunSealError::with_details(code, reason, details));
            }

            return Err(RunSealError::with_details(
                "EXECUTION_FAILED_TO_START",
                format!("failed to spawn command {}: {err}", command[0]),
                json!({
                    "execution_id": ids.execution_id,
                    "session_id": ids.session_id,
                    "seal_id": ids.seal_id,
                    "audit_path": audit_path,
                }),
            ));
        }
    };
    let backend_events = execution_output
        .events
        .iter()
        .map(|event| execution_event_now(event.clone(), &event_context))
        .collect::<Vec<_>>();
    for event in &backend_events {
        write_audit_event_with_metadata(&mut audit, event, &metadata)?;
    }
    let mut output = execution_output.output;
    let original_stdout_bytes = output.stdout.len();
    let original_stderr_bytes = output.stderr.len();
    let output_truncated = truncate_output(&mut output, policy.resources.max_output_bytes);
    let duration_ms = duration_millis_u64(timer.elapsed());
    if execution_output.timed_out {
        let timeout_ms = timeout.map(duration_millis_u64);
        let limit_exceeded = execution_event_now(
            json!({
                "type": "execution.resource.limit_exceeded",
                "decision": "limit_exceeded",
                "resource": "timeout_ms",
                "limit": timeout_ms,
                "duration_ms": duration_ms,
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &limit_exceeded, &metadata)?;
        let failed = execution_event_now(
            json!({
                "type": "execution.failed",
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "status": "failed",
                "reason": "execution timed out",
                "timeout_ms": timeout_ms,
                "duration_ms": duration_ms,
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &failed, &metadata)?;

        return Err(RunSealError::with_details(
            "EXECUTION_TIMEOUT",
            "execution timed out",
            json!({
                "execution_id": ids.execution_id,
                "session_id": ids.session_id,
                "seal_id": ids.seal_id,
                "audit_path": audit_path,
                "timeout_ms": timeout_ms,
                "stdout_bytes": output.stdout.len(),
                "stderr_bytes": output.stderr.len(),
            }),
        ));
    }
    let mut events = vec![started];
    events.extend(backend_events);
    if !output.stdout.is_empty() {
        let event = stream_event("execution.stdout", &event_context, &output.stdout, 0);
        let audit_event = audit_stream_event_metadata(&event);
        write_audit_event_with_metadata(&mut audit, &audit_event, &metadata)?;
        events.push(event);
    }
    if !output.stderr.is_empty() {
        let event = stream_event("execution.stderr", &event_context, &output.stderr, 0);
        let audit_event = audit_stream_event_metadata(&event);
        write_audit_event_with_metadata(&mut audit, &audit_event, &metadata)?;
        events.push(event);
    }
    if output_truncated {
        let event = execution_event_now(
            json!({
                "type": "execution.output.truncated",
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "decision": "truncated",
                "max_output_bytes": policy.resources.max_output_bytes,
                "stdout_bytes": output.stdout.len(),
                "stderr_bytes": output.stderr.len(),
                "original_stdout_bytes": original_stdout_bytes,
                "original_stderr_bytes": original_stderr_bytes,
            }),
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &event, &metadata)?;
        events.push(event);
    }
    let exit_code = output.status.code().unwrap_or(1);
    let output_program = command.first().map(String::as_str).unwrap_or("");
    let stdout = decode_process_output(output_program, &output.stdout);
    let stderr = decode_process_output(output_program, &output.stderr);
    let finished_at = timestamp_now();
    let resource_sample = execution_event_at(
        json!({
            "type": "execution.resource.sample",
            "duration_ms": duration_ms,
            "stdout_bytes": output.stdout.len(),
            "stderr_bytes": output.stderr.len(),
            "output_truncated": output_truncated,
        }),
        &finished_at,
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &resource_sample, &metadata)?;
    if output_truncated {
        let limit_exceeded = execution_event_at(
            json!({
                "type": "execution.resource.limit_exceeded",
                "decision": "limit_exceeded",
                "resource": "max_output_bytes",
                "limit": policy.resources.max_output_bytes,
                "stdout_bytes": original_stdout_bytes,
                "stderr_bytes": original_stderr_bytes,
                "retained_stdout_bytes": output.stdout.len(),
                "retained_stderr_bytes": output.stderr.len(),
            }),
            &finished_at,
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &limit_exceeded, &metadata)?;
        let failed = execution_event_at(
            json!({
                "type": "execution.failed",
                "execution_id": ids.execution_id,
                "policy_id": policy_id,
                "policy_hash": policy_hash,
                "audit_path": audit_path,
                "status": "failed",
                "reason": "output limit exceeded",
                "max_output_bytes": policy.resources.max_output_bytes,
                "stdout_bytes": original_stdout_bytes,
                "stderr_bytes": original_stderr_bytes,
            }),
            &finished_at,
            &event_context,
        );
        write_audit_event_with_metadata(&mut audit, &failed, &metadata)?;

        return Err(RunSealError::with_details(
            "OUTPUT_LIMIT_EXCEEDED",
            "output limit exceeded",
            json!({
                "execution_id": ids.execution_id,
                "session_id": ids.session_id,
                "seal_id": ids.seal_id,
                "audit_path": audit_path,
                "max_output_bytes": policy.resources.max_output_bytes,
                "stdout_bytes": original_stdout_bytes,
                "stderr_bytes": original_stderr_bytes,
                "retained_stdout_bytes": output.stdout.len(),
                "retained_stderr_bytes": output.stderr.len(),
            }),
        ));
    }
    let finished = execution_event_at(
        json!({
            "type": "execution.finished",
            "execution_id": ids.execution_id,
            "exit_code": exit_code,
            "status": "finished",
        }),
        &finished_at,
        &event_context,
    );
    write_audit_event_with_metadata(&mut audit, &finished, &metadata)?;
    events.push(finished);

    let result = json!({
        "execution_id": ids.execution_id,
        "session_id": ids.session_id,
        "seal_id": ids.seal_id,
        "status": "finished",
        "exit_code": exit_code,
        "signal": null,
        "started_at": started_at,
        "finished_at": finished_at,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "policy_epoch": policy_epoch,
        "audit_path": audit_path,
        "sandbox": {
            "level": policy.sandbox_level.as_str(),
            "enforced": sandbox_enforced,
        },
        "network": network_audit_json(policy),
        "backend": {
            "name": plan.backend,
            "status": plan.backend_status,
            "platform": plan.platform,
        },
        "platform_plan": plan.json(),
        "stdout_bytes": output.stdout.len(),
        "stderr_bytes": output.stderr.len(),
        "output_truncated": output_truncated,
        "stdout": stdout,
        "stderr": stderr,
        "resource_usage": {
            "duration_ms": duration_ms,
        }
    });

    Ok((events, result))
}

fn backend_execution_error(
    err: &io::Error,
    sandbox_enforced: bool,
    cwd: &Path,
) -> Option<(&'static str, String, Option<Value>)> {
    if let Some(reason) = policy_transition_busy_reason(err) {
        return Some(("POLICY_TRANSITION_BUSY", reason.to_string(), None));
    }
    if sandbox_enforced {
        let reason =
            backend_unavailable_reason(err).unwrap_or(generic_backend_unavailable_reason());
        return Some((
            "BACKEND_UNAVAILABLE",
            reason.to_string(),
            backend_unavailable_setup_status(reason, cwd),
        ));
    }
    None
}

fn network_audit_json(policy: &SandboxPolicy) -> Value {
    json!({
        "mode": policy.network.mode.as_str(),
        "routes": policy.network.routes,
        "direct_allow_hosts": policy.network.direct_allow_hosts,
    })
}

fn generic_backend_unavailable_reason() -> &'static str {
    #[cfg(windows)]
    {
        "windows sandbox setup unavailable; run `runseal setup windows-sandbox` to install or repair"
    }

    #[cfg(not(windows))]
    {
        "sandbox backend unavailable"
    }
}

fn backend_unavailable_setup_status(reason: &str, cwd: &Path) -> Option<Value> {
    #[cfg(windows)]
    {
        if reason.starts_with("windows sandbox setup unavailable") {
            return commands::setup::windows_sandbox_setup_status_for_cwd(cwd).ok();
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (reason, cwd);
    }

    None
}

fn truncate_output(output: &mut Output, max_output_bytes: Option<u64>) -> bool {
    let Some(max_output_bytes) = max_output_bytes.and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let original_stdout_len = output.stdout.len();
    let original_stderr_len = output.stderr.len();

    let stdout_len = output.stdout.len().min(max_output_bytes);
    output.stdout.truncate(stdout_len);
    let stderr_budget = max_output_bytes.saturating_sub(stdout_len);
    output
        .stderr
        .truncate(output.stderr.len().min(stderr_budget));

    output.stdout.len() != original_stdout_len || output.stderr.len() != original_stderr_len
}

fn audit_stream_event_metadata(event: &Value) -> Value {
    let mut event = event.clone();
    if let Some(object) = event.as_object_mut() {
        object.remove("data");
        object.remove("text");
    }
    event
}

fn validate_execution_cwd(cwd: &Path) -> Result<(), RunSealError> {
    let metadata = fs::symlink_metadata(cwd).map_err(|err| {
        RunSealError::new(
            "INVALID_REQUEST",
            format!("params.cwd must be an existing directory: {err}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunSealError::new(
            "INVALID_REQUEST",
            format!(
                "params.cwd must be an existing directory: {}",
                cwd.display()
            ),
        ));
    }

    Ok(())
}

fn normalize_execution_cwd(cwd: &Path) -> Result<PathBuf, RunSealError> {
    validate_execution_cwd(cwd)?;
    fs::canonicalize(cwd)
        .map(simplify_windows_extended_path)
        .map_err(|err| {
            RunSealError::new(
                "INVALID_REQUEST",
                format!("params.cwd must be an existing directory: {err}"),
            )
        })
}

fn simplify_windows_extended_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let value = path.to_string_lossy();
        if let Some(stripped) = value.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{stripped}"));
        }
        if let Some(stripped) = value.strip_prefix(r"\\?\") {
            return PathBuf::from(stripped);
        }
    }
    path
}

fn current_dir() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[cfg(windows)]
    #[test]
    fn policy_transition_busy_maps_to_public_error_code() {
        let err = backend::policy_transition_busy_error_for_test();
        let (code, reason, setup_status) = backend_execution_error(&err, true, Path::new("."))
            .expect("busy error must map to public code");

        assert_eq!(code, "POLICY_TRANSITION_BUSY");
        assert!(reason.contains("policy transition busy"));
        assert_eq!(setup_status, None);
    }

    #[test]
    fn execution_ids_are_unique_for_fast_local_requests() {
        let mut execution_ids = HashSet::new();
        let mut session_ids = HashSet::new();
        let mut seal_ids = HashSet::new();

        for _ in 0..4096 {
            let ids = new_execution_ids();
            assert!(execution_ids.insert(ids.execution_id));
            assert!(session_ids.insert(ids.session_id));
            assert!(seal_ids.insert(ids.seal_id));
        }
    }

    #[test]
    fn windows_setup_failure_message_hides_vendor_codes() {
        assert!(!WINDOWS_SANDBOX_SETUP_FAILED.contains("orchestrator_"));
        assert!(!WINDOWS_SANDBOX_SETUP_FAILED.contains("helper_"));
        assert!(WINDOWS_SANDBOX_SETUP_FAILED.contains("first install requires an elevated shell"));
        assert!(WINDOWS_SANDBOX_SETUP_FAILED.contains("repairs can reuse the setup broker"));
        assert!(!WINDOWS_SANDBOX_SETUP_FAILED.contains("install or repair requires"));
    }

    #[test]
    fn windows_setup_failed_json_includes_setup_status() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = windows_sandbox_setup_failed_error(tmp.path());
        let expected_code = if cfg!(windows) {
            "WINDOWS_SANDBOX_SETUP_FAILED"
        } else {
            "WINDOWS_SANDBOX_UNSUPPORTED"
        };
        let expected_reason = if cfg!(windows) {
            WINDOWS_SANDBOX_SETUP_FAILED
        } else {
            WINDOWS_SANDBOX_UNSUPPORTED
        };

        assert_eq!(err.code, expected_code);
        assert_eq!(err.reason, expected_reason);
        let details = err.details.expect("details");
        assert_eq!(details["setup_status"]["setup"], "windows-sandbox");
        assert!(details["setup_status"]["next_action"].as_str().is_some());
    }

    #[cfg(windows)]
    #[test]
    fn windows_setup_success_payload_hides_internal_paths() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let payload = windows_sandbox_setup_success_payload(tmp.path());

        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["setup"], "windows-sandbox");
        assert_eq!(payload["setup_status"]["setup"], "windows-sandbox");
        assert!(payload.get("sandbox_home").is_none());
        assert!(payload.get("profile_root").is_none());
        assert!(payload.get("runtime_root").is_none());
    }

    #[test]
    fn windows_setup_status_can_repair_via_elevation_or_broker() {
        let elevated = windows_sandbox_setup_status_payload(true, false, false, Some(true));
        let broker = windows_sandbox_setup_status_payload(true, false, true, Some(false));
        let ready = windows_sandbox_setup_status_payload(true, true, false, Some(false));
        let missing = windows_sandbox_setup_status_payload(true, false, false, Some(false));
        let unsupported = windows_sandbox_setup_status_payload(false, false, true, Some(true));

        assert_eq!(elevated["can_repair"], true);
        assert_eq!(elevated["can_run_setup_now"], true);
        assert_eq!(elevated["requires_setup"], true);
        assert_eq!(elevated["next_action"], "run_setup");
        assert_eq!(
            elevated["next_command"],
            "runseal setup windows-sandbox --cwd <absolute-workspace-path> --json"
        );
        assert_eq!(broker["can_repair"], true);
        assert_eq!(broker["can_run_setup_now"], true);
        assert_eq!(broker["requires_setup"], true);
        assert_eq!(broker["next_action"], "run_setup");
        assert_eq!(
            broker["next_command"],
            "runseal setup windows-sandbox --cwd <absolute-workspace-path> --json"
        );
        assert_eq!(ready["can_repair"], false);
        assert_eq!(ready["can_run_setup_now"], false);
        assert_eq!(ready["requires_setup"], false);
        assert_eq!(ready["next_action"], "none");
        assert!(ready["next_command"].is_null());
        assert_eq!(missing["can_repair"], false);
        assert_eq!(missing["can_run_setup_now"], false);
        assert_eq!(missing["requires_setup"], true);
        assert_eq!(missing["next_action"], "open_elevated_shell");
        assert_eq!(
            missing["next_command"],
            "runseal setup windows-sandbox --cwd <absolute-workspace-path> --json"
        );
        assert_eq!(unsupported["can_repair"], false);
        assert_eq!(unsupported["can_run_setup_now"], false);
        assert_eq!(unsupported["requires_setup"], false);
        assert_eq!(unsupported["next_action"], "unsupported");
        assert!(unsupported["next_command"].is_null());
    }

    #[test]
    fn duration_millis_conversion_saturates_to_u64() {
        assert_eq!(duration_millis_u64(Duration::from_millis(42)), 42);
        assert_eq!(duration_millis_u64(Duration::MAX), u64::MAX);
    }
}
