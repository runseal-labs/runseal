use super::errors::backend_execution_error;
use super::output::{audit_stream_event_metadata, truncate_output};
use super::paths::validate_execution_cwd;
use crate::audit::{create_audit_writer, write_audit_event_with_metadata};
use crate::backend::{ExecutionEnv, ExecutionStdin, SandboxBackend, active_backend};
use crate::error::RunSealError;
use crate::events::{
    ExecutionEventContext, backend_event_json, execution_event_at, execution_event_now,
    new_execution_ids, stream_event, timestamp_now,
};
use crate::policy::SandboxPolicy;
use crate::process_output::decode_process_output;
use crate::protocol::request_validation::duration_millis_u64;
use crate::stdin::stdin_audit_json;
use serde_json::{Value, json};
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) fn execute_command(
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
                    "policy_id": policy_id,
                    "policy_hash": policy_hash,
                    "policy_epoch": policy_epoch,
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
                    "policy_id": policy_id,
                    "policy_hash": policy_hash,
                    "policy_epoch": policy_epoch,
                    "audit_path": audit_path,
                    "backend": {
                        "name": plan.backend,
                        "status": plan.backend_status,
                        "platform": plan.platform,
                    },
                    "platform_plan": plan.json(),
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

fn network_audit_json(policy: &SandboxPolicy) -> Value {
    json!({
        "mode": policy.network.mode.as_str(),
        "routes": policy.network.routes,
        "direct_allow_hosts": policy.network.direct_allow_hosts,
    })
}
