use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use tempfile::TempDir;

const PRIVATE_TERMS: &[&str] = &["sid", "acl", "wfp", "seatbelt", "seccomp", "landlock"];

fn runseal_bin() -> PathBuf {
    env::var_os("RUNSEAL_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_runseal")))
}

fn rpc_request(method: &str, params: Value) -> String {
    format!(
        "{}\n",
        json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    )
}

fn harmless_command() -> Value {
    json!([runseal_bin(), "version"])
}

fn python_bin() -> &'static str {
    static PYTHON: OnceLock<String> = OnceLock::new();
    PYTHON.get_or_init(resolve_python_bin)
}

fn resolve_python_bin() -> String {
    if let Some(path) = env::var_os("RUNSEAL_TEST_PYTHON") {
        return PathBuf::from(path).to_string_lossy().into_owned();
    }
    let output = match if cfg!(windows) {
        Command::new("where.exe").arg("python").output()
    } else {
        Command::new("sh")
            .args(["-c", "command -v python3"])
            .output()
    } {
        Ok(output) => output,
        Err(err) => panic!("failed to locate python: {err}"),
    };
    let stdout = match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout,
        Err(err) => panic!("python path must be utf-8: {err}"),
    };
    match stdout.lines().next() {
        Some(path) => path.to_string(),
        None => panic!("python must exist"),
    }
}

fn run_rpc(message: &str) -> Result<std::process::Output> {
    let mut child = Command::new(runseal_bin())
        .args(["rpc", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run runseal rpc")?;
    child
        .stdin
        .as_mut()
        .context("stdin unavailable")?
        .write_all(message.as_bytes())
        .context("failed to write rpc request")?;
    child.wait_with_output().context("failed to wait for rpc")
}

#[test]
fn adversarial_policy_cases_run() -> Result<()> {
    adversarial_tier0_policy_cases_emit_public_safe_results()?;
    adversarial_policy_hash_spoof_case_runs()?;
    adversarial_network_override_hash_drift_case_runs()?;
    adversarial_stale_policy_epoch_case_runs()
}

#[test]
fn adversarial_execution_injection_cases_run() -> Result<()> {
    adversarial_execution_injection_deny_cases_run()?;
    adversarial_stdin_file_outside_cwd_case_runs()?;
    adversarial_program_resolution_confusion_case_runs()
}

#[test]
fn adversarial_audit_cases_run() -> Result<()> {
    adversarial_audit_metadata_redaction_cases_run()?;
    adversarial_audit_lookup_deny_cases_run()?;
    adversarial_audit_consistency_cases_run()?;
    adversarial_audit_deny_event_cases_run()
}

#[test]
fn adversarial_filesystem_and_runtime_cases_run() -> Result<()> {
    adversarial_filesystem_path_denial_cases_run()?;
    adversarial_runtime_root_denial_cases_run()
}

#[test]
fn adversarial_process_cases_run() -> Result<()> {
    adversarial_process_policy_cases_run()?;
    #[cfg(windows)]
    adversarial_process_timeout_cases_run()?;
    Ok(())
}

#[test]
fn adversarial_network_cases_run() -> Result<()> {
    adversarial_network_fail_closed_cases_run()
}

#[test]
fn adversarial_harness_internals_work() -> Result<()> {
    adversarial_harness_materializes_file_fixtures_before_execution()?;
    adversarial_harness_materializes_directory_fixtures_before_execution()?;
    adversarial_harness_materializes_symlink_fixtures_before_execution()?;
    #[cfg(windows)]
    adversarial_harness_materializes_junction_fixtures_before_execution()?;
    adversarial_harness_cleans_fixture_workspace()?;
    adversarial_harness_skips_unsupported_fixtures()?;
    adversarial_harness_inspects_file_side_effects()?;
    adversarial_harness_maps_file_oracles_to_inspection()?;
    adversarial_harness_computes_result_severity();
    adversarial_harness_emits_complete_public_safe_results()
}

fn adversarial_tier0_policy_cases_emit_public_safe_results() -> Result<()> {
    let cases = load_cases()?;
    let tier0_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some(
                "adv.policy.unknown-top-level-field.v1"
                    | "adv.policy.malformed-json.v1"
                    | "adv.policy.unsupported-nonempty-section.v1"
                    | "adv.policy.merge-ambiguity.v1"
            )
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    for case in tier0_cases {
        ran += 1;
        let tmp = TempDir::new()?;
        let response = run_case(case, tmp.path())?;
        let error_code = response["error"]["data"]["code"].as_str();
        let observed_result = if matches!(error_code, Some("INVALID_REQUEST" | "POLICY_INVALID")) {
            "policy_rejected"
        } else {
            "harness_error"
        };
        let result = emit_result(case, observed_result, true)?;
        assert_public_safe(&result.to_string())?;
        assert_eq!(result["status"], "passed", "{result}");
    }

    assert!(
        ran >= 4,
        "tier0 policy harness must run policy rejection cases"
    );
    Ok(())
}

fn adversarial_policy_hash_spoof_case_runs() -> Result<()> {
    let case = load_cases()?
        .into_iter()
        .find(|case| case["case_id"] == "adv.policy.policy-hash-spoof.v1")
        .context("policy hash spoof adversarial case must exist")?;
    let tmp = TempDir::new()?;
    let response = run_case_with_command(&case, tmp.path(), harmless_command())?;

    assert_eq!(
        observed_denial_result(&response),
        "deny",
        "case {} must deny: {response}",
        case["case_id"]
    );
    let result = emit_result(&case, "deny", true)?;
    assert_eq!(result["status"], "passed", "{result}");
    assert_public_safe(&result.to_string())?;
    Ok(())
}

fn adversarial_network_override_hash_drift_case_runs() -> Result<()> {
    let case = load_cases()?
        .into_iter()
        .find(|case| case["case_id"] == "adv.policy.network-override-hash-drift.v1")
        .context("network override hash drift adversarial case must exist")?;
    let tmp = TempDir::new()?;
    let proxy = rpc_result(&rpc_request(
        "explainPolicy",
        json!({"policy": case["request"]["policy"], "cwd": tmp.path(), "network": {"mode": "proxy"}}),
    ))?;
    let disabled = rpc_result(&rpc_request(
        "explainPolicy",
        json!({"policy": case["request"]["policy"], "cwd": tmp.path(), "network": {"mode": "disabled"}}),
    ))?;

    assert_eq!(proxy["network"]["mode"], "proxy");
    assert_eq!(disabled["network"]["mode"], "disabled");
    assert_ne!(proxy["policy_hash"], disabled["policy_hash"]);
    assert_ne!(proxy["canonical_policy"], disabled["canonical_policy"]);

    let result = emit_result(&case, "allow_no_side_effect_outside_policy", true)?;
    assert_eq!(result["status"], "passed", "{result}");
    assert_public_safe(&result.to_string())?;
    Ok(())
}

fn adversarial_stale_policy_epoch_case_runs() -> Result<()> {
    let case = load_cases()?
        .into_iter()
        .find(|case| case["case_id"] == "adv.policy.stale-policy-epoch.v1")
        .context("stale policy epoch adversarial case must exist")?;
    let tmp = TempDir::new()?;
    let first = rpc_response_result(&rpc_request(
        "execute",
        json!({
            "command": harmless_command(),
            "cwd": tmp.path(),
            "policy": case["request"]["policy"],
            "network": {"mode": "disabled"}
        }),
    ))?;
    let same = rpc_response_result(&rpc_request(
        "execute",
        json!({
            "command": harmless_command(),
            "cwd": tmp.path(),
            "policy": case["request"]["policy"],
            "network": {"mode": "disabled"}
        }),
    ))?;
    let changed = rpc_response_result(&rpc_request(
        "execute",
        json!({
            "command": harmless_command(),
            "cwd": tmp.path(),
            "policy": case["request"]["policy"],
            "network": {"mode": "proxy"}
        }),
    ))?;

    assert_eq!(first["status"], "finished");
    assert_eq!(same["status"], "finished");
    assert_eq!(changed["status"], "finished");
    assert_eq!(first["policy_epoch"], first["policy_hash"]);
    assert_eq!(same["policy_epoch"], same["policy_hash"]);
    assert_eq!(changed["policy_epoch"], changed["policy_hash"]);
    assert_eq!(first["policy_epoch"], same["policy_epoch"]);
    assert_ne!(first["policy_epoch"], changed["policy_epoch"]);

    let result = emit_result(&case, "allow_no_side_effect_outside_policy", true)?;
    assert_eq!(result["status"], "passed", "{result}");
    assert_public_safe(&result.to_string())?;
    Ok(())
}

fn adversarial_execution_injection_deny_cases_run() -> Result<()> {
    let cases = load_cases()?;
    let deny_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some(
                "adv.execution_injection.argv-shell-metacharacters.v1"
                    | "adv.execution_injection.stdin-mode-confusion.v1"
                    | "adv.execution_injection.invalid-base64-stdin.v1"
                    | "adv.execution_injection.encoding-divergence.v1"
                    | "adv.execution_injection.environment-variable-injection.v1"
                    | "adv.execution_injection.secret-env-key.v1"
            )
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    for case in deny_cases {
        ran += 1;
        let tmp = TempDir::new()?;
        let response =
            if case["case_id"] == "adv.execution_injection.environment-variable-injection.v1" {
                run_case_with_command(case, tmp.path(), command_with_local_python(case)?)?
            } else {
                run_case(case, tmp.path())?
            };
        assert_eq!(
            observed_denial_result(&response),
            "deny",
            "case {} must deny: {response}",
            case["case_id"]
        );
        let result = emit_result(case, "deny", true)?;
        assert_eq!(result["status"], "passed", "{result}");
        assert_public_safe(&result.to_string())?;
    }

    assert!(
        ran >= 6,
        "execution injection harness must run fixture-free deny cases"
    );
    Ok(())
}

fn adversarial_stdin_file_outside_cwd_case_runs() -> Result<()> {
    let case = load_cases()?
        .into_iter()
        .find(|case| case["case_id"] == "adv.execution_injection.stdin-file-outside-cwd.v1")
        .context("stdin file outside cwd adversarial case must exist")?;
    let tmp = TempDir::new()?;
    for fixture in case["fixtures"].as_array().into_iter().flatten() {
        materialize_file_fixture(tmp.path(), fixture)?;
    }
    let workspace = tmp.path().join("workspace");
    fs::create_dir(&workspace)?;

    let response = run_case(&case, &workspace)?;
    assert_eq!(
        observed_denial_result(&response),
        "deny",
        "case {} must deny: {response}",
        case["case_id"]
    );
    let result = emit_result(&case, "deny", true)?;
    assert_eq!(result["status"], "passed", "{result}");
    assert_public_safe(&result.to_string())?;
    Ok(())
}

fn adversarial_program_resolution_confusion_case_runs() -> Result<()> {
    let case = load_cases()?
        .into_iter()
        .find(|case| case["case_id"] == "adv.execution_injection.program-resolution-confusion.v1")
        .context("program resolution confusion adversarial case must exist")?;
    let tmp = TempDir::new()?;

    let response = run_case(&case, tmp.path())?;
    assert_eq!(
        observed_denial_result(&response),
        "deny",
        "case {} must deny: {response}",
        case["case_id"]
    );
    let result = emit_result(&case, "deny", true)?;
    assert_eq!(result["status"], "passed", "{result}");
    assert_public_safe(&result.to_string())?;
    Ok(())
}

fn adversarial_audit_metadata_redaction_cases_run() -> Result<()> {
    let cases = load_cases()?;
    let audit_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some(
                "adv.audit.secret-metadata-redaction.v1"
                    | "adv.audit.authorization-header-leakage.v1"
                    | "adv.audit.proxy-credential-leakage.v1"
            )
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    for case in audit_cases {
        ran += 1;
        let tmp = TempDir::new()?;
        let response = run_case_with_command(case, tmp.path(), harmless_command())?;
        let result = response["result"].clone();
        assert_eq!(result["status"], "finished", "{response}");
        let audit_path = result["audit_path"]
            .as_str()
            .context("audit redaction case must return audit_path")?;
        let audit_jsonl = fs::read_to_string(tmp.path().join(audit_path))?;

        assert!(audit_jsonl.contains("[REDACTED]"));
        assert!(audit_jsonl.contains("\"safe\":\"visible\""));
        assert!(!audit_jsonl.contains("Bearer secret"));
        assert!(!audit_jsonl.contains("user:secret"));
        assert!(!audit_jsonl.contains("\"Authorization\":\"value\""));
        let result = emit_result(case, "audit_redacted", true)?;
        assert_eq!(result["status"], "passed", "{result}");
        assert_public_safe(&result.to_string())?;
    }

    assert!(ran >= 3, "audit metadata redaction cases must run");
    Ok(())
}

fn adversarial_audit_lookup_deny_cases_run() -> Result<()> {
    let cases = load_cases()?;
    let audit_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some("adv.audit.audit-path-traversal.v1" | "adv.audit.audit-lookup-by-path.v1")
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    for case in audit_cases {
        ran += 1;
        let tmp = TempDir::new()?;
        let response = if case["case_id"] == "adv.audit.audit-path-traversal.v1" {
            run_case_with_command(case, tmp.path(), harmless_command())?
        } else {
            run_case(case, tmp.path())?
        };
        assert_eq!(
            observed_denial_result(&response),
            "deny",
            "case {} must deny: {response}",
            case["case_id"]
        );
        let result = emit_result(case, "deny", true)?;
        assert_eq!(result["status"], "passed", "{result}");
        assert_public_safe(&result.to_string())?;
    }

    assert!(ran >= 2, "audit lookup deny cases must run");
    Ok(())
}

fn adversarial_audit_consistency_cases_run() -> Result<()> {
    let cases = load_cases()?;
    let audit_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some(
                "adv.audit.event-ordering-drift.v1"
                    | "adv.audit.policy-hash-consistency.v1"
                    | "adv.policy.policy-hash-plan-event-audit-mismatch.v1"
            )
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    for case in audit_cases {
        ran += 1;
        let tmp = TempDir::new()?;
        let messages = run_case_messages_with_command(case, tmp.path(), harmless_command())?;
        let response = response_message(&messages)?;
        let result = response["result"].clone();
        assert_eq!(result["status"], "finished", "{response}");
        assert_eq!(result["policy_epoch"], result["policy_hash"]);

        let event_types = messages
            .iter()
            .filter_map(|message| message["params"]["type"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            &event_types[..3],
            &["execution.requested", "policy.resolved", "policy.allowed"]
        );
        assert!(event_types.contains(&"execution.finished"));
        for event in messages.iter().filter_map(|message| message.get("params")) {
            assert_eq!(event["policy_hash"], result["policy_hash"]);
            assert_eq!(event["policy_epoch"], result["policy_epoch"]);
        }

        let audit_path = result["audit_path"]
            .as_str()
            .context("audit consistency case must return audit_path")?;
        let audit_events = read_audit_events(tmp.path(), audit_path)?;
        assert!(
            audit_events
                .iter()
                .any(|event| event["type"] == "execution.finished")
        );
        for event in &audit_events {
            assert_eq!(event["policy_hash"], result["policy_hash"]);
            assert_eq!(event["policy_epoch"], result["policy_epoch"]);
        }

        let result = emit_result(case, "allow_no_side_effect_outside_policy", true)?;
        assert_eq!(result["status"], "passed", "{result}");
        assert_public_safe(&result.to_string())?;
    }

    assert!(ran >= 3, "audit consistency cases must run");
    Ok(())
}

fn adversarial_audit_deny_event_cases_run() -> Result<()> {
    let cases = load_cases()?;
    let audit_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some(
                "adv.audit.missing-deny-event.v1"
                    | "adv.audit.missing-fail-closed-event.v1"
                    | "adv.audit.backend-private-redaction.v1"
            )
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    for case in audit_cases {
        ran += 1;
        let tmp = TempDir::new()?;
        let response = run_case_with_command(case, tmp.path(), harmless_command())?;
        assert_eq!(
            response["error"]["data"]["code"], "POLICY_DENIED",
            "case {} must deny: {response}",
            case["case_id"]
        );
        let audit_path = response["error"]["data"]["audit_path"]
            .as_str()
            .context("audit deny case must return audit_path")?;
        let audit_jsonl = fs::read_to_string(tmp.path().join(audit_path))?;
        assert_public_safe(&audit_jsonl)?;
        let audit_events = read_audit_events(tmp.path(), audit_path)?;
        assert!(
            audit_events
                .iter()
                .any(|event| event["type"] == "policy.denied")
        );

        let observed = if case["oracle"]["expected_result"] == "policy_rejected" {
            "policy_rejected"
        } else {
            "deny_or_fail_closed"
        };
        let result = emit_result(case, observed, true)?;
        assert_eq!(result["status"], "passed", "{result}");
        assert_public_safe(&result.to_string())?;
    }

    assert!(ran >= 3, "audit deny event cases must run");
    Ok(())
}

fn adversarial_filesystem_path_denial_cases_run() -> Result<()> {
    let cases = load_cases()?;
    let filesystem_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some(
                "adv.filesystem.parent-traversal.v1"
                    | "adv.filesystem.absolute-path-confusion.v1"
                    | "adv.filesystem.relative-cwd-confusion.v1"
                    | "adv.filesystem.symlink-parent-traversal.v1"
                    | "adv.filesystem.junction-parent-traversal.v1"
                    | "adv.filesystem.symlink-swap-race.v1"
                    | "adv.filesystem.case-folding-bypass.v1"
                    | "adv.filesystem.path-normalization-difference.v1"
                    | "adv.filesystem.reserved-device-name.v1"
                    | "adv.filesystem.unc-path-injection.v1"
                    | "adv.filesystem.preexisting-symlinked-runtime-root.v1"
                    | "adv.filesystem.protected-subpath-write.v1"
                    | "adv.filesystem.protected-git-metadata-write.v1"
                    | "adv.filesystem.external-write-from-workspace-write.v1"
                    | "adv.filesystem.external-read-from-workspace-contained.v1"
            )
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    let mut ran_protected_git_metadata = false;
    for case in filesystem_cases {
        ran += 1;
        ran_protected_git_metadata |=
            case["case_id"] == "adv.filesystem.protected-git-metadata-write.v1";
        let tmp = TempDir::new()?;
        materialize_supported_fixtures(tmp.path(), case)?;
        let workspace = tmp.path().join("workspace");
        fs::create_dir_all(&workspace)?;

        let command = command_with_local_python(case)?;
        let response = run_case_with_command(case, &workspace, command)?;
        assert_eq!(
            observed_filesystem_denial_result(&response),
            "deny_or_fail_closed",
            "case {} must deny or fail closed: {response}",
            case["case_id"]
        );
        assert_forbidden_file_side_effects_hold(tmp.path(), case)?;

        let result = emit_result(case, "deny_or_fail_closed", true)?;
        assert_eq!(result["status"], "passed", "{result}");
        assert_public_safe(&result.to_string())?;
    }

    assert!(ran >= 6, "filesystem path denial cases must run");
    assert!(
        ran_protected_git_metadata,
        "protected Git metadata case must run"
    );
    Ok(())
}

fn adversarial_runtime_root_denial_cases_run() -> Result<()> {
    let cases = load_cases()?;
    let runtime_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some(
                "adv.runtime.precreated-runtime-root.v1"
                    | "adv.runtime.runtime-marker-spoof.v1"
                    | "adv.runtime.runtime-root-symlink-replacement.v1"
                    | "adv.runtime.execution-id-reuse.v1"
                    | "adv.runtime.partial-setup-continuation.v1"
                    | "adv.runtime.cleanup-partial-failure.v1"
                    | "adv.runtime.cross-execution-contamination.v1"
            )
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    for case in runtime_cases {
        ran += 1;
        let tmp = TempDir::new()?;
        materialize_supported_fixtures(tmp.path(), case)?;
        let workspace = tmp.path().join("workspace");
        fs::create_dir_all(&workspace)?;

        let command = command_with_local_python(case)?;
        let response = run_case_with_command(case, &workspace, command)?;
        assert_eq!(
            observed_filesystem_denial_result(&response),
            "deny_or_fail_closed",
            "case {} must deny or fail closed: {response}",
            case["case_id"]
        );
        assert_forbidden_file_side_effects_hold(tmp.path(), case)?;

        let result = emit_result(case, "deny_or_fail_closed", true)?;
        assert_eq!(result["status"], "passed", "{result}");
        assert_public_safe(&result.to_string())?;
    }

    assert!(ran >= 5, "runtime root denial cases must run");
    Ok(())
}

fn adversarial_process_policy_cases_run() -> Result<()> {
    let cases = load_cases()?;
    let process_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some("adv.process.interactive-disabled.v1")
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    for case in process_cases {
        ran += 1;
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));

        let command = command_with_local_python(case)?;
        let response = run_case_with_command(case, workspace, command)?;
        assert_eq!(
            observed_policy_rejected_result(&response),
            "policy_rejected",
            "case {} must reject policy: {response}",
            case["case_id"]
        );

        let result = emit_result(case, "policy_rejected", true)?;
        assert_eq!(result["status"], "passed", "{result}");
        assert_public_safe(&result.to_string())?;
    }

    assert!(ran >= 1, "process policy cases must run");
    Ok(())
}

#[cfg(windows)]
fn adversarial_process_timeout_cases_run() -> Result<()> {
    let cases = load_cases()?;
    let process_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some(
                "adv.process.orphan-child-after-cancel.v1"
                    | "adv.process.background-daemon-after-timeout.v1"
                    | "adv.process.process-tree-cleanup-bypass.v1"
                    | "adv.process.shell-trampoline-child.v1"
            )
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    for case in process_cases {
        ran += 1;
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
        let response = run_case_with_overrides(case, workspace, |params| {
            params.insert("command".to_string(), windows_timeout_command());
            params.insert("network".to_string(), json!("disabled"));
        })?;
        let observed = observed_timeout_result(&response);
        assert_eq!(
            if observed == "setup_unavailable" {
                "timeout"
            } else {
                observed
            },
            "timeout",
            "case {} must time out or fail closed before execution: {response}",
            case["case_id"]
        );

        let result = if observed == "setup_unavailable" {
            unsupported_fixture_result(case, "windows sandbox setup unavailable")?
        } else {
            emit_result(case, "timeout", true)?
        };
        assert!(
            matches!(
                result["status"].as_str(),
                Some("passed" | "unsupported_fixture")
            ),
            "{result}"
        );
        assert_public_safe(&result.to_string())?;
    }

    assert!(ran >= 4, "process timeout cases must run");
    Ok(())
}

fn adversarial_network_fail_closed_cases_run() -> Result<()> {
    let cases = load_cases()?;
    let network_cases = cases.iter().filter(|case| {
        matches!(
            case["case_id"].as_str(),
            Some(
                "adv.network.direct-egress-disabled.v1"
                    | "adv.network.http-egress-disabled.v1"
                    | "adv.network.managed-proxy-bypass.v1"
                    | "adv.network.proxy-env-override.v1"
                    | "adv.network.proxy-credential-redaction.v1"
                    | "adv.network.dns-fallback-leakage.v1"
                    | "adv.network.localhost-tunnel-abuse.v1"
                    | "adv.network.route-allowlist-bypass.v1"
            )
        ) && string_array_contains(&case["platforms"], current_platform())
            && string_array_contains(&case["backend_status"], "local-baseline")
    });

    let mut ran = 0;
    let mut ran_disabled_http = false;
    for case in network_cases {
        ran += 1;
        ran_disabled_http |= case["case_id"] == "adv.network.http-egress-disabled.v1";
        let tmp = TempDir::new()?;
        let workspace = tmp.path().join("workspace");
        fs::create_dir_all(&workspace)?;

        let command = command_with_local_python(case)?;
        let env = environment_fixtures(case)?;
        let response = run_case_with_overrides(case, &workspace, |params| {
            params.insert("command".to_string(), command);
            if !env.is_empty() {
                params.insert("env".to_string(), json!(env));
            }
        })?;
        assert_eq!(
            observed_filesystem_denial_result(&response),
            "deny_or_fail_closed",
            "case {} must deny or fail closed: {response}",
            case["case_id"]
        );
        if let Some(audit_path) = response["error"]["data"]["audit_path"].as_str() {
            let audit_jsonl = fs::read_to_string(workspace.join(audit_path))?;
            assert_public_safe(&audit_jsonl)?;
            assert!(!audit_jsonl.contains("user:secret"));
        }

        let result = emit_result(case, "deny_or_fail_closed", true)?;
        assert_eq!(result["status"], "passed", "{result}");
        assert_public_safe(&result.to_string())?;
    }

    assert!(ran >= 8, "network fail-closed cases must run");
    assert!(ran_disabled_http, "disabled HTTP egress case must run");
    Ok(())
}

fn adversarial_harness_materializes_file_fixtures_before_execution() -> Result<()> {
    let cases = load_cases()?;
    let mut materialized = 0;
    for case in cases.iter() {
        for fixture in case["fixtures"].as_array().into_iter().flatten() {
            if fixture["kind"] != "file" {
                continue;
            }
            materialized += 1;
            let tmp = TempDir::new()?;
            let path = materialize_file_fixture(tmp.path(), fixture)?;
            let pre_state = fs::metadata(&path)
                .with_context(|| format!("fixture must exist at {}", path.display()))?;
            assert!(pre_state.is_file());
            assert!(!path.starts_with(Path::new(env!("CARGO_MANIFEST_DIR"))));
        }
    }

    assert!(materialized >= 2, "harness must materialize file fixtures");
    Ok(())
}

fn adversarial_harness_materializes_directory_fixtures_before_execution() -> Result<()> {
    let cases = load_cases()?;
    let mut materialized = 0;
    for case in cases.iter() {
        for fixture in case["fixtures"].as_array().into_iter().flatten() {
            if fixture["kind"] != "directory" {
                continue;
            }
            materialized += 1;
            let tmp = TempDir::new()?;
            let path = materialize_directory_fixture(tmp.path(), fixture)?;
            let pre_state = fs::metadata(&path)
                .with_context(|| format!("fixture must exist at {}", path.display()))?;
            assert!(pre_state.is_dir());
            assert!(!path.starts_with(Path::new(env!("CARGO_MANIFEST_DIR"))));
        }
    }

    assert!(
        materialized >= 2,
        "harness must materialize directory fixtures"
    );
    Ok(())
}

fn adversarial_harness_materializes_symlink_fixtures_before_execution() -> Result<()> {
    let cases = load_cases()?;
    let mut materialized = 0;
    for case in cases.iter() {
        for fixture in case["fixtures"].as_array().into_iter().flatten() {
            if fixture["kind"] != "symlink" {
                continue;
            }
            materialized += 1;
            let tmp = TempDir::new()?;
            materialize_supported_fixtures(tmp.path(), case)?;
            let path = tmp.path().join(safe_fixture_relative_path(
                fixture["path"]
                    .as_str()
                    .context("symlink fixture path must be a string")?,
                "symlink",
            )?);
            let pre_state = fs::symlink_metadata(&path)
                .with_context(|| format!("fixture must exist at {}", path.display()))?;
            assert!(pre_state.file_type().is_symlink());
            assert!(!path.starts_with(Path::new(env!("CARGO_MANIFEST_DIR"))));
        }
    }

    assert!(
        materialized >= 2,
        "harness must materialize symlink fixtures"
    );
    Ok(())
}

#[cfg(windows)]
fn adversarial_harness_materializes_junction_fixtures_before_execution() -> Result<()> {
    let cases = load_cases()?;
    let mut materialized = 0;
    for case in cases.iter() {
        for fixture in case["fixtures"].as_array().into_iter().flatten() {
            if fixture["kind"] != "junction" {
                continue;
            }
            materialized += 1;
            let tmp = TempDir::new()?;
            materialize_supported_fixtures(tmp.path(), case)?;
            let path = tmp.path().join(safe_fixture_relative_path(
                fixture["path"]
                    .as_str()
                    .context("junction fixture path must be a string")?,
                "junction",
            )?);
            let pre_state = fs::metadata(&path)
                .with_context(|| format!("fixture must exist at {}", path.display()))?;
            assert!(pre_state.is_dir());
            assert!(!path.starts_with(Path::new(env!("CARGO_MANIFEST_DIR"))));
        }
    }

    assert!(
        materialized >= 1,
        "harness must materialize junction fixtures"
    );
    Ok(())
}

fn adversarial_harness_cleans_fixture_workspace() -> Result<()> {
    let case = load_cases()?
        .into_iter()
        .find(|case| case["case_id"] == "adv.filesystem.parent-traversal.v1")
        .context("file fixture adversarial case must exist")?;
    let fixture = case["fixtures"]
        .as_array()
        .and_then(|fixtures| fixtures.first())
        .context("case must include a file fixture")?;
    let workspace;
    {
        let tmp = TempDir::new()?;
        workspace = tmp.path().to_path_buf();
        let path = materialize_file_fixture(tmp.path(), fixture)?;
        assert!(path.exists());
    }
    assert!(!workspace.exists());
    Ok(())
}

fn adversarial_harness_skips_unsupported_fixtures() -> Result<()> {
    let mut case = load_cases()?
        .into_iter()
        .find(|case| case["case_id"] == "adv.filesystem.parent-traversal.v1")
        .context("file fixture adversarial case must exist")?;
    case["fixtures"] = json!([{"kind": "symlink", "path": "link", "target": "target"}]);

    let result = unsupported_fixture_result(&case, "unsupported fixture kind: symlink")?;

    assert_eq!(result["status"], "unsupported_fixture");
    assert_eq!(result["skipped"], true);
    assert_eq!(result["passed"], false);
    assert_eq!(result["skip_reason"], "unsupported fixture kind: symlink");
    assert_public_safe(&result.to_string())?;
    Ok(())
}

fn adversarial_harness_inspects_file_side_effects() -> Result<()> {
    let tmp = TempDir::new()?;
    let path = tmp.path().join("tracked.txt");
    fs::write(&path, "before")?;
    let pre_state = FilePreState::capture(&path)?;

    assert!(inspect_file_side_effect(
        "file_exists",
        &path,
        pre_state.as_ref()
    )?);
    assert!(inspect_file_side_effect(
        "path_not_modified",
        &path,
        pre_state.as_ref()
    )?);
    fs::write(&path, "after")?;
    assert!(!inspect_file_side_effect(
        "path_not_modified",
        &path,
        pre_state.as_ref()
    )?);
    assert!(inspect_file_side_effect(
        "file_not_exists",
        &tmp.path().join("missing.txt"),
        None
    )?);
    assert!(inspect_file_side_effect(
        "path_not_accessible",
        &tmp.path().join("missing.txt"),
        None
    )?);
    assert!(!inspect_file_side_effect(
        "path_not_accessible",
        &path,
        pre_state.as_ref()
    )?);
    Ok(())
}

fn adversarial_harness_maps_file_oracles_to_inspection() -> Result<()> {
    let cases = load_cases()?;
    let mut inspected = 0;
    for case in cases.iter() {
        if !string_array_contains(
            &case["oracle"]["forbidden_side_effects"],
            "path_not_accessible",
        ) {
            continue;
        }
        for fixture in case["fixtures"].as_array().into_iter().flatten() {
            if fixture["kind"] != "file" {
                continue;
            }
            inspected += 1;
            let tmp = TempDir::new()?;
            let path = materialize_file_fixture(tmp.path(), fixture)?;
            let pre_state = FilePreState::capture(&path)?;
            assert!(!inspect_file_side_effect(
                "path_not_accessible",
                &path,
                pre_state.as_ref()
            )?);
        }
    }

    assert!(inspected >= 1, "harness must inspect file oracle effects");
    Ok(())
}

fn adversarial_harness_computes_result_severity() {
    assert_eq!(severity_for_result("policy_rejected", true), "S0");
    assert_eq!(severity_for_result("deny", true), "S0");
    assert_eq!(severity_for_result("fail_closed", true), "S0");
    assert_eq!(severity_for_result("harness_error", true), "S3");
    assert_eq!(severity_for_result("policy_rejected", false), "S4");
}

fn adversarial_harness_emits_complete_public_safe_results() -> Result<()> {
    let case = load_cases()?
        .into_iter()
        .find(|case| case["case_id"] == "adv.policy.unknown-top-level-field.v1")
        .context("policy adversarial case must exist")?;
    let result = emit_result(&case, "policy_rejected", true)?;

    assert_eq!(result["schema_version"], "runseal.adversarial-result/v1");
    assert_eq!(result["case_id"], case["case_id"]);
    assert_eq!(result["backend_status"], "local-baseline");
    assert_eq!(result["observed_result"], "policy_rejected");
    assert_eq!(result["severity"], "S0");
    assert_eq!(result["status"], "passed");
    assert_public_safe(&result.to_string())?;
    Ok(())
}

fn load_cases() -> Result<Vec<Value>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("adversarial/cases/rfc0016-initial.json");
    let manifest =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&manifest)
        .with_context(|| format!("manifest must be JSON: {}", path.display()))
}

fn emit_result(case: &Value, observed_result: &str, public_outcome_visible: bool) -> Result<Value> {
    let result = json!({
        "schema_version": "runseal.adversarial-result/v1",
        "case_id": case["case_id"],
        "backend_name": "runseal-local",
        "backend_status": "local-baseline",
        "platform": current_platform(),
        "capabilities_under_test": case["capabilities_under_test"],
        "sandbox_level": case["sandbox_level"],
        "network_mode": case["network_mode"],
        "expected_result": case["oracle"]["expected_result"],
        "observed_result": observed_result,
        "severity": severity_for_result(observed_result, public_outcome_visible),
        "passed": observed_result == case["oracle"]["expected_result"],
        "skipped": false,
        "skip_reason": null,
        "policy_hash_present": observed_result == "allow_no_side_effect_outside_policy",
        "policy_epoch_present": observed_result == "allow_no_side_effect_outside_policy",
        "audit_present": case["oracle"]["audit"]["required"].as_bool().unwrap_or(false),
        "events_present": case["oracle"]["events"]["required"].as_bool().unwrap_or(false),
        "public_safe_output": true,
        "status": if observed_result == case["oracle"]["expected_result"] { "passed" } else { "failed" }
    });
    assert_public_safe(&result.to_string())?;
    Ok(result)
}

fn unsupported_fixture_result(case: &Value, reason: &str) -> Result<Value> {
    let result = json!({
        "schema_version": "runseal.adversarial-result/v1",
        "case_id": case["case_id"],
        "backend_name": "runseal-local",
        "backend_status": "local-baseline",
        "platform": current_platform(),
        "capabilities_under_test": case["capabilities_under_test"],
        "sandbox_level": case["sandbox_level"],
        "network_mode": case["network_mode"],
        "expected_result": case["oracle"]["expected_result"],
        "observed_result": case["oracle"]["expected_result"],
        "severity": "S0",
        "passed": false,
        "skipped": true,
        "skip_reason": reason,
        "policy_hash_present": false,
        "policy_epoch_present": false,
        "audit_present": false,
        "events_present": false,
        "public_safe_output": true,
        "status": "unsupported_fixture"
    });
    assert_public_safe(&result.to_string())?;
    Ok(result)
}

fn severity_for_result(observed_result: &str, public_audit_visible: bool) -> &'static str {
    match (observed_result, public_audit_visible) {
        (
            "allow_no_side_effect_outside_policy"
            | "audit_redacted"
            | "policy_rejected"
            | "deny"
            | "fail_closed"
            | "deny_or_fail_closed",
            true,
        ) => "S0",
        (_, false) => "S4",
        _ => "S3",
    }
}

#[derive(Clone, Copy)]
struct FilePreState {
    len: u64,
    modified: std::time::SystemTime,
}

impl FilePreState {
    fn capture(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let metadata = fs::metadata(path)
            .with_context(|| format!("failed to read metadata for {}", path.display()))?;
        Ok(Some(Self {
            len: metadata.len(),
            modified: metadata
                .modified()
                .with_context(|| format!("failed to read modified time for {}", path.display()))?,
        }))
    }
}

fn inspect_file_side_effect(
    kind: &str,
    path: &Path,
    pre_state: Option<&FilePreState>,
) -> Result<bool> {
    match kind {
        "file_exists" => Ok(path.exists()),
        "file_not_exists" => Ok(!path.exists()),
        "path_not_accessible" => Ok(fs::metadata(path).is_err()),
        "path_not_modified" => {
            let Some(pre_state) = pre_state else {
                return Ok(!path.exists());
            };
            let metadata = fs::metadata(path)
                .with_context(|| format!("failed to read metadata for {}", path.display()))?;
            Ok(metadata.len() == pre_state.len
                && metadata.modified().with_context(|| {
                    format!("failed to read modified time for {}", path.display())
                })? == pre_state.modified)
        }
        _ => bail!("unsupported file side-effect inspection {kind}"),
    }
}

fn materialize_file_fixture(root: &Path, fixture: &Value) -> Result<PathBuf> {
    let relative = fixture["path"]
        .as_str()
        .context("file fixture path must be a string")?;
    let relative_path = safe_fixture_relative_path(relative, "file")?;
    let path = root.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, fixture["body"].as_str().unwrap_or(""))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn materialize_directory_fixture(root: &Path, fixture: &Value) -> Result<PathBuf> {
    let relative = fixture["path"]
        .as_str()
        .context("directory fixture path must be a string")?;
    let relative_path = safe_fixture_relative_path(relative, "directory")?;
    let path = root.join(relative_path);
    fs::create_dir_all(&path).with_context(|| format!("failed to create {}", path.display()))?;
    Ok(path)
}

fn materialize_readonly_file_fixture(root: &Path, fixture: &Value) -> Result<PathBuf> {
    let path = materialize_file_fixture(root, fixture)?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions)
        .with_context(|| format!("failed to set readonly permissions on {}", path.display()))?;
    Ok(path)
}

fn materialize_preexisting_runtime_root_fixture(root: &Path, fixture: &Value) -> Result<PathBuf> {
    let relative = fixture["path"]
        .as_str()
        .context("preexisting runtime root fixture path must be a string")?;
    let relative_path = safe_fixture_relative_path(relative, "preexisting runtime root")?;
    let path = root.join("workspace").join(relative_path);
    fs::create_dir_all(&path).with_context(|| format!("failed to create {}", path.display()))?;
    fs::write(path.join(".runseal-runtime-root"), b"preexisting")
        .with_context(|| format!("failed to write marker in {}", path.display()))?;
    Ok(path)
}

fn materialize_supported_fixtures(root: &Path, case: &Value) -> Result<Vec<PathBuf>> {
    case["fixtures"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|fixture| match fixture["kind"].as_str() {
            Some("file") => materialize_file_fixture(root, fixture),
            Some("readonly_file") => materialize_readonly_file_fixture(root, fixture),
            Some("directory") => materialize_directory_fixture(root, fixture),
            Some("symlink") => materialize_symlink_fixture(root, fixture),
            Some("junction") => materialize_junction_fixture(root, fixture),
            Some("preexisting_runtime_root") => {
                materialize_preexisting_runtime_root_fixture(root, fixture)
            }
            Some(kind) => bail!("unsupported fixture kind: {kind}"),
            None => bail!("fixture kind must be a string"),
        })
        .collect()
}

fn environment_fixtures(case: &Value) -> Result<serde_json::Map<String, Value>> {
    let mut env = serde_json::Map::new();
    for fixture in case["fixtures"].as_array().into_iter().flatten() {
        if fixture["kind"] != "environment" {
            continue;
        }
        let name = fixture["name"]
            .as_str()
            .context("environment fixture name must be a string")?;
        let value = fixture["value"]
            .as_str()
            .context("environment fixture value must be a string")?;
        env.insert(name.to_string(), json!(value));
    }
    Ok(env)
}

fn safe_fixture_relative_path<'a>(relative: &'a str, kind: &str) -> Result<&'a Path> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("{kind} fixture path must stay inside the isolated workspace");
    }
    Ok(relative_path)
}

fn materialize_symlink_fixture(root: &Path, fixture: &Value) -> Result<PathBuf> {
    let relative = fixture["path"]
        .as_str()
        .context("symlink fixture path must be a string")?;
    let target = fixture["target"]
        .as_str()
        .context("symlink fixture target must be a string")?;
    let relative_path = safe_fixture_relative_path(relative, "symlink")?;
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        bail!("symlink fixture target must be relative");
    }

    let path = root.join(relative_path);
    let parent = path
        .parent()
        .with_context(|| format!("symlink fixture must have a parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;

    let resolved_target = normalize_path(parent.join(target_path));
    if !resolved_target.starts_with(root) {
        bail!("symlink fixture target must stay inside the isolated workspace");
    }

    create_symlink(target_path, &resolved_target, &path)?;
    Ok(path)
}

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

#[cfg(windows)]
fn create_symlink(target: &Path, resolved_target: &Path, link: &Path) -> Result<()> {
    if resolved_target.is_dir() {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
    .with_context(|| format!("failed to create symlink {}", link.display()))
}

#[cfg(unix)]
fn create_symlink(target: &Path, _resolved_target: &Path, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link)
        .with_context(|| format!("failed to create symlink {}", link.display()))
}

#[cfg(windows)]
fn materialize_junction_fixture(root: &Path, fixture: &Value) -> Result<PathBuf> {
    let relative = fixture["path"]
        .as_str()
        .context("junction fixture path must be a string")?;
    let target = fixture["target"]
        .as_str()
        .context("junction fixture target must be a string")?;
    let relative_path = safe_fixture_relative_path(relative, "junction")?;
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        bail!("junction fixture target must be relative");
    }

    let path = root.join(relative_path);
    let parent = path
        .parent()
        .with_context(|| format!("junction fixture must have a parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;

    let resolved_target = normalize_path(parent.join(target_path));
    if !resolved_target.starts_with(root) {
        bail!("junction fixture target must stay inside the isolated workspace");
    }
    if !resolved_target.is_dir() {
        bail!("junction fixture target must be an existing directory");
    }

    let script = format!(
        "New-Item -ItemType Junction -Path {} -Target {} | Out-Null",
        ps_literal_path(&path),
        ps_literal_path(&resolved_target)
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command"])
        .arg(&script)
        .output()
        .context("failed to run powershell.exe")?;
    if !output.status.success() {
        bail!(
            "failed to create junction {}: {}{}",
            path.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(path)
}

#[cfg(windows)]
fn ps_literal_path(path: &Path) -> String {
    format!(
        "'{}'",
        path.to_string_lossy()
            .replace('/', "\\")
            .replace('\'', "''")
    )
}

#[cfg(not(windows))]
fn materialize_junction_fixture(_root: &Path, _fixture: &Value) -> Result<PathBuf> {
    bail!("junction fixtures are only supported on windows")
}

fn command_with_local_python(case: &Value) -> Result<Value> {
    let mut command = case["request"]["command"]
        .as_array()
        .context("case.request.command must be an array")?
        .clone();
    if command.first().and_then(Value::as_str) == Some("python") {
        command[0] = json!(python_bin());
    }
    Ok(Value::Array(command))
}

#[cfg(windows)]
fn windows_timeout_command() -> Value {
    let system_root = env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    json!([
        format!("{system_root}\\System32\\cmd.exe"),
        "/C",
        "ping 127.0.0.1 -n 6 >NUL"
    ])
}

#[cfg(windows)]
fn observed_timeout_result(response: &Value) -> &'static str {
    match response["error"]["data"]["code"].as_str() {
        Some("EXECUTION_TIMEOUT") => "timeout",
        Some("BACKEND_UNAVAILABLE") => "setup_unavailable",
        _ => "harness_error",
    }
}

fn observed_filesystem_denial_result(response: &Value) -> &'static str {
    match response["error"]["data"]["code"].as_str() {
        Some(
            "BACKEND_UNAVAILABLE"
            | "BACKEND_CAPABILITY_MISSING"
            | "POLICY_DENIED"
            | "EXECUTION_FAILED_TO_START",
        ) => "deny_or_fail_closed",
        _ if response["result"]["status"] == "finished" && response["result"]["exit_code"] != 0 => {
            "deny_or_fail_closed"
        }
        _ => "harness_error",
    }
}

fn observed_policy_rejected_result(response: &Value) -> &'static str {
    match response["error"]["data"]["code"].as_str() {
        Some("INVALID_REQUEST" | "POLICY_INVALID") => "policy_rejected",
        _ => "harness_error",
    }
}

fn assert_forbidden_file_side_effects_hold(root: &Path, case: &Value) -> Result<()> {
    if !string_array_contains(
        &case["oracle"]["forbidden_side_effects"],
        "path_not_modified",
    ) {
        return Ok(());
    }

    for fixture in case["fixtures"].as_array().into_iter().flatten() {
        if fixture["kind"] != "file" {
            continue;
        }
        let relative = fixture["path"]
            .as_str()
            .context("file fixture path must be a string")?;
        let path = root.join(safe_fixture_relative_path(relative, "file")?);
        let expected = fixture["body"].as_str().unwrap_or("");
        let actual = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        assert_eq!(
            actual,
            expected,
            "case {} must not modify {}",
            case["case_id"],
            path.display()
        );
    }
    Ok(())
}

fn run_case(case: &Value, cwd: &Path) -> Result<Value> {
    run_case_with_overrides(case, cwd, |_| {})
}

fn run_case_with_command(case: &Value, cwd: &Path, command: Value) -> Result<Value> {
    run_case_with_overrides(case, cwd, |params| {
        params.insert("command".to_string(), command);
    })
}

fn run_case_messages_with_command(case: &Value, cwd: &Path, command: Value) -> Result<Vec<Value>> {
    run_case_messages_with_overrides(case, cwd, |params| {
        params.insert("command".to_string(), command);
    })
}

fn run_case_with_overrides(
    case: &Value,
    cwd: &Path,
    apply: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> Result<Value> {
    Ok(response_message(&run_case_messages_with_overrides(case, cwd, apply)?)?.clone())
}

fn run_case_messages_with_overrides(
    case: &Value,
    cwd: &Path,
    apply: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> Result<Vec<Value>> {
    let request = case["request"]
        .as_object()
        .context("case.request must be an object")?;
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .context("case.request.method must be a string")?;
    let mut params = request.clone();
    params.remove("method");
    params.insert("cwd".to_string(), json!(cwd));
    apply(&mut params);

    rpc_messages(&rpc_request(method, Value::Object(params)))
}

fn observed_denial_result(response: &Value) -> &'static str {
    match response["error"]["data"]["code"].as_str() {
        Some("INVALID_REQUEST" | "POLICY_INVALID") => "deny",
        _ => "harness_error",
    }
}

fn rpc_result(message: &str) -> Result<Value> {
    rpc_response_result(message)
}

fn rpc_response_result(message: &str) -> Result<Value> {
    rpc_response(message)?
        .get("result")
        .cloned()
        .context("rpc response result must exist")
}

fn rpc_response(message: &str) -> Result<Value> {
    response_message(&rpc_messages(message)?).cloned()
}

fn rpc_messages(message: &str) -> Result<Vec<Value>> {
    let output = run_rpc(message)?;
    if !output.status.success() {
        bail!("{}", String::from_utf8_lossy(&output.stderr));
    }
    let stdout = String::from_utf8(output.stdout).context("stdout must be utf-8")?;
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()
        .context("rpc response must be JSON")
}

fn response_message(messages: &[Value]) -> Result<&Value> {
    messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .context("rpc response must exist")
}

fn read_audit_events(root: &Path, audit_path: &str) -> Result<Vec<Value>> {
    fs::read_to_string(root.join(audit_path))?
        .lines()
        .map(|line| serde_json::from_str(line).context("audit line must be JSON"))
        .collect()
}

fn current_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

fn string_array_contains(value: &Value, needle: &str) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(needle)))
}

fn assert_public_safe(output: &str) -> Result<()> {
    let lower = output.to_ascii_lowercase();
    let terms = lower
        .split(|byte: char| !byte.is_ascii_alphanumeric())
        .collect::<std::collections::HashSet<_>>();
    for term in PRIVATE_TERMS {
        if terms.contains(term) {
            bail!("adversarial result contains private term {term}");
        }
    }
    Ok(())
}
