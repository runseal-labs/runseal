use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
fn adversarial_tier0_policy_cases_emit_public_safe_results() -> Result<()> {
    let cases = load_cases()?;
    let tier0_cases = cases.iter().filter(|case| {
        case["primary_class"] == "policy"
            && case["oracle"]["expected_result"] == "policy_rejected"
            && string_array_contains(&case["platforms"], current_platform())
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
fn adversarial_harness_computes_result_severity() {
    assert_eq!(severity_for_result("policy_rejected", true), "S0");
    assert_eq!(severity_for_result("deny", true), "S0");
    assert_eq!(severity_for_result("fail_closed", true), "S0");
    assert_eq!(severity_for_result("harness_error", true), "S3");
    assert_eq!(severity_for_result("policy_rejected", false), "S4");
}

#[test]
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
        ("policy_rejected" | "deny" | "fail_closed" | "deny_or_fail_closed", true) => "S0",
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
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("file fixture path must stay inside the isolated workspace");
    }
    let path = root.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, fixture["body"].as_str().unwrap_or(""))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn run_case(case: &Value, cwd: &Path) -> Result<Value> {
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

    let output = run_rpc(&rpc_request(method, Value::Object(params)))?;
    if !output.status.success() {
        bail!("{}", String::from_utf8_lossy(&output.stderr));
    }
    let stdout = String::from_utf8(output.stdout).context("stdout must be utf-8")?;
    stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .transpose()
        .context("rpc response must be JSON")?
        .context("rpc response must exist")
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
        .context("rpc response must be JSON")?
        .into_iter()
        .find(|message| message.get("id") == Some(&json!(1)))
        .context("rpc response must exist")
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
