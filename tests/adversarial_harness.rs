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
            && case["sandbox_level"] == "malformed"
            && case["oracle"]["expected_result"] == "policy_rejected"
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
            "severity": if observed_result == "policy_rejected" { "S0" } else { "S4" },
            "passed": observed_result == "policy_rejected",
            "skipped": false,
            "skip_reason": null,
            "policy_hash_present": false,
            "policy_epoch_present": false,
            "audit_present": false,
            "events_present": false,
            "public_safe_output": true,
            "status": if observed_result == "policy_rejected" { "passed" } else { "failed" }
        });
        assert_public_safe(&result.to_string())?;
        assert_eq!(result["status"], "passed", "{result}");
    }

    assert!(
        ran >= 2,
        "tier0 policy harness must run malformed policy cases"
    );
    Ok(())
}

fn load_cases() -> Result<Vec<Value>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("adversarial/cases/rfc0016-initial.json");
    let manifest =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&manifest)
        .with_context(|| format!("manifest must be JSON: {}", path.display()))
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
