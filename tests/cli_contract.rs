use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;
use tempfile::TempDir;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn runseal_bin() -> PathBuf {
    env::var_os("RUNSEAL_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_runseal").map(PathBuf::from))
        .unwrap_or_else(|| {
            let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/runseal");
            if cfg!(windows) {
                path.set_extension("exe");
            }
            path
        })
}

fn require_runseal_bin() -> Result<PathBuf> {
    let bin = runseal_bin();
    if !bin.exists() {
        bail!(
            "RunSeal binary not found at {}. Set RUNSEAL_BIN to a candidate implementation to run conformance tests.",
            bin.display()
        );
    }
    Ok(bin)
}

fn run_cli(args: &[&str]) -> Result<Output> {
    let bin = require_runseal_bin()?;
    Command::new(bin)
        .args(args)
        .output()
        .context("failed to spawn runseal")
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

fn stdout_json(output: &Output) -> Result<Value> {
    serde_json::from_slice(&output.stdout).context("stdout was not valid JSON")
}

fn stdout_json_lines(output: &Output) -> Result<Vec<Value>> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("stdout line was not valid JSON"))
        .collect()
}

fn decode_stream_event(event: &Value) -> Result<String> {
    assert_rfc3339_timestamp(&event["time"])?;
    assert_eq!(event["encoding"], "base64");
    assert_eq!(event["stream_offset"], 0);
    assert!(event.get("text").is_none());
    let encoded = event["data"]
        .as_str()
        .and_then(|data| data.strip_prefix("base64:"))
        .context("stream event must include base64-prefixed data")?;
    let bytes = STANDARD
        .decode(encoded)
        .context("stream data must decode")?;
    String::from_utf8(bytes).context("stream data must be UTF-8 for this test")
}

fn assert_rfc3339_timestamp(value: &Value) -> Result<()> {
    let timestamp = value.as_str().context("timestamp must be a string")?;
    OffsetDateTime::parse(timestamp, &Rfc3339)
        .with_context(|| format!("timestamp must be RFC3339 UTC: {timestamp}"))?;
    Ok(())
}

fn assert_event_envelope(event: &Value) -> Result<()> {
    assert!(event["type"].as_str().is_some());
    assert_rfc3339_timestamp(&event["time"])?;
    assert!(
        event["execution_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("exec_")
    );
    assert!(
        event["session_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sess_")
    );
    assert!(
        event["seal_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("seal_")
    );
    assert!(event["policy_id"].as_str().is_some());
    assert!(
        event["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert!(event["policy_epoch"].as_str().is_some());
    assert!(event["runseal_version"].as_str().is_some());
    assert!(
        event["audit_path"]
            .as_str()
            .unwrap_or_default()
            .starts_with(".runseal/audit/sess_")
    );
    assert!(event["backend"]["name"].as_str().is_some());
    assert!(event["backend"]["status"].as_str().is_some());
    assert!(event["backend"]["platform"].as_str().is_some());
    Ok(())
}

fn expected_backend_name() -> &'static str {
    if cfg!(windows) {
        "runseal-windows-reference"
    } else if cfg!(target_os = "macos") {
        "runseal-macos-experimental"
    } else if cfg!(target_os = "linux") {
        "runseal-linux-community"
    } else {
        "runseal-local"
    }
}

fn expected_backend_status() -> &'static str {
    if cfg!(windows) {
        "reference"
    } else if cfg!(any(target_os = "macos", target_os = "linux")) {
        "experimental"
    } else {
        "local-baseline"
    }
}

fn expected_backend_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

fn expected_disabled_feature_reported() -> bool {
    cfg!(any(windows, target_os = "macos", target_os = "linux"))
}

fn expected_disabled_feature_status() -> &'static str {
    if cfg!(windows) {
        "supported"
    } else if cfg!(any(target_os = "macos", target_os = "linux")) {
        "experimental"
    } else {
        "unsupported"
    }
}

fn expected_windows_sandbox_supported() -> bool {
    cfg!(windows)
}

fn expected_proxy_feature_reported() -> bool {
    cfg!(any(windows, target_os = "macos", target_os = "linux"))
}

fn expected_proxy_feature_status() -> &'static str {
    if cfg!(windows) {
        "supported"
    } else if cfg!(any(target_os = "macos", target_os = "linux")) {
        "experimental"
    } else {
        "unsupported"
    }
}

fn expected_network_proxy_status() -> &'static str {
    expected_status(expected_proxy_feature_reported())
}

fn expected_resource_limits_supported() -> bool {
    false
}

fn expected_status(supported: bool) -> &'static str {
    if supported {
        "supported"
    } else {
        "unsupported"
    }
}

fn expected_read_only_status() -> &'static str {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        "supported"
    } else {
        expected_status(expected_windows_sandbox_supported())
    }
}

fn expected_workspace_write_status() -> &'static str {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        "supported"
    } else {
        expected_status(expected_windows_sandbox_supported())
    }
}

fn expected_workspace_contained_status() -> &'static str {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        "supported"
    } else if cfg!(windows) {
        expected_status(expected_windows_sandbox_supported())
    } else {
        "unsupported"
    }
}

fn expected_network_disabled_status() -> &'static str {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        "supported"
    } else {
        expected_status(expected_windows_sandbox_supported())
    }
}

fn assert_no_private_windows_setup_terms(text: &str) {
    for private_term in [
        "single-sandbox-user",
        "RunSealSandbox",
        "RunSealSandboxUsers",
        "restricted-token",
        "kill-on-close-job",
        "orchestrator_",
        "helper_",
        "vendored",
        "upstream",
        "WindowsSandboxSetup",
        "scheduled task",
        "sandbox account",
        "local user",
        "profile account",
        "SID",
        "ACL",
        "WFP",
        "firewall",
        "Job Object",
        "Codex",
        "OpenAI",
        "WindowsApps",
        "offline",
        "online",
        "dual",
        "two users",
    ] {
        assert!(
            !text.contains(private_term),
            "CLI output must not expose private Windows setup term {private_term}"
        );
    }
}

fn assert_portable_fail_closed_preview(plan: &Value) {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }

    assert_eq!(plan["backend"]["name"], expected_backend_name());
    assert_eq!(plan["backend"]["status"], expected_backend_status());
    assert_eq!(plan["backend"]["platform"], expected_backend_platform());
    assert_eq!(plan["sandbox_level"], "read-only");
    assert_eq!(plan["enforcement"], "fail-closed-preview");
    assert_eq!(plan["cwd"], "workspace");
    assert_eq!(plan["runtime_root"], "runtime_root");
    assert_eq!(plan["profile_root"], "profile_root");
    assert_eq!(plan["synthetic_home"], "synthetic_home");
    assert_eq!(plan["temp_root"], "temp_root");
    assert_eq!(plan["filesystem"]["read"], json!(["workspace"]));
    assert_eq!(
        plan["filesystem"]["write"],
        json!([
            "runtime_root",
            "profile_root",
            "synthetic_home",
            "temp_root"
        ])
    );
    assert_eq!(plan["process"]["boundary"], "platform-sandbox");
    assert_eq!(plan["process"]["identity"], "current-user");
    assert_eq!(plan["process"]["cleanup"], "process-tree");
    assert_eq!(plan["network"]["direct_egress"], "deny");
    assert_eq!(plan["network"]["managed_proxy"], "none");
    assert_eq!(
        plan["required_backend_features"],
        json!([
            "filesystem_policy",
            "runtime_roots",
            "runtime_environment",
            "process_isolation",
            "process_cleanup",
            "direct_network_deny",
            "network_disabled"
        ])
    );
    let plan_text = plan.to_string();
    for private_term in [
        "bubblewrap",
        "landlock",
        "namespace",
        "seccomp",
        "sandbox_exec",
        "seatbelt",
        "profile fragment",
    ] {
        assert!(
            !plan_text.contains(private_term),
            "portable preview must not expose private mechanism term {private_term}"
        );
    }
}

fn assert_portable_capability_probe_contract(payload: &Value) {
    #[cfg(windows)]
    assert!(payload.get("capability_probes").is_none());

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let Some(probes) = payload["capability_probes"].as_array() else {
            panic!("portable backend must report diagnostic capability probes");
        };
        assert!(!probes.is_empty());
        let mut mechanisms = Vec::with_capacity(probes.len());
        for probe in probes {
            assert!(probe["capability"].as_str().is_some());
            let Some(mechanism) = probe["mechanism"].as_str() else {
                panic!("portable backend probe must report mechanism");
            };
            assert!(
                [
                    "supported",
                    "experimental",
                    "unsupported",
                    "unavailable",
                    "requires_setup",
                ]
                .iter()
                .any(|status| probe["status"] == *status)
            );
            assert_eq!(probe["diagnostic_only"], true);
            assert!(probe["available"].is_boolean());
            mechanisms.push(mechanism);
        }
        #[cfg(target_os = "linux")]
        assert_eq!(
            mechanisms,
            vec![
                "landlock",
                "landlock_abi_version",
                "user_namespaces",
                "user_namespace_quota",
                "mount_namespaces",
                "pid_namespaces",
                "network_namespaces",
                "seccomp",
                "bubblewrap",
                "unprivileged_user_namespaces",
            ]
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            mechanisms,
            vec![
                "sandbox_exec",
                "sandbox_exec_executable",
                "macos_version",
                "temporary_profile",
                "canonical_paths",
                "symlink_path_model",
            ]
        );
    }
}

#[test]
fn missing_binary_is_explicit_red_state() {
    if runseal_bin().exists() {
        return;
    }
    let error = run_cli(&["--version"]).expect_err("missing implementation should be RED");
    let message = error.to_string();
    assert!(message.contains("RunSeal binary not found"), "{message}");
    assert!(message.contains("RUNSEAL_BIN"), "{message}");
}

#[test]
fn help_lists_core_commands() -> Result<()> {
    let output = run_cli(&["--help"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Usage: runseal <command> [options]"));
    assert!(stdout.contains("exec --policy <policy>"));
    assert!(stdout.contains("mcp --stdio"));
    assert!(stdout.contains("setup windows-sandbox [--cwd <path>]"));
    assert!(stdout.contains("capabilities"));
    assert_no_private_windows_setup_terms(&stdout);
    Ok(())
}

#[test]
fn service_local_ipc_modes_fail_closed() -> Result<()> {
    for flag in ["--pipe", "--socket"] {
        let output = run_cli(&["service", flag])?;

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("local service transport RFC"), "{stderr}");
        assert_no_private_windows_setup_terms(&stderr);

        let output = run_cli(&["service", flag, "runseal-test"])?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("local service transport RFC"), "{stderr}");
        assert_no_private_windows_setup_terms(&stderr);
    }
    Ok(())
}

#[test]
fn service_remote_transport_modes_fail_closed() -> Result<()> {
    for flag in ["--tcp", "--http"] {
        let output = run_cli(&["service", flag])?;

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("remote transport RFC"), "{stderr}");
        assert_no_private_windows_setup_terms(&stderr);

        let output = run_cli(&["service", flag, "127.0.0.1:0"])?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains("remote transport RFC"), "{stderr}");
        assert_no_private_windows_setup_terms(&stderr);
    }
    Ok(())
}

#[test]
fn setup_help_describes_explicit_windows_setup() -> Result<()> {
    for args in [
        &["setup", "--help"][..],
        &["setup", "windows-sandbox", "--help"][..],
    ] {
        let output = run_cli(args)?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.contains("Usage: runseal setup windows-sandbox [--cwd <path>]"));
        assert!(stdout.contains("Use --elevate to request UAC"));
        assert!(stdout.contains("Later repairs reuse the sandbox broker"));
        assert!(stdout.contains("fails closed"));
        assert!(stdout.contains("--status"));
        assert!(stdout.contains("--json"));
        assert!(stdout.contains("--elevate"));
        assert_no_private_windows_setup_terms(&stdout);
    }
    Ok(())
}

#[test]
fn readme_does_not_expose_private_windows_setup_terms() {
    assert_no_private_windows_setup_terms(include_str!("../README.md"));
}

#[test]
fn setup_status_reports_setup_readiness_without_running_setup() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    for args in [
        vec!["setup", "windows-sandbox", "--cwd", &cwd, "--status"],
        vec![
            "setup",
            "windows-sandbox",
            "--cwd",
            &cwd,
            "--status",
            "--json",
        ],
    ] {
        let output = run_cli(&args)?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let payload = stdout_json(&output)?;
        assert_eq!(payload["setup"], "windows-sandbox");
        assert_eq!(payload["platform_supported"], cfg!(windows));
        if cfg!(windows) {
            assert!(payload["elevated"].is_boolean(), "{payload}");
            let elevated = payload["elevated"].as_bool().unwrap_or(false);
            let broker_available = payload["broker"] == "available";
            assert_eq!(
                payload["can_repair"].as_bool(),
                Some(elevated || broker_available),
                "{payload}"
            );
            assert_eq!(
                payload["can_run_setup_now"].as_bool(),
                Some(elevated || broker_available),
                "{payload}"
            );
        } else {
            assert!(payload["elevated"].is_null(), "{payload}");
            assert_eq!(payload["can_repair"], false, "{payload}");
            assert_eq!(payload["can_run_setup_now"], false, "{payload}");
        }
        assert!(
            matches!(
                payload["broker"].as_str(),
                Some("available" | "unavailable")
            ),
            "{payload}"
        );
        assert!(payload["requires_setup"].is_boolean(), "{payload}");
        assert!(
            matches!(
                payload["next_action"].as_str(),
                Some("none" | "run_setup" | "open_elevated_shell" | "unsupported")
            ),
            "{payload}"
        );
        match payload["next_action"].as_str() {
            Some("run_setup") => {
                assert_eq!(payload["requires_setup"], true, "{payload}");
                assert_eq!(
                    payload["next_command"],
                    "runseal setup windows-sandbox --cwd <absolute-workspace-path> --json",
                    "{payload}"
                );
            }
            Some("open_elevated_shell") => {
                assert_eq!(payload["requires_setup"], true, "{payload}");
                assert_eq!(
                    payload["next_command"],
                    "runseal setup windows-sandbox --cwd <absolute-workspace-path> --json --elevate",
                    "{payload}"
                );
            }
            Some("none" | "unsupported") => {
                assert_eq!(payload["requires_setup"], false, "{payload}");
                assert!(payload["next_command"].is_null(), "{payload}");
            }
            _ => unreachable!("{payload}"),
        }
        assert_no_private_windows_setup_terms(&payload.to_string());
    }
    Ok(())
}

#[test]
fn command_help_describes_policy_entrypoints() -> Result<()> {
    for (args, usage) in [
        (
            &["exec", "--help"][..],
            "Usage: runseal exec [--json|--events]",
        ),
        (
            &["explain-policy", "--help"][..],
            "Usage: runseal explain-policy [--policy <policy>]",
        ),
        (
            &["mcp", "--help"][..],
            "Usage: runseal mcp --stdio [--policy <policy>]",
        ),
    ] {
        let output = run_cli(args)?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.contains(usage));
        assert!(stdout.contains("--policy"));
        if args[0] != "mcp" {
            assert!(stdout.contains("--network"));
            assert!(stdout.contains("--cwd"));
        }
        assert_no_private_windows_setup_terms(&stdout);
    }
    Ok(())
}

#[test]
fn setup_rejects_invalid_cwd_before_windows_setup() -> Result<()> {
    let tmp = TempDir::new()?;
    let missing = tmp.path().join("missing").to_string_lossy().to_string();
    let file = tmp.path().join("not-a-directory");
    fs::write(&file, "not a directory")?;
    let file = file.to_string_lossy().to_string();

    for args in [
        vec!["setup", "windows-sandbox", "--cwd", &missing],
        vec!["setup", "windows-sandbox", "--cwd", &file],
        vec!["setup", "windows-sandbox", "--cwd", &missing, "--status"],
        vec!["setup", "windows-sandbox", "--cwd", &file, "--status"],
    ] {
        let output = run_cli(&args)?;

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("params.cwd must be an existing directory"),
            "{stderr}"
        );
        assert!(!stderr.contains("windows sandbox setup failed"), "{stderr}");
        assert_no_private_windows_setup_terms(&stderr);
    }
    Ok(())
}

#[test]
fn setup_json_reports_invalid_cwd_as_json_error() -> Result<()> {
    let tmp = TempDir::new()?;
    let missing = tmp.path().join("missing").to_string_lossy().to_string();

    for args in [
        vec!["setup", "windows-sandbox", "--json", "--cwd", &missing],
        vec![
            "setup",
            "windows-sandbox",
            "--json",
            "--cwd",
            &missing,
            "--status",
        ],
    ] {
        let output = run_cli(&args)?;

        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let payload = stdout_json(&output)?;
        assert_eq!(payload["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            payload["error"]["data"]["reason"]
                .as_str()
                .expect("reason")
                .contains("params.cwd must be an existing directory")
        );
        assert_no_private_windows_setup_terms(&payload.to_string());
    }
    Ok(())
}

#[test]
fn setup_json_reports_parse_errors_as_json_error() -> Result<()> {
    for args in [
        vec!["setup", "--json"],
        vec!["setup", "unknown", "--json"],
        vec!["setup", "windows-sandbox", "--json", "--cwd"],
        vec!["setup", "windows-sandbox", "--json", "--unknown"],
    ] {
        let output = run_cli(&args)?;

        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let payload = stdout_json(&output)?;
        assert_eq!(payload["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            payload["error"]["data"]["reason"]
                .as_str()
                .expect("reason")
                .contains("usage: runseal setup windows-sandbox")
        );
        assert_no_private_windows_setup_terms(&payload.to_string());
    }
    Ok(())
}

#[test]
fn version_reports_protocol_and_runtime_versions() -> Result<()> {
    let output = run_cli(&["--json", "version"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert!(payload["runseal_version"].as_str().is_some());
    assert_eq!(payload["protocol_version"], "runseal.protocol/v1");
    assert!(
        payload["policy_versions"]
            .as_array()
            .expect("policy_versions must be an array")
            .iter()
            .any(|version| version == "runseal.policy/v1")
    );
    Ok(())
}

#[test]
fn capabilities_cli_reports_active_backend_baseline() -> Result<()> {
    let output = run_cli(&["capabilities"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert_eq!(payload["backend"], expected_backend_name());
    assert_eq!(payload["backend_status"], expected_backend_status());
    assert!(payload["platform"].as_str().is_some());
    assert_eq!(
        payload["capability_statuses"],
        json!([
            "supported",
            "experimental",
            "unsupported",
            "unavailable",
            "requires_setup"
        ])
    );
    assert_eq!(payload["features"]["local_execution"], true);
    assert_eq!(
        payload["features"]["filesystem_policy"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["runtime_roots"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["runtime_environment"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["process_isolation"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["process_cleanup"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["direct_network_deny"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["managed_proxy"],
        expected_proxy_feature_reported()
    );
    assert_eq!(
        payload["features"]["network_proxy"],
        expected_proxy_feature_reported()
    );
    assert_eq!(
        payload["features"]["network_disabled"],
        expected_disabled_feature_reported()
    );
    assert_eq!(
        payload["features"]["policy_epoch"],
        expected_disabled_feature_reported()
    );
    for feature in [
        "filesystem_policy",
        "runtime_roots",
        "runtime_environment",
        "process_isolation",
        "process_cleanup",
        "direct_network_deny",
        "network_disabled",
        "policy_epoch",
    ] {
        assert_eq!(
            payload["feature_statuses"][feature],
            expected_disabled_feature_status()
        );
    }
    assert_eq!(
        payload["feature_statuses"]["network_proxy"],
        expected_proxy_feature_status()
    );
    assert_eq!(
        payload["feature_statuses"]["managed_proxy"],
        expected_proxy_feature_status()
    );
    assert_eq!(payload["features"]["setup_readiness"], true);
    assert_eq!(payload["features"]["stdin_bytes"], true);
    assert_eq!(payload["features"]["stdin_file"], true);
    assert_eq!(
        payload["features"]["resource_limits"],
        expected_resource_limits_supported()
    );
    assert_eq!(payload["features"]["audit_jsonl"], true);
    assert_eq!(payload["features"]["otel_export"], false);
    assert_eq!(payload["sandbox_levels"]["danger-full-access"], "supported");
    assert_eq!(
        payload["sandbox_levels"]["read-only"],
        expected_read_only_status()
    );
    assert_eq!(
        payload["sandbox_levels"]["workspace-write"],
        expected_workspace_write_status()
    );
    assert_eq!(
        payload["sandbox_levels"]["workspace-contained"],
        expected_workspace_contained_status()
    );
    assert_eq!(
        payload["network_modes"]["proxy"],
        expected_network_proxy_status()
    );
    assert_eq!(
        payload["network_modes"]["disabled"],
        expected_network_disabled_status()
    );
    assert_eq!(payload["network_modes"]["unmanaged"], "supported");
    if cfg!(windows) {
        assert_eq!(payload["setup_status"]["setup"], "windows-sandbox");
        assert!(payload["setup_status"]["next_action"].as_str().is_some());
    } else {
        assert!(payload.get("setup_status").is_none());
    }
    assert_portable_capability_probe_contract(&payload);
    assert_no_private_windows_setup_terms(&payload.to_string());
    Ok(())
}

#[test]
fn explain_policy_cli_materializes_standard_profile() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "explain-policy",
        "--policy",
        "workspace-write",
        "--network",
        "disabled",
        "--cwd",
        &cwd,
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert_eq!(payload["policy_id"], "workspace-write");
    assert_eq!(payload["sandbox_level"], "workspace-write");
    assert_eq!(payload["network"]["mode"], "disabled");
    assert_eq!(payload["environment"]["inherit"], "minimal");
    assert_eq!(payload["backend_requirement"], "sandbox-backend");
    assert_eq!(
        payload["support"],
        expected_status(expected_windows_sandbox_supported())
    );
    if cfg!(windows) {
        assert_eq!(payload["setup_status"]["setup"], "windows-sandbox");
        assert!(payload["setup_status"]["can_run_setup_now"].is_boolean());
    } else {
        assert!(payload.get("setup_status").is_none());
    }
    assert_eq!(
        payload["required_backend_features"],
        serde_json::json!([
            "filesystem_policy",
            "runtime_roots",
            "runtime_environment",
            "process_isolation",
            "process_cleanup",
            "direct_network_deny",
            "network_disabled"
        ])
    );
    let expected_missing_features = if expected_windows_sandbox_supported() {
        serde_json::json!([])
    } else {
        payload["required_backend_features"].clone()
    };
    assert_eq!(payload["missing_features"], expected_missing_features);
    assert_eq!(
        payload["canonical_policy"]["filesystem"]["protect_vcs"],
        true
    );
    assert!(
        payload["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert_no_private_windows_setup_terms(&payload.to_string());
    Ok(())
}

#[test]
fn explain_policy_cli_normalizes_relative_cwd() -> Result<()> {
    let output = run_cli(&[
        "explain-policy",
        "--policy",
        "workspace-write",
        "--cwd",
        ".",
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    let cwd = std::env::current_dir()?.to_string_lossy().to_string();
    assert_eq!(payload["canonical_policy"]["filesystem"]["write"][0], cwd);
    assert_ne!(payload["canonical_policy"]["filesystem"]["write"][0], ".");
    Ok(())
}

#[test]
fn exec_events_stream_uses_execution_vocabulary() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "exec",
        "--events",
        "--policy",
        "danger-full-access",
        "--cwd",
        &cwd,
        "--",
        python_bin(),
        "-c",
        "print('hello from runseal')",
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = stdout_json_lines(&output)?;
    let event_types: Vec<_> = events
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();

    assert!(event_types.contains(&"execution.requested"));
    assert!(event_types.contains(&"policy.resolved"));
    assert!(event_types.contains(&"policy.allowed"));
    assert!(event_types.contains(&"execution.started"));
    assert!(event_types.contains(&"execution.stdout"));
    assert!(event_types.contains(&"execution.resource.sample"));
    assert!(event_types.contains(&"execution.finished"));
    for event in &events {
        assert_event_envelope(event)?;
    }
    let first_event = events
        .first()
        .context("exec --events must emit at least one event")?;
    for event in &events {
        assert_eq!(event["execution_id"], first_event["execution_id"]);
        assert_eq!(event["policy_hash"], first_event["policy_hash"]);
        assert_eq!(event["policy_epoch"], first_event["policy_epoch"]);
        assert_eq!(event["policy_epoch"], event["policy_hash"]);
    }
    let stdout_event = events
        .iter()
        .find(|event| event["type"] == "execution.stdout")
        .context("execution.stdout event must exist")?;
    assert!(decode_stream_event(stdout_event)?.contains("hello from runseal"));
    assert!(
        events
            .iter()
            .filter(|event| event["type"]
                .as_str()
                .unwrap_or_default()
                .starts_with("execution."))
            .all(|event| event.get("execution_id").is_some())
    );
    assert!(events.iter().all(|event| event.get("process_id").is_none()));
    Ok(())
}

#[test]
fn exec_events_reports_policy_errors_as_json_line() -> Result<()> {
    let output = run_cli(&[
        "exec",
        "--events",
        "--policy",
        "workspace-proxy",
        "--",
        python_bin(),
        "-c",
        "print('must not run')",
    ])?;

    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let messages = stdout_json_lines(&output)?;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["error"]["data"]["code"], "POLICY_INVALID");
    assert!(
        messages[0]["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("unknown policy profile"),
        "{}",
        messages[0]
    );
    Ok(())
}

#[test]
fn exec_json_returns_execution_result() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "exec",
        "--json",
        "--policy",
        "danger-full-access",
        "--cwd",
        &cwd,
        "--",
        python_bin(),
        "-c",
        "print(42)",
    ])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output)?;
    assert_eq!(payload["status"], "finished");
    assert_eq!(payload["exit_code"], 0);
    assert_eq!(payload["signal"], Value::Null);
    assert_rfc3339_timestamp(&payload["started_at"])?;
    assert_rfc3339_timestamp(&payload["finished_at"])?;
    assert!(
        payload["execution_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("exec_")
    );
    let session_id = payload["session_id"]
        .as_str()
        .expect("ExecutionResult must include session_id");
    let seal_id = payload["seal_id"]
        .as_str()
        .expect("ExecutionResult must include seal_id");
    assert!(session_id.starts_with("sess_"));
    assert!(seal_id.starts_with("seal_"));
    assert_eq!(payload["policy_id"], "danger-full-access");
    assert_eq!(payload["sandbox"]["enforced"], false);
    assert_eq!(payload["platform_plan"]["enforcement"], "local-execution");
    assert_eq!(
        payload["platform_plan"]["backend"]["name"],
        expected_backend_name()
    );
    assert_eq!(payload["platform_plan"]["filesystem"]["write"][0], "*");
    assert!(
        payload["policy_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:")
    );
    assert_eq!(payload["policy_epoch"], payload["policy_hash"]);
    let audit_path = payload["audit_path"]
        .as_str()
        .expect("ExecutionResult must include audit_path");
    assert_eq!(audit_path, format!(".runseal/audit/{session_id}.jsonl"));
    let audit_file = tmp.path().join(audit_path);
    let audit_jsonl = fs::read_to_string(&audit_file)
        .with_context(|| format!("audit file must exist at {}", audit_file.display()))?;
    let audit_events: Vec<Value> = audit_jsonl
        .lines()
        .map(|line| serde_json::from_str(line).context("audit line must be JSON"))
        .collect::<Result<_>>()?;
    let audit_event_types: Vec<_> = audit_events
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();
    assert!(audit_event_types.contains(&"execution.started"));
    assert!(audit_event_types.contains(&"execution.stdout"));
    assert!(audit_event_types.contains(&"execution.finished"));
    for event in &audit_events {
        assert_event_envelope(event)?;
        assert_eq!(event["session_id"], session_id);
        assert_eq!(event["seal_id"], seal_id);
        assert_eq!(event["policy_epoch"], payload["policy_epoch"]);
    }
    let audit_stdout = audit_events
        .iter()
        .find(|event| event["type"] == "execution.stdout")
        .context("execution.stdout audit event must exist")?;
    assert_eq!(audit_stdout["encoding"], "base64");
    assert_eq!(audit_stdout["stream_offset"], 0);
    assert!(audit_stdout["bytes"].as_u64().unwrap_or_default() > 0);
    assert!(audit_stdout.get("data").is_none());
    assert!(audit_stdout.get("text").is_none());
    assert!(payload["stdout_bytes"].as_u64().unwrap_or_default() > 0);
    assert_eq!(payload["output_truncated"], false);
    assert!(payload["resource_usage"]["duration_ms"].as_u64().is_some());
    Ok(())
}

#[test]
fn sandboxed_exec_cli_uses_backend_or_reports_unavailable() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let mut args = vec![
        "exec",
        "--json",
        "--policy",
        "read-only",
        "--cwd",
        &cwd,
        "--",
    ];
    if cfg!(windows) {
        args.extend(["cmd", "/d", "/c", "echo sandbox-ok"]);
    } else if cfg!(any(target_os = "linux", target_os = "macos")) {
        args.extend([python_bin(), "-c", "print('sandbox-ok')"]);
    } else {
        args.extend([python_bin(), "-c", "print('must not run')"]);
    }
    let output = run_cli(&args)?;

    if cfg!(windows) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_no_private_windows_setup_terms(&stderr);
        if output.status.success() {
            let payload = stdout_json(&output)?;
            assert_eq!(payload["sandbox"]["enforced"], true);
            assert_eq!(payload["platform_plan"]["enforcement"], "windows-sandbox");
            assert_no_private_windows_setup_terms(&payload.to_string());
            let audit_path = payload["audit_path"]
                .as_str()
                .context("ExecutionResult must include audit_path")?;
            let audit_jsonl = fs::read_to_string(tmp.path().join(audit_path))?;
            assert_no_private_windows_setup_terms(&audit_jsonl);
        } else {
            assert!(stderr.is_empty(), "{stderr}");
            let payload = stdout_json(&output)?;
            assert_eq!(payload["error"]["data"]["code"], "BACKEND_UNAVAILABLE");
            assert!(
                payload["error"]["data"]["reason"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("windows sandbox setup unavailable"),
                "{payload}"
            );
            assert_eq!(
                payload["error"]["data"]["setup_status"]["setup"],
                "windows-sandbox"
            );
            assert_no_private_windows_setup_terms(&payload.to_string());
            let audit_dir = tmp.path().join(".runseal").join("audit");
            let audit_files = fs::read_dir(&audit_dir)
                .with_context(|| format!("audit dir must exist at {}", audit_dir.display()))?
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(audit_files.len(), 1);
            let audit_jsonl = fs::read_to_string(audit_files[0].path())?;
            assert_no_private_windows_setup_terms(&audit_jsonl);
        }
        let runtime_dir = tmp.path().join(".runseal").join("runtime");
        if runtime_dir.exists() {
            let runtime_entries = fs::read_dir(&runtime_dir)
                .with_context(|| {
                    format!("runtime dir must be readable at {}", runtime_dir.display())
                })?
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(runtime_entries.len(), 0);
        }
        return Ok(());
    }

    if cfg!(any(target_os = "linux", target_os = "macos")) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.is_empty(), "{stderr}");
        let payload = stdout_json(&output)?;
        let expected_enforcement = if cfg!(target_os = "macos") {
            "macos-experimental"
        } else {
            "linux-experimental"
        };
        if output.status.success() {
            assert_eq!(payload["status"], "finished");
            assert_eq!(payload["exit_code"], 0);
            assert_eq!(payload["sandbox"]["enforced"], true);
            assert_eq!(
                payload["platform_plan"]["enforcement"],
                expected_enforcement
            );
        } else {
            assert!(
                matches!(
                    payload["error"]["data"]["code"].as_str(),
                    Some("BACKEND_UNAVAILABLE" | "EXECUTION_FAILED_TO_START")
                ),
                "{payload}"
            );
            assert_eq!(
                payload["error"]["data"]["backend"]["name"],
                expected_backend_name()
            );
            assert_eq!(
                payload["error"]["data"]["backend"]["status"],
                expected_backend_status()
            );
            assert_eq!(
                payload["error"]["data"]["backend"]["platform"],
                expected_backend_platform()
            );
        }
        assert_no_private_windows_setup_terms(&payload.to_string());
        return Ok(());
    }

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.is_empty(), "{stderr}");
    let payload = stdout_json(&output)?;
    assert_eq!(
        payload["error"]["data"]["code"],
        "BACKEND_CAPABILITY_MISSING"
    );
    assert_eq!(payload["error"]["data"]["support"], "unsupported");
    assert_eq!(
        payload["error"]["data"]["backend"]["name"],
        expected_backend_name()
    );
    assert_eq!(
        payload["error"]["data"]["backend"]["status"],
        expected_backend_status()
    );
    assert_eq!(
        payload["error"]["data"]["backend"]["platform"],
        expected_backend_platform()
    );
    assert_eq!(
        payload["error"]["data"]["missing_features"],
        json!([
            "filesystem_policy",
            "runtime_roots",
            "runtime_environment",
            "process_isolation",
            "process_cleanup",
            "direct_network_deny",
            "network_disabled"
        ])
    );
    assert!(
        payload["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot enforce policy read-only"),
        "{payload}"
    );
    assert_portable_fail_closed_preview(&payload["error"]["data"]["platform_plan"]);
    assert_no_private_windows_setup_terms(&payload.to_string());

    let audit_dir = tmp.path().join(".runseal").join("audit");
    let audit_files = fs::read_dir(&audit_dir)
        .with_context(|| format!("audit dir must exist at {}", audit_dir.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(audit_files.len(), 1);
    let audit_jsonl = fs::read_to_string(audit_files[0].path())?;
    assert_no_private_windows_setup_terms(&audit_jsonl);
    Ok(())
}

#[test]
fn exec_cli_enforces_timeout_ms() -> Result<()> {
    let tmp = TempDir::new()?;
    let cwd = tmp.path().to_string_lossy().to_string();
    let output = run_cli(&[
        "exec",
        "--json",
        "--policy",
        "danger-full-access",
        "--timeout-ms",
        "10",
        "--cwd",
        &cwd,
        "--",
        python_bin(),
        "-c",
        "import time; time.sleep(1)",
    ])?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.is_empty(), "{stderr}");
    let payload = stdout_json(&output)?;
    assert!(
        payload["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("execution timed out"),
        "{payload}"
    );
    Ok(())
}

#[test]
fn exec_cli_rejects_invalid_timeout_ms() -> Result<()> {
    let output = run_cli(&[
        "exec",
        "--policy",
        "danger-full-access",
        "--timeout-ms",
        "soon",
        "--",
        python_bin(),
        "-c",
        "print('must not run')",
    ])?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timeout must be an integer in milliseconds"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn exec_machine_readable_modes_report_parse_errors_as_json() -> Result<()> {
    for mode in ["--json", "--events"] {
        let output = run_cli(&[
            "exec",
            mode,
            "--policy",
            "danger-full-access",
            "--timeout-ms",
            "soon",
            "--",
            python_bin(),
            "-c",
            "print('must not run')",
        ])?;

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.is_empty(), "{stderr}");
        let messages = stdout_json_lines(&output)?;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["error"]["data"]["code"], "INVALID_REQUEST");
        assert!(
            messages[0]["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("timeout must be an integer in milliseconds"),
            "{}",
            messages[0]
        );
    }
    Ok(())
}
