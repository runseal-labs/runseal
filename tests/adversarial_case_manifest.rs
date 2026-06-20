use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const CLASSES: &[&str] = &[
    "filesystem",
    "runtime",
    "process",
    "network",
    "policy",
    "execution_injection",
    "audit",
];
const PLATFORMS: &[&str] = &["windows", "macos", "linux", "other"];
const BACKEND_STATUS: &[&str] = &[
    "reference",
    "experimental",
    "future-community",
    "local-baseline",
    "scaffold",
];
const SANDBOX_LEVELS: &[&str] = &[
    "read-only",
    "workspace-contained",
    "workspace-write",
    "danger-full-access",
    "malformed",
];
const NETWORK_MODES: &[&str] = &["disabled", "proxy", "malformed"];
const EXPECTED_RESULTS: &[&str] = &[
    "allow_no_side_effect_outside_policy",
    "deny",
    "fail_closed",
    "deny_or_fail_closed",
    "backend_unavailable",
    "timeout",
    "cancelled",
    "audit_redacted",
    "event_emitted",
    "policy_rejected",
];
const SEVERITIES: &[&str] = &["S0", "S1", "S2", "S3", "S4"];
const PROMOTION_SEVERITIES: &[&str] = &["S0", "S1"];
const CAPABILITIES: &[&str] = &[
    "filesystem_policy",
    "runtime_roots",
    "runtime_environment",
    "process_isolation",
    "process_cleanup",
    "direct_network_deny",
    "network_disabled",
    "network_proxy",
    "managed_proxy",
    "policy_epoch",
    "setup_readiness",
    "stdin_bytes",
    "stdin_file",
    "audit_jsonl",
    "resource_limits",
];
const FIXTURE_KINDS: &[&str] = &[
    "file",
    "directory",
    "symlink",
    "hardlink",
    "junction",
    "readonly_file",
    "executable_script",
    "environment",
    "preexisting_runtime_root",
    "background_process",
    "network_listener",
    "malformed_request",
];
const SIDE_EFFECTS: &[&str] = &[
    "file_exists",
    "file_not_exists",
    "file_content_equals",
    "file_content_not_contains",
    "path_not_accessible",
    "path_not_modified",
    "process_not_running",
    "network_connection_absent",
    "audit_contains_event_type",
    "audit_not_contains_secret",
    "event_contains_type",
    "event_not_contains_private_detail",
    "policy_hash_consistent",
    "policy_epoch_consistent",
];
const PRIVATE_TERMS: &[&str] = &["sid", "acl", "wfp", "seatbelt", "seccomp", "landlock"];
const CASE_FIELDS: &[&str] = &[
    "schema_version",
    "case_id",
    "title",
    "primary_class",
    "secondary_classes",
    "capabilities_under_test",
    "platforms",
    "backend_status",
    "sandbox_level",
    "network_mode",
    "request",
    "oracle",
    "risk_summary",
    "references",
    "fixtures",
    "preconditions",
    "setup_steps",
    "inspection_steps",
    "cleanup_steps",
    "timeout_ms",
    "skip_if",
    "xfail_if",
    "negative_side_effects",
    "public_report_labels",
];
const ORACLE_FIELDS: &[&str] = &[
    "expected_result",
    "max_severity",
    "forbidden_side_effects",
    "audit",
    "events",
];
const ORACLE_FLAG_FIELDS: &[&str] = &["required"];
const REQUEST_FIELDS: &[&str] = &[
    "method",
    "command",
    "policy",
    "timeout_ms",
    "cancel_after_ms",
    "stdin",
    "env",
    "metadata",
    "interactive",
    "network",
    "policy_epoch",
    "execution_id",
    "audit_path",
];
const REQUEST_METHODS: &[&str] = &["execute", "getAuditEvents"];
const STDIN_FIELDS: &[&str] = &["mode", "path", "encoding", "data"];
const STDIN_MODES: &[&str] = &["empty", "file", "bytes"];
const FIXTURE_FIELDS: &[&str] = &["kind", "path", "target", "name", "value", "command", "body"];
const RESULT_FIELDS: &[&str] = &[
    "schema_version",
    "case_id",
    "backend_name",
    "backend_status",
    "platform",
    "capabilities_under_test",
    "sandbox_level",
    "network_mode",
    "expected_result",
    "observed_result",
    "severity",
    "passed",
    "skipped",
    "skip_reason",
    "policy_hash_present",
    "policy_epoch_present",
    "audit_present",
    "events_present",
    "public_safe_output",
    "status",
];
const RESULT_STATUS: &[&str] = &[
    "passed",
    "failed",
    "skipped",
    "xfailed",
    "invalid_case",
    "unsupported_fixture",
    "harness_error",
];
const REPORT_LABELS: &[&str] = &[
    "protocol_contract",
    "cli_contract",
    "filesystem_conformance",
    "network_conformance",
    "runtime_conformance",
    "process_conformance",
    "adversarial_case_manifest",
];
const REQUIRED_INITIAL_CASES: &[&str] = &[
    "adv.filesystem.parent-traversal.v1",
    "adv.filesystem.symlink-parent-traversal.v1",
    "adv.filesystem.preexisting-symlinked-runtime-root.v1",
    "adv.filesystem.protected-subpath-write.v1",
    "adv.filesystem.external-write-from-workspace-write.v1",
    "adv.filesystem.external-read-from-workspace-contained.v1",
    "adv.runtime.precreated-runtime-root.v1",
    "adv.runtime.runtime-marker-spoof.v1",
    "adv.runtime.execution-id-reuse.v1",
    "adv.runtime.cleanup-partial-failure.v1",
    "adv.runtime.cross-execution-contamination.v1",
    "adv.process.orphan-child-after-cancel.v1",
    "adv.process.background-daemon-after-timeout.v1",
    "adv.process.shell-trampoline-child.v1",
    "adv.process.interactive-disabled.v1",
    "adv.network.direct-egress-disabled.v1",
    "adv.network.proxy-env-override.v1",
    "adv.network.proxy-credential-redaction.v1",
    "adv.network.dns-leak-disabled.v1",
    "adv.network.loopback-tunnel-bypass.v1",
    "adv.policy.unknown-top-level-field.v1",
    "adv.policy.unsupported-nonempty-section.v1",
    "adv.policy.network-override-hash-drift.v1",
    "adv.policy.stale-policy-epoch.v1",
    "adv.policy.malformed-json.v1",
    "adv.execution_injection.argv-shell-metacharacters.v1",
    "adv.execution_injection.stdin-file-outside-cwd.v1",
    "adv.execution_injection.invalid-base64-stdin.v1",
    "adv.execution_injection.secret-env-key.v1",
    "adv.execution_injection.program-resolution-confusion.v1",
    "adv.audit.secret-metadata-redaction.v1",
    "adv.audit.audit-path-traversal.v1",
    "adv.audit.missing-deny-event.v1",
    "adv.audit.policy-hash-consistency.v1",
    "adv.audit.backend-private-redaction.v1",
];

#[test]
fn adversarial_case_manifests_match_rfc0016_shape() -> Result<()> {
    let mut case_ids = HashSet::new();
    for path in manifest_paths()? {
        let manifest = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        assert_public_safe(&manifest, &path)?;
        let cases: Vec<Value> = serde_json::from_str(&manifest)
            .with_context(|| format!("manifest must be a JSON array: {}", path.display()))?;
        for case in cases {
            validate_case(&case, &path, &mut case_ids)?;
        }
    }
    for required in REQUIRED_INITIAL_CASES {
        if !case_ids.contains(*required) {
            bail!("missing RFC-0016 initial adversarial case {required}");
        }
    }
    Ok(())
}

#[test]
fn adversarial_result_gate_rejects_non_promotable_results() {
    assert!(promotion_gate_allows(
        "passed", "S0", "S0", true, false, true
    ));
    assert!(promotion_gate_allows(
        "passed", "S1", "S1", true, false, true
    ));
    assert!(!promotion_gate_allows(
        "passed", "S2", "S1", true, false, true
    ));
    assert!(!promotion_gate_allows(
        "failed", "S0", "S1", false, false, true
    ));
    assert!(!promotion_gate_allows(
        "skipped", "S0", "S1", true, true, true
    ));
    assert!(!promotion_gate_allows(
        "xfailed", "S0", "S1", true, false, true
    ));
    assert!(!promotion_gate_allows(
        "passed", "S0", "S0", true, false, false
    ));
    assert!(!promotion_gate_allows(
        "invalid_case",
        "S0",
        "S1",
        true,
        false,
        true
    ));
    assert!(!promotion_gate_allows(
        "unsupported_fixture",
        "S0",
        "S1",
        true,
        false,
        true
    ));
    assert!(!promotion_gate_allows(
        "harness_error",
        "S0",
        "S1",
        true,
        false,
        true
    ));
}

#[test]
fn adversarial_result_schema_requires_public_skip_reason() -> Result<()> {
    let mut result = json!({
        "schema_version": "runseal.adversarial-result/v1",
        "case_id": "adv.audit.audit-path-traversal.v1",
        "backend_name": "runseal-windows-reference",
        "backend_status": "reference",
        "platform": "windows",
        "capabilities_under_test": ["audit_jsonl"],
        "sandbox_level": "danger-full-access",
        "network_mode": "disabled",
        "expected_result": "deny",
        "observed_result": "deny",
        "severity": "S0",
        "passed": true,
        "skipped": false,
        "skip_reason": null,
        "policy_hash_present": true,
        "policy_epoch_present": true,
        "audit_present": true,
        "events_present": true,
        "public_safe_output": true,
        "status": "passed"
    });
    validate_result(&result)?;

    result["backend_name"] = json!("   ");
    assert!(validate_result(&result).is_err());
    result["backend_name"] = json!("runseal-windows-reference");

    result["skipped"] = json!(true);
    result["status"] = json!("skipped");
    result["passed"] = json!(false);
    assert!(validate_result(&result).is_err());
    result["skip_reason"] = json!("unsupported fixture kind");
    validate_result(&result)?;

    result["status"] = json!("unsupported_fixture");
    validate_result(&result)?;
    result["skipped"] = json!(false);
    assert!(validate_result(&result).is_err());
    result["skipped"] = json!(true);

    result["status"] = json!("failed");
    assert!(validate_result(&result).is_err());
    result["status"] = json!("skipped");
    result["skipped"] = json!(false);
    assert!(validate_result(&result).is_err());
    result["skipped"] = json!(true);

    result["skip_reason"] = json!("");
    assert!(validate_result(&result).is_err());
    result["skip_reason"] = json!("   ");
    assert!(validate_result(&result).is_err());
    result["skip_reason"] = json!("unsupported fixture kind");

    result["skipped"] = json!(false);
    result["status"] = json!("failed");
    result["skip_reason"] = json!("not actually skipped");
    assert!(validate_result(&result).is_err());
    result["skip_reason"] = Value::Null;
    result["status"] = json!("skipped");
    result["skipped"] = json!(true);

    result["skip_reason"] = json!("mentions ACL detail");
    assert!(validate_result(&result).is_err());

    result["skip_reason"] = Value::Null;
    result["skipped"] = json!(false);
    result["status"] = json!("passed");
    result["passed"] = json!(false);
    assert!(validate_result(&result).is_err());

    result["passed"] = json!(true);
    result["status"] = json!("failed");
    assert!(validate_result(&result).is_err());

    result["status"] = json!("passed");
    result["public_safe_output"] = json!(false);
    assert!(validate_result(&result).is_err());
    result["public_safe_output"] = json!(true);

    result["passed"] = json!(false);
    result["status"] = json!("xfailed");
    result["backend_status"] = json!("reference");
    assert!(validate_result(&result).is_err());
    result["backend_status"] = json!("experimental");
    validate_result(&result)?;

    result["case_id"] = json!("adv.audit.v1");
    assert!(validate_result(&result).is_err());
    result["case_id"] = json!("adv.unknown.case.v1");
    assert!(validate_result(&result).is_err());
    result["case_id"] = json!("adv.audit.audit-path-traversal.v1");

    result["capabilities_under_test"] = json!(["audit_jsonl", "audit_jsonl"]);
    assert!(validate_result(&result).is_err());
    Ok(())
}

fn manifest_paths() -> Result<Vec<PathBuf>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("adversarial/cases");
    let mut paths = fs::read_dir(&root)
        .with_context(|| format!("failed to read {}", root.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    });
    paths.sort();
    if paths.is_empty() {
        bail!(
            "no RFC-0016 adversarial case manifests found in {}",
            root.display()
        );
    }
    Ok(paths)
}

fn validate_case(case: &Value, path: &Path, case_ids: &mut HashSet<String>) -> Result<()> {
    assert_allowed_fields(case, "case", CASE_FIELDS, path)?;
    let case_id = required_string(case, "case_id", path)?;
    if !case_ids.insert(case_id.to_string()) {
        bail!("duplicate case_id {case_id} in {}", path.display());
    }
    assert_eq!(
        required_string(case, "schema_version", path)?,
        "runseal.adversarial-case/v1"
    );
    let primary_class = required_string(case, "primary_class", path)?;
    assert_member(primary_class, CLASSES, path)?;
    let case_class = case_id_class(case_id)?;
    if case_class != primary_class {
        bail!("case_id class {case_class} must match primary_class {primary_class}");
    }
    if let Some(secondary_classes) = case.get("secondary_classes") {
        assert_array_members(secondary_classes, "case.secondary_classes", CLASSES, path)?;
        for secondary_class in secondary_classes
            .as_array()
            .context("case.secondary_classes must be an array")?
        {
            if secondary_class == primary_class {
                bail!("case.secondary_classes must not repeat primary_class {primary_class}");
            }
        }
    }
    if let Some(labels) = case.get("public_report_labels") {
        assert_array_members(labels, "case.public_report_labels", REPORT_LABELS, path)?;
    }
    assert_non_empty_string(case, "title", path)?;
    assert_members(case, "capabilities_under_test", CAPABILITIES, path)?;
    assert_members(case, "platforms", PLATFORMS, path)?;
    assert_members(case, "backend_status", BACKEND_STATUS, path)?;
    assert_member(
        required_string(case, "sandbox_level", path)?,
        SANDBOX_LEVELS,
        path,
    )?;
    assert_member(
        required_string(case, "network_mode", path)?,
        NETWORK_MODES,
        path,
    )?;
    let malformed_sandbox = required_string(case, "sandbox_level", path)? == "malformed";
    let malformed_network = required_string(case, "network_mode", path)? == "malformed";
    if (malformed_sandbox || malformed_network) && primary_class != "policy" {
        bail!("malformed sandbox/network values are only valid for policy cases");
    }
    let request = case
        .get("request")
        .and_then(Value::as_object)
        .context("case.request must be an object")?;
    let request = Value::Object(request.clone());
    assert_allowed_fields(&request, "case.request", REQUEST_FIELDS, path)?;
    assert_member(
        required_string(&request, "method", path)?,
        REQUEST_METHODS,
        path,
    )?;
    let method = required_string(&request, "method", path)?;
    if method == "execute" {
        match request
            .get("command")
            .context("case.request.command must be present")?
        {
            Value::Array(command) => {
                if command.is_empty() {
                    bail!("case.request.command must not be empty");
                }
                for arg in command {
                    assert_string_value(arg, "case.request.command[]", path)?;
                }
            }
            Value::String(command)
                if primary_class == "execution_injection" && !command.trim().is_empty() => {}
            _ => bail!(
                "case.request.command must be an argv array outside execution_injection cases"
            ),
        }
    } else if request.get("command").is_some() {
        bail!("case.request.command is only valid for execute requests");
    }
    if let Some(stdin) = request.get("stdin") {
        if method != "execute" {
            bail!("case.request.stdin is only valid for execute requests");
        }
        validate_stdin(stdin, path)?;
    }
    for field in ["env", "metadata"] {
        if let Some(values) = request.get(field) {
            if method != "execute" {
                bail!("case.request.{field} is only valid for execute requests");
            }
            validate_string_map(values, &format!("case.request.{field}"), path)?;
        }
    }
    if let Some(interactive) = request.get("interactive") {
        if method != "execute" {
            bail!("case.request.interactive is only valid for execute requests");
        }
        if !interactive.is_boolean() {
            bail!("case.request.interactive must be a boolean");
        }
    }
    if let Some(timeout_ms) = request.get("timeout_ms") {
        assert_positive_u64(timeout_ms, "case.request.timeout_ms", path)?;
    }
    if let Some(cancel_after_ms) = request.get("cancel_after_ms") {
        assert_positive_u64(cancel_after_ms, "case.request.cancel_after_ms", path)?;
    }
    if let Some(timeout_ms) = case.get("timeout_ms") {
        assert_positive_u64(timeout_ms, "case.timeout_ms", path)?;
    }
    if let Some(fixtures) = case.get("fixtures") {
        validate_fixtures(fixtures, path)?;
    }
    let oracle = case
        .get("oracle")
        .and_then(Value::as_object)
        .context("case.oracle must be an object")?;
    assert_allowed_fields(
        &Value::Object(oracle.clone()),
        "case.oracle",
        ORACLE_FIELDS,
        path,
    )?;
    assert_member(
        oracle
            .get("expected_result")
            .and_then(Value::as_str)
            .context("case.oracle.expected_result must be a string")?,
        EXPECTED_RESULTS,
        path,
    )?;
    assert_member(
        oracle
            .get("max_severity")
            .and_then(Value::as_str)
            .context("case.oracle.max_severity must be a string")?,
        SEVERITIES,
        path,
    )?;
    assert_member(
        oracle
            .get("max_severity")
            .and_then(Value::as_str)
            .context("case.oracle.max_severity must be a string")?,
        PROMOTION_SEVERITIES,
        path,
    )?;
    if let Some(side_effects) = oracle.get("forbidden_side_effects") {
        assert_array_members(
            side_effects,
            "case.oracle.forbidden_side_effects",
            SIDE_EFFECTS,
            path,
        )?;
    }
    validate_oracle_flag(oracle.get("audit"), "case.oracle.audit", path)?;
    validate_oracle_flag(oracle.get("events"), "case.oracle.events", path)?;
    Ok(())
}

fn required_string<'a>(case: &'a Value, field: &str, path: &Path) -> Result<&'a str> {
    case.get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("case.{field} must be a string in {}", path.display()))
}

fn case_id_class(case_id: &str) -> Result<&str> {
    let case_id_parts = case_id.split('.').collect::<Vec<_>>();
    if case_id_parts.len() != 4
        || case_id_parts[0] != "adv"
        || case_id_parts[2].is_empty()
        || case_id_parts[3] != "v1"
    {
        bail!("case_id must use adv.<class>.<name>.v1 format: {case_id}");
    }
    Ok(case_id_parts[1])
}

fn assert_non_empty_string(case: &Value, field: &str, path: &Path) -> Result<()> {
    if required_string(case, field, path)?.trim().is_empty() {
        bail!("case.{field} must not be empty in {}", path.display());
    }
    Ok(())
}

fn assert_members(case: &Value, field: &str, allowed: &[&str], path: &Path) -> Result<()> {
    let values = case
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("case.{field} must be an array in {}", path.display()))?;
    if values.is_empty() {
        bail!("case.{field} must not be empty in {}", path.display());
    }
    let mut seen = HashSet::new();
    for value in values {
        let value = value
            .as_str()
            .with_context(|| format!("case.{field} entries must be strings"))?;
        if !seen.insert(value) {
            bail!("case.{field} must not contain duplicate value {value}");
        }
        assert_member(value, allowed, path)?;
    }
    Ok(())
}

fn assert_array_members(values: &Value, field: &str, allowed: &[&str], path: &Path) -> Result<()> {
    let values = values
        .as_array()
        .with_context(|| format!("{field} must be an array in {}", path.display()))?;
    let mut seen = HashSet::new();
    for value in values {
        let value = value
            .as_str()
            .with_context(|| format!("{field} entries must be strings"))?;
        if !seen.insert(value) {
            bail!("{field} must not contain duplicate value {value}");
        }
        assert_member(value, allowed, path)?;
    }
    Ok(())
}

fn validate_fixtures(fixtures: &Value, path: &Path) -> Result<()> {
    let fixtures = fixtures
        .as_array()
        .with_context(|| format!("case.fixtures must be an array in {}", path.display()))?;
    for fixture in fixtures {
        assert_allowed_fields(fixture, "case.fixtures[]", FIXTURE_FIELDS, path)?;
        let kind = fixture
            .get("kind")
            .and_then(Value::as_str)
            .context("case.fixtures entries must include kind")?;
        assert_member(kind, FIXTURE_KINDS, path)?;
        for field in ["path", "target", "name", "value", "command", "body"] {
            if let Some(value) = fixture.get(field) {
                assert_string_value(value, &format!("case.fixtures[].{field}"), path)?;
            }
        }
    }
    Ok(())
}

fn validate_stdin(stdin: &Value, path: &Path) -> Result<()> {
    assert_allowed_fields(stdin, "case.request.stdin", STDIN_FIELDS, path)?;
    let mode = required_string(stdin, "mode", path)?;
    assert_member(mode, STDIN_MODES, path)?;
    match mode {
        "file" => assert_string_value(
            stdin
                .get("path")
                .context("case.request.stdin.path must be present")?,
            "case.request.stdin.path",
            path,
        )?,
        "bytes" => {
            let encoding = stdin
                .get("encoding")
                .and_then(Value::as_str)
                .context("case.request.stdin.encoding must be a string")?;
            if encoding != "base64" {
                bail!("case.request.stdin.encoding must be base64");
            }
            assert_string_value(
                stdin
                    .get("data")
                    .context("case.request.stdin.data must be present")?,
                "case.request.stdin.data",
                path,
            )?;
        }
        "empty" => {}
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_string_map(value: &Value, label: &str, path: &Path) -> Result<()> {
    let object = value
        .as_object()
        .with_context(|| format!("{label} must be an object in {}", path.display()))?;
    for (key, value) in object {
        if key.trim().is_empty() {
            bail!("{label} keys must not be empty");
        }
        assert_string_value(value, &format!("{label}.{key}"), path)?;
    }
    Ok(())
}

fn assert_string_value(value: &Value, label: &str, path: &Path) -> Result<()> {
    let value = value
        .as_str()
        .with_context(|| format!("{label} must be a string in {}", path.display()))?;
    if value.is_empty() {
        bail!("{label} must not be empty in {}", path.display());
    }
    Ok(())
}

fn assert_positive_u64(value: &Value, label: &str, path: &Path) -> Result<()> {
    let value = value
        .as_u64()
        .with_context(|| format!("{label} must be an integer in {}", path.display()))?;
    if value == 0 {
        bail!("{label} must be greater than zero in {}", path.display());
    }
    Ok(())
}

fn validate_oracle_flag(value: Option<&Value>, label: &str, path: &Path) -> Result<()> {
    let value = value.with_context(|| format!("{label} must be present in {}", path.display()))?;
    assert_allowed_fields(value, label, ORACLE_FLAG_FIELDS, path)?;
    value
        .get("required")
        .and_then(Value::as_bool)
        .with_context(|| format!("{label}.required must be a boolean in {}", path.display()))?;
    Ok(())
}

fn validate_result(result: &Value) -> Result<()> {
    let path = Path::new("adversarial-result");
    assert_public_safe(&serde_json::to_string(result)?, path)?;
    assert_allowed_fields(result, "result", RESULT_FIELDS, path)?;
    assert_eq!(
        required_string(result, "schema_version", path)?,
        "runseal.adversarial-result/v1"
    );
    assert_member(
        case_id_class(required_string(result, "case_id", path)?)?,
        CLASSES,
        path,
    )?;
    assert_non_empty_string(result, "backend_name", path)?;
    assert_member(
        required_string(result, "backend_status", path)?,
        BACKEND_STATUS,
        path,
    )?;
    assert_member(required_string(result, "platform", path)?, PLATFORMS, path)?;
    assert_members(result, "capabilities_under_test", CAPABILITIES, path)?;
    assert_member(
        required_string(result, "sandbox_level", path)?,
        SANDBOX_LEVELS,
        path,
    )?;
    assert_member(
        required_string(result, "network_mode", path)?,
        NETWORK_MODES,
        path,
    )?;
    assert_member(
        required_string(result, "expected_result", path)?,
        EXPECTED_RESULTS,
        path,
    )?;
    assert_member(
        required_string(result, "observed_result", path)?,
        EXPECTED_RESULTS,
        path,
    )?;
    assert_member(required_string(result, "severity", path)?, SEVERITIES, path)?;
    assert_member(
        required_string(result, "status", path)?,
        RESULT_STATUS,
        path,
    )?;
    for field in [
        "passed",
        "skipped",
        "policy_hash_present",
        "policy_epoch_present",
        "audit_present",
        "events_present",
        "public_safe_output",
    ] {
        result
            .get(field)
            .and_then(Value::as_bool)
            .with_context(|| format!("result.{field} must be a boolean"))?;
    }
    let status = required_string(result, "status", path)?;
    let passed = result["passed"] == true;
    let skipped = result["skipped"] == true;
    let skipped_status = matches!(status, "skipped" | "unsupported_fixture");
    if status == "passed" && (!passed || skipped) {
        bail!("passed adversarial results must set passed=true and skipped=false");
    }
    if passed && result["public_safe_output"] != true {
        bail!("passed adversarial results must set public_safe_output=true");
    }
    if status != "passed" && passed {
        bail!("non-passed adversarial results must not set passed=true");
    }
    if skipped_status && !skipped {
        bail!("skipped adversarial status must set skipped=true");
    }
    if !skipped_status && skipped {
        bail!("non-skipped adversarial status must not set skipped=true");
    }
    if status == "xfailed" && required_string(result, "backend_status", path)? != "experimental" {
        bail!("xfailed adversarial results require experimental backend status");
    }
    if skipped {
        match result.get("skip_reason").and_then(Value::as_str) {
            Some(reason) if !reason.trim().is_empty() => {}
            _ => bail!("skipped adversarial results must include skip_reason"),
        }
    }
    if !skipped && !result.get("skip_reason").is_some_and(Value::is_null) {
        bail!("non-skipped adversarial results must set skip_reason=null");
    }
    Ok(())
}

fn assert_allowed_fields(value: &Value, label: &str, allowed: &[&str], path: &Path) -> Result<()> {
    let object = value
        .as_object()
        .with_context(|| format!("{label} must be an object in {}", path.display()))?;
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            bail!(
                "{label}.{key} is not an RFC-0016 field in {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn assert_member(value: &str, allowed: &[&str], path: &Path) -> Result<()> {
    if !allowed.contains(&value) {
        bail!(
            "{value} is not an allowed RFC-0016 value in {}",
            path.display()
        );
    }
    Ok(())
}

fn assert_public_safe(manifest: &str, path: &Path) -> Result<()> {
    let lower = manifest.to_ascii_lowercase();
    let terms = lower
        .split(|byte: char| !byte.is_ascii_alphanumeric())
        .collect::<HashSet<_>>();
    for term in PRIVATE_TERMS {
        if terms.contains(term) {
            bail!(
                "manifest contains non-public term {term} in {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn promotion_gate_allows(
    status: &str,
    observed_severity: &str,
    max_severity: &str,
    passed: bool,
    skipped: bool,
    public_safe_output: bool,
) -> bool {
    status == "passed"
        && passed
        && !skipped
        && public_safe_output
        && severity_rank(observed_severity).is_some_and(|observed| {
            severity_rank(max_severity).is_some_and(|maximum| observed <= maximum)
        })
}

fn severity_rank(severity: &str) -> Option<usize> {
    SEVERITIES
        .iter()
        .position(|candidate| *candidate == severity)
}
