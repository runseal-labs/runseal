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

    result["skipped"] = json!(true);
    result["status"] = json!("skipped");
    result["passed"] = json!(false);
    assert!(validate_result(&result).is_err());
    result["skip_reason"] = json!("unsupported fixture kind");
    validate_result(&result)?;

    result["status"] = json!("failed");
    assert!(validate_result(&result).is_err());
    result["status"] = json!("skipped");
    result["skipped"] = json!(false);
    assert!(validate_result(&result).is_err());
    result["skipped"] = json!(true);

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
    assert!(
        case_id.starts_with("adv.") && case_id.ends_with(".v1"),
        "case_id must use adv.<class>.<name>.v1 format: {case_id}"
    );
    let primary_class = required_string(case, "primary_class", path)?;
    assert_member(primary_class, CLASSES, path)?;
    let case_class = case_id
        .split('.')
        .nth(1)
        .context("case_id must include a class segment")?;
    if case_class != primary_class {
        bail!("case_id class {case_class} must match primary_class {primary_class}");
    }
    if let Some(secondary_classes) = case.get("secondary_classes") {
        assert_array_members(secondary_classes, "case.secondary_classes", CLASSES, path)?;
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
    case.get("request")
        .and_then(Value::as_object)
        .context("case.request must be an object")?;
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
    Ok(())
}

fn required_string<'a>(case: &'a Value, field: &str, path: &Path) -> Result<&'a str> {
    case.get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("case.{field} must be a string in {}", path.display()))
}

fn assert_non_empty_string(case: &Value, field: &str, path: &Path) -> Result<()> {
    if required_string(case, field, path)?.is_empty() {
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
    for value in values {
        assert_member(
            value
                .as_str()
                .with_context(|| format!("case.{field} entries must be strings"))?,
            allowed,
            path,
        )?;
    }
    Ok(())
}

fn assert_array_members(values: &Value, field: &str, allowed: &[&str], path: &Path) -> Result<()> {
    let values = values
        .as_array()
        .with_context(|| format!("{field} must be an array in {}", path.display()))?;
    for value in values {
        assert_member(
            value
                .as_str()
                .with_context(|| format!("{field} entries must be strings"))?,
            allowed,
            path,
        )?;
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
    }
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
    if status == "passed" && (!passed || skipped) {
        bail!("passed adversarial results must set passed=true and skipped=false");
    }
    if passed && result["public_safe_output"] != true {
        bail!("passed adversarial results must set public_safe_output=true");
    }
    if status != "passed" && passed {
        bail!("non-passed adversarial results must not set passed=true");
    }
    if status == "skipped" && !skipped {
        bail!("skipped adversarial status must set skipped=true");
    }
    if status != "skipped" && skipped {
        bail!("non-skipped adversarial status must not set skipped=true");
    }
    if status == "xfailed" && required_string(result, "backend_status", path)? != "experimental" {
        bail!("xfailed adversarial results require experimental backend status");
    }
    if skipped && result.get("skip_reason").and_then(Value::as_str).is_none() {
        bail!("skipped adversarial results must include skip_reason");
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
