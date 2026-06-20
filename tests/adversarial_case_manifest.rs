use anyhow::{Context, Result, bail};
use serde_json::Value;
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
    assert_non_empty_string(case, "title", path)?;
    assert_string_array(case, "capabilities_under_test", path)?;
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
    if let Some(side_effects) = oracle.get("side_effects") {
        assert_array_members(side_effects, "case.oracle.side_effects", SIDE_EFFECTS, path)?;
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

fn assert_string_array(case: &Value, field: &str, path: &Path) -> Result<()> {
    let values = case
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("case.{field} must be an array in {}", path.display()))?;
    if values.is_empty() || !values.iter().all(Value::is_string) {
        bail!(
            "case.{field} must include at least one string in {}",
            path.display()
        );
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
        let kind = fixture
            .get("kind")
            .and_then(Value::as_str)
            .context("case.fixtures entries must include kind")?;
        assert_member(kind, FIXTURE_KINDS, path)?;
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
