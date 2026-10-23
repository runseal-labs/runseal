use serde_json::Value;
use std::env;
use std::process::Command;

#[test]
fn cli_reports_the_compiled_version_and_current_protocol() {
    let version = env!("CARGO_PKG_VERSION");
    let binary = env!("CARGO_BIN_EXE_runseal");

    let output = Command::new(binary)
        .arg("--version")
        .output()
        .expect("run runseal --version");
    assert!(
        output.status.success(),
        "runseal --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("version output is utf-8")
            .trim(),
        version
    );

    let output = Command::new(binary)
        .args(["version", "--json"])
        .output()
        .expect("run runseal version --json");
    assert!(
        output.status.success(),
        "runseal version --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload =
        serde_json::from_slice::<Value>(&output.stdout).expect("version payload must be JSON");
    assert_eq!(
        payload["runseal_version"].as_str(),
        Some(version),
        "structured version must match the compiled package version"
    );
    assert_eq!(
        payload["protocol_version"].as_str(),
        Some("runseal.protocol/v2"),
        "release binaries must report the current protocol version"
    );
}
