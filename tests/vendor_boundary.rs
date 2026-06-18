const VENDOR_SETUP_SOURCES: &[(&str, &str)] = &[
    (
        "setup.rs",
        include_str!("../vendor/codex-windows-sandbox/upstream/setup.rs"),
    ),
    (
        "identity.rs",
        include_str!("../vendor/codex-windows-sandbox/upstream/identity.rs"),
    ),
    (
        "setup_main/win.rs",
        include_str!("../vendor/codex-windows-sandbox/upstream/bin/setup_main/win.rs"),
    ),
    (
        "setup_main/win/sandbox_users.rs",
        include_str!(
            "../vendor/codex-windows-sandbox/upstream/bin/setup_main/win/sandbox_users.rs"
        ),
    ),
    (
        "setup_main/win/firewall.rs",
        include_str!("../vendor/codex-windows-sandbox/upstream/bin/setup_main/win/firewall.rs"),
    ),
];

const WINDOWS_SANDBOX_MANIFEST: &str =
    include_str!("../vendor/codex-windows-sandbox/upstream/Cargo.toml");

#[test]
fn vendored_windows_setup_state_uses_single_user_schema() {
    for (name, source) in VENDOR_SETUP_SOURCES {
        for forbidden in [
            "offline_username",
            "online_username",
            "CodexSandboxOffline",
            "CodexSandboxOnline",
            "offline: SandboxUserRecord",
            "online: SandboxUserRecord",
            "SandboxNetworkIdentity",
            "OfflineProxySettings",
            "offline_proxy_settings_from_env",
            "uses_offline_identity",
            "configure_offline_sandbox_network",
            "ensure_offline_proxy_allowlist",
            "ensure_offline_outbound_block",
            "offline_sid",
            "OFFLINE_",
            "codex_sandbox_offline",
            "Codex Sandbox Offline",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} must not contain legacy dual-user schema token {forbidden}"
            );
        }
    }

    assert!(
        VENDOR_SETUP_SOURCES
            .iter()
            .any(|(_, source)| source.contains("sandbox_username"))
    );
    assert!(
        VENDOR_SETUP_SOURCES
            .iter()
            .any(|(_, source)| source.contains("user: SandboxUserRecord"))
    );
}

#[test]
fn vendored_windows_sandbox_uses_local_trimmed_dependencies() {
    for required in [
        "codex-utils-pty = { path = \"../../codex-utils-pty\" }",
        "codex-utils-absolute-path = { path = \"../../codex-utils-absolute-path\" }",
        "codex-utils-string = { path = \"../../codex-utils-string\" }",
        "codex-otel = { path = \"../../codex-otel\" }",
        "path = \"../../codex-protocol\"",
    ] {
        assert!(
            WINDOWS_SANDBOX_MANIFEST.contains(required),
            "vendored Windows sandbox manifest must use local dependency {required}"
        );
    }

    for forbidden in [
        "github.com/openai/codex",
        "rev =",
        "codex-otel-shim",
        "workspace = true",
    ] {
        assert!(
            !WINDOWS_SANDBOX_MANIFEST.contains(forbidden),
            "vendored Windows sandbox manifest must not use {forbidden}"
        );
    }
}

#[test]
fn vendored_windows_setup_launch_suppresses_shell_error_ui() {
    let setup = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup.rs").then_some(*source))
        .expect("setup.rs must be included");

    assert!(setup.contains("SEE_MASK_FLAG_NO_UI"));
    assert!(setup.contains("SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI"));
}
