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
];

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
