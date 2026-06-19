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

const VENDOR_TIMEOUT_SOURCES: &[(&str, &str)] = &[
    (
        "lib.rs",
        include_str!("../vendor/codex-windows-sandbox/upstream/lib.rs"),
    ),
    (
        "unified_exec/backends/legacy.rs",
        include_str!("../vendor/codex-windows-sandbox/upstream/unified_exec/backends/legacy.rs"),
    ),
    (
        "command_runner/win.rs",
        include_str!("../vendor/codex-windows-sandbox/upstream/bin/command_runner/win.rs"),
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
fn vendored_windows_timeouts_keep_explicit_limits_finite() {
    for (name, source) in VENDOR_TIMEOUT_SOURCES {
        assert!(
            source.contains("const MAX_FINITE_WAIT_MS: u32 = INFINITE - 1;"),
            "{name} must reserve INFINITE for absent timeouts"
        );
        assert!(
            source.contains("ms.min(MAX_FINITE_WAIT_MS as u64) as u32"),
            "{name} must clamp explicit timeouts to a finite Win32 wait"
        );
        assert!(
            !source.contains("ms.min(u32::MAX as u64) as u32"),
            "{name} must not map explicit timeouts to Win32 INFINITE"
        );
    }
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
fn vendored_windows_setup_helper_uses_runseal_binary_name() {
    let setup = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup.rs").then_some(*source))
        .expect("setup.rs must be included");

    assert!(WINDOWS_SANDBOX_MANIFEST.contains("name = \"runseal-windows-sandbox-setup\""));
    assert!(setup.contains("runseal-windows-sandbox-setup.exe"));
    assert!(!setup.contains("codex-windows-sandbox-setup.exe"));
}

#[test]
fn vendored_windows_runner_uses_runseal_binary_name() {
    let helper_materialization =
        include_str!("../vendor/codex-windows-sandbox/upstream/helper_materialization.rs");
    let runner_client =
        include_str!("../vendor/codex-windows-sandbox/upstream/elevated/runner_client.rs");
    let runner_pipe =
        include_str!("../vendor/codex-windows-sandbox/upstream/elevated/runner_pipe.rs");

    assert!(WINDOWS_SANDBOX_MANIFEST.contains("name = \"runseal-command-runner\""));
    assert!(!WINDOWS_SANDBOX_MANIFEST.contains("name = \"codex-command-runner\""));

    for source in [helper_materialization, runner_client] {
        assert!(source.contains("runseal-command-runner.exe"));
        assert!(!source.contains("codex-command-runner.exe"));
    }

    assert!(runner_client.contains("runseal-runner-connect-"));
    assert!(!runner_client.contains("codex-runner-connect-"));
    assert!(runner_pipe.contains("runseal-runner-"));
    assert!(!runner_pipe.contains("codex-runner-"));
}

#[test]
fn vendored_windows_runner_requires_kill_on_close_job() {
    let runner = include_str!("../vendor/codex-windows-sandbox/upstream/bin/command_runner/win.rs");

    assert!(runner.contains("assign_child_to_kill_on_close_job"));
    assert!(runner.contains("cleanup_unmanaged_spawned_process"));
    assert!(runner.contains("send_error(&pipe_write, \"spawn_failed\""));
    assert!(runner.contains("TerminateJobObject(h_job, 1)"));
    assert!(!runner.contains("runner failed to create kill-on-close job object"));
}

#[test]
fn vendored_windows_read_acl_mutex_uses_runseal_namespace() {
    let runner = include_str!("../vendor/codex-windows-sandbox/upstream/bin/command_runner/win.rs");
    let setup = include_str!(
        "../vendor/codex-windows-sandbox/upstream/bin/setup_main/win/read_acl_mutex.rs"
    );

    for source in [runner, setup] {
        assert!(source.contains("Local\\\\RunSealSandboxReadAcl"));
        assert!(!source.contains(concat!("Local\\\\", "Codex", "SandboxReadAcl")));
    }
}

#[test]
fn vendored_windows_setup_has_no_host_app_runtime_bin_special_case() {
    for (name, source) in VENDOR_SETUP_SOURCES {
        for forbidden in [
            "ensure_codex_app_runtime_bin_readable",
            concat!("Windows", "Apps"),
            concat!("Open", "AI"),
            "LocalAppData cache",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} must not contain host app runtime-bin special case {forbidden}"
            );
        }
    }
}

#[test]
fn vendored_windows_setup_passes_payload_by_file() {
    let setup = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup.rs").then_some(*source))
        .expect("setup.rs must be included");
    let setup_main = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup_main/win.rs").then_some(*source))
        .expect("setup_main/win.rs must be included");

    for source in [setup, setup_main] {
        assert!(source.contains("--payload-file"));
        assert!(source.contains("write_setup_payload_file"));
        assert!(!source.contains("payload_b64"));
        assert!(!source.contains("failed to decode payload b64"));
        assert!(!source.contains("expected payload argument"));
    }
}

#[test]
fn vendored_windows_setup_reuses_elevation_via_scheduled_task() {
    let setup = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup.rs").then_some(*source))
        .expect("setup.rs must be included");
    let setup_main = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup_main/win.rs").then_some(*source))
        .expect("setup_main/win.rs must be included");

    assert!(setup.contains("try_run_setup_exe_via_scheduled_task"));
    assert!(setup.contains("schtasks.exe"));
    assert!(setup.contains("--task-run"));
    assert!(setup.contains("\\RunSeal\\WindowsSandboxSetup"));
    assert!(setup.contains("RUNSEAL_WINDOWS_SANDBOX_SETUP_BROKER_HOME"));

    assert!(setup_main.contains("run_scheduled_setup_task"));
    assert!(setup_main.contains("ensure_scheduled_setup_task"));
    assert!(setup_main.contains("ensure_scheduled_setup_task_or_fail"));
    assert!(setup_main.contains("use codex_windows_sandbox::resolve_current_exe_for_launch;"));
    assert!(
        setup_main
            .contains("const SETUP_EXE_FILENAME: &str = \"runseal-windows-sandbox-setup.exe\";")
    );
    assert!(
        setup_main.contains(
            "let exe = resolve_current_exe_for_launch(&broker_home, SETUP_EXE_FILENAME);"
        )
    );
    assert!(setup_main.contains("/RL"));
    assert!(setup_main.contains("HIGHEST"));
    assert!(setup_main.contains("\\RunSeal\\WindowsSandboxSetup"));
    assert!(setup_main.contains("RUNSEAL_WINDOWS_SANDBOX_SETUP_BROKER_HOME"));

    assert!(setup.contains("RunSeal"));
    assert!(setup_main.contains("RunSeal"));
}

#[test]
fn vendored_windows_provisioning_setup_reuses_scheduled_task_when_available() {
    let setup = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup.rs").then_some(*source))
        .expect("setup.rs must be included");

    assert!(setup.contains("pub fn run_elevated_provisioning_setup"));
    assert!(setup.contains("pub fn provisioning_setup_broker_is_available"));
    assert!(setup.contains("scheduled_setup_task_is_usable(&broker_home)"));
    assert!(setup.contains("let needs_elevation = !is_elevated()"));
    assert!(setup.contains("run_setup_exe(&payload, needs_elevation, codex_home)"));
    assert!(!setup.contains("sandbox provisioning setup must be run from an elevated process"));
}

#[test]
fn vendored_windows_setup_does_not_shell_elevate_from_exec_path() {
    let setup = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup.rs").then_some(*source))
        .expect("setup.rs must be included");

    assert!(!setup.contains("ShellExecuteExW"));
    assert!(!setup.contains("SEE_MASK"));
    assert!(!setup.contains("\"runas\""));
    assert!(!setup.contains("RUNSEAL_WINDOWS_SANDBOX_NO_UAC"));
    assert!(setup.contains("run `runseal setup windows-sandbox`"));
}

#[test]
fn vendored_windows_setup_launches_copied_setup_helper() {
    let setup = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup.rs").then_some(*source))
        .expect("setup.rs must be included");

    assert!(setup.contains("use crate::helper_materialization::resolve_exe_for_launch;"));
    assert!(setup.contains("fn find_setup_exe(codex_home: &Path) -> PathBuf"));
    assert!(setup.contains("return resolve_exe_for_launch(&setup_exe, codex_home);"));
    assert!(setup.contains("let exe = find_setup_exe(codex_home);"));
}
