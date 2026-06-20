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
    (
        "wfp_setup.rs",
        include_str!("../vendor/codex-windows-sandbox/upstream/wfp_setup.rs"),
    ),
    (
        "process.rs",
        include_str!("../vendor/codex-windows-sandbox/upstream/process.rs"),
    ),
];

const WINDOWS_SANDBOX_MANIFEST: &str =
    include_str!("../vendor/codex-windows-sandbox/upstream/Cargo.toml");
const WINDOWS_SANDBOX_VENDOR_NOTES: &str =
    include_str!("../vendor/codex-windows-sandbox/VENDOR.md");
const RUNSEAL_BACKEND_SOURCE: &str = include_str!("../src/backend/windows.rs");
const RUNSEAL_SETUP_COMMAND_SOURCE: &str = include_str!("../src/commands/setup.rs");
const WINDOWS_SANDBOX_SETUP_MAIN: &str =
    include_str!("../vendor/codex-windows-sandbox/upstream/bin/setup_main/main.rs");
const WINDOWS_SANDBOX_RUNNER_MAIN: &str =
    include_str!("../vendor/codex-windows-sandbox/upstream/bin/command_runner/main.rs");
const RUNSEAL_BACKEND_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/backend");

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
fn backend_modules_do_not_depend_on_service_modules() {
    for entry in std::fs::read_dir(RUNSEAL_BACKEND_DIR).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }

        let source = std::fs::read_to_string(&path).unwrap();
        for forbidden in ["crate::service", "super::service"] {
            assert!(
                !source.contains(forbidden),
                "{} must not depend on service module token {forbidden}",
                path.display()
            );
        }
    }
}

#[test]
fn vendored_windows_sandbox_notes_capture_runseal_divergence() {
    for required in [
        "intentionally diverges",
        "single sandbox identity",
        "one dedicated sandbox user",
        "do not add readers or migrations",
        "upstream `offline` and `online` records",
        "keep the account model private",
    ] {
        assert!(
            WINDOWS_SANDBOX_VENDOR_NOTES.contains(required),
            "VENDOR.md must document RunSeal Windows sandbox divergence: {required}"
        );
    }
}

#[test]
fn runseal_windows_setup_runs_workspace_full_setup() {
    let setup_cli = RUNSEAL_SETUP_COMMAND_SOURCE
        .split_once("fn run_windows_sandbox_setup(")
        .and_then(|(_, tail)| tail.split_once("fn run_windows_sandbox_full_setup"))
        .map(|(setup_cli, _)| setup_cli)
        .expect("windows setup CLI function must be present");

    assert!(setup_cli.contains("run_windows_sandbox_full_setup"));
    assert!(!setup_cli.contains("run_elevated_provisioning_setup"));
    assert!(RUNSEAL_SETUP_COMMAND_SOURCE.contains("codex_windows_sandbox::run_elevated_setup"));
    assert!(RUNSEAL_SETUP_COMMAND_SOURCE.contains("write_roots: Some(vec![cwd.to_path_buf()])"));
}

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

    let setup = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup.rs").then_some(*source))
        .expect("setup.rs must be included");
    let marker = setup
        .split_once("pub struct SetupMarker {")
        .and_then(|(_, tail)| tail.split_once("impl SetupMarker"))
        .map(|(marker, _)| marker)
        .expect("setup marker struct must be present");
    assert!(marker.contains("pub created_at: String,"));
    assert!(marker.contains("pub proxy_ports: Vec<u16>,"));
    assert!(marker.contains("pub allow_local_binding: bool,"));
    assert!(!marker.contains("pub created_at: Option<String>"));
    assert!(!marker.contains("#[serde(default)]"));
}

#[test]
fn vendored_windows_wfp_metrics_use_runseal_namespace() {
    let wfp_setup = include_str!("../vendor/codex-windows-sandbox/upstream/wfp_setup.rs");

    assert!(wfp_setup.contains("runseal.windows_sandbox.wfp_setup_success"));
    assert!(wfp_setup.contains("runseal.windows_sandbox.wfp_setup_failure"));
    assert!(!wfp_setup.contains("codex.windows_sandbox"));
}

#[test]
fn vendored_windows_wfp_objects_use_runseal_namespace() {
    let wfp = include_str!("../vendor/codex-windows-sandbox/upstream/wfp.rs");
    let filter_specs = include_str!("../vendor/codex-windows-sandbox/upstream/wfp/filter_specs.rs");

    for source in [wfp, filter_specs] {
        assert!(source.contains("RunSeal") || source.contains("runseal_wfp_"));
        assert!(!source.contains("Codex Windows Sandbox WFP"));
        assert!(!source.contains("codex_wfp_"));
        assert!(!source.contains("Codex-owned"));
    }
}

#[test]
fn vendored_windows_sandbox_child_processes_do_not_open_console_windows() {
    let process = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "process.rs").then_some(*source))
        .expect("process.rs must be included");

    assert!(process.contains("CREATE_NO_WINDOW"));
    assert!(process.contains("STARTF_USESHOWWINDOW"));
    assert!(process.contains("STARTF_FORCEOFFFEEDBACK"));
    assert!(process.contains("SW_HIDE"));
    assert!(process.contains("STARTF_USESTDHANDLES | STARTF_FORCEOFFFEEDBACK"));
    assert!(process.contains("CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW"));
    assert!(
        process.contains(
            "CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW"
        )
    );
}

#[test]
fn vendored_windows_sandbox_helper_bins_use_windows_subsystem() {
    for source in [WINDOWS_SANDBOX_SETUP_MAIN, WINDOWS_SANDBOX_RUNNER_MAIN] {
        assert!(source.contains("#![windows_subsystem = \"windows\"]"));
    }
}

#[test]
fn vendored_windows_runner_suppresses_startup_feedback() {
    let runner_client =
        include_str!("../vendor/codex-windows-sandbox/upstream/elevated/runner_client.rs");

    assert!(runner_client.contains("STARTF_FORCEOFFFEEDBACK"));
    assert!(runner_client.contains("si.dwFlags = STARTF_FORCEOFFFEEDBACK"));
}

#[test]
fn vendored_windows_setup_launches_suppress_system_error_dialogs() {
    for (name, source) in VENDOR_SETUP_SOURCES {
        if *name == "setup.rs" || *name == "setup_main/win.rs" {
            assert!(
                source.contains("SetErrorMode"),
                "{name} must suppress Windows system error dialogs around setup launches"
            );
            assert!(
                source.contains("SETUP_ERROR_MODE_FLAGS"),
                "{name} must keep setup launch error-mode flags explicit"
            );
            assert!(
                source.contains("with_suppressed_windows_error_dialogs"),
                "{name} must wrap setup child-process launches"
            );
        }
    }
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
fn vendored_windows_runner_cleanup_does_not_sweep_sandbox_identity() {
    let runner = include_str!("../vendor/codex-windows-sandbox/upstream/bin/command_runner/win.rs");

    for forbidden in [
        "taskkill",
        "WTSLogoffSession",
        "WTSEnumerateProcesses",
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
        "EnumProcesses",
        "OpenProcessToken",
        "LookupAccountNameW",
        "TokenUser",
    ] {
        assert!(
            !runner.contains(forbidden),
            "runner cleanup must stay per-execution and not use user-wide process cleanup token {forbidden}"
        );
    }

    assert!(runner.contains("AssignProcessToJobObject(job, process)"));
    assert!(runner.contains("TerminateJobObject(h_job, 1)"));
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
    assert!(setup.contains("absolute_env_path(\"RUNSEAL_WINDOWS_SANDBOX_SETUP_BROKER_HOME\")"));
    assert!(setup.contains("filter(|path| path.is_absolute())"));

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
    assert!(
        setup_main.contains("absolute_env_path(\"RUNSEAL_WINDOWS_SANDBOX_SETUP_BROKER_HOME\")")
    );
    assert!(setup_main.contains("filter(|path| path.is_absolute())"));

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
    assert!(setup.contains("pub fn current_process_is_elevated"));
    assert!(setup.contains("pub fn provisioning_setup_broker_is_available"));
    assert!(setup.contains("scheduled_setup_task_is_usable(&broker_home)"));
    assert!(setup.contains("let needs_elevation = !is_elevated()"));
    assert!(setup.contains("run_setup_exe(&payload, needs_elevation, codex_home)"));
    assert!(!setup.contains("sandbox provisioning setup must be run from an elevated process"));
}

#[test]
fn vendored_windows_setup_uses_broker_without_direct_uac() {
    let setup = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup.rs").then_some(*source))
        .expect("setup.rs must be included");

    assert!(!setup.contains("ShellExecuteExW"));
    assert!(!setup.contains("SEE_MASK_NOCLOSEPROCESS"));
    assert!(!setup.contains("\"runas\""));
    assert!(setup.contains("let exe = find_setup_exe(codex_home);"));
    assert!(setup.contains(".arg(\"--payload-file\")"));
    assert!(setup.contains("try_run_setup_exe_via_scheduled_task"));
    assert!(!setup.contains("RUNSEAL_WINDOWS_SANDBOX_NO_UAC"));
}

#[test]
fn vendored_windows_setup_launches_copied_setup_helper() {
    let setup = VENDOR_SETUP_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == "setup.rs").then_some(*source))
        .expect("setup.rs must be included");
    let helper_materialization =
        include_str!("../vendor/codex-windows-sandbox/upstream/helper_materialization.rs");

    assert!(setup.contains("use crate::helper_materialization::resolve_exe_for_launch;"));
    assert!(setup.contains("fn find_setup_exe(codex_home: &Path) -> PathBuf"));
    assert!(setup.contains("return resolve_exe_for_launch(&setup_exe, codex_home);"));
    assert!(setup.contains("setup_exe_fallback(codex_home)"));
    assert!(setup.contains("helper_bin_dir(codex_home).join(SETUP_EXE_FILENAME)"));
    assert!(!setup.contains("PathBuf::from(SETUP_EXE_FILENAME)"));
    assert!(setup.contains("let exe = find_setup_exe(codex_home);"));
    assert!(helper_materialization.contains("using unavailable sandbox-bin path"));
    assert!(
        helper_materialization.contains("fallback_exe_for_launch(codex_home, fallback_executable)")
    );
    assert!(!helper_materialization.contains("PathBuf::from(fallback_executable)"));
    assert!(!helper_materialization.contains("falling back to legacy path"));
    assert!(!helper_materialization.contains("fn legacy_lookup"));
}

#[test]
fn runseal_windows_backend_uses_elevated_vendor_capture_only() {
    assert!(
        RUNSEAL_BACKEND_SOURCE
            .contains("run_windows_sandbox_capture_for_permission_profile_elevated")
    );
    for forbidden in [
        "run_windows_sandbox_capture(",
        "run_windows_sandbox_capture_with_filesystem_overrides",
        "run_windows_sandbox_legacy_preflight",
        "spawn_windows_sandbox_session_for_level",
        "spawn_windows_sandbox_session_legacy",
    ] {
        assert!(
            !RUNSEAL_BACKEND_SOURCE.contains(forbidden),
            "RunSeal Windows backend must not call legacy vendor API {forbidden}"
        );
    }
}
