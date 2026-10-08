use super::*;
use std::time::Duration;

impl WindowsReferenceBackend {
    pub(super) fn fail_closed_plan(
        self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> PlatformSandboxPlan {
        self.fail_closed_plan_with_host_roots(
            execution_id,
            cwd,
            policy,
            WindowsHostRoots::from_current_environment(),
        )
    }

    pub(super) fn fail_closed_plan_with_host_roots(
        self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
        host_roots: WindowsHostRoots,
    ) -> PlatformSandboxPlan {
        let runtime_root = cwd.join(".runseal").join("runtime").join(execution_id);
        let profile_root = runtime_root.join("profile");
        let synthetic_home = runtime_root.join("home");
        let temp_root = runtime_root.join("temp");
        let windows_policy = WindowsPolicyPlan::from_policy_runtime_and_host_roots(
            policy,
            Some(WindowsRuntimeRoots::new(
                path_string(&runtime_root),
                path_string(&profile_root),
                path_string(&synthetic_home),
                path_string(&temp_root),
            )),
            host_roots,
        );
        let private_filesystem_deny = windows_policy.filesystem.private_protected_roots.clone();
        let private_filesystem_rules = windows_policy.filesystem.enforcement_rules();
        let private_process_sandbox_user_model = windows_policy.process.sandbox_user_model.as_str();
        let private_setup_account_name = windows_policy
            .process
            .sandbox_user_model
            .local_account_name();
        let private_setup_group_name = windows_policy.process.sandbox_user_model.local_group_name();
        let private_setup_identity_artifacts = windows_policy
            .process
            .sandbox_user_model
            .setup_identity_artifacts();
        let private_process_token = windows_policy.process.token.as_str();
        let private_process_job = windows_policy.process.job.as_str();
        let vendor_profile = WindowsVendorSandboxProfile::from_policy(policy);
        let vendor_sandbox_home = vendor_sandbox_home(cwd);
        let private_setup_payload = vendor_profile.single_user_setup_payload(
            &vendor_sandbox_home,
            cwd,
            &windows_setup_real_user(),
        );
        #[cfg(windows)]
        let private_vendor_permission_profile = vendor_profile
            .permission_profile_with_runtime_roots(&windows_policy.filesystem.runtime_write_roots)
            .ok()
            .and_then(|profile| serde_json::to_string(&profile).ok());
        #[cfg(not(windows))]
        let private_vendor_permission_profile = None;
        let filesystem_write = windows_policy.filesystem.effective_write_roots();

        PlatformSandboxPlan {
            backend: self.name(),
            backend_status: self.status(),
            platform: self.platform(),
            execution_id: execution_id.to_string(),
            policy_id: policy.id.clone(),
            policy_hash: policy.hash(),
            sandbox_level: policy.sandbox_level.as_str(),
            enforcement: "fail-closed-preview",
            cwd: path_string(cwd),
            runtime_root: Some(path_string(&runtime_root)),
            profile_root: Some(path_string(&profile_root)),
            synthetic_home: Some(path_string(&synthetic_home)),
            temp_root: Some(path_string(&temp_root)),
            filesystem_read: windows_policy.filesystem.read_roots,
            filesystem_write,
            filesystem_deny: windows_policy.filesystem.protected_roots,
            filesystem_protected: protected_filesystem_labels(policy),
            private_filesystem_deny,
            private_filesystem_rules,
            private_portable_read_roots: Vec::new(),
            private_portable_write_roots: Vec::new(),
            private_portable_deny_roots: Vec::new(),
            process_boundary: windows_policy.process.boundary.as_str(),
            process_identity: windows_policy.process.identity.as_str(),
            process_cleanup: windows_policy.process.cleanup.as_str(),
            private_process_sandbox_user_model,
            private_process_token,
            private_process_job,
            private_setup_account_name,
            private_setup_group_name,
            private_setup_identity_artifacts,
            private_setup_payload: private_setup_payload.map(|payload| payload.to_string()),
            private_vendor_permission_profile,
            network_mode: windows_policy.network.guard.as_str(),
            network_direct_egress: windows_policy.network.direct_egress.as_str(),
            network_managed_proxy: windows_policy.network.managed_proxy.as_str(),
            environment_inherit: policy.environment.inherit.clone(),
            environment_scrub: policy.environment.scrub.clone(),
            environment_proxy: windows_policy.network.inject_proxy_environment,
            environment_runtime: windows_policy.environment.runtime,
            required_backend_features: policy.required_backend_feature_names(),
        }
    }
}

#[cfg(test)]
pub(super) fn has_single_user_setup_payload(payload: Option<&str>) -> bool {
    let Some(payload) = payload else {
        return false;
    };
    let Ok(payload) = serde_json::from_str::<Value>(payload) else {
        return false;
    };

    payload.get("sandbox_username").and_then(Value::as_str) == Some("RunSealSandbox")
        && payload.get("codex_home").and_then(Value::as_str).is_some()
        && payload.get("command_cwd").and_then(Value::as_str).is_some()
        && payload.get("real_user").and_then(Value::as_str).is_some()
        && payload.get("sandbox_home").is_none()
        && payload.get("network").is_none()
        && payload.get("offline_username").is_none()
        && payload.get("online_username").is_none()
}

fn windows_setup_real_user() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsReferenceBackend;

#[cfg(windows)]
const WINDOWS_REFERENCE_SUPPORTED_FEATURES: &[BackendFeature] = &[
    BackendFeature::FilesystemPolicy,
    BackendFeature::RuntimeRoots,
    BackendFeature::RuntimeEnvironment,
    BackendFeature::ProcessIsolation,
    BackendFeature::ProcessCleanup,
    BackendFeature::DirectNetworkDeny,
    BackendFeature::NetworkDisabled,
    BackendFeature::NetworkProxy,
    BackendFeature::ManagedProxy,
    BackendFeature::PolicyEpoch,
];

#[cfg(not(windows))]
const WINDOWS_REFERENCE_SUPPORTED_FEATURES: &[BackendFeature] = &[
    BackendFeature::RuntimeRoots,
    BackendFeature::RuntimeEnvironment,
    BackendFeature::ProcessCleanup,
];

impl SandboxBackend for WindowsReferenceBackend {
    fn name(&self) -> &'static str {
        "runseal-windows-reference"
    }

    fn status(&self) -> &'static str {
        if cfg!(windows) {
            "reference"
        } else {
            "scaffold"
        }
    }

    fn platform(&self) -> &'static str {
        "windows"
    }

    fn supported_features(&self) -> &'static [BackendFeature] {
        WINDOWS_REFERENCE_SUPPORTED_FEATURES
    }

    fn execution_capabilities(&self) -> super::capability::ExecutionCapabilityStatuses {
        #[cfg(windows)]
        {
            super::capability::interactive_execution_capabilities()
        }
        #[cfg(not(windows))]
        {
            super::capability::baseline_execution_capabilities()
        }
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        if policy.allows_local_execution() {
            Ok(PlatformSandboxPlan::local_execution(
                self,
                execution_id,
                cwd,
                policy,
            ))
        } else {
            #[cfg(windows)]
            {
                let protected =
                    super::policy_epoch::cross_process_gate_state_dir().and_then(|root| {
                        match fs::canonicalize(root) {
                            Ok(root) => {
                                let cwd = fs::canonicalize(cwd)?;
                                let root: Vec<u16> =
                                    std::os::windows::ffi::OsStrExt::encode_wide(root.as_os_str())
                                        .collect();
                                let cwd: Vec<u16> =
                                    std::os::windows::ffi::OsStrExt::encode_wide(cwd.as_os_str())
                                        .collect();
                                let matches = cwd.len() >= root.len()
                                    && unsafe {
                                        windows_sys::Win32::Globalization::CompareStringOrdinal(
                                            cwd.as_ptr(),
                                            root.len() as _,
                                            root.as_ptr(),
                                            root.len() as _,
                                            1,
                                        )
                                    } == windows_sys::Win32::Globalization::CSTR_EQUAL;
                                Ok(matches
                                    && (cwd.len() == root.len()
                                        || cwd[root.len()] == u16::from(b'\\')))
                            }
                            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                            Err(error) => Err(error),
                        }
                    });
                match protected {
                    Ok(false) => {}
                    Ok(true) => {
                        let mut error = BackendError::unsupported(self, policy);
                        error.reason = "workspace overlaps protected execution state".to_string();
                        error.missing_features = vec!["runtime_roots"];
                        return Err(error);
                    }
                    Err(_) => {
                        let mut error = BackendError::unsupported(self, policy);
                        error.code = "BACKEND_UNAVAILABLE";
                        error.reason = "protected execution state unavailable".to_string();
                        error.missing_features.clear();
                        return Err(error);
                    }
                }
            }
            let mut plan = self.fail_closed_plan(execution_id, cwd, policy);
            if self.missing_features(policy).is_empty() {
                plan.enforcement = "windows-sandbox";
                Ok(plan)
            } else {
                Err(BackendError::unsupported_with_plan(
                    self,
                    policy,
                    Some(plan),
                ))
            }
        }
    }

    fn execute_plan(
        &self,
        plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
        stdin: ExecutionStdin,
        env: &ExecutionEnv,
        options: BackendExecutionOptions,
    ) -> io::Result<BackendExecutionOutput> {
        let BackendExecutionOptions { timeout, output } = options;
        if plan.is_sandbox_enforced() {
            return execute_windows_sandbox_plan(plan, command, cwd, stdin, env, timeout, output);
        }
        spawn_local_command_with_output(plan, command, cwd, stdin, env, timeout, output)
    }

    fn capabilities_json(&self) -> Value {
        capabilities_json_for(
            self,
            &[
                "Windows reference backend enforces sandboxed policies with OS-native process, filesystem, and network boundaries",
                "RunSeal policy, plan, audit, and conformance surfaces stay platform-neutral",
                "runtime roots are created, marked, and cleaned with containment checks",
                "runtime environment redirects are injected into sandboxed child environments",
                "process cleanup terminates sandboxed process trees when the parent exits",
                "filesystem and network enforcement fail closed when setup is unavailable",
            ],
        )
    }
}

#[cfg(windows)]
pub(super) fn prepare_windows_sandbox_setup(cwd: &Path) -> io::Result<PathBuf> {
    let setup_status =
        crate::commands::setup::windows_sandbox_setup_status_for_cwd(cwd).map_err(|err| {
            io::Error::other(BackendUnavailableError {
                reason: format!("windows sandbox setup unavailable: {err}"),
            })
        })?;
    let vendor_sandbox_home = vendor_sandbox_home(cwd);
    if setup_status["requires_setup"].as_bool().unwrap_or(true) {
        if setup_status["broker"].as_str() != Some("available") {
            return Err(io::Error::other(BackendUnavailableError {
                reason: public_windows_setup_unavailable_reason("requires_setup"),
            }));
        }
        // The scheduled setup broker is installed: repair the workspace setup
        // state through the broker without opening UAC. run_elevated_setup
        // selects the scheduled-task path internally.
        crate::commands::setup::run_windows_sandbox_full_setup(cwd, &vendor_sandbox_home).map_err(
            |err| {
                io::Error::other(BackendUnavailableError {
                    reason: format!(
                        "windows sandbox setup repair through scheduled broker failed: {err}"
                    ),
                })
            },
        )?;
    }

    Ok(vendor_sandbox_home)
}

#[cfg(windows)]
pub(super) fn execute_windows_sandbox_plan(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
    output: Option<ExecutionOutputSink>,
) -> io::Result<BackendExecutionOutput> {
    let cleanup_budget = codex_windows_sandbox::CleanupBudget::try_from(
        crate::limits::deployment().cleanup_timeout_ms as u64,
    )
    .map_err(io::Error::other)?;
    let _execution_guard = windows_sandbox_execution_gate(plan)?;
    let vendor_sandbox_home = prepare_windows_sandbox_setup(cwd).inspect_err(|_| {
        report_windows_test_diagnostic("setup_preparation_failed");
    })?;

    let _runtime_root = required_plan_path(plan.runtime_root.as_deref(), "runtime_root")?;
    let input_acknowledged = match &stdin {
        ExecutionStdin::Stream(queue) => {
            let queue = queue.clone();
            let control = output.as_ref().map(|sink| sink.control.clone());
            Some(Box::new(move |count| {
                let accepted = queue.acknowledge(count).is_ok();
                if !accepted && let Some(control) = &control {
                    control.request(crate::execution::TerminationCause::InputFailed);
                }
                accepted
            }) as Box<dyn FnMut(usize) -> bool + Send>)
        }
        _ => None,
    };
    let (stdin_bytes, input_source) = match stdin {
        ExecutionStdin::Empty => (Vec::new(), None),
        ExecutionStdin::Bytes(bytes) | ExecutionStdin::File(bytes) => (bytes, None),
        ExecutionStdin::Stream(queue) => {
            let input_control = output.as_ref().map(|sink| sink.control.clone());
            let terminal_control = output
                .as_ref()
                .filter(|sink| sink.io.is_pty())
                .map(|sink| sink.control.clone());
            (
                Vec::new(),
                Some(Box::new(move || {
                    if let Some(command) = terminal_control
                        .as_ref()
                        .and_then(crate::execution::ExecutionControl::take_terminal_command)
                    {
                        return match command {
                            crate::execution::TerminalCommand::Resize { rows, cols } => {
                                codex_windows_sandbox::SandboxInputPoll::Resize { rows, cols }
                            }
                            crate::execution::TerminalCommand::Interrupt => {
                                codex_windows_sandbox::SandboxInputPoll::Interrupt
                            }
                        };
                    }
                    match queue.poll() {
                        Ok(InputPoll::Data(bytes)) => {
                            codex_windows_sandbox::SandboxInputPoll::Data(bytes)
                        }
                        Ok(InputPoll::Pending) => codex_windows_sandbox::SandboxInputPoll::Pending,
                        Ok(InputPoll::Eof) => codex_windows_sandbox::SandboxInputPoll::Eof,
                        Err(_) => {
                            if let Some(control) = &input_control {
                                control.request(crate::execution::TerminationCause::InputFailed);
                            }
                            codex_windows_sandbox::SandboxInputPoll::Failed
                        }
                    }
                })
                    as codex_windows_sandbox::SandboxInputSource),
            )
        }
    };
    let workspace_roots = windows_sandbox_workspace_roots_for_plan(cwd, plan)?;
    let write_roots_override = windows_sandbox_write_roots_for_plan(plan);
    let mut deny_write_paths_override = plan
        .filesystem_deny
        .iter()
        .map(|root| {
            AbsolutePathBuf::try_from(PathBuf::from(root))
                .map_err(|err| io::Error::other(err.to_string()))
        })
        .collect::<io::Result<Vec<_>>>()?;
    deny_write_paths_override.push(
        AbsolutePathBuf::try_from(super::policy_epoch::cross_process_gate_state_dir()?)
            .map_err(|_| io::Error::other("execution gate protection unavailable"))?,
    );
    let permission_profile = plan.vendor_permission_profile()?;
    plan.prepare_runtime_roots().inspect_err(|_| {
        report_windows_test_diagnostic("runtime_root_preparation_failed");
    })?;

    let result = (|| {
        prepare_vendor_sandbox_home(cwd, &vendor_sandbox_home)?;
        let managed_proxy = if plan.network_managed_proxy == "required" {
            Some(ManagedSandboxProxy::start().map_err(|err| {
                io::Error::other(BackendUnavailableError {
                    reason: format!("windows managed proxy unavailable: {err}"),
                })
            })?)
        } else {
            None
        };
        let mut events = if managed_proxy.is_some() {
            vec![json!({
                "type": "execution.network.proxy_ready",
                "time": timestamp_now(),
                "decision": "ready",
                "network": {
                    "mode": plan.network_mode,
                    "direct_egress": plan.network_direct_egress,
                    "managed_proxy": plan.network_managed_proxy,
                },
            })]
        } else {
            Vec::new()
        };
        let env_map = sandbox_environment(plan, env, managed_proxy.as_ref());
        let scoped_read = codex_windows_sandbox::isolation_mode_for_permission_profile(
            &permission_profile,
            &workspace_roots,
            cwd,
            &env_map,
        )
        .map_err(|_| io::Error::other("sandbox permission profile unavailable"))?
            == codex_windows_sandbox::WindowsSandboxIsolationMode::AppContainerCapabilities;
        let read_cap_sid = if scoped_read {
            let workspace_root = workspace_roots
                .first()
                .ok_or_else(|| io::Error::other("sandbox requires an active workspace root"))?;
            Some(
                codex_windows_sandbox::workspace_appcontainer_read_capability_sid(
                    &vendor_sandbox_home,
                    workspace_root.as_path(),
                )
                .map_err(|err| io::Error::other(err.to_string()))?,
            )
        } else {
            None
        };
        let sandbox_command = windows_sandbox_command(command, &env_map);

        let capture =
            codex_windows_sandbox::run_windows_sandbox_capture_for_permission_profile_elevated(
                codex_windows_sandbox::ElevatedSandboxProfileCaptureRequest {
                    permission_profile: &permission_profile,
                    workspace_roots: workspace_roots.as_slice(),
                    codex_home: &vendor_sandbox_home,
                    command: sandbox_command,
                    cwd,
                    env_map,
                    timeout_ms: timeout.map(duration_millis_u64),
                    stdin: stdin_bytes,
                    terminal_size: output.as_ref().and_then(|sink| match sink.io {
                        ExecutionIo::Pipe | ExecutionIo::PipeControl => None,
                        ExecutionIo::Pty { rows, cols } => {
                            Some(codex_windows_sandbox::ResizePayload { rows, cols })
                        }
                    }),
                    input_source,
                    input_acknowledged,
                    control_source: output
                        .as_ref()
                        .and_then(|sink| {
                            sink.control_input
                                .clone()
                                .map(|queue| (queue, sink.control.clone()))
                        })
                        .map(|(queue, control)| {
                            Box::new(move || match queue.poll() {
                                Ok(InputPoll::Data(bytes)) => {
                                    codex_windows_sandbox::SandboxInputPoll::Data(bytes)
                                }
                                Ok(InputPoll::Pending) => {
                                    codex_windows_sandbox::SandboxInputPoll::Pending
                                }
                                Ok(InputPoll::Eof) => codex_windows_sandbox::SandboxInputPoll::Eof,
                                Err(_) => {
                                    control
                                        .request(crate::execution::TerminationCause::InputFailed);
                                    codex_windows_sandbox::SandboxInputPoll::Failed
                                }
                            })
                                as codex_windows_sandbox::SandboxInputSource
                        }),
                    control_acknowledged: output
                        .as_ref()
                        .and_then(|sink| {
                            sink.control_input
                                .clone()
                                .map(|queue| (queue, sink.control.clone()))
                        })
                        .map(|(queue, control)| {
                            Box::new(move |count| {
                                let accepted = queue.acknowledge(count).is_ok();
                                if !accepted {
                                    control
                                        .request(crate::execution::TerminationCause::InputFailed);
                                }
                                accepted
                            }) as Box<dyn FnMut(usize) -> bool + Send>
                        }),
                    cancellation: Some(
                        output
                            .as_ref()
                            .map(|sink| {
                                let control = sink.control.clone();
                                let deadline_control = control.clone();
                                let cleanup_control = control.clone();
                                codex_windows_sandbox::WindowsSandboxCancellationToken::new(
                                    move || control.is_cancelled(),
                                )
                                .with_cleanup_deadline(move || deadline_control.begin_cleanup())
                                .with_cleanup_started(
                                    move |deadline, exit_code, timed_out| {
                                        if timed_out {
                                            cleanup_control.request(
                                                crate::execution::TerminationCause::Timeout,
                                            );
                                        } else if exit_code.is_some() {
                                            cleanup_control.request(
                                                crate::execution::TerminationCause::Exited,
                                            );
                                        }
                                        cleanup_control.adopt_cleanup_deadline(deadline)
                                    },
                                )
                            })
                            .unwrap_or_else(|| {
                                codex_windows_sandbox::WindowsSandboxCancellationToken::new(|| {
                                    false
                                })
                            })
                            .with_cleanup_budget(cleanup_budget),
                    ),
                    started_observer: output.clone().map(|sink| {
                        Box::new(move || {
                            let _ = sink.started();
                        }) as Box<dyn FnMut() + Send>
                    }),
                    output_observer: output.clone().map(|sink| {
                        Box::new(move |stream, bytes: &[u8]| {
                            let stream = match stream {
                                codex_windows_sandbox::OutputStream::Stdout if sink.io.is_pty() => {
                                    OutputStream::Terminal
                                }
                                codex_windows_sandbox::OutputStream::Stdout => OutputStream::Stdout,
                                codex_windows_sandbox::OutputStream::Stderr => OutputStream::Stderr,
                                codex_windows_sandbox::OutputStream::Control => {
                                    OutputStream::Control
                                }
                            };
                            let _ = sink.send(stream, bytes);
                        }) as codex_windows_sandbox::SandboxOutputObserver
                    }),
                    use_private_desktop: true,
                    proxy_enforced: plan.network_managed_proxy == "required",
                    allow_network_proxy: plan.network_direct_egress != "deny"
                        || plan.network_managed_proxy == "required",
                    sandbox_proxy_settings: managed_proxy_settings(managed_proxy.as_ref()),
                    read_cap_sid,
                    read_roots_override: None,
                    read_roots_include_platform_defaults: scoped_read,
                    write_roots_override: Some(write_roots_override.as_slice()),
                    deny_write_paths_override: &deny_write_paths_override,
                },
            )
            .map_err(|err| {
                if let Some(failure) =
                    err.downcast_ref::<codex_windows_sandbox::SandboxCaptureInputError>()
                {
                    if let Some(sink) = &output {
                        sink.control.request(if failure.timed_out {
                            crate::execution::TerminationCause::Timeout
                        } else {
                            crate::execution::TerminationCause::InputFailed
                        });
                    }
                    return io::Error::other(super::error::BackendInputFacts {
                        exit_code: failure.exit_code,
                        timed_out: failure.timed_out,
                    });
                }
                if let Some(failure) =
                    err.downcast_ref::<codex_windows_sandbox::SandboxCaptureCleanupError>()
                {
                    return io::Error::other(super::error::BackendCleanupFacts {
                        exit_code: failure.exit_code,
                        timed_out: failure.timed_out,
                    });
                }
                if err
                    .downcast_ref::<codex_windows_sandbox::SandboxCleanupError>()
                    .is_some()
                {
                    return io::Error::other(BackendCleanupError);
                }
                if let Some(failure) = codex_windows_sandbox::extract_setup_failure(&err) {
                    return io::Error::other(BackendUnavailableError {
                        reason: public_windows_setup_unavailable_reason(failure.code.as_str()),
                    });
                }
                io::Error::other(err.to_string())
            })?;
        if let Some(managed_proxy) = &managed_proxy {
            events.extend(managed_proxy.drain_events());
        }
        Ok((capture, events))
    })();
    let capture_cleanup_failed = result.as_ref().err().is_some_and(super::cleanup_failed);
    let capture_failed = result.is_err();
    let cleanup = plan.cleanup_runtime_roots();
    if capture_cleanup_failed {
        report_windows_test_diagnostic("sandbox_capture_cleanup_failed");
    } else if capture_failed {
        report_windows_test_diagnostic("sandbox_capture_failed");
    } else {
        report_windows_test_diagnostic("sandbox_capture_succeeded");
    }
    report_windows_test_diagnostic(if cleanup.is_err() {
        "runtime_root_cleanup_failed"
    } else {
        "runtime_root_cleanup_succeeded"
    });
    if result.as_ref().err().is_some_and(super::cleanup_failed) || cleanup.is_err() {
        let _ = _execution_guard.mark_cleanup_failed();
    }

    let (capture, events) = match (result, cleanup) {
        (Ok(capture), Ok(_)) => capture,
        (Err(err), Ok(_)) => return Err(err),
        (Ok((capture, _)), Err(_)) => {
            return Err(io::Error::other(super::error::BackendCleanupFacts {
                exit_code: Some(capture.exit_code),
                timed_out: capture.timed_out,
            }));
        }
        (Err(err), Err(_)) if super::cleanup_failed(&err) => return Err(err),
        (Err(err), Err(_)) => {
            return Err(io::Error::other(super::error::BackendCleanupFacts {
                exit_code: super::failure_exit_code(&err),
                timed_out: super::failure_timed_out(&err),
            }));
        }
    };

    Ok(BackendExecutionOutput {
        output: Output {
            status: std::process::ExitStatus::from_raw(capture.exit_code as u32),
            stdout: capture.stdout,
            stderr: capture.stderr,
        },
        timed_out: capture.timed_out,
        cleanup_complete: true,
        events,
    })
}

#[cfg(windows)]
fn report_windows_test_diagnostic(stage: &str) {
    if std::env::var_os("RUNSEAL_WINDOWS_TEST_DIAGNOSTICS").is_some() {
        eprintln!("runseal-test-diagnostic: windows={stage}");
    }
}

#[cfg(windows)]
pub(super) fn windows_sandbox_write_roots_for_plan(plan: &PlatformSandboxPlan) -> Vec<PathBuf> {
    plan.filesystem_write.iter().map(PathBuf::from).collect()
}

#[cfg(windows)]
pub(super) fn windows_sandbox_workspace_roots_for_plan(
    cwd: &Path,
    plan: &PlatformSandboxPlan,
) -> io::Result<Vec<AbsolutePathBuf>> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    for root in [
        Some(cwd.to_path_buf()),
        plan.runtime_root.as_deref().map(PathBuf::from),
        plan.profile_root.as_deref().map(PathBuf::from),
        plan.synthetic_home.as_deref().map(PathBuf::from),
        plan.temp_root.as_deref().map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    {
        if !seen.insert(windows_sandbox_path_key(&root)) {
            continue;
        }
        roots.push(
            AbsolutePathBuf::from_absolute_path_checked(&root).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "invalid Windows sandbox workspace root {}: {err}",
                        root.display()
                    ),
                )
            })?,
        );
    }
    Ok(roots)
}

#[cfg(windows)]
pub(super) fn windows_sandbox_command(
    command: &[String],
    env_map: &HashMap<String, String>,
) -> Vec<String> {
    let Some((program, args)) = command.split_first() else {
        return Vec::new();
    };
    let mut resolved = Vec::with_capacity(command.len());
    resolved
        .push(resolve_windows_sandbox_program(program, env_map).unwrap_or_else(|| program.clone()));
    resolved.extend(args.iter().cloned());
    resolved
}

#[cfg(windows)]
fn resolve_windows_sandbox_program(
    program: &str,
    env_map: &HashMap<String, String>,
) -> Option<String> {
    let program_path = Path::new(program);
    if program_path.is_absolute() || program.contains('\\') || program.contains('/') {
        return Some(program.to_string());
    }

    let path_env = windows_environment_value(env_map, "PATH")
        .map(str::to_string)
        .or_else(|| std::env::var("PATH").ok())?;
    let pathext = windows_environment_value(env_map, "PATHEXT")
        .map(str::to_string)
        .or_else(|| std::env::var("PATHEXT").ok())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
    let candidate_names = windows_executable_candidate_names(program, &pathext);

    for dir in std::env::split_paths(&path_env) {
        for name in &candidate_names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }

    None
}

#[cfg(windows)]
fn windows_environment_value<'a>(
    env_map: &'a HashMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    env_map
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
}

#[cfg(windows)]
fn windows_executable_candidate_names(program: &str, pathext: &str) -> Vec<String> {
    if Path::new(program).extension().is_some() {
        return vec![program.to_string()];
    }

    let mut names = Vec::new();
    for ext in pathext.split(';') {
        let ext = ext.trim();
        if ext.is_empty() {
            continue;
        }
        if ext.starts_with('.') {
            names.push(format!("{program}{ext}"));
        } else {
            names.push(format!("{program}.{ext}"));
        }
    }
    names.push(program.to_string());
    names
}

#[cfg(windows)]
pub(super) fn windows_sandbox_path_key(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

#[cfg(not(windows))]
fn execute_windows_sandbox_plan(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
    output: Option<ExecutionOutputSink>,
) -> io::Result<BackendExecutionOutput> {
    spawn_local_command_with_output(plan, command, cwd, stdin, env, timeout, output)
}

#[cfg(windows)]
fn required_plan_path(value: Option<&str>, name: &'static str) -> io::Result<PathBuf> {
    value.map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("sandboxed plan is missing {name}"),
        )
    })
}

/// Machine-level Windows sandbox home, shared across workspaces so a
/// one-time setup (setup marker, sandbox identity, helper binaries, scheduled
/// setup broker) applies to every workspace. A workspace-scoped home would
/// require a fresh UAC elevation each time the active workspace changes.
/// Overridable through `RUNSEAL_WINDOWS_SANDBOX_HOME` for managed installs
/// and tests; falls back to the legacy workspace-scoped location only when no
/// user-level app-data root is available.
fn machine_windows_sandbox_home(cwd: &Path) -> PathBuf {
    if let Some(home) = std::env::var_os("RUNSEAL_WINDOWS_SANDBOX_HOME") {
        // Resolve once to an absolute path so the caller and the scheduled
        // broker agree regardless of each process's working directory. A
        // relative override would point the broker at a different directory
        // than the caller and silently skip setup.
        let home_path = PathBuf::from(home);
        return std::path::absolute(home_path.clone()).unwrap_or(home_path);
    }
    std::env::var_os("LOCALAPPDATA")
        .map(|root| PathBuf::from(root).join("RunSeal").join("windows-sandbox"))
        .unwrap_or_else(|| cwd.join(".runseal").join("sandbox"))
}

#[cfg(windows)]
pub(crate) fn windows_sandbox_home(cwd: &Path) -> PathBuf {
    machine_windows_sandbox_home(cwd)
}

pub(crate) fn vendor_sandbox_home(cwd: &Path) -> PathBuf {
    machine_windows_sandbox_home(cwd)
}

#[cfg(windows)]
fn prepare_vendor_sandbox_home(cwd: &Path, home: &Path) -> io::Result<()> {
    let expected = normalize_lexical(&vendor_sandbox_home(cwd));
    if normalize_lexical(home) != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to prepare sandbox home outside planned location: {}",
                home.display()
            ),
        ));
    }
    // The machine-level home lives outside the workspace, so validate its
    // entire ancestor chain rather than only the workspace-scoped prefix.
    for ancestor in expected.ancestors() {
        validate_runtime_root_not_symlink(ancestor, "prepare")?;
    }
    fs::create_dir_all(home)?;
    validate_runtime_tree_has_no_symlinks(home, "prepare")
}

#[cfg(windows)]
fn sandbox_environment(
    plan: &PlatformSandboxPlan,
    env: &ExecutionEnv,
    managed_proxy: Option<&ManagedSandboxProxy>,
) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for (key, value) in minimal_environment(plan) {
        result.insert(
            key.to_string_lossy().to_ascii_uppercase(),
            value.to_string_lossy().into_owned(),
        );
    }
    result.extend(
        env.entries
            .iter()
            .map(|(key, value)| (key.to_ascii_uppercase(), value.clone())),
    );
    if let Some(proxy) = managed_proxy {
        for (key, value) in proxy.environment() {
            result.insert(key.to_ascii_uppercase(), value);
        }
    }
    result
}

#[cfg(windows)]
fn managed_proxy_settings(
    managed_proxy: Option<&ManagedSandboxProxy>,
) -> Option<codex_windows_sandbox::SandboxProxySettings> {
    managed_proxy.map(|proxy| {
        codex_windows_sandbox::SandboxProxySettings::loopback_proxy(proxy.addr().port())
    })
}

#[cfg(windows)]
fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn managed_proxy_settings_use_the_active_loopback_port() {
        let proxy = ManagedSandboxProxy::start().expect("start managed proxy");
        let settings = managed_proxy_settings(Some(&proxy)).expect("proxy settings");

        assert_eq!(settings.proxy_ports, vec![proxy.addr().port()]);
        assert!(!settings.allow_local_binding);
        assert!(managed_proxy_settings(None).is_none());
    }
}
