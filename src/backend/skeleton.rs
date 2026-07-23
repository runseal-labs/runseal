use super::*;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default)]
pub struct LocalBackend;

impl SandboxBackend for LocalBackend {
    fn name(&self) -> &'static str {
        "runseal-local"
    }

    fn status(&self) -> &'static str {
        "local-baseline"
    }

    fn platform(&self) -> &'static str {
        host_platform()
    }

    fn supported_features(&self) -> &'static [BackendFeature] {
        &[]
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        compile_local_execution_or_unsupported(self, execution_id, cwd, policy)
    }

    fn execute_plan(
        &self,
        plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
        stdin: ExecutionStdin,
        env: &ExecutionEnv,
        timeout: Option<Duration>,
    ) -> io::Result<BackendExecutionOutput> {
        spawn_local_command(plan, command, cwd, stdin, env, timeout)
    }

    fn capabilities_json(&self) -> Value {
        capabilities_json_for(
            self,
            &[
                "danger-full-access is explicit local execution with no sandbox guarantee",
                "sandboxed policies require a platform backend and fail closed in this build",
            ],
        )
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct MacosExperimentalBackend;

impl SandboxBackend for MacosExperimentalBackend {
    fn name(&self) -> &'static str {
        "runseal-macos-experimental"
    }

    fn status(&self) -> &'static str {
        "experimental"
    }

    fn platform(&self) -> &'static str {
        "macos"
    }

    fn supported_features(&self) -> &'static [BackendFeature] {
        &[]
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        compile_macos_plan(self, execution_id, cwd, policy)
    }

    fn execute_plan(
        &self,
        plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
        stdin: ExecutionStdin,
        env: &ExecutionEnv,
        timeout: Option<Duration>,
    ) -> io::Result<BackendExecutionOutput> {
        execute_macos_plan(plan, command, cwd, stdin, env, timeout)
    }

    fn capabilities_json(&self) -> Value {
        let mut payload = capabilities_json_for(
            self,
            &[
                "macOS backend is an experimental contribution track",
                "unsupported sandboxed policies fail closed until conformance tests prove enforcement",
            ],
        );
        payload["sandbox_levels"]["read-only"] = json!(CapabilityStatus::Supported.as_str());
        payload["sandbox_levels"]["workspace-write"] = json!(CapabilityStatus::Supported.as_str());
        payload["sandbox_levels"]["workspace-contained"] =
            json!(CapabilityStatus::Supported.as_str());
        payload["network_modes"]["disabled"] = json!(CapabilityStatus::Supported.as_str());
        payload["network_modes"]["proxy"] = json!(CapabilityStatus::Supported.as_str());
        mark_portable_disabled_features_experimental(&mut payload);
        mark_proxy_features_experimental(&mut payload);
        payload["capability_probes"] = crate::macos::capability_probe::capability_probes();
        payload
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxCommunityBackend;

impl SandboxBackend for LinuxCommunityBackend {
    fn name(&self) -> &'static str {
        "runseal-linux-community"
    }

    fn status(&self) -> &'static str {
        "experimental"
    }

    fn platform(&self) -> &'static str {
        "linux"
    }

    fn supported_features(&self) -> &'static [BackendFeature] {
        &[]
    }

    fn compile_plan(
        &self,
        execution_id: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<PlatformSandboxPlan, BackendError> {
        compile_linux_plan(self, execution_id, cwd, policy)
    }

    fn execute_plan(
        &self,
        plan: &PlatformSandboxPlan,
        command: &[String],
        cwd: &Path,
        stdin: ExecutionStdin,
        env: &ExecutionEnv,
        timeout: Option<Duration>,
    ) -> io::Result<BackendExecutionOutput> {
        execute_linux_plan(plan, command, cwd, stdin, env, timeout)
    }

    fn capabilities_json(&self) -> Value {
        let mut payload = capabilities_json_for(
            self,
            &[
                "Linux backend is an experimental contribution track for portable sandboxing",
                "unsupported sandboxed policies fail closed until conformance tests prove enforcement",
            ],
        );
        payload["backend_status"] = json!(self.status());
        payload["sandbox_levels"]["read-only"] = json!(CapabilityStatus::Supported.as_str());
        payload["sandbox_levels"]["workspace-write"] = json!(CapabilityStatus::Supported.as_str());
        payload["sandbox_levels"]["workspace-contained"] =
            json!(CapabilityStatus::Supported.as_str());
        payload["network_modes"]["disabled"] = json!(CapabilityStatus::Supported.as_str());
        payload["network_modes"]["proxy"] = json!(CapabilityStatus::Supported.as_str());
        mark_portable_disabled_features_experimental(&mut payload);
        mark_proxy_features_experimental(&mut payload);
        payload["capability_probes"] = crate::linux::capability_probe::capability_probes();
        payload
    }
}

fn mark_portable_disabled_features_experimental(payload: &mut Value) {
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
        payload["features"][feature] = json!(true);
        payload["feature_statuses"][feature] = json!(CapabilityStatus::Experimental.as_str());
    }
}

fn mark_proxy_features_experimental(payload: &mut Value) {
    for feature in ["network_proxy", "managed_proxy"] {
        payload["features"][feature] = json!(true);
        payload["feature_statuses"][feature] = json!(CapabilityStatus::Experimental.as_str());
    }
}

fn compile_local_execution_or_unsupported(
    backend: &dyn SandboxBackend,
    execution_id: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<PlatformSandboxPlan, BackendError> {
    if policy.allows_local_execution() {
        Ok(PlatformSandboxPlan::local_execution(
            backend,
            execution_id,
            cwd,
            policy,
        ))
    } else {
        Err(BackendError::unsupported(backend, policy))
    }
}

fn compile_macos_plan(
    backend: &dyn SandboxBackend,
    execution_id: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<PlatformSandboxPlan, BackendError> {
    if policy.allows_local_execution() {
        return Ok(PlatformSandboxPlan::local_execution(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    if policy.sandbox_level == SandboxLevel::ReadOnly && macos_network_mode(policy) {
        return Ok(PlatformSandboxPlan::macos_read_only_experimental(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    if policy.sandbox_level == SandboxLevel::WorkspaceWrite && macos_network_mode(policy) {
        return Ok(PlatformSandboxPlan::macos_workspace_write_experimental(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    if policy.sandbox_level == SandboxLevel::WorkspaceContained && macos_network_mode(policy) {
        return Ok(PlatformSandboxPlan::macos_workspace_contained_experimental(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    Err(BackendError::unsupported_with_plan(
        backend,
        policy,
        Some(PlatformSandboxPlan::portable_fail_closed_preview(
            backend,
            execution_id,
            cwd,
            policy,
        )),
    ))
}

fn compile_linux_plan(
    backend: &dyn SandboxBackend,
    execution_id: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<PlatformSandboxPlan, BackendError> {
    if policy.allows_local_execution() {
        return Ok(PlatformSandboxPlan::local_execution(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    if policy.sandbox_level == SandboxLevel::ReadOnly && portable_network_mode(policy) {
        return Ok(PlatformSandboxPlan::linux_read_only_experimental(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    if policy.sandbox_level == SandboxLevel::WorkspaceWrite && portable_network_mode(policy) {
        return Ok(PlatformSandboxPlan::linux_workspace_write_experimental(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    if policy.sandbox_level == SandboxLevel::WorkspaceContained && portable_network_mode(policy) {
        return Ok(PlatformSandboxPlan::linux_workspace_contained_experimental(
            backend,
            execution_id,
            cwd,
            policy,
        ));
    }
    Err(BackendError::unsupported_with_plan(
        backend,
        policy,
        Some(PlatformSandboxPlan::portable_fail_closed_preview(
            backend,
            execution_id,
            cwd,
            policy,
        )),
    ))
}

fn portable_network_mode(policy: &SandboxPolicy) -> bool {
    matches!(
        policy.network.mode,
        NetworkMode::Unmanaged | NetworkMode::Disabled | NetworkMode::Proxy
    )
}

fn macos_network_mode(policy: &SandboxPolicy) -> bool {
    matches!(
        policy.network.mode,
        NetworkMode::Unmanaged | NetworkMode::Disabled | NetworkMode::Proxy
    )
}

#[cfg(target_os = "linux")]
fn execute_linux_plan(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    if !plan.is_sandbox_enforced() {
        return spawn_local_command(plan, command, cwd, stdin, env, timeout);
    }
    if plan.enforcement != "linux-experimental" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported Linux sandbox enforcement",
        ));
    }
    plan.prepare_runtime_roots()?;
    let output = (|| {
        let managed_proxy = if plan.network_managed_proxy == "required" {
            Some(LinuxSandboxProxy::start().map_err(|_| {
                io::Error::other(BackendUnavailableError {
                    reason: "Linux managed proxy unavailable".to_string(),
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
        let mut execution_env = env.clone();
        if let Some(proxy) = &managed_proxy {
            execution_env.entries.extend(proxy.environment());
        }
        let helper_path = std::env::current_exe().map_err(|_| {
            io::Error::other(BackendUnavailableError {
                reason: "Linux managed proxy helper unavailable".to_string(),
            })
        })?;
        let proxy_launch = managed_proxy.as_ref().map(|proxy| LinuxProxyLaunch {
            host_dir: proxy.host_dir(),
            helper_path: helper_path.as_path(),
        });
        let mut output = spawn_linux_bwrap(
            plan,
            command,
            cwd,
            stdin,
            &execution_env,
            timeout,
            proxy_launch,
        )?;
        if let Some(proxy) = &managed_proxy {
            events.extend(proxy.drain_events());
        }
        output.events.extend(events);
        Ok(output)
    })();
    let cleanup = plan.cleanup_runtime_roots();
    match (output, cleanup) {
        (Ok(output), Ok(_)) => Ok(output),
        (Err(err), Ok(_)) => Err(err),
        (Ok(_), Err(err)) => Err(err),
        (Err(output_err), Err(cleanup_err)) => Err(io::Error::other(format!(
            "Linux sandbox execution failed ({output_err}); runtime cleanup failed ({cleanup_err})"
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
fn execute_linux_plan(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    if !plan.is_sandbox_enforced() {
        return spawn_local_command(plan, command, cwd, stdin, env, timeout);
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux sandbox execution is unavailable on this platform",
    ))
}

fn execute_macos_plan(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
) -> io::Result<BackendExecutionOutput> {
    if !plan.is_sandbox_enforced() {
        return spawn_local_command(plan, command, cwd, stdin, env, timeout);
    }
    if plan.enforcement != "macos-experimental" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported macOS sandbox enforcement",
        ));
    }
    plan.prepare_runtime_roots()?;
    let output = (|| {
        let managed_proxy = if plan.network_managed_proxy == "required" {
            Some(ManagedSandboxProxy::start().map_err(|err| {
                io::Error::other(BackendUnavailableError {
                    reason: format!("macOS managed proxy unavailable: {err}"),
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
        let mut execution_env = env.clone();
        if let Some(proxy) = &managed_proxy {
            execution_env.entries.extend(proxy.environment());
        }
        let mut output = spawn_macos_sandbox_exec(
            plan,
            command,
            cwd,
            stdin,
            &execution_env,
            timeout,
            managed_proxy.as_ref(),
        )?;
        if let Some(proxy) = &managed_proxy {
            events.extend(proxy.drain_events());
        }
        output.events.extend(events);
        Ok(output)
    })();
    let cleanup = plan.cleanup_runtime_roots();
    match (output, cleanup) {
        (Ok(output), Ok(_)) => Ok(output),
        (Err(err), Ok(_)) => Err(err),
        (Ok(_), Err(err)) => Err(err),
        (Err(output_err), Err(cleanup_err)) => Err(io::Error::other(format!(
            "macOS sandbox execution failed ({output_err}); runtime cleanup failed ({cleanup_err})"
        ))),
    }
}

fn spawn_macos_sandbox_exec(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
    managed_proxy: Option<&ManagedSandboxProxy>,
) -> io::Result<BackendExecutionOutput> {
    let profile = macos_profile(plan, cwd, managed_proxy.map(ManagedSandboxProxy::addr))?;
    let mut sandbox_command = vec![
        "/usr/bin/sandbox-exec".to_string(),
        "-p".to_string(),
        profile,
    ];
    sandbox_command.extend(command.iter().cloned());

    let mut runner_plan = plan.clone();
    runner_plan.enforcement = "local-execution";
    runner_plan.process_boundary = "local-process";
    runner_plan.process_cleanup = "direct-child";
    spawn_local_command(&runner_plan, &sandbox_command, cwd, stdin, env, timeout)
}

fn macos_profile(
    plan: &PlatformSandboxPlan,
    _cwd: &Path,
    managed_proxy_addr: Option<std::net::SocketAddr>,
) -> io::Result<String> {
    let workspace_contained = plan.sandbox_level == SandboxLevel::WorkspaceContained.as_str();
    let mut readable_roots = Vec::new();
    if workspace_contained {
        for root in &plan.private_portable_read_roots {
            push_unique_macos_subpath(&mut readable_roots, Path::new(root))?;
        }
    }

    let mut writable_roots = Vec::new();
    for root in &plan.private_portable_write_roots {
        push_unique_macos_subpath(&mut writable_roots, Path::new(root))?;
    }
    for root in [
        plan.runtime_root.as_deref(),
        plan.profile_root.as_deref(),
        plan.synthetic_home.as_deref(),
        plan.temp_root.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        push_unique_macos_subpath(&mut writable_roots, Path::new(root))?;
        if workspace_contained {
            push_unique_macos_subpath(&mut readable_roots, Path::new(root))?;
        }
    }
    if writable_roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "macOS plan requires writable roots",
        ));
    }
    let mut profile = if workspace_contained {
        format!(
            "(version 1)(deny default)(allow process*)(allow sysctl-read)(allow mach-lookup)(allow file-read-metadata)(allow file-read-data (literal \"/\"))(allow file-read* {} {})(allow file-write* {} (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\"))",
            MACOS_CONTAINED_SYSTEM_READ_RULES.join(" "),
            readable_roots.join(" "),
            writable_roots.join(" ")
        )
    } else {
        format!(
            "(version 1)(deny default)(allow process*)(allow sysctl-read)(allow mach-lookup)(allow file-read*)(allow file-write* {})",
            writable_roots.join(" ")
        )
    };
    if plan.network_direct_egress == "unmanaged" {
        profile.push_str("(allow network*)");
    } else if plan.network_managed_proxy == "required" {
        let addr = managed_proxy_addr.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "macOS proxy plan requires a managed proxy endpoint",
            )
        })?;
        if !addr.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "macOS managed proxy endpoint must be loopback",
            ));
        }
        profile.push_str(&format!(
            "(allow network-outbound (remote ip \"localhost:{}\"))",
            addr.port()
        ));
        profile.push_str(MACOS_PROXY_SUPPORT_POLICY);
    }
    for denied_root in &plan.private_portable_deny_roots {
        let denied_root = Path::new(denied_root);
        if denied_root.exists() {
            profile.push_str(&format!(
                "(deny file-read* file-write* (subpath \"{}\"))",
                macos_profile_path_literal(denied_root)?
            ));
        }
    }
    Ok(profile)
}

const MACOS_PROXY_SUPPORT_POLICY: &str = r#"
(allow system-socket
  (require-all
    (socket-domain AF_SYSTEM)
    (socket-protocol 2)
  )
)
(allow mach-lookup
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.networkd")
  (global-name "com.apple.ocspd")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.SystemConfiguration.DNSConfiguration")
  (global-name "com.apple.SystemConfiguration.configd")
)
(allow sysctl-read
  (sysctl-name-regex #"^net.routetable")
)
"#;

const MACOS_CONTAINED_SYSTEM_READ_RULES: &[&str] = &[
    "(subpath \"/bin\")",
    "(subpath \"/sbin\")",
    "(subpath \"/usr/bin\")",
    "(subpath \"/usr/sbin\")",
    "(subpath \"/usr/lib\")",
    "(subpath \"/usr/libexec\")",
    "(subpath \"/usr/share\")",
    "(subpath \"/System\")",
    "(subpath \"/Library\")",
    "(subpath \"/private/etc\")",
    "(subpath \"/private/var/db/timezone\")",
    "(subpath \"/private/var/db/dyld\")",
    "(literal \"/dev/null\")",
    "(literal \"/dev/zero\")",
    "(literal \"/dev/random\")",
    "(literal \"/dev/urandom\")",
];

fn push_unique_macos_subpath(rules: &mut Vec<String>, path: &Path) -> io::Result<()> {
    let rule = format!("(subpath \"{}\")", macos_profile_path_literal(path)?);
    if !rules.contains(&rule) {
        rules.push(rule);
    }
    Ok(())
}

fn macos_profile_path_literal(path: impl AsRef<Path>) -> io::Result<String> {
    let path = std::fs::canonicalize(path)?;
    Ok(macos_profile_literal(&path_string(&path)))
}

fn macos_profile_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "linux")]
struct LinuxProxyLaunch<'a> {
    host_dir: &'a Path,
    helper_path: &'a Path,
}

#[cfg(target_os = "linux")]
const LINUX_PROXY_BRIDGE_DIR: &str = "/run/runseal-proxy";
#[cfg(target_os = "linux")]
const LINUX_PROXY_HELPER_PATH: &str = "/run/runseal-proxy-helper";

#[cfg(target_os = "linux")]
fn spawn_linux_bwrap(
    plan: &PlatformSandboxPlan,
    command: &[String],
    cwd: &Path,
    stdin: ExecutionStdin,
    env: &ExecutionEnv,
    timeout: Option<Duration>,
    proxy_launch: Option<LinuxProxyLaunch<'_>>,
) -> io::Result<BackendExecutionOutput> {
    let mut bwrap_command = vec!["bwrap".to_string()];
    let workspace_contained = plan.sandbox_level == SandboxLevel::WorkspaceContained.as_str();
    if workspace_contained {
        bwrap_command.extend([
            "--tmpfs".to_string(),
            "/run".to_string(),
            "--tmpfs".to_string(),
            "/tmp".to_string(),
        ]);
        for root in LINUX_CONTAINED_SYSTEM_READ_ROOTS {
            bwrap_command.extend([
                "--ro-bind-try".to_string(),
                (*root).to_string(),
                (*root).to_string(),
            ]);
        }
        bwrap_command.extend([
            "--symlink".to_string(),
            "/run".to_string(),
            "/var/run".to_string(),
        ]);
    } else {
        bwrap_command.extend(["--ro-bind".to_string(), "/".to_string(), "/".to_string()]);
        bwrap_command.extend(["--tmpfs".to_string(), "/run".to_string()]);
        if plan.network_direct_egress != "unmanaged" {
            bwrap_command.extend(["--tmpfs".to_string(), "/tmp".to_string()]);
        }
    }

    bwrap_command.extend([
        "--proc".to_string(),
        "/proc".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
    ]);

    if workspace_contained {
        for root in &plan.private_portable_read_roots {
            push_linux_bind(&mut bwrap_command, "--ro-bind", root)?;
        }
    }
    for root in &plan.private_portable_write_roots {
        push_linux_bind(&mut bwrap_command, "--bind", root)?;
    }
    for root in [
        plan.runtime_root.as_deref(),
        plan.profile_root.as_deref(),
        plan.synthetic_home.as_deref(),
        plan.temp_root.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        push_linux_bind(&mut bwrap_command, "--bind", root)?;
    }
    for denied_root in &plan.private_portable_deny_roots {
        push_linux_deny(&mut bwrap_command, Path::new(denied_root))?;
    }
    if let Some(proxy) = &proxy_launch {
        push_linux_bind_to(
            &mut bwrap_command,
            "--ro-bind",
            proxy.host_dir,
            LINUX_PROXY_BRIDGE_DIR,
        )?;
        push_linux_bind_to(
            &mut bwrap_command,
            "--ro-bind",
            proxy.helper_path,
            LINUX_PROXY_HELPER_PATH,
        )?;
    }
    if workspace_contained {
        bwrap_command.extend([
            "--remount-ro".to_string(),
            "/run".to_string(),
            "--remount-ro".to_string(),
            "/tmp".to_string(),
        ]);
    } else if plan.network_direct_egress != "unmanaged" {
        bwrap_command.extend(["--remount-ro".to_string(), "/tmp".to_string()]);
    }
    bwrap_command.extend([
        "--unshare-user".to_string(),
        "--unshare-pid".to_string(),
        "--unshare-ipc".to_string(),
        "--unshare-uts".to_string(),
        "--die-with-parent".to_string(),
        "--clearenv".to_string(),
        "--setenv".to_string(),
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    ]);
    if plan.network_direct_egress != "unmanaged" {
        bwrap_command.push("--unshare-net".to_string());
    }
    for (key, value) in &plan.environment_runtime {
        bwrap_command.extend(["--setenv".to_string(), key.clone(), value.clone()]);
    }
    for (key, value) in &env.entries {
        bwrap_command.extend(["--setenv".to_string(), key.clone(), value.clone()]);
    }
    bwrap_command.extend(["--chdir".to_string(), path_string(cwd), "--".to_string()]);
    if proxy_launch.is_some() {
        bwrap_command.extend([
            LINUX_PROXY_HELPER_PATH.to_string(),
            "__linux-proxy-relay".to_string(),
        ]);
    }
    bwrap_command.extend(command.iter().cloned());

    let mut runner_plan = plan.clone();
    runner_plan.enforcement = "local-execution";
    runner_plan.process_boundary = "local-process";
    runner_plan.process_cleanup = "direct-child";
    spawn_local_command(&runner_plan, &bwrap_command, cwd, stdin, env, timeout)
}

#[cfg(any(target_os = "linux", test))]
const LINUX_CONTAINED_SYSTEM_READ_ROOTS: &[&str] = &[
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib32",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/share",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki",
    "/run/systemd/resolve",
    "/run/NetworkManager",
    "/run/resolvconf",
    "/mnt/wsl/resolv.conf",
];

#[cfg(target_os = "linux")]
fn push_linux_bind(command: &mut Vec<String>, operation: &str, path: &str) -> io::Result<()> {
    let canonical = std::fs::canonicalize(path)?;
    command.extend([
        operation.to_string(),
        path_string(&canonical),
        path.to_string(),
    ]);
    Ok(())
}

#[cfg(target_os = "linux")]
fn push_linux_bind_to(
    command: &mut Vec<String>,
    operation: &str,
    source: &Path,
    destination: &str,
) -> io::Result<()> {
    let canonical = std::fs::canonicalize(source)?;
    command.extend([
        operation.to_string(),
        path_string(&canonical),
        destination.to_string(),
    ]);
    Ok(())
}

#[cfg(target_os = "linux")]
fn push_linux_deny(command: &mut Vec<String>, path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let canonical = std::fs::canonicalize(path)?;
    let destination = path_string(&canonical);
    if canonical.is_dir() {
        command.extend([
            "--tmpfs".to_string(),
            destination.clone(),
            "--remount-ro".to_string(),
            destination,
        ]);
    } else {
        command.extend([
            "--ro-bind".to_string(),
            "/dev/null".to_string(),
            destination,
        ]);
    }
    Ok(())
}

#[cfg(test)]
mod portable_contained_tests {
    use super::*;
    use crate::normalize_policy;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn macos_contained_profile_uses_default_deny_reads() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir_all(workspace.join(".git"))?;
        let policy = normalize_policy(
            &json!("workspace-contained"),
            &workspace,
            Some(NetworkMode::Disabled),
        )
        .map_err(|err| io::Error::other(format!("{err:?}")))?;
        let plan = MacosExperimentalBackend
            .compile_plan("macos_contained_profile", &workspace, &policy)
            .map_err(|err| io::Error::other(format!("{err:?}")))?;
        plan.prepare_runtime_roots()?;

        let profile = macos_profile(&plan, &workspace, None)?;
        assert!(profile.contains("(deny default)"));
        assert!(!profile.contains("(allow file-read*)"));
        assert!(profile.contains("(subpath \"/System\")"));
        assert!(profile.contains(&macos_profile_path_literal(&workspace)?));
        assert!(profile.contains("(deny file-read* file-write*"));

        plan.cleanup_runtime_roots()?;
        Ok(())
    }

    #[test]
    fn macos_proxy_profile_allows_only_managed_loopback_endpoint() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir_all(&workspace)?;
        let policy = normalize_policy(
            &json!({"sandbox_level": "workspace-write", "network": {"mode": "proxy"}}),
            &workspace,
            None,
        )
        .unwrap();
        let plan = MacosExperimentalBackend
            .compile_plan("macos_proxy_profile", &workspace, &policy)
            .unwrap();
        plan.prepare_runtime_roots()?;
        let proxy_addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 43129);

        let profile = macos_profile(&plan, &workspace, Some(proxy_addr))?;

        assert!(profile.contains(r#"(allow network-outbound (remote ip "localhost:43129"))"#));
        assert!(!profile.contains("(allow network*)"));
        assert!(profile.contains("com.apple.trustd.agent"));
        plan.cleanup_runtime_roots()?;
        Ok(())
    }

    #[test]
    fn portable_contained_linux_baseline_excludes_host_profile_roots() {
        for excluded in ["/", "/home", "/root", "/opt", "/usr/local", "/var", "/run"] {
            assert!(
                !LINUX_CONTAINED_SYSTEM_READ_ROOTS.contains(&excluded),
                "contained baseline must not expose {excluded}"
            );
        }
    }
}
