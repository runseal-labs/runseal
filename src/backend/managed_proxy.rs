use crate::events::timestamp_now;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::OnceLock;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use std::{
    fs::DirBuilder,
    os::unix::{
        fs::DirBuilderExt,
        net::{UnixListener, UnixStream},
        process::ExitStatusExt,
    },
    process::{Command, Stdio},
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const NO_PROXY: &str = "";
const MANAGED_PROXY_PORT: u16 = 43129;
#[cfg(target_os = "linux")]
const LINUX_SANDBOX_PROXY_PORT: u16 = 43129;
#[cfg(target_os = "linux")]
const LINUX_SANDBOX_PROXY_SOCKET: &str = "/run/runseal-proxy/proxy.sock";
const MANAGED_PROXY_BIND_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const MANAGED_PROXY_BIND_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const MANAGED_PROXY_HEALTH_HOST: &str = "runseal.local";
const MANAGED_PROXY_HEALTH_PATH: &str = "/.runseal/managed-proxy/health";
const PROXY_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "GIT_HTTP_PROXY",
    "GIT_HTTPS_PROXY",
];
const NO_PROXY_KEYS: &[&str] = &["NO_PROXY", "no_proxy"];
const PROXY_AUTHORIZATION_KEY: &str = "RUNSEAL_NETWORK_PROXY_AUTHORIZATION";
type ProxyTokenMap = Arc<Mutex<HashMap<String, PathBuf>>>;

pub(super) struct ManagedSandboxProxy {
    inner: Option<Arc<ManagedSandboxProxyState>>,
    addr: SocketAddr,
    token: String,
    event_path: PathBuf,
}

#[cfg(target_os = "linux")]
pub(super) struct LinuxSandboxProxy {
    managed_proxy: ManagedSandboxProxy,
    host_dir: PathBuf,
    host_socket: PathBuf,
    shutdown: Arc<AtomicBool>,
    bridge_thread: Option<JoinHandle<()>>,
}

struct ManagedSandboxProxyState {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    tokens: ProxyTokenMap,
    thread: Option<JoinHandle<()>>,
}

impl ManagedSandboxProxy {
    #[cfg(windows)]
    pub(super) fn start() -> io::Result<Self> {
        static SHARED_PROXY: OnceLock<Mutex<Option<Arc<ManagedSandboxProxyState>>>> =
            OnceLock::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), MANAGED_PROXY_PORT);
        let mut shared = SHARED_PROXY
            .get_or_init(|| Mutex::new(None))
            .lock()
            .map_err(|_| io::Error::other("managed proxy cache lock poisoned"))?;
        if let Some(inner) = shared.as_ref() {
            if inner
                .thread
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
            {
                *shared = None;
            } else {
                return Self::register_owned(Arc::clone(inner));
            }
        }

        if managed_proxy_health_check(addr) {
            return Self::register_external(addr);
        }

        match Self::start_dedicated_on_with_token(addr, new_proxy_token()?) {
            Ok(proxy) => {
                if let Some(inner) = &proxy.inner {
                    *shared = Some(Arc::clone(inner));
                }
                Ok(proxy)
            }
            Err(err)
                if err.kind() == io::ErrorKind::AddrInUse && managed_proxy_health_check(addr) =>
            {
                Self::register_external(addr)
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn start() -> io::Result<Self> {
        Self::start_dedicated_on_with_token(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            new_proxy_token()?,
        )
    }

    #[cfg(windows)]
    fn register_owned(inner: Arc<ManagedSandboxProxyState>) -> io::Result<Self> {
        let token = new_proxy_token()?;
        let event_path = managed_proxy_event_path(&token)?;
        inner.add_token(token.clone(), event_path.clone())?;
        register_managed_proxy_token(&token, &event_path)?;
        Ok(Self {
            addr: inner.addr,
            inner: Some(inner),
            token,
            event_path,
        })
    }

    #[cfg(windows)]
    fn register_external(addr: SocketAddr) -> io::Result<Self> {
        let token = new_proxy_token()?;
        let event_path = managed_proxy_event_path(&token)?;
        register_managed_proxy_token(&token, &event_path)?;
        Ok(Self {
            addr,
            inner: None,
            token,
            event_path,
        })
    }

    fn start_dedicated_on_with_token(addr: SocketAddr, token: String) -> io::Result<Self> {
        let listener = bind_proxy_listener(addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let event_path = managed_proxy_event_path(&token)?;
        let tokens = Arc::new(Mutex::new(HashMap::from([(
            token.clone(),
            event_path.clone(),
        )])));
        let thread_tokens = Arc::clone(&tokens);
        let thread = thread::spawn(move || accept_loop(listener, thread_shutdown, thread_tokens));
        let inner = Arc::new(ManagedSandboxProxyState {
            addr,
            shutdown,
            tokens,
            thread: Some(thread),
        });
        register_managed_proxy_token(&token, &event_path)?;
        Ok(Self {
            addr,
            inner: Some(inner),
            token,
            event_path,
        })
    }

    #[cfg(test)]
    fn start_dedicated_ephemeral() -> io::Result<Self> {
        Self::start_dedicated_on_with_token(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            new_proxy_token()?,
        )
    }

    pub(super) fn environment(&self) -> Vec<(String, String)> {
        self.environment_for_addr(self.addr)
    }

    fn environment_for_addr(&self, addr: SocketAddr) -> Vec<(String, String)> {
        let proxy_url = format!("http://runseal:{}@{addr}", self.token);
        let mut env = vec![
            ("RUNSEAL_NETWORK_PROXY_ACTIVE".to_string(), "1".to_string()),
            (
                PROXY_AUTHORIZATION_KEY.to_string(),
                proxy_basic_auth_value(&self.token),
            ),
            (
                "RUNSEAL_NETWORK_ALLOW_LOCAL_BINDING".to_string(),
                "0".to_string(),
            ),
            ("ELECTRON_GET_USE_PROXY".to_string(), "true".to_string()),
            ("NODE_USE_ENV_PROXY".to_string(), "1".to_string()),
        ];
        env.extend(
            PROXY_KEYS
                .iter()
                .map(|key| ((*key).to_string(), proxy_url.clone())),
        );
        env.extend(
            NO_PROXY_KEYS
                .iter()
                .map(|key| ((*key).to_string(), NO_PROXY.to_string())),
        );
        env
    }

    pub(super) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(super) fn drain_events(&self) -> Vec<Value> {
        drain_proxy_events(&self.event_path).unwrap_or_default()
    }
}

#[cfg(target_os = "linux")]
impl LinuxSandboxProxy {
    pub(super) fn start() -> io::Result<Self> {
        let managed_proxy = ManagedSandboxProxy::start()?;
        let host_dir = create_linux_proxy_bridge_dir()?;
        let host_socket = host_dir.join("proxy.sock");
        let listener = match UnixListener::bind(&host_socket) {
            Ok(listener) => listener,
            Err(err) => {
                let _ = fs::remove_dir(&host_dir);
                return Err(err);
            }
        };
        if let Err(err) = listener.set_nonblocking(true) {
            let _ = fs::remove_file(&host_socket);
            let _ = fs::remove_dir(&host_dir);
            return Err(err);
        }
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let target = managed_proxy.addr();
        let bridge_thread = thread::spawn(move || {
            linux_proxy_bridge_accept_loop(listener, target, thread_shutdown);
        });
        Ok(Self {
            managed_proxy,
            host_dir,
            host_socket,
            shutdown,
            bridge_thread: Some(bridge_thread),
        })
    }

    pub(super) fn environment(&self) -> Vec<(String, String)> {
        self.managed_proxy.environment_for_addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            LINUX_SANDBOX_PROXY_PORT,
        ))
    }

    pub(super) fn host_dir(&self) -> &Path {
        &self.host_dir
    }

    pub(super) fn drain_events(&self) -> Vec<Value> {
        self.managed_proxy.drain_events()
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxSandboxProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = UnixStream::connect(&self.host_socket);
        if let Some(thread) = self.bridge_thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.host_socket);
        let _ = fs::remove_dir(&self.host_dir);
    }
}

impl Drop for ManagedSandboxProxy {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            inner.remove_token(&self.token);
        }
        let _ = unregister_managed_proxy_token(&self.token);
        let _ = fs::remove_file(&self.event_path);
    }
}

impl ManagedSandboxProxyState {
    #[cfg(windows)]
    fn add_token(&self, token: String, event_path: PathBuf) -> io::Result<()> {
        self.tokens
            .lock()
            .map_err(|_| io::Error::other("managed proxy token lock poisoned"))?
            .insert(token, event_path);
        Ok(())
    }

    fn remove_token(&self, token: &str) {
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.remove(token);
        }
    }
}

fn bind_proxy_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let started_at = Instant::now();
    loop {
        match TcpListener::bind(addr) {
            Ok(listener) => return Ok(listener),
            Err(err)
                if addr.port() == MANAGED_PROXY_PORT
                    && err.kind() == io::ErrorKind::AddrInUse
                    && started_at.elapsed() < MANAGED_PROXY_BIND_RETRY_TIMEOUT =>
            {
                thread::sleep(MANAGED_PROXY_BIND_RETRY_INTERVAL);
            }
            Err(err) if addr.port() == MANAGED_PROXY_PORT => {
                return Err(io::Error::new(
                    err.kind(),
                    format!("fixed managed proxy port {addr} is unavailable: {err}"),
                ));
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(windows)]
fn managed_proxy_health_check(addr: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) else {
        return false;
    };
    let request = format!(
        "GET http://{MANAGED_PROXY_HEALTH_HOST}{MANAGED_PROXY_HEALTH_PATH} HTTP/1.1\r\nHost: {MANAGED_PROXY_HEALTH_HOST}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = [0_u8; 128];
    let Ok(read) = stream.read(&mut response) else {
        return false;
    };
    String::from_utf8_lossy(&response[..read]).starts_with("HTTP/1.1 204 RunSeal Managed Proxy")
}

impl Drop for ManagedSandboxProxyState {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn accept_loop(listener: TcpListener, shutdown: Arc<AtomicBool>, tokens: ProxyTokenMap) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, _)) => {
                if client.set_nonblocking(false).is_err() {
                    continue;
                }
                let tokens = Arc::clone(&tokens);
                thread::spawn(move || {
                    let _ = handle_client(client, tokens);
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

#[cfg(target_os = "linux")]
fn create_linux_proxy_bridge_dir() -> io::Result<PathBuf> {
    for _ in 0..16 {
        let suffix: String = new_proxy_token()?.chars().take(24).collect();
        let path = std::env::temp_dir().join(format!("runseal-proxy-{suffix}"));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a private managed proxy bridge directory",
    ))
}

#[cfg(target_os = "linux")]
fn linux_proxy_bridge_accept_loop(
    listener: UnixListener,
    target: SocketAddr,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, _)) => {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if client.set_nonblocking(false).is_err() {
                    continue;
                }
                thread::spawn(move || {
                    let Ok(upstream) = TcpStream::connect_timeout(&target, Duration::from_secs(2))
                    else {
                        return;
                    };
                    let _ = copy_tcp_unix(upstream, client);
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn run_linux_proxy_relay(command: &[String]) -> Result<i32, String> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| "internal Linux proxy relay requires a command".to_string())?;
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, LINUX_SANDBOX_PROXY_PORT)).map_err(|_| {
            "internal Linux proxy relay could not bind its loopback endpoint".to_string()
        })?;
    listener.set_nonblocking(true).map_err(|_| {
        "internal Linux proxy relay could not configure its loopback endpoint".to_string()
    })?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = Arc::clone(&shutdown);
    let relay_thread = thread::spawn(move || {
        linux_sandbox_relay_accept_loop(listener, thread_shutdown);
    });

    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();

    shutdown.store(true, Ordering::Relaxed);
    let _ = TcpStream::connect((Ipv4Addr::LOCALHOST, LINUX_SANDBOX_PROXY_PORT));
    let _ = relay_thread.join();

    let status =
        status.map_err(|_| "internal Linux proxy relay could not start command".to_string())?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
}

#[cfg(target_os = "linux")]
fn linux_sandbox_relay_accept_loop(listener: TcpListener, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, _)) => {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if client.set_nonblocking(false).is_err() {
                    continue;
                }
                thread::spawn(move || {
                    let Ok(bridge) = UnixStream::connect(LINUX_SANDBOX_PROXY_SOCKET) else {
                        return;
                    };
                    let _ = copy_tcp_unix(client, bridge);
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

#[cfg(target_os = "linux")]
fn copy_tcp_unix(mut tcp: TcpStream, mut unix: UnixStream) -> io::Result<()> {
    let mut tcp_reader = tcp.try_clone()?;
    let mut unix_writer = unix.try_clone()?;
    let writer = thread::spawn(move || {
        let result = io::copy(&mut tcp_reader, &mut unix_writer);
        let _ = unix_writer.shutdown(Shutdown::Write);
        result
    });
    let reader_result = io::copy(&mut unix, &mut tcp);
    let _ = tcp.shutdown(Shutdown::Write);
    let writer_result = writer
        .join()
        .map_err(|_| io::Error::other("Linux managed proxy relay thread panicked"))?;
    match (reader_result, writer_result) {
        (Ok(_), Ok(_)) => Ok(()),
        (Err(reader_err), Ok(_)) => Err(reader_err),
        (Ok(_), Err(writer_err)) => Err(writer_err),
        (Err(reader_err), Err(writer_err)) => Err(io::Error::other(format!(
            "Linux managed proxy relay read failed ({reader_err}); write failed ({writer_err})"
        ))),
    }
}
fn handle_client(mut client: TcpStream, tokens: ProxyTokenMap) -> io::Result<()> {
    let mut buffer = Vec::with_capacity(4096);
    loop {
        let mut chunk = [0_u8; 4096];
        let read = client.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(invalid_proxy_request("proxy request header is too large"));
        }
        if let Some(header_end) = find_header_end(&buffer) {
            let body_prefix = buffer[header_end..].to_vec();
            let header = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
            if is_managed_proxy_health_request(&header) {
                client.write_all(b"HTTP/1.1 204 RunSeal Managed Proxy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                return Ok(());
            }
            let Some(events) = authorized_proxy_request(&header, &tokens)? else {
                client.write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"runseal\"\r\nContent-Length: 0\r\n\r\n",
                )?;
                return Ok(());
            };
            let started_at = Instant::now();
            let result = forward_request(client, &header, &body_prefix);
            record_proxy_request_event(&events, &header, started_at.elapsed(), result.as_ref());
            return result;
        }
    }
}

fn authorized_proxy_request(
    header: &str,
    tokens: &Mutex<HashMap<String, PathBuf>>,
) -> io::Result<Option<PathBuf>> {
    let Some(actual) = header_value(header, "Proxy-Authorization") else {
        return Ok(None);
    };
    let tokens = tokens
        .lock()
        .map_err(|_| io::Error::other("managed proxy token lock poisoned"))?;
    Ok(tokens
        .iter()
        .find_map(|(token, event_path)| {
            (actual == proxy_basic_auth_value(token)).then(|| event_path.clone())
        })
        .or_else(|| {
            actual
                .strip_prefix("Basic ")
                .and_then(|encoded| STANDARD.decode(encoded).ok())
                .and_then(|decoded| String::from_utf8(decoded).ok())
                .and_then(|decoded| decoded.strip_prefix("runseal:").map(str::to_string))
                .and_then(|token| managed_proxy_registered_event_path(&token).ok().flatten())
        }))
}

fn is_managed_proxy_health_request(header: &str) -> bool {
    let request_line = header.split("\r\n").next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    method.eq_ignore_ascii_case("GET")
        && (target == MANAGED_PROXY_HEALTH_PATH
            || target == format!("http://{MANAGED_PROXY_HEALTH_HOST}{MANAGED_PROXY_HEALTH_PATH}"))
}

fn proxy_basic_auth_value(token: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("runseal:{token}")))
}

fn record_proxy_request_event(
    event_path: &Path,
    header: &str,
    duration: Duration,
    result: Result<&(), &io::Error>,
) {
    let request = proxy_request_metadata(header);
    let (event_type, decision) = if result.is_ok() {
        ("execution.network.request", "allowed")
    } else {
        ("execution.network.error", "error")
    };
    let mut event = json!({
        "type": event_type,
        "time": timestamp_now(),
        "decision": decision,
        "method": request.method,
        "scheme": request.scheme,
        "host": request.host,
        "path": request.path,
        "duration_ms": duration.as_millis(),
    });
    if let (Some(object), Err(err)) = (event.as_object_mut(), result) {
        object.insert("reason".to_string(), json!(err.to_string()));
    }
    let _ = append_proxy_event(event_path, &event);
}

fn managed_proxy_event_path(token: &str) -> io::Result<PathBuf> {
    let dir = managed_proxy_state_dir().join("events");
    fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{token}.jsonl")))
}

fn managed_proxy_token_path(token: &str) -> io::Result<PathBuf> {
    let dir = managed_proxy_state_dir().join("tokens");
    fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{token}.json")))
}

fn managed_proxy_state_dir() -> PathBuf {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return PathBuf::from(appdata).join("RunSeal").join("managed-proxy");
    }
    std::env::temp_dir().join("RunSeal").join("managed-proxy")
}

fn register_managed_proxy_token(token: &str, event_path: &Path) -> io::Result<()> {
    let path = managed_proxy_token_path(token)?;
    fs::write(
        path,
        json!({
            "pid": std::process::id(),
            "event_path": event_path.to_string_lossy(),
        })
        .to_string(),
    )
}

fn unregister_managed_proxy_token(token: &str) -> io::Result<()> {
    match fs::remove_file(managed_proxy_token_path(token)?) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn managed_proxy_registered_event_path(token: &str) -> io::Result<Option<PathBuf>> {
    let path = managed_proxy_token_path(token)?;
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let value: Value = serde_json::from_str(&contents).map_err(io::Error::other)?;
    let Some(pid) = value
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
    else {
        return Ok(None);
    };
    if !process_is_running(pid) {
        let _ = unregister_managed_proxy_token(token);
        return Ok(None);
    }
    Ok(value
        .get("event_path")
        .and_then(Value::as_str)
        .map(PathBuf::from))
}

fn process_is_running(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    process_is_running_platform(pid)
}

#[cfg(windows)]
fn process_is_running_platform(pid: u32) -> bool {
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const WAIT_TIMEOUT: u32 = 0x102;
    let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let wait = unsafe { WaitForSingleObject(handle, 0) };
    unsafe {
        CloseHandle(handle);
    }
    wait == WAIT_TIMEOUT
}

#[cfg(unix)]
fn process_is_running_platform(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn append_proxy_event(path: &Path, event: &Value) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{event}")
}

fn drain_proxy_events(path: &Path) -> io::Result<Vec<Value>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    if contents.is_empty() || !contents.ends_with('\n') {
        return Ok(Vec::new());
    }
    let events = contents
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>();
    let Ok(events) = events else {
        return Ok(Vec::new());
    };
    let _ = fs::write(path, "");
    Ok(events)
}

struct ProxyRequestMetadata {
    method: String,
    scheme: String,
    host: String,
    path: String,
}

fn proxy_request_metadata(header: &str) -> ProxyRequestMetadata {
    let request_line = header.split("\r\n").next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default();
    let (scheme, host, path) = if method == "CONNECT" {
        (
            "https".to_string(),
            host_without_port(target),
            String::new(),
        )
    } else if let Some(rest) = strip_http_scheme(target) {
        let (authority, path) = split_proxy_target_for_audit(rest);
        ("http".to_string(), host_without_port(authority), path)
    } else {
        (
            "http".to_string(),
            find_host_header(header)
                .map(|host| host_without_port(&host))
                .unwrap_or_default(),
            path_without_query(target),
        )
    };
    ProxyRequestMetadata {
        method,
        scheme,
        host,
        path,
    }
}

fn split_proxy_target_for_audit(rest: &str) -> (&str, String) {
    match rest.split_once('/') {
        Some((authority, path)) => (authority, path_without_query(&format!("/{path}"))),
        None => match rest.split_once('?') {
            Some((authority, _)) => (authority, "/".to_string()),
            None => (rest, "/".to_string()),
        },
    }
}

fn path_without_query(path: &str) -> String {
    path.split_once('?')
        .map_or(path, |(path, _)| path)
        .to_string()
}

fn host_without_port(authority: &str) -> String {
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, value)| value);
    if let Some(host) = authority.strip_prefix('[') {
        return host
            .split_once(']')
            .map_or(authority, |(host, _)| host)
            .to_string();
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
        .to_string()
}

fn forward_request(mut client: TcpStream, header: &str, body_prefix: &[u8]) -> io::Result<()> {
    let request_line = header
        .split("\r\n")
        .next()
        .ok_or_else(|| invalid_proxy_request("proxy request missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| invalid_proxy_request("proxy request missing method"))?;
    let target = parts
        .next()
        .ok_or_else(|| invalid_proxy_request("proxy request missing target"))?;
    let version = parts
        .next()
        .ok_or_else(|| invalid_proxy_request("proxy request missing version"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let mut upstream = TcpStream::connect(authority_with_default_port(target, 443)?)?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        if !body_prefix.is_empty() {
            upstream.write_all(body_prefix)?;
        }
        return copy_bidirectional(client, upstream);
    }

    let (upstream_addr, rewritten) = rewrite_plain_http_request(method, target, version, header)?;
    let mut upstream = TcpStream::connect(upstream_addr)?;
    upstream.write_all(rewritten.as_bytes())?;
    upstream.write_all(body_prefix)?;
    copy_bidirectional(client, upstream)
}

fn copy_bidirectional(mut client: TcpStream, mut upstream: TcpStream) -> io::Result<()> {
    let mut client_to_upstream = client.try_clone()?;
    let mut upstream_for_client = upstream.try_clone()?;
    let writer = thread::spawn(move || {
        let result = io::copy(&mut client_to_upstream, &mut upstream_for_client);
        let _ = upstream_for_client.shutdown(Shutdown::Write);
        result
    });
    let reader_result = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let writer_result = writer
        .join()
        .map_err(|_| io::Error::other("managed proxy tunnel writer thread panicked"))?;
    match (reader_result, writer_result) {
        (Ok(_), Ok(_)) => Ok(()),
        (Err(reader_err), Ok(_)) => Err(reader_err),
        (Ok(_), Err(writer_err)) => Err(writer_err),
        (Err(reader_err), Err(writer_err)) => Err(io::Error::other(format!(
            "managed proxy tunnel read failed ({reader_err}); write failed ({writer_err})"
        ))),
    }
}

fn rewrite_plain_http_request(
    method: &str,
    target: &str,
    version: &str,
    header: &str,
) -> io::Result<(String, String)> {
    let (upstream_addr, path) = if let Some(rest) = strip_http_scheme(target) {
        split_http_url(rest)?
    } else {
        let host = find_host_header(header)
            .ok_or_else(|| invalid_proxy_request("plain HTTP proxy request missing Host header"))?;
        (authority_with_default_port(&host, 80)?, target.to_string())
    };

    let mut rewritten = format!("{method} {path} {version}\r\n");
    for line in header.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if line.split_once(':').is_some_and(|(name, _)| {
            name.eq_ignore_ascii_case("Proxy-Connection")
                || name.eq_ignore_ascii_case("Proxy-Authorization")
                || name.eq_ignore_ascii_case("Connection")
        }) {
            continue;
        }
        rewritten.push_str(line);
        rewritten.push_str("\r\n");
    }
    rewritten.push_str("Connection: close\r\n");
    rewritten.push_str("\r\n");
    Ok((upstream_addr, rewritten))
}

fn strip_http_scheme(target: &str) -> Option<&str> {
    let scheme = target.get(.."http://".len())?;
    let rest = target.get("http://".len()..)?;
    scheme.eq_ignore_ascii_case("http://").then_some(rest)
}

fn split_http_url(rest: &str) -> io::Result<(String, String)> {
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => match rest.split_once('?') {
            Some((authority, query)) => (authority, format!("/?{query}")),
            None => (rest, "/".to_string()),
        },
    };
    Ok((authority_with_default_port(authority, 80)?, path))
}

fn authority_with_default_port(authority: &str, default_port: u16) -> io::Result<String> {
    if authority.is_empty() {
        return Err(invalid_proxy_request("proxy target missing host"));
    }
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, value)| value);
    if authority.starts_with('[') {
        if let Some((host, rest)) = authority.split_once(']')
            && rest.is_empty()
        {
            return Ok(format!("{host}]:{default_port}"));
        }
        return Ok(authority.to_string());
    }
    if authority.rsplit_once(':').is_some() {
        return Ok(authority.to_string());
    }
    Ok(format!("{authority}:{default_port}"))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn find_host_header(header: &str) -> Option<String> {
    header_value(header, "Host")
}

fn header_value(header: &str, header_name: &str) -> Option<String> {
    header.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(header_name)
            .then(|| value.trim().to_string())
    })
}

fn invalid_proxy_request(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn new_proxy_token() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_sets_loopback_proxy_for_vendor_guard() {
        let proxy = ManagedSandboxProxy::start().expect("start proxy");
        let env = proxy.environment();
        assert!(env.iter().any(|(key, value)| key == "HTTP_PROXY"
            && value.starts_with("http://runseal:")
            && value.ends_with(&format!("@{}", proxy.addr))));
        let proxy_url = env
            .iter()
            .find_map(|(key, value)| (key == "HTTP_PROXY").then_some(value.as_str()))
            .expect("HTTP_PROXY");
        assert_eq!(
            proxy_url,
            format!("http://runseal:{}@{}", proxy.token, proxy.addr)
        );
        assert!(env.iter().any(|(key, value)| {
            key == PROXY_AUTHORIZATION_KEY && value == &proxy_basic_auth_value(&proxy.token)
        }));
        for key in [
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "GIT_HTTP_PROXY",
            "GIT_HTTPS_PROXY",
        ] {
            assert!(
                env.iter()
                    .any(|(name, value)| name == key && value == proxy_url)
            );
        }
        assert!(
            env.iter()
                .any(|(key, value)| key == "RUNSEAL_NETWORK_PROXY_ACTIVE" && value == "1")
        );
        assert!(
            env.iter()
                .any(|(key, value)| key == "RUNSEAL_NETWORK_ALLOW_LOCAL_BINDING" && value == "0")
        );
        for key in ["NO_PROXY", "no_proxy"] {
            assert!(
                env.iter()
                    .any(|(name, value)| name == key && value.is_empty())
            );
        }
        assert!(!env.iter().any(|(key, _)| key.starts_with("CODEX_")));
    }

    #[cfg(windows)]
    #[test]
    fn reuses_active_proxy_listener() {
        let first = ManagedSandboxProxy::start().expect("start first proxy");
        let first_url = first
            .environment()
            .into_iter()
            .find_map(|(key, value)| (key == "HTTP_PROXY").then_some(value))
            .expect("first HTTP_PROXY");
        let second = ManagedSandboxProxy::start().expect("start second proxy");
        let second_url = second
            .environment()
            .into_iter()
            .find_map(|(key, value)| (key == "HTTP_PROXY").then_some(value))
            .expect("second HTTP_PROXY");

        assert_eq!(first.addr, second.addr);
        assert_ne!(first_url, second_url);
    }

    #[cfg(windows)]
    #[test]
    fn shared_proxy_listener_survives_handle_drop() {
        let first = ManagedSandboxProxy::start().expect("start first proxy");
        let addr = first.addr;
        drop(first);

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))
            .expect("shared proxy listener should stay alive for process reuse");
        drop(stream);

        let second = ManagedSandboxProxy::start().expect("start second proxy");
        assert_eq!(second.addr, addr);
    }

    #[test]
    fn drops_listener_when_last_proxy_handle_drops() {
        let proxy = ManagedSandboxProxy::start_dedicated_ephemeral().expect("start proxy");
        let addr = proxy.addr;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))
            .expect("proxy listener should accept while proxy is alive");
        drop(stream);

        drop(proxy);

        assert!(
            TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err(),
            "managed proxy listener must stop after the last proxy handle drops"
        );
    }

    #[test]
    fn rewrites_plain_http_absolute_form() {
        let request = "GET http://example.test:8080/a?q=1 HTTP/1.1\r\nHost: example.test:8080\r\nProxy-Connection: keep-alive\r\n\r\n";
        let (upstream, rewritten) = rewrite_plain_http_request(
            "GET",
            "http://example.test:8080/a?q=1",
            "HTTP/1.1",
            request,
        )
        .expect("rewrite");
        assert_eq!(upstream, "example.test:8080");
        assert!(rewritten.starts_with("GET /a?q=1 HTTP/1.1\r\n"));
        assert!(!rewritten.contains("Proxy-Connection"));
        assert!(rewritten.contains("Connection: close\r\n"));

        let request = "GET HTTP://example.test/upper HTTP/1.1\r\nHost: ignored.test\r\n\r\n";
        let (upstream, rewritten) =
            rewrite_plain_http_request("GET", "HTTP://example.test/upper", "HTTP/1.1", request)
                .expect("rewrite uppercase scheme");
        assert_eq!(upstream, "example.test:80");
        assert!(rewritten.starts_with("GET /upper HTTP/1.1\r\n"));

        let request = "GET http://example.test?only=query HTTP/1.1\r\nHost: ignored.test\r\n\r\n";
        let (upstream, rewritten) = rewrite_plain_http_request(
            "GET",
            "http://example.test?only=query",
            "HTTP/1.1",
            request,
        )
        .expect("rewrite query-only absolute URI");
        assert_eq!(upstream, "example.test:80");
        assert!(rewritten.starts_with("GET /?only=query HTTP/1.1\r\n"));
        assert_eq!(strip_http_scheme("\u{00e9}\u{00e9}\u{00e9}\u{00e9}"), None);
    }

    #[test]
    fn adds_default_ports() {
        assert_eq!(
            authority_with_default_port("example.test", 80).unwrap(),
            "example.test:80"
        );
        assert_eq!(
            authority_with_default_port("[::1]", 443).unwrap(),
            "[::1]:443"
        );
    }

    #[test]
    fn proxies_plain_http_to_loopback_server() {
        let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream addr");
        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().expect("accept upstream");
            let mut request = [0_u8; 256];
            let read = stream.read(&mut request).expect("read upstream request");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /ok HTTP/1.1\r\n"));
            assert!(!request.contains("Proxy-Authorization"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .expect("write upstream response");
        });

        let proxy = ManagedSandboxProxy::start().expect("start proxy");
        let mut client = TcpStream::connect(proxy.addr).expect("connect proxy");
        let auth = proxy_basic_auth_value(&proxy.token);
        client
            .write_all(
                format!(
                    "GET http://{upstream_addr}/ok HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Authorization: {auth}\r\n\r\n"
                )
                    .as_bytes(),
            )
            .expect("write proxy request");
        client
            .shutdown(Shutdown::Write)
            .expect("close request side");
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("read proxy response");
        assert!(response.ends_with("\r\n\r\nok"));
        upstream_thread.join().expect("upstream thread");
        let events = wait_for_proxy_events(&proxy);
        let event = events
            .iter()
            .find(|event| event["type"] == "execution.network.request")
            .expect("proxy request audit event");
        assert_eq!(event["decision"], "allowed");
        assert_eq!(event["method"], "GET");
        assert_eq!(event["scheme"], "http");
        assert_eq!(event["host"], "127.0.0.1");
        assert_eq!(event["path"], "/ok");
    }

    #[test]
    fn tunnels_connect_bytes_to_loopback_server() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let upstream_thread = thread::spawn(move || {
            let (mut connection, _) = upstream.accept().expect("accept upstream");
            let mut request = [0_u8; 4];
            connection
                .read_exact(&mut request)
                .expect("read tunnel bytes");
            assert_eq!(&request, b"ping");
            connection.write_all(b"pong").expect("write tunnel bytes");
        });
        let proxy = ManagedSandboxProxy::start_dedicated_ephemeral().expect("start proxy");
        let mut client = TcpStream::connect(proxy.addr).expect("connect proxy");
        client
            .write_all(
                format!(
                    "CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",
                    proxy_basic_auth_value(&proxy.token)
                )
                .as_bytes(),
            )
            .expect("write CONNECT request");
        let mut response = [0_u8; 128];
        let count = client.read(&mut response).expect("read CONNECT response");
        assert!(
            String::from_utf8_lossy(&response[..count])
                .starts_with("HTTP/1.1 200 Connection Established")
        );
        client.write_all(b"ping").expect("write tunnel payload");
        let mut reply = [0_u8; 4];
        client.read_exact(&mut reply).expect("read tunnel payload");
        assert_eq!(&reply, b"pong");
        upstream_thread.join().expect("join upstream");
    }

    #[test]
    fn rejects_proxy_requests_without_token() {
        let proxy = ManagedSandboxProxy::start().expect("start proxy");
        let mut client = TcpStream::connect(proxy.addr).expect("connect proxy");
        client
            .write_all(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .expect("write proxy request");

        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("read proxy response");

        assert!(response.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));
    }

    #[test]
    fn accepts_registered_cross_process_token() {
        let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream addr");
        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().expect("accept upstream");
            let mut request = [0_u8; 256];
            let read = stream.read(&mut request).expect("read upstream request");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /external HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .expect("write upstream response");
        });

        let proxy = ManagedSandboxProxy::start_dedicated_ephemeral().expect("start proxy");
        let token = new_proxy_token().expect("token");
        let event_path = managed_proxy_event_path(&token).expect("event path");
        register_managed_proxy_token(&token, &event_path).expect("register token");

        let mut client = TcpStream::connect(proxy.addr).expect("connect proxy");
        let auth = proxy_basic_auth_value(&token);
        client
            .write_all(
                format!(
                    "GET http://{upstream_addr}/external HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Authorization: {auth}\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("write proxy request");
        client
            .shutdown(Shutdown::Write)
            .expect("close request side");
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("read proxy response");
        assert!(response.ends_with("\r\n\r\nok"));
        upstream_thread.join().expect("upstream thread");

        let events = wait_for_proxy_events_at(&event_path);
        assert!(
            events
                .iter()
                .any(|event| event["type"] == "execution.network.request"
                    && event["path"] == "/external")
        );

        unregister_managed_proxy_token(&token).expect("unregister token");
        let _ = fs::remove_file(event_path);
    }

    #[test]
    fn records_proxy_error_events_without_query_or_credentials() {
        let proxy = ManagedSandboxProxy::start_dedicated_ephemeral().expect("start proxy");
        let unused_listener = TcpListener::bind("127.0.0.1:0").expect("bind unused port");
        let unused_addr = unused_listener.local_addr().expect("unused addr");
        drop(unused_listener);

        let mut client = TcpStream::connect(proxy.addr).expect("connect proxy");
        let auth = proxy_basic_auth_value(&proxy.token);
        client
            .write_all(
                format!(
                    "GET http://{unused_addr}/secret?token=hidden HTTP/1.1\r\nHost: {unused_addr}\r\nProxy-Authorization: {auth}\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("write proxy request");
        let mut response = String::new();
        let _ = client.read_to_string(&mut response);

        let events = wait_for_proxy_events(&proxy);
        let event = events
            .iter()
            .find(|event| event["type"] == "execution.network.error")
            .expect("proxy error audit event");
        assert_eq!(event["decision"], "error");
        assert_eq!(event["method"], "GET");
        assert_eq!(event["scheme"], "http");
        assert_eq!(event["host"], "127.0.0.1");
        assert_eq!(event["path"], "/secret");
        assert!(!event.to_string().contains("hidden"));
        assert!(!event.to_string().contains(&auth));
    }

    fn wait_for_proxy_events(proxy: &ManagedSandboxProxy) -> Vec<Value> {
        wait_for_proxy_events_at(&proxy.event_path)
    }

    fn wait_for_proxy_events_at(path: &Path) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let events = drain_proxy_events(path).expect("drain events");
            if !events.is_empty() || Instant::now() >= deadline {
                return events;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
