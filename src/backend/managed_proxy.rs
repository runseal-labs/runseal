use crate::events::timestamp_now;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const NO_PROXY: &str = "";
const MANAGED_PROXY_PORT: u16 = 43129;
const MANAGED_PROXY_BIND_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const MANAGED_PROXY_BIND_RETRY_INTERVAL: Duration = Duration::from_millis(50);
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
type ProxyEventBuffer = Arc<Mutex<Vec<Value>>>;
type ProxyTokenMap = Arc<Mutex<HashMap<String, ProxyEventBuffer>>>;

pub(super) struct ManagedSandboxProxy {
    inner: Arc<ManagedSandboxProxyState>,
    token: String,
    events: Arc<Mutex<Vec<Value>>>,
}

struct ManagedSandboxProxyState {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    tokens: ProxyTokenMap,
    thread: Option<JoinHandle<()>>,
}

impl ManagedSandboxProxy {
    pub(super) fn start() -> io::Result<Self> {
        static SHARED_PROXY: OnceLock<Mutex<Option<Arc<ManagedSandboxProxyState>>>> =
            OnceLock::new();
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
                let token = new_proxy_token()?;
                let events = Arc::new(Mutex::new(Vec::new()));
                inner.add_token(token.clone(), Arc::clone(&events))?;
                return Ok(Self {
                    inner: Arc::clone(inner),
                    token,
                    events,
                });
            }
        }

        let proxy = Self::start_dedicated_on_with_token(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), MANAGED_PROXY_PORT),
            new_proxy_token()?,
        )?;
        *shared = Some(Arc::clone(&proxy.inner));
        Ok(proxy)
    }

    fn start_dedicated_on_with_token(addr: SocketAddr, token: String) -> io::Result<Self> {
        let listener = bind_proxy_listener(addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let events = Arc::new(Mutex::new(Vec::new()));
        let tokens = Arc::new(Mutex::new(HashMap::from([(
            token.clone(),
            Arc::clone(&events),
        )])));
        let thread_tokens = Arc::clone(&tokens);
        let thread = thread::spawn(move || accept_loop(listener, thread_shutdown, thread_tokens));
        let inner = Arc::new(ManagedSandboxProxyState {
            addr,
            shutdown,
            tokens,
            thread: Some(thread),
        });
        Ok(Self {
            inner,
            token,
            events,
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
        let proxy_url = format!("http://runseal:{}@{}", self.token, self.inner.addr);
        let mut env = vec![
            ("RUNSEAL_NETWORK_PROXY_ACTIVE".to_string(), "1".to_string()),
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

    pub(super) fn drain_events(&self) -> Vec<Value> {
        self.events
            .lock()
            .map(|mut events| events.drain(..).collect())
            .unwrap_or_default()
    }
}

impl Drop for ManagedSandboxProxy {
    fn drop(&mut self) {
        self.inner.remove_token(&self.token);
    }
}

impl ManagedSandboxProxyState {
    fn add_token(&self, token: String, events: Arc<Mutex<Vec<Value>>>) -> io::Result<()> {
        self.tokens
            .lock()
            .map_err(|_| io::Error::other("managed proxy token lock poisoned"))?
            .insert(token, events);
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
    tokens: &Mutex<HashMap<String, ProxyEventBuffer>>,
) -> io::Result<Option<ProxyEventBuffer>> {
    let Some(actual) = header_value(header, "Proxy-Authorization") else {
        return Ok(None);
    };
    let tokens = tokens
        .lock()
        .map_err(|_| io::Error::other("managed proxy token lock poisoned"))?;
    Ok(tokens.iter().find_map(|(token, events)| {
        (actual == proxy_basic_auth_value(token)).then(|| Arc::clone(events))
    }))
}

fn proxy_basic_auth_value(token: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("runseal:{token}")))
}

fn record_proxy_request_event(
    events: &Mutex<Vec<Value>>,
    header: &str,
    duration: Duration,
    result: Result<&(), &io::Error>,
) {
    let Ok(mut events) = events.lock() else {
        return;
    };
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
    events.push(event);
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
        let _ = io::copy(&mut client_to_upstream, &mut upstream_for_client);
        let _ = upstream_for_client.shutdown(Shutdown::Write);
    });
    let result = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = writer.join();
    result.map(|_| ())
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
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(io::Error::other(format!(
            "BCryptGenRandom failed: {status}"
        )));
    }
    Ok(URL_SAFE_NO_PAD.encode(bytes))
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
            && value.ends_with(&format!("@127.0.0.1:{MANAGED_PROXY_PORT}"))));
        let proxy_url = env
            .iter()
            .find_map(|(key, value)| (key == "HTTP_PROXY").then_some(value.as_str()))
            .expect("HTTP_PROXY");
        assert_eq!(
            proxy_url,
            format!(
                "http://runseal:{}@127.0.0.1:{MANAGED_PROXY_PORT}",
                proxy.token
            )
        );
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

        assert_eq!(first.inner.addr, second.inner.addr);
        assert_ne!(first_url, second_url);
    }

    #[test]
    fn shared_proxy_listener_survives_handle_drop() {
        let first = ManagedSandboxProxy::start().expect("start first proxy");
        let addr = first.inner.addr;
        drop(first);

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))
            .expect("shared proxy listener should stay alive for process reuse");
        drop(stream);

        let second = ManagedSandboxProxy::start().expect("start second proxy");
        assert_eq!(second.inner.addr, addr);
    }

    #[test]
    fn drops_listener_when_last_proxy_handle_drops() {
        let proxy = ManagedSandboxProxy::start_dedicated_ephemeral().expect("start proxy");
        let addr = proxy.inner.addr;
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
        let mut client = TcpStream::connect(proxy.inner.addr).expect("connect proxy");
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
    fn rejects_proxy_requests_without_token() {
        let proxy = ManagedSandboxProxy::start().expect("start proxy");
        let mut client = TcpStream::connect(proxy.inner.addr).expect("connect proxy");
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
    fn records_proxy_error_events_without_query_or_credentials() {
        let proxy = ManagedSandboxProxy::start_dedicated_ephemeral().expect("start proxy");
        let unused_listener = TcpListener::bind("127.0.0.1:0").expect("bind unused port");
        let unused_addr = unused_listener.local_addr().expect("unused addr");
        drop(unused_listener);

        let mut client = TcpStream::connect(proxy.inner.addr).expect("connect proxy");
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
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let events = proxy.drain_events();
            if !events.is_empty() || Instant::now() >= deadline {
                return events;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
