use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const NO_PROXY: &str = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";
const PROXY_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];
const NO_PROXY_KEYS: &[&str] = &["NO_PROXY", "no_proxy"];

pub(super) struct ManagedSandboxProxy {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ManagedSandboxProxy {
    pub(super) fn start() -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = thread::spawn(move || accept_loop(listener, thread_shutdown));
        Ok(Self {
            addr,
            shutdown,
            thread: Some(thread),
        })
    }

    pub(super) fn environment(&self) -> Vec<(String, String)> {
        let proxy_url = format!("http://{}", self.addr);
        let mut env = vec![
            ("CODEX_NETWORK_PROXY_ACTIVE".to_string(), "1".to_string()),
            (
                "CODEX_NETWORK_ALLOW_LOCAL_BINDING".to_string(),
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
}

impl Drop for ManagedSandboxProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn accept_loop(listener: TcpListener, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, _)) => {
                thread::spawn(move || {
                    let _ = handle_client(client);
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn handle_client(mut client: TcpStream) -> io::Result<()> {
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
            return forward_request(client, &header, &body_prefix);
        }
    }
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
    let (upstream_addr, path) = if let Some(rest) = target.strip_prefix("http://") {
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
            name.eq_ignore_ascii_case("Proxy-Connection") || name.eq_ignore_ascii_case("Connection")
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

fn split_http_url(rest: &str) -> io::Result<(String, String)> {
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
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
    header.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("Host")
            .then(|| value.trim().to_string())
    })
}

fn invalid_proxy_request(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_sets_loopback_proxy_for_vendor_guard() {
        let proxy = ManagedSandboxProxy::start().expect("start proxy");
        let env = proxy.environment();
        assert!(
            env.iter()
                .any(|(key, value)| key == "HTTP_PROXY" && value.starts_with("http://127.0.0.1:"))
        );
        assert!(
            env.iter()
                .any(|(key, value)| key == "CODEX_NETWORK_PROXY_ACTIVE" && value == "1")
        );
        assert!(
            env.iter()
                .any(|(key, value)| key == "CODEX_NETWORK_ALLOW_LOCAL_BINDING" && value == "0")
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
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .expect("write upstream response");
        });

        let proxy = ManagedSandboxProxy::start().expect("start proxy");
        let proxy_url = proxy
            .environment()
            .into_iter()
            .find_map(|(key, value)| (key == "HTTP_PROXY").then_some(value))
            .expect("HTTP_PROXY");
        let proxy_addr = proxy_url.strip_prefix("http://").expect("proxy url");
        let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
        client
            .write_all(
                format!("GET http://{upstream_addr}/ok HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n")
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
    }
}
