use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST,
    TRANSFER_ENCODING,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const LOCAL_HTTP_REQUEST_MAX_BYTES: usize = 16 * 1024 * 1024;
const LOCAL_CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(120);
const UPSTREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_ACTIVE_CLIENTS: usize = 128;

pub struct ProxyServer {
    listen_host: String,
    listen_port: u16,
    upstream_base_url: String,
    upstream_api_key: String,
    available: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    bound_port: Option<u16>,
}

impl ProxyServer {
    pub fn new(
        listen_host: String,
        listen_port: u16,
        upstream_base_url: String,
        upstream_api_key: String,
        available: bool,
    ) -> Self {
        Self {
            listen_host,
            listen_port,
            upstream_base_url: upstream_base_url.trim_end_matches('/').to_string(),
            upstream_api_key,
            available: Arc::new(AtomicBool::new(available)),
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
            bound_port: None,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        let listener = TcpListener::bind((self.listen_host.as_str(), self.listen_port))?;
        listener.set_nonblocking(true)?;
        self.bound_port = Some(listener.local_addr()?.port());
        let available = Arc::clone(&self.available);
        let running = Arc::clone(&self.running);
        let upstream = self.upstream_base_url.clone();
        let key = self.upstream_api_key.clone();
        let listen_host = self.listen_host.clone();
        let bound_port = self.bound_port.unwrap_or(self.listen_port);
        let active_clients = Arc::new(AtomicUsize::new(0));
        let http_client = Arc::new(Client::builder().timeout(UPSTREAM_TOTAL_TIMEOUT).build()?);
        self.running.store(true, Ordering::SeqCst);
        self.handle = Some(thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    Err(_) => break,
                };
                let Some(active_guard) = try_acquire_active_client(&active_clients) else {
                    let _ = stream.set_nonblocking(false);
                    let _ = write_json(
                        &mut stream,
                        503,
                        r#"{"error":{"message":"proxy overloaded","type":"watchapi_proxy_local","code":"local_overloaded"}}"#,
                    );
                    continue;
                };
                let available = Arc::clone(&available);
                let upstream = upstream.clone();
                let key = key.clone();
                let listen_host = listen_host.clone();
                let http_client = Arc::clone(&http_client);
                thread::spawn(move || {
                    let _active_guard = active_guard;
                    let _ = stream.set_read_timeout(Some(LOCAL_CLIENT_READ_TIMEOUT));
                    let _ = stream.set_write_timeout(None);
                    let _ = handle_client(
                        stream,
                        available,
                        &upstream,
                        &key,
                        &listen_host,
                        bound_port,
                        &http_client,
                    );
                });
            }
        }));
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = TcpStream::connect((
                self.listen_host.as_str(),
                self.bound_port.unwrap_or(self.listen_port),
            ));
            let _ = handle.join();
        }
    }

    pub fn port(&self) -> Result<u16> {
        self.bound_port
            .ok_or_else(|| anyhow!("proxy server is not started"))
    }

    pub fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::SeqCst);
    }

    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::SeqCst)
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ActiveClientGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ActiveClientGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

fn try_acquire_active_client(counter: &Arc<AtomicUsize>) -> Option<ActiveClientGuard> {
    let mut current = counter.load(Ordering::SeqCst);
    loop {
        if current >= MAX_ACTIVE_CLIENTS {
            return None;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                return Some(ActiveClientGuard {
                    counter: Arc::clone(counter),
                });
            }
            Err(next) => current = next,
        }
    }
}

fn handle_client(
    mut stream: TcpStream,
    available: Arc<AtomicBool>,
    upstream: &str,
    upstream_key: &str,
    listen_host: &str,
    listen_port: u16,
    http_client: &Client,
) -> Result<()> {
    let _ = stream.set_read_timeout(Some(LOCAL_CLIENT_READ_TIMEOUT));
    let _ = stream.set_write_timeout(None);
    let raw = read_http_request(&mut stream)?;
    if raw.is_empty() {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&raw);
    let request_line = request.lines().next().unwrap_or_default();
    let method = request_line.split_whitespace().next().unwrap_or_default();
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    if method == "GET" && path == "/_watchapi/admin/status" {
        return write_json(
            &mut stream,
            200,
            &format!(
                r#"{{"available":{},"listen_host":"{}","listen_port":{},"upstream_base_url":"{}"}}"#,
                available.load(Ordering::SeqCst),
                json_escape(listen_host),
                listen_port,
                json_escape(upstream)
            ),
        );
    }
    if method == "POST" && path == "/_watchapi/admin/up" {
        available.store(true, Ordering::SeqCst);
        return write_json(&mut stream, 200, r#"{"available":true}"#);
    }
    if method == "POST" && path == "/_watchapi/admin/down" {
        available.store(false, Ordering::SeqCst);
        return write_json(&mut stream, 200, r#"{"available":false}"#);
    }
    if method != "POST" {
        return write_json(&mut stream, 404, r#"{"error":"not found"}"#);
    }
    if !available.load(Ordering::SeqCst) {
        return write_json(
            &mut stream,
            503,
            r#"{"available":false,"error":"proxy disabled"}"#,
        );
    }
    forward(
        &mut stream,
        &raw,
        upstream,
        upstream_key,
        method,
        path,
        http_client,
    )
}

fn forward(
    client: &mut TcpStream,
    raw_request: &[u8],
    upstream: &str,
    upstream_key: &str,
    method: &str,
    path: &str,
    http_client: &Client,
) -> Result<()> {
    let upstream_url = upstream_url(upstream, path)?;
    let body_start = find_body(raw_request).ok_or_else(|| anyhow!("invalid http request"))?;
    let body = raw_request[body_start..].to_vec();
    let headers = forward_headers(raw_request, upstream_key)?;
    let http_method =
        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST);
    let response = http_client
        .request(http_method, upstream_url)
        .headers(headers)
        .body(body)
        .send();
    match response {
        Ok(response) => write_upstream_response(client, response),
        Err(err) => write_json(
            client,
            502,
            &format!(
                r#"{{"error":"upstream unavailable","detail":"{}"}}"#,
                json_escape(&err.to_string())
            ),
        ),
    }
}

fn write_upstream_response(
    client: &mut TcpStream,
    response: reqwest::blocking::Response,
) -> Result<()> {
    let status = response.status();
    let mut raw_response = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("OK")
    )
    .into_bytes();
    let response_headers = response.headers().clone();
    let payload = response
        .bytes()
        .map(|bytes| bytes.to_vec())
        .unwrap_or_default();
    for (name, value) in response_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "transfer-encoding" | "connection" | "content-length"
        ) {
            continue;
        }
        raw_response.extend_from_slice(name.as_str().as_bytes());
        raw_response.extend_from_slice(b": ");
        raw_response.extend_from_slice(value.as_bytes());
        raw_response.extend_from_slice(b"\r\n");
    }
    raw_response.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        )
        .as_bytes(),
    );
    raw_response.extend_from_slice(&payload);
    client.write_all(&raw_response)?;
    Ok(())
}

fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut body_start = None;
    let mut content_length = 0_usize;
    loop {
        let size = stream.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..size]);
        if body_start.is_none() {
            if let Some(index) = find_body(&raw) {
                body_start = Some(index);
                content_length = parse_content_length(&raw[..index]).unwrap_or(0);
            }
        }
        if let Some(index) = body_start {
            if raw.len().saturating_sub(index) >= content_length {
                break;
            }
        }
        if raw.len() > LOCAL_HTTP_REQUEST_MAX_BYTES {
            return Err(anyhow!("request too large"));
        }
    }
    Ok(raw)
}

fn upstream_url(upstream: &str, path: &str) -> Result<String> {
    let base = url::Url::parse(upstream)?;
    let joined = if path.starts_with('/') {
        base.join(path.trim_start_matches('/'))?
    } else {
        base.join(path)?
    };
    Ok(joined.to_string())
}

fn forward_headers(raw_request: &[u8], upstream_key: &str) -> Result<HeaderMap> {
    let header_end = find_body(raw_request).ok_or_else(|| anyhow!("invalid http request"))?;
    let text = String::from_utf8_lossy(&raw_request[..header_end]);
    let mut headers = HeaderMap::new();
    for line in text.lines().skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let name = HeaderName::from_bytes(key.trim().as_bytes())?;
        if name == HOST
            || name == AUTHORIZATION
            || name == CONNECTION
            || name == CONTENT_LENGTH
            || name == TRANSFER_ENCODING
        {
            continue;
        }
        headers.insert(name, HeaderValue::from_str(value.trim())?);
    }
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {upstream_key}"))?,
    );
    Ok(headers)
}

fn find_body(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

fn write_json(stream: &mut TcpStream, status: u16, body: &str) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn json_escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Mutex, OnceLock};

    fn proxy_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn proxy_active_client_guard_caps_and_releases_connections() {
        let counter = Arc::new(AtomicUsize::new(MAX_ACTIVE_CLIENTS - 1));
        let guard = try_acquire_active_client(&counter).expect("last slot should be available");

        assert_eq!(counter.load(Ordering::SeqCst), MAX_ACTIVE_CLIENTS);
        assert!(try_acquire_active_client(&counter).is_none());

        drop(guard);
        assert_eq!(counter.load(Ordering::SeqCst), MAX_ACTIVE_CLIENTS - 1);
    }

    #[test]
    fn proxy_admin_status_returns_state() {
        let _guard = proxy_test_lock();
        let mut proxy = ProxyServer::new(
            "127.0.0.1".to_string(),
            0,
            "http://127.0.0.1:1".to_string(),
            "key".to_string(),
            false,
        );
        proxy.start().unwrap();

        let response = request(proxy.port().unwrap(), "GET", "/_watchapi/admin/status", "");

        assert!(response.contains("200 OK"));
        assert!(response.contains(r#""available":false"#));
    }

    #[test]
    fn proxy_forwards_post_and_rewrites_authorization() {
        let _guard = proxy_test_lock();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut buffer = [0_u8; 4096];
            let size = stream.read(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..size]).to_string();
            let body = r#"{"ok":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });
        let mut proxy = ProxyServer::new(
            "127.0.0.1".to_string(),
            0,
            format!("http://127.0.0.1:{upstream_port}"),
            "real-key".to_string(),
            true,
        );
        proxy.start().unwrap();

        let response = request(
            proxy.port().unwrap(),
            "POST",
            "/v1/responses",
            r#"{"input":"hello"}"#,
        );
        let upstream_request = handle.join().unwrap();

        assert!(response.contains("200 OK"));
        assert!(response.contains(r#"{"ok":true}"#));
        assert!(upstream_request
            .to_ascii_lowercase()
            .contains("authorization: bearer real-key"));
        assert!(upstream_request.contains("POST /v1/responses HTTP/1.1"));
    }

    #[test]
    fn proxy_upstream_transport_error_preserves_detail() {
        let _guard = proxy_test_lock();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        drop(upstream);
        let mut proxy = ProxyServer::new(
            "127.0.0.1".to_string(),
            0,
            format!("http://127.0.0.1:{upstream_port}"),
            "real-key".to_string(),
            true,
        );
        proxy.start().unwrap();

        let response = request(
            proxy.port().unwrap(),
            "POST",
            "/v1/responses",
            r#"{"input":"hello"}"#,
        );

        assert!(response.contains("502 Bad Gateway"), "{response}");
        assert!(
            response.contains(r#""error":"upstream unavailable""#),
            "{response}"
        );
        assert!(!response.contains("closed connection"), "{response}");
    }

    #[test]
    fn proxy_client_write_side_has_no_short_local_timeout() {
        let source = include_str!("proxy.rs");
        let handle_client_start = source
            .find("fn handle_client(")
            .expect("handle_client should exist");
        let forward_start = source.find("fn forward(").expect("forward should exist");
        let production_prelude = &source[..forward_start.max(handle_client_start)];

        assert!(production_prelude.contains("stream.set_write_timeout(None)"));
        assert!(
            !production_prelude.contains("stream.set_write_timeout(Some(Duration::from_secs(30)))")
        );
    }

    #[test]
    fn proxy_local_client_read_timeout_matches_agent_turns() {
        assert!(LOCAL_CLIENT_READ_TIMEOUT >= Duration::from_secs(120));

        let source = include_str!("proxy.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source should exist");
        assert!(!production.contains("set_read_timeout(Some(Duration::from_secs(30)))"));
        assert!(production.contains("set_read_timeout(Some(LOCAL_CLIENT_READ_TIMEOUT))"));
    }

    #[test]
    fn proxy_reuses_http_client_per_server() {
        let source = include_str!("proxy.rs");
        let start_block = source
            .split("pub fn start(&mut self) -> Result<()>")
            .nth(1)
            .and_then(|tail| tail.split("pub fn stop(&mut self)").next())
            .expect("proxy start block should be discoverable");
        let forward_block = source
            .split("fn forward(")
            .nth(1)
            .and_then(|tail| tail.split("fn write_upstream_response").next())
            .expect("proxy forward block should be discoverable");

        assert!(start_block.contains("Client::builder()"));
        assert!(start_block.contains("Arc::new"));
        assert!(!forward_block.contains("Client::builder()"));
        assert!(forward_block.contains("http_client"));
        assert!(forward_block.contains(".request(http_method, upstream_url)"));
    }

    #[test]
    fn proxy_upstream_timeout_allows_long_agent_turns() {
        assert!(UPSTREAM_TOTAL_TIMEOUT >= Duration::from_secs(15 * 60));
    }

    fn request(port: u16, method: &str, path: &str, body: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }
}
