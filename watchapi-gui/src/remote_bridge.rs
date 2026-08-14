use parking_lot::RwLock;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use watchapi_core::terminal::TerminalControl;

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_PROMPT_CHARS: usize = 16 * 1024;
const TAIL_CHARS: usize = 24_000;
const BRIDGE_STATE_FILE: &str = ".watchapi-bridge.json";

pub struct RemoteBridge {
    shared: Arc<RwLock<BridgeState>>,
    state_path: PathBuf,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

pub struct WorkspaceCandidate {
    pub identity: String,
    pub label: String,
    pub status: String,
    pub submit_sequence: String,
    pub control: Option<TerminalControl>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteWorkspaceAction {
    Start,
    Stop,
    Restart,
}

impl RemoteWorkspaceAction {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "restart" => Some(Self::Restart),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteWorkspaceCommand {
    pub workspace_id: String,
    pub action: RemoteWorkspaceAction,
}

#[derive(Clone)]
struct BridgeWorkspace {
    id: String,
    label: String,
    status: String,
    submit_sequence: String,
    control: Option<TerminalControl>,
}

#[derive(Default)]
struct BridgeState {
    workspaces: Vec<BridgeWorkspace>,
    commands: VecDeque<RemoteWorkspaceCommand>,
}

#[derive(Serialize)]
struct PublicWorkspace {
    id: String,
    label: String,
    status: String,
    running: bool,
    cursor: u64,
}

#[derive(Serialize)]
struct BridgeDescriptor<'a> {
    version: u32,
    base_url: String,
    bearer_token: &'a str,
    pid: u32,
}

impl RemoteBridge {
    pub fn start(app_root: &Path) -> Result<Self, String> {
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|err| format!("启动 QQ 控制桥失败：{err}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|err| format!("设置 QQ 控制桥失败：{err}"))?;
        let address = listener
            .local_addr()
            .map_err(|err| format!("读取 QQ 控制桥地址失败：{err}"))?;
        let bearer_token = random_token(32);
        let state_path = app_root.join(BRIDGE_STATE_FILE);
        write_descriptor(&state_path, address.port(), &bearer_token)?;

        let shared = Arc::new(RwLock::new(BridgeState::default()));
        let running = Arc::new(AtomicBool::new(true));
        let worker_shared = Arc::clone(&shared);
        let worker_running = Arc::clone(&running);
        let worker_token = bearer_token.clone();
        let worker = thread::spawn(move || {
            while worker_running.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => handle_connection(stream, &worker_token, &worker_shared),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(40));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(100)),
                }
            }
        });

        Ok(Self {
            shared,
            state_path,
            running,
            worker: Some(worker),
        })
    }

    pub fn sync(&self, candidates: Vec<WorkspaceCandidate>) {
        let mut state = self.shared.write();
        state.workspaces = candidates
            .into_iter()
            .map(|candidate| BridgeWorkspace {
                id: workspace_id_for_identity(&candidate.identity),
                label: candidate.label,
                status: candidate.status,
                submit_sequence: candidate.submit_sequence,
                control: candidate.control,
            })
            .collect();
    }

    pub fn drain_commands(&self) -> Vec<RemoteWorkspaceCommand> {
        self.shared.write().commands.drain(..).collect()
    }
}

/// Derive an opaque, stable workspace ID without ever exposing the config path.
pub fn workspace_id_for_identity(identity: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in identity.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ws-{hash:016x}")
}

impl Drop for RemoteBridge {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_file(&self.state_path);
    }
}

fn write_descriptor(path: &Path, port: u16, bearer_token: &str) -> Result<(), String> {
    let descriptor = BridgeDescriptor {
        version: 1,
        base_url: format!("http://127.0.0.1:{port}"),
        bearer_token,
        pid: std::process::id(),
    };
    let bytes = serde_json::to_vec_pretty(&descriptor)
        .map_err(|err| format!("生成 QQ 控制桥配置失败：{err}"))?;
    fs::write(path, bytes).map_err(|err| format!("写入 QQ 控制桥配置失败：{err}"))
}

fn random_token(bytes: usize) -> String {
    let mut raw = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut raw);
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn handle_connection(mut stream: TcpStream, bearer_token: &str, shared: &Arc<RwLock<BridgeState>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let Some(request) = read_request(&mut stream) else {
        write_response(&mut stream, 400, json!({"error": "bad_request"}));
        return;
    };
    let expected = format!("Bearer {bearer_token}");
    if request.authorization.as_deref() != Some(expected.as_str()) {
        write_response(&mut stream, 401, json!({"error": "unauthorized"}));
        return;
    }
    let response = route_request(&request, shared);
    write_response(&mut stream, response.0, response.1);
}

struct HttpRequest {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<HttpRequest> {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut buffer).ok()?;
        if count == 0 {
            return None;
        }
        data.extend_from_slice(&buffer[..count]);
        if data.len() > MAX_REQUEST_BYTES {
            return None;
        }
        if let Some(index) = find_bytes(&data, b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&data[..header_end]).ok()?;
    let mut lines = headers.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let target = request_line.next()?;
    let (path, query) = target
        .split_once('?')
        .map(|(path, query)| (path.to_string(), query.to_string()))
        .unwrap_or_else(|| (target.to_string(), String::new()));
    let mut authorization = None;
    let mut content_length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.trim().to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().ok()?;
        }
    }
    if content_length > MAX_REQUEST_BYTES || header_end + content_length > MAX_REQUEST_BYTES {
        return None;
    }
    while data.len() < header_end + content_length {
        let count = stream.read(&mut buffer).ok()?;
        if count == 0 {
            return None;
        }
        data.extend_from_slice(&buffer[..count]);
    }
    Some(HttpRequest {
        method,
        path,
        query,
        authorization,
        body: data[header_end..header_end + content_length].to_vec(),
    })
}

fn route_request(request: &HttpRequest, shared: &Arc<RwLock<BridgeState>>) -> (u16, Value) {
    if request.method == "GET" && request.path == "/v1/workspaces" {
        let workspaces = shared
            .read()
            .workspaces
            .iter()
            .map(|workspace| {
                let running = workspace
                    .control
                    .as_ref()
                    .is_some_and(TerminalControl::is_running);
                let cursor = workspace
                    .control
                    .as_ref()
                    .map(TerminalControl::view_revision)
                    .unwrap_or_default();
                PublicWorkspace {
                    id: workspace.id.clone(),
                    label: workspace.label.clone(),
                    status: workspace.status.clone(),
                    running,
                    cursor,
                }
            })
            .collect::<Vec<_>>();
        return (200, json!({"workspaces": workspaces}));
    }

    let Some(rest) = request.path.strip_prefix("/v1/workspaces/") else {
        return (404, json!({"error": "not_found"}));
    };
    let mut parts = rest.split('/');
    let workspace_id = parts.next().unwrap_or_default();
    let action = parts.next().unwrap_or_default();
    if parts.next().is_some() || workspace_id.is_empty() || action.is_empty() {
        return (404, json!({"error": "not_found"}));
    }

    if request.method == "POST" && action == "lifecycle" {
        let payload = serde_json::from_slice::<Value>(&request.body).ok();
        let Some(requested_action) = payload
            .as_ref()
            .and_then(|value| value.get("action"))
            .and_then(Value::as_str)
            .and_then(RemoteWorkspaceAction::parse)
        else {
            return (400, json!({"error": "invalid_lifecycle_action"}));
        };
        let mut state = shared.write();
        if !state.workspaces.iter().any(|item| item.id == workspace_id) {
            return (404, json!({"error": "workspace_not_found"}));
        }
        let command = RemoteWorkspaceCommand {
            workspace_id: workspace_id.to_string(),
            action: requested_action,
        };
        if !state.commands.iter().any(|queued| queued == &command) {
            state.commands.push_back(command.clone());
        }
        return (
            202,
            json!({"ok": true, "accepted": true, "workspace_id": workspace_id, "action": command.action.as_str()}),
        );
    }

    let state = shared.read();
    let Some(workspace) = state.workspaces.iter().find(|item| item.id == workspace_id) else {
        return (404, json!({"error": "workspace_not_found"}));
    };
    let Some(control) = workspace.control.as_ref() else {
        return (409, json!({"error": "workspace_not_running"}));
    };
    if !control.is_running() {
        return (409, json!({"error": "workspace_not_running"}));
    }

    match (request.method.as_str(), action) {
        ("POST", "input") => {
            let payload = serde_json::from_slice::<Value>(&request.body).ok();
            let text = payload
                .as_ref()
                .and_then(|value| value.get("text"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if text.is_empty() || text.chars().count() > MAX_PROMPT_CHARS {
                return (400, json!({"error": "invalid_prompt"}));
            }
            let input = format!("{}{}", text, submit_text(&workspace.submit_sequence));
            match control.write_user_input(&input) {
                Ok(()) => (200, json!({"ok": true, "label": workspace.label})),
                Err(err) => (
                    500,
                    json!({"error": "write_failed", "message": err.to_string()}),
                ),
            }
        }
        ("POST", "escape") => match control.write_user_input("\u{1b}") {
            Ok(()) => (200, json!({"ok": true, "label": workspace.label})),
            Err(err) => (
                500,
                json!({"error": "write_failed", "message": err.to_string()}),
            ),
        },
        ("GET", "output") => {
            let tail = query_value(&request.query, "tail") == Some("1");
            let cursor = control.output_revision();
            let requested_cursor = query_value(&request.query, "cursor")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_default();
            let output = if tail || requested_cursor != cursor {
                render_terminal_output(control.output_text())
            } else {
                String::new()
            };
            (
                200,
                json!({"label": workspace.label, "output": output, "cursor": cursor}),
            )
        }
        _ => (404, json!({"error": "not_found"})),
    }
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        (name == key).then_some(value)
    })
}

fn submit_text(sequence: &str) -> &'static str {
    match sequence {
        "crlf" => "\r\n",
        "lf" => "\n",
        _ => "\r",
    }
}

fn last_chars(text: &str, limit: usize) -> String {
    let start = text
        .char_indices()
        .rev()
        .nth(limit.saturating_sub(1))
        .map(|(index, _)| index)
        .unwrap_or_default();
    text[start..].to_string()
}

fn render_terminal_output(output: String) -> String {
    let normalized = output.replace("\r\n", "\n").replace('\r', "\n");
    last_chars(&normalized, TAIL_CHARS)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_response(stream: &mut TcpStream, status: u16, value: Value) {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn submit_sequence_matches_terminal_configuration() {
        assert_eq!(submit_text("control-m"), "\r");
        assert_eq!(submit_text("cr"), "\r");
        assert_eq!(submit_text("crlf"), "\r\n");
        assert_eq!(submit_text("lf"), "\n");
    }

    #[test]
    fn tail_is_utf8_safe() {
        assert_eq!(last_chars("a中文", 2), "中文");
        assert_eq!(last_chars("短", 10), "短");
    }

    #[test]
    fn terminal_output_keeps_raw_lines_without_screen_reflow() {
        assert_eq!(
            render_terminal_output("first\r\nsecond\rthird".to_string()),
            "first\nsecond\nthird"
        );
    }

    #[test]
    fn authenticated_workspace_list_exposes_only_public_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let bridge = RemoteBridge::start(directory.path()).unwrap();
        bridge.sync(vec![WorkspaceCandidate {
            identity: r"D:\private\config.json".to_string(),
            label: "rust / 新配置".to_string(),
            status: "已停止".to_string(),
            submit_sequence: "control-m".to_string(),
            control: None,
        }]);
        let descriptor: Value =
            serde_json::from_slice(&fs::read(directory.path().join(BRIDGE_STATE_FILE)).unwrap())
                .unwrap();
        let base_url = descriptor["base_url"].as_str().unwrap();
        let address = base_url.strip_prefix("http://").unwrap();
        let bearer = descriptor["bearer_token"].as_str().unwrap();
        let mut stream = TcpStream::connect(address).unwrap();
        write!(
            stream,
            "GET /v1/workspaces HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("rust / 新配置"));
        assert!(!response.contains("private"));
        assert!(!response.contains("config.json"));
        assert!(response.contains("\"id\":\"ws-"));
    }

    #[test]
    fn workspace_id_is_stable_and_does_not_reveal_the_identity() {
        let identity = r"D:\private\config.json";
        let first = workspace_id_for_identity(identity);

        assert_eq!(first, workspace_id_for_identity(identity));
        assert!(first.starts_with("ws-"));
        assert!(!first.contains("private"));
        assert!(!first.contains("config"));
    }

    #[test]
    fn lifecycle_requests_are_queued_for_the_gui_thread() {
        let directory = tempfile::tempdir().unwrap();
        let bridge = RemoteBridge::start(directory.path()).unwrap();
        let identity = "workspace-a";
        let workspace_id = workspace_id_for_identity(identity);
        bridge.sync(vec![WorkspaceCandidate {
            identity: identity.to_string(),
            label: "rust / 新配置".to_string(),
            status: "已停止".to_string(),
            submit_sequence: "control-m".to_string(),
            control: None,
        }]);

        let request = HttpRequest {
            method: "POST".to_string(),
            path: format!("/v1/workspaces/{workspace_id}/lifecycle"),
            query: String::new(),
            authorization: None,
            body: br#"{"action":"start"}"#.to_vec(),
        };
        let response = route_request(&request, &bridge.shared);

        assert_eq!(response.0, 202);
        assert_eq!(
            bridge.drain_commands(),
            vec![RemoteWorkspaceCommand {
                workspace_id,
                action: RemoteWorkspaceAction::Start,
            }]
        );
    }
}
