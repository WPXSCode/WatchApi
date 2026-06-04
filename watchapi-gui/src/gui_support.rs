#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, Write};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

pub const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
pub const LOG_BACKUP_COUNT: usize = 3;

static SESSION_LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn session_log_lock() -> &'static Mutex<()> {
    SESSION_LOG_LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GuiConfigRegistry {
    pub state_path: PathBuf,
    pub paths: Vec<PathBuf>,
    pub selected_path: Option<PathBuf>,
    pub aliases: HashMap<String, String>,
    pub manual_prompt_history: Vec<String>,
    pub autostart_paths: HashSet<String>,
    pub workspaces: Vec<GuiWorkspace>,
    pub selected_workspace_id: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiWorkspace {
    pub id: String,
    pub path: PathBuf,
    pub name: Option<String>,
    pub pinned: bool,
    pub expanded: bool,
    pub config_paths: Vec<PathBuf>,
    pub pinned_config_paths: HashSet<String>,
    pub config_defaults: serde_json::Value,
    pub last_used_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistryState {
    #[serde(default)]
    configs: Vec<String>,
    selected: Option<String>,
    #[serde(default)]
    aliases: HashMap<String, String>,
    #[serde(default)]
    manual_prompt_history: Vec<String>,
    #[serde(default)]
    autostart: Vec<String>,
    #[serde(default)]
    workspaces: Vec<RegistryWorkspaceState>,
    selected_workspace: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistryWorkspaceState {
    id: String,
    path: String,
    name: Option<String>,
    #[serde(default)]
    pinned: bool,
    #[serde(default = "default_workspace_expanded")]
    expanded: bool,
    #[serde(default)]
    config_paths: Vec<String>,
    #[serde(default)]
    pinned_config_paths: Vec<String>,
    #[serde(default = "default_workspace_config_defaults")]
    config_defaults: serde_json::Value,
    #[serde(default)]
    last_used_at: u64,
}

fn default_workspace_expanded() -> bool {
    true
}

fn default_workspace_config_defaults() -> serde_json::Value {
    json!({})
}

impl GuiConfigRegistry {
    pub fn new(state_path: PathBuf) -> Self {
        Self {
            state_path,
            ..Self::default()
        }
    }

    pub fn load(&mut self) {
        let Some(state) = fs::read_to_string(&self.state_path)
            .ok()
            .and_then(|text| serde_json::from_str::<RegistryState>(&text).ok())
        else {
            return;
        };

        self.paths.clear();
        self.workspaces = state
            .workspaces
            .into_iter()
            .filter_map(registry_workspace_from_state)
            .collect();
        self.rebuild_paths_from_workspaces();

        self.selected_path = state
            .selected
            .map(PathBuf::from)
            .map(normalize_config_path)
            .filter(|path| self.paths.contains(path));
        self.selected_workspace_id = state
            .selected_workspace
            .filter(|id| self.workspaces.iter().any(|workspace| workspace.id == *id));
        if self.selected_workspace_id.is_none() {
            self.selected_workspace_id = self
                .selected_path
                .as_ref()
                .and_then(|path| {
                    self.workspace_for_config(path)
                        .map(|workspace| workspace.id.clone())
                })
                .or_else(|| {
                    self.workspaces
                        .first()
                        .map(|workspace| workspace.id.clone())
                });
        }

        self.aliases = state
            .aliases
            .into_iter()
            .filter_map(|(key, value)| {
                let text = value.trim();
                if text.is_empty() {
                    None
                } else {
                    Some((
                        normalize_config_path(PathBuf::from(key))
                            .to_string_lossy()
                            .to_string(),
                        text.to_string(),
                    ))
                }
            })
            .collect();
        self.manual_prompt_history =
            normalize_manual_prompt_history(state.manual_prompt_history, 20);
        self.autostart_paths = state
            .autostart
            .into_iter()
            .map(PathBuf::from)
            .map(normalize_config_path)
            .map(|path| path.to_string_lossy().to_string())
            .collect();
    }

    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let state = RegistryState {
            configs: self
                .paths
                .iter()
                .map(|path| path.to_string_lossy().to_string())
                .collect(),
            selected: self
                .selected_path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string()),
            aliases: self.aliases.clone(),
            manual_prompt_history: self.manual_prompt_history.clone(),
            autostart: {
                let mut items = self.autostart_paths.iter().cloned().collect::<Vec<_>>();
                items.sort();
                items
            },
            workspaces: self
                .workspaces
                .iter()
                .map(registry_workspace_to_state)
                .collect(),
            selected_workspace: self.selected_workspace_id.clone(),
        };
        write_text_atomic(
            &self.state_path,
            &(serde_json::to_string_pretty(&state).unwrap_or_default() + "\n"),
        )
    }

    fn rebuild_paths_from_workspaces(&mut self) {
        self.paths.clear();
        let sorted = self.sorted_workspaces();
        for workspace in sorted {
            for path in workspace.config_paths {
                if !self.paths.contains(&path) {
                    self.paths.push(path);
                }
            }
        }
        if self
            .selected_path
            .as_ref()
            .is_some_and(|path| !self.paths.contains(path))
        {
            self.selected_path = self.paths.first().cloned();
        }
    }

    pub fn open_workspace(&mut self, path: impl Into<PathBuf>) -> String {
        let normalized = normalize_config_path(path.into());
        let id = workspace_id_for_path(&normalized);
        let now = registry_timestamp();
        if let Some(workspace) = self
            .workspaces
            .iter_mut()
            .find(|workspace| workspace.id == id)
        {
            workspace.path = normalized;
            workspace.last_used_at = now;
        } else {
            self.workspaces.push(GuiWorkspace {
                id: id.clone(),
                path: normalized,
                name: None,
                pinned: false,
                expanded: true,
                config_paths: Vec::new(),
                pinned_config_paths: HashSet::new(),
                config_defaults: default_workspace_config_defaults(),
                last_used_at: now,
            });
        }
        self.selected_workspace_id = Some(id.clone());
        id
    }

    pub fn remove_workspace(&mut self, workspace_id: &str) {
        let removed_paths = self
            .workspaces
            .iter()
            .find(|workspace| workspace.id == workspace_id)
            .map(|workspace| workspace.config_paths.clone())
            .unwrap_or_default();
        self.workspaces
            .retain(|workspace| workspace.id != workspace_id);
        for path in removed_paths {
            let key = path.to_string_lossy().to_string();
            self.paths.retain(|item| item != &path);
            self.aliases.remove(&key);
            self.autostart_paths.remove(&key);
            if self.selected_path.as_ref() == Some(&path) {
                self.selected_path = None;
            }
        }
        if self.selected_workspace_id.as_deref() == Some(workspace_id) {
            self.selected_workspace_id = self
                .workspaces
                .first()
                .map(|workspace| workspace.id.clone());
        }
        self.rebuild_paths_from_workspaces();
    }

    pub fn current_workspace_id(&self) -> Option<&str> {
        self.selected_workspace_id.as_deref()
    }

    pub fn current_workspace(&self) -> Option<&GuiWorkspace> {
        let id = self.selected_workspace_id.as_deref()?;
        self.workspaces.iter().find(|workspace| workspace.id == id)
    }

    pub fn current_workspace_mut(&mut self) -> Option<&mut GuiWorkspace> {
        let id = self.selected_workspace_id.clone()?;
        self.workspaces
            .iter_mut()
            .find(|workspace| workspace.id == id)
    }

    pub fn workspace_host_dir(&self, app_root: &Path, workspace_id: &str) -> PathBuf {
        app_root.join("Workspaces").join(workspace_id)
    }

    pub fn register_config_in_workspace(
        &mut self,
        workspace_id: &str,
        path: impl Into<PathBuf>,
    ) -> PathBuf {
        let normalized = normalize_config_path(path.into());
        let key = normalized.to_string_lossy().to_string();
        for workspace in &mut self.workspaces {
            if workspace.id != workspace_id {
                workspace.config_paths.retain(|item| item != &normalized);
                workspace.pinned_config_paths.remove(&key);
            }
        }
        if let Some(workspace) = self
            .workspaces
            .iter_mut()
            .find(|workspace| workspace.id == workspace_id)
        {
            workspace.config_paths.retain(|item| item != &normalized);
            workspace.config_paths.insert(0, normalized.clone());
            workspace.last_used_at = registry_timestamp();
        }
        self.paths.retain(|item| item != &normalized);
        self.paths.insert(0, normalized.clone());
        self.selected_path = Some(normalized.clone());
        self.selected_workspace_id = Some(workspace_id.to_string());
        normalized
    }

    pub fn remove_config_from_workspace(&mut self, path: impl Into<PathBuf>) {
        let normalized = normalize_config_path(path.into());
        let key = normalized.to_string_lossy().to_string();
        for workspace in &mut self.workspaces {
            workspace.config_paths.retain(|item| item != &normalized);
            workspace.pinned_config_paths.remove(&key);
        }
        self.paths.retain(|item| item != &normalized);
        self.aliases.remove(&key);
        self.autostart_paths.remove(&key);
        if self.selected_path.as_ref() == Some(&normalized) {
            self.selected_path = self.paths.first().cloned();
        }
    }

    pub fn set_workspace_pinned(&mut self, workspace_id: &str, pinned: bool) {
        if let Some(workspace) = self
            .workspaces
            .iter_mut()
            .find(|workspace| workspace.id == workspace_id)
        {
            workspace.pinned = pinned;
        }
    }

    pub fn set_config_pinned(&mut self, path: impl Into<PathBuf>, pinned: bool) {
        let normalized = normalize_config_path(path.into());
        let key = normalized.to_string_lossy().to_string();
        for workspace in &mut self.workspaces {
            if workspace.config_paths.contains(&normalized) {
                if pinned {
                    workspace.pinned_config_paths.insert(key.clone());
                } else {
                    workspace.pinned_config_paths.remove(&key);
                }
                sort_workspace_configs(workspace, &self.aliases);
            }
        }
        self.rebuild_paths_from_workspaces();
    }

    pub fn sorted_workspaces(&self) -> Vec<GuiWorkspace> {
        let mut items = self
            .workspaces
            .iter()
            .cloned()
            .enumerate()
            .collect::<Vec<_>>();
        for workspace in &mut items {
            sort_workspace_configs(&mut workspace.1, &self.aliases);
        }
        items.sort_by(|left, right| {
            right
                .1
                .pinned
                .cmp(&left.1.pinned)
                .then_with(|| left.0.cmp(&right.0))
        });
        items.into_iter().map(|(_, workspace)| workspace).collect()
    }

    pub fn workspace_for_config(&self, path: &Path) -> Option<&GuiWorkspace> {
        let normalized = normalize_config_path(path.to_path_buf());
        self.workspaces
            .iter()
            .find(|workspace| workspace.config_paths.contains(&normalized))
    }
    pub fn add(&mut self, path: impl Into<PathBuf>) -> PathBuf {
        let normalized = normalize_config_path(path.into());
        if let Some(id) = self.selected_workspace_id.clone() {
            self.register_config_in_workspace(&id, normalized)
        } else {
            normalized
        }
    }

    pub fn touch(&mut self, path: impl Into<PathBuf>) -> PathBuf {
        let normalized = normalize_config_path(path.into());
        if let Some(workspace_id) = self
            .workspace_for_config(&normalized)
            .map(|workspace| workspace.id.clone())
        {
            self.selected_path = Some(normalized.clone());
            self.selected_workspace_id = Some(workspace_id);
            normalized
        } else if let Some(id) = self.selected_workspace_id.clone() {
            self.register_config_in_workspace(&id, normalized)
        } else {
            normalized
        }
    }

    pub fn remove(&mut self, path: impl Into<PathBuf>) {
        let normalized = normalize_config_path(path.into());
        let key = normalized.to_string_lossy().to_string();
        self.remove_config_from_workspace(normalized.clone());
        self.aliases.remove(&key);
        self.autostart_paths.remove(&key);
        if self.selected_path.as_ref() == Some(&normalized) {
            self.selected_path = self.paths.first().cloned();
        }
    }

    pub fn set_alias(&mut self, path: impl Into<PathBuf>, alias: &str) {
        let normalized = normalize_config_path(path.into());
        let key = normalized.to_string_lossy().to_string();
        let text = alias.trim();
        if text.is_empty() {
            self.aliases.remove(&key);
        } else {
            self.aliases.insert(key, text.to_string());
        }
    }

    pub fn display_name(&self, path: impl Into<PathBuf>) -> String {
        let normalized = normalize_config_path(path.into());
        let key = normalized.to_string_lossy().to_string();
        self.aliases
            .get(&key)
            .cloned()
            .unwrap_or_else(|| config_display_name(&normalized))
    }

    pub fn add_manual_prompt_history(&mut self, prompt: &str) {
        self.manual_prompt_history =
            add_manual_prompt_history(&self.manual_prompt_history, prompt, 20);
    }

    pub fn set_autostart(&mut self, path: impl Into<PathBuf>, enabled: bool) {
        let normalized = normalize_config_path(path.into());
        let key = normalized.to_string_lossy().to_string();
        if enabled {
            self.autostart_paths.insert(key);
        } else {
            self.autostart_paths.remove(&key);
        }
    }

    pub fn is_autostart(&self, path: impl Into<PathBuf>) -> bool {
        let normalized = normalize_config_path(path.into());
        self.autostart_paths
            .contains(normalized.to_string_lossy().as_ref())
    }
}

fn registry_workspace_from_state(state: RegistryWorkspaceState) -> Option<GuiWorkspace> {
    let path = normalize_config_path(PathBuf::from(state.path));
    let id = if state.id.trim().is_empty() {
        workspace_id_for_path(&path)
    } else {
        sanitize_workspace_id(&state.id)
    };
    let mut workspace = GuiWorkspace {
        id,
        path,
        name: state.name.and_then(|name| {
            let text = name.trim().to_string();
            (!text.is_empty()).then_some(text)
        }),
        pinned: state.pinned,
        expanded: state.expanded,
        config_paths: state
            .config_paths
            .into_iter()
            .map(PathBuf::from)
            .map(normalize_config_path)
            .collect(),
        pinned_config_paths: state
            .pinned_config_paths
            .into_iter()
            .map(PathBuf::from)
            .map(normalize_config_path)
            .map(|path| path.to_string_lossy().to_string())
            .collect(),
        config_defaults: state.config_defaults,
        last_used_at: state.last_used_at,
    };
    dedup_paths(&mut workspace.config_paths);
    Some(workspace)
}

fn registry_workspace_to_state(workspace: &GuiWorkspace) -> RegistryWorkspaceState {
    let mut pinned = workspace
        .pinned_config_paths
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    pinned.sort();
    RegistryWorkspaceState {
        id: workspace.id.clone(),
        path: workspace.path.to_string_lossy().to_string(),
        name: workspace.name.clone(),
        pinned: workspace.pinned,
        expanded: workspace.expanded,
        config_paths: workspace
            .config_paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect(),
        pinned_config_paths: pinned,
        config_defaults: workspace.config_defaults.clone(),
        last_used_at: workspace.last_used_at,
    }
}

fn workspace_id_for_path(path: &Path) -> String {
    let normalized = normalize_config_path(path.to_path_buf());
    let mut hasher = DefaultHasher::new();
    normalized
        .to_string_lossy()
        .to_ascii_lowercase()
        .hash(&mut hasher);
    format!("ws-{:016x}", hasher.finish())
}

fn sanitize_workspace_id(id: &str) -> String {
    let text = id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .collect::<String>();
    if text.is_empty() {
        "ws-empty".to_string()
    } else {
        text
    }
}

fn registry_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn workspace_display_name(workspace: &GuiWorkspace) -> String {
    workspace
        .name
        .as_ref()
        .filter(|name| !name.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| {
            workspace
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.trim().is_empty())
                .unwrap_or("工作区")
                .to_string()
        })
}

fn sort_workspace_configs(workspace: &mut GuiWorkspace, _aliases: &HashMap<String, String>) {
    let pinned = &workspace.pinned_config_paths;
    workspace
        .config_paths
        .sort_by_key(|path| !pinned.contains(path.to_string_lossy().as_ref()));
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = HashSet::new();
    paths.retain(|path| seen.insert(path.to_string_lossy().to_ascii_lowercase()));
}
fn write_text_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("watchapi-state.json");
    let tmp_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&tmp_path, text)?;
    replace_file_atomic(&tmp_path, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp_path);
    })
}

#[cfg(windows)]
fn replace_file_atomic(source: &Path, target: &Path) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target_wide = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file_atomic(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::rename(source, target)
}

pub fn normalize_config_path(path: PathBuf) -> PathBuf {
    let expanded = expand_home(path);
    strip_windows_verbatim_prefix(expanded.canonicalize().unwrap_or(expanded))
}

fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return PathBuf::from(rest.to_string());
        }
    }
    path
}

fn expand_home(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") || text.starts_with("~\\") {
        if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
            let suffix = text.trim_start_matches('~').trim_start_matches(['/', '\\']);
            return PathBuf::from(home).join(suffix);
        }
    }
    path
}

pub fn config_display_name(path: &Path) -> String {
    if let Some(stem) = path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
    {
        stem.to_string()
    } else {
        path.to_string_lossy().to_string()
    }
}

pub fn normalize_manual_prompt_history(items: Vec<String>, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for item in items {
        let text = item.trim();
        if !text.is_empty() && !out.iter().any(|existing: &String| existing == text) {
            out.push(text.to_string());
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

pub fn add_manual_prompt_history(history: &[String], prompt: &str, limit: usize) -> Vec<String> {
    let text = prompt.trim();
    if text.is_empty() {
        return history.iter().take(limit).cloned().collect();
    }
    let mut updated = vec![text.to_string()];
    for item in history {
        let value = item.trim();
        if !value.is_empty() && value != text && !updated.iter().any(|existing| existing == value) {
            updated.push(value.to_string());
        }
        if updated.len() >= limit {
            break;
        }
    }
    updated
}

#[cfg(test)]
pub fn format_config_status_label(
    name: &str,
    state: &str,
    selected_endpoint: &str,
    detail: &str,
    runtime: &str,
    last_error: &str,
) -> String {
    if state == "running" {
        let endpoint = if selected_endpoint.is_empty() {
            "启动中"
        } else {
            selected_endpoint
        };
        let status = if detail.is_empty() {
            "运行中"
        } else {
            detail
        };
        let mut parts = vec![
            format!("● {name}"),
            endpoint.to_string(),
            status.to_string(),
        ];
        if !runtime.is_empty() {
            parts.push(runtime.to_string());
        }
        if !last_error.is_empty() {
            parts.push(format!("异常: {last_error}"));
        }
        return parts.join(" | ");
    }
    if state == "error" {
        return format!(
            "! {name} | 异常 | {}",
            if detail.is_empty() {
                "需要检查"
            } else {
                detail
            }
        );
    }
    format!("○ {name} | 已停止")
}

pub fn format_pause_state_label(auto_paused: bool, completion_pause_detected: bool) -> String {
    if auto_paused && completion_pause_detected {
        return "检测到完成关键词，自动续航当前已暂停".to_string();
    }
    if auto_paused {
        return "自动续航已暂停".to_string();
    }
    String::new()
}

pub fn close_action_prompt_text(running_count: usize) -> (String, String) {
    if running_count > 0 {
        return (
            "关闭 WatchApi".to_string(),
            format!("当前有 {running_count} 个配置仍在运行。要直接关闭并停止，还是进入系统托盘后台运行？"),
        );
    }
    (
        "关闭 WatchApi".to_string(),
        "要直接关闭 WatchApi，还是进入系统托盘后台运行？".to_string(),
    )
}

pub fn tray_status_label(running_count: usize, error_count: usize) -> String {
    format!("运行 {running_count} | 异常 {error_count}")
}

#[cfg(test)]
pub fn portable_package_entries() -> Vec<&'static str> {
    vec![
        "watchapi-gui.exe",
        "watchapi-cli.exe",
        "README.md",
        "Configs/",
        "ProxyConfigs/",
        "logs/",
        "prompt-library.json",
    ]
}

#[cfg(test)]
pub fn format_duration(seconds: f64) -> String {
    let total = seconds.max(0.0) as u64;
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let secs = total % 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}m")
    } else if minutes > 0 {
        format!("{minutes}m{secs:02}s")
    } else {
        format!("{secs}s")
    }
}

pub fn session_log_path(config_path: &Path, root: &Path) -> PathBuf {
    let stem = config_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("config");
    let safe_name = sanitize_log_name(stem);
    root.join(format!("{safe_name}.log"))
}

pub fn append_session_log(config_path: &Path, text: &str, root: &Path) -> std::io::Result<()> {
    let _guard = session_log_lock().lock().ok();
    let path = session_log_path(config_path, root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    rotate_log_file(&path, LOG_MAX_BYTES, LOG_BACKUP_COUNT)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(text.as_bytes())
}

pub fn rotate_log_file(path: &Path, max_bytes: u64, backups: usize) -> std::io::Result<()> {
    if max_bytes == 0 || backups == 0 || !path.exists() {
        return Ok(());
    }
    let metadata = path.metadata()?;
    if metadata.len() <= max_bytes {
        return Ok(());
    }
    for index in (1..=backups).rev() {
        let source = log_backup_path(path, index);
        let target = log_backup_path(path, index + 1);
        if index == backups && source.exists() {
            fs::remove_file(&source)?;
            continue;
        }
        if source.exists() {
            fs::rename(&source, &target)?;
        }
    }
    fs::rename(path, log_backup_path(path, 1))
}

pub fn log_backup_path(path: &Path, index: usize) -> PathBuf {
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("config");
    let suffix = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{value}"))
        .unwrap_or_default();
    path.with_file_name(format!("{stem}.{index}{suffix}"))
}

pub fn search_log_file(path: &Path, keyword: &str, limit: usize) -> Vec<String> {
    let needle = keyword.to_lowercase();
    if needle.trim().is_empty() {
        return Vec::new();
    }
    let Ok(file) = fs::File::open(path) else {
        return Vec::new();
    };
    let reader = std::io::BufReader::new(file);
    let mut matches = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.unwrap_or_default();
        if line.to_lowercase().contains(&needle) {
            matches.push(format!("{}: {}\n", index + 1, line));
            if matches.len() >= limit {
                break;
            }
        }
    }
    matches
}

pub fn add_config_initial_dir(app_root: &Path, cwd: &Path) -> PathBuf {
    let configs = app_root.join("Configs");
    if configs.exists() {
        configs
    } else {
        cwd.to_path_buf()
    }
}

pub fn default_agent_command_for_driver(driver: &str) -> Option<Vec<String>> {
    match driver.trim().to_ascii_lowercase().as_str() {
        "codex" => Some(vec![default_codex_command_name().to_string()]),
        "claude-code" => Some(vec!["claude".to_string()]),
        "opencode" => Some(vec!["opencode".to_string()]),
        _ => None,
    }
}

fn default_codex_command_name() -> &'static str {
    if cfg!(windows) {
        "codex.cmd"
    } else {
        "codex"
    }
}

pub fn default_agent_home_for_driver(driver: &str, home: &Path) -> Option<String> {
    match driver.trim().to_ascii_lowercase().as_str() {
        "codex" => Some(home.join(".codex").to_string_lossy().to_string()),
        "claude-code" => Some(home.join(".claude").to_string_lossy().to_string()),
        _ => None,
    }
}

fn sanitize_log_name(name: &str) -> String {
    let text = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches(&['.', '_'][..])
        .to_string();
    if text.is_empty() {
        "config".to_string()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_round_trips_alias_history_and_autostart() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("gui.json");
        let config = tmp.path().join("Configs").join("A.json");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::write(&config, "{}").unwrap();

        let mut registry = GuiConfigRegistry::new(state.clone());
        let workspace_id = registry.open_workspace(tmp.path().join("Workspace"));
        let normalized = registry.register_config_in_workspace(&workspace_id, &config);
        registry.set_alias(&config, "主配置");
        registry.add_manual_prompt_history(" first ");
        registry.add_manual_prompt_history("second");
        registry.add_manual_prompt_history("first");
        registry.set_autostart(&config, true);
        registry.save().unwrap();

        let mut loaded = GuiConfigRegistry::new(state);
        loaded.load();

        assert_eq!(loaded.paths, vec![normalized.clone()]);
        assert_eq!(loaded.selected_path, Some(normalized.clone()));
        assert_eq!(loaded.display_name(&config), "主配置");
        assert!(loaded.is_autostart(&config));
        assert_eq!(
            loaded.manual_prompt_history,
            vec!["first".to_string(), "second".to_string()]
        );
    }

    #[test]
    fn registry_round_trips_workspace_config_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("gui.json");
        let mut registry = GuiConfigRegistry::new(state.clone());
        let workspace_id = registry.open_workspace(tmp.path().join("Workspace"));
        registry
            .workspaces
            .iter_mut()
            .find(|workspace| workspace.id == workspace_id)
            .unwrap()
            .config_defaults = json!({
            "probe_interval_seconds": 40,
            "auto_prompt": "继续"
        });
        registry.save().unwrap();

        let mut loaded = GuiConfigRegistry::new(state);
        loaded.load();

        let workspace = loaded
            .workspaces
            .iter()
            .find(|workspace| workspace.id == workspace_id)
            .unwrap();
        assert_eq!(
            workspace.config_defaults["probe_interval_seconds"],
            json!(40)
        );
        assert_eq!(workspace.config_defaults["auto_prompt"], json!("继续"));
    }

    #[test]
    fn registry_discards_flat_configs_without_workspaces() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("gui.json");
        let old_config = tmp.path().join("old.json");
        fs::write(&old_config, "{}").unwrap();
        fs::write(
            &state,
            serde_json::json!({
                "configs": [old_config.to_string_lossy()],
                "selected": old_config.to_string_lossy(),
                "aliases": { old_config.to_string_lossy().to_string(): "旧配置" },
                "autostart": [old_config.to_string_lossy()],
                "manual_prompt_history": ["keep"]
            })
            .to_string(),
        )
        .unwrap();

        let mut registry = GuiConfigRegistry::new(state);
        registry.load();

        assert!(registry.paths.is_empty());
        assert!(registry.selected_path.is_none());
        assert!(registry.sorted_workspaces().is_empty());
        assert_eq!(registry.manual_prompt_history, vec!["keep".to_string()]);
    }

    #[test]
    fn registry_does_not_recover_unregistered_hosted_workspace_configs_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join(".watchapi-gui.json");
        let workspace_path = tmp.path().join("HHHL");
        fs::create_dir_all(&workspace_path).unwrap();
        let workspace_id = workspace_id_for_path(&workspace_path);
        let host_dir = tmp.path().join("Workspaces").join(&workspace_id);
        fs::create_dir_all(&host_dir).unwrap();
        let hosted = host_dir.join("新配置.json");
        fs::write(
            &hosted,
            json!({
                "config_name": "主线",
                "workdir": workspace_path.to_string_lossy()
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            host_dir.join("其它.json"),
            json!({
                "config_name": "其它",
                "workdir": tmp.path().join("Other").to_string_lossy()
            })
            .to_string(),
        )
        .unwrap();
        fs::write(host_dir.join(".watchapi-state.json"), "{}").unwrap();
        fs::write(
            &state,
            json!({
                "workspaces": [{
                    "id": workspace_id,
                    "path": workspace_path.to_string_lossy(),
                    "expanded": true,
                    "config_paths": []
                }],
                "selected_workspace": workspace_id
            })
            .to_string(),
        )
        .unwrap();

        let mut registry = GuiConfigRegistry::new(state);
        registry.load();

        let normalized = normalize_config_path(hosted);
        let workspace = registry
            .workspaces
            .iter()
            .find(|workspace| workspace.id == workspace_id)
            .unwrap();
        assert!(
            !workspace.config_paths.contains(&normalized),
            "启动加载注册表不能把工作区目录里的残留 json 全部恢复到左侧配置树"
        );
        assert!(!registry.paths.contains(&normalized));
    }

    #[test]
    fn registry_reuses_workspace_by_normalized_path_and_stable_id() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("gui.json");
        let workspace = tmp.path().join("Workspace");
        fs::create_dir_all(&workspace).unwrap();

        let mut registry = GuiConfigRegistry::new(state);
        let first = registry.open_workspace(&workspace);
        let second = registry.open_workspace(&workspace);

        assert_eq!(first, second);
        assert_eq!(registry.sorted_workspaces().len(), 1);
        assert_eq!(registry.current_workspace_id(), Some(first.as_str()));
        assert!(first
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-'));
    }

    #[test]
    fn registry_workspace_and_config_pinning_affect_order() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("gui.json");
        let first_dir = tmp.path().join("A");
        let second_dir = tmp.path().join("B");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let mut registry = GuiConfigRegistry::new(state);
        let first = registry.open_workspace(&first_dir);
        let second = registry.open_workspace(&second_dir);
        registry.set_workspace_pinned(&first, true);
        let b = registry.register_config_in_workspace(&second, tmp.path().join("b.json"));
        let a = registry.register_config_in_workspace(&second, tmp.path().join("a.json"));
        registry.set_config_pinned(&a, true);

        let workspaces = registry.sorted_workspaces();
        assert_eq!(workspaces[0].id, first);
        assert_eq!(workspaces[1].id, second);
        assert_eq!(workspaces[1].config_paths, vec![a, b]);
    }

    #[test]
    fn registry_touch_keeps_existing_config_in_original_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("gui.json");
        let first_dir = tmp.path().join("A");
        let second_dir = tmp.path().join("B");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let mut registry = GuiConfigRegistry::new(state);
        let first = registry.open_workspace(&first_dir);
        let config = registry.register_config_in_workspace(&first, tmp.path().join("a.json"));
        let second = registry.open_workspace(&second_dir);
        registry.selected_workspace_id = Some(second.clone());

        let selected = registry.touch(&config);

        assert_eq!(selected, config);
        assert_eq!(registry.current_workspace_id(), Some(first.as_str()));
        assert!(registry
            .workspaces
            .iter()
            .find(|workspace| workspace.id == first)
            .is_some_and(|workspace| workspace.config_paths.contains(&config)));
        assert!(registry
            .workspaces
            .iter()
            .find(|workspace| workspace.id == second)
            .is_some_and(|workspace| !workspace.config_paths.contains(&config)));
    }

    #[test]
    fn registry_touch_does_not_reorder_existing_config_or_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("gui.json");
        let first_dir = tmp.path().join("A");
        let second_dir = tmp.path().join("B");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let mut registry = GuiConfigRegistry::new(state);
        let first = registry.open_workspace(&first_dir);
        let second = registry.open_workspace(&second_dir);
        let a = registry.register_config_in_workspace(&first, tmp.path().join("a.json"));
        let b = registry.register_config_in_workspace(&first, tmp.path().join("b.json"));
        let workspace_order_before = registry
            .sorted_workspaces()
            .into_iter()
            .map(|workspace| workspace.id)
            .collect::<Vec<_>>();
        let config_order_before = registry
            .workspaces
            .iter()
            .find(|workspace| workspace.id == first)
            .unwrap()
            .config_paths
            .clone();

        let selected = registry.touch(&a);

        assert_eq!(selected, a);
        assert_eq!(registry.current_workspace_id(), Some(first.as_str()));
        assert_eq!(
            registry
                .workspaces
                .iter()
                .find(|workspace| workspace.id == first)
                .unwrap()
                .config_paths,
            config_order_before
        );
        assert_eq!(
            registry
                .sorted_workspaces()
                .into_iter()
                .map(|workspace| workspace.id)
                .collect::<Vec<_>>(),
            workspace_order_before
        );
        assert_eq!(registry.workspaces[0].id, first);
        assert_eq!(registry.workspaces[1].id, second);
        assert_eq!(config_order_before, vec![b, a]);
    }

    #[test]
    fn registry_register_config_keeps_single_workspace_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("gui.json");
        let first_dir = tmp.path().join("A");
        let second_dir = tmp.path().join("B");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let mut registry = GuiConfigRegistry::new(state);
        let first = registry.open_workspace(&first_dir);
        let second = registry.open_workspace(&second_dir);
        let config = tmp.path().join("shared.json");
        let normalized = registry.register_config_in_workspace(&first, &config);
        registry.set_config_pinned(&config, true);

        registry.register_config_in_workspace(&second, &config);

        assert!(registry
            .workspaces
            .iter()
            .find(|workspace| workspace.id == first)
            .is_some_and(|workspace| !workspace.config_paths.contains(&normalized)
                && !workspace
                    .pinned_config_paths
                    .contains(normalized.to_string_lossy().as_ref())));
        assert!(registry
            .workspaces
            .iter()
            .find(|workspace| workspace.id == second)
            .is_some_and(
                |workspace| workspace.config_paths == vec![normalized.clone()]
                    && !workspace
                        .pinned_config_paths
                        .contains(normalized.to_string_lossy().as_ref())
            ));
        assert_eq!(
            registry
                .workspaces
                .iter()
                .filter(|workspace| workspace.config_paths.contains(&normalized))
                .count(),
            1
        );
    }

    #[test]
    fn registry_remove_workspace_does_not_delete_files() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("gui.json");
        let workspace = tmp.path().join("Workspace");
        let hosted = tmp.path().join("hosted.json");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(&hosted, "{}").unwrap();
        let mut registry = GuiConfigRegistry::new(state);
        let id = registry.open_workspace(&workspace);
        registry.register_config_in_workspace(&id, &hosted);

        registry.remove_workspace(&id);

        assert!(workspace.exists());
        assert!(hosted.exists());
        assert!(registry.sorted_workspaces().is_empty());
        assert!(registry.paths.is_empty());
    }

    #[test]
    fn registry_remove_config_from_workspace_does_not_recurse_or_delete_file() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("gui.json");
        let workspace = tmp.path().join("Workspace");
        let hosted = tmp.path().join("hosted.json");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(&hosted, "{}").unwrap();
        let mut registry = GuiConfigRegistry::new(state);
        let id = registry.open_workspace(&workspace);
        let normalized = registry.register_config_in_workspace(&id, &hosted);
        registry.set_alias(&hosted, "主线");
        registry.set_autostart(&hosted, true);
        registry.set_config_pinned(&hosted, true);

        registry.remove_config_from_workspace(&hosted);

        assert!(hosted.exists());
        assert!(!registry.paths.contains(&normalized));
        assert!(registry.display_name(&hosted).contains("hosted"));
        assert!(!registry.is_autostart(&hosted));
        let workspace = registry
            .workspaces
            .iter()
            .find(|workspace| workspace.id == id)
            .expect("workspace should remain");
        assert!(!workspace.config_paths.contains(&normalized));
        assert!(workspace.pinned_config_paths.is_empty());
    }
    #[test]
    fn log_helpers_rotate_and_search() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("bad name.json");
        let root = tmp.path().join("logs");
        let path = session_log_path(&config, &root);
        append_session_log(&config, "hello\nneedle line\n", &root).unwrap();

        assert_eq!(path.file_name().unwrap().to_string_lossy(), "bad_name.log");
        assert_eq!(
            search_log_file(&path, "NEEDLE", 80),
            vec!["2: needle line\n".to_string()]
        );

        fs::write(&path, "abcdef").unwrap();
        rotate_log_file(&path, 1, 2).unwrap();
        assert!(log_backup_path(&path, 1).exists());
    }

    #[test]
    fn append_session_log_reports_write_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let root_file = tmp.path().join("not-a-dir");
        fs::write(&root_file, "block parent creation").unwrap();
        let config = tmp.path().join("blocked.json");

        assert!(append_session_log(&config, "lost?\n", &root_file).is_err());
    }

    #[test]
    fn status_and_history_match_python_semantics() {
        assert_eq!(
            add_manual_prompt_history(&["old".to_string(), "x".to_string()], " old ", 20),
            vec!["old".to_string(), "x".to_string()]
        );
        assert_eq!(
            add_manual_prompt_history(
                &[
                    "third".to_string(),
                    "second".to_string(),
                    "first".to_string()
                ],
                "new",
                20
            ),
            vec![
                "new".to_string(),
                "third".to_string(),
                "second".to_string(),
                "first".to_string()
            ],
            "历史提示词下拉应保持最近使用优先，不能在新增后把旧历史倒序"
        );
        assert_eq!(
            format_config_status_label("A", "running", "", "", "3s", "err"),
            "● A | 启动中 | 运行中 | 3s | 异常: err"
        );
        assert_eq!(
            format_pause_state_label(true, true),
            "检测到完成关键词，自动续航当前已暂停"
        );
        assert_eq!(format_duration(61.0), "1m01s");
    }

    #[test]
    fn close_prompt_and_tray_status_match_python_semantics() {
        assert_eq!(
            close_action_prompt_text(2),
            (
                "关闭 WatchApi".to_string(),
                "当前有 2 个配置仍在运行。要直接关闭并停止，还是进入系统托盘后台运行？".to_string()
            )
        );
        assert_eq!(
            close_action_prompt_text(0),
            (
                "关闭 WatchApi".to_string(),
                "要直接关闭 WatchApi，还是进入系统托盘后台运行？".to_string()
            )
        );
        assert_eq!(tray_status_label(3, 1), "运行 3 | 异常 1");
        assert!(portable_package_entries().contains(&"watchapi-gui.exe"));
        assert!(portable_package_entries().contains(&"Configs/"));
    }

    #[test]
    fn normalize_config_path_strips_windows_verbatim_prefix_for_display() {
        let plain = PathBuf::from(r"C:\Users\ExampleUser\Desktop\TEST\config.json");
        let prefixed = PathBuf::from(r"\\?\C:\Users\ExampleUser\Desktop\TEST\config.json");
        let unc_prefixed = PathBuf::from(r"\\?\UNC\server\share\config.json");

        #[cfg(windows)]
        {
            assert_eq!(strip_windows_verbatim_prefix(prefixed), plain);
            assert_eq!(
                strip_windows_verbatim_prefix(unc_prefixed),
                PathBuf::from(r"\\server\share\config.json")
            );
        }

        #[cfg(not(windows))]
        {
            assert_eq!(strip_windows_verbatim_prefix(prefixed.clone()), prefixed);
            assert_eq!(
                strip_windows_verbatim_prefix(unc_prefixed.clone()),
                unc_prefixed
            );
        }
    }
}
