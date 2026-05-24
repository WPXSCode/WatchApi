use crate::agent::AgentProcess;
use crate::atomic_write::write_text_atomic;
use crate::config::{AppConfig, EndpointConfig};
use crate::control::{
    enqueue_manual_prompt, pop_manual_prompt, read_control_state, update_control_state,
};
use crate::guard_proxy::{GuardAuditSnapshot, GuardProxyServer};
use crate::health::EndpointHealthTracker;
use crate::http_probe::HttpProbe;
use crate::probe::ProbeResult;
use crate::selector::choose_best_endpoint;
use crate::terminal::TerminalControl;
use crate::terminal_emulator::TerminalView;
use crate::tokens::{format_token_cost, TokenUsage};
use chrono::{DateTime, Local};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const GUARD_PROXY_PORT_MIN: u16 = 45000;
const GUARD_PROXY_PORT_MAX: u16 = 59999;
static GUARD_PROXY_PORT_REGISTRY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeState {
    Stopped,
    Probing,
    WaitingAvailable,
    Running,
    Idle,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub state_label: String,
    pub rows: Vec<EndpointRow>,
    pub terminal_output: String,
    pub terminal_output_revision: u64,
    pub terminal_view_revision: u64,
    pub terminal_view: Option<TerminalView>,
    pub terminal_process_id: Option<u32>,
    pub terminal_control: Option<TerminalControl>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeEvent {
    Snapshot(RuntimeSnapshot),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeEventSignature {
    state_label: String,
    current_endpoint: Option<String>,
    terminal_output_revision: u64,
    terminal_view_revision: u64,
    terminal_process_id: Option<u32>,
    force_probe_endpoint: Option<String>,
    fixed_endpoint: Option<String>,
    request_counts: Vec<(String, u64)>,
    last_status_codes: Vec<(String, Option<u16>)>,
    probe_keys: Vec<(String, bool, bool, bool, Option<u16>)>,
    runtime_tick: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRow {
    pub enabled: bool,
    pub force_probe: bool,
    pub fixed: bool,
    pub guard_proxy_enabled: bool,
    pub name: String,
    pub url: String,
    pub weight: i64,
    pub request_status: String,
    pub selected: bool,
    pub runtime_state: String,
    pub agent_runtime: String,
    pub endpoint_runtime: String,
    pub token_cost: String,
    pub historical_token_cost: String,
    pub request_count: u64,
    pub last_request_at: String,
    pub last_status_code: String,
    pub next_probe_in_seconds: Option<u64>,
}

pub struct RuntimeCore {
    config: AppConfig,
    health: EndpointHealthTracker,
    current_endpoint: Option<String>,
    state: RuntimeState,
    agent: Option<AgentProcess>,
    guard_proxy: Option<GuardProxyServer>,
    guard_audit_by_endpoint: HashMap<String, GuardAuditSnapshot>,
    fixed_endpoint: Option<String>,
    force_probe_endpoint: Option<String>,
    token_usage_by_endpoint: HashMap<String, TokenUsage>,
    historical_usage_by_key: HashMap<String, TokenUsage>,
    usage_state_path: Option<PathBuf>,
    usage_save_error: Option<String>,
    request_count_by_endpoint: HashMap<String, u64>,
    last_request_at_by_endpoint: HashMap<String, String>,
    last_status_code_by_endpoint: HashMap<String, Option<u16>>,
    last_availability: HashMap<String, ProbeResult>,
    started_at_by_endpoint: HashMap<String, Instant>,
    last_activity_at_by_endpoint: HashMap<String, String>,
    runtime_seconds_by_endpoint: HashMap<String, f64>,
    last_agent_token_usage_by_session: HashMap<String, TokenUsage>,
    transient_failures_by_endpoint: HashMap<String, u32>,
    stall_failures_by_endpoint: HashMap<String, u32>,
    endpoint_request_failures_by_endpoint: HashMap<String, u32>,
    endpoint_auto_prompt_blocked_until: HashMap<String, Instant>,
    next_probe_at: HashMap<String, Instant>,
    polluted_until: HashMap<String, Instant>,
    startup_failed_until: HashMap<String, Instant>,
    startup_failure_error: HashMap<String, String>,
    probing_endpoint: Option<String>,
    counted_probe_inflight: HashSet<String>,
    event_tx: Option<Sender<RuntimeEvent>>,
    last_event_snapshot: Mutex<Option<RuntimeSnapshot>>,
    last_event_signature: Mutex<Option<RuntimeEventSignature>>,
    pending_initial_prompt: Option<String>,
    last_prompt_at: Option<Instant>,
    last_auto_prompt_signature: Option<(String, String)>,
    waiting_for_assistant_progress: bool,
    trigger_now_clear_failed: bool,
    force_new_session_once: bool,
    force_current_probe_once: bool,
    confirm_current_probe_once: bool,
    force_full_probe_once: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeMode {
    Full,
    ModelsOnly,
    Upgrade,
}

impl RuntimeCore {
    pub fn new(config: AppConfig) -> Self {
        let health = EndpointHealthTracker::new(
            config.endpoint_failure_threshold,
            config.endpoint_recovery_threshold,
        );
        let usage_state_path = config
            .config_path
            .as_ref()
            .map(|path| path.with_file_name(".watchapi-usage.json"));
        let historical_usage_by_key = usage_state_path
            .as_ref()
            .map(load_usage_state)
            .unwrap_or_default();
        Self {
            config,
            health,
            current_endpoint: None,
            state: RuntimeState::Stopped,
            agent: None,
            guard_proxy: None,
            guard_audit_by_endpoint: HashMap::new(),
            fixed_endpoint: None,
            force_probe_endpoint: None,
            token_usage_by_endpoint: HashMap::new(),
            historical_usage_by_key,
            usage_state_path,
            usage_save_error: None,
            request_count_by_endpoint: HashMap::new(),
            last_request_at_by_endpoint: HashMap::new(),
            last_status_code_by_endpoint: HashMap::new(),
            last_availability: HashMap::new(),
            started_at_by_endpoint: HashMap::new(),
            last_activity_at_by_endpoint: HashMap::new(),
            runtime_seconds_by_endpoint: HashMap::new(),
            last_agent_token_usage_by_session: HashMap::new(),
            transient_failures_by_endpoint: HashMap::new(),
            stall_failures_by_endpoint: HashMap::new(),
            endpoint_request_failures_by_endpoint: HashMap::new(),
            endpoint_auto_prompt_blocked_until: HashMap::new(),
            next_probe_at: HashMap::new(),
            polluted_until: HashMap::new(),
            startup_failed_until: HashMap::new(),
            startup_failure_error: HashMap::new(),
            probing_endpoint: None,
            counted_probe_inflight: HashSet::new(),
            event_tx: None,
            last_event_snapshot: Mutex::new(None),
            last_event_signature: Mutex::new(None),
            pending_initial_prompt: None,
            last_prompt_at: None,
            last_auto_prompt_signature: None,
            waiting_for_assistant_progress: false,
            trigger_now_clear_failed: false,
            force_new_session_once: false,
            force_current_probe_once: false,
            confirm_current_probe_once: false,
            force_full_probe_once: false,
        }
    }

    pub async fn tick(&mut self, probe: &HttpProbe) -> Option<EndpointConfig> {
        self.sync_control_state();
        let auto_paused = self.auto_paused();
        let mut current_failed = false;
        let mut skip_current = false;
        let force_probe_current = self.force_current_probe_once;
        let confirm_probe_current = self.confirm_current_probe_once;
        let force_full_probe = self.force_full_probe_once;
        self.force_current_probe_once = false;
        self.confirm_current_probe_once = false;
        let mut overrides = HashMap::new();
        if auto_paused && self.current_endpoint.is_some() && !force_full_probe {
            if let Some(current) = self.current_endpoint.clone() {
                if let Some(endpoint) = self.endpoint_by_name(&current).cloned() {
                    self.maybe_drive_prompt(&endpoint);
                    self.record_agent_usage(&endpoint);
                    self.health.update(&self.config.endpoints, &overrides);
                    return Some(endpoint);
                }
            }
        }
        if let Some(current) = self.current_endpoint.clone() {
            let mut mark_polluted = false;
            if self.current_guard_proxy_unreachable() {
                current_failed = true;
                self.state = RuntimeState::Error("保护层端口失效".to_string());
            }
            if let Some(agent) = self.agent.as_mut() {
                agent.poll_monitor();
                if !agent.is_running() {
                    current_failed = true;
                } else if agent.pollution_detected {
                    overrides.insert(current.clone(), ProbeResult::synthetic_polluted());
                    agent.pollution_detected = false;
                    current_failed = true;
                    skip_current = true;
                    mark_polluted = true;
                } else if agent.completion_pause_detected {
                    agent.clear_completion_pause_detected();
                } else if agent.endpoint_failure_detected {
                    let mut result = ProbeResult::synthetic_unavailable();
                    result.status_code = agent.endpoint_failure_status_code;
                    result.retry_after_seconds = agent.endpoint_failure_retry_after_seconds;
                    overrides.insert(current.clone(), result);
                    agent.endpoint_failure_detected = false;
                    agent.mark_current_turn_failed();
                    self.waiting_for_assistant_progress = false;
                    self.state = RuntimeState::Error("请求失败".to_string());
                    if self.record_endpoint_request_failure_reached_threshold(&current) {
                        current_failed = true;
                        skip_current = true;
                    }
                } else if agent.transient_endpoint_failure_detected {
                    overrides.insert(current.clone(), ProbeResult::synthetic_unavailable());
                    agent.transient_endpoint_failure_detected = false;
                    agent.mark_current_turn_failed();
                    self.waiting_for_assistant_progress = false;
                    self.state = RuntimeState::Error("网络波动".to_string());
                    if self.record_transient_failure(&current)
                        >= self.config.transient_network_failure_threshold
                    {
                        current_failed = true;
                        skip_current = true;
                    }
                } else if !auto_paused && agent.is_turn_stalled(self.config.turn_stall_seconds) {
                    overrides.insert(current.clone(), ProbeResult::synthetic_unavailable());
                    self.state = RuntimeState::Error("响应卡死".to_string());
                    if self.record_stall_failure(&current)
                        >= self.config.turn_stall_failure_threshold
                    {
                        current_failed = true;
                        skip_current = true;
                    }
                } else {
                    self.transient_failures_by_endpoint.remove(&current);
                    self.stall_failures_by_endpoint.remove(&current);
                }
            }
            if mark_polluted {
                self.mark_endpoint_polluted(&current);
            }
        }
        self.remember_probe_results(overrides.clone());

        if force_probe_current || confirm_probe_current {
            if let Some(current) = self.current_endpoint.clone() {
                if !current_failed {
                    if let Some(endpoint) = self.endpoint_by_name(&current).cloned() {
                        let now = Instant::now();
                        let result = if confirm_probe_current {
                            let cached_before_due = self
                                .next_probe_at
                                .get(&endpoint.name)
                                .is_some_and(|next| now < *next)
                                .then(|| {
                                    self.last_availability
                                        .get(&endpoint.name)
                                        .cloned()
                                        .map(cached_probe_result)
                                })
                                .flatten();
                            self.hard_cooldown_result(&endpoint, now)
                                .or_else(|| self.cooldown_result(&endpoint, now))
                                .or(cached_before_due)
                        } else {
                            self.hard_cooldown_result(&endpoint, now)
                        };
                        if let Some(result) = result {
                            current_failed = !result.available;
                            if current_failed {
                                skip_current = true;
                            }
                            overrides.insert(endpoint.name.clone(), result);
                        } else {
                            self.mark_probe_started(&endpoint);
                            let result = probe.probe_endpoint(&endpoint, &self.config).await;
                            current_failed = !result.available;
                            if current_failed {
                                skip_current = true;
                            }
                            self.remember_single_probe_result(&endpoint, &result, now);
                            self.counted_probe_inflight.remove(&endpoint.name);
                            if self.probing_endpoint.as_deref() == Some(endpoint.name.as_str()) {
                                self.probing_endpoint = None;
                            }
                            overrides.insert(endpoint.name.clone(), cached_probe_result(result));
                            self.publish_snapshot_event();
                        }
                    }
                }
            }
        }

        if auto_paused && self.current_endpoint.is_some() && !current_failed && !force_full_probe {
            if let Some(current) = self.current_endpoint.clone() {
                if let Some(endpoint) = self.endpoint_by_name(&current).cloned() {
                    self.maybe_drive_prompt(&endpoint);
                    self.record_agent_usage(&endpoint);
                    self.health.update(&self.config.endpoints, &overrides);
                    return Some(endpoint);
                }
            }
        }

        let (selected, mut availability) = self
            .select_endpoint_with_options(probe, current_failed, skip_current, force_full_probe)
            .await;
        if force_full_probe {
            self.force_full_probe_once = false;
        }
        availability.extend(overrides);
        self.remember_fresh_probe_results(availability.clone());
        self.health.update(&self.config.endpoints, &availability);

        let Some(selected) = selected else {
            self.stop_agent();
            self.current_endpoint = None;
            self.probing_endpoint = None;
            self.counted_probe_inflight.clear();
            if !matches!(self.state, RuntimeState::Error(_)) {
                self.state = RuntimeState::WaitingAvailable;
            }
            self.publish_snapshot_event();
            return None;
        };

        let mut selected = selected;
        let mut changed =
            self.current_endpoint.as_deref() != Some(selected.name.as_str()) || current_failed;
        if changed
            && self.current_endpoint.as_deref() == Some(selected.name.as_str())
            && self.agent.as_ref().is_some_and(AgentProcess::is_running)
            && availability
                .get(&selected.name)
                .is_some_and(|result| result.available)
        {
            changed = false;
        }
        loop {
            if !changed {
                self.maybe_drive_prompt(&selected);
                self.record_agent_usage(&selected);
                return Some(selected);
            }
            match self.switch_to(selected.clone()) {
                Ok(()) => {
                    self.maybe_drive_prompt(&selected);
                    self.record_agent_usage(&selected);
                    return Some(selected);
                }
                Err(err) => {
                    self.mark_startup_failure(&selected.name, err.clone());
                    self.state = RuntimeState::Error(format!("启动失败：{err}"));
                    let startup_failed = self.synthetic_startup_failure_result(&selected.name);
                    availability.insert(selected.name.clone(), startup_failed);
                    self.health.update(&self.config.endpoints, &availability);
                    let (next_selected, next_availability) =
                        self.select_endpoint(probe, true, true).await;
                    availability.extend(next_availability);
                    let next_selected =
                        next_selected.filter(|endpoint| endpoint.name != selected.name)?;
                    selected = next_selected;
                    changed = true;
                }
            }
        }
    }

    pub fn tick_blocking(&mut self, probe: &HttpProbe) -> Option<EndpointConfig> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        self.tick_with_runtime(probe, &runtime)
    }

    pub fn tick_with_runtime(
        &mut self,
        probe: &HttpProbe,
        runtime: &tokio::runtime::Runtime,
    ) -> Option<EndpointConfig> {
        runtime.block_on(self.tick(probe))
    }

    pub fn poll_terminal_events(&mut self) {
        if let Some(agent) = self.agent.as_mut() {
            agent.poll_monitor();
            self.publish_snapshot_event();
        }
    }

    pub fn stop(&mut self) {
        self.stop_agent();
        self.current_endpoint = None;
        self.state = RuntimeState::Stopped;
        self.probing_endpoint = None;
        self.counted_probe_inflight.clear();
        self.publish_snapshot_event();
    }

    pub fn restart_agent(&mut self) {
        self.stop_agent();
        self.current_endpoint = None;
        self.force_current_probe_once = false;
        self.confirm_current_probe_once = false;
        self.force_full_probe_once = false;
        self.pending_initial_prompt = None;
        self.last_prompt_at = None;
        self.last_auto_prompt_signature = None;
        self.waiting_for_assistant_progress = false;
        self.trigger_now_clear_failed = false;
        self.state = RuntimeState::WaitingAvailable;
        self.probing_endpoint = None;
        self.counted_probe_inflight.clear();
        self.publish_snapshot_event();
    }

    pub fn force_current_probe_next_tick(&mut self) {
        self.force_current_probe_once = true;
        self.publish_snapshot_event();
    }

    pub fn confirm_current_probe_next_tick(&mut self) {
        self.confirm_current_probe_once = true;
        self.publish_snapshot_event();
    }

    pub fn force_full_probe_next_tick(&mut self) {
        self.force_full_probe_once = true;
        self.publish_snapshot_event();
    }

    fn auto_paused(&self) -> bool {
        let Some(path) = self.config.config_path.as_ref() else {
            return false;
        };
        read_control_state(path)
            .get("auto_paused")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true)
    }
    pub fn terminal_output(&self) -> String {
        self.agent
            .as_ref()
            .map(AgentProcess::terminal_output_text)
            .unwrap_or_default()
    }

    pub fn terminal_output_revision(&self) -> u64 {
        self.agent
            .as_ref()
            .map(AgentProcess::terminal_output_revision)
            .unwrap_or_default()
    }

    pub fn terminal_view_revision(&self) -> u64 {
        self.agent
            .as_ref()
            .map(AgentProcess::terminal_view_revision)
            .unwrap_or_default()
    }

    pub fn terminal_view(&self) -> Option<TerminalView> {
        self.agent.as_ref().and_then(AgentProcess::terminal_view)
    }

    pub fn terminal_process_id(&self) -> Option<u32> {
        self.agent
            .as_ref()
            .and_then(AgentProcess::terminal_process_id)
    }

    pub fn terminal_control(&self) -> Option<TerminalControl> {
        self.agent.as_ref().and_then(AgentProcess::terminal_control)
    }

    pub fn write_user_input(&mut self, text: &str) -> Result<(), String> {
        if let Some(agent) = &self.agent {
            agent
                .write_user_input(text)
                .map_err(|err| format!("终端输入失败：{err}"))?;
        }
        Ok(())
    }

    pub fn resize_terminal(&mut self, rows: u16, cols: u16) -> Result<(), String> {
        if let Some(agent) = &self.agent {
            agent
                .resize_terminal(rows, cols)
                .map_err(|err| format!("终端尺寸调整失败：{err}"))?;
        }
        Ok(())
    }

    pub fn scroll_terminal(&mut self, delta: i32) -> Result<(), String> {
        if let Some(agent) = &self.agent {
            agent
                .scroll_terminal(delta)
                .map_err(|err| format!("终端滚动失败：{err}"))?;
        }
        Ok(())
    }

    pub fn scroll_terminal_bottom(&mut self) -> Result<(), String> {
        if let Some(agent) = &self.agent {
            agent
                .scroll_terminal_bottom()
                .map_err(|err| format!("终端滚动失败：{err}"))?;
        }
        Ok(())
    }

    pub fn scroll_terminal_to_offset(&mut self, offset: usize) -> Result<(), String> {
        if let Some(agent) = &self.agent {
            agent
                .scroll_terminal_to_offset(offset)
                .map_err(|err| format!("终端滚动失败：{err}"))?;
        }
        Ok(())
    }

    pub fn mark_terminal_command_failed(&mut self, error: String) {
        self.state = RuntimeState::Error(error);
        self.publish_snapshot_event();
    }

    pub fn mark_user_input_active(&self, active: bool) {
        if let Some(agent) = &self.agent {
            agent.mark_user_input_active(active);
        }
    }

    pub fn force_new_conversation_next_start(&mut self) {
        self.force_new_session_once = true;
        self.stop_agent();
        self.current_endpoint = None;
        self.pending_initial_prompt = None;
        self.last_prompt_at = None;
        self.last_auto_prompt_signature = None;
        self.waiting_for_assistant_progress = false;
        self.trigger_now_clear_failed = false;
        self.state = RuntimeState::Stopped;
        self.probing_endpoint = None;
        self.counted_probe_inflight.clear();
        self.publish_snapshot_event();
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn state_label(&self) -> String {
        self.runtime_state_label()
    }

    pub fn set_event_sender(&mut self, event_tx: Option<Sender<RuntimeEvent>>) {
        self.event_tx = event_tx;
        if let Ok(mut last) = self.last_event_snapshot.lock() {
            *last = None;
        }
        if let Ok(mut last) = self.last_event_signature.lock() {
            *last = None;
        }
        self.publish_snapshot_event();
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        let terminal_snapshot = self
            .agent
            .as_ref()
            .and_then(AgentProcess::terminal_snapshot);
        let terminal_output_revision = self.terminal_output_revision();
        let terminal_view_revision = self.terminal_view_revision();
        RuntimeSnapshot {
            state_label: self.runtime_state_label(),
            rows: self.rows(),
            terminal_output: terminal_snapshot
                .as_ref()
                .map(|snapshot| snapshot.output.clone())
                .unwrap_or_default(),
            terminal_output_revision,
            terminal_view_revision,
            terminal_view: terminal_snapshot.map(|snapshot| snapshot.view),
            terminal_process_id: self.terminal_process_id(),
            terminal_control: self.terminal_control(),
        }
    }

    fn event_snapshot(&self, terminal_process_id: Option<u32>) -> RuntimeSnapshot {
        RuntimeSnapshot {
            state_label: self.runtime_state_label(),
            rows: self.rows(),
            terminal_output: String::new(),
            terminal_output_revision: self.terminal_output_revision(),
            terminal_view_revision: self.terminal_view_revision(),
            terminal_view: None,
            terminal_process_id,
            terminal_control: self.terminal_control(),
        }
    }

    fn event_signature(&self, terminal_process_id: Option<u32>) -> RuntimeEventSignature {
        let mut request_counts = self
            .request_count_by_endpoint
            .iter()
            .map(|(name, count)| (name.clone(), *count))
            .collect::<Vec<_>>();
        request_counts.sort_by(|left, right| left.0.cmp(&right.0));
        let mut last_status_codes = self
            .last_status_code_by_endpoint
            .iter()
            .map(|(name, code)| (name.clone(), *code))
            .collect::<Vec<_>>();
        last_status_codes.sort_by(|left, right| left.0.cmp(&right.0));
        let mut probe_keys = self
            .last_availability
            .iter()
            .map(|(name, result)| {
                (
                    name.clone(),
                    result.available,
                    result.polluted,
                    result.quota_limited,
                    result.status_code,
                )
            })
            .collect::<Vec<_>>();
        probe_keys.sort_by(|left, right| left.0.cmp(&right.0));

        RuntimeEventSignature {
            state_label: self.runtime_state_label(),
            current_endpoint: self.current_endpoint.clone(),
            terminal_output_revision: self.terminal_output_revision(),
            terminal_view_revision: self.terminal_view_revision(),
            terminal_process_id,
            force_probe_endpoint: self.force_probe_endpoint.clone(),
            fixed_endpoint: self.fixed_endpoint.clone(),
            request_counts,
            last_status_codes,
            probe_keys,
            runtime_tick: runtime_event_time_bucket(),
        }
    }

    pub fn publish_snapshot(&self) {
        self.publish_snapshot_event();
    }

    pub fn mark_probe_started(&mut self, endpoint: &EndpointConfig) {
        self.probing_endpoint = Some(endpoint.name.clone());
        if self.counted_probe_inflight.insert(endpoint.name.clone()) {
            *self
                .request_count_by_endpoint
                .entry(endpoint.name.clone())
                .or_default() += 1;
            self.last_request_at_by_endpoint
                .insert(endpoint.name.clone(), now_text());
            self.last_status_code_by_endpoint
                .insert(endpoint.name.clone(), None);
        }
        if self.current_endpoint.is_none() {
            self.state = RuntimeState::Probing;
        }
        self.publish_snapshot_event();
    }

    pub fn apply_probe_results(
        &mut self,
        results: HashMap<String, ProbeResult>,
    ) -> Option<EndpointConfig> {
        for (name, result) in &results {
            self.last_availability.insert(name.clone(), result.clone());
            if result.request_made {
                *self
                    .request_count_by_endpoint
                    .entry(name.clone())
                    .or_default() += 1;
                self.last_request_at_by_endpoint
                    .insert(name.clone(), now_text());
                self.last_status_code_by_endpoint
                    .insert(name.clone(), result.status_code);
            }
            if !result.usage.is_empty() {
                let entry = self
                    .token_usage_by_endpoint
                    .entry(name.clone())
                    .or_default();
                entry.input_tokens += result.usage.input_tokens;
                entry.cached_input_tokens += result.usage.cached_input_tokens;
                entry.output_tokens += result.usage.output_tokens;
                entry.total_tokens += result.usage.total_tokens;
            }
        }

        let effective = self.health.update(&self.config.endpoints, &results);
        let selected = self.select_from_effective(&effective).cloned();
        if let Some(endpoint) = &selected {
            let changed = self.current_endpoint.as_deref() != Some(endpoint.name.as_str());
            self.current_endpoint = Some(endpoint.name.clone());
            self.state = RuntimeState::Running;
            if changed {
                self.started_at_by_endpoint
                    .insert(endpoint.name.clone(), Instant::now());
            }
        } else {
            self.current_endpoint = None;
            self.state = RuntimeState::WaitingAvailable;
        }
        self.publish_snapshot_event();
        selected
    }

    pub fn set_fixed_endpoint(&mut self, name: Option<String>) {
        self.fixed_endpoint = name.filter(|value| !value.trim().is_empty());
        if let Some(config_path) = &self.config.config_path {
            let _ = update_control_state(
                config_path,
                &[(
                    "fixed_endpoint",
                    serde_json::json!(self.fixed_endpoint.clone().unwrap_or_default()),
                )],
            );
        }
    }

    pub fn set_force_probe_endpoint(&mut self, name: Option<String>) {
        self.force_probe_endpoint = name.filter(|value| !value.trim().is_empty());
        if let Some(config_path) = &self.config.config_path {
            if let Err(err) = update_control_state(
                config_path,
                &[(
                    "force_probe_endpoint",
                    serde_json::json!(self.force_probe_endpoint.clone().unwrap_or_default()),
                )],
            ) {
                self.state = RuntimeState::Error(format!("保存强制探测接口失败：{err}"));
            }
        }
        self.publish_snapshot_event();
    }

    pub fn set_endpoint_enabled(&mut self, name: &str, enabled: bool) -> bool {
        let Some(index) = self
            .config
            .endpoints
            .iter()
            .position(|endpoint| endpoint.name == name)
        else {
            return false;
        };

        if self.config.endpoints[index].enabled == enabled {
            return true;
        }

        self.config.endpoints[index].enabled = enabled;
        self.next_probe_at.remove(name);
        self.startup_failed_until.remove(name);
        self.startup_failure_error.remove(name);
        self.endpoint_auto_prompt_blocked_until.remove(name);
        self.clear_endpoint_request_failures(name);
        self.transient_failures_by_endpoint.remove(name);
        self.stall_failures_by_endpoint.remove(name);

        if enabled {
            self.publish_snapshot_event();
            return true;
        }

        self.polluted_until.remove(name);
        if self.fixed_endpoint.as_deref() == Some(name) {
            self.fixed_endpoint = None;
        }
        if self.force_probe_endpoint.as_deref() == Some(name) {
            self.force_probe_endpoint = None;
        }
        if self.probing_endpoint.as_deref() == Some(name) {
            self.probing_endpoint = None;
        }
        self.counted_probe_inflight.remove(name);

        if self.current_endpoint.as_deref() == Some(name) {
            self.stop_agent();
            self.current_endpoint = None;
            self.state = RuntimeState::WaitingAvailable;
        }

        if let Some(config_path) = &self.config.config_path {
            let _ = update_control_state(
                config_path,
                &[
                    (
                        "fixed_endpoint",
                        serde_json::json!(self.fixed_endpoint.clone().unwrap_or_default()),
                    ),
                    (
                        "force_probe_endpoint",
                        serde_json::json!(self.force_probe_endpoint.clone().unwrap_or_default()),
                    ),
                ],
            );
        }
        self.publish_snapshot_event();
        true
    }

    pub fn set_endpoint_guard_proxy_enabled(&mut self, name: &str, enabled: bool) -> bool {
        let Some(endpoint) = self
            .config
            .endpoints
            .iter_mut()
            .find(|endpoint| endpoint.name == name)
        else {
            return false;
        };

        if endpoint.guard_proxy.enabled == enabled {
            return true;
        }

        endpoint.guard_proxy.enabled = enabled;
        let should_restart_current = self.current_endpoint.as_deref() == Some(name);
        if should_restart_current {
            self.restart_agent();
        }
        self.publish_snapshot_event();
        true
    }

    pub fn rows(&self) -> Vec<EndpointRow> {
        let now = Instant::now();
        self.config
            .endpoints
            .iter()
            .map(|endpoint| {
                let selected = self.current_endpoint.as_deref() == Some(endpoint.name.as_str());
                EndpointRow {
                    enabled: endpoint.enabled,
                    force_probe: self.force_probe_endpoint.as_deref()
                        == Some(endpoint.name.as_str()),
                    fixed: self.fixed_endpoint.as_deref() == Some(endpoint.name.as_str()),
                    guard_proxy_enabled: endpoint.guard_proxy.enabled,
                    name: endpoint.name.clone(),
                    url: endpoint.base_url.clone(),
                    weight: endpoint.weight,
                    request_status: self.request_status_label(endpoint, selected),
                    selected,
                    runtime_state: if selected {
                        self.runtime_state_label()
                    } else {
                        String::new()
                    },
                    agent_runtime: if selected {
                        self.current_agent_activity_text()
                    } else {
                        self.last_activity_at_by_endpoint
                            .get(&endpoint.name)
                            .cloned()
                            .unwrap_or_default()
                    },
                    endpoint_runtime: self.endpoint_runtime_text(endpoint, selected),
                    token_cost: format_token_cost(
                        endpoint.model.as_str(),
                        self.token_usage_by_endpoint
                            .get(&endpoint.name)
                            .copied()
                            .unwrap_or_default(),
                    ),
                    historical_token_cost: format_token_cost(
                        endpoint.model.as_str(),
                        self.historical_usage_by_key
                            .get(&usage_key(endpoint))
                            .copied()
                            .unwrap_or_default(),
                    ),
                    request_count: self
                        .request_count_by_endpoint
                        .get(&endpoint.name)
                        .copied()
                        .unwrap_or_default(),
                    last_request_at: self
                        .last_request_at_by_endpoint
                        .get(&endpoint.name)
                        .cloned()
                        .unwrap_or_default(),
                    last_status_code: self
                        .last_status_code_by_endpoint
                        .get(&endpoint.name)
                        .and_then(|value| *value)
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    next_probe_in_seconds: self.next_probe_in_seconds(endpoint, now),
                }
            })
            .collect()
    }

    fn next_probe_in_seconds(&self, endpoint: &EndpointConfig, now: Instant) -> Option<u64> {
        self.next_probe_at.get(&endpoint.name).map(|next| {
            next.checked_duration_since(now)
                .map(|duration| duration.as_secs_f64().ceil() as u64)
                .unwrap_or(0)
        })
    }

    async fn select_endpoint(
        &mut self,
        probe: &HttpProbe,
        current_failed: bool,
        skip_current: bool,
    ) -> (Option<EndpointConfig>, HashMap<String, ProbeResult>) {
        self.select_endpoint_with_options(probe, current_failed, skip_current, false)
            .await
    }

    async fn select_endpoint_with_options(
        &mut self,
        probe: &HttpProbe,
        current_failed: bool,
        skip_current: bool,
        force_full_probe: bool,
    ) -> (Option<EndpointConfig>, HashMap<String, ProbeResult>) {
        if force_full_probe {
            return self
                .find_first_available(
                    probe,
                    self.enabled_by_weight(),
                    false,
                    ProbeMode::Full,
                    true,
                )
                .await;
        }

        if let Some(fixed_name) = &self.fixed_endpoint {
            if let Some(endpoint) = self.endpoint_by_name(fixed_name).cloned() {
                if self.current_endpoint.as_deref() == Some(endpoint.name.as_str())
                    && !current_failed
                {
                    let cached = self
                        .last_availability
                        .get(&endpoint.name)
                        .cloned()
                        .filter(|result| result.available)
                        .map(cached_probe_result)
                        .unwrap_or_else(ProbeResult::cached_available);
                    return (
                        Some(endpoint),
                        HashMap::from([(fixed_name.clone(), cached)]),
                    );
                }
                return self
                    .find_first_available(probe, vec![endpoint], false, ProbeMode::Full, false)
                    .await;
            }
        }

        if let Some(force_name) = &self.force_probe_endpoint {
            if let (Some(current), Some(force)) = (
                self.current_endpoint.clone(),
                self.endpoint_by_name(force_name).cloned(),
            ) {
                if force.name != current && !current_failed {
                    let (selected, mut availability) = self
                        .find_first_available(
                            probe,
                            vec![force],
                            false,
                            ProbeMode::ModelsOnly,
                            true,
                        )
                        .await;
                    if selected.is_some() {
                        return (selected, availability);
                    }
                    if let Some(cached) = self
                        .last_availability
                        .get(&current)
                        .cloned()
                        .filter(|result| result.available)
                        .map(cached_probe_result)
                    {
                        availability.insert(current.clone(), cached);
                    } else {
                        availability.insert(current.clone(), ProbeResult::cached_available());
                    }
                    return (self.endpoint_by_name(&current).cloned(), availability);
                }
            }
        }

        if self.current_endpoint.is_none() || current_failed {
            let mut endpoints = self.enabled_by_weight();
            if current_failed && skip_current {
                if let Some(current) = &self.current_endpoint {
                    endpoints.retain(|endpoint| endpoint.name != *current);
                }
            }
            return self
                .find_first_available(probe, endpoints, false, ProbeMode::Full, false)
                .await;
        }

        let Some(current) = self.current_endpoint.clone() else {
            return (None, HashMap::new());
        };
        let current_endpoint = self.endpoint_by_name(&current).cloned();
        let mut availability = HashMap::new();
        let current_probe_result = self
            .last_availability
            .get(&current)
            .cloned()
            .filter(|result| result.available)
            .map(cached_probe_result)
            .unwrap_or_else(ProbeResult::cached_available);
        availability.insert(current.clone(), current_probe_result);
        let Some(current_endpoint_ref) = current_endpoint.as_ref() else {
            return (None, availability);
        };
        let higher: Vec<_> = self
            .enabled_by_weight()
            .into_iter()
            .filter(|endpoint| endpoint.weight > current_endpoint_ref.weight)
            .collect();
        let (upgraded, higher_availability) = self
            .find_first_available(probe, higher, true, ProbeMode::Upgrade, false)
            .await;
        availability.extend(higher_availability);
        if upgraded.is_some() {
            return (upgraded, availability);
        }
        (current_endpoint, availability)
    }

    async fn find_first_available(
        &mut self,
        probe: &HttpProbe,
        endpoints: Vec<EndpointConfig>,
        _respect_probe_interval: bool,
        probe_mode: ProbeMode,
        ignore_cooldown: bool,
    ) -> (Option<EndpointConfig>, HashMap<String, ProbeResult>) {
        let mut availability = HashMap::new();
        let now = Instant::now();
        for endpoint in endpoints {
            if let Some(blocked) = self.hard_cooldown_result(&endpoint, now) {
                availability.insert(endpoint.name.clone(), blocked);
                continue;
            }
            if !ignore_cooldown {
                if let Some(blocked) = self.cooldown_result(&endpoint, now) {
                    availability.insert(endpoint.name.clone(), blocked);
                    continue;
                }
            }
            if self
                .next_probe_at
                .get(&endpoint.name)
                .is_some_and(|next| now < *next)
            {
                if let Some(cached) = self
                    .last_availability
                    .get(&endpoint.name)
                    .cloned()
                    .map(cached_probe_result)
                {
                    let available = cached.available;
                    availability.insert(endpoint.name.clone(), cached);
                    if available {
                        return (Some(endpoint), availability);
                    }
                    if !ignore_cooldown {
                        continue;
                    }
                }
            }
            self.mark_probe_started(&endpoint);
            let result = self
                .probe_endpoint_with_mode(probe, &endpoint, probe_mode)
                .await;
            self.remember_single_probe_result(&endpoint, &result, now);
            self.counted_probe_inflight.remove(&endpoint.name);
            if self.probing_endpoint.as_deref() == Some(endpoint.name.as_str()) {
                self.probing_endpoint = None;
            }
            self.publish_snapshot_event();
            let available = result.available;
            availability.insert(endpoint.name.clone(), cached_probe_result(result));
            if available {
                return (Some(endpoint), availability);
            }
        }
        (None, availability)
    }

    async fn probe_endpoint_with_mode(
        &self,
        probe: &HttpProbe,
        endpoint: &EndpointConfig,
        probe_mode: ProbeMode,
    ) -> ProbeResult {
        match probe_mode {
            ProbeMode::Full => probe.probe_endpoint(endpoint, &self.config).await,
            ProbeMode::ModelsOnly => {
                let result = probe.probe_models_endpoint(endpoint).await;
                if result.available || result.status_code != Some(200) {
                    result
                } else {
                    probe.probe_endpoint(endpoint, &self.config).await
                }
            }
            ProbeMode::Upgrade => {
                if crate::aggregate_egress::lookup_runtime(&endpoint.base_url).is_some() {
                    probe.probe_endpoint(endpoint, &self.config).await
                } else {
                    let result = probe.probe_models_endpoint(endpoint).await;
                    if result.available || result.status_code != Some(200) {
                        result
                    } else {
                        probe.probe_endpoint(endpoint, &self.config).await
                    }
                }
            }
        }
    }

    fn switch_to(&mut self, endpoint: EndpointConfig) -> Result<(), String> {
        self.stop_agent();
        let force_new_session = std::mem::take(&mut self.force_new_session_once);
        let mut launch_endpoint = endpoint.clone();
        if endpoint.guard_proxy.enabled {
            let guard = start_guard_proxy_with_stable_port(&self.config, &endpoint)?;
            launch_endpoint.base_url = guard.local_base_url().map_err(|err| err.to_string())?;
            self.guard_proxy = Some(guard);
        }
        let mut agent = AgentProcess::new(
            self.config.clone(),
            launch_endpoint.clone(),
            force_new_session,
        );
        if let Err(err) = agent.start() {
            if let Some(mut guard) = self.guard_proxy.take() {
                self.guard_audit_by_endpoint
                    .insert(guard.endpoint_name().to_string(), guard.audit_snapshot());
                guard.stop();
            }
            return Err(err.to_string());
        }
        let now = Instant::now();
        self.current_endpoint = Some(endpoint.name.clone());
        self.started_at_by_endpoint
            .insert(endpoint.name.clone(), now);
        self.pending_initial_prompt = agent
            .launch
            .as_ref()
            .filter(|launch| !launch.resumed)
            .map(|_| endpoint.initial_prompt.clone());
        self.last_prompt_at = None;
        self.last_auto_prompt_signature = None;
        self.waiting_for_assistant_progress = false;
        self.trigger_now_clear_failed = false;
        self.state = RuntimeState::Running;
        self.agent = Some(agent);
        self.publish_snapshot_event();
        Ok(())
    }

    fn maybe_drive_prompt(&mut self, endpoint: &EndpointConfig) {
        let mut session_assistant_confirmed = false;
        let can_send_prompt = {
            let Some(agent) = self.agent.as_mut() else {
                return;
            };
            if agent.needs_submit_retry(self.config.prompt_submit_retry_seconds) {
                let _ = agent.retry_submit();
                self.state = RuntimeState::Running;
                return;
            }
            if !agent.is_idle(
                self.config.idle_seconds,
                self.config.inflight_idle_fallback_seconds,
            ) {
                self.state = RuntimeState::Running;
                return;
            }
            self.state = RuntimeState::Idle;
            let _ = agent.capture_session_id(&endpoint.workdir);
            if agent.has_session_assistant_message_since_prompt() {
                session_assistant_confirmed = true;
                self.waiting_for_assistant_progress = false;
            } else if agent.has_assistant_message_since_prompt() {
                self.waiting_for_assistant_progress = false;
            }
            if agent.auto_wait_safely_released() {
                self.waiting_for_assistant_progress = false;
            }
            agent.can_send_prompt()
        };
        if session_assistant_confirmed {
            self.clear_endpoint_request_failures(&endpoint.name);
            self.endpoint_auto_prompt_blocked_until
                .remove(&endpoint.name);
        }
        if !can_send_prompt {
            self.publish_snapshot_event();
            return;
        }
        let control_state = self
            .config
            .config_path
            .as_ref()
            .map(|path| read_control_state(path))
            .unwrap_or_else(|| serde_json::json!({}));
        let trigger_now = control_state
            .get("trigger_now")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if !trigger_now {
            self.trigger_now_clear_failed = false;
        }
        let trigger_now_requested = trigger_now && !self.trigger_now_clear_failed;
        let auto_paused = control_state
            .get("auto_paused")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let manual_prompt = self
            .config
            .config_path
            .as_ref()
            .and_then(|path| pop_manual_prompt(path));
        let can_send_by_interval = self.last_prompt_at.is_none_or(|at| {
            at.elapsed() >= Duration::from_secs_f64(self.config.min_prompt_interval_seconds)
        });
        let automatic_requested = trigger_now_requested
            || (!auto_paused && (self.pending_initial_prompt.is_some() || can_send_by_interval));
        if manual_prompt.is_none()
            && automatic_requested
            && self.auto_prompt_blocked_by_endpoint_cooldown(&endpoint.name)
        {
            self.state = RuntimeState::Error("冷却等待".to_string());
            return;
        }
        if manual_prompt.is_none() && (!automatic_requested || self.waiting_for_assistant_progress)
        {
            if automatic_requested && self.waiting_for_assistant_progress {
                self.state = RuntimeState::Error("等待回复".to_string());
            }
            return;
        }
        let is_manual = manual_prompt.is_some();
        let mut restore_initial_prompt = false;
        let prompt = if let Some(prompt) = manual_prompt {
            prompt
        } else if let Some(prompt) = self.pending_initial_prompt.take() {
            restore_initial_prompt = true;
            prompt
        } else {
            self.latest_auto_prompt(endpoint)
        };
        if prompt.trim().is_empty() {
            self.publish_snapshot_event();
            return;
        }
        let Some(agent) = self.agent.as_mut() else {
            if is_manual {
                if let Some(config_path) = &self.config.config_path {
                    let _ = enqueue_manual_prompt(config_path, &prompt);
                }
            } else if restore_initial_prompt {
                self.pending_initial_prompt = Some(prompt);
            }
            return;
        };
        if agent.send_prompt(&prompt).is_ok() {
            self.last_prompt_at = Some(Instant::now());
            self.last_auto_prompt_signature = Some((endpoint.name.clone(), prompt));
            self.waiting_for_assistant_progress = !is_manual;
            let mut cleanup_error = None;
            if trigger_now {
                if let Some(config_path) = &self.config.config_path {
                    if let Err(err) = update_control_state(
                        config_path,
                        &[("trigger_now", serde_json::json!(false))],
                    ) {
                        self.trigger_now_clear_failed = true;
                        cleanup_error = Some(format!("清理立即续航标记失败：{err}"));
                    } else {
                        self.trigger_now_clear_failed = false;
                    }
                } else {
                    self.trigger_now_clear_failed = false;
                }
            }
            self.state = cleanup_error
                .map(RuntimeState::Error)
                .unwrap_or(RuntimeState::Running);
        } else if is_manual {
            if let Some(config_path) = &self.config.config_path {
                let _ = enqueue_manual_prompt(config_path, &prompt);
            }
        } else if restore_initial_prompt {
            self.pending_initial_prompt = Some(prompt);
        }
        self.publish_snapshot_event();
    }

    fn record_agent_usage(&mut self, endpoint: &EndpointConfig) {
        let Some(agent) = self.agent.as_mut() else {
            return;
        };
        agent.poll_monitor();
        let usage = agent.token_usage_total;
        if usage.is_empty() {
            return;
        }
        let session_key = agent
            .launch
            .as_ref()
            .and_then(|launch| launch.session_id.clone())
            .unwrap_or_else(|| endpoint.name.clone());
        let previous = self
            .last_agent_token_usage_by_session
            .get(&session_key)
            .copied()
            .unwrap_or_default();
        if previous.is_empty() && agent.launch.as_ref().is_some_and(|launch| launch.resumed) {
            self.last_agent_token_usage_by_session
                .insert(session_key, usage);
            return;
        }
        let delta = usage.delta_from(previous);
        self.last_agent_token_usage_by_session
            .insert(session_key, usage);
        if delta.is_empty() {
            return;
        }
        let entry = self
            .token_usage_by_endpoint
            .entry(endpoint.name.clone())
            .or_default();
        *entry = *entry + delta;
        let history_key = usage_key(endpoint);
        let historical = self.historical_usage_by_key.entry(history_key).or_default();
        *historical = *historical + delta;
        if self.save_usage_state() {
            self.publish_snapshot_event();
        }
    }

    fn save_usage_state(&mut self) -> bool {
        let previous_error = self.usage_save_error.clone();
        let Some(path) = &self.usage_state_path else {
            self.usage_save_error = None;
            return previous_error != self.usage_save_error;
        };
        let mut endpoints = serde_json::Map::new();
        for (key, usage) in &self.historical_usage_by_key {
            endpoints.insert(
                key.clone(),
                json!({
                    "input_tokens": usage.input_tokens,
                    "cached_input_tokens": usage.cached_input_tokens,
                    "output_tokens": usage.output_tokens,
                    "reasoning_output_tokens": usage.reasoning_output_tokens,
                    "total_tokens": usage.total_tokens,
                }),
            );
        }
        let payload = json!({"endpoints": endpoints});
        let text = match serde_json::to_string_pretty(&payload) {
            Ok(text) => text + "\n",
            Err(err) => {
                self.usage_save_error = Some(format!("序列化用量统计失败：{err}"));
                return previous_error != self.usage_save_error;
            }
        };
        match write_text_atomic(path, &text) {
            Ok(()) => self.usage_save_error = None,
            Err(err) => self.usage_save_error = Some(format!("保存用量统计失败：{err}")),
        }
        previous_error != self.usage_save_error
    }

    fn stop_agent(&mut self) {
        if let Some(current) = self.current_endpoint.clone() {
            if let Some(activity) = self.current_agent_activity_text_opt() {
                self.last_activity_at_by_endpoint
                    .insert(current.clone(), activity);
            }
            if let Some(started) = self.started_at_by_endpoint.get(&current).copied() {
                let elapsed = started.elapsed().as_secs_f64();
                *self
                    .runtime_seconds_by_endpoint
                    .entry(current.clone())
                    .or_default() += elapsed;
            }
            self.started_at_by_endpoint.remove(&current);
        }
        if let Some(mut agent) = self.agent.take() {
            agent.stop();
        }
        if let Some(mut guard) = self.guard_proxy.take() {
            self.guard_audit_by_endpoint
                .insert(guard.endpoint_name().to_string(), guard.audit_snapshot());
            guard.stop();
        }
    }

    fn current_guard_proxy_unreachable(&self) -> bool {
        self.guard_proxy
            .as_ref()
            .is_some_and(|guard| !guard.is_listening())
    }

    fn startup_failure_retry_seconds(&self) -> f64 {
        self.config.probe_interval_seconds.clamp(2.0, 8.0)
    }

    fn mark_startup_failure(&mut self, endpoint_name: &str, error: String) {
        self.startup_failed_until.insert(
            endpoint_name.to_string(),
            Instant::now() + Duration::from_secs_f64(self.startup_failure_retry_seconds()),
        );
        self.startup_failure_error
            .insert(endpoint_name.to_string(), error);
    }

    fn synthetic_startup_failure_result(&self, endpoint_name: &str) -> ProbeResult {
        ProbeResult {
            available: false,
            request_made: false,
            error: self
                .startup_failure_error
                .get(endpoint_name)
                .cloned()
                .unwrap_or_else(|| "启动失败".to_string()),
            ..Default::default()
        }
    }

    fn endpoint_by_name(&self, name: &str) -> Option<&EndpointConfig> {
        self.config
            .endpoints
            .iter()
            .find(|endpoint| endpoint.enabled && endpoint.name == name)
    }

    fn enabled_by_weight(&self) -> Vec<EndpointConfig> {
        let mut endpoints: Vec<_> = self
            .config
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.enabled)
            .cloned()
            .collect();
        endpoints.sort_by_key(|endpoint| std::cmp::Reverse(endpoint.weight));
        endpoints
    }

    fn remember_probe_results(&mut self, results: HashMap<String, ProbeResult>) {
        let now = Instant::now();
        for (name, result) in results {
            if let Some(endpoint) = self.endpoint_by_name(&name).cloned() {
                self.remember_single_probe_result(&endpoint, &result, now);
            }
        }
    }

    fn remember_fresh_probe_results(&mut self, results: HashMap<String, ProbeResult>) {
        let now = Instant::now();
        for (name, result) in results {
            if !result.request_made {
                continue;
            }
            if let Some(endpoint) = self.endpoint_by_name(&name).cloned() {
                self.remember_single_probe_result(&endpoint, &result, now);
            }
        }
    }

    fn remember_single_probe_result(
        &mut self,
        endpoint: &EndpointConfig,
        result: &ProbeResult,
        now: Instant,
    ) {
        self.last_availability
            .insert(endpoint.name.clone(), result.clone());
        let already_counted = self.counted_probe_inflight.contains(&endpoint.name);
        if result.request_made {
            if !already_counted {
                *self
                    .request_count_by_endpoint
                    .entry(endpoint.name.clone())
                    .or_default() += 1;
                self.last_request_at_by_endpoint
                    .insert(endpoint.name.clone(), now_text());
            }
            self.last_status_code_by_endpoint
                .insert(endpoint.name.clone(), result.status_code);
        } else if result.status_code.is_some() || !result.available {
            self.last_status_code_by_endpoint
                .insert(endpoint.name.clone(), result.status_code);
        }
        if result.request_made && result.available {
            self.clear_endpoint_request_failures(&endpoint.name);
            self.endpoint_auto_prompt_blocked_until
                .remove(&endpoint.name);
        }
        if let Some(seconds) = result.retry_after_seconds {
            self.endpoint_auto_prompt_blocked_until
                .insert(endpoint.name.clone(), now + Duration::from_secs(seconds));
        }
        if !result.usage.is_empty() {
            let entry = self
                .token_usage_by_endpoint
                .entry(endpoint.name.clone())
                .or_default();
            *entry = *entry + result.usage;
        }
        let next = if let Some(seconds) = result.retry_after_seconds {
            now + Duration::from_secs(seconds)
        } else if result.polluted || result.quota_limited {
            now + Duration::from_secs_f64(self.config.polluted_endpoint_cooldown_seconds)
        } else if result.available {
            now + Duration::from_secs_f64(
                self.config
                    .healthy_probe_interval_seconds
                    .max(self.config.probe_interval_seconds),
            )
        } else {
            now + Duration::from_secs_f64(self.config.probe_interval_seconds)
        };
        self.next_probe_at.insert(endpoint.name.clone(), next);
    }

    fn cooldown_result(&mut self, endpoint: &EndpointConfig, now: Instant) -> Option<ProbeResult> {
        if let Some(until) = self.startup_failed_until.get(&endpoint.name).copied() {
            if now < until {
                return Some(self.synthetic_startup_failure_result(&endpoint.name));
            }
            self.startup_failed_until.remove(&endpoint.name);
            self.startup_failure_error.remove(&endpoint.name);
        }
        if let Some(until) = self.polluted_until.get(&endpoint.name).copied() {
            if now < until {
                return Some(ProbeResult::synthetic_polluted());
            }
            self.polluted_until.remove(&endpoint.name);
        }
        let cached = self.last_availability.get(&endpoint.name)?;
        if !(cached.polluted || cached.quota_limited || cached.retry_after_seconds.is_some()) {
            return None;
        }
        if self
            .next_probe_at
            .get(&endpoint.name)
            .is_some_and(|next| now < *next)
        {
            return Some(cached_probe_result(cached.clone()));
        }
        None
    }

    fn hard_cooldown_result(&self, endpoint: &EndpointConfig, now: Instant) -> Option<ProbeResult> {
        let cached = self.last_availability.get(&endpoint.name)?;
        cached.retry_after_seconds?;
        if self
            .next_probe_at
            .get(&endpoint.name)
            .is_some_and(|next| now < *next)
        {
            return Some(cached_probe_result(cached.clone()));
        }
        None
    }

    fn mark_endpoint_polluted(&mut self, endpoint_name: &str) {
        self.polluted_until.insert(
            endpoint_name.to_string(),
            Instant::now()
                + Duration::from_secs_f64(self.config.polluted_endpoint_cooldown_seconds),
        );
    }

    fn select_from_effective(&self, effective: &HashMap<String, bool>) -> Option<&EndpointConfig> {
        if let Some(fixed_name) = &self.fixed_endpoint {
            return self.config.endpoints.iter().find(|endpoint| {
                endpoint.enabled
                    && endpoint.name == *fixed_name
                    && effective.get(&endpoint.name).copied().unwrap_or(false)
            });
        }
        choose_best_endpoint(&self.config.endpoints, effective)
    }

    fn request_status_label(&self, endpoint: &EndpointConfig, selected: bool) -> String {
        if !endpoint.enabled {
            return "已禁用".to_string();
        }
        if self.probing_endpoint.as_deref() == Some(endpoint.name.as_str()) {
            return "探测中".to_string();
        }
        let label = self.health.status_label(&endpoint.name);
        let now = Instant::now();
        let guard_audit = if selected {
            self.guard_proxy
                .as_ref()
                .filter(|guard| guard.endpoint_name() == endpoint.name)
                .map(|guard| guard.audit_snapshot())
        } else {
            None
        }
        .or_else(|| self.guard_audit_by_endpoint.get(&endpoint.name).cloned());
        let guard_suffix = guard_audit
            .as_ref()
            .filter(|audit| audit.requests > 0)
            .map(|audit| {
                let upstream = audit
                    .last_upstream_status
                    .map(|status| {
                        format!(
                            " 上游{} 尝试{}",
                            status,
                            audit.last_upstream_attempts.max(1)
                        )
                    })
                    .unwrap_or_else(|| {
                        format!(" 上游- 尝试{}", audit.last_upstream_attempts.max(1))
                    });
                let error = audit
                    .last_upstream_error
                    .as_deref()
                    .filter(|error| !error.trim().is_empty())
                    .map(|error| format!(" 错误{}", error))
                    .unwrap_or_default();
                format!(
                    " | 保护 请求{} 污染{} 高危替换{} 连续高危{} 过滤{} 脱敏{}",
                    audit.requests,
                    audit.pollution_failures,
                    audit.high_risk_replacements,
                    audit.consecutive_high_risk,
                    audit.filtered_responses,
                    audit.redactions
                ) + &upstream
                    + &error
            })
            .unwrap_or_default();
        let startup_error = self
            .startup_failed_until
            .get(&endpoint.name)
            .copied()
            .filter(|until| now < *until)
            .and_then(|_| self.startup_failure_error.get(&endpoint.name))
            .cloned();
        if let Some(error) = startup_error {
            return format!("启动失败: {error}{guard_suffix}");
        }
        if let Some(status) = guard_audit
            .as_ref()
            .and_then(|audit| audit.last_upstream_status)
            .filter(|status| *status >= 400)
        {
            let error = guard_audit
                .as_ref()
                .and_then(|audit| audit.last_upstream_error.as_deref())
                .filter(|error| !error.trim().is_empty())
                .map(|error| format!(": {error}"))
                .unwrap_or_default();
            return format!("不可用: HTTP {status}{error}{guard_suffix}");
        }
        if let Some(failures) = self
            .endpoint_request_failures_by_endpoint
            .get(&endpoint.name)
            .copied()
            .filter(|failures| *failures > 0)
        {
            let status = self
                .last_status_code_by_endpoint
                .get(&endpoint.name)
                .and_then(|value| *value)
                .map(|status| format!(" HTTP {status}"))
                .unwrap_or_default();
            return format!(
                "请求失败 {}/{}{}{guard_suffix}",
                failures,
                self.config.endpoint_failure_threshold.max(1),
                status
            );
        }
        let last_result = self.last_availability.get(&endpoint.name);
        if label == "未知" {
            if let Some(result) = last_result.filter(|result| {
                result.request_made || result.status_code.is_some() || !result.error.is_empty()
            }) {
                return format!("{}{guard_suffix}", probe_result_status_label(result));
            }
        }
        if selected && label == "未知" {
            return format!("运行中未额外探测{guard_suffix}");
        }
        let error = last_result
            .map(|result| result.error.as_str())
            .unwrap_or("");
        if !error.is_empty() && label != "正常" && label != "运行中未额外探测" {
            return format!("{label}: {error}{guard_suffix}");
        }
        format!("{label}{guard_suffix}")
    }

    fn sync_control_state(&mut self) {
        let Some(config_path) = &self.config.config_path else {
            return;
        };
        let state = read_control_state(config_path);
        self.fixed_endpoint = state
            .get("fixed_endpoint")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        self.force_probe_endpoint = state
            .get("force_probe_endpoint")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
    }

    fn record_transient_failure(&mut self, endpoint_name: &str) -> u32 {
        let entry = self
            .transient_failures_by_endpoint
            .entry(endpoint_name.to_string())
            .or_default();
        *entry += 1;
        *entry
    }

    fn record_stall_failure(&mut self, endpoint_name: &str) -> u32 {
        let entry = self
            .stall_failures_by_endpoint
            .entry(endpoint_name.to_string())
            .or_default();
        *entry += 1;
        *entry
    }

    fn record_endpoint_request_failure_reached_threshold(&mut self, endpoint_name: &str) -> bool {
        let entry = self
            .endpoint_request_failures_by_endpoint
            .entry(endpoint_name.to_string())
            .or_default();
        *entry += 1;
        self.state = RuntimeState::Error(format!(
            "请求失败 {}/{}",
            *entry,
            self.config.endpoint_failure_threshold.max(1)
        ));
        *entry >= self.config.endpoint_failure_threshold.max(1)
    }

    fn auto_prompt_blocked_by_endpoint_cooldown(&mut self, endpoint_name: &str) -> bool {
        let Some(until) = self
            .endpoint_auto_prompt_blocked_until
            .get(endpoint_name)
            .copied()
        else {
            return false;
        };
        if Instant::now() < until {
            return true;
        }
        self.endpoint_auto_prompt_blocked_until
            .remove(endpoint_name);
        false
    }

    fn clear_endpoint_request_failures(&mut self, endpoint_name: &str) {
        self.endpoint_request_failures_by_endpoint
            .remove(endpoint_name);
    }

    fn latest_auto_prompt(&self, endpoint: &EndpointConfig) -> String {
        let Some(config_path) = &self.config.config_path else {
            return endpoint.auto_prompt.clone();
        };
        let Ok(text) = std::fs::read_to_string(config_path) else {
            return endpoint.auto_prompt.clone();
        };
        let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) else {
            return endpoint.auto_prompt.clone();
        };
        if let Some(prompt) = data
            .get("auto_prompt")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return prompt.to_string();
        }
        let Some(items) = data.get("endpoints").and_then(serde_json::Value::as_array) else {
            return endpoint.auto_prompt.clone();
        };
        for item in items {
            if item.get("name").and_then(serde_json::Value::as_str) != Some(endpoint.name.as_str())
            {
                continue;
            }
            if let Some(prompt) = item
                .get("auto_prompt")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return prompt.to_string();
            }
        }
        endpoint.auto_prompt.clone()
    }

    fn current_agent_activity_text(&self) -> String {
        self.current_agent_activity_text_opt().unwrap_or_default()
    }

    fn current_agent_activity_text_opt(&self) -> Option<String> {
        self.agent
            .as_ref()
            .and_then(AgentProcess::last_activity_instant)
            .map(format_instant_as_local_time)
    }

    fn endpoint_runtime_text(&self, endpoint: &EndpointConfig, selected: bool) -> String {
        let mut seconds = self
            .runtime_seconds_by_endpoint
            .get(&endpoint.name)
            .copied()
            .unwrap_or_default();
        if selected {
            if let Some(started) = self.started_at_by_endpoint.get(&endpoint.name) {
                seconds += started.elapsed().as_secs_f64();
            }
        }
        if seconds <= 0.0 && !selected {
            return String::new();
        }
        format_elapsed(seconds)
    }

    fn runtime_state_label(&self) -> String {
        let base = match &self.state {
            RuntimeState::Stopped => "已停止".to_string(),
            RuntimeState::Probing => "正在探测".to_string(),
            RuntimeState::WaitingAvailable => "等待可用接口".to_string(),
            RuntimeState::Running => "运行中".to_string(),
            RuntimeState::Idle => "空闲".to_string(),
            RuntimeState::Error(error) => format!("异常：{error}"),
        };
        match self.usage_save_error.as_deref() {
            Some(error) if !error.trim().is_empty() => format!("{base} | {error}"),
            _ => base,
        }
    }

    fn publish_snapshot_event(&self) {
        if let Some(tx) = &self.event_tx {
            let terminal_process_id = self.terminal_process_id();
            let signature = self.event_signature(terminal_process_id);
            if let Ok(mut last) = self.last_event_signature.lock() {
                if last.as_ref() == Some(&signature) {
                    return;
                }
                *last = Some(signature);
            }
            let snapshot = self.event_snapshot(terminal_process_id);
            if let Ok(mut last) = self.last_event_snapshot.lock() {
                if last.as_ref() == Some(&snapshot) {
                    return;
                }
                *last = Some(snapshot.clone());
            }
            let _ = tx.send(RuntimeEvent::Snapshot(snapshot));
        }
    }
}

fn now_text() -> String {
    let now: DateTime<Local> = Local::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn runtime_event_time_bucket() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn format_instant_as_local_time(instant: Instant) -> String {
    let elapsed = instant.elapsed();
    let now: DateTime<Local> = Local::now();
    let activity = now - chrono::Duration::from_std(elapsed).unwrap_or_default();
    activity.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn format_elapsed(seconds: f64) -> String {
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

fn probe_result_status_label(result: &ProbeResult) -> String {
    let status = result
        .status_code
        .map(|code| format!("HTTP {code}"))
        .unwrap_or_else(|| "已请求".to_string());
    if let Some(seconds) = result.retry_after_seconds {
        return if result.error.is_empty() {
            format!("{status} 冷却等待{seconds}s")
        } else {
            format!("{status} 冷却等待{seconds}s: {}", result.error)
        };
    }
    if result.polluted {
        return if result.error.is_empty() {
            format!("{status} 污染")
        } else {
            format!("{status} 污染: {}", result.error)
        };
    }
    if result.quota_limited {
        return if result.error.is_empty() {
            format!("{status} 额度不足")
        } else {
            format!("{status} 额度不足: {}", result.error)
        };
    }
    if !result.error.is_empty() {
        return format!("{status}: {}", result.error);
    }
    if result.available {
        return format!("{status} 可用");
    }
    format!("{status} 不可用")
}

fn cached_probe_result(mut result: ProbeResult) -> ProbeResult {
    result.request_made = false;
    result.usage = TokenUsage::default();
    result
}

fn usage_key(endpoint: &EndpointConfig) -> String {
    format!(
        "{}|{}",
        endpoint.base_url.trim_end_matches('/'),
        endpoint.model
    )
}

fn guard_proxy_port_registry_path(config: &AppConfig) -> Option<PathBuf> {
    config
        .config_path
        .as_ref()
        .map(|path| path.with_file_name(".watchapi-guard-ports.json"))
}

fn reserve_guard_proxy_port(
    config: &AppConfig,
    endpoint: &EndpointConfig,
) -> Result<Option<u16>, String> {
    let Some(path) = guard_proxy_port_registry_path(config) else {
        return Ok(None);
    };
    reserve_guard_proxy_port_at(&path, &endpoint.name)
}

fn start_guard_proxy_with_stable_port(
    config: &AppConfig,
    endpoint: &EndpointConfig,
) -> Result<GuardProxyServer, String> {
    let preferred_port = reserve_guard_proxy_port(config, endpoint)?;
    let mut guard = GuardProxyServer::new_with_preferred_port(endpoint.clone(), preferred_port);
    match guard.start() {
        Ok(()) => Ok(guard),
        Err(first_err) => {
            clear_guard_proxy_port_assignment(config, &endpoint.name);
            let retry_port = reserve_guard_proxy_port(config, endpoint)?;
            let mut retry_guard =
                GuardProxyServer::new_with_preferred_port(endpoint.clone(), retry_port);
            retry_guard.start().map_err(|retry_err| {
                format!(
                    "保护层端口绑定失败，原端口 {preferred_port:?}: {first_err}; 重试端口 {retry_port:?}: {retry_err}"
                )
            })?;
            Ok(retry_guard)
        }
    }
}

fn reserve_guard_proxy_port_at(path: &Path, endpoint_name: &str) -> Result<Option<u16>, String> {
    let _guard = GUARD_PROXY_PORT_REGISTRY_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "保护层端口注册表锁已损坏".to_string())?;
    let mut registry = load_guard_proxy_port_registry(path);
    let key = endpoint_name.trim();
    if key.is_empty() {
        return Ok(None);
    }
    if let Some(port) = registry
        .get(key)
        .copied()
        .filter(|port| port_available(*port))
    {
        return Ok(Some(port));
    }
    let Some(port) = find_available_guard_proxy_port(&registry, key) else {
        return Ok(None);
    };
    registry.insert(key.to_string(), port);
    save_guard_proxy_port_registry(path, &registry)
        .map_err(|err| format!("保存保护层端口注册表失败：{}: {err}", path.display()))?;
    Ok(Some(port))
}

fn clear_guard_proxy_port_assignment(config: &AppConfig, endpoint_name: &str) -> bool {
    let Some(path) = guard_proxy_port_registry_path(config) else {
        return false;
    };
    let Ok(_guard) = GUARD_PROXY_PORT_REGISTRY_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
    else {
        return false;
    };
    let mut registry = load_guard_proxy_port_registry(&path);
    if registry.remove(endpoint_name.trim()).is_none() {
        return false;
    }
    save_guard_proxy_port_registry(&path, &registry).is_ok()
}

fn load_guard_proxy_port_registry(path: &Path) -> HashMap<String, u16> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<HashMap<String, u16>>(&text).ok())
        .unwrap_or_default()
}

fn save_guard_proxy_port_registry(
    path: &Path,
    registry: &HashMap<String, u16>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(registry).unwrap_or_else(|_| "{}".to_string()) + "\n";
    write_text_atomic(path, &text)
}

fn find_available_guard_proxy_port(registry: &HashMap<String, u16>, key: &str) -> Option<u16> {
    (GUARD_PROXY_PORT_MIN..=GUARD_PROXY_PORT_MAX).find(|port| {
        !registry
            .iter()
            .any(|(assigned_key, assigned_port)| assigned_key != key && assigned_port == port)
            && port_available(*port)
    })
}

fn port_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn load_usage_state(path: &PathBuf) -> HashMap<String, TokenUsage> {
    let Some(map) = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| value.get("endpoints").and_then(Value::as_object).cloned())
    else {
        return HashMap::new();
    };
    map.into_iter()
        .map(|(key, value)| {
            (
                key,
                TokenUsage {
                    input_tokens: value
                        .get("input_tokens")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                    cached_input_tokens: value
                        .get("cached_input_tokens")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                    output_tokens: value
                        .get("output_tokens")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                    reasoning_output_tokens: value
                        .get("reasoning_output_tokens")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                    total_tokens: value
                        .get("total_tokens")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn endpoint(name: &str, weight: i64) -> EndpointConfig {
        EndpointConfig {
            name: name.to_string(),
            base_url: format!("https://{name}.example.test/v1"),
            api_key: "key".to_string(),
            model: "gpt-5.5".to_string(),
            reasoning_effort: "high".to_string(),
            service_tier: None,
            initial_prompt: "init".to_string(),
            auto_prompt: "auto".to_string(),
            workdir: PathBuf::from("."),
            weight,
            enabled: true,
            probe_url: None,
            guard_proxy: Default::default(),
        }
    }

    fn config() -> AppConfig {
        AppConfig {
            agent_id: "default".to_string(),
            endpoints: vec![endpoint("high", 100), endpoint("low", 10)],
            config_path: None,
            workdir: PathBuf::from("."),
            probe_interval_seconds: 1.0,
            healthy_probe_interval_seconds: 300.0,
            polluted_endpoint_cooldown_seconds: 300.0,
            request_timeout_seconds: 15.0,
            idle_seconds: 3.0,
            inflight_idle_fallback_seconds: 60.0,
            turn_stall_seconds: 180.0,
            turn_stall_failure_threshold: 1,
            transient_network_failure_threshold: 3,
            min_prompt_interval_seconds: 1.0,
            prompt_submit_sequence: "control-m".to_string(),
            prompt_submit_retry_seconds: 5.0,
            endpoint_failure_threshold: 1,
            endpoint_recovery_threshold: 1,
            agent_driver: crate::config::AgentDriver::Codex,
            agent_command: crate::config::AgentCommand::Args(vec!["codex".to_string()]),
            agent_home: None,
            codex_config_path: PathBuf::from("config.toml"),
            codex_auth_path: PathBuf::from("auth.json"),
            codex_home: PathBuf::from(".codex"),
            session_state_path: PathBuf::from(".watchapi-state.json"),
            restore_sessions: true,
            codex_provider_name: "custom".to_string(),
            probe_expected_text: "WATCHAPI_OK".to_string(),
            probe_path: "/v1/responses".to_string(),
            polluted_response_keywords: vec![],
            polluted_response_threshold: 0.35,
            polluted_context_window: 12,
            polluted_check_max_chars: 300,
            completion_pause_keywords: vec![],
        }
    }

    #[test]
    fn selects_highest_available_endpoint_and_builds_rows() {
        let mut runtime = RuntimeCore::new(config());
        let selected = runtime.apply_probe_results(HashMap::from([
            ("high".to_string(), ProbeResult::available()),
            ("low".to_string(), ProbeResult::available()),
        ]));

        assert_eq!(selected.unwrap().name, "high");
        let rows = runtime.rows();
        assert!(rows[0].selected);
        assert_eq!(rows[0].request_status, "正常");
        assert_eq!(rows[0].request_count, 1);
    }

    #[test]
    fn rows_expose_guard_proxy_enabled_state() {
        let mut cfg = config();
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[1].guard_proxy.enabled = false;

        let rows = RuntimeCore::new(cfg).rows();

        assert!(rows[0].guard_proxy_enabled);
        assert!(!rows[1].guard_proxy_enabled);
    }

    #[test]
    fn set_endpoint_guard_proxy_enabled_updates_rows() {
        let mut runtime = RuntimeCore::new(config());

        assert!(runtime.set_endpoint_guard_proxy_enabled("high", true));
        let rows = runtime.rows();

        assert!(rows[0].guard_proxy_enabled);
        assert!(!rows[1].guard_proxy_enabled);
        assert!(!runtime.set_endpoint_guard_proxy_enabled("missing", false));
    }

    #[test]
    fn toggling_selected_guard_proxy_restarts_current_agent() {
        let mut runtime = RuntimeCore::new(config());
        runtime.current_endpoint = Some("high".to_string());
        runtime.state = RuntimeState::Running;

        assert!(runtime.set_endpoint_guard_proxy_enabled("high", true));

        assert_eq!(runtime.current_endpoint, None);
        assert_eq!(runtime.state, RuntimeState::WaitingAvailable);
        assert!(runtime.rows()[0].guard_proxy_enabled);
    }

    #[test]
    fn rows_expose_guard_proxy_upstream_diagnostics() {
        let mut runtime = RuntimeCore::new(config());
        runtime.guard_audit_by_endpoint.insert(
            "high".to_string(),
            GuardAuditSnapshot {
                requests: 2,
                upstream_failures: 1,
                last_upstream_status: Some(502),
                last_upstream_error: Some("upstream transient".to_string()),
                last_upstream_attempts: 4,
                ..Default::default()
            },
        );

        let rows = runtime.rows();
        let status = &rows[0].request_status;

        assert!(status.contains("保护 请求2"), "{status}");
        assert!(status.contains("上游502"), "{status}");
        assert!(status.contains("尝试4"), "{status}");
        assert!(status.contains("错误upstream transient"), "{status}");
    }

    #[test]
    fn guard_proxy_upstream_error_takes_precedence_over_stale_healthy_label() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = runtime.config.endpoints[0].clone();
        runtime.remember_probe_results(HashMap::from([(
            endpoint.name.clone(),
            ProbeResult::available(),
        )]));
        runtime.health.update(
            &runtime.config.endpoints,
            &HashMap::from([(endpoint.name.clone(), ProbeResult::available())]),
        );
        runtime.guard_audit_by_endpoint.insert(
            endpoint.name.clone(),
            GuardAuditSnapshot {
                requests: 13,
                last_upstream_status: Some(400),
                last_upstream_error: Some("休息一会，库存充足再开".to_string()),
                last_upstream_attempts: 1,
                ..Default::default()
            },
        );

        let status = runtime.rows()[0].request_status.clone();

        assert!(status.starts_with("不可用: HTTP 400"), "{status}");
        assert!(!status.starts_with("正常"), "{status}");
        assert!(status.contains("休息一会"), "{status}");
    }

    #[test]
    fn restart_agent_resets_current_agent_for_next_tick() {
        let mut runtime = RuntimeCore::new(config());
        runtime.current_endpoint = Some("high".to_string());
        runtime.pending_initial_prompt = Some("old prompt".to_string());
        runtime.last_prompt_at = Some(Instant::now());
        runtime.last_auto_prompt_signature = Some(("high".to_string(), "prompt".to_string()));
        runtime.waiting_for_assistant_progress = true;
        runtime.probing_endpoint = Some("low".to_string());
        runtime.counted_probe_inflight.insert("high".to_string());
        runtime.state = RuntimeState::Running;

        runtime.restart_agent();

        assert_eq!(runtime.current_endpoint, None);
        assert_eq!(runtime.state, RuntimeState::WaitingAvailable);
        assert_eq!(runtime.pending_initial_prompt, None);
        assert_eq!(runtime.last_prompt_at, None);
        assert_eq!(runtime.last_auto_prompt_signature, None);
        assert!(!runtime.waiting_for_assistant_progress);
        assert_eq!(runtime.probing_endpoint, None);
        assert!(runtime.counted_probe_inflight.is_empty());
    }

    #[test]
    fn fixed_endpoint_overrides_weight() {
        let mut runtime = RuntimeCore::new(config());
        runtime.set_fixed_endpoint(Some("low".to_string()));
        let selected = runtime.apply_probe_results(HashMap::from([
            ("high".to_string(), ProbeResult::available()),
            ("low".to_string(), ProbeResult::available()),
        ]));

        assert_eq!(selected.unwrap().name, "low");
        assert!(runtime.rows()[1].fixed);
    }

    #[test]
    fn disabling_selected_endpoint_removes_it_from_active_runtime() {
        let mut runtime = RuntimeCore::new(config());
        let selected = runtime.apply_probe_results(HashMap::from([(
            "high".to_string(),
            ProbeResult::available(),
        )]));
        assert_eq!(selected.unwrap().name, "high");

        assert!(runtime.set_endpoint_enabled("high", false));

        let rows = runtime.rows();
        assert!(!rows[0].enabled);
        assert!(!rows[0].selected);
        assert_eq!(rows[0].request_status, "已禁用");
        assert_eq!(runtime.state_label(), "等待可用接口");
    }

    #[test]
    fn switch_failure_stops_guard_proxy() {
        let mut cfg = config();
        cfg.agent_command = crate::config::AgentCommand::Args(vec![
            "definitely-missing-watchapi-command".to_string(),
        ]);
        let mut runtime = RuntimeCore::new(cfg);
        let mut guarded = endpoint("high", 100);
        guarded.guard_proxy.enabled = true;

        let result = runtime.switch_to(guarded);

        assert!(result.is_err());
        assert!(runtime.guard_proxy.is_none());
        assert!(runtime.guard_audit_by_endpoint.contains_key("high"));
    }

    #[test]
    fn guard_proxy_disconnect_marks_current_agent_failed() {
        let mut cfg = config();
        cfg.endpoints[0].guard_proxy.enabled = true;
        let mut runtime = RuntimeCore::new(cfg.clone());
        runtime.current_endpoint = Some(cfg.endpoints[0].name.clone());
        runtime.guard_proxy = Some(GuardProxyServer::new(cfg.endpoints[0].clone()));

        assert!(runtime.current_guard_proxy_unreachable());
    }

    #[test]
    fn guard_proxy_port_registry_reuses_stable_endpoint_port() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(".watchapi-guard-ports.json");

        let first = reserve_guard_proxy_port_at(&path, "main").unwrap().unwrap();
        let second = reserve_guard_proxy_port_at(&path, "main").unwrap().unwrap();

        assert_eq!(first, second);
        assert_eq!(
            load_guard_proxy_port_registry(&path).get("main").copied(),
            Some(first)
        );
    }

    #[test]
    fn guard_proxy_port_registry_skips_occupied_and_assigned_ports() {
        let occupied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(".watchapi-guard-ports.json");
        save_guard_proxy_port_registry(
            &path,
            &HashMap::from([
                ("main".to_string(), occupied_port),
                ("other".to_string(), GUARD_PROXY_PORT_MIN),
            ]),
        )
        .unwrap();

        let reserved = reserve_guard_proxy_port_at(&path, "main").unwrap().unwrap();

        assert_ne!(reserved, occupied_port);
        assert_ne!(reserved, GUARD_PROXY_PORT_MIN);
        assert!(port_available(reserved));
    }

    #[test]
    fn concurrent_guard_proxy_port_reservations_are_unique() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(".watchapi-guard-ports.json");
        let handles = (0..8)
            .map(|index| {
                let path = path.clone();
                std::thread::spawn(move || {
                    reserve_guard_proxy_port_at(&path, &format!("endpoint-{index}"))
                        .unwrap()
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();

        let ports = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        let unique = ports.iter().copied().collect::<HashSet<_>>();
        let registry = load_guard_proxy_port_registry(&path);

        assert_eq!(unique.len(), ports.len());
        assert_eq!(registry.len(), ports.len());
    }

    #[test]
    fn guard_proxy_port_registry_save_failure_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        let parent_file = temp.path().join("not-a-dir");
        fs::write(&parent_file, "block parent directory").unwrap();
        let path = parent_file.join(".watchapi-guard-ports.json");

        let err = reserve_guard_proxy_port_at(&path, "main").unwrap_err();

        assert!(err.contains("保存保护层端口注册表失败"));
        assert!(err.contains("not-a-dir"));
    }

    #[test]
    fn guard_proxy_server_binds_preferred_port() {
        let preferred = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut endpoint = endpoint("guarded", 100);
        endpoint.guard_proxy.enabled = true;
        let mut proxy = GuardProxyServer::new_with_preferred_port(endpoint, Some(preferred));

        proxy.start().unwrap();

        assert_eq!(
            proxy.local_base_url().unwrap(),
            format!("http://127.0.0.1:{preferred}/v1")
        );
    }

    #[test]
    fn stable_guard_proxy_start_replaces_occupied_registered_port() {
        let occupied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let temp = tempfile::tempdir().unwrap();
        let mut cfg = config();
        cfg.config_path = Some(temp.path().join("watchapi.json"));
        let registry_path = guard_proxy_port_registry_path(&cfg).unwrap();
        save_guard_proxy_port_registry(
            &registry_path,
            &HashMap::from([("guarded".to_string(), occupied_port)]),
        )
        .unwrap();
        let mut endpoint = endpoint("guarded", 100);
        endpoint.guard_proxy.enabled = true;

        let proxy = start_guard_proxy_with_stable_port(&cfg, &endpoint).unwrap();
        let registered = load_guard_proxy_port_registry(&registry_path)["guarded"];

        assert_ne!(registered, occupied_port);
        assert_eq!(
            proxy.local_base_url().unwrap(),
            format!("http://127.0.0.1:{registered}/v1")
        );
    }

    #[test]
    fn cached_probe_result_does_not_count_as_request_or_usage() {
        let mut runtime = RuntimeCore::new(config());
        let mut result = ProbeResult::available();
        result.usage = TokenUsage {
            input_tokens: 10,
            output_tokens: 5,
            total_tokens: 15,
            ..Default::default()
        };

        runtime.remember_probe_results(HashMap::from([("high".to_string(), result)]));
        runtime.remember_probe_results(HashMap::from([(
            "high".to_string(),
            cached_probe_result(runtime.last_availability["high"].clone()),
        )]));

        let row = runtime
            .rows()
            .into_iter()
            .find(|row| row.name == "high")
            .unwrap();
        assert_eq!(row.request_count, 1);
        assert!(row.token_cost.starts_with("15/"));
    }

    #[test]
    fn probe_status_label_shows_key_switch_cooldown_wait() {
        let result = ProbeResult {
            status_code: Some(400),
            retry_after_seconds: Some(51),
            error: "切换key需要冷却41秒".to_string(),
            ..Default::default()
        };

        assert_eq!(
            probe_result_status_label(&result),
            "HTTP 400 冷却等待51s: 切换key需要冷却41秒"
        );
    }

    #[test]
    fn key_switch_cooldown_uses_next_probe_without_blocking_tick() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = endpoint("high", 100);
        let now = Instant::now();
        let result = ProbeResult {
            status_code: Some(400),
            retry_after_seconds: Some(51),
            error: "切换key需要冷却41秒".to_string(),
            request_made: true,
            ..Default::default()
        };

        runtime.remember_single_probe_result(&endpoint, &result, now);
        let blocked = runtime.cooldown_result(&endpoint, now + Duration::from_secs(1));

        assert!(blocked.is_some());
        assert!(!blocked.unwrap().request_made);
        assert!(runtime.next_probe_at[&endpoint.name] >= now + Duration::from_secs(51));
    }

    #[test]
    fn rows_expose_next_probe_countdown_seconds() {
        let mut runtime = RuntimeCore::new(config());
        runtime
            .next_probe_at
            .insert("high".to_string(), Instant::now() + Duration::from_secs(42));

        let row = runtime
            .rows()
            .into_iter()
            .find(|row| row.name == "high")
            .unwrap();

        assert!(matches!(row.next_probe_in_seconds, Some(41..=42)));
    }

    #[test]
    fn key_switch_cooldown_blocks_force_full_probe_until_due() {
        let mut runtime = RuntimeCore::new(config());
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        let now = Instant::now();
        runtime.remember_single_probe_result(
            &high,
            &ProbeResult {
                status_code: Some(400),
                retry_after_seconds: Some(51),
                error: "切换key需要冷却41秒".to_string(),
                request_made: true,
                ..Default::default()
            },
            now,
        );
        runtime.remember_single_probe_result(&low, &ProbeResult::available(), now);

        let (selected, availability) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(runtime.find_first_available(
                &HttpProbe::new(0.1).unwrap(),
                vec![high.clone(), low.clone()],
                false,
                ProbeMode::Full,
                true,
            ));

        assert_eq!(selected.unwrap().name, low.name);
        assert!(!availability[&high.name].request_made);
        assert_eq!(runtime.request_count_by_endpoint[&high.name], 1);
    }

    #[test]
    fn unavailable_probe_cache_blocks_reprobe_until_interval_due() {
        let mut cfg = config();
        cfg.probe_interval_seconds = 120.0;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        cfg.endpoints[0].base_url = format!("http://{addr}/v1");
        cfg.endpoints.truncate(1);
        let mut runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();
        let now = Instant::now();
        runtime.remember_single_probe_result(&endpoint, &ProbeResult::unavailable(), now);

        let (selected, availability) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(runtime.find_first_available(
                &HttpProbe::new(0.1).unwrap(),
                vec![endpoint.clone()],
                false,
                ProbeMode::Full,
                false,
            ));

        assert!(selected.is_none());
        assert!(!availability[&endpoint.name].request_made);
        assert_eq!(runtime.request_count_by_endpoint[&endpoint.name], 1);
        assert!(runtime.next_probe_at[&endpoint.name] >= now + Duration::from_secs(119));
    }

    #[test]
    fn cached_selection_result_does_not_push_next_probe_forward() {
        let mut cfg = config();
        cfg.probe_interval_seconds = 40.0;
        cfg.endpoints.truncate(1);
        let mut runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();
        let now = Instant::now();
        runtime.remember_single_probe_result(&endpoint, &ProbeResult::unavailable(), now);
        let first_due = runtime.next_probe_at[&endpoint.name];
        let cached = runtime
            .last_availability
            .get(&endpoint.name)
            .cloned()
            .map(cached_probe_result)
            .unwrap();

        runtime.remember_fresh_probe_results(HashMap::from([(endpoint.name.clone(), cached)]));

        assert_eq!(runtime.request_count_by_endpoint[&endpoint.name], 1);
        assert_eq!(runtime.next_probe_at[&endpoint.name], first_due);
    }

    #[test]
    fn confirm_current_probe_respects_unavailable_probe_interval() {
        let mut cfg = config();
        cfg.probe_interval_seconds = 120.0;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        cfg.endpoints[0].base_url = format!("http://{addr}/v1");
        cfg.endpoints.truncate(1);
        let mut runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();
        runtime.current_endpoint = Some(endpoint.name.clone());
        runtime.remember_single_probe_result(
            &endpoint,
            &ProbeResult::unavailable(),
            Instant::now(),
        );
        runtime.confirm_current_probe_next_tick();

        let selected = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(runtime.tick(&HttpProbe::new(0.1).unwrap()));

        assert!(selected.is_none());
        assert_eq!(runtime.request_count_by_endpoint[&endpoint.name], 1);
    }

    #[test]
    fn agent_cooldown_result_blocks_auto_prompt_retry() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = runtime.config.endpoints[0].clone();
        runtime.current_endpoint = Some(endpoint.name.clone());
        runtime.last_prompt_at = Some(
            Instant::now()
                - Duration::from_secs_f64(runtime.config.min_prompt_interval_seconds + 1.0),
        );
        runtime.remember_single_probe_result(
            &endpoint,
            &ProbeResult {
                retry_after_seconds: Some(40),
                error: "一分钟30次，冷却20秒".to_string(),
                ..ProbeResult::synthetic_unavailable()
            },
            Instant::now(),
        );

        assert!(runtime.auto_prompt_blocked_by_endpoint_cooldown(&endpoint.name));
    }

    #[test]
    fn terminal_cooldown_blocks_background_upgrade_probe_until_due() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let high_requests = Arc::new(AtomicUsize::new(0));
        let server_done = Arc::clone(&done);
        let server_high_requests = Arc::clone(&high_requests);
        let handle = thread::spawn(move || loop {
            let (mut socket, _) = match server.accept() {
                Ok(value) => value,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if server_done.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => break,
            };
            server_high_requests.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0_u8; 4096];
            let _ = socket.read(&mut buffer);
            let body = r#"{"data":[{"id":"gpt-5.5"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes());
        });

        let mut cfg = config();
        cfg.probe_interval_seconds = 1.0;
        cfg.healthy_probe_interval_seconds = 40.0;
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        let mut runtime = RuntimeCore::new(cfg);
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        runtime.current_endpoint = Some(low.name.clone());
        runtime.remember_single_probe_result(&low, &ProbeResult::available(), Instant::now());
        runtime.remember_single_probe_result(
            &high,
            &ProbeResult {
                retry_after_seconds: Some(40),
                error: "一分钟30次，冷却20秒".to_string(),
                ..ProbeResult::synthetic_unavailable()
            },
            Instant::now(),
        );

        let selected = runtime.tick_blocking(&HttpProbe::new(0.2).unwrap());

        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(selected.unwrap().name, low.name);
        assert_eq!(high_requests.load(Ordering::SeqCst), 0);
        assert_eq!(
            runtime
                .request_count_by_endpoint
                .get(&high.name)
                .copied()
                .unwrap_or(0),
            0
        );
    }

    #[test]
    fn endpoint_disable_clears_auto_prompt_cooldown() {
        let mut runtime = RuntimeCore::new(config());
        runtime
            .endpoint_auto_prompt_blocked_until
            .insert("high".to_string(), Instant::now() + Duration::from_secs(40));

        assert!(runtime.set_endpoint_enabled("high", false));

        assert!(!runtime
            .endpoint_auto_prompt_blocked_until
            .contains_key("high"));
    }

    #[test]
    fn latest_auto_prompt_reads_saved_top_level_prompt() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("watchapi.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&json!({
                "auto_prompt": "new-auto",
                "endpoints": [{
                    "name": "high",
                    "auto_prompt": "legacy-endpoint-auto"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        let runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();

        assert_eq!(runtime.latest_auto_prompt(&endpoint), "new-auto");
    }

    #[test]
    fn usage_state_save_failure_is_visible_and_recovers() {
        let temp = tempfile::tempdir().unwrap();
        let mut cfg = config();
        cfg.config_path = Some(temp.path().join("blocked").join("watchapi.json"));
        std::fs::write(temp.path().join("blocked"), "not a directory").unwrap();
        let mut runtime = RuntimeCore::new(cfg);
        runtime.historical_usage_by_key.insert(
            "high:gpt-5.5".to_string(),
            TokenUsage {
                input_tokens: 1,
                total_tokens: 1,
                ..Default::default()
            },
        );

        assert!(runtime.save_usage_state());
        assert!(runtime.state_label().contains("保存用量统计失败"));
        assert!(!runtime.save_usage_state());

        let mut cfg = config();
        cfg.config_path = Some(temp.path().join("ok").join("watchapi.json"));
        std::fs::create_dir_all(temp.path().join("ok")).unwrap();
        runtime.usage_state_path = cfg
            .config_path
            .as_ref()
            .map(|path| path.with_file_name(".watchapi-usage.json"));
        assert!(runtime.save_usage_state());
        assert!(!runtime.state_label().contains("保存用量统计失败"));
    }

    #[test]
    fn usage_state_save_error_change_publishes_runtime_event() {
        let temp = tempfile::tempdir().unwrap();
        let mut cfg = config();
        cfg.config_path = Some(temp.path().join("blocked").join("watchapi.json"));
        std::fs::write(temp.path().join("blocked"), "not a directory").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut runtime = RuntimeCore::new(cfg);
        runtime.set_event_sender(Some(tx));
        runtime.historical_usage_by_key.insert(
            "high:gpt-5.5".to_string(),
            TokenUsage {
                input_tokens: 1,
                total_tokens: 1,
                ..Default::default()
            },
        );

        rx.try_recv().expect("initial snapshot should publish");
        if runtime.save_usage_state() {
            runtime.publish_snapshot_event();
        }

        let event = rx
            .try_recv()
            .expect("usage save failure should publish event");
        let RuntimeEvent::Snapshot(snapshot) = event;
        assert!(snapshot.state_label.contains("保存用量统计失败"));
    }

    #[test]
    fn finished_inflight_probe_is_not_counted_twice() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = runtime.config.endpoints[0].clone();

        runtime.mark_probe_started(&endpoint);
        runtime.remember_single_probe_result(&endpoint, &ProbeResult::available(), Instant::now());

        assert_eq!(runtime.rows()[0].request_count, 1);
        assert_eq!(runtime.rows()[0].last_status_code, "");
    }

    #[test]
    fn select_endpoint_records_each_real_probe_once() {
        let mut runtime = RuntimeCore::new(config());
        let probe = HttpProbe::new(0.1).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (_, availability) = tokio.block_on(runtime.find_first_available(
            &probe,
            vec![runtime.config.endpoints[0].clone()],
            false,
            ProbeMode::ModelsOnly,
            false,
        ));
        runtime.remember_probe_results(availability);

        assert_eq!(runtime.rows()[0].request_count, 1);
    }

    #[test]
    fn force_probe_control_state_save_failure_is_reported() {
        let source = include_str!("runtime.rs");
        let block = source
            .split("pub fn set_force_probe_endpoint")
            .nth(1)
            .and_then(|tail| tail.split("pub fn set_endpoint_enabled").next())
            .expect("force probe setter should be discoverable");

        assert!(block.contains("if let Err(err) = update_control_state"));
        assert!(block.contains("保存强制探测接口失败"));
        assert!(block.contains("self.publish_snapshot_event();"));
        assert!(!block.contains("let _ = update_control_state"));
    }

    #[test]
    fn models_only_probe_falls_back_to_real_request_when_models_miss_configured_model() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let models_requests = Arc::new(AtomicUsize::new(0));
        let response_requests = Arc::new(AtomicUsize::new(0));
        let server_done = Arc::clone(&done);
        let server_models_requests = Arc::clone(&models_requests);
        let server_response_requests = Arc::clone(&response_requests);
        let handle = thread::spawn(move || loop {
            let (mut socket, _) = match server.accept() {
                Ok(value) => value,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if server_done.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => break,
            };
            let mut buffer = [0_u8; 8192];
            let size = socket.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..size]);
            let (status, body) = if request.starts_with("GET /v1/models ") {
                server_models_requests.fetch_add(1, Ordering::SeqCst);
                (200_u16, r#"{"data":[{"id":"yuzyuz"}]}"#)
            } else if request.starts_with("POST /v1/responses ") {
                server_response_requests.fetch_add(1, Ordering::SeqCst);
                (200_u16, r#"{"output_text":"WATCHAPI_OK"}"#)
            } else {
                (404_u16, r#"{"error":{"message":"not found"}}"#)
            };
            let reason = if status == 200 { "OK" } else { "Not Found" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes());
        });

        let mut cfg = config();
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[0].model = "gpt-5.5".to_string();
        let mut runtime = RuntimeCore::new(cfg);
        let probe = HttpProbe::new(0.5).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (selected, availability) = tokio.block_on(runtime.find_first_available(
            &probe,
            vec![runtime.config.endpoints[0].clone()],
            false,
            ProbeMode::ModelsOnly,
            false,
        ));

        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(
            selected.as_ref().map(|endpoint| endpoint.name.as_str()),
            Some("high")
        );
        assert!(availability["high"].available);
        assert_eq!(availability["high"].status_code, Some(200));
        assert_eq!(models_requests.load(Ordering::SeqCst), 1);
        assert_eq!(response_requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn paused_auto_continuation_blocks_pending_initial_prompt() {
        let source = include_str!("runtime.rs");
        let block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn record_agent_usage").next())
            .expect("maybe_drive_prompt block should be discoverable");

        assert!(
            block.contains(
                "!auto_paused && (self.pending_initial_prompt.is_some() || can_send_by_interval)"
            ),
            "暂停自动续航时 pending_initial_prompt 也不能自动发送，否则启动终端后仍会自动续航"
        );
        assert!(
            block.contains("let automatic_requested = trigger_now"),
            "手动立即触发仍应绕过暂停状态"
        );
    }

    #[test]
    fn missing_or_invalid_control_state_defaults_to_auto_paused() {
        let source = include_str!("runtime.rs");
        let auto_paused_block = source
            .split("fn auto_paused")
            .nth(1)
            .and_then(|tail| tail.split("pub fn terminal_output").next())
            .expect("auto_paused block should be discoverable");
        let prompt_block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("let manual_prompt =").next())
            .expect("prompt control-state block should be discoverable");

        assert!(
            auto_paused_block.contains("unwrap_or(true)"),
            "控制状态缺失或损坏时必须默认暂停，避免读不到状态就自动续航"
        );
        assert!(
            prompt_block.contains("unwrap_or(true)"),
            "maybe_drive_prompt 读取不到 auto_paused 时也必须 fail-closed"
        );
    }

    #[test]
    fn failed_trigger_now_cleanup_is_not_silent_or_repeated() {
        let source = include_str!("runtime.rs");
        let struct_block = source
            .split("pub struct RuntimeCore")
            .nth(1)
            .and_then(|tail| {
                tail.split("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
                    .next()
            })
            .expect("runtime struct should be discoverable");
        let prompt_block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn record_agent_usage").next())
            .expect("prompt driver should be discoverable");

        assert!(
            struct_block.contains("trigger_now_clear_failed"),
            "trigger_now 清理失败需要内存闸门，避免文件仍为 true 时反复续航"
        );
        assert!(
            prompt_block.contains("trigger_now_requested")
                && prompt_block.contains("!self.trigger_now_clear_failed"),
            "自动续航判定必须忽略已经发送但清理失败的旧 trigger_now"
        );
        assert!(
            !prompt_block.contains("let _ = update_control_state(\n                        config_path,\n                        &[(\"trigger_now\""),
            "清理 trigger_now 不能静默忽略失败"
        );
        assert!(
            prompt_block.contains("清理立即续航标记失败"),
            "清理失败要进入可见状态，便于定位文件权限或状态文件异常"
        );
    }

    #[test]
    fn paused_auto_continuation_blocks_turn_stall_restart() {
        let source = include_str!("runtime.rs");
        let tick_block = source
            .split("pub async fn tick")
            .nth(1)
            .and_then(|tail| tail.split("self.remember_probe_results").next())
            .expect("tick monitor block should be discoverable");

        assert!(
            tick_block.contains(
                "} else if !auto_paused && agent.is_turn_stalled(self.config.turn_stall_seconds) {"
            ),
            "暂停自动续航后，长时间无输出不能触发卡死失败并重启/切换"
        );
    }

    #[test]
    fn paused_auto_continuation_holds_current_agent_before_failure_switching() {
        let source = include_str!("runtime.rs");
        let tick_block = source
            .split("pub async fn tick")
            .nth(1)
            .and_then(|tail| tail.split("let (selected, mut availability)").next())
            .expect("tick pre-selection block should be discoverable");
        let paused_hold_pos = tick_block
            .find("if auto_paused && self.current_endpoint.is_some() && !force_full_probe")
            .expect("paused runtime must hold the current endpoint before selection");
        let endpoint_failure_pos = tick_block
            .find("agent.endpoint_failure_detected")
            .expect("endpoint failure branch should exist");
        let selection_flag_pos = tick_block
            .find("current_failed = true")
            .expect("failure selection flag should exist");

        assert!(
            paused_hold_pos < endpoint_failure_pos && paused_hold_pos < selection_flag_pos,
            "暂停后必须先保持当前 agent，不能继续消费失败/卡死信号后触发 switch_to 重启终端"
        );
    }

    #[test]
    fn runtime_wait_gate_has_safe_watchdog_after_idle_check() {
        let source = include_str!("runtime.rs");
        let block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("agent.can_send_prompt()").next())
            .expect("maybe_drive_prompt readiness block should be discoverable");

        assert!(block.contains("agent.has_assistant_message_since_prompt()"));
        assert!(block.contains("agent.auto_wait_safely_released()"));
        assert!(
            block.find("agent.auto_wait_safely_released()") > block.find("agent.is_idle("),
            "watchdog 必须在 idle/ready 判定之后运行，不能绕过 Working 检测"
        );
    }

    #[test]
    fn failed_auto_prompt_send_only_restores_pending_initial_prompt() {
        let source = include_str!("runtime.rs");
        let block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn record_agent_usage").next())
            .expect("maybe_drive_prompt block should be discoverable");

        assert!(block.contains("let mut restore_initial_prompt = false;"));
        assert!(block.contains("restore_initial_prompt = true;"));
        assert!(
            block.contains("} else if restore_initial_prompt {\n                self.pending_initial_prompt = Some(prompt);"),
            "发送被最终闸门拒绝时，只能恢复真实 pending initial prompt，不能把普通 auto prompt 塞回首轮提示词"
        );
    }

    #[test]
    fn completion_pause_detection_does_not_disable_auto_continuation() {
        let source = include_str!("runtime.rs");
        let tick_block = source
            .split("pub async fn tick")
            .nth(1)
            .and_then(|tail| tail.split("self.remember_probe_results").next())
            .expect("tick monitor block should be discoverable");
        let completion_pause_block = tick_block
            .split("agent.completion_pause_detected")
            .nth(1)
            .and_then(|tail| tail.split("agent.endpoint_failure_detected").next())
            .expect("completion pause branch should be discoverable");

        assert!(
            !completion_pause_block.contains("\"auto_paused\""),
            "完成关键词只能清理检测标记，不能把自动续航改成暂停"
        );
    }

    #[test]
    fn forced_current_probe_keeps_same_running_endpoint_without_restart() {
        let source = include_str!("runtime.rs");
        let tick_block = source
            .split("pub async fn tick")
            .nth(1)
            .and_then(|tail| tail.split("pub fn tick_blocking").next())
            .expect("tick block should be discoverable");

        assert!(
            tick_block.contains("self.agent.as_ref().is_some_and(AgentProcess::is_running)"),
            "同接口探测恢复可用时，必须确认 agent 仍在运行才允许跳过重启"
        );
        assert!(
            tick_block.contains(".get(&selected.name)")
                && tick_block.contains(".is_some_and(|result| result.available)"),
            "同接口跳过重启必须基于本轮探测/选择结果可用，不能复用旧状态误判"
        );
        assert!(
            tick_block.find("changed = false") < tick_block.find("match self.switch_to"),
            "同接口且仍可用时应在 switch_to 前清除 changed，避免重启 agent"
        );
    }

    #[test]
    fn paused_current_endpoint_skips_background_upgrade_probe() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let request_count = Arc::new(AtomicUsize::new(0));
        let server_done = Arc::clone(&done);
        let server_request_count = Arc::clone(&request_count);
        let handle = thread::spawn(move || loop {
            let (mut socket, _) = match server.accept() {
                Ok(value) => value,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if server_done.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => break,
            };
            server_request_count.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0_u8; 4096];
            let _ = socket.read(&mut buffer);
            let body = r#"{"data":[{"id":"gpt-5.5"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes());
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("auto_paused", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        let mut runtime = RuntimeCore::new(cfg);
        runtime.current_endpoint = Some("low".to_string());
        runtime.remember_probe_results(HashMap::from([(
            "low".to_string(),
            ProbeResult::available(),
        )]));
        let probe = HttpProbe::new(0.2).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let selected = tokio.block_on(runtime.tick(&probe));

        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(selected.unwrap().name, "low");
        assert_eq!(request_count.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn force_current_probe_switches_when_current_endpoint_is_unavailable() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let high_requests = Arc::new(AtomicUsize::new(0));
        let low_requests = Arc::new(AtomicUsize::new(0));
        let server_done = Arc::clone(&done);
        let server_high_requests = Arc::clone(&high_requests);
        let server_low_requests = Arc::clone(&low_requests);
        let handle = thread::spawn(move || loop {
            let (mut socket, _) = match server.accept() {
                Ok(value) => value,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if server_done.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => break,
            };
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let size = socket.read(&mut buffer).unwrap_or(0);
                if size == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..size]);
                if raw.windows(4).any(|item| item == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&raw);
            let is_low = request.contains("low-model");
            let (status, reason, body) = if is_low {
                server_low_requests.fetch_add(1, Ordering::SeqCst);
                (
                    502_u16,
                    "Bad Gateway",
                    r#"{"error":{"message":"low down"}}"#.to_string(),
                )
            } else {
                server_high_requests.fetch_add(1, Ordering::SeqCst);
                (
                    200_u16,
                    "OK",
                    r#"{"output":[{"content":[{"text":"WATCHAPI_OK"}]}]}"#.to_string(),
                )
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("auto_paused", json!(false))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[0].model = "high-model".to_string();
        cfg.endpoints[1].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[1].model = "low-model".to_string();
        let mut runtime = RuntimeCore::new(cfg);
        runtime.current_endpoint = Some("low".to_string());
        runtime.remember_probe_results(HashMap::from([(
            "low".to_string(),
            ProbeResult::available(),
        )]));
        runtime.force_current_probe_next_tick();
        let probe = HttpProbe::new(0.5).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let selected = tokio.block_on(runtime.tick(&probe));

        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(selected.unwrap().name, "high");
        assert_eq!(low_requests.load(Ordering::SeqCst), 1);
        assert!(high_requests.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn force_current_probe_flag_is_consumed_when_current_endpoint_already_failed() {
        let source = include_str!("runtime.rs");
        let tick_prelude = source
            .split("pub async fn tick")
            .nth(1)
            .and_then(|tail| {
                tail.split("if let Some(current) = self.current_endpoint.clone()")
                    .next()
            })
            .expect("tick prelude should be discoverable");

        assert!(
            tick_prelude.contains("self.force_current_probe_once = false"),
            "force_current_probe_once 是一次性请求，必须在 tick 开头消费，避免当前接口已失败时遗留到后续轮次"
        );
    }

    #[test]
    fn force_full_probe_scans_by_weight_and_keeps_control_pause_state() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let high_requests = Arc::new(AtomicUsize::new(0));
        let low_requests = Arc::new(AtomicUsize::new(0));
        let server_done = Arc::clone(&done);
        let server_high_requests = Arc::clone(&high_requests);
        let server_low_requests = Arc::clone(&low_requests);
        let handle = thread::spawn(move || loop {
            let (mut socket, _) = match server.accept() {
                Ok(value) => value,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if server_done.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => break,
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let size = socket.read(&mut buffer).unwrap_or(0);
                if size == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..size]);
                if raw.windows(4).any(|item| item == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&raw);
            let is_probe_post = request.starts_with("POST /v1/responses ");
            let is_low = request.contains("low-model");
            let (status, reason, body) = if is_low {
                if is_probe_post {
                    server_low_requests.fetch_add(1, Ordering::SeqCst);
                }
                (
                    200_u16,
                    "OK",
                    r#"{"output":[{"content":[{"text":"WATCHAPI_OK"}]}]}"#.to_string(),
                )
            } else {
                if is_probe_post {
                    server_high_requests.fetch_add(1, Ordering::SeqCst);
                }
                (
                    502_u16,
                    "Bad Gateway",
                    r#"{"error":{"message":"high down"}}"#.to_string(),
                )
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("auto_paused", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path.clone());
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[0].model = "high-model".to_string();
        cfg.endpoints[1].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[1].model = "low-model".to_string();
        let mut runtime = RuntimeCore::new(cfg);
        runtime.current_endpoint = Some("low".to_string());
        runtime.force_full_probe_next_tick();
        let probe = HttpProbe::new(0.5).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let selected = tokio.block_on(runtime.tick(&probe));

        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(selected.unwrap().name, "low");
        assert_eq!(high_requests.load(Ordering::SeqCst), 1);
        assert_eq!(low_requests.load(Ordering::SeqCst), 1);
        assert_eq!(
            crate::control::read_control_state(&config_path)["auto_paused"],
            json!(true)
        );
    }

    #[test]
    fn higher_aggregate_endpoint_requires_full_probe_before_upgrade() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let models_count = Arc::new(AtomicUsize::new(0));
        let responses_count = Arc::new(AtomicUsize::new(0));
        let server_done = Arc::clone(&done);
        let server_models_count = Arc::clone(&models_count);
        let server_responses_count = Arc::clone(&responses_count);
        let handle = thread::spawn(move || loop {
            let (mut socket, _) = match server.accept() {
                Ok(value) => value,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if server_done.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => break,
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let size = socket.read(&mut buffer).unwrap();
                if size == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..size]);
                if raw.windows(4).any(|item| item == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&raw);
            let (status, reason, body) = if request.starts_with("GET /v1/models ") {
                server_models_count.fetch_add(1, Ordering::SeqCst);
                (200_u16, "OK", r#"{"data":[{"id":"gpt-5.5"}]}"#.to_string())
            } else if request.starts_with("POST /v1/responses ") {
                server_responses_count.fetch_add(1, Ordering::SeqCst);
                (
                    429_u16,
                    "Too Many Requests",
                    r#"{"error":{"message":"cooldown"}}"#.to_string(),
                )
            } else {
                (404_u16, "Not Found", r#"{"error":"not found"}"#.to_string())
            };
            let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            socket.write_all(response.as_bytes()).unwrap();
        });

        let mut cfg = config();
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[1].base_url = "https://low.example.test/v1".to_string();
        let mut runtime = RuntimeCore::new(cfg);
        runtime.current_endpoint = Some("low".to_string());
        runtime.remember_probe_results(HashMap::from([(
            "low".to_string(),
            ProbeResult::available(),
        )]));
        let temp = tempfile::tempdir().unwrap();
        let aggregate_runtime = Arc::new(
            crate::aggregate_egress::AggregateEgressRuntime::new(
                crate::aggregate_egress::AggregateEgressConfig {
                    enabled: true,
                    ..crate::aggregate_egress::AggregateEgressConfig::default()
                },
                vec![crate::aggregate_egress::AggregateDeploymentSeed {
                    upstream: "test".to_string(),
                    base_url: format!("http://127.0.0.1:{port}/v1"),
                    public_model: "gpt-5.5".to_string(),
                    actual_model: "gpt-5.5".to_string(),
                    max_qps: None,
                    max_rpm: None,
                    max_concurrency: 5,
                    upstream_cooldown_seconds: None,
                    egress_note: String::new(),
                    key: "sk-test".to_string(),
                    key_label: "sk-test".to_string(),
                    quality_key: "test".to_string(),
                }],
                temp.path().join("quality.json"),
                None,
                0,
            )
            .unwrap(),
        );
        crate::aggregate_egress::register_runtime(
            &format!("http://127.0.0.1:{port}/v1"),
            &aggregate_runtime,
        )
        .unwrap();

        let probe = HttpProbe::new(2.0).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (selected, availability) =
            tokio.block_on(runtime.select_endpoint(&probe, false, false));

        crate::aggregate_egress::unregister_runtime(&format!("http://127.0.0.1:{port}/v1"));
        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(selected.unwrap().name, "low");
        assert!(!availability["high"].available);
        assert_eq!(models_count.load(Ordering::SeqCst), 1);
        assert_eq!(responses_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn starting_probe_is_visible_before_result_finishes() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = runtime.config.endpoints[0].clone();

        runtime.mark_probe_started(&endpoint);

        assert_eq!(runtime.state_label(), "正在探测");
        assert_eq!(runtime.rows()[0].request_status, "探测中");
    }

    #[test]
    fn row_status_explains_real_request_when_health_is_unknown() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = runtime.config.endpoints[0].clone();
        let result = ProbeResult {
            available: true,
            status_code: Some(200),
            request_made: true,
            ..Default::default()
        };

        runtime.remember_single_probe_result(&endpoint, &result, Instant::now());

        let row = runtime.rows().remove(0);
        assert_eq!(row.last_status_code, "200");
        assert_ne!(row.request_status, "未知");
        assert!(
            row.request_status.contains("HTTP 200"),
            "status should explain the real request, got {}",
            row.request_status
        );
    }

    #[test]
    fn row_status_explains_cached_status_code_when_health_is_unknown() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = runtime.config.endpoints[0].clone();
        let result = ProbeResult {
            available: true,
            status_code: Some(200),
            request_made: false,
            ..Default::default()
        };

        runtime.remember_single_probe_result(&endpoint, &result, Instant::now());

        let row = runtime.rows().remove(0);
        assert_eq!(row.last_status_code, "200");
        assert_ne!(row.request_status, "未知");
        assert!(
            row.request_status.contains("HTTP 200"),
            "status should explain the cached status code, got {}",
            row.request_status
        );
    }

    #[test]
    fn synthetic_unavailable_clears_stale_status_code() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = runtime.config.endpoints[0].clone();
        let ok_result = ProbeResult {
            available: true,
            status_code: Some(200),
            request_made: true,
            ..Default::default()
        };

        runtime.remember_single_probe_result(&endpoint, &ok_result, Instant::now());
        runtime.remember_single_probe_result(
            &endpoint,
            &ProbeResult::synthetic_unavailable(),
            Instant::now(),
        );

        let row = runtime.rows().remove(0);
        assert_eq!(row.last_status_code, "");
        assert!(
            !row.request_status.contains("HTTP 200"),
            "synthetic failure should not show stale HTTP status, got {}",
            row.request_status
        );
    }

    #[test]
    fn synthetic_unavailable_health_status_does_not_keep_stale_200() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = runtime.config.endpoints[0].clone();
        let ok_result = ProbeResult {
            available: true,
            status_code: Some(200),
            request_made: true,
            ..Default::default()
        };

        runtime.remember_single_probe_result(&endpoint, &ok_result, Instant::now());
        runtime.health.update(
            &runtime.config.endpoints,
            &HashMap::from([("high".to_string(), ok_result)]),
        );
        runtime.remember_single_probe_result(
            &endpoint,
            &ProbeResult::synthetic_unavailable(),
            Instant::now(),
        );
        runtime.health.update(
            &runtime.config.endpoints,
            &HashMap::from([("high".to_string(), ProbeResult::synthetic_unavailable())]),
        );

        let row = runtime
            .rows()
            .into_iter()
            .find(|row| row.name == "high")
            .unwrap();
        assert_eq!(row.request_status, "不可用");
        assert_eq!(row.last_status_code, "");
    }

    #[test]
    fn running_current_endpoint_does_not_replay_stale_unavailable_probe() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = runtime.config.endpoints[0].clone();
        runtime.current_endpoint = Some(endpoint.name.clone());
        runtime.state = RuntimeState::Running;
        runtime
            .last_availability
            .insert(endpoint.name.clone(), ProbeResult::synthetic_unavailable());
        runtime.health.update(
            &runtime.config.endpoints,
            &HashMap::from([(endpoint.name.clone(), ProbeResult::synthetic_unavailable())]),
        );

        let probe = HttpProbe::new(0.1).unwrap();
        runtime.tick_blocking(&probe);

        let row = runtime
            .rows()
            .into_iter()
            .find(|row| row.name == endpoint.name)
            .unwrap();
        assert!(row.selected);
        assert_ne!(row.request_status, "不可用");
    }

    #[test]
    fn runtime_snapshot_contains_pty_terminal_output_only() {
        let runtime = RuntimeCore::new(config());
        let snapshot = runtime.snapshot();

        assert!(snapshot.terminal_output.is_empty());
    }

    #[test]
    fn terminal_output_uses_lightweight_text_path() {
        let source = include_str!("runtime.rs");
        let block = source
            .split("pub fn terminal_output(&self) -> String")
            .nth(1)
            .and_then(|tail| tail.split("pub fn terminal_process_id").next())
            .expect("terminal_output block should be discoverable");

        assert!(
            block.contains("terminal_output_text"),
            "terminal_output should not build a full TerminalView"
        );
        assert!(
            !block.contains("terminal_snapshot"),
            "terminal_output must avoid terminal_snapshot because it clones the PTY grid"
        );
    }

    #[test]
    fn terminal_command_failures_are_not_silently_ignored() {
        let source = include_str!("runtime.rs");
        let block = source
            .split("pub fn write_user_input")
            .nth(1)
            .and_then(|tail| tail.split("pub fn mark_user_input_active").next())
            .expect("terminal command helpers should be discoverable");

        assert!(!block.contains("let _ = agent.write_user_input"));
        assert!(!block.contains("let _ = agent.resize_terminal"));
        assert!(!block.contains("let _ = agent.scroll_terminal"));
        assert!(block.contains("Result<(), String>"));
        assert!(block.contains("mark_terminal_command_failed"));
    }

    #[test]
    fn terminal_view_uses_lightweight_revision_before_grid_clone() {
        let source = include_str!("runtime.rs");
        let impl_block = source
            .split("impl RuntimeCore")
            .nth(1)
            .and_then(|tail| tail.split("#[cfg(test)]").next())
            .expect("RuntimeCore impl block should be discoverable");

        assert!(
            impl_block.contains("pub fn terminal_view_revision(&self) -> u64"),
            "runtime should expose a cheap TerminalView revision check"
        );
        assert!(
            impl_block.contains("pub fn terminal_view(&self) -> Option<TerminalView>"),
            "runtime should expose a direct TerminalView getter for GUI refresh"
        );
    }

    #[test]
    fn runtime_events_do_not_clone_terminal_payloads() {
        let source = include_str!("runtime.rs");
        let event_snapshot_block = source
            .split("fn event_snapshot(&self")
            .nth(1)
            .and_then(|tail| tail.split("pub fn publish_snapshot").next())
            .expect("event snapshot block should be discoverable");
        let publish_block = source
            .split("fn publish_snapshot_event(&self)")
            .nth(1)
            .and_then(|tail| tail.split("fn now_text").next())
            .expect("publish snapshot block should be discoverable");

        assert!(event_snapshot_block.contains("terminal_output: String::new()"));
        assert!(event_snapshot_block.contains("terminal_view: None"));
        assert!(event_snapshot_block
            .contains("terminal_output_revision: self.terminal_output_revision()"));
        assert!(
            event_snapshot_block.contains("terminal_view_revision: self.terminal_view_revision()")
        );
        assert!(publish_block.contains("self.event_snapshot(terminal_process_id)"));
        assert!(!publish_block.contains("self.snapshot()"));
    }

    #[test]
    fn runtime_snapshot_events_are_deduplicated() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut runtime = RuntimeCore::new(config());
        runtime.set_event_sender(Some(tx));

        assert!(rx.try_recv().is_ok());
        runtime.publish_snapshot();
        runtime.publish_snapshot();

        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn set_event_sender_publishes_initial_snapshot() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut runtime = RuntimeCore::new(config());

        runtime.set_event_sender(Some(tx));

        let event = rx
            .try_recv()
            .expect("event sender should receive initial snapshot");
        let RuntimeEvent::Snapshot(snapshot) = event;
        assert_eq!(snapshot.state_label, "已停止");
        assert_eq!(snapshot.rows.len(), runtime.config.endpoints.len());
    }

    #[test]
    fn runtime_event_publish_skips_snapshot_when_signature_is_unchanged() {
        let source = include_str!("runtime.rs");
        let publish_block = source
            .split("fn publish_snapshot_event(&self)")
            .nth(1)
            .and_then(|tail| tail.split("fn now_text").next())
            .expect("publish snapshot block should be discoverable");

        assert!(
            publish_block.contains("let signature = self.event_signature(terminal_process_id);")
        );
        assert!(publish_block.contains("return;"));
        assert!(publish_block.contains("let snapshot = self.event_snapshot(terminal_process_id);"));
        assert!(
            publish_block.find("let signature = self.event_signature(terminal_process_id);")
                < publish_block.find("let snapshot = self.event_snapshot(terminal_process_id);"),
            "runtime should avoid building rows when the lightweight event signature is unchanged"
        );
        assert!(source.contains("fn runtime_event_time_bucket() -> u64"));
    }

    #[test]
    fn runtime_event_publish_reuses_single_terminal_process_probe() {
        let source = include_str!("runtime.rs");
        let publish_block = source
            .split("fn publish_snapshot_event(&self)")
            .nth(1)
            .and_then(|tail| tail.split("fn now_text").next())
            .expect("publish snapshot block should be discoverable");
        let event_snapshot_block = source
            .split("fn event_snapshot(&self")
            .nth(1)
            .and_then(|tail| tail.split("fn event_signature").next())
            .expect("event snapshot block should be discoverable");
        let event_signature_block = source
            .split("fn event_signature(&self")
            .nth(1)
            .and_then(|tail| tail.split("pub fn publish_snapshot").next())
            .expect("event signature block should be discoverable");

        assert!(publish_block.contains("let terminal_process_id = self.terminal_process_id();"));
        assert_eq!(
            publish_block.matches("self.terminal_process_id()").count(),
            1,
            "发布事件时进程状态只应探测一次，避免签名/快照重复 try_wait"
        );
        assert!(publish_block.contains("self.event_signature(terminal_process_id)"));
        assert!(publish_block.contains("self.event_snapshot(terminal_process_id)"));
        assert!(!event_snapshot_block.contains("self.terminal_process_id()"));
        assert!(!event_signature_block.contains("self.terminal_process_id()"));
    }

    #[test]
    fn no_available_endpoint_keeps_watcher_waiting() {
        let mut runtime = RuntimeCore::new(config());

        let selected = runtime.apply_probe_results(HashMap::from([
            ("high".to_string(), ProbeResult::unavailable()),
            ("low".to_string(), ProbeResult::unavailable()),
        ]));

        assert!(selected.is_none());
        assert_eq!(runtime.state_label(), "等待可用接口");
    }

    #[test]
    fn endpoint_request_failures_reach_threshold_before_switching() {
        let mut cfg = config();
        cfg.endpoint_failure_threshold = 3;
        let mut runtime = RuntimeCore::new(cfg);

        assert!(!runtime.record_endpoint_request_failure_reached_threshold("high"));
        assert!(!runtime.record_endpoint_request_failure_reached_threshold("high"));
        assert!(runtime.record_endpoint_request_failure_reached_threshold("high"));

        runtime.clear_endpoint_request_failures("high");
        assert!(!runtime.record_endpoint_request_failure_reached_threshold("high"));
    }

    #[test]
    fn endpoint_request_failures_survive_normal_ticks_until_success_evidence() {
        let mut cfg = config();
        cfg.endpoint_failure_threshold = 3;
        let mut runtime = RuntimeCore::new(cfg);
        runtime.current_endpoint = Some("high".to_string());
        runtime.state = RuntimeState::Running;
        runtime
            .last_status_code_by_endpoint
            .insert("high".to_string(), Some(401));

        assert!(!runtime.record_endpoint_request_failure_reached_threshold("high"));
        runtime.transient_failures_by_endpoint.remove("high");
        runtime.stall_failures_by_endpoint.remove("high");

        assert_eq!(
            runtime.endpoint_request_failures_by_endpoint["high"], 1,
            "没有新错误的普通 tick 不能把请求失败容错计数清零"
        );
        assert_eq!(runtime.rows()[0].request_status, "请求失败 1/3 HTTP 401");

        let endpoint = runtime.config.endpoints[0].clone();
        runtime.remember_single_probe_result(&endpoint, &ProbeResult::available(), Instant::now());

        assert!(
            !runtime
                .endpoint_request_failures_by_endpoint
                .contains_key("high"),
            "真实探测成功才是清零请求失败计数的成功证据"
        );
    }

    #[test]
    fn endpoint_failure_branch_releases_auto_wait_before_retry() {
        let source = include_str!("runtime.rs");
        let failure_branch = source
            .split("} else if agent.endpoint_failure_detected {")
            .nth(1)
            .and_then(|tail| {
                tail.split("} else if agent.transient_endpoint_failure_detected {")
                    .next()
            })
            .expect("endpoint failure branch should exist");

        assert!(failure_branch.contains("agent.mark_current_turn_failed();"));
        assert!(failure_branch.contains("self.waiting_for_assistant_progress = false;"));
        assert!(failure_branch.contains("result.status_code = agent.endpoint_failure_status_code"));
        assert!(failure_branch
            .contains("result.retry_after_seconds = agent.endpoint_failure_retry_after_seconds"));
    }

    #[test]
    fn auto_prompt_checks_endpoint_cooldown_before_send() {
        let source = include_str!("runtime.rs");
        let prompt_block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| {
                tail.split("let is_manual = manual_prompt.is_some();")
                    .next()
            })
            .expect("prompt driver should be discoverable");

        assert!(prompt_block.contains("auto_prompt_blocked_by_endpoint_cooldown"));
        assert!(prompt_block.contains("manual_prompt.is_none()"));
    }

    #[test]
    fn endpoint_failure_counter_is_cleared_only_by_success_evidence() {
        let source = include_str!("runtime.rs");
        let normal_agent_branch = source
            .split("} else if agent.is_turn_stalled(self.config.turn_stall_seconds) {")
            .nth(1)
            .and_then(|tail| tail.split("if mark_polluted {").next())
            .expect("normal agent branch should be discoverable");
        let prompt_block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn record_agent_usage").next())
            .expect("prompt driver should be discoverable");
        let probe_block = source
            .split("fn remember_single_probe_result")
            .nth(1)
            .and_then(|tail| tail.split("fn cooldown_result").next())
            .expect("probe result recorder should be discoverable");

        assert!(
            !normal_agent_branch.contains("clear_endpoint_request_failures(&current)"),
            "普通 tick 不能清请求失败计数，否则连续错误码会一直停在 1/3"
        );
        assert!(
            prompt_block.contains("agent.has_session_assistant_message_since_prompt()")
                && prompt_block.contains("self.clear_endpoint_request_failures(&endpoint.name)"),
            "会话文件里的 assistant 回复才是清请求失败计数的回复成功证据"
        );
        assert!(
            probe_block.contains("result.request_made && result.available")
                && probe_block.contains("self.clear_endpoint_request_failures(&endpoint.name)"),
            "真实探测成功才是清请求失败计数的探测成功证据"
        );
    }

    #[test]
    fn select_endpoint_skips_recent_start_failure_and_uses_cached_fallback() {
        let mut runtime = RuntimeCore::new(config());
        runtime.remember_probe_results(HashMap::from([
            ("high".to_string(), ProbeResult::available()),
            ("low".to_string(), ProbeResult::available()),
        ]));
        runtime.mark_startup_failure("high", "agent start failed".to_string());

        let probe = HttpProbe::new(0.1).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (selected, availability) =
            tokio.block_on(runtime.select_endpoint(&probe, false, false));

        assert_eq!(selected.unwrap().name, "low");
        assert!(!availability.get("high").unwrap().request_made);
        assert!(!availability.get("high").unwrap().available);
        assert!(availability
            .get("high")
            .unwrap()
            .error
            .contains("agent start failed"));
    }

    #[test]
    fn startup_failure_does_not_destroy_cached_available_result() {
        let mut runtime = RuntimeCore::new(config());
        runtime.remember_probe_results(HashMap::from([(
            "high".to_string(),
            ProbeResult::available(),
        )]));

        runtime.mark_startup_failure("high", "agent start failed".to_string());

        assert!(runtime.last_availability["high"].available);
        assert!(runtime.last_availability["high"].request_made);
    }
}
