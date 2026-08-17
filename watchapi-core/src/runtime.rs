use crate::agent::AgentProcess;
use crate::atomic_write::write_text_atomic;
use crate::config::{AgentDriver, AppConfig, EndpointConfig};
use crate::control::{
    enqueue_manual_prompt, pop_manual_prompt, read_control_state, update_control_state,
};
use crate::guard_proxy::{GuardAuditSnapshot, GuardProxyServer};
use crate::health::EndpointHealthTracker;
use crate::http_probe::HttpProbe;
use crate::probe::ProbeResult;
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
use std::sync::{Arc, Mutex, OnceLock};
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
    WaitingInput(String),
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

pub type RuntimeEventWakeup = Arc<dyn Fn() + Send + Sync + 'static>;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct GuardPollutionSignal {
    pollution_failures: u64,
    high_risk_replacements: u64,
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
    guard_pollution_signal_by_endpoint: HashMap<String, GuardPollutionSignal>,
    fixed_endpoint: Option<String>,
    force_probe_endpoint: Option<String>,
    token_usage_by_endpoint: HashMap<String, TokenUsage>,
    historical_usage_by_key: HashMap<String, TokenUsage>,
    usage_state_path: Option<PathBuf>,
    usage_save_error: Option<String>,
    control_save_error: Option<String>,
    manual_prompt_requeue_error: Option<String>,
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
    guard_polluted_until: HashMap<String, Instant>,
    pollution_recovery_successes_by_endpoint: HashMap<String, u32>,
    startup_failed_until: HashMap<String, Instant>,
    startup_failure_error: HashMap<String, String>,
    probing_endpoint: Option<String>,
    counted_probe_inflight: HashSet<String>,
    event_tx: Option<Sender<RuntimeEvent>>,
    event_wakeup: Option<RuntimeEventWakeup>,
    last_event_snapshot: Mutex<Option<RuntimeSnapshot>>,
    last_event_signature: Mutex<Option<RuntimeEventSignature>>,
    pending_initial_prompt: Option<String>,
    pending_goal_prompt: Option<String>,
    pending_continuation_trigger_prompt: Option<String>,
    last_prompt_at: Option<Instant>,
    last_auto_prompt_signature: Option<(String, String)>,
    waiting_for_assistant_progress: bool,
    goal_synced_this_run: bool,
    goal_turn_active: bool,
    goal_request_clear_failed_signature: Option<String>,
    trigger_now_clear_failed: bool,
    force_new_session_once: bool,
    direct_endpoint_once: Option<String>,
    fork_source_session_once: Option<(String, Option<PathBuf>)>,
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
            guard_pollution_signal_by_endpoint: HashMap::new(),
            fixed_endpoint: None,
            force_probe_endpoint: None,
            token_usage_by_endpoint: HashMap::new(),
            historical_usage_by_key,
            usage_state_path,
            usage_save_error: None,
            control_save_error: None,
            manual_prompt_requeue_error: None,
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
            guard_polluted_until: HashMap::new(),
            pollution_recovery_successes_by_endpoint: HashMap::new(),
            startup_failed_until: HashMap::new(),
            startup_failure_error: HashMap::new(),
            probing_endpoint: None,
            counted_probe_inflight: HashSet::new(),
            event_tx: None,
            event_wakeup: None,
            last_event_snapshot: Mutex::new(None),
            last_event_signature: Mutex::new(None),
            pending_initial_prompt: None,
            pending_goal_prompt: None,
            pending_continuation_trigger_prompt: None,
            last_prompt_at: None,
            last_auto_prompt_signature: None,
            waiting_for_assistant_progress: false,
            goal_synced_this_run: false,
            goal_turn_active: false,
            goal_request_clear_failed_signature: None,
            trigger_now_clear_failed: false,
            force_new_session_once: false,
            direct_endpoint_once: None,
            fork_source_session_once: None,
            force_current_probe_once: false,
            confirm_current_probe_once: false,
            force_full_probe_once: false,
        }
    }

    pub async fn tick(&mut self, probe: &HttpProbe) -> Option<EndpointConfig> {
        self.sync_control_state();
        if let Some(endpoint_name) = self.direct_endpoint_once.take() {
            let Some(endpoint) = self
                .endpoint_by_name_including_disabled(&endpoint_name)
                .cloned()
            else {
                self.state =
                    RuntimeState::Error(format!("直接启动失败：未找到接口组：{endpoint_name}"));
                self.publish_snapshot_event();
                return None;
            };
            match self.switch_to(endpoint.clone()) {
                Ok(()) => {
                    self.maybe_drive_prompt(&endpoint);
                    self.record_agent_usage(&endpoint);
                    self.publish_snapshot_event();
                    return Some(endpoint);
                }
                Err(err) => {
                    self.state = RuntimeState::Error(format!("直接启动失败：{err}"));
                    self.publish_snapshot_event();
                    return None;
                }
            }
        }
        let auto_paused = self.auto_paused();
        let mut current_failed = false;
        let mut skip_current = false;
        let mut hold_current_on_no_alternative = false;
        let force_probe_current = self.force_current_probe_once;
        let confirm_probe_current = self.confirm_current_probe_once;
        let force_full_probe = self.force_full_probe_once;
        self.force_current_probe_once = false;
        self.confirm_current_probe_once = false;
        let mut overrides = HashMap::new();

        if auto_paused && self.current_endpoint.is_some() && !force_full_probe && !current_failed {
            if let Some(current) = self.current_endpoint.clone() {
                if let Some(endpoint) = self.endpoint_by_name(&current).cloned() {
                    self.maybe_drive_prompt(&endpoint);
                    self.record_agent_usage(&endpoint);
                    let direct_pollution_replaced =
                        guard_replaces_direct_pollution_detection(&endpoint);
                    let current_polluted = if let Some(agent) = self.agent.as_mut() {
                        let polluted = agent.pollution_detected;
                        if polluted {
                            agent.pollution_detected = false;
                        } else if agent.completion_pause_detected {
                            agent.clear_completion_pause_detected();
                        }
                        polluted && !direct_pollution_replaced
                    } else {
                        false
                    };
                    let mut recovery = HashMap::new();
                    if current_polluted {
                        let result = ProbeResult::synthetic_polluted();
                        self.remember_single_probe_result(&endpoint, &result, Instant::now());
                        self.mark_endpoint_polluted(&current);
                        recovery.insert(current.clone(), result);
                    }
                    if self.record_current_guard_pollution_signal(&current, &mut recovery) {
                        if let Some(result) = recovery.get(&current).cloned() {
                            self.remember_single_probe_result(&endpoint, &result, Instant::now());
                        }
                    }
                    recovery.extend(
                        self.probe_due_unhealthy_endpoints(
                            probe,
                            vec![endpoint.clone()],
                            ProbeMode::Full,
                        )
                        .await,
                    );
                    recovery.extend(
                        self.probe_due_background_recovery(probe, &current, ProbeMode::Full)
                            .await,
                    );
                    self.health.update(&self.config.endpoints, &recovery);
                    return Some(endpoint);
                }
            }
        }

        if let Some(current) = self.current_endpoint.clone() {
            if self.endpoint_request_failure_threshold_reached(&current)
                && !self.clear_endpoint_request_failures_on_session_success(&current)
            {
                current_failed = true;
                skip_current = true;
                hold_current_on_no_alternative = true;
                self.state =
                    RuntimeState::Error(self.endpoint_request_failure_state_text(&current));
            }
        }

        if let Some(current) = self.current_endpoint.clone() {
            if self.record_current_guard_pollution_signal(&current, &mut overrides) {
                current_failed = true;
                skip_current = true;
                self.state = RuntimeState::Error("保护层污染".to_string());
            }
        }

        if let Some(current) = self.current_endpoint.clone() {
            let mut mark_polluted = false;
            let direct_pollution_replaced = self
                .endpoint_by_name(&current)
                .is_some_and(guard_replaces_direct_pollution_detection);
            if self.current_guard_proxy_unreachable() {
                current_failed = true;
                self.state = RuntimeState::Error("保护层端口失效".to_string());
            }
            if let Some(agent) = self.agent.as_mut() {
                agent.poll_monitor();
                if self.pending_continuation_trigger_prompt.is_none() {
                    self.pending_continuation_trigger_prompt =
                        agent.take_continuation_trigger_prompt();
                }
                let direct_polluted = agent.pollution_detected;
                if direct_polluted {
                    agent.pollution_detected = false;
                }
                if !agent.is_running() {
                    current_failed = true;
                } else if direct_polluted && !direct_pollution_replaced {
                    overrides.insert(current.clone(), ProbeResult::synthetic_polluted());
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
                        hold_current_on_no_alternative = true;
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
                        hold_current_on_no_alternative = true;
                    }
                } else if !auto_paused && agent.is_turn_stalled(self.config.turn_stall_seconds) {
                    overrides.insert(current.clone(), ProbeResult::synthetic_unavailable());
                    self.state = RuntimeState::Error("响应卡死".to_string());
                    if self.record_stall_failure(&current)
                        >= self.config.turn_stall_failure_threshold
                    {
                        current_failed = true;
                        skip_current = true;
                        hold_current_on_no_alternative = true;
                    }
                } else {
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
                                hold_current_on_no_alternative = !result.polluted;
                            }
                            overrides.insert(endpoint.name.clone(), result);
                        } else {
                            self.mark_probe_started(&endpoint);
                            let result = probe.probe_endpoint(&endpoint, &self.config).await;
                            current_failed = !result.available;
                            if current_failed {
                                skip_current = true;
                                hold_current_on_no_alternative = !result.polluted;
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
            // A terminal that has returned repeated endpoint errors should be released even when
            // it is the only configured endpoint. Keeping the stale session alive makes every
            // subsequent automatic prompt continue to hit the same broken connection.
            let keep_running_single_endpoint = hold_current_on_no_alternative
                && !self.endpoint_request_failure_threshold_reached(
                    self.current_endpoint.as_deref().unwrap_or_default(),
                );
            if keep_running_single_endpoint || (force_full_probe && !current_failed) {
                if let Some(endpoint) =
                    self.running_single_current_endpoint_without_cooldown(&availability)
                {
                    self.probing_endpoint = None;
                    self.counted_probe_inflight.clear();
                    let previous_state = self.state.clone();
                    self.maybe_drive_prompt(&endpoint);
                    if self.endpoint_request_failure_threshold_reached(&endpoint.name)
                        && matches!(previous_state, RuntimeState::Error(_))
                    {
                        self.state = previous_state;
                    }
                    self.record_agent_usage(&endpoint);
                    self.publish_snapshot_event();
                    return Some(endpoint);
                }
            }
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
        self.direct_endpoint_once = None;
        self.state = RuntimeState::Stopped;
        self.probing_endpoint = None;
        self.counted_probe_inflight.clear();
        self.publish_snapshot_event();
    }

    pub fn restart_agent(&mut self) {
        self.stop_agent();
        self.current_endpoint = None;
        self.direct_endpoint_once = None;
        self.force_current_probe_once = false;
        self.confirm_current_probe_once = false;
        self.force_full_probe_once = false;
        self.pending_initial_prompt = None;
        self.pending_goal_prompt = None;
        self.last_prompt_at = None;
        self.last_auto_prompt_signature = None;
        self.waiting_for_assistant_progress = false;
        self.goal_synced_this_run = false;
        self.goal_turn_active = false;
        self.goal_request_clear_failed_signature = None;
        self.trigger_now_clear_failed = false;
        self.manual_prompt_requeue_error = None;
        self.state = RuntimeState::WaitingAvailable;
        self.probing_endpoint = None;
        self.counted_probe_inflight.clear();
        self.publish_snapshot_event();
    }

    pub fn replace_config_snapshot(&mut self, config: AppConfig) {
        let valid_names = config
            .endpoints
            .iter()
            .map(|endpoint| endpoint.name.clone())
            .collect::<std::collections::HashSet<_>>();
        self.config = config;
        if self
            .current_endpoint
            .as_ref()
            .is_some_and(|name| !valid_names.contains(name))
        {
            self.current_endpoint = None;
            self.state = RuntimeState::WaitingAvailable;
        }
        if self
            .fixed_endpoint
            .as_ref()
            .is_some_and(|name| !valid_names.contains(name))
        {
            self.fixed_endpoint = None;
        }
        if self
            .force_probe_endpoint
            .as_ref()
            .is_some_and(|name| !valid_names.contains(name))
        {
            self.force_probe_endpoint = None;
        }
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

    fn goal_enabled(&self) -> bool {
        let Some(path) = self.config.config_path.as_ref() else {
            return false;
        };
        let state = read_control_state(path);
        goal_mode_enabled_runtime(&self.config, &state)
    }
    pub fn terminal_output(&self) -> String {
        self.agent
            .as_ref()
            .map(AgentProcess::terminal_output_text)
            .unwrap_or_default()
    }

    pub fn terminal_output_delta_from(&self, start: usize) -> (String, usize) {
        self.agent
            .as_ref()
            .map(|agent| agent.terminal_output_delta_from(start))
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
        let Some(agent) = &self.agent else {
            return Err("终端输入失败：终端未启动".to_string());
        };
        agent
            .write_user_input(text)
            .map_err(|err| format!("终端输入失败：{err}"))
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

    pub fn clear_terminal_local_view(&mut self) -> Result<(), String> {
        if let Some(agent) = &self.agent {
            agent
                .clear_terminal_local_view()
                .map_err(|err| format!("终端清屏失败：{err}"))?;
        }
        Ok(())
    }

    pub fn mark_terminal_command_failed(&mut self, error: String) {
        self.state = RuntimeState::Error(error);
        self.publish_snapshot_event();
    }

    pub fn mark_control_command_failed(&mut self, error: String) {
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
        self.direct_endpoint_once = None;
        self.fork_source_session_once = None;
        self.stop_agent();
        self.current_endpoint = None;
        self.pending_initial_prompt = None;
        self.pending_goal_prompt = None;
        self.last_prompt_at = None;
        self.last_auto_prompt_signature = None;
        self.waiting_for_assistant_progress = false;
        self.goal_synced_this_run = false;
        self.goal_request_clear_failed_signature = None;
        self.trigger_now_clear_failed = false;
        self.manual_prompt_requeue_error = None;
        self.state = RuntimeState::Stopped;
        self.probing_endpoint = None;
        self.counted_probe_inflight.clear();
        self.publish_snapshot_event();
    }

    pub fn force_start_endpoint_next_tick(&mut self, name: String) -> Result<(), String> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err("直接启动失败：接口名称为空".to_string());
        }
        if self.endpoint_by_name_including_disabled(&name).is_none() {
            return Err(format!("直接启动失败：未找到接口组：{name}"));
        }
        self.set_fixed_endpoint(Some(name.clone()));
        self.direct_endpoint_once = Some(name);
        self.publish_snapshot_event();
        Ok(())
    }

    pub fn fork_session_next_start(
        &mut self,
        source_session_id: String,
        source_session_path: Option<PathBuf>,
    ) -> Result<(), String> {
        if self.config.agent_driver == AgentDriver::Generic {
            return Err("Generic 配置不支持分叉会话".to_string());
        }
        if source_session_id.trim().is_empty() {
            return Err("无法分叉：源会话 ID 为空".to_string());
        }
        self.fork_source_session_once = Some((source_session_id, source_session_path));
        self.force_new_session_once = false;
        self.stop_agent();
        self.current_endpoint = None;
        self.pending_initial_prompt = None;
        self.pending_goal_prompt = None;
        self.last_prompt_at = None;
        self.last_auto_prompt_signature = None;
        self.waiting_for_assistant_progress = false;
        self.goal_synced_this_run = false;
        self.goal_request_clear_failed_signature = None;
        self.trigger_now_clear_failed = false;
        self.manual_prompt_requeue_error = None;
        self.state = RuntimeState::Stopped;
        self.probing_endpoint = None;
        self.counted_probe_inflight.clear();
        self.publish_snapshot_event();
        Ok(())
    }

    pub fn fork_codex_session_next_start(
        &mut self,
        source_session_id: String,
        source_session_path: Option<PathBuf>,
    ) -> Result<(), String> {
        if self.config.agent_driver != AgentDriver::Codex {
            return Err("只有 Codex 配置支持此兼容接口".to_string());
        }
        self.fork_session_next_start(source_session_id, source_session_path)
    }

    pub fn active_session(&self) -> Option<(String, Option<PathBuf>)> {
        self.agent.as_ref().and_then(AgentProcess::active_session)
    }

    pub fn active_codex_session(&self) -> Option<(String, Option<PathBuf>)> {
        if self.config.agent_driver != AgentDriver::Codex {
            return None;
        }
        self.active_session()
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

    pub fn set_event_wakeup(&mut self, event_wakeup: Option<RuntimeEventWakeup>) {
        self.event_wakeup = event_wakeup;
        if let Some(agent) = self.agent.as_ref() {
            agent.set_terminal_activity_wakeup(self.event_wakeup.clone());
        }
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
        let now = Instant::now();
        for (name, result) in &results {
            if let Some(endpoint) = self.endpoint_by_name(name).cloned() {
                self.remember_single_probe_result(&endpoint, result, now);
            } else {
                self.last_availability.insert(name.clone(), result.clone());
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
            match update_control_state(
                config_path,
                &[(
                    "fixed_endpoint",
                    serde_json::json!(self.fixed_endpoint.clone().unwrap_or_default()),
                )],
            ) {
                Ok(_) => self.clear_control_save_error(),
                Err(err) => self.set_control_save_error(format!("保存固定接口失败：{err}")),
            }
        } else {
            self.clear_control_save_error();
        }
        self.publish_snapshot_event();
    }

    pub fn set_force_probe_endpoint(&mut self, name: Option<String>) {
        self.force_probe_endpoint = name.filter(|value| !value.trim().is_empty());
        if let Some(config_path) = &self.config.config_path {
            match update_control_state(
                config_path,
                &[(
                    "force_probe_endpoint",
                    serde_json::json!(self.force_probe_endpoint.clone().unwrap_or_default()),
                )],
            ) {
                Ok(_) => self.clear_control_save_error(),
                Err(err) => self.set_control_save_error(format!("保存强制探测接口失败：{err}")),
            }
        } else {
            self.clear_control_save_error();
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
        self.guard_polluted_until.remove(name);
        self.guard_pollution_signal_by_endpoint.remove(name);
        self.pollution_recovery_successes_by_endpoint.remove(name);
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
            match update_control_state(
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
            ) {
                Ok(_) => self.clear_control_save_error(),
                Err(err) => self.set_control_save_error(format!("保存禁用接口状态失败：{err}")),
            }
        } else {
            self.clear_control_save_error();
        }
        self.publish_snapshot_event();
        true
    }

    fn set_control_save_error(&mut self, error: String) {
        self.control_save_error = Some(error);
    }

    fn clear_control_save_error(&mut self) {
        self.control_save_error = None;
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

        let replaces_direct_pollution = endpoint.guard_proxy.replace_direct_pollution_detection;
        endpoint.guard_proxy.enabled = enabled;
        if enabled && replaces_direct_pollution {
            self.clear_replaced_direct_pollution_cooldown(name);
        } else if !enabled {
            self.clear_guard_pollution_cooldown(name);
        }
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
            let endpoints = if current_failed {
                self.enabled_by_weight()
            } else {
                self.enabled_by_weight_preferring_current_tier()
            };
            return self
                .find_first_available(probe, endpoints, false, ProbeMode::Full, true)
                .await;
        }

        if let Some(fixed_name) = &self.fixed_endpoint {
            if let Some(endpoint) = self.endpoint_by_name(fixed_name).cloned() {
                if self.current_endpoint.as_deref() == Some(endpoint.name.as_str())
                    && !current_failed
                    && !self.pollution_cooldown_active(&endpoint.name, Instant::now())
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
        let already_checked = availability.keys().cloned().collect::<HashSet<_>>();
        let recovery = self
            .enabled_by_weight()
            .into_iter()
            .filter(|endpoint| endpoint.name != current)
            .filter(|endpoint| !already_checked.contains(&endpoint.name))
            .collect::<Vec<_>>();
        let recovery_availability = self
            .probe_due_unhealthy_endpoints(probe, recovery, ProbeMode::Full)
            .await;
        availability.extend(recovery_availability);
        (current_endpoint, availability)
    }

    async fn probe_due_unhealthy_endpoints(
        &mut self,
        probe: &HttpProbe,
        endpoints: Vec<EndpointConfig>,
        probe_mode: ProbeMode,
    ) -> HashMap<String, ProbeResult> {
        let mut availability = HashMap::new();
        let now = Instant::now();
        for endpoint in endpoints {
            if self.hard_cooldown_result(&endpoint, now).is_some() {
                continue;
            }
            if self.cooldown_result(&endpoint, now).is_some() {
                continue;
            }
            if self
                .next_probe_at
                .get(&endpoint.name)
                .is_some_and(|next| now < *next)
            {
                continue;
            }
            let should_probe = self
                .last_availability
                .get(&endpoint.name)
                .is_some_and(|cached| {
                    !cached.available
                        || cached.polluted
                        || cached.quota_limited
                        || cached.retry_after_seconds.is_some()
                });
            if !should_probe {
                continue;
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
            availability.insert(endpoint.name.clone(), cached_probe_result(result));
        }
        availability
    }

    async fn probe_due_background_recovery(
        &mut self,
        probe: &HttpProbe,
        current: &str,
        probe_mode: ProbeMode,
    ) -> HashMap<String, ProbeResult> {
        let endpoints = self
            .enabled_by_weight()
            .into_iter()
            .filter(|endpoint| endpoint.name != current)
            .collect::<Vec<_>>();
        self.probe_due_unhealthy_endpoints(probe, endpoints, probe_mode)
            .await
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
                    let selectable =
                        available && !self.pollution_cooldown_active(&endpoint.name, now);
                    availability.insert(endpoint.name.clone(), cached);
                    if selectable {
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
            let selectable = available && !self.pollution_cooldown_active(&endpoint.name, now);
            availability.insert(endpoint.name.clone(), cached_probe_result(result));
            if selectable {
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
        let recovering_pollution = self.pollution_cooldown_active(&endpoint.name, Instant::now());
        match probe_mode {
            ProbeMode::Full => probe.probe_endpoint(endpoint, &self.config).await,
            ProbeMode::ModelsOnly if recovering_pollution => {
                probe.probe_endpoint(endpoint, &self.config).await
            }
            ProbeMode::ModelsOnly => {
                let result = probe.probe_models_endpoint(endpoint).await;
                if result.available || result.status_code != Some(200) {
                    result
                } else {
                    probe.probe_endpoint(endpoint, &self.config).await
                }
            }
            ProbeMode::Upgrade if recovering_pollution => {
                probe.probe_endpoint(endpoint, &self.config).await
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
        let fork_source = self.fork_source_session_once.clone();
        let mut launch_endpoint = endpoint.clone();
        if endpoint.guard_proxy.enabled {
            let guard = start_guard_proxy_with_stable_port(&self.config, &endpoint)?;
            launch_endpoint.base_url = guard.local_base_url().map_err(|err| err.to_string())?;
            self.guard_pollution_signal_by_endpoint
                .remove(&endpoint.name);
            self.guard_proxy = Some(guard);
        }
        let mut agent = if let Some((source_session_id, source_session_path)) = &fork_source {
            AgentProcess::new_fork(
                self.config.clone(),
                launch_endpoint.clone(),
                source_session_id.clone(),
                source_session_path.clone(),
            )
        } else {
            AgentProcess::new(
                self.config.clone(),
                launch_endpoint.clone(),
                force_new_session,
            )
        };
        if let Err(err) = agent.start() {
            if let Some(mut guard) = self.guard_proxy.take() {
                self.guard_audit_by_endpoint
                    .insert(guard.endpoint_name().to_string(), guard.audit_snapshot());
                guard.stop();
            }
            return Err(err.to_string());
        }
        self.fork_source_session_once = None;
        let now = Instant::now();
        self.current_endpoint = Some(endpoint.name.clone());
        self.started_at_by_endpoint
            .insert(endpoint.name.clone(), now);
        self.pending_goal_prompt = (!fork_source.is_some())
            .then(|| {
                agent
                    .launch
                    .as_ref()
                    .and_then(|launch| self.goal_prompt_for_new_session(launch.resumed))
            })
            .flatten();
        self.pending_initial_prompt = if self.pending_goal_prompt.is_some() {
            None
        } else {
            agent
                .launch
                .as_ref()
                .filter(|launch| !launch.resumed)
                .map(|_| endpoint.initial_prompt.clone())
        };
        self.last_prompt_at = None;
        self.last_auto_prompt_signature = None;
        self.waiting_for_assistant_progress = false;
        self.goal_synced_this_run = false;
        self.goal_request_clear_failed_signature = None;
        self.trigger_now_clear_failed = false;
        self.manual_prompt_requeue_error = None;
        self.state = RuntimeState::Running;
        agent.set_terminal_activity_wakeup(self.event_wakeup.clone());
        self.agent = Some(agent);
        self.publish_snapshot_event();
        Ok(())
    }

    fn goal_prompt_for_new_session(&self, resumed: bool) -> Option<String> {
        if self.config.agent_driver != AgentDriver::Codex
            || !self.config.agent_goal.enabled
            || !self.goal_enabled()
        {
            return None;
        }
        let control_state = self
            .config
            .config_path
            .as_ref()
            .map(|path| read_control_state(path))
            .unwrap_or_else(|| serde_json::json!({}));
        if resumed {
            if should_resume_goal_runtime(&self.config, &control_state) {
                return Some("/goal resume".to_string());
            }
            return None;
        }
        if !self.config.agent_goal.sync_on_new_session {
            return None;
        }
        let text = self.config.agent_goal.text.trim();
        if text.is_empty() {
            return None;
        }
        Some(format!("/goal {text}"))
    }

    fn goal_prompt_for_active_session(&self, control_state: &Value) -> Option<String> {
        if self.config.agent_driver != AgentDriver::Codex
            || !self.config.agent_goal.enabled
            || !self.goal_enabled()
        {
            return None;
        }
        if let Some(prompt) = control_state_goal_prompt_for_config(&self.config, control_state) {
            return Some(prompt);
        }
        if should_resume_goal_runtime(&self.config, control_state) {
            return Some("/goal resume".to_string());
        }
        let text = self.config.agent_goal.text.trim();
        if text.is_empty() {
            return None;
        }
        Some(format!("/goal {text}"))
    }

    fn goal_fallback_prompt(&self) -> Option<String> {
        if !self.goal_synced_this_run
            || !self.config.agent_goal.enabled
            || !self.goal_enabled()
            || !self.config.agent_goal.fallback_enabled
            || self.config.agent_goal.text.trim().is_empty()
        {
            return None;
        }
        let prompt = self.config.agent_goal.fallback_prompt.trim();
        if prompt.is_empty() {
            return None;
        }
        Some(prompt.to_string())
    }

    fn maybe_drive_prompt(&mut self, endpoint: &EndpointConfig) {
        let mut session_assistant_confirmed = false;
        let mut input_block_reason = None;
        let can_send_prompt = {
            let Some(agent) = self.agent.as_mut() else {
                return;
            };
            if agent.needs_submit_retry(self.config.prompt_submit_retry_seconds) {
                if let Err(err) = agent.retry_submit() {
                    agent.mark_current_turn_failed();
                    self.waiting_for_assistant_progress = false;
                    self.state = RuntimeState::Error(format!("重试提交失败：{err}"));
                    self.publish_snapshot_event();
                    return;
                }
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
            let can_send = agent.can_send_prompt();
            if !can_send {
                input_block_reason = agent.auto_input_block_reason();
            }
            can_send
        };
        if session_assistant_confirmed {
            self.clear_endpoint_request_failures(&endpoint.name);
            self.clear_transient_failures(&endpoint.name);
            self.endpoint_auto_prompt_blocked_until
                .remove(&endpoint.name);
            if self.goal_turn_active {
                self.goal_turn_active = false;
                self.disable_goal_mode_after_completed_turn();
            }
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
        let goal_request_signature = control_state_goal_request_signature(&control_state);
        if self.goal_request_clear_failed_signature.as_deref() != goal_request_signature.as_deref()
        {
            self.goal_request_clear_failed_signature = None;
        }
        let auto_paused = control_state
            .get("auto_paused")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let goal_enabled = goal_mode_enabled_runtime(&self.config, &control_state);
        let goal_request_clear_failed =
            goal_request_signature.as_deref().is_some_and(|signature| {
                self.goal_request_clear_failed_signature.as_deref() == Some(signature)
            });
        let explicit_goal_prompt = (!goal_request_clear_failed)
            .then(|| control_state_goal_prompt_for_config(&self.config, &control_state))
            .flatten();
        let explicit_goal_request_signature = explicit_goal_prompt
            .is_some()
            .then(|| goal_request_signature.clone())
            .flatten();
        if goal_enabled
            && self.pending_goal_prompt.is_none()
            && (!self.goal_synced_this_run || explicit_goal_prompt.is_some())
        {
            let fallback_goal_prompt = if goal_request_clear_failed {
                self.goal_prompt_for_active_session(&control_state_without_goal_request(
                    &control_state,
                ))
            } else {
                self.goal_prompt_for_active_session(&control_state)
            };
            self.pending_goal_prompt = explicit_goal_prompt.or(fallback_goal_prompt);
            if self.pending_goal_prompt.is_some() {
                if let Some(signature) = explicit_goal_request_signature {
                    self.clear_goal_request_control_state(signature);
                }
            }
        }
        let manual_prompt = self
            .config
            .config_path
            .as_ref()
            .and_then(|path| pop_manual_prompt(path));
        let can_send_by_interval = self.last_prompt_at.is_none_or(|at| {
            at.elapsed() >= Duration::from_secs_f64(self.config.min_prompt_interval_seconds)
        });
        let automatic_requested = trigger_now_requested
            || (goal_enabled && self.pending_goal_prompt.is_some())
            || (!auto_paused
                && (self.pending_continuation_trigger_prompt.is_some()
                    || self.pending_initial_prompt.is_some()
                    || can_send_by_interval));
        if !can_send_prompt {
            if let Some(prompt) = manual_prompt.as_ref() {
                self.requeue_manual_prompt(prompt);
            }
            if automatic_requested || manual_prompt.is_some() {
                let reason = input_block_reason.unwrap_or("终端未就绪");
                self.state = RuntimeState::WaitingInput(reason.to_string());
            }
            self.publish_snapshot_event();
            return;
        }
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
        let mut restore_goal_prompt = false;
        let mut restore_continuation_trigger_prompt = false;
        let mut restore_initial_prompt = false;
        let (prompt, is_goal_command) = if let Some(prompt) = manual_prompt {
            (prompt, false)
        } else if let Some(prompt) = self.pending_goal_prompt.take() {
            restore_goal_prompt = true;
            (prompt, true)
        } else if let Some(prompt) = self.pending_continuation_trigger_prompt.take() {
            restore_continuation_trigger_prompt = true;
            (prompt, false)
        } else if let Some(prompt) = self.pending_initial_prompt.take() {
            restore_initial_prompt = true;
            (prompt, false)
        } else if let Some(prompt) = self.goal_fallback_prompt() {
            (prompt, false)
        } else {
            (self.latest_auto_prompt(endpoint), false)
        };
        if prompt.trim().is_empty() {
            self.publish_snapshot_event();
            return;
        }
        let Some(agent) = self.agent.as_mut() else {
            if is_manual {
                self.requeue_manual_prompt(&prompt);
            } else if restore_goal_prompt {
                self.pending_goal_prompt = Some(prompt);
            } else if restore_continuation_trigger_prompt {
                self.pending_continuation_trigger_prompt = Some(prompt);
            } else if restore_initial_prompt {
                self.pending_initial_prompt = Some(prompt);
            }
            return;
        };
        let send_result = agent.send_prompt(&prompt);
        if send_result.is_ok() {
            self.last_prompt_at = Some(Instant::now());
            if !is_goal_command {
                self.last_auto_prompt_signature = Some((endpoint.name.clone(), prompt));
            }
            if is_goal_command {
                self.goal_turn_active = true;
                self.goal_synced_this_run = true;
                self.mark_goal_synced();
            }
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
            if is_manual {
                self.manual_prompt_requeue_error = None;
            }
        } else {
            let error = send_result
                .err()
                .map(|err| format!("提示词发送失败：{err}"))
                .unwrap_or_else(|| "提示词发送失败".to_string());
            self.waiting_for_assistant_progress = false;
            if is_manual {
                self.requeue_manual_prompt(&prompt);
            } else if restore_goal_prompt {
                self.pending_goal_prompt = Some(prompt);
            } else if restore_continuation_trigger_prompt {
                self.pending_continuation_trigger_prompt = Some(prompt);
            } else if restore_initial_prompt {
                self.pending_initial_prompt = Some(prompt);
            }
            self.state = RuntimeState::Error(error);
        }
        self.publish_snapshot_event();
    }

    fn requeue_manual_prompt(&mut self, prompt: &str) -> bool {
        let previous_error = self.manual_prompt_requeue_error.clone();
        let result = if let Some(config_path) = &self.config.config_path {
            enqueue_manual_prompt(config_path, prompt)
                .map_err(|err| format!("恢复手动提示失败：{err}"))
        } else {
            Err("恢复手动提示失败：未设置配置路径".to_string())
        };
        match result {
            Ok(()) => self.manual_prompt_requeue_error = None,
            Err(err) => self.manual_prompt_requeue_error = Some(err),
        }
        if previous_error != self.manual_prompt_requeue_error {
            self.publish_snapshot_event();
        }
        self.manual_prompt_requeue_error.is_none()
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

    fn disable_goal_mode_after_completed_turn(&mut self) {
        self.update_goal_control_state(
            &[
                ("goal_enabled", serde_json::json!(false)),
                ("goal_completed", serde_json::json!(true)),
                (
                    "goal_completed_revision",
                    serde_json::json!(self.config.agent_goal.revision),
                ),
                (
                    "goal_completed_source_goal_signature",
                    serde_json::json!(self.config.agent_goal.source_goal_signature),
                ),
                ("goal_request", serde_json::Value::Null),
            ],
            "保存目标完成状态失败",
        );
    }

    fn mark_goal_synced(&mut self) {
        self.update_goal_control_state(
            &[
                (
                    "goal_synced_revision",
                    serde_json::json!(self.config.agent_goal.revision),
                ),
                (
                    "goal_synced_source_goal_signature",
                    serde_json::json!(self.config.agent_goal.source_goal_signature),
                ),
                (
                    "goal_synced_text",
                    serde_json::json!(self.config.agent_goal.text),
                ),
                (
                    "goal_synced_source",
                    serde_json::json!(self.config.agent_goal.source),
                ),
                ("goal_completed", serde_json::json!(false)),
                ("goal_request", serde_json::Value::Null),
            ],
            "保存目标同步状态失败",
        );
    }

    fn clear_goal_request_control_state(&mut self, signature: String) {
        if self.update_goal_control_state(
            &[("goal_request", serde_json::Value::Null)],
            "清理目标请求失败",
        ) {
            self.goal_request_clear_failed_signature = None;
        } else {
            self.goal_request_clear_failed_signature = Some(signature);
        }
    }

    fn update_goal_control_state(&mut self, updates: &[(&str, Value)], error_prefix: &str) -> bool {
        let Some(config_path) = &self.config.config_path else {
            self.clear_control_save_error();
            return true;
        };
        let previous_error = self.control_save_error.clone();
        match update_control_state(config_path, updates) {
            Ok(_) => {
                self.clear_control_save_error();
                if previous_error != self.control_save_error {
                    self.publish_snapshot_event();
                }
                true
            }
            Err(err) => {
                self.set_control_save_error(format!("{error_prefix}：{err}"));
                if previous_error != self.control_save_error {
                    self.publish_snapshot_event();
                }
                false
            }
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

    fn record_current_guard_pollution_signal(
        &mut self,
        endpoint_name: &str,
        overrides: &mut HashMap<String, ProbeResult>,
    ) -> bool {
        let Some(endpoint) = self.endpoint_by_name(endpoint_name).cloned() else {
            return false;
        };
        let Some(audit) = self
            .guard_proxy
            .as_ref()
            .filter(|guard| guard.endpoint_name() == endpoint.name)
            .map(|guard| guard.audit_snapshot())
        else {
            return false;
        };
        let previous_signal = self
            .guard_pollution_signal_by_endpoint
            .get(&endpoint.name)
            .copied();
        let Some((signal, error)) =
            guard_audit_endpoint_pollution_signal(&audit, &endpoint.guard_proxy, previous_signal)
        else {
            return false;
        };

        overrides.insert(
            endpoint.name.clone(),
            ProbeResult {
                available: false,
                polluted: true,
                request_made: false,
                error,
                ..Default::default()
            },
        );
        self.guard_pollution_signal_by_endpoint
            .insert(endpoint.name.clone(), signal);
        self.mark_endpoint_guard_polluted(&endpoint.name);
        true
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

    fn endpoint_by_name_including_disabled(&self, name: &str) -> Option<&EndpointConfig> {
        self.config
            .endpoints
            .iter()
            .find(|endpoint| endpoint.name == name)
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

    fn enabled_by_weight_preferring_current_tier(&self) -> Vec<EndpointConfig> {
        let current = self.current_endpoint.as_deref();
        let mut endpoints = self.enabled_by_weight();
        endpoints.sort_by_key(|endpoint| {
            (
                std::cmp::Reverse(endpoint.weight),
                current != Some(endpoint.name.as_str()),
            )
        });
        endpoints
    }

    fn running_single_current_endpoint_without_cooldown(
        &self,
        availability: &HashMap<String, ProbeResult>,
    ) -> Option<EndpointConfig> {
        let current = self.current_endpoint.as_deref()?;
        let endpoint = self.endpoint_by_name(current)?.clone();
        if self.enabled_by_weight().len() != 1 {
            return None;
        }
        if availability
            .get(current)
            .is_some_and(|result| result.polluted)
        {
            return None;
        }
        if self.pollution_cooldown_active(&endpoint.name, Instant::now()) {
            return None;
        }
        if !self.agent.as_ref().is_some_and(AgentProcess::is_running) {
            return None;
        }
        Some(endpoint)
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
            self.clear_transient_failures(&endpoint.name);
            self.endpoint_auto_prompt_blocked_until
                .remove(&endpoint.name);
            self.record_pollution_recovery_success(&endpoint.name, now);
        } else if result.request_made && !result.available {
            self.pollution_recovery_successes_by_endpoint
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
        let recovering_pollution = self.pollution_cooldown_active(&endpoint.name, now);
        let next = if let Some(seconds) = result.retry_after_seconds {
            now + Duration::from_secs(seconds)
        } else if result.polluted || (result.available && recovering_pollution) {
            now + Duration::from_secs_f64(self.config.probe_interval_seconds)
        } else if result.quota_limited {
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

    fn record_pollution_recovery_success(&mut self, endpoint_name: &str, now: Instant) {
        if !self.pollution_cooldown_active(endpoint_name, now) {
            self.clear_pollution_recovery(endpoint_name);
            return;
        }
        let threshold = self.pollution_recovery_threshold();
        let successes = self
            .pollution_recovery_successes_by_endpoint
            .entry(endpoint_name.to_string())
            .or_default();
        *successes += 1;
        if *successes >= threshold {
            self.clear_pollution_recovery(endpoint_name);
        }
    }

    fn pollution_recovery_threshold(&self) -> u32 {
        self.config.endpoint_recovery_threshold.max(3)
    }

    fn pollution_cooldown_active(&self, endpoint_name: &str, now: Instant) -> bool {
        self.polluted_until
            .get(endpoint_name)
            .is_some_and(|until| now < *until)
            || self
                .guard_polluted_until
                .get(endpoint_name)
                .is_some_and(|until| now < *until)
    }

    fn pollution_recovery_probe_due(&self, endpoint_name: &str, now: Instant) -> bool {
        self.next_probe_at
            .get(endpoint_name)
            .is_none_or(|next| now >= *next)
    }

    fn clear_pollution_recovery(&mut self, endpoint_name: &str) {
        self.polluted_until.remove(endpoint_name);
        self.guard_polluted_until.remove(endpoint_name);
        self.pollution_recovery_successes_by_endpoint
            .remove(endpoint_name);
    }

    fn cooldown_result(&mut self, endpoint: &EndpointConfig, now: Instant) -> Option<ProbeResult> {
        if let Some(until) = self.startup_failed_until.get(&endpoint.name).copied() {
            if now < until {
                return Some(self.synthetic_startup_failure_result(&endpoint.name));
            }
            self.startup_failed_until.remove(&endpoint.name);
            self.startup_failure_error.remove(&endpoint.name);
        }
        if let Some(until) = self.guard_polluted_until.get(&endpoint.name).copied() {
            if now < until {
                if self.pollution_recovery_probe_due(&endpoint.name, now) {
                    return None;
                }
                return Some(ProbeResult::synthetic_polluted());
            }
            self.guard_polluted_until.remove(&endpoint.name);
        }
        if guard_replaces_direct_pollution_detection(endpoint) {
            self.clear_replaced_direct_pollution_cooldown(&endpoint.name);
        }
        if let Some(until) = self.polluted_until.get(&endpoint.name).copied() {
            if now < until {
                if self.pollution_recovery_probe_due(&endpoint.name, now) {
                    return None;
                }
                return Some(ProbeResult::synthetic_polluted());
            }
            self.polluted_until.remove(&endpoint.name);
            self.pollution_recovery_successes_by_endpoint
                .remove(&endpoint.name);
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
        if let Some(cached) = self.last_availability.get(&endpoint.name) {
            if cached.retry_after_seconds.is_some()
                && self
                    .next_probe_at
                    .get(&endpoint.name)
                    .is_some_and(|next| now < *next)
            {
                return Some(cached_probe_result(cached.clone()));
            }
        }
        if self
            .guard_polluted_until
            .get(&endpoint.name)
            .is_some_and(|until| now < *until)
        {
            if self.pollution_recovery_probe_due(&endpoint.name, now) {
                return None;
            }
            return Some(ProbeResult::synthetic_polluted());
        }
        if self
            .polluted_until
            .get(&endpoint.name)
            .is_some_and(|until| now < *until)
        {
            if self.pollution_recovery_probe_due(&endpoint.name, now) {
                return None;
            }
            return Some(ProbeResult::synthetic_polluted());
        }
        None
    }

    fn mark_endpoint_polluted(&mut self, endpoint_name: &str) {
        let now = Instant::now();
        self.polluted_until.insert(
            endpoint_name.to_string(),
            now + Duration::from_secs_f64(self.config.polluted_endpoint_cooldown_seconds),
        );
        self.pollution_recovery_successes_by_endpoint
            .insert(endpoint_name.to_string(), 0);
        self.schedule_pollution_recovery_probe(endpoint_name, now);
    }

    fn mark_endpoint_guard_polluted(&mut self, endpoint_name: &str) {
        let now = Instant::now();
        let until =
            now + Duration::from_secs_f64(self.guard_polluted_cooldown_seconds(endpoint_name));
        self.polluted_until.insert(endpoint_name.to_string(), until);
        self.guard_polluted_until
            .insert(endpoint_name.to_string(), until);
        self.pollution_recovery_successes_by_endpoint
            .insert(endpoint_name.to_string(), 0);
        self.schedule_pollution_recovery_probe(endpoint_name, now);
    }

    fn schedule_pollution_recovery_probe(&mut self, endpoint_name: &str, now: Instant) {
        let next_due = now + Duration::from_secs_f64(self.config.probe_interval_seconds);
        self.next_probe_at
            .entry(endpoint_name.to_string())
            .and_modify(|current| {
                if *current > next_due {
                    *current = next_due;
                }
            })
            .or_insert(next_due);
    }

    fn guard_polluted_cooldown_seconds(&self, endpoint_name: &str) -> f64 {
        self.endpoint_by_name(endpoint_name)
            .map(|endpoint| endpoint.guard_proxy.polluted_cooldown_seconds)
            .unwrap_or(self.config.polluted_endpoint_cooldown_seconds)
    }

    fn clear_guard_pollution_cooldown(&mut self, endpoint_name: &str) {
        self.guard_pollution_signal_by_endpoint
            .remove(endpoint_name);
        if self.guard_polluted_until.remove(endpoint_name).is_none() {
            return;
        }
        self.polluted_until.remove(endpoint_name);
        self.pollution_recovery_successes_by_endpoint
            .remove(endpoint_name);
        self.next_probe_at.remove(endpoint_name);
        self.last_availability
            .insert(endpoint_name.to_string(), ProbeResult::cached_available());
        self.health.reset(endpoint_name);
        self.health.update(
            &self.config.endpoints,
            &HashMap::from([(endpoint_name.to_string(), ProbeResult::cached_available())]),
        );
    }

    fn clear_replaced_direct_pollution_cooldown(&mut self, endpoint_name: &str) {
        if self.guard_polluted_until.contains_key(endpoint_name) {
            return;
        }
        let direct_polluted = self.polluted_until.remove(endpoint_name).is_some()
            || self
                .last_availability
                .get(endpoint_name)
                .is_some_and(|result| result.polluted);
        if !direct_polluted {
            return;
        }
        self.next_probe_at.remove(endpoint_name);
        self.pollution_recovery_successes_by_endpoint
            .remove(endpoint_name);
        self.last_availability
            .insert(endpoint_name.to_string(), ProbeResult::cached_available());
        self.health.reset(endpoint_name);
        self.health.update(
            &self.config.endpoints,
            &HashMap::from([(endpoint_name.to_string(), ProbeResult::cached_available())]),
        );
    }

    fn select_from_effective(&self, effective: &HashMap<String, bool>) -> Option<&EndpointConfig> {
        let now = Instant::now();
        if let Some(fixed_name) = &self.fixed_endpoint {
            return self.config.endpoints.iter().find(|endpoint| {
                endpoint.enabled
                    && endpoint.name == *fixed_name
                    && effective.get(&endpoint.name).copied().unwrap_or(false)
                    && !self.pollution_cooldown_active(&endpoint.name, now)
            });
        }
        self.config
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.enabled && effective.get(&endpoint.name).copied().unwrap_or(false)
            })
            .filter(|endpoint| !self.pollution_cooldown_active(&endpoint.name, now))
            .max_by_key(|endpoint| endpoint.weight)
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
                    .map(|error| format!(" 错误{}", guard_upstream_error_display(error)))
                    .unwrap_or_default();
                let filtered_preview = audit
                    .last_filtered_response_preview
                    .as_deref()
                    .filter(|preview| !preview.trim().is_empty())
                    .map(|preview| {
                        format!(" 预览{}", guard_filtered_response_preview_display(preview))
                    })
                    .unwrap_or_default();
                format!(
                    " | 保护 请求{} 命中{} 污染{} 高危替换{} 连续高危{} 过滤{} 脱敏{}",
                    audit.requests,
                    guard_keyword_hit_count(audit),
                    audit.pollution_failures,
                    audit.high_risk_replacements,
                    audit.consecutive_high_risk,
                    audit.filtered_responses,
                    audit.redactions
                ) + &upstream
                    + &error
                    + &filtered_preview
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
        if let Some(status) = self.pollution_recovery_status_label(&endpoint.name, now) {
            return format!("{status}{guard_suffix}");
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
                .map(|error| format!(": {}", guard_upstream_error_display(error)))
                .unwrap_or_default();
            return format!("不可用: HTTP {status}{error}{guard_suffix}");
        }
        if let Some(error) = guard_audit.as_ref().and_then(guard_upstream_failure_error) {
            return format!(
                "不可用: {}{guard_suffix}",
                guard_upstream_error_display(error)
            );
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

    fn pollution_recovery_status_label(&self, endpoint_name: &str, now: Instant) -> Option<String> {
        if !self.pollution_cooldown_active(endpoint_name, now) {
            return None;
        }
        let successes = self
            .pollution_recovery_successes_by_endpoint
            .get(endpoint_name)
            .copied()
            .unwrap_or_default();
        if successes == 0 {
            return Some("污染不可用".to_string());
        }
        Some(format!(
            "污染恢复中 {}/{}",
            successes,
            self.pollution_recovery_threshold()
        ))
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

    fn endpoint_request_failure_threshold_reached(&self, endpoint_name: &str) -> bool {
        self.endpoint_request_failures_by_endpoint
            .get(endpoint_name)
            .copied()
            .unwrap_or_default()
            >= self.config.endpoint_failure_threshold.max(1)
    }

    fn endpoint_request_failure_state_text(&self, endpoint_name: &str) -> String {
        let failures = self
            .endpoint_request_failures_by_endpoint
            .get(endpoint_name)
            .copied()
            .unwrap_or_default();
        format!(
            "请求失败 {}/{}",
            failures,
            self.config.endpoint_failure_threshold.max(1)
        )
    }

    fn clear_endpoint_request_failures_on_session_success(&mut self, endpoint_name: &str) -> bool {
        let Some(endpoint) = self.endpoint_by_name(endpoint_name).cloned() else {
            return false;
        };
        let Some(agent) = self.agent.as_mut() else {
            return false;
        };
        let _ = agent.capture_session_id(&endpoint.workdir);
        if !agent.has_session_assistant_message_since_prompt() {
            return false;
        }
        self.clear_endpoint_request_failures(endpoint_name);
        self.endpoint_auto_prompt_blocked_until
            .remove(endpoint_name);
        true
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

    fn clear_transient_failures(&mut self, endpoint_name: &str) {
        self.transient_failures_by_endpoint.remove(endpoint_name);
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
            RuntimeState::WaitingInput(reason) => format!("等待可输入：{reason}"),
            RuntimeState::Error(error) => format!("异常：{error}"),
        };
        let mut label = base;
        if let Some(error) = self.control_save_error.as_deref() {
            if !error.trim().is_empty() {
                label.push_str(" | ");
                label.push_str(error);
            }
        }
        if let Some(error) = self.usage_save_error.as_deref() {
            if !error.trim().is_empty() {
                label.push_str(" | ");
                label.push_str(error);
            }
        }
        if let Some(error) = self.manual_prompt_requeue_error.as_deref() {
            if !error.trim().is_empty() {
                label.push_str(" | ");
                label.push_str(error);
            }
        }
        label
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
            if tx.send(RuntimeEvent::Snapshot(snapshot)).is_ok() {
                if let Some(wakeup) = &self.event_wakeup {
                    wakeup();
                }
            }
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

fn guard_upstream_failure_error(audit: &GuardAuditSnapshot) -> Option<&str> {
    if audit.upstream_failures == 0 {
        return None;
    }
    audit
        .last_upstream_error
        .as_deref()
        .filter(|error| !error.trim().is_empty())
}

fn guard_keyword_hit_count(audit: &GuardAuditSnapshot) -> u64 {
    audit.keyword_hits.values().copied().sum()
}

fn guard_replaces_direct_pollution_detection(endpoint: &EndpointConfig) -> bool {
    endpoint.guard_proxy.enabled && endpoint.guard_proxy.replace_direct_pollution_detection
}

fn guard_audit_endpoint_pollution_signal(
    audit: &GuardAuditSnapshot,
    config: &crate::config::GuardProxyConfig,
    previous: Option<GuardPollutionSignal>,
) -> Option<(GuardPollutionSignal, String)> {
    let current = GuardPollutionSignal {
        pollution_failures: audit.pollution_failures,
        high_risk_replacements: audit.high_risk_replacements,
    };
    let previous = previous.unwrap_or_default();
    if current.pollution_failures > previous.pollution_failures {
        return Some((current, "保护层污染响应".to_string()));
    }
    let threshold = config.high_risk_failure_threshold.max(1);
    if audit.consecutive_high_risk >= threshold
        && current.high_risk_replacements > previous.high_risk_replacements
    {
        return Some((
            current,
            format!(
                "保护层连续高危 {}/{}",
                audit.consecutive_high_risk, threshold
            ),
        ));
    }
    None
}

fn guard_filtered_response_preview_display(preview: &str) -> String {
    let clean = preview.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.chars().count() <= 80 {
        return clean;
    }
    let mut out = clean.chars().take(79).collect::<String>();
    out.push('…');
    out
}

fn guard_upstream_error_display(error: &str) -> String {
    let trimmed = error.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("stream upstream closed before response.completed") {
        return "上游流提前断开，未收到 response.completed".to_string();
    }
    if lower.contains("stream upstream interrupted after partial response")
        || lower.contains("stream upstream interrupted before completion")
    {
        return "上游流中断，响应未完整结束".to_string();
    }
    if lower.contains("invalid_encrypted_content") || lower.contains("encrypted content") {
        return "会话加密内容失效，需新会话或去除 encrypted_content 重试".to_string();
    }
    trimmed.to_string()
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

fn completed_imported_goal_matches_runtime(config: &AppConfig, state: &Value) -> bool {
    if !state
        .get("goal_completed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    let completed_revision = state
        .get("goal_completed_revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if completed_revision != 0 && completed_revision == config.agent_goal.revision {
        return true;
    }
    let completed_signature = state
        .get("goal_completed_source_goal_signature")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    !completed_signature.is_empty()
        && completed_signature == config.agent_goal.source_goal_signature.trim()
}

fn should_resume_goal_runtime(config: &AppConfig, state: &Value) -> bool {
    if !goal_config_ready_runtime(config) {
        return false;
    }
    if completed_imported_goal_matches_runtime(config, state) {
        return false;
    }
    if synced_goal_matches_current_runtime(config, state) {
        return true;
    }
    config.agent_goal.sync_on_resume
        && config.agent_goal.source == "session_import"
        && !config.agent_goal.source_goal_signature.trim().is_empty()
}

fn synced_goal_matches_current_runtime(config: &AppConfig, state: &Value) -> bool {
    let synced_revision = state
        .get("goal_synced_revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if config.agent_goal.revision != 0 && synced_revision == config.agent_goal.revision {
        return true;
    }
    let synced_signature = state
        .get("goal_synced_source_goal_signature")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if !synced_signature.is_empty()
        && synced_signature == config.agent_goal.source_goal_signature.trim()
    {
        return true;
    }
    let synced_text = state
        .get("goal_synced_text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    !synced_text.is_empty() && synced_text == config.agent_goal.text.trim()
}

fn goal_config_ready_runtime(config: &AppConfig) -> bool {
    config.agent_goal.enabled && !config.agent_goal.text.trim().is_empty()
}

fn goal_mode_enabled_runtime(config: &AppConfig, state: &Value) -> bool {
    goal_config_ready_runtime(config)
        && state
            .get("goal_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn control_state_goal_prompt_for_config(config: &AppConfig, state: &Value) -> Option<String> {
    if !goal_config_ready_runtime(config) {
        return None;
    }
    control_state_goal_prompt(state)
}

fn control_state_without_goal_request(state: &Value) -> Value {
    let mut state = state.clone();
    if let Some(map) = state.as_object_mut() {
        map.remove("goal_request");
    }
    state
}

fn control_state_goal_request_signature(state: &Value) -> Option<String> {
    state
        .get("goal_request")
        .filter(|request| !request.is_null())
        .map(|request| serde_json::to_string(request).unwrap_or_else(|_| request.to_string()))
}

fn control_state_goal_prompt(state: &Value) -> Option<String> {
    let request = state.get("goal_request")?;
    let action = request
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("set")
        .trim();
    if action == "resume" {
        return Some("/goal resume".to_string());
    }
    let goal = request
        .get("text")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())?;
    Some(format!("/goal {goal}"))
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
    use std::path::{Path, PathBuf};

    fn block_control_state_path(config_path: &Path) -> PathBuf {
        let control_path = crate::control::control_state_path(config_path);
        unblock_control_state_path(&control_path);
        std::fs::create_dir_all(&control_path).unwrap();
        control_path
    }

    fn unblock_control_state_path(path: &Path) {
        if path.is_dir() {
            std::fs::remove_dir_all(path).unwrap();
        } else if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }

    fn read_test_http_request(socket: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            match socket.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => {
                    request.extend_from_slice(&buffer[..size]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n")
                        || request.len() >= 8192
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    fn start_test_json_upstream(body: &'static str) -> (u16, std::thread::JoinHandle<()>) {
        use std::io::Write;
        use std::net::TcpListener;
        use std::thread;

        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let _ = read_test_http_request(&mut socket);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).unwrap();
        });
        (port, handle)
    }

    fn send_test_guard_chat_request(port: u16) -> String {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let body = r#"{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}"#;
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    fn attach_test_guard_proxy(runtime: &mut RuntimeCore, endpoint: &EndpointConfig) -> u16 {
        let mut guard = GuardProxyServer::new(endpoint.clone());
        guard.start().unwrap();
        let base_url = guard.local_base_url().unwrap();
        let port = url::Url::parse(&base_url).unwrap().port().unwrap();
        runtime.guard_proxy = Some(guard);
        port
    }

    fn endpoint(name: &str, weight: i64) -> EndpointConfig {
        EndpointConfig {
            name: name.to_string(),
            base_url: format!("https://{name}.example.test/v1"),
            api_key: "key".to_string(),
            model: "gpt-5.5".to_string(),
            probe_model: None,
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
            continuation_mode: crate::config::ContinuationMode::Auto,
            agent_goal: Default::default(),
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
            codex_model_context_window: None,
            codex_provider_model_limits: Default::default(),
            probe_expected_text: "WATCHAPI_OK".to_string(),
            probe_path: "/v1/responses".to_string(),
            polluted_response_keywords: vec![],
            polluted_response_threshold: 0.35,
            polluted_context_window: 12,
            polluted_check_max_chars: 300,
            completion_pause_keywords: vec![],
            continuation_trigger_rules: vec![],
        }
    }

    fn long_running_test_command() -> crate::config::AgentCommand {
        if cfg!(windows) {
            crate::config::AgentCommand::Args(vec![
                "cmd.exe".to_string(),
                "/d".to_string(),
                "/c".to_string(),
                "ping -n 30 127.0.0.1 >nul".to_string(),
            ])
        } else {
            crate::config::AgentCommand::Args(vec![
                "sh".to_string(),
                "-c".to_string(),
                "sleep 30".to_string(),
            ])
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
    fn disabling_guard_proxy_clears_guard_polluted_cooldown() {
        let mut cfg = config();
        cfg.endpoint_recovery_threshold = 2;
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[0].guard_proxy.polluted_cooldown_seconds = 120.0;
        let mut runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();
        runtime.remember_single_probe_result(
            &endpoint,
            &ProbeResult::synthetic_polluted(),
            Instant::now(),
        );
        runtime.mark_endpoint_guard_polluted(&endpoint.name);
        runtime.health.update(
            &runtime.config.endpoints,
            &HashMap::from([(endpoint.name.clone(), ProbeResult::synthetic_polluted())]),
        );

        assert!(runtime.cooldown_result(&endpoint, Instant::now()).is_some());
        assert_eq!(runtime.rows()[0].request_status, "污染不可用");

        assert!(runtime.set_endpoint_guard_proxy_enabled(&endpoint.name, false));

        assert!(!runtime.guard_polluted_until.contains_key(&endpoint.name));
        assert!(!runtime.polluted_until.contains_key(&endpoint.name));
        assert!(!runtime.next_probe_at.contains_key(&endpoint.name));
        assert!(runtime.cooldown_result(&endpoint, Instant::now()).is_none());
        assert_eq!(runtime.rows()[0].request_status, "正常");
    }

    #[test]
    fn enabling_guard_replacement_clears_direct_polluted_cooldown() {
        let mut cfg = config();
        cfg.endpoint_recovery_threshold = 2;
        cfg.endpoints[0].guard_proxy.enabled = false;
        cfg.endpoints[0]
            .guard_proxy
            .replace_direct_pollution_detection = true;
        let mut runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();
        runtime.remember_single_probe_result(
            &endpoint,
            &ProbeResult::synthetic_polluted(),
            Instant::now(),
        );
        runtime.mark_endpoint_polluted(&endpoint.name);
        runtime.health.update(
            &runtime.config.endpoints,
            &HashMap::from([(endpoint.name.clone(), ProbeResult::synthetic_polluted())]),
        );

        assert!(runtime.cooldown_result(&endpoint, Instant::now()).is_some());
        assert_eq!(runtime.rows()[0].request_status, "污染不可用");

        assert!(runtime.set_endpoint_guard_proxy_enabled(&endpoint.name, true));

        assert!(!runtime.polluted_until.contains_key(&endpoint.name));
        assert!(!runtime.next_probe_at.contains_key(&endpoint.name));
        assert!(runtime.cooldown_result(&endpoint, Instant::now()).is_none());
        assert_eq!(runtime.rows()[0].request_status, "正常");
    }

    #[test]
    fn enabling_guard_fallback_keeps_direct_polluted_cooldown() {
        let mut cfg = config();
        cfg.endpoints[0].guard_proxy.enabled = false;
        cfg.endpoints[0]
            .guard_proxy
            .replace_direct_pollution_detection = false;
        let mut runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();
        runtime.remember_single_probe_result(
            &endpoint,
            &ProbeResult::synthetic_polluted(),
            Instant::now(),
        );
        runtime.mark_endpoint_polluted(&endpoint.name);

        assert!(runtime.set_endpoint_guard_proxy_enabled(&endpoint.name, true));

        assert!(runtime.polluted_until.contains_key(&endpoint.name));
        assert!(runtime.cooldown_result(&endpoint, Instant::now()).is_some());
    }

    #[test]
    fn guard_replacement_cooldown_result_clears_stale_direct_pollution() {
        let mut cfg = config();
        cfg.endpoint_recovery_threshold = 2;
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[0]
            .guard_proxy
            .replace_direct_pollution_detection = true;
        let mut runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();
        runtime.remember_single_probe_result(
            &endpoint,
            &ProbeResult::synthetic_polluted(),
            Instant::now(),
        );
        runtime.mark_endpoint_polluted(&endpoint.name);
        runtime.health.update(
            &runtime.config.endpoints,
            &HashMap::from([(endpoint.name.clone(), ProbeResult::synthetic_polluted())]),
        );

        assert!(runtime.polluted_until.contains_key(&endpoint.name));
        assert_eq!(runtime.rows()[0].request_status, "污染不可用");

        assert!(runtime.cooldown_result(&endpoint, Instant::now()).is_none());

        assert!(!runtime.polluted_until.contains_key(&endpoint.name));
        assert!(!runtime.next_probe_at.contains_key(&endpoint.name));
        assert!(runtime.last_availability[&endpoint.name].available);
        assert_eq!(runtime.rows()[0].request_status, "正常");
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
    fn rows_expose_guard_proxy_keyword_hit_count_separately_from_failures() {
        let mut runtime = RuntimeCore::new(config());
        runtime.guard_audit_by_endpoint.insert(
            "high".to_string(),
            GuardAuditSnapshot {
                requests: 2,
                pollution_failures: 0,
                filtered_responses: 1,
                keyword_hits: HashMap::from([("余额不足".to_string(), 2), ("公益".to_string(), 1)]),
                ..Default::default()
            },
        );

        let rows = runtime.rows();
        let status = &rows[0].request_status;

        assert!(status.contains("命中3"), "{status}");
        assert!(status.contains("污染0"), "{status}");
        assert!(status.contains("过滤1"), "{status}");
    }

    #[test]
    fn rows_expose_guard_proxy_filtered_response_preview_compactly() {
        let mut runtime = RuntimeCore::new(config());
        runtime.guard_audit_by_endpoint.insert(
            "high".to_string(),
            GuardAuditSnapshot {
                requests: 2,
                filtered_responses: 1,
                last_filtered_response_preview: Some(format!(
                    "处理后响应 {}",
                    "safe text ".repeat(20)
                )),
                ..Default::default()
            },
        );

        let rows = runtime.rows();
        let status = &rows[0].request_status;

        assert!(status.contains("过滤1"), "{status}");
        assert!(status.contains("预览处理后响应"), "{status}");
        assert!(status.contains('…'), "{status}");
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
    fn guard_proxy_stream_interruption_without_status_is_not_reported_as_healthy() {
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
                requests: 3,
                upstream_failures: 1,
                last_upstream_status: None,
                last_upstream_error: Some(
                    "stream upstream closed before response.completed".to_string(),
                ),
                last_upstream_attempts: 1,
                ..Default::default()
            },
        );

        let status = runtime.rows()[0].request_status.clone();

        assert!(status.starts_with("不可用: 上游流提前断开"), "{status}");
        assert!(!status.starts_with("正常"), "{status}");
        assert!(status.contains("未收到 response.completed"), "{status}");
    }

    #[test]
    fn guard_proxy_pollution_signal_skips_polluted_fallback_and_switches_clean() {
        let (port, handle) = start_test_json_upstream(r#"{"output_text":"余额不足"}"#);
        let temp = tempfile::tempdir().unwrap();
        let workdir = temp.path().join("workspace");
        fs::create_dir_all(&workdir).unwrap();
        let mut cfg = config();
        cfg.agent_driver = crate::config::AgentDriver::Generic;
        cfg.agent_command = long_running_test_command();
        cfg.workdir = workdir.clone();
        cfg.session_state_path = temp.path().join("session-state.json");
        cfg.endpoints.push(endpoint("clean", 1));
        for endpoint in &mut cfg.endpoints {
            endpoint.workdir = workdir.clone();
        }
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[0].guard_proxy.fail_keywords = vec!["余额不足".to_string()];
        let mut runtime = RuntimeCore::new(cfg);
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        let clean = runtime.config.endpoints[2].clone();
        runtime.current_endpoint = Some(high.name.clone());
        runtime.remember_single_probe_result(&high, &ProbeResult::available(), Instant::now());
        runtime.remember_single_probe_result(&low, &ProbeResult::available(), Instant::now());
        runtime.remember_single_probe_result(&clean, &ProbeResult::available(), Instant::now());
        runtime.health.update(
            &runtime.config.endpoints,
            &HashMap::from([
                (high.name.clone(), ProbeResult::available()),
                (low.name.clone(), ProbeResult::available()),
                (clean.name.clone(), ProbeResult::available()),
            ]),
        );
        let guard_port = attach_test_guard_proxy(&mut runtime, &high);
        let response = send_test_guard_chat_request(guard_port);
        handle.join().unwrap();
        assert!(response.contains("本地保护层"), "{response}");
        runtime.remember_single_probe_result(
            &low,
            &ProbeResult::synthetic_polluted(),
            Instant::now(),
        );
        runtime.mark_endpoint_guard_polluted(&low.name);
        runtime
            .next_probe_at
            .insert(low.name.clone(), Instant::now() + Duration::from_secs(600));

        let probe = HttpProbe::new(0.1).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let selected = tokio.block_on(runtime.tick(&probe));

        assert_eq!(
            selected.as_ref().map(|endpoint| endpoint.name.as_str()),
            Some(clean.name.as_str()),
            "state={:?}, current={:?}, startup_failures={:?}, availability={:?}",
            runtime.state,
            runtime.current_endpoint,
            runtime.startup_failure_error,
            runtime.last_availability
        );
        assert!(runtime.last_availability[&high.name].polluted);
        assert!(runtime.polluted_until.contains_key(&high.name));
        assert!(runtime.guard_polluted_until.contains_key(&high.name));
        assert!(runtime.guard_polluted_until.contains_key(&low.name));
        assert_eq!(runtime.health.status_label(&high.name), "污染不可用");
        runtime.stop();
    }

    #[test]
    fn paused_current_endpoint_records_guard_proxy_pollution_before_holding_agent() {
        let (port, handle) = start_test_json_upstream(r#"{"output_text":"余额不足"}"#);
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("auto_paused", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[0].guard_proxy.fail_keywords = vec!["余额不足".to_string()];
        let mut runtime = RuntimeCore::new(cfg);
        let current = runtime.config.endpoints[0].clone();
        runtime.current_endpoint = Some(current.name.clone());
        let guard_port = attach_test_guard_proxy(&mut runtime, &current);
        let response = send_test_guard_chat_request(guard_port);
        handle.join().unwrap();
        assert!(response.contains("本地保护层"), "{response}");
        let probe = HttpProbe::new(0.1).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let selected = tokio.block_on(runtime.tick(&probe));

        assert_eq!(selected.unwrap().name, current.name);
        assert!(runtime.last_availability[&current.name].polluted);
        assert!(runtime.polluted_until.contains_key(&current.name));
        assert!(runtime.guard_polluted_until.contains_key(&current.name));
        assert_eq!(runtime.health.status_label(&current.name), "污染不可用");
        runtime.stop();
    }

    #[test]
    fn paused_guard_pollution_signal_does_not_extend_same_cooldown_every_tick() {
        let (port, handle) = start_test_json_upstream(r#"{"output_text":"余额不足"}"#);
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("auto_paused", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.probe_interval_seconds = 60.0;
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[0].guard_proxy.polluted_cooldown_seconds = 120.0;
        cfg.endpoints[0].guard_proxy.fail_keywords = vec!["余额不足".to_string()];
        let mut runtime = RuntimeCore::new(cfg);
        let current = runtime.config.endpoints[0].clone();
        runtime.current_endpoint = Some(current.name.clone());
        let guard_port = attach_test_guard_proxy(&mut runtime, &current);
        let response = send_test_guard_chat_request(guard_port);
        handle.join().unwrap();
        assert!(response.contains("本地保护层"), "{response}");
        let probe = HttpProbe::new(0.1).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        tokio.block_on(runtime.tick(&probe));
        let first_until = runtime.guard_polluted_until[&current.name];
        std::thread::sleep(Duration::from_millis(20));

        let selected = tokio.block_on(runtime.tick(&probe));
        let second_until = runtime.guard_polluted_until[&current.name];

        assert_eq!(selected.unwrap().name, current.name);
        assert_eq!(second_until, first_until);
        assert_eq!(runtime.health.status_label(&current.name), "污染不可用");
        runtime.stop();
    }

    #[test]
    fn guard_polluted_fallback_keeps_searching_to_clean_endpoint() {
        let mut cfg = config();
        cfg.endpoints = vec![
            endpoint("high", 100),
            endpoint("low", 10),
            endpoint("clean", 1),
        ];
        cfg.probe_interval_seconds = 1.0;
        cfg.polluted_endpoint_cooldown_seconds = 300.0;
        let mut runtime = RuntimeCore::new(cfg);
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        let clean = runtime.config.endpoints[2].clone();
        runtime.current_endpoint = Some(high.name.clone());
        runtime.remember_single_probe_result(
            &high,
            &ProbeResult::synthetic_polluted(),
            Instant::now() - Duration::from_secs(2),
        );
        runtime.mark_endpoint_guard_polluted(&high.name);
        runtime.remember_single_probe_result(
            &low,
            &ProbeResult::synthetic_polluted(),
            Instant::now() - Duration::from_secs(2),
        );
        runtime.mark_endpoint_guard_polluted(&low.name);
        let future_probe = Instant::now() + Duration::from_secs(120);
        runtime
            .next_probe_at
            .insert(high.name.clone(), future_probe);
        runtime.next_probe_at.insert(low.name.clone(), future_probe);
        runtime.remember_single_probe_result(&clean, &ProbeResult::available(), Instant::now());
        let probe = HttpProbe::new(0.5).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (selected, availability) = tokio.block_on(runtime.select_endpoint(&probe, true, true));

        assert_eq!(selected.unwrap().name, clean.name);
        assert!(availability[&low.name].polluted);
        assert!(!availability[&low.name].request_made);
        assert!(availability[&clean.name].available);
        assert!(!availability[&clean.name].request_made);
        assert!(runtime.guard_polluted_until.contains_key(&low.name));
    }

    #[test]
    fn guard_polluted_cooldown_uses_endpoint_guard_config() {
        let mut cfg = config();
        cfg.polluted_endpoint_cooldown_seconds = 300.0;
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[0].guard_proxy.polluted_cooldown_seconds = 120.0;
        let mut runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();

        runtime.mark_endpoint_guard_polluted(&endpoint.name);

        let remaining = runtime.guard_polluted_until[&endpoint.name]
            .saturating_duration_since(Instant::now())
            .as_secs_f64();
        assert!(
            (100.0..=121.0).contains(&remaining),
            "remaining={remaining}"
        );
        assert_eq!(
            runtime.polluted_until[&endpoint.name],
            runtime.guard_polluted_until[&endpoint.name]
        );
        let next_probe_remaining = runtime.next_probe_at[&endpoint.name]
            .saturating_duration_since(Instant::now())
            .as_secs_f64();
        assert!(
            (0.0..=2.0).contains(&next_probe_remaining),
            "next_probe_remaining={next_probe_remaining}"
        );
    }

    #[test]
    fn restart_agent_resets_current_agent_for_next_tick() {
        let mut runtime = RuntimeCore::new(config());
        runtime.current_endpoint = Some("high".to_string());
        runtime.pending_initial_prompt = Some("old prompt".to_string());
        runtime.pending_goal_prompt = Some("/goal old goal".to_string());
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
        assert_eq!(runtime.pending_goal_prompt, None);
        assert_eq!(runtime.last_prompt_at, None);
        assert_eq!(runtime.last_auto_prompt_signature, None);
        assert!(!runtime.waiting_for_assistant_progress);
        assert_eq!(runtime.probing_endpoint, None);
        assert!(runtime.counted_probe_inflight.is_empty());
    }

    #[test]
    fn fork_codex_session_prepares_only_the_next_agent_start() {
        let mut runtime = RuntimeCore::new(config());
        runtime.current_endpoint = Some("high".to_string());
        runtime.pending_initial_prompt = Some("old prompt".to_string());
        runtime.force_new_session_once = true;
        let session_path = PathBuf::from("Runtime/codex-homes/source/session.jsonl");

        runtime
            .fork_codex_session_next_start("source-session".to_string(), Some(session_path.clone()))
            .unwrap();

        assert_eq!(
            runtime.fork_source_session_once,
            Some(("source-session".to_string(), Some(session_path)))
        );
        assert!(!runtime.force_new_session_once);
        assert_eq!(runtime.current_endpoint, None);
        assert_eq!(runtime.pending_initial_prompt, None);
        assert_eq!(runtime.state, RuntimeState::Stopped);

        runtime.force_new_conversation_next_start();

        assert_eq!(runtime.fork_source_session_once, None);
        assert!(runtime.force_new_session_once);
    }

    #[test]
    fn fork_session_accepts_claude_and_opencode_but_rejects_generic() {
        for driver in [AgentDriver::ClaudeCode, AgentDriver::OpenCode] {
            let mut cfg = config();
            cfg.agent_driver = driver;
            let mut runtime = RuntimeCore::new(cfg);

            runtime
                .fork_session_next_start("source-session".to_string(), None)
                .unwrap();

            assert_eq!(
                runtime.fork_source_session_once,
                Some(("source-session".to_string(), None))
            );
        }

        let mut cfg = config();
        cfg.agent_driver = AgentDriver::Generic;
        let mut runtime = RuntimeCore::new(cfg);
        assert!(runtime
            .fork_session_next_start("source-session".to_string(), None)
            .is_err());
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
    fn direct_endpoint_start_bypasses_probe_and_enabled_state() {
        let temp = tempfile::tempdir().unwrap();
        let workdir = temp.path().join("workspace");
        fs::create_dir_all(&workdir).unwrap();
        let mut cfg = config();
        cfg.agent_driver = crate::config::AgentDriver::Generic;
        cfg.agent_command = long_running_test_command();
        cfg.workdir = workdir.clone();
        cfg.session_state_path = temp.path().join("session-state.json");
        for endpoint in &mut cfg.endpoints {
            endpoint.workdir = workdir.clone();
            endpoint.base_url = "http://127.0.0.1:1/unavailable".to_string();
        }
        cfg.endpoints[1].enabled = false;
        let mut runtime = RuntimeCore::new(cfg);
        let probe = HttpProbe::new(0.1).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime
            .force_start_endpoint_next_tick("low".to_string())
            .unwrap();
        let selected = tokio.block_on(runtime.tick(&probe));

        assert_eq!(
            selected.as_ref().map(|endpoint| endpoint.name.as_str()),
            Some("low")
        );
        assert_eq!(runtime.current_endpoint.as_deref(), Some("low"));
        assert_eq!(runtime.fixed_endpoint.as_deref(), Some("low"));
        assert!(runtime.last_availability.is_empty());
        runtime.stop();
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
    fn disabling_endpoint_clears_guard_polluted_cooldown_before_reenable() {
        let mut cfg = config();
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[0].guard_proxy.polluted_cooldown_seconds = 120.0;
        let mut runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();
        runtime.mark_endpoint_guard_polluted(&endpoint.name);

        assert!(runtime.cooldown_result(&endpoint, Instant::now()).is_some());

        assert!(runtime.set_endpoint_enabled(&endpoint.name, false));
        assert!(!runtime.guard_polluted_until.contains_key(&endpoint.name));
        assert!(!runtime.polluted_until.contains_key(&endpoint.name));
        assert!(!runtime.next_probe_at.contains_key(&endpoint.name));

        assert!(runtime.set_endpoint_enabled(&endpoint.name, true));
        let reenabled = runtime.config.endpoints[0].clone();

        assert!(runtime
            .cooldown_result(&reenabled, Instant::now())
            .is_none());
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
    fn successful_probes_clear_pending_polluted_cooldown_after_three_clean_results() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = endpoint("high", 100);
        let now = Instant::now();
        runtime.remember_single_probe_result(&endpoint, &ProbeResult::synthetic_polluted(), now);
        runtime.mark_endpoint_polluted(&endpoint.name);

        runtime.remember_single_probe_result(&endpoint, &ProbeResult::available(), now);
        runtime.next_probe_at.insert(endpoint.name.clone(), now);
        let blocked = runtime.cooldown_result(&endpoint, now + Duration::from_millis(1));

        assert!(blocked.is_none());
        assert!(runtime.polluted_until.contains_key(&endpoint.name));

        runtime.remember_single_probe_result(&endpoint, &ProbeResult::available(), now);
        runtime.remember_single_probe_result(&endpoint, &ProbeResult::available(), now);

        assert!(!runtime.polluted_until.contains_key(&endpoint.name));
    }

    #[test]
    fn applied_available_probe_results_clear_pending_polluted_cooldown_after_three_clean_results() {
        let mut runtime = RuntimeCore::new(config());
        let endpoint = endpoint("high", 100);
        runtime.mark_endpoint_polluted(&endpoint.name);

        for _ in 0..2 {
            runtime.apply_probe_results(HashMap::from([(
                endpoint.name.clone(),
                ProbeResult::available(),
            )]));
        }
        assert!(runtime.polluted_until.contains_key(&endpoint.name));

        runtime.apply_probe_results(HashMap::from([(
            endpoint.name.clone(),
            ProbeResult::available(),
        )]));

        assert!(!runtime.polluted_until.contains_key(&endpoint.name));
    }

    #[test]
    fn polluted_endpoint_requires_three_clean_results_before_selection() {
        let mut runtime = RuntimeCore::new(config());
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        runtime.apply_probe_results(HashMap::from([(
            low.name.clone(),
            ProbeResult::available(),
        )]));
        runtime.mark_endpoint_polluted(&high.name);

        for expected_successes in 1..=2 {
            let selected = runtime.apply_probe_results(HashMap::from([(
                high.name.clone(),
                ProbeResult::available(),
            )]));

            assert_eq!(selected.unwrap().name, low.name);
            assert!(runtime.polluted_until.contains_key(&high.name));
            assert_eq!(
                runtime.rows()[0].request_status,
                format!("污染恢复中 {expected_successes}/3")
            );
        }

        let selected = runtime.apply_probe_results(HashMap::from([(
            high.name.clone(),
            ProbeResult::available(),
        )]));

        assert_eq!(selected.unwrap().name, high.name);
        assert!(!runtime.polluted_until.contains_key(&high.name));
        assert_eq!(runtime.rows()[0].request_status, "正常");
    }

    #[test]
    fn polluted_background_endpoint_reprobes_without_clearing_before_three_clean_results() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let response_requests = Arc::new(AtomicUsize::new(0));
        let server_done = Arc::clone(&done);
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
            let request = read_test_http_request(&mut socket);
            let (status, reason, body) = if request.starts_with("GET /v1/models ") {
                (200_u16, "OK", r#"{"data":[{"id":"gpt-5.5"}]}"#)
            } else if request.starts_with("POST /v1/responses ") {
                server_response_requests.fetch_add(1, Ordering::SeqCst);
                (200_u16, "OK", r#"{"output_text":"WATCHAPI_OK"}"#)
            } else {
                (404_u16, "Not Found", r#"{"error":"not found"}"#)
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes());
        });

        let mut cfg = config();
        cfg.probe_interval_seconds = 1.0;
        cfg.polluted_endpoint_cooldown_seconds = 300.0;
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        let mut runtime = RuntimeCore::new(cfg);
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        runtime.current_endpoint = Some(low.name.clone());
        runtime.remember_single_probe_result(&low, &ProbeResult::available(), Instant::now());
        runtime.remember_single_probe_result(
            &high,
            &ProbeResult::synthetic_polluted(),
            Instant::now() - Duration::from_secs(2),
        );
        runtime.mark_endpoint_polluted(&high.name);

        let availability = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(runtime.probe_due_unhealthy_endpoints(
                &HttpProbe::new(2.0).unwrap(),
                vec![high.clone()],
                ProbeMode::Full,
            ));

        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(response_requests.load(Ordering::SeqCst), 1);
        assert!(runtime.last_availability[&high.name].available);
        assert!(runtime.polluted_until.contains_key(&high.name));
        assert_eq!(runtime.rows()[0].request_status, "污染恢复中 1/3");
        assert!(availability[&high.name].available);
    }

    #[test]
    fn polluted_upgrade_candidate_uses_full_probe_and_waits_for_three_clean_results() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let model_requests = Arc::new(AtomicUsize::new(0));
        let response_requests = Arc::new(AtomicUsize::new(0));
        let server_done = Arc::clone(&done);
        let server_model_requests = Arc::clone(&model_requests);
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
            let request = read_test_http_request(&mut socket);
            let (status, reason, body) = if request.starts_with("GET /v1/models ") {
                server_model_requests.fetch_add(1, Ordering::SeqCst);
                (200_u16, "OK", r#"{"data":[{"id":"gpt-5.5"}]}"#)
            } else if request.starts_with("POST /v1/responses ") {
                server_response_requests.fetch_add(1, Ordering::SeqCst);
                (200_u16, "OK", r#"{"output_text":"WATCHAPI_OK"}"#)
            } else {
                (404_u16, "Not Found", r#"{"error":"not found"}"#)
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes());
        });

        let mut cfg = config();
        cfg.probe_interval_seconds = 1.0;
        cfg.polluted_endpoint_cooldown_seconds = 300.0;
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        let mut runtime = RuntimeCore::new(cfg);
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        runtime.current_endpoint = Some(low.name.clone());
        runtime.remember_single_probe_result(&low, &ProbeResult::available(), Instant::now());
        runtime.remember_single_probe_result(
            &high,
            &ProbeResult::synthetic_polluted(),
            Instant::now() - Duration::from_secs(2),
        );
        runtime.mark_endpoint_polluted(&high.name);
        let probe = HttpProbe::new(2.0).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        for expected_successes in 1..=2 {
            let (selected, _) =
                tokio.block_on(runtime.select_endpoint_with_options(&probe, false, false, false));

            assert_eq!(selected.unwrap().name, low.name);
            assert_eq!(
                runtime.rows()[0].request_status,
                format!("污染恢复中 {expected_successes}/3")
            );
            runtime
                .next_probe_at
                .insert(high.name.clone(), Instant::now() - Duration::from_secs(1));
        }

        let (selected, _) =
            tokio.block_on(runtime.select_endpoint_with_options(&probe, false, false, false));

        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(selected.unwrap().name, high.name);
        assert_eq!(response_requests.load(Ordering::SeqCst), 3);
        assert!(!runtime.polluted_until.contains_key(&high.name));
    }

    #[test]
    fn healthy_current_endpoint_still_reprobes_due_unhealthy_background_endpoints() {
        let source = include_str!("runtime.rs");
        let select_block = source
            .split("fn select_endpoint_with_options")
            .nth(1)
            .and_then(|tail| tail.split("async fn find_first_available").next())
            .expect("endpoint selection block should be discoverable");

        assert!(source.contains("fn probe_due_unhealthy_endpoints"));
        assert!(select_block.contains("probe_due_unhealthy_endpoints("));
        assert!(
            select_block.find("find_first_available(probe, higher")
                < select_block.find("probe_due_unhealthy_endpoints("),
            "当前接口健康时应先尝试高权重升级，再后台复探冷却到期的异常接口"
        );
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
    fn guard_polluted_cooldown_blocks_force_full_probe_until_due() {
        use std::io::Write;
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
            let request = read_test_http_request(&mut socket);
            if request.starts_with("POST /v1/responses ") && request.contains("high-model") {
                server_high_requests.fetch_add(1, Ordering::SeqCst);
            }
            let body = r#"{"output_text":"WATCHAPI_OK"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes());
        });

        let mut cfg = config();
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[0].model = "high-model".to_string();
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[0].guard_proxy.polluted_cooldown_seconds = 120.0;
        cfg.endpoints[1].base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.endpoints[1].model = "low-model".to_string();
        let mut runtime = RuntimeCore::new(cfg);
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        runtime.remember_single_probe_result(
            &high,
            &ProbeResult::synthetic_polluted(),
            Instant::now(),
        );
        runtime.mark_endpoint_guard_polluted(&high.name);

        let (selected, availability) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(runtime.find_first_available(
                &HttpProbe::new(0.5).unwrap(),
                vec![high.clone(), low.clone()],
                false,
                ProbeMode::Full,
                true,
            ));

        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(selected.unwrap().name, low.name);
        assert_eq!(high_requests.load(Ordering::SeqCst), 0);
        assert!(!availability[&high.name].request_made);
        assert!(availability[&high.name].polluted);
        assert!(runtime.guard_polluted_until.contains_key(&high.name));
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

        assert!(block.contains("match update_control_state"));
        assert!(block.contains("Ok(_) => self.clear_control_save_error()"));
        assert!(block.contains("保存强制探测接口失败"));
        assert!(block.contains("self.publish_snapshot_event();"));
        assert!(!block.contains("let _ = update_control_state"));
    }

    #[test]
    fn fixed_endpoint_control_state_save_failure_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        let control_path = block_control_state_path(&config_path);
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        let mut runtime = RuntimeCore::new(cfg);

        runtime.set_fixed_endpoint(Some("high".to_string()));

        assert!(runtime.state_label().contains("保存固定接口失败"));
        unblock_control_state_path(&control_path);
    }

    #[test]
    fn control_state_save_failure_preserves_and_recovers_runtime_state() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        let control_path = block_control_state_path(&config_path);
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        let mut runtime = RuntimeCore::new(cfg);
        runtime.state = RuntimeState::Running;

        runtime.set_fixed_endpoint(Some("high".to_string()));

        let failed_label = runtime.state_label();
        assert!(failed_label.starts_with("运行中 | "), "{failed_label}");
        assert!(failed_label.contains("保存固定接口失败"), "{failed_label}");

        unblock_control_state_path(&control_path);
        runtime.set_fixed_endpoint(None);

        assert_eq!(runtime.state_label(), "运行中");
    }

    #[test]
    fn disabling_endpoint_control_state_save_failure_is_reported() {
        let source = include_str!("runtime.rs");
        let block = source
            .split("pub fn set_endpoint_enabled")
            .nth(1)
            .and_then(|tail| tail.split("pub fn set_endpoint_guard_proxy_enabled").next())
            .expect("endpoint enabled setter should be discoverable");

        assert!(block.contains("match update_control_state"));
        assert!(block.contains("Ok(_) => self.clear_control_save_error()"));
        assert!(block.contains("保存禁用接口状态失败"));
        assert!(block.contains("self.publish_snapshot_event();"));
        assert!(
            !block.contains("let _ = update_control_state"),
            "禁用接口时清理 fixed/force 控制状态失败不能静默忽略"
        );
    }

    #[test]
    fn models_only_probe_falls_back_to_real_request_when_models_miss_configured_model() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
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
                Err(_) => break,
            };
            if server_done.load(Ordering::SeqCst) {
                break;
            }
            let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = socket.set_write_timeout(Some(Duration::from_secs(5)));
            let request = read_test_http_request(&mut socket);
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
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
        handle.join().unwrap();
        assert!(availability["high"].available, "{:?}", availability["high"]);
        assert_eq!(availability["high"].status_code, Some(200));
        assert_eq!(
            selected.as_ref().map(|endpoint| endpoint.name.as_str()),
            Some("high")
        );
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
            block.contains("!auto_paused")
                && block.contains("self.pending_goal_prompt.is_some()")
                && block.contains("self.pending_initial_prompt.is_some()")
                && block.contains("can_send_by_interval"),
            "暂停自动续航时 pending goal/initial prompt 都不能自动发送，否则启动终端后仍会自动续航"
        );
        assert!(
            block.contains("let automatic_requested = trigger_now"),
            "手动立即触发仍应绕过暂停状态"
        );
    }

    #[test]
    fn goal_mode_queues_goal_instead_of_initial_prompt_for_new_codex_session() {
        let source = include_str!("runtime.rs");
        let switch_block = source
            .split("fn switch_to(&mut self, endpoint: EndpointConfig)")
            .nth(1)
            .and_then(|tail| tail.split("fn maybe_drive_prompt").next())
            .expect("switch_to block should be discoverable");

        assert!(switch_block.contains("pending_goal_prompt"));
        assert!(switch_block.contains("goal_prompt_for_new_session"));
        assert!(switch_block
            .contains("self.pending_initial_prompt = if self.pending_goal_prompt.is_some()"));
    }

    #[test]
    fn goal_mode_sends_goal_before_auto_prompt_without_counting_as_auto_prompt() {
        let source = include_str!("runtime.rs");
        let prompt_block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn record_agent_usage").next())
            .expect("maybe_drive_prompt block should be discoverable");

        assert!(prompt_block.contains("pending_goal_prompt"));
        assert!(prompt_block.contains("is_goal_command"));
        assert!(prompt_block.contains("!is_goal_command"));
        assert!(
            prompt_block.find("pending_goal_prompt") < prompt_block.find("pending_initial_prompt"),
            "queued goal command must be chosen before initial or auto prompts"
        );
    }

    #[test]
    fn resumed_imported_goal_uses_goal_resume() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("goal_enabled", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.continuation_mode = crate::config::ContinuationMode::Goal;
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "历史目标".to_string();
        cfg.agent_goal.source = "session_import".to_string();
        cfg.agent_goal.source_goal_signature = "line:4:hash:abc".to_string();
        cfg.agent_goal.sync_on_resume = true;
        let runtime = RuntimeCore::new(cfg);

        assert_eq!(
            runtime.goal_prompt_for_new_session(true),
            Some("/goal resume".to_string())
        );
    }

    #[test]
    fn user_edited_goal_does_not_resume_imported_goal() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("goal_enabled", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.continuation_mode = crate::config::ContinuationMode::Goal;
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "用户新目标".to_string();
        cfg.agent_goal.source = "user_edit".to_string();
        cfg.agent_goal.source_goal_signature = String::new();
        cfg.agent_goal.sync_on_resume = true;
        let runtime = RuntimeCore::new(cfg);

        assert_eq!(runtime.goal_prompt_for_new_session(true), None);
    }

    #[test]
    fn resumed_synced_unfinished_goal_uses_goal_resume_after_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        crate::control::update_control_state(
            &config_path,
            &[
                ("goal_enabled", json!(true)),
                ("goal_completed", json!(false)),
                ("goal_synced_revision", json!(12)),
                ("goal_synced_text", json!("长目标")),
            ],
        )
        .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.continuation_mode = crate::config::ContinuationMode::Goal;
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "长目标".to_string();
        cfg.agent_goal.revision = 12;
        cfg.agent_goal.sync_on_resume = true;
        let runtime = RuntimeCore::new(cfg);

        assert_eq!(
            runtime.goal_prompt_for_new_session(true),
            Some("/goal resume".to_string())
        );
    }

    #[test]
    fn changed_goal_does_not_resume_stale_synced_goal() {
        let state = json!({
            "goal_enabled": true,
            "goal_completed": false,
            "goal_synced_revision": 12,
            "goal_synced_text": "旧目标"
        });
        let mut cfg = config();
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "新目标".to_string();
        cfg.agent_goal.revision = 13;
        cfg.agent_goal.sync_on_resume = true;

        assert!(!should_resume_goal_runtime(&cfg, &state));
    }

    #[test]
    fn sent_goal_command_marks_current_goal_synced_for_next_start() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let mut cfg = config();
        cfg.config_path = Some(config_path.clone());
        cfg.agent_goal.text = "持久目标".to_string();
        cfg.agent_goal.revision = 21;
        cfg.agent_goal.source_goal_signature = "line:1:hash:goal".to_string();
        let mut runtime = RuntimeCore::new(cfg);

        runtime.mark_goal_synced();

        let state = crate::control::read_control_state(&config_path);
        assert_eq!(state["goal_synced_revision"], json!(21));
        assert_eq!(state["goal_synced_text"], json!("持久目标"));
        assert_eq!(
            state["goal_synced_source_goal_signature"],
            json!("line:1:hash:goal")
        );
        assert_eq!(state["goal_completed"], json!(false));
    }

    #[test]
    fn completed_goal_turn_disables_goal_switch_for_next_start() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        crate::control::update_control_state(
            &config_path,
            &[
                ("goal_enabled", json!(true)),
                ("goal_request", json!({"action": "resume"})),
            ],
        )
        .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path.clone());
        cfg.agent_goal.revision = 7;
        cfg.agent_goal.source_goal_signature = "line:4:hash:abc".to_string();
        let mut runtime = RuntimeCore::new(cfg);
        runtime.goal_turn_active = true;

        runtime.disable_goal_mode_after_completed_turn();

        let state = crate::control::read_control_state(&config_path);
        assert_eq!(state["goal_enabled"], json!(false));
        assert_eq!(state["goal_completed"], json!(true));
        assert_eq!(state["goal_completed_revision"], json!(7));
        assert_eq!(
            state["goal_completed_source_goal_signature"],
            json!("line:4:hash:abc")
        );
        assert!(state.get("goal_request").is_none_or(Value::is_null));
    }

    #[test]
    fn control_state_goal_request_builds_codex_goal_command() {
        let state = json!({
            "goal_request": {
                "action": "set",
                "text": "  修复终端渲染  "
            }
        });

        assert_eq!(
            control_state_goal_prompt(&state),
            Some("/goal 修复终端渲染".to_string())
        );
        assert_eq!(
            control_state_goal_prompt(&json!({"goal_request": {"text": ""}})),
            None
        );
        assert_eq!(
            control_state_goal_prompt(&json!({"goal_request": {"action": "resume"}})),
            Some("/goal resume".to_string())
        );
    }

    #[test]
    fn stale_goal_request_without_goal_text_is_ignored() {
        let mut cfg = config();
        cfg.agent_goal.enabled = false;
        cfg.agent_goal.text.clear();
        let state = json!({
            "goal_enabled": true,
            "goal_request": {"action": "resume"}
        });

        assert_eq!(control_state_goal_prompt_for_config(&cfg, &state), None);
        assert!(!goal_mode_enabled_runtime(&cfg, &state));
        assert!(!should_resume_goal_runtime(&cfg, &state));

        cfg.agent_goal.enabled = true;
        assert_eq!(control_state_goal_prompt_for_config(&cfg, &state), None);
        assert!(!goal_mode_enabled_runtime(&cfg, &state));
    }

    #[test]
    fn active_goal_session_prefers_resume_for_imported_goal() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("goal_enabled", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "历史目标".to_string();
        cfg.agent_goal.source = "session_import".to_string();
        cfg.agent_goal.source_goal_signature = "line:4:hash:abc".to_string();
        cfg.agent_goal.sync_on_resume = true;
        let runtime = RuntimeCore::new(cfg);

        assert_eq!(
            runtime.goal_prompt_for_active_session(&json!({"goal_enabled": true})),
            Some("/goal resume".to_string())
        );
    }

    #[test]
    fn active_goal_session_prefers_explicit_request_over_synthetic_resume() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("goal_enabled", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "历史目标".to_string();
        cfg.agent_goal.source = "session_import".to_string();
        cfg.agent_goal.source_goal_signature = "line:4:hash:abc".to_string();
        cfg.agent_goal.sync_on_resume = true;
        let runtime = RuntimeCore::new(cfg);

        assert_eq!(
            runtime.goal_prompt_for_active_session(&json!({
                "goal_enabled": true,
                "goal_request": {"action": "set", "text": "新目标"}
            })),
            Some("/goal 新目标".to_string())
        );
    }

    #[test]
    fn explicit_goal_request_is_not_blocked_by_synced_goal_state() {
        let source = include_str!("runtime.rs");
        let prompt_block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("let manual_prompt =").next())
            .expect("goal request loading block should be discoverable");

        assert!(prompt_block.contains("let explicit_goal_prompt"));
        assert!(prompt_block.contains("control_state_goal_prompt_for_config"));
        assert!(
            prompt_block.contains("!self.goal_synced_this_run || explicit_goal_prompt.is_some()")
        );
        assert!(prompt_block.contains("self.pending_goal_prompt = explicit_goal_prompt"));
    }

    #[test]
    fn goal_request_cleanup_failure_is_reported_and_gated() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        let control_path = block_control_state_path(&config_path);
        let mut cfg = config();
        cfg.config_path = Some(config_path.clone());
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "默认目标".to_string();
        let mut runtime = RuntimeCore::new(cfg);
        let state = json!({"goal_request": {"action": "set", "text": "新目标"}});
        let signature = control_state_goal_request_signature(&state).unwrap();

        runtime.clear_goal_request_control_state(signature.clone());

        let failed_label = runtime.state_label();
        assert!(failed_label.contains("清理目标请求失败"), "{failed_label}");
        assert_eq!(
            runtime.goal_request_clear_failed_signature.as_deref(),
            Some(signature.as_str())
        );

        unblock_control_state_path(&control_path);
        crate::control::update_control_state(
            &config_path,
            &[("goal_request", json!({"action": "set", "text": "新目标"}))],
        )
        .unwrap();

        runtime.clear_goal_request_control_state(signature);

        let recovered_label = runtime.state_label();
        let state = crate::control::read_control_state(&config_path);
        assert!(state.get("goal_request").is_some_and(Value::is_null));
        assert_eq!(runtime.goal_request_clear_failed_signature, None);
        assert!(
            !recovered_label.contains("清理目标请求失败"),
            "{recovered_label}"
        );
    }

    #[test]
    fn goal_control_state_save_failures_are_reported_and_recover() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        let mut cfg = config();
        cfg.config_path = Some(config_path.clone());
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "目标".to_string();
        cfg.agent_goal.revision = 7;
        let mut runtime = RuntimeCore::new(cfg);

        let control_path = block_control_state_path(&config_path);
        runtime.mark_goal_synced();
        let synced_failed_label = runtime.state_label();
        assert!(
            synced_failed_label.contains("保存目标同步状态失败"),
            "{synced_failed_label}"
        );

        unblock_control_state_path(&control_path);
        runtime.mark_goal_synced();
        let synced_state = crate::control::read_control_state(&config_path);
        assert_eq!(synced_state["goal_synced_revision"], json!(7));
        assert!(synced_state.get("goal_request").is_some_and(Value::is_null));
        assert_eq!(runtime.state_label(), "已停止");

        let control_path = block_control_state_path(&config_path);
        runtime.disable_goal_mode_after_completed_turn();
        let completed_failed_label = runtime.state_label();
        assert!(
            completed_failed_label.contains("保存目标完成状态失败"),
            "{completed_failed_label}"
        );

        unblock_control_state_path(&control_path);
        runtime.disable_goal_mode_after_completed_turn();
        let completed_state = crate::control::read_control_state(&config_path);
        assert_eq!(completed_state["goal_enabled"], json!(false));
        assert_eq!(completed_state["goal_completed"], json!(true));
        assert!(completed_state
            .get("goal_request")
            .is_some_and(Value::is_null));
        assert_eq!(runtime.state_label(), "已停止");
    }

    #[test]
    fn goal_request_cleanup_failure_skips_same_stale_request_only() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("goal_enabled", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "默认目标".to_string();
        let mut runtime = RuntimeCore::new(cfg);
        let stale_state = json!({
            "goal_enabled": true,
            "goal_request": {"action": "set", "text": "旧请求"}
        });
        let fresh_state = json!({
            "goal_enabled": true,
            "goal_request": {"action": "set", "text": "新请求"}
        });
        runtime.goal_request_clear_failed_signature =
            control_state_goal_request_signature(&stale_state);

        let stale_signature = control_state_goal_request_signature(&stale_state);
        let stale_failed = stale_signature.as_deref().is_some_and(|signature| {
            runtime.goal_request_clear_failed_signature.as_deref() == Some(signature)
        });
        let fresh_signature = control_state_goal_request_signature(&fresh_state);
        let fresh_failed = fresh_signature.as_deref().is_some_and(|signature| {
            runtime.goal_request_clear_failed_signature.as_deref() == Some(signature)
        });

        assert!(stale_failed);
        assert!(!fresh_failed);
        assert_eq!(
            runtime
                .goal_prompt_for_active_session(&control_state_without_goal_request(&stale_state,)),
            Some("/goal 默认目标".to_string())
        );
        assert_eq!(
            control_state_goal_prompt_for_config(&runtime.config, &fresh_state),
            Some("/goal 新请求".to_string())
        );
    }

    #[test]
    fn goal_mode_requires_goal_command_before_fallback_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("goal_enabled", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.continuation_mode = crate::config::ContinuationMode::Goal;
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "修复终端渲染".to_string();
        cfg.agent_goal.fallback_prompt = "继续围绕当前 /goal 推进".to_string();
        let mut runtime = RuntimeCore::new(cfg);

        assert_eq!(
            runtime.goal_prompt_for_active_session(&json!({"goal_enabled": true})),
            Some("/goal 修复终端渲染".to_string())
        );
        assert_eq!(runtime.goal_fallback_prompt(), None);

        runtime.goal_synced_this_run = true;
        assert_eq!(
            runtime.goal_fallback_prompt(),
            Some("继续围绕当前 /goal 推进".to_string())
        );

        let source = include_str!("runtime.rs");
        let prompt_block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn record_agent_usage").next())
            .expect("maybe_drive_prompt block should be discoverable");
        assert!(
            prompt_block.find("pending_goal_prompt") < prompt_block.find("goal_fallback_prompt"),
            "Goal command must be selected before fallback prompt"
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
    fn blocked_auto_prompt_reports_waiting_for_input_instead_of_idle() {
        let source = include_str!("runtime.rs");
        let prompt_block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn record_agent_usage").next())
            .expect("prompt driver should be discoverable");
        let blocked_block = prompt_block
            .split("if !can_send_prompt {")
            .nth(1)
            .and_then(|tail| tail.split("if manual_prompt.is_none()").next())
            .expect("blocked can_send_prompt block should be discoverable");

        assert!(blocked_block.contains("self.requeue_manual_prompt"));
        assert!(blocked_block.contains("automatic_requested || manual_prompt.is_some()"));
        assert!(prompt_block.contains("agent.auto_input_block_reason()"));
        assert!(blocked_block.contains("RuntimeState::WaitingInput(reason.to_string())"));
    }

    #[test]
    fn manual_prompt_requeue_failure_is_visible_and_recovers() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        let queue_path = crate::control::prompt_queue_path(&config_path);
        if queue_path.is_dir() {
            std::fs::remove_dir_all(&queue_path).unwrap();
        } else if queue_path.exists() {
            std::fs::remove_file(&queue_path).unwrap();
        }
        std::fs::create_dir_all(&queue_path).unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path.clone());
        let mut runtime = RuntimeCore::new(cfg);
        runtime.state = RuntimeState::WaitingInput("终端未就绪".to_string());

        assert!(!runtime.requeue_manual_prompt("继续执行"));

        let failed_label = runtime.state_label();
        assert!(failed_label.starts_with("等待可输入：终端未就绪 | "));
        assert!(failed_label.contains("恢复手动提示失败"), "{failed_label}");

        std::fs::remove_dir_all(&queue_path).unwrap();

        assert!(runtime.requeue_manual_prompt("继续执行"));

        let recovered_label = runtime.state_label();
        assert_eq!(
            crate::control::pop_manual_prompt(&config_path),
            Some("继续执行".to_string())
        );
        assert_eq!(recovered_label, "等待可输入：终端未就绪");
    }

    #[test]
    fn manual_prompt_requeue_failures_are_not_silent() {
        let source = include_str!("runtime.rs");
        let prompt_block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn requeue_manual_prompt").next())
            .expect("prompt driver should be discoverable");

        assert!(prompt_block.contains("self.requeue_manual_prompt"));
        assert!(
            !prompt_block.contains("let _ = enqueue_manual_prompt"),
            "手动提示回队列失败不能静默吞掉，否则用户输入可能丢失"
        );
    }

    #[test]
    fn waiting_input_state_label_is_not_error() {
        let mut runtime = RuntimeCore::new(config());
        runtime.state = RuntimeState::WaitingInput("检测到 Working".to_string());

        assert_eq!(runtime.state_label(), "等待可输入：检测到 Working");
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
    fn failed_auto_prompt_send_is_visible_and_releases_wait_gate() {
        let source = include_str!("runtime.rs");
        let block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn record_agent_usage").next())
            .expect("maybe_drive_prompt block should be discoverable");

        assert!(block.contains("let send_result = agent.send_prompt(&prompt);"));
        assert!(block.contains("提示词发送失败"));
        assert!(block.contains("self.waiting_for_assistant_progress = false;"));
        assert!(block.contains("self.state = RuntimeState::Error(error);"));
    }

    #[test]
    fn continuation_trigger_prompt_is_prioritized_once_and_respects_auto_pause() {
        let source = include_str!("runtime.rs");
        let block = source
            .split("fn maybe_drive_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn requeue_manual_prompt").next())
            .expect("maybe_drive_prompt block should be discoverable");

        let manual_pos = block
            .find("if let Some(prompt) = manual_prompt")
            .expect("manual prompt branch should exist");
        let goal_pos = block
            .find("self.pending_goal_prompt.take()")
            .expect("goal prompt branch should exist");
        let trigger_pos = block
            .find("self.pending_continuation_trigger_prompt.take()")
            .expect("continuation trigger branch should exist");
        let initial_pos = block
            .find("self.pending_initial_prompt.take()")
            .expect("initial prompt branch should exist");

        assert!(manual_pos < goal_pos && goal_pos < trigger_pos && trigger_pos < initial_pos);
        assert!(block.contains(
            "!auto_paused\n                && (self.pending_continuation_trigger_prompt.is_some()"
        ));
        assert!(block.contains("restore_continuation_trigger_prompt = true;"));
        assert!(block.contains("self.pending_continuation_trigger_prompt = Some(prompt);"));
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
        let selection_block = tick_block
            .split("let mut selected = selected;")
            .nth(1)
            .expect("接口选择分支应存在");
        let changed_reset = selection_block
            .find("changed = false")
            .expect("同接口且仍可用时应在 switch_to 前清除 changed，避免重启 agent");
        let switch = selection_block
            .find("match self.switch_to")
            .expect("切换接口分支应存在");
        assert!(changed_reset < switch);
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
    fn paused_current_endpoint_records_pollution_signal_before_holding_agent() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("auto_paused", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        let mut runtime = RuntimeCore::new(cfg);
        let current = runtime.config.endpoints[0].clone();
        runtime.current_endpoint = Some(current.name.clone());
        let mut agent = AgentProcess::new(runtime.config.clone(), current.clone(), false);
        agent.pollution_detected = true;
        runtime.agent = Some(agent);
        let probe = HttpProbe::new(0.1).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let selected = tokio.block_on(runtime.tick(&probe));

        assert_eq!(selected.unwrap().name, current.name);
        assert!(runtime.polluted_until.contains_key(&current.name));
        assert!(runtime.last_availability[&current.name].polluted);
        assert!(!runtime
            .agent
            .as_ref()
            .is_some_and(|agent| agent.pollution_detected));
    }

    #[test]
    fn guard_replacement_ignores_direct_pollution_signal_while_paused() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("auto_paused", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[0]
            .guard_proxy
            .replace_direct_pollution_detection = true;
        let mut runtime = RuntimeCore::new(cfg);
        let current = runtime.config.endpoints[0].clone();
        runtime.current_endpoint = Some(current.name.clone());
        runtime.remember_single_probe_result(&current, &ProbeResult::available(), Instant::now());
        let mut agent = AgentProcess::new(runtime.config.clone(), current.clone(), false);
        agent.pollution_detected = true;
        runtime.agent = Some(agent);
        let probe = HttpProbe::new(0.1).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let selected = tokio.block_on(runtime.tick(&probe));

        assert_eq!(selected.unwrap().name, current.name);
        assert!(!runtime.polluted_until.contains_key(&current.name));
        assert!(runtime.last_availability[&current.name].available);
        assert!(!runtime
            .agent
            .as_ref()
            .is_some_and(|agent| agent.pollution_detected));
    }

    #[test]
    fn guard_fallback_keeps_direct_pollution_signal_while_paused() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("auto_paused", json!(true))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.endpoints[0].guard_proxy.enabled = true;
        cfg.endpoints[0]
            .guard_proxy
            .replace_direct_pollution_detection = false;
        let mut runtime = RuntimeCore::new(cfg);
        let current = runtime.config.endpoints[0].clone();
        runtime.current_endpoint = Some(current.name.clone());
        let mut agent = AgentProcess::new(runtime.config.clone(), current.clone(), false);
        agent.pollution_detected = true;
        runtime.agent = Some(agent);
        let probe = HttpProbe::new(0.1).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let selected = tokio.block_on(runtime.tick(&probe));

        assert_eq!(selected.unwrap().name, current.name);
        assert!(runtime.polluted_until.contains_key(&current.name));
        assert!(runtime.last_availability[&current.name].polluted);
        assert!(!runtime
            .agent
            .as_ref()
            .is_some_and(|agent| agent.pollution_detected));
    }

    #[test]
    fn paused_current_endpoint_still_reprobes_due_polluted_background_endpoint() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let response_requests = Arc::new(AtomicUsize::new(0));
        let server_done = Arc::clone(&done);
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
            let request = read_test_http_request(&mut socket);
            let (status, reason, body) = if request.starts_with("GET /v1/models ") {
                (200_u16, "OK", r#"{"data":[{"id":"gpt-5.5"}]}"#)
            } else if request.starts_with("POST /v1/responses ") {
                server_response_requests.fetch_add(1, Ordering::SeqCst);
                (200_u16, "OK", r#"{"output_text":"WATCHAPI_OK"}"#)
            } else {
                (404_u16, "Not Found", r#"{"error":"not found"}"#)
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        cfg.probe_interval_seconds = 1.0;
        cfg.polluted_endpoint_cooldown_seconds = 300.0;
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        let mut runtime = RuntimeCore::new(cfg);
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        runtime.current_endpoint = Some(low.name.clone());
        runtime.remember_single_probe_result(&low, &ProbeResult::available(), Instant::now());
        runtime.remember_single_probe_result(
            &high,
            &ProbeResult::synthetic_polluted(),
            Instant::now() - Duration::from_secs(2),
        );
        runtime.mark_endpoint_polluted(&high.name);
        runtime
            .next_probe_at
            .insert(high.name.clone(), Instant::now() - Duration::from_secs(1));
        let probe = HttpProbe::new(0.5).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let selected = tokio.block_on(runtime.tick(&probe));

        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(selected.unwrap().name, low.name);
        assert_eq!(response_requests.load(Ordering::SeqCst), 1);
        assert!(runtime.last_availability[&high.name].available);
        assert!(runtime.polluted_until.contains_key(&high.name));
        assert_eq!(runtime.rows()[0].request_status, "污染恢复中 1/3");
    }

    #[test]
    fn paused_current_endpoint_reprobes_itself_when_polluted_recovery_is_due() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let response_requests = Arc::new(AtomicUsize::new(0));
        let server_done = Arc::clone(&done);
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
            let request = read_test_http_request(&mut socket);
            let (status, reason, body) = if request.starts_with("GET /v1/models ") {
                (200_u16, "OK", r#"{"data":[{"id":"gpt-5.5"}]}"#)
            } else if request.starts_with("POST /v1/responses ") {
                server_response_requests.fetch_add(1, Ordering::SeqCst);
                (200_u16, "OK", r#"{"output_text":"WATCHAPI_OK"}"#)
            } else {
                (404_u16, "Not Found", r#"{"error":"not found"}"#)
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        cfg.probe_interval_seconds = 1.0;
        cfg.polluted_endpoint_cooldown_seconds = 300.0;
        cfg.endpoints[0].base_url = format!("http://127.0.0.1:{port}/v1");
        let mut runtime = RuntimeCore::new(cfg);
        let current = runtime.config.endpoints[0].clone();
        runtime.current_endpoint = Some(current.name.clone());
        runtime.remember_single_probe_result(
            &current,
            &ProbeResult::synthetic_polluted(),
            Instant::now() - Duration::from_secs(2),
        );
        runtime.mark_endpoint_polluted(&current.name);
        let probe = HttpProbe::new(0.5).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let selected = tokio.block_on(runtime.tick(&probe));

        done.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(selected.unwrap().name, current.name);
        assert_eq!(response_requests.load(Ordering::SeqCst), 1);
        assert!(runtime.last_availability[&current.name].available);
        assert!(runtime.polluted_until.contains_key(&current.name));
        assert_eq!(runtime.rows()[0].request_status, "污染恢复中 1/3");
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
    fn force_full_probe_keeps_running_equal_weight_endpoint() {
        let mut cfg = config();
        cfg.endpoints = vec![
            endpoint("peer", 100),
            endpoint("current", 100),
            endpoint("lower", 10),
        ];
        let mut runtime = RuntimeCore::new(cfg);
        runtime.current_endpoint = Some("current".to_string());
        runtime.remember_probe_results(HashMap::from([
            ("peer".to_string(), ProbeResult::available()),
            ("current".to_string(), ProbeResult::available()),
            ("lower".to_string(), ProbeResult::available()),
        ]));
        let future = Instant::now() + Duration::from_secs(60);
        runtime.next_probe_at.insert("peer".to_string(), future);
        runtime.next_probe_at.insert("current".to_string(), future);

        let probe = HttpProbe::new(0.1).unwrap();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (selected, _) =
            tokio.block_on(runtime.select_endpoint_with_options(&probe, false, false, true));

        assert_eq!(selected.unwrap().name, "current");
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
    fn single_running_endpoint_repeated_failure_stops_terminal() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        crate::control::update_control_state(&config_path, &[("auto_paused", json!(false))])
            .unwrap();
        let mut cfg = config();
        cfg.config_path = Some(config_path);
        cfg.agent_driver = crate::config::AgentDriver::Generic;
        cfg.agent_command = long_running_test_command();
        cfg.endpoints.truncate(1);
        cfg.endpoint_failure_threshold = 1;
        let mut runtime = RuntimeCore::new(cfg);
        let endpoint = runtime.config.endpoints[0].clone();
        runtime.switch_to(endpoint.clone()).unwrap();
        let first_pid = runtime.terminal_process_id();
        assert!(first_pid.is_some());
        runtime.remember_single_probe_result(&endpoint, &ProbeResult::available(), Instant::now());
        if let Some(agent) = runtime.agent.as_mut() {
            agent.endpoint_failure_detected = true;
            agent.endpoint_failure_status_code = Some(502);
        }

        let selected = runtime.tick_blocking(&HttpProbe::new(0.1).unwrap());

        assert!(selected.is_none());
        assert!(runtime.current_endpoint.is_none());
        assert!(runtime.terminal_process_id().is_none());
        assert_eq!(runtime.state_label(), "异常：请求失败 1/1");
        assert!(first_pid.is_some());
        runtime.stop();
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
    fn runtime_event_publish_wakes_after_successful_send() {
        let (tx, rx) = std::sync::mpsc::channel();
        let wakeups = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wakeups_for_callback = std::sync::Arc::clone(&wakeups);
        let mut runtime = RuntimeCore::new(config());
        runtime.set_event_wakeup(Some(std::sync::Arc::new(move || {
            wakeups_for_callback.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })));

        runtime.set_event_sender(Some(tx));

        rx.try_recv().expect("initial snapshot should publish");
        assert_eq!(wakeups.load(std::sync::atomic::Ordering::SeqCst), 1);

        runtime.publish_snapshot();

        assert!(rx.try_recv().is_err());
        assert_eq!(
            wakeups.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "deduplicated runtime events must not wake the UI without a new snapshot"
        );
    }

    #[test]
    fn runtime_event_wakeup_is_installed_on_terminal_activity() {
        let source = include_str!("runtime.rs");
        let set_wakeup_block = source
            .split("pub fn set_event_wakeup")
            .nth(1)
            .and_then(|tail| tail.split("pub fn snapshot").next())
            .expect("set_event_wakeup block should be discoverable");
        let switch_block = source
            .split("fn switch_to(&mut self, endpoint: EndpointConfig)")
            .nth(1)
            .and_then(|tail| tail.split("fn goal_prompt_for_new_session").next())
            .expect("switch_to block should be discoverable");

        assert!(set_wakeup_block.contains("agent.set_terminal_activity_wakeup"));
        assert!(
            switch_block.contains("agent.set_terminal_activity_wakeup(self.event_wakeup.clone())")
                && switch_block.find("agent.set_terminal_activity_wakeup")
                    < switch_block.find("self.agent = Some(agent);"),
            "newly started PTY sessions must inherit the GUI repaint wakeup before the runtime snapshot is published"
        );
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
    fn endpoint_request_failure_threshold_switches_away_on_next_tick() {
        let mut cfg = config();
        cfg.agent_driver = crate::config::AgentDriver::Generic;
        cfg.agent_command = long_running_test_command();
        cfg.endpoint_failure_threshold = 3;
        let mut runtime = RuntimeCore::new(cfg);
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        runtime.switch_to(high.clone()).unwrap();
        runtime.remember_single_probe_result(&high, &ProbeResult::available(), Instant::now());
        runtime.remember_single_probe_result(&low, &ProbeResult::available(), Instant::now());
        runtime
            .endpoint_request_failures_by_endpoint
            .insert(high.name.clone(), 3);

        let selected = runtime.tick_blocking(&HttpProbe::new(0.1).unwrap());

        assert_eq!(selected.unwrap().name, low.name);
        assert_eq!(runtime.current_endpoint.as_deref(), Some(low.name.as_str()));
        runtime.stop();
    }

    #[test]
    fn transient_network_failures_survive_normal_ticks_until_success_evidence() {
        let mut cfg = config();
        cfg.agent_driver = crate::config::AgentDriver::Generic;
        cfg.agent_command = long_running_test_command();
        cfg.transient_network_failure_threshold = 2;
        let mut runtime = RuntimeCore::new(cfg);
        let high = runtime.config.endpoints[0].clone();
        let low = runtime.config.endpoints[1].clone();
        runtime.switch_to(high.clone()).unwrap();
        runtime.remember_single_probe_result(&high, &ProbeResult::available(), Instant::now());
        runtime.remember_single_probe_result(&low, &ProbeResult::available(), Instant::now());

        if let Some(agent) = runtime.agent.as_mut() {
            agent.transient_endpoint_failure_detected = true;
        }
        let selected = runtime.tick_blocking(&HttpProbe::new(0.1).unwrap());
        assert_eq!(selected.unwrap().name, high.name);
        assert_eq!(
            runtime
                .transient_failures_by_endpoint
                .get(&high.name)
                .copied(),
            Some(1)
        );
        assert_eq!(
            runtime.current_endpoint.as_deref(),
            Some(high.name.as_str())
        );

        let selected = runtime.tick_blocking(&HttpProbe::new(0.1).unwrap());
        assert_eq!(selected.unwrap().name, high.name);
        assert_eq!(
            runtime
                .transient_failures_by_endpoint
                .get(&high.name)
                .copied(),
            Some(1),
            "没有新错误的普通 tick 不能把网络波动容错计数清零"
        );

        if let Some(agent) = runtime.agent.as_mut() {
            agent.transient_endpoint_failure_detected = true;
        }
        let selected = runtime.tick_blocking(&HttpProbe::new(0.1).unwrap());
        assert_eq!(selected.unwrap().name, low.name);
        assert_eq!(runtime.current_endpoint.as_deref(), Some(low.name.as_str()));

        runtime.remember_single_probe_result(&high, &ProbeResult::available(), Instant::now());
        assert!(
            !runtime
                .transient_failures_by_endpoint
                .contains_key(&high.name),
            "真实探测成功才是清零网络波动计数的成功证据"
        );
        runtime.stop();
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
    fn submit_retry_failure_is_visible_and_releases_auto_wait() {
        let source = include_str!("runtime.rs");
        let retry_block = source
            .split("if agent.needs_submit_retry(self.config.prompt_submit_retry_seconds) {")
            .nth(1)
            .and_then(|tail| tail.split("if !agent.is_idle(").next())
            .expect("submit retry branch should be discoverable");

        assert!(
            !retry_block.contains("let _ = agent.retry_submit();"),
            "自动提交重试失败不能静默忽略，否则终端写入失败时界面会继续显示运行中"
        );
        assert!(retry_block.contains("agent.mark_current_turn_failed();"));
        assert!(retry_block.contains("self.waiting_for_assistant_progress = false;"));
        assert!(retry_block.contains("重试提交失败"));
        assert!(retry_block.contains("self.publish_snapshot_event();"));
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
            .split(
                "} else if !auto_paused && agent.is_turn_stalled(self.config.turn_stall_seconds) {",
            )
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
            !normal_agent_branch.contains("clear_transient_failures(&current)")
                && !normal_agent_branch.contains("transient_failures_by_endpoint.remove(&current)"),
            "普通 tick 不能清网络波动计数，否则连续断流永远达不到切换阈值"
        );
        assert!(
            prompt_block.contains("agent.has_session_assistant_message_since_prompt()")
                && prompt_block.contains("self.clear_endpoint_request_failures(&endpoint.name)")
                && prompt_block.contains("self.clear_transient_failures(&endpoint.name)"),
            "会话文件里的 assistant 回复才是清请求失败/网络波动计数的回复成功证据"
        );
        assert!(
            probe_block.contains("result.request_made && result.available")
                && probe_block.contains("self.clear_endpoint_request_failures(&endpoint.name)")
                && probe_block.contains("self.clear_transient_failures(&endpoint.name)"),
            "真实探测成功才是清请求失败/网络波动计数的探测成功证据"
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
