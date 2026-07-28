use crate::codex_files::{
    apply_codex_endpoint_with_model_context_window, ensure_codex_unattended_state,
    get_current_model_provider,
};
use crate::config::{
    agent_driver_from_command_part, shell_wrapper_command_start, split_shell_like_command,
    AgentCommand, AgentDriver as AgentDriverKind, AppConfig, ContinuationMode, EndpointConfig,
};
use crate::cooldown::cooldown_seconds_from_text;
use crate::sessions::{
    codex_session_file_matches, discover_codex_session_homes, ClaudeSessionIndex,
    ClaudeSessionMonitor, CodexSessionIndex, CodexSessionMonitor, OpenCodeSessionMonitor,
    SessionBindingKey, SessionStore,
};
use crate::terminal::{
    resolved_command_parts, InputSource, TerminalActivityWakeup, TerminalControl, TerminalError,
    TerminalSession, TerminalSnapshot,
};
use crate::terminal_emulator::TerminalView;
use crate::tokens::TokenUsage;
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

const CODEX_READY_UNLOCK_GRACE: Duration = Duration::from_secs(2);
const CODEX_STALE_WORKING_UNLOCK_GRACE: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLaunch {
    pub command: AgentCommand,
    pub resumed: bool,
    pub session_id: Option<String>,
}

pub struct AgentProcess {
    config: AppConfig,
    endpoint: EndpointConfig,
    store: SessionStore,
    force_new_session: bool,
    terminal: Option<TerminalSession>,
    monitor: Option<AgentSessionMonitor>,
    pub launch: Option<AgentLaunch>,
    pub pollution_detected: bool,
    pub completion_pause_detected: bool,
    pub continuation_trigger_prompt: Option<String>,
    pub endpoint_failure_detected: bool,
    pub transient_endpoint_failure_detected: bool,
    pub endpoint_failure_status_code: Option<u16>,
    pub endpoint_failure_retry_after_seconds: Option<u64>,
    pub token_usage_total: TokenUsage,
    last_prompt_sent_at: Option<Instant>,
    last_submit_attempt_at: Option<Instant>,
    submit_retry_count: u32,
    awaiting_turn_completion: bool,
    recent_output: String,
    saw_ready_banner: bool,
    handled_model_upgrade_prompt: bool,
    handled_codex_update_prompt: bool,
    handled_trust_directory_prompt: bool,
    handled_sandbox_setup_prompt: bool,
    handled_codex_repair_prompt: bool,
    handled_generic_startup_option_prompt: bool,
    observed_terminal_view_revision: u64,
    observed_terminal_view_text: String,
    observed_current_input_placeholder: bool,
    last_prompt_sent_view_revision: Option<u64>,
    isolated_codex_home: Option<IsolatedCodexHome>,
    launched_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingSessionPolicy {
    New,
    LegacyLatest,
}

#[derive(Debug, Clone)]
struct IsolatedCodexHome {
    home: PathBuf,
    source_home: PathBuf,
    session_baseline: HashMap<PathBuf, SessionFileFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionFileFingerprint {
    len: u64,
    modified_millis: Option<u128>,
}

enum AgentSessionMonitor {
    Codex(CodexSessionMonitor),
    Claude(ClaudeSessionMonitor),
    OpenCode(OpenCodeSessionMonitor),
}

impl AgentSessionMonitor {
    fn poll(&mut self) {
        match self {
            Self::Codex(monitor) => monitor.poll(),
            Self::Claude(monitor) => monitor.poll(),
            Self::OpenCode(monitor) => monitor.poll(),
        }
    }

    fn session_id(&self) -> Option<String> {
        match self {
            Self::Codex(monitor) => monitor.session_id.clone(),
            Self::Claude(monitor) => monitor.session_id.clone(),
            Self::OpenCode(monitor) => monitor.session_id.clone(),
        }
    }

    fn take_pollution_detected(&mut self) -> bool {
        match self {
            Self::Codex(monitor) => std::mem::take(&mut monitor.pollution_detected),
            Self::Claude(monitor) => std::mem::take(&mut monitor.pollution_detected),
            Self::OpenCode(monitor) => std::mem::take(&mut monitor.pollution_detected),
        }
    }

    fn take_completion_pause_detected(&mut self) -> bool {
        match self {
            Self::Codex(monitor) => std::mem::take(&mut monitor.completion_pause_detected),
            Self::Claude(monitor) => std::mem::take(&mut monitor.completion_pause_detected),
            Self::OpenCode(monitor) => std::mem::take(&mut monitor.completion_pause_detected),
        }
    }

    fn take_continuation_trigger_prompt(&mut self) -> Option<String> {
        match self {
            Self::Codex(monitor) => std::mem::take(&mut monitor.continuation_trigger_prompt),
            Self::Claude(monitor) => std::mem::take(&mut monitor.continuation_trigger_prompt),
            Self::OpenCode(monitor) => std::mem::take(&mut monitor.continuation_trigger_prompt),
        }
    }

    fn take_endpoint_failure_detected(&mut self) -> bool {
        match self {
            Self::Codex(monitor) => std::mem::take(&mut monitor.endpoint_failure_detected),
            Self::Claude(_) | Self::OpenCode(_) => false,
        }
    }

    fn token_usage_total(&self) -> TokenUsage {
        match self {
            Self::Codex(monitor) => monitor.token_usage_total,
            Self::Claude(_) | Self::OpenCode(_) => TokenUsage::default(),
        }
    }

    fn begin_waiting_for_new_turn(&mut self) {
        if let Self::Codex(monitor) = self {
            monitor.begin_waiting_for_new_turn();
        }
    }

    fn has_inflight_turn(&self) -> bool {
        matches!(self, Self::Codex(monitor) if monitor.has_inflight_turn())
    }

    fn last_task_started(&self) -> bool {
        matches!(self, Self::Codex(monitor) if monitor.last_task_started_at.is_some())
    }

    fn last_task_finished(&self) -> bool {
        matches!(self, Self::Codex(monitor) if monitor.last_task_finished_at.is_some())
    }

    fn mark_turn_completed_by_idle(&mut self) {
        if let Self::Codex(monitor) = self {
            monitor.mark_turn_completed_by_idle();
        }
    }

    fn has_assistant_message_since_wait_start(&self) -> bool {
        match self {
            Self::Codex(monitor) => monitor.has_assistant_message_since_wait_start(),
            Self::Claude(_) | Self::OpenCode(_) => true,
        }
    }

    fn has_completed_assistant_message_since_wait_start(&self) -> bool {
        match self {
            Self::Codex(monitor) => {
                monitor.last_task_finished_at.is_some()
                    && !monitor.has_inflight_turn()
                    && monitor.has_assistant_message_since_wait_start()
            }
            Self::Claude(_) | Self::OpenCode(_) => true,
        }
    }

    fn has_codex_assistant_message_since_wait_start(&self) -> bool {
        matches!(self, Self::Codex(monitor) if monitor.has_assistant_message_since_wait_start())
    }

    fn clear_completion_pause_detected(&mut self) {
        match self {
            Self::Codex(monitor) => monitor.completion_pause_detected = false,
            Self::Claude(monitor) => monitor.completion_pause_detected = false,
            Self::OpenCode(monitor) => monitor.completion_pause_detected = false,
        }
    }

    fn last_session_append_elapsed(&self) -> Option<Duration> {
        match self {
            Self::Codex(monitor) => monitor.last_session_append_at.map(|at| at.elapsed()),
            Self::Claude(_) | Self::OpenCode(_) => None,
        }
    }

    fn session_tail_stalled(&self, stall_after: Duration) -> bool {
        match self {
            Self::Codex(monitor) => monitor.session_tail_stalled(stall_after),
            Self::Claude(_) | Self::OpenCode(_) => false,
        }
    }

    fn last_session_append_instant(&self) -> Option<Instant> {
        match self {
            Self::Codex(monitor) => monitor.last_session_append_at,
            Self::Claude(_) | Self::OpenCode(_) => None,
        }
    }
}

impl AgentProcess {
    pub fn new(config: AppConfig, endpoint: EndpointConfig, force_new_session: bool) -> Self {
        let store = SessionStore::new(config.session_state_path.clone());
        Self {
            config,
            endpoint,
            store,
            force_new_session,
            terminal: None,
            monitor: None,
            launch: None,
            pollution_detected: false,
            completion_pause_detected: false,
            continuation_trigger_prompt: None,
            endpoint_failure_detected: false,
            transient_endpoint_failure_detected: false,
            endpoint_failure_status_code: None,
            endpoint_failure_retry_after_seconds: None,
            token_usage_total: TokenUsage::default(),
            last_prompt_sent_at: None,
            last_submit_attempt_at: None,
            submit_retry_count: 0,
            awaiting_turn_completion: false,
            recent_output: String::new(),
            saw_ready_banner: false,
            handled_model_upgrade_prompt: false,
            handled_codex_update_prompt: false,
            handled_trust_directory_prompt: false,
            handled_sandbox_setup_prompt: false,
            handled_codex_repair_prompt: false,
            handled_generic_startup_option_prompt: false,
            observed_terminal_view_revision: 0,
            observed_terminal_view_text: String::new(),
            observed_current_input_placeholder: false,
            last_prompt_sent_view_revision: None,
            isolated_codex_home: None,
            launched_at: None,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        let mut launch_config = self.config.clone();
        let mut terminal_env = HashMap::new();
        if launch_config.agent_driver == AgentDriverKind::Codex {
            let isolated_home = prepare_isolated_codex_home(&launch_config)?;
            launch_config.codex_home = isolated_home.home.clone();
            launch_config.codex_config_path = isolated_home.home.join("config.toml");
            launch_config.codex_auth_path = isolated_home.home.join("auth.json");
            terminal_env.insert(
                "CODEX_HOME".to_string(),
                isolated_home.home.to_string_lossy().to_string(),
            );
            self.isolated_codex_home = Some(isolated_home);
        }
        let mut launch =
            self.build_launch_for_runtime_config(&launch_config, &self.config.clone())?;
        if launch_config.agent_driver == AgentDriverKind::Codex {
            if let Some(session_id) = launch.session_id.as_deref().filter(|_| launch.resumed) {
                let binding = session_binding_key(&self.config, &self.endpoint);
                let bound_session_path = self.store.get_bound_session_path(&binding);
                let copied_session = copy_codex_resume_session_to_isolated_home(
                    &self.config.codex_home,
                    &launch_config.codex_home,
                    &self.endpoint.workdir,
                    session_id,
                    bound_session_path.as_deref(),
                )?;
                self.store
                    .set_bound_session_id(&binding, session_id, Some(&copied_session))?;
                if let Some(isolated) = self.isolated_codex_home.as_mut() {
                    add_codex_session_baseline_file(
                        &mut isolated.session_baseline,
                        &isolated.home,
                        &copied_session,
                    );
                }
            }
            ensure_codex_unattended_state(&launch_config.codex_home)?;
            apply_codex_endpoint_with_model_context_window(
                &self.endpoint,
                &launch_config.codex_config_path,
                &launch_config.codex_auth_path,
                &launch_config.codex_provider_name,
                launch_config.codex_model_context_window,
            )?;
            terminal_env.insert("OPENAI_API_KEY".to_string(), self.endpoint.api_key.clone());
            launch.command =
                codex_command_with_cli_overrides(launch.command, &self.endpoint, &launch_config);
        }
        let terminal = TerminalSession::start_with_env(
            &launch.command,
            self.endpoint.workdir.clone(),
            30,
            120,
            1_000_000,
            &terminal_env,
        )?;
        terminal.push_local_output(&format!(
            "> 启动 Agent: {}\r\n",
            display_agent_command(&launch.command)
        ));
        if let Ok((program, args)) = resolved_command_parts(&launch.command) {
            terminal.push_local_output(&format!(
                "> PTY 实际进程: {}{}\r\n",
                program,
                display_command_args_suffix(&args)
            ));
        }
        if let Some(pid) = terminal.process_id() {
            terminal.push_local_output(&format!("> PTY PID: {pid}\r\n"));
        }
        let direct_pollution_keywords = if self.endpoint.guard_proxy.enabled
            && self.endpoint.guard_proxy.replace_direct_pollution_detection
        {
            Vec::new()
        } else {
            launch_config.polluted_response_keywords.clone()
        };
        self.monitor = match launch_config.agent_driver {
            AgentDriverKind::Codex => Some(AgentSessionMonitor::Codex(
                CodexSessionMonitor::new_with_continuation_trigger_rules(
                    launch_config.codex_home.clone(),
                    self.endpoint.workdir.clone(),
                    Utc::now(),
                    launch.session_id.clone(),
                    direct_pollution_keywords.clone(),
                    launch_config.completion_pause_keywords.clone(),
                    launch_config.continuation_trigger_rules.clone(),
                    launch_config.polluted_response_threshold,
                    launch_config.polluted_context_window,
                    launch_config.polluted_check_max_chars,
                ),
            )),
            AgentDriverKind::ClaudeCode => Some(AgentSessionMonitor::Claude(
                ClaudeSessionMonitor::new_with_continuation_trigger_rules(
                    launch_config
                        .agent_home
                        .clone()
                        .unwrap_or_else(|| home_dir().join(".claude")),
                    self.endpoint.workdir.clone(),
                    Utc::now(),
                    launch.session_id.clone(),
                    direct_pollution_keywords.clone(),
                    launch_config.completion_pause_keywords.clone(),
                    launch_config.continuation_trigger_rules.clone(),
                    launch_config.polluted_response_threshold,
                    launch_config.polluted_context_window,
                    launch_config.polluted_check_max_chars,
                ),
            )),
            AgentDriverKind::OpenCode => Some(AgentSessionMonitor::OpenCode(
                OpenCodeSessionMonitor::new_with_continuation_trigger_rules(
                    command_args(&launch.command),
                    self.endpoint.workdir.clone(),
                    Utc::now(),
                    launch.session_id.clone(),
                    direct_pollution_keywords.clone(),
                    launch_config.completion_pause_keywords.clone(),
                    launch_config.continuation_trigger_rules.clone(),
                    launch_config.polluted_response_threshold,
                    launch_config.polluted_context_window,
                    launch_config.polluted_check_max_chars,
                ),
            )),
            AgentDriverKind::Generic => None,
        };
        self.launch = Some(launch);
        self.terminal = Some(terminal);
        self.launched_at = Some(Instant::now());
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(terminal) = self.terminal.take() {
            terminal.stop();
        }
        self.monitor = None;
        if let Some(isolated) = self.isolated_codex_home.take() {
            let _ = merge_codex_sessions_back_with_baseline(
                &isolated.home,
                &isolated.source_home,
                &isolated.session_baseline,
            );
        }
    }

    pub fn is_running(&self) -> bool {
        self.terminal
            .as_ref()
            .is_some_and(TerminalSession::is_running)
    }

    pub fn poll_monitor(&mut self) {
        self.drain_terminal_events();
        self.refresh_observed_terminal_view_text();
        self.handle_terminal_prompts();
        let mut discovered_session = false;
        if let Some(monitor) = self.monitor.as_mut() {
            monitor.poll();
            if let Some(session_id) = monitor.session_id() {
                if let Some(launch) = self.launch.as_mut() {
                    launch.session_id.get_or_insert(session_id);
                }
                discovered_session = true;
            }
            self.pollution_detected |= monitor.take_pollution_detected();
            self.completion_pause_detected |= monitor.take_completion_pause_detected();
            if self.continuation_trigger_prompt.is_none() {
                self.continuation_trigger_prompt = monitor.take_continuation_trigger_prompt();
            }
            self.endpoint_failure_detected |= monitor.take_endpoint_failure_detected();
            if !monitor.token_usage_total().is_empty() {
                self.token_usage_total = monitor.token_usage_total();
            }
        }
        if discovered_session {
            let _ = self.capture_session_id(&self.endpoint.workdir.clone());
        }
    }

    pub fn terminal_snapshot(&self) -> Option<TerminalSnapshot> {
        self.terminal.as_ref().map(TerminalSession::snapshot)
    }

    pub fn terminal_control(&self) -> Option<TerminalControl> {
        self.terminal.as_ref().map(TerminalSession::control)
    }

    pub fn set_terminal_activity_wakeup(&self, wakeup: Option<TerminalActivityWakeup>) {
        if let Some(terminal) = &self.terminal {
            terminal.set_activity_wakeup(wakeup);
        }
    }

    pub fn terminal_output_text(&self) -> String {
        self.terminal
            .as_ref()
            .map(TerminalSession::output_text)
            .unwrap_or_default()
    }

    pub fn terminal_output_delta_from(&self, start: usize) -> (String, usize) {
        self.terminal
            .as_ref()
            .map(|terminal| terminal.output_delta_from(start))
            .unwrap_or_default()
    }

    pub fn terminal_output_revision(&self) -> u64 {
        self.terminal
            .as_ref()
            .map(TerminalSession::output_revision)
            .unwrap_or_default()
    }

    pub fn terminal_view_revision(&self) -> u64 {
        self.terminal
            .as_ref()
            .map(TerminalSession::view_revision)
            .unwrap_or_default()
    }

    pub fn terminal_view(&self) -> Option<TerminalView> {
        self.terminal.as_ref().map(TerminalSession::view)
    }

    pub fn terminal_process_id(&self) -> Option<u32> {
        self.terminal.as_ref().and_then(TerminalSession::process_id)
    }

    pub fn last_activity_instant(&self) -> Option<Instant> {
        let terminal = self
            .terminal
            .as_ref()
            .map(TerminalSession::last_output_instant);
        let session = self
            .monitor
            .as_ref()
            .and_then(AgentSessionMonitor::last_session_append_instant);
        match (terminal, session) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        }
    }

    pub fn mark_user_input_active(&self, active: bool) {
        if let Some(terminal) = &self.terminal {
            terminal.mark_user_input_active(active);
        }
    }

    pub fn write_user_input(&self, text: &str) -> Result<(), TerminalError> {
        self.terminal
            .as_ref()
            .ok_or(TerminalError::NotRunning)?
            .write_input(text, InputSource::User)
    }

    pub fn resize_terminal(&self, rows: u16, cols: u16) -> Result<(), TerminalError> {
        self.terminal
            .as_ref()
            .ok_or(TerminalError::NotRunning)?
            .resize(rows, cols)
    }

    pub fn scroll_terminal(&self, delta: i32) -> Result<(), TerminalError> {
        self.terminal
            .as_ref()
            .ok_or(TerminalError::NotRunning)?
            .scroll_display(delta);
        Ok(())
    }

    pub fn scroll_terminal_bottom(&self) -> Result<(), TerminalError> {
        self.terminal
            .as_ref()
            .ok_or(TerminalError::NotRunning)?
            .scroll_bottom();
        Ok(())
    }

    pub fn scroll_terminal_to_offset(&self, offset: usize) -> Result<(), TerminalError> {
        self.terminal
            .as_ref()
            .ok_or(TerminalError::NotRunning)?
            .scroll_to_offset(offset);
        Ok(())
    }

    pub fn clear_terminal_local_view(&self) -> Result<(), TerminalError> {
        self.terminal
            .as_ref()
            .ok_or(TerminalError::NotRunning)?
            .clear_local_view();
        Ok(())
    }

    pub fn send_prompt(&mut self, prompt: &str) -> Result<(), TerminalError> {
        self.poll_monitor();
        if !self.can_send_prompt() {
            return Err(TerminalError::AutoInputBlocked(
                "agent is not ready for automatic prompt".to_string(),
            ));
        }
        let terminal = self.terminal.as_ref().ok_or(TerminalError::NotRunning)?;
        let prompt_text;
        let prompt = if self.config.agent_driver == AgentDriverKind::Codex {
            prompt_text = codex_auto_prompt_input_text(prompt);
            prompt_text.as_str()
        } else {
            prompt
        };
        terminal.send_prompt(
            prompt,
            &self.config.prompt_submit_sequence,
            InputSource::Auto,
        )?;
        let sent_view_revision = terminal.view_revision();
        self.clear_stale_terminal_failure_signals();
        let now = Instant::now();
        self.last_prompt_sent_at = Some(now);
        self.last_submit_attempt_at = Some(now);
        self.last_prompt_sent_view_revision = Some(sent_view_revision);
        self.submit_retry_count = 0;
        self.awaiting_turn_completion = true;
        self.saw_ready_banner = false;
        self.observed_terminal_view_revision = 0;
        self.observed_terminal_view_text.clear();
        if let Some(monitor) = self.monitor.as_mut() {
            monitor.begin_waiting_for_new_turn();
        }
        Ok(())
    }

    fn clear_stale_terminal_failure_signals(&mut self) {
        self.recent_output.clear();
        self.endpoint_failure_detected = false;
        self.transient_endpoint_failure_detected = false;
        self.endpoint_failure_status_code = None;
        self.endpoint_failure_retry_after_seconds = None;
    }

    pub fn retry_submit(&mut self) -> Result<(), TerminalError> {
        let terminal = self.terminal.as_ref().ok_or(TerminalError::NotRunning)?;
        terminal.write_input(
            submit_sequence_text(&self.config.prompt_submit_sequence),
            InputSource::Auto,
        )?;
        self.last_submit_attempt_at = Some(Instant::now());
        self.submit_retry_count += 1;
        Ok(())
    }

    pub fn is_idle(&mut self, idle_seconds: f64, inflight_idle_fallback_seconds: f64) -> bool {
        self.poll_monitor();
        let Some(terminal) = &self.terminal else {
            return false;
        };
        if !terminal.is_running() {
            return false;
        }
        let recent_elapsed = self.recent_activity_elapsed();
        let current_view_ready = self.current_terminal_view_ready();
        let current_view_busy = self.current_terminal_view_busy();
        let ready_unlock_allowed = !self.codex_ready_unlock_grace_active();
        if let Some(monitor) = self.monitor.as_mut() {
            if self.awaiting_turn_completion {
                if self.saw_ready_banner && current_view_ready && ready_unlock_allowed {
                    self.awaiting_turn_completion = false;
                    return true;
                }
                if current_view_busy {
                    return false;
                }
                if monitor.has_inflight_turn() {
                    if recent_elapsed >= Duration::from_secs_f64(inflight_idle_fallback_seconds) {
                        monitor.mark_turn_completed_by_idle();
                        self.awaiting_turn_completion = false;
                        return true;
                    }
                    return false;
                }
                if monitor.last_task_finished() {
                    if monitor.has_assistant_message_since_wait_start()
                        || (self.saw_ready_banner && current_view_ready && ready_unlock_allowed)
                    {
                        self.awaiting_turn_completion = false;
                        return true;
                    }
                    if recent_elapsed >= Duration::from_secs_f64(inflight_idle_fallback_seconds) {
                        monitor.mark_turn_completed_by_idle();
                        self.awaiting_turn_completion = false;
                        return true;
                    }
                    return false;
                }
                if monitor.last_task_started() {
                    if recent_elapsed >= Duration::from_secs_f64(inflight_idle_fallback_seconds) {
                        monitor.mark_turn_completed_by_idle();
                        self.awaiting_turn_completion = false;
                        return true;
                    }
                    return false;
                }
                if recent_elapsed >= Duration::from_secs_f64(inflight_idle_fallback_seconds) {
                    monitor.mark_turn_completed_by_idle();
                    self.awaiting_turn_completion = false;
                    return true;
                }
                return false;
            }
        }
        if !self.awaiting_turn_completion
            && self.last_prompt_sent_at.is_none()
            && self.saw_ready_banner
        {
            return true;
        }
        let quiet = recent_elapsed >= Duration::from_secs_f64(idle_seconds);
        if quiet && self.awaiting_turn_completion {
            self.awaiting_turn_completion = false;
        }
        quiet && !self.awaiting_turn_completion
    }

    pub fn can_send_prompt(&self) -> bool {
        if self.awaiting_turn_completion || !self.startup_ready_for_prompt() {
            return false;
        }
        if codex_prefilled_input_visible(
            &self.observed_terminal_view_text,
            self.observed_current_input_placeholder,
        ) {
            return false;
        }
        if self.current_terminal_view_busy() {
            if self.stale_working_prompt_can_unlock() {
                return true;
            }
            return self.monitor.as_ref().is_some_and(
                AgentSessionMonitor::has_completed_assistant_message_since_wait_start,
            );
        }
        true
    }

    pub fn auto_input_block_reason(&self) -> Option<&'static str> {
        if self.awaiting_turn_completion {
            return Some("等待上一轮完成");
        }
        if !self.startup_ready_for_prompt() {
            if self.config.agent_driver == AgentDriverKind::Codex
                && codex_update_prompt_visible(&self.recent_output)
            {
                return Some("等待 Codex 更新确认");
            }
            return Some("等待 Codex 就绪");
        }
        if codex_prefilled_input_visible(
            &self.observed_terminal_view_text,
            self.observed_current_input_placeholder,
        ) {
            return Some("输入框已有内容");
        }
        if self.current_terminal_view_busy() {
            if self.stale_working_prompt_can_unlock()
                || self.monitor.as_ref().is_some_and(
                    AgentSessionMonitor::has_completed_assistant_message_since_wait_start,
                )
            {
                return None;
            }
            if codex_queued_message_visible(&self.observed_terminal_view_text) {
                return Some("已有排队消息");
            }
            if codex_working_prompt_visible(&self.observed_terminal_view_text) {
                if self.config.agent_driver == AgentDriverKind::Codex
                    && self.last_prompt_sent_at.is_none()
                {
                    return Some("等待 Codex 就绪");
                }
                return Some("检测到 Working");
            }
            return Some("终端忙碌");
        }
        None
    }

    pub fn auto_wait_safely_released(&self) -> bool {
        if self.awaiting_turn_completion {
            return false;
        }
        if self.current_terminal_view_busy() {
            if self.stale_working_prompt_can_unlock() {
                return true;
            }
            return self.monitor.as_ref().is_some_and(
                AgentSessionMonitor::has_completed_assistant_message_since_wait_start,
            );
        }
        if self
            .monitor
            .as_ref()
            .is_some_and(AgentSessionMonitor::has_assistant_message_since_wait_start)
        {
            return true;
        }
        self.saw_ready_banner
            && self.current_terminal_view_ready()
            && !self.codex_ready_unlock_grace_active()
    }

    pub fn needs_submit_retry(&self, retry_seconds: f64) -> bool {
        if !self.startup_ready_for_prompt() {
            return false;
        }
        if self.current_terminal_view_busy() {
            return false;
        }
        let visible_prefilled_input = codex_prefilled_input_visible(
            &self.observed_terminal_view_text,
            self.observed_current_input_placeholder,
        );
        if !self.awaiting_turn_completion && !visible_prefilled_input {
            return false;
        }
        if let Some(monitor) = &self.monitor {
            if !visible_prefilled_input
                && (monitor.has_inflight_turn() || monitor.last_task_started())
            {
                return false;
            }
        }
        self.last_submit_attempt_at
            .is_some_and(|at| at.elapsed() >= Duration::from_secs_f64(retry_seconds))
    }

    pub fn is_turn_stalled(&mut self, stall_seconds: f64) -> bool {
        self.poll_monitor();
        let Some(_terminal) = &self.terminal else {
            return false;
        };
        if !self.awaiting_turn_completion {
            return false;
        }
        let stall_after = Duration::from_secs_f64(stall_seconds);
        if self
            .monitor
            .as_ref()
            .is_some_and(|monitor| monitor.session_tail_stalled(stall_after))
        {
            return true;
        }
        self.recent_activity_elapsed() >= stall_after
    }

    pub fn has_assistant_message_since_prompt(&mut self) -> bool {
        if self.has_session_assistant_message_since_prompt() {
            return true;
        }
        self.terminal_had_activity_since_prompt()
    }

    pub fn has_session_assistant_message_since_prompt(&mut self) -> bool {
        self.poll_monitor();
        self.monitor
            .as_ref()
            .is_some_and(AgentSessionMonitor::has_codex_assistant_message_since_wait_start)
    }

    fn terminal_had_activity_since_prompt(&self) -> bool {
        self.last_prompt_sent_at
            .map(|sent| {
                self.terminal
                    .as_ref()
                    .is_some_and(|terminal| terminal.last_activity_elapsed() < sent.elapsed())
            })
            .unwrap_or(true)
    }

    pub fn clear_completion_pause_detected(&mut self) {
        self.completion_pause_detected = false;
        if let Some(monitor) = self.monitor.as_mut() {
            monitor.clear_completion_pause_detected();
        }
    }

    pub fn take_continuation_trigger_prompt(&mut self) -> Option<String> {
        std::mem::take(&mut self.continuation_trigger_prompt)
    }

    pub fn mark_current_turn_failed(&mut self) {
        self.awaiting_turn_completion = false;
        self.submit_retry_count = 0;
        self.recent_output.clear();
        self.endpoint_failure_status_code = None;
        self.endpoint_failure_retry_after_seconds = None;
        if let Some(monitor) = self.monitor.as_mut() {
            monitor.mark_turn_completed_by_idle();
        }
    }

    pub fn capture_session_id(&mut self, _workdir: &Path) -> Result<()> {
        if !self.config.restore_sessions {
            return Ok(());
        }
        if let Some(session_id) = self
            .launch
            .as_ref()
            .and_then(|launch| launch.session_id.as_deref())
        {
            let key = session_binding_key(&self.config, &self.endpoint);
            let session_path = self.store.get_bound_session_path(&key);
            self.store
                .set_bound_session_id(&key, session_id, session_path.as_deref())?;
        }
        Ok(())
    }

    pub fn build_launch(&mut self) -> Result<AgentLaunch> {
        let config = self.config.clone();
        self.build_launch_for_config(&config)
    }

    fn build_launch_for_config(&mut self, config: &AppConfig) -> Result<AgentLaunch> {
        let codex_index = CodexSessionIndex::new(config.codex_home.clone());
        build_agent_launch_with_policy(
            config,
            &self.endpoint,
            &mut self.store,
            &codex_index,
            self.force_new_session,
            MissingSessionPolicy::New,
        )
    }

    fn build_launch_for_runtime_config(
        &mut self,
        runtime_config: &AppConfig,
        restore_config: &AppConfig,
    ) -> Result<AgentLaunch> {
        build_agent_launch_for_codex_restore_home(
            runtime_config,
            restore_config,
            &self.endpoint,
            &mut self.store,
            self.force_new_session,
            MissingSessionPolicy::New,
        )
    }

    fn drain_terminal_events(&mut self) {
        let Some(events) = self.terminal.as_ref().map(|terminal| terminal.events()) else {
            return;
        };
        let mut saw_exit = false;
        for event in events.try_iter().collect::<Vec<_>>() {
            match event {
                crate::terminal::TerminalEvent::Output(text) => self.observe_output_text(&text),
                crate::terminal::TerminalEvent::Exit(status) => {
                    saw_exit = true;
                    if let Some(status) = status {
                        if let Some(terminal) = &self.terminal {
                            terminal.push_local_output(&format!("> 终端退出状态: {status}\r\n"));
                        }
                    }
                }
            }
        }
        if saw_exit {
            if let Some(terminal) = &self.terminal {
                terminal.push_local_output("> 终端进程已退出\r\n");
            }
        }
    }

    fn observe_output_text(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        const READY_BUFFER_LIMIT: usize = 4096;
        self.recent_output.push_str(text);
        if self.recent_output.len() > READY_BUFFER_LIMIT {
            self.recent_output = utf8_tail(&self.recent_output, READY_BUFFER_LIMIT);
        }
        if is_endpoint_failure_text(&self.recent_output) {
            self.endpoint_failure_detected = true;
            self.endpoint_failure_status_code = endpoint_failure_status_code(&self.recent_output);
            self.endpoint_failure_retry_after_seconds =
                endpoint_failure_cooldown_seconds(&self.recent_output);
        }
        if is_transient_endpoint_failure_text(&self.recent_output) {
            self.transient_endpoint_failure_detected = true;
        }
        if !self.saw_ready_banner && ready_banner_visible(&self.recent_output) {
            self.saw_ready_banner = true;
        }
    }

    fn handle_terminal_prompts(&mut self) {
        if self.handled_model_upgrade_prompt
            && self.handled_codex_update_prompt
            && self.handled_trust_directory_prompt
            && self.handled_sandbox_setup_prompt
            && self.handled_codex_repair_prompt
            && self.handled_generic_startup_option_prompt
        {
            return;
        }
        let observed = self.observed_terminal_text();
        let observed = observed.as_str();
        if !self.handled_model_upgrade_prompt
            && model_upgrade_prompt_visible(observed)
            && self.write_auto_terminal_input(
                submit_sequence_text(&self.config.prompt_submit_sequence).to_string(),
            )
        {
            self.handled_model_upgrade_prompt = true;
        }
        if !self.handled_codex_update_prompt
            && codex_update_prompt_visible(observed)
            && self.write_auto_terminal_input(format!(
                "3{}",
                submit_sequence_text(&self.config.prompt_submit_sequence)
            ))
        {
            self.handled_codex_update_prompt = true;
        }
        if !self.handled_trust_directory_prompt
            && trust_directory_prompt_visible(observed)
            && self.write_auto_terminal_input(trust_directory_prompt_response(
                &self.config.prompt_submit_sequence,
            ))
        {
            self.handled_trust_directory_prompt = true;
        }
        if !self.handled_sandbox_setup_prompt
            && sandbox_setup_prompt_visible(observed)
            && self.write_auto_terminal_input(format!(
                "2{}",
                submit_sequence_text(&self.config.prompt_submit_sequence)
            ))
        {
            self.handled_sandbox_setup_prompt = true;
        }
        if !self.handled_codex_repair_prompt
            && codex_repair_prompt_visible(observed)
            && self.write_auto_terminal_input(format!(
                "y{}",
                submit_sequence_text(&self.config.prompt_submit_sequence)
            ))
        {
            self.handled_codex_repair_prompt = true;
        }
        if !self.handled_generic_startup_option_prompt
            && generic_first_option_prompt_visible(observed)
            && self.write_auto_terminal_input(format!(
                "1{}",
                submit_sequence_text(&self.config.prompt_submit_sequence)
            ))
        {
            self.handled_generic_startup_option_prompt = true;
        }
    }

    fn observed_terminal_text(&self) -> String {
        if self.observed_terminal_view_text.trim().is_empty() {
            return self.recent_output.clone();
        }
        if self.recent_output.is_empty() {
            self.observed_terminal_view_text.clone()
        } else {
            format!(
                "{}\n{}",
                self.recent_output, self.observed_terminal_view_text
            )
        }
    }

    fn refresh_observed_terminal_view_text(&mut self) {
        let Some(terminal) = self.terminal.as_ref() else {
            self.observed_terminal_view_revision = 0;
            self.observed_terminal_view_text.clear();
            self.observed_current_input_placeholder = false;
            return;
        };
        let revision = terminal.view_revision();
        if revision == self.observed_terminal_view_revision {
            return;
        }
        self.observed_terminal_view_revision = revision;
        let view = terminal.view();
        self.observed_current_input_placeholder = terminal_view_current_codex_input(&view)
            .is_some_and(|input| !input.text.is_empty() && input.placeholder);
        let screen = terminal_view_visible_text(&view);
        if screen.trim().is_empty() {
            self.observed_terminal_view_text.clear();
            self.observed_current_input_placeholder = false;
        } else {
            self.observed_terminal_view_text = screen;
            let view_updated_after_prompt = self
                .last_prompt_sent_view_revision
                .is_none_or(|sent_revision| revision > sent_revision);
            if !self.saw_ready_banner
                && view_updated_after_prompt
                && ready_banner_visible(&self.observed_terminal_view_text)
            {
                self.saw_ready_banner = true;
            }
        }
    }

    fn write_auto_terminal_input(&self, text: String) -> bool {
        self.terminal
            .as_ref()
            .is_some_and(|terminal| terminal.write_input(&text, InputSource::User).is_ok())
    }

    fn recent_activity_elapsed(&self) -> Duration {
        let terminal_elapsed = self
            .terminal
            .as_ref()
            .map(TerminalSession::last_activity_elapsed)
            .unwrap_or_else(|| Duration::from_secs(u64::MAX / 2));
        let session_elapsed = self
            .monitor
            .as_ref()
            .and_then(AgentSessionMonitor::last_session_append_elapsed)
            .unwrap_or_else(|| Duration::from_secs(u64::MAX / 2));
        terminal_elapsed.min(session_elapsed)
    }

    fn current_terminal_view_ready(&self) -> bool {
        !self.observed_terminal_view_text.trim().is_empty()
            && ready_banner_visible(&self.observed_terminal_view_text)
            && (self.config.agent_driver != AgentDriverKind::Codex
                || !codex_prefilled_input_visible(
                    &self.observed_terminal_view_text,
                    self.observed_current_input_placeholder,
                ))
    }

    fn current_terminal_view_busy(&self) -> bool {
        !self.observed_terminal_view_text.trim().is_empty()
            && codex_busy_prompt_visible(&self.observed_terminal_view_text)
    }

    fn stale_working_prompt_can_unlock(&self) -> bool {
        let text = self.observed_terminal_view_text.as_str();
        if text.trim().is_empty()
            || codex_queued_message_visible(text)
            || !codex_working_prompt_visible(text)
            || !codex_idle_prompt_visible(text)
            || self.codex_ready_unlock_grace_active()
        {
            return false;
        }
        self.last_prompt_sent_at
            .is_some_and(|at| at.elapsed() >= CODEX_STALE_WORKING_UNLOCK_GRACE)
            && self.recent_activity_elapsed() >= CODEX_STALE_WORKING_UNLOCK_GRACE
    }

    fn codex_ready_unlock_grace_active(&self) -> bool {
        self.config.agent_driver == AgentDriverKind::Codex
            && self
                .last_prompt_sent_at
                .is_some_and(|at| at.elapsed() < CODEX_READY_UNLOCK_GRACE)
    }

    fn startup_ready_for_prompt(&self) -> bool {
        if self.config.agent_driver != AgentDriverKind::Codex {
            return true;
        }
        if codex_update_prompt_visible(&self.recent_output) {
            return false;
        }
        if self.saw_ready_banner {
            return true;
        }
        self.launched_at
            .is_some_and(|at| at.elapsed() >= Duration::from_secs(12))
    }
}

fn utf8_tail(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut start = text.len().saturating_sub(max_bytes);
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_string()
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn build_agent_launch(
    config: &AppConfig,
    endpoint: &EndpointConfig,
    store: &mut SessionStore,
    codex_index: &CodexSessionIndex,
    force_new_session: bool,
) -> Result<AgentLaunch> {
    build_agent_launch_with_policy(
        config,
        endpoint,
        store,
        codex_index,
        force_new_session,
        MissingSessionPolicy::New,
    )
}

pub fn build_agent_launch_with_policy(
    config: &AppConfig,
    endpoint: &EndpointConfig,
    store: &mut SessionStore,
    codex_index: &CodexSessionIndex,
    force_new_session: bool,
    missing_policy: MissingSessionPolicy,
) -> Result<AgentLaunch> {
    match config.agent_driver {
        AgentDriverKind::Codex => {
            let session_id = resume_session_id(
                config,
                endpoint,
                store,
                codex_index,
                force_new_session,
                missing_policy,
            )?;
            Ok(AgentLaunch {
                command: codex_resume_command(
                    &codex_goal_feature_command(config),
                    &endpoint.workdir,
                    session_id.as_deref(),
                ),
                resumed: session_id.is_some(),
                session_id,
            })
        }
        AgentDriverKind::ClaudeCode => {
            let session_id = claude_resume_session_id(
                config,
                endpoint,
                store,
                force_new_session,
                missing_policy,
            )?;
            Ok(AgentLaunch {
                command: claude_resume_command(&config.agent_command, session_id.as_deref()),
                resumed: session_id.is_some(),
                session_id,
            })
        }
        AgentDriverKind::OpenCode => {
            if force_new_session || !config.restore_sessions {
                return Ok(AgentLaunch {
                    command: config.agent_command.clone(),
                    resumed: false,
                    session_id: None,
                });
            }
            let binding = session_binding_key(config, endpoint);
            let session_id = store
                .get_bound_session_id(&binding)
                .and_then(|session_id| {
                    if store.session_id_bound_to_other(&binding, &session_id) {
                        let _ = store.delete_bound_session_id(&binding);
                        None
                    } else {
                        Some(session_id)
                    }
                })
                .or_else(|| {
                    (missing_policy == MissingSessionPolicy::LegacyLatest)
                        .then(|| store.get_session_id(&endpoint.workdir))
                        .flatten()
                });
            if session_id.is_none() && missing_policy == MissingSessionPolicy::New {
                return Ok(AgentLaunch {
                    command: config.agent_command.clone(),
                    resumed: false,
                    session_id: None,
                });
            }
            Ok(AgentLaunch {
                command: opencode_command(&config.agent_command, session_id.as_deref()),
                resumed: session_id.is_some(),
                session_id,
            })
        }
        AgentDriverKind::Generic => Ok(AgentLaunch {
            command: config.agent_command.clone(),
            resumed: false,
            session_id: None,
        }),
    }
}

fn build_agent_launch_for_codex_restore_home(
    runtime_config: &AppConfig,
    restore_config: &AppConfig,
    endpoint: &EndpointConfig,
    store: &mut SessionStore,
    force_new_session: bool,
    missing_policy: MissingSessionPolicy,
) -> Result<AgentLaunch> {
    if runtime_config.agent_driver != AgentDriverKind::Codex {
        let index = CodexSessionIndex::new(runtime_config.codex_home.clone());
        return build_agent_launch_with_policy(
            runtime_config,
            endpoint,
            store,
            &index,
            force_new_session,
            missing_policy,
        );
    }
    let mut additional_homes = historical_isolated_codex_homes();
    additional_homes.push(runtime_config.codex_home.clone());
    let codex_index = CodexSessionIndex::new(restore_config.codex_home.clone())
        .with_additional_homes(additional_homes);
    let session_id = resume_session_id(
        restore_config,
        endpoint,
        store,
        &codex_index,
        force_new_session,
        missing_policy,
    )?;
    Ok(AgentLaunch {
        command: codex_resume_command(
            &codex_goal_feature_command(runtime_config),
            &endpoint.workdir,
            session_id.as_deref(),
        ),
        resumed: session_id.is_some(),
        session_id,
    })
}

fn claude_resume_session_id(
    config: &AppConfig,
    endpoint: &EndpointConfig,
    store: &mut SessionStore,
    force_new_session: bool,
    missing_policy: MissingSessionPolicy,
) -> Result<Option<String>> {
    if !config.restore_sessions || force_new_session {
        return Ok(None);
    }
    let binding = session_binding_key(config, endpoint);
    if let Some(session_id) = store.get_bound_session_id(&binding) {
        if store.session_id_bound_to_other(&binding, &session_id) {
            store.delete_bound_session_id(&binding)?;
            return Ok(None);
        }
        return Ok(Some(session_id));
    }
    if missing_policy == MissingSessionPolicy::New {
        return Ok(None);
    }
    let claude_home = config
        .agent_home
        .clone()
        .unwrap_or_else(|| home_dir().join(".claude"));
    let index = ClaudeSessionIndex::new(claude_home);
    if let Some(session_id) = index.find_latest_session_id_for_workdir(&endpoint.workdir) {
        store.set_session_id(&endpoint.workdir, &session_id)?;
        return Ok(Some(session_id));
    }
    Ok(None)
}

fn resume_session_id(
    config: &AppConfig,
    endpoint: &EndpointConfig,
    store: &mut SessionStore,
    index: &CodexSessionIndex,
    force_new_session: bool,
    missing_policy: MissingSessionPolicy,
) -> Result<Option<String>> {
    if !config.restore_sessions || force_new_session {
        return Ok(None);
    }
    let binding = session_binding_key(config, endpoint);
    if let Some(session_id) = store.get_bound_session_id(&binding) {
        if store.session_id_bound_to_other(&binding, &session_id) {
            store.delete_bound_session_id(&binding)?;
            return Ok(None);
        }
        if store
            .get_bound_session_path(&binding)
            .as_deref()
            .is_some_and(|path| codex_session_file_matches(path, &endpoint.workdir, &session_id))
        {
            return Ok(Some(session_id));
        }
        if let Some((_, path)) =
            index.find_latest_session_for_workdir(&endpoint.workdir, Some(&session_id))
        {
            store.set_bound_session_id(&binding, &session_id, Some(&path))?;
            return Ok(Some(session_id));
        }
        store.delete_bound_session_id(&binding)?;
    }
    if missing_policy == MissingSessionPolicy::New {
        return Ok(None);
    }
    if let Some((session_id, path)) = index.find_latest_session_for_workdir(&endpoint.workdir, None)
    {
        store.set_bound_session_id(&binding, &session_id, Some(&path))?;
        return Ok(Some(session_id));
    }
    Ok(None)
}

fn session_binding_key(config: &AppConfig, endpoint: &EndpointConfig) -> SessionBindingKey {
    SessionBindingKey {
        config_path: config.config_path.clone(),
        agent_id: config.agent_id.clone(),
        driver: agent_driver_key(config.agent_driver.clone()),
        workdir: endpoint.workdir.clone(),
    }
}

fn agent_driver_key(driver: AgentDriverKind) -> String {
    match driver {
        AgentDriverKind::Codex => "codex",
        AgentDriverKind::ClaudeCode => "claude",
        AgentDriverKind::OpenCode => "opencode",
        AgentDriverKind::Generic => "generic",
    }
    .to_string()
}

fn codex_goal_feature_command(config: &AppConfig) -> AgentCommand {
    if config.continuation_mode != ContinuationMode::Goal
        || !config.agent_goal.enabled
        || config.agent_goal.text.trim().is_empty()
    {
        return config.agent_command.clone();
    }
    match &config.agent_command {
        AgentCommand::Args(items) => {
            if codex_enable_goals_present(items) {
                return config.agent_command.clone();
            }
            let mut out = Vec::new();
            if let Some(first) = items.first() {
                out.push(first.clone());
                out.push("--enable".to_string());
                out.push("goals".to_string());
                out.extend(items.iter().skip(1).cloned());
            }
            AgentCommand::Args(out)
        }
        AgentCommand::Shell(_) => config.agent_command.clone(),
    }
}

fn codex_enable_goals_present(items: &[String]) -> bool {
    let mut iter = items.iter();
    while let Some(item) = iter.next() {
        if item == "--enable" && iter.next().is_some_and(|value| value == "goals") {
            return true;
        }
        if item == "--enable=goals" {
            return true;
        }
        if item == "-c"
            && iter
                .next()
                .is_some_and(|value| value == "features.goals=true")
        {
            return true;
        }
        if item == "-c=features.goals=true" || item == "--config=features.goals=true" {
            return true;
        }
    }
    false
}

fn codex_resume_command(
    command: &AgentCommand,
    workdir: &Path,
    session_id: Option<&str>,
) -> AgentCommand {
    let Some(session_id) = session_id else {
        return command.clone();
    };
    match command {
        AgentCommand::Args(items) => {
            let mut out = Vec::new();
            if let Some(first) = items.first() {
                out.push(first.clone());
                out.push("resume".to_string());
                out.push("-C".to_string());
                out.push(workdir.to_string_lossy().to_string());
                out.extend(strip_codex_cd_args(items.iter().skip(1)));
                out.push(session_id.to_string());
            }
            AgentCommand::Args(out)
        }
        AgentCommand::Shell(_) => command.clone(),
    }
}

fn strip_codex_cd_args<'a>(items: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for item in items {
        if skip_next {
            skip_next = false;
            continue;
        }
        if item == "-C" || item == "--cd" {
            skip_next = true;
            continue;
        }
        if item.starts_with("--cd=") {
            continue;
        }
        out.push(item.clone());
    }
    out
}

fn claude_resume_command(command: &AgentCommand, session_id: Option<&str>) -> AgentCommand {
    let Some(session_id) = session_id else {
        return command.clone();
    };
    match command {
        AgentCommand::Args(items) => {
            let mut out = Vec::new();
            if let Some(first) = items.first() {
                out.push(first.clone());
                out.push("--resume".to_string());
                out.push(session_id.to_string());
                out.extend(items.iter().skip(1).cloned());
            }
            AgentCommand::Args(out)
        }
        AgentCommand::Shell(_) => command.clone(),
    }
}

fn opencode_command(command: &AgentCommand, session_id: Option<&str>) -> AgentCommand {
    match command {
        AgentCommand::Args(items) => {
            let mut out = items.clone();
            if let Some(session_id) = session_id {
                out.push("--session".to_string());
                out.push(session_id.to_string());
            } else {
                out.push("--continue".to_string());
            }
            AgentCommand::Args(out)
        }
        AgentCommand::Shell(_) => command.clone(),
    }
}

fn submit_sequence_text(sequence: &str) -> &'static str {
    match sequence {
        "crlf" => "\r\n",
        "lf" => "\n",
        _ => "\r",
    }
}

fn prepare_isolated_codex_home(config: &AppConfig) -> Result<IsolatedCodexHome> {
    let home = stable_isolated_codex_home_path(config);
    fs::create_dir_all(&home)
        .with_context(|| format!("create isolated Codex home {}", home.display()))?;

    copy_file_if_exists(&config.codex_config_path, &home.join("config.toml")).with_context(
        || {
            format!(
                "copy Codex config from {} to {}",
                config.codex_config_path.display(),
                home.join("config.toml").display()
            )
        },
    )?;
    copy_file_if_exists(&config.codex_auth_path, &home.join("auth.json")).with_context(|| {
        format!(
            "copy Codex auth from {} to {}",
            config.codex_auth_path.display(),
            home.join("auth.json").display()
        )
    })?;
    copy_file_if_exists(
        &config.codex_home.join(".codex-global-state.json"),
        &home.join(".codex-global-state.json"),
    )
    .with_context(|| {
        format!(
            "copy Codex global state from {} to {}",
            config.codex_home.join(".codex-global-state.json").display(),
            home.join(".codex-global-state.json").display()
        )
    })?;
    copy_file_if_exists(
        &config.codex_home.join("state_5.sqlite"),
        &home.join("state_5.sqlite"),
    )?;
    let session_baseline = collect_codex_session_baseline(&home);

    Ok(IsolatedCodexHome {
        home,
        source_home: config.codex_home.clone(),
        session_baseline,
    })
}

fn stable_isolated_codex_home_path(config: &AppConfig) -> PathBuf {
    app_runtime_dir()
        .join("codex-homes")
        .join(stable_config_key(config))
        .join(sanitize_path_segment(&config.agent_id))
}

fn app_runtime_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .join("Runtime")
}

fn historical_isolated_codex_homes() -> Vec<PathBuf> {
    discover_codex_session_homes(&app_runtime_dir().join("codex-homes"))
}

fn stable_config_key(config: &AppConfig) -> String {
    let raw = config
        .config_path
        .as_ref()
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_else(|| config.workdir.to_string_lossy().to_string());
    let basename = config
        .config_path
        .as_ref()
        .and_then(|path| path.file_stem())
        .and_then(|value| value.to_str())
        .unwrap_or("config");
    let hash = fnv1a64(raw.as_bytes());
    format!("{}-{:016x}", sanitize_path_segment(basename), hash)
}

fn sanitize_path_segment(value: &str) -> String {
    let clean = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric()
                || matches!(ch, '.' | '_' | '-')
                || ('\u{4e00}'..='\u{9fff}').contains(&ch)
            {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches(&['.', '_'][..])
        .to_string();
    if clean.is_empty() {
        "default".to_string()
    } else {
        clean
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn codex_command_with_cli_overrides(
    command: AgentCommand,
    endpoint: &EndpointConfig,
    config: &AppConfig,
) -> AgentCommand {
    let provider_name = fs::read_to_string(&config.codex_config_path)
        .ok()
        .and_then(|text| get_current_model_provider(&text))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| config.codex_provider_name.clone());
    let mut overrides = vec![
        "-c".to_string(),
        format!("model={}", toml_cli_string(&endpoint.model)),
        "-c".to_string(),
        format!(
            "model_reasoning_effort={}",
            toml_cli_string(&endpoint.reasoning_effort)
        ),
        "-c".to_string(),
        "sandbox_mode=\"danger-full-access\"".to_string(),
        "-c".to_string(),
        "approval_policy=\"never\"".to_string(),
        "-c".to_string(),
        "status_line=true".to_string(),
        "-c".to_string(),
        "status_line_use_colors=true".to_string(),
        "-c".to_string(),
        concat!(
            "tui.status_line=[\"model-with-reasoning\",\"context-window\",\"context-remaining\",\"current-dir\",\"git-branch\",\"context-used\",\"run-state\",\"task-progress\",\"used-",
            "to",
            "kens\",\"fast-mode\"]"
        )
        .to_string(),
        "-c".to_string(),
        "tui.show_tooltips=true".to_string(),
        "-c".to_string(),
        "tui.animations=true".to_string(),
        "-c".to_string(),
        "tui.raw_output_mode=false".to_string(),
        "-c".to_string(),
        format!("model_provider={}", toml_cli_string(&provider_name)),
        "-c".to_string(),
        format!(
            "model_providers.{}.base_url={}",
            provider_name,
            toml_cli_string(&endpoint.base_url)
        ),
    ];
    if let Some(service_tier) = endpoint
        .service_tier
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        overrides.push("-c".to_string());
        overrides.push(format!("service_tier={}", toml_cli_string(service_tier)));
    }
    if let Some(model_context_window) = config.codex_model_context_window {
        overrides.push("-c".to_string());
        overrides.push(format!("model_context_window={model_context_window}"));
    }
    match command {
        AgentCommand::Args(items) => {
            AgentCommand::Args(insert_codex_cli_overrides(items, overrides))
        }
        AgentCommand::Shell(text) => {
            let parts = split_shell_like_command(&text);
            if parts.is_empty() {
                return AgentCommand::Shell(text);
            }
            AgentCommand::Args(insert_codex_cli_overrides(parts, overrides))
        }
    }
}

fn insert_codex_cli_overrides(mut parts: Vec<String>, mut overrides: Vec<String>) -> Vec<String> {
    if parts.is_empty() {
        return parts;
    }
    if is_codex_command_part(&parts[0]) {
        parts.splice(1..1, overrides);
        return parts;
    }
    if let Some(start) = shell_wrapper_command_start(&parts) {
        if is_codex_command_part(&parts[start]) {
            parts.splice(start + 1..start + 1, overrides);
            return parts;
        }
        let nested = split_shell_like_command(&parts[start]);
        if nested
            .first()
            .is_some_and(|part| is_codex_command_part(part))
        {
            let mut replacement = Vec::with_capacity(nested.len() + overrides.len());
            replacement.push(nested[0].clone());
            replacement.append(&mut overrides);
            replacement.extend(nested.into_iter().skip(1));
            parts.splice(start..start + 1, replacement);
            return parts;
        }
    }
    parts.splice(1..1, overrides);
    parts
}

fn is_codex_command_part(part: &str) -> bool {
    agent_driver_from_command_part(part) == Some("codex")
}

fn toml_cli_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn copy_file_if_exists(source: &Path, target: &Path) -> Result<()> {
    if !source.exists() {
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }
    fs::copy(source, target).with_context(|| {
        format!(
            "copy file from {} to {}",
            source.display(),
            target.display()
        )
    })?;
    Ok(())
}

fn copy_codex_resume_session_to_isolated_home(
    source_home: &Path,
    isolated_home: &Path,
    workdir: &Path,
    session_id: &str,
    source_session_path: Option<&Path>,
) -> Result<PathBuf> {
    let source = if let Some(path) = source_session_path {
        if !codex_session_file_matches(path, workdir, session_id) {
            anyhow::bail!(
                "bound Codex session path {} does not match session {session_id} for workdir {}",
                path.display(),
                workdir.display()
            );
        }
        path.to_path_buf()
    } else {
        let index = CodexSessionIndex::new(source_home.to_path_buf());
        index
            .find_latest_session_file_for_workdir(workdir, Some(session_id))
            .with_context(|| {
                format!(
                    "find Codex session {session_id} for workdir {} in {}",
                    workdir.display(),
                    source_home.display()
                )
            })?
    };
    let relative = codex_session_relative_path(&source, source_home)?;
    let target = isolated_home.join(relative);
    if paths_equivalent(&source, &target) {
        return Ok(target);
    }
    copy_file_if_exists(&source, &target).with_context(|| {
        format!(
            "copy Codex resume session from {} to {}",
            source.display(),
            target.display()
        )
    })?;
    Ok(target)
}

fn codex_session_relative_path(source: &Path, source_home: &Path) -> Result<PathBuf> {
    if let Ok(relative) = source.strip_prefix(source_home) {
        return Ok(relative.to_path_buf());
    }
    let mut relative = PathBuf::new();
    let mut copying = false;
    for component in source.components() {
        if let std::path::Component::Normal(value) = component {
            let text = value.to_string_lossy();
            if text.eq_ignore_ascii_case("sessions")
                || text.eq_ignore_ascii_case("archived_sessions")
            {
                copying = true;
            }
        }
        if copying {
            relative.push(Path::new(component.as_os_str()));
        }
    }
    if copying {
        return Ok(relative);
    }
    anyhow::bail!(
        "session path {} is outside {} and does not contain a sessions directory",
        source.display(),
        source_home.display()
    )
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn collect_codex_session_baseline(home: &Path) -> HashMap<PathBuf, SessionFileFingerprint> {
    let mut out = HashMap::new();
    for root_name in ["sessions", "archived_sessions"] {
        let root = home.join(root_name);
        for path in jsonl_files_under(&root) {
            let relative = path
                .strip_prefix(home)
                .unwrap_or(path.as_path())
                .to_path_buf();
            if let Some(fingerprint) = session_file_fingerprint(&path) {
                out.insert(relative, fingerprint);
            }
        }
    }
    out
}

fn add_codex_session_baseline_file(
    baseline: &mut HashMap<PathBuf, SessionFileFingerprint>,
    home: &Path,
    path: &Path,
) {
    let relative = path.strip_prefix(home).unwrap_or(path).to_path_buf();
    if let Some(fingerprint) = session_file_fingerprint(path) {
        baseline.insert(relative, fingerprint);
    }
}

fn session_file_fingerprint(path: &Path) -> Option<SessionFileFingerprint> {
    let metadata = fs::metadata(path).ok()?;
    let modified_millis = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis());
    Some(SessionFileFingerprint {
        len: metadata.len(),
        modified_millis,
    })
}

fn jsonl_files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_jsonl_files_under(root, &mut out);
    out
}

fn collect_jsonl_files_under(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_jsonl_files_under(&path, out);
        } else if path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
            out.push(path);
        }
    }
}

fn merge_codex_sessions_back_with_baseline(
    temp_home: &Path,
    source_home: &Path,
    baseline: &HashMap<PathBuf, SessionFileFingerprint>,
) -> Result<()> {
    for root_name in ["sessions", "archived_sessions"] {
        let root = temp_home.join(root_name);
        for path in jsonl_files_under(&root) {
            let relative = path
                .strip_prefix(temp_home)
                .unwrap_or(path.as_path())
                .to_path_buf();
            let current = session_file_fingerprint(&path);
            if current.is_some() && baseline.get(&relative).copied() == current {
                continue;
            }
            copy_file_if_exists(&path, &source_home.join(&relative))?;
        }
    }
    copy_file_if_exists(
        &temp_home.join(".codex-global-state.json"),
        &source_home.join(".codex-global-state.json"),
    )?;
    copy_file_if_exists(
        &temp_home.join("state_5.sqlite"),
        &source_home.join("state_5.sqlite"),
    )?;
    Ok(())
}

fn command_args(command: &AgentCommand) -> Vec<String> {
    match command {
        AgentCommand::Args(items) => items.clone(),
        AgentCommand::Shell(text) => split_shell_like_command(text),
    }
}

fn display_agent_command(command: &AgentCommand) -> String {
    match command {
        AgentCommand::Args(items) => items.join(" "),
        AgentCommand::Shell(text) => text.clone(),
    }
}

fn display_command_args_suffix(args: &[String]) -> String {
    if args.is_empty() {
        String::new()
    } else {
        format!(" {}", args.join(" "))
    }
}

fn home_dir() -> std::path::PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

fn ready_banner_visible(text: &str) -> bool {
    if codex_busy_prompt_visible(text) {
        return false;
    }
    let known_ready_marker = ["Sandbox ready", "permissions: YOLO mode"]
        .iter()
        .any(|marker| text.contains(marker));
    known_ready_marker || codex_idle_prompt_visible(text)
}

fn codex_idle_prompt_visible(text: &str) -> bool {
    text.lines().any(|line| {
        let Some((_, input)) = line.split_once('›') else {
            return false;
        };
        let input = codex_visible_input_text(input);
        input.is_empty() || codex_placeholder_input_visible(input)
    })
}

fn codex_prefilled_input_visible(text: &str, current_input_placeholder: bool) -> bool {
    if codex_busy_prompt_visible(text) {
        return false;
    }
    let Some(input) = codex_current_prompt_input(text) else {
        return false;
    };
    !input.is_empty() && !current_input_placeholder && !codex_placeholder_input_visible(input)
}

fn codex_visible_input_text(input: &str) -> &str {
    input.trim()
}

fn codex_current_prompt_input(text: &str) -> Option<&str> {
    text.lines().rev().find_map(|line| {
        line.split_once('›')
            .map(|(_, input)| codex_visible_input_text(input))
    })
}

fn codex_placeholder_input_visible(input: &str) -> bool {
    const EXACT_PLACEHOLDERS: &[&str] = &[
        "Explain this codebase",
        "Run /review on my current changes",
        "Summarize recent commits",
    ];

    if EXACT_PLACEHOLDERS.contains(&input) {
        return true;
    }
    input.len() <= 96
        && input.is_ascii()
        && (input.contains("@filename") || input.contains("{feature}"))
}

fn codex_auto_prompt_input_text(prompt: &str) -> String {
    compact_whitespace(prompt)
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

fn codex_busy_prompt_visible(text: &str) -> bool {
    codex_working_prompt_visible(text) || codex_queued_message_visible(text)
}

fn codex_working_prompt_visible(text: &str) -> bool {
    text.lines().any(|line| {
        if line.contains('›') {
            return false;
        }
        let lowered = line.to_ascii_lowercase();
        let has_working = lowered.contains("working")
            || line.contains("运行中")
            || line.contains("处理中")
            || line.contains("正在执行");
        let has_interrupt_control = lowered.contains("interrupt")
            || lowered.contains("esc")
            || lowered.contains("ctrl")
            || line.contains("中断")
            || line.contains("停止");
        let has_codex_interrupt_hint = lowered.contains("esc to interrupt")
            || lowered.contains("ctrl-c to interrupt")
            || lowered.contains("ctrl+c to interrupt")
            || line.contains("esc 中断");

        (has_working && has_interrupt_control) || has_codex_interrupt_hint
    })
}

fn codex_queued_message_visible(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("messages to be submitted after next tool call")
        || lowered.contains("press esc to interrupt and send immediately")
}

fn model_upgrade_prompt_visible(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("introducing gpt-")
        && lowered.contains("choose how you'd like codex to proceed")
        && lowered.contains("try new model")
}

fn codex_update_prompt_visible(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("update available")
        && lowered.contains("update now")
        && (lowered.contains("skip until next version") || lowered.contains("skip"))
}

fn trust_directory_prompt_visible(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    (lowered.contains("do you trust the contents of this directory")
        || lowered.contains("working with untrusted contents"))
        && (lowered.contains("yes, continue")
            || lowered.contains("1. yes")
            || lowered.contains("trust the contents"))
}

fn sandbox_setup_prompt_visible(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("set up the codex agent sandbox")
        && lowered.contains("use non-admin sandbox")
        && lowered.contains("press enter to confirm")
}

fn codex_repair_prompt_visible(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("repair codex local data now?")
        && (lowered.contains("local database appears to be damaged")
            || lowered.contains("database disk image is malformed")
            || lowered.contains("failed to initialize state runtime"))
}

fn generic_first_option_prompt_visible(text: &str) -> bool {
    let lines = text.lines().collect::<Vec<_>>();
    let codex_goal_resume_context = codex_goal_resume_prompt_visible(text);
    lines.iter().enumerate().any(|(index, line)| {
        let Some(selector) = selected_first_option_selector(line) else {
            return false;
        };
        nearby_second_option(&lines, index)
            && (selector != FirstOptionSelector::CodexPromptArrow || codex_goal_resume_context)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstOptionSelector {
    Generic,
    CodexPromptArrow,
}

fn selected_first_option_selector(line: &str) -> Option<FirstOptionSelector> {
    if line
        .trim_start()
        .strip_prefix('›')
        .is_some_and(|input| input.trim_start().starts_with("1."))
    {
        return Some(FirstOptionSelector::CodexPromptArrow);
    }

    [">", "❯", "➜"].iter().find_map(|marker| {
        line.match_indices(marker)
            .any(|(index, _)| line[index + marker.len()..].trim_start().starts_with("1."))
            .then_some(FirstOptionSelector::Generic)
    })
}

fn codex_goal_resume_prompt_visible(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("resume paused goal")
        || (lowered.contains("goal:") && lowered.contains("resume goal"))
        || lowered.contains("mark it active and continue when idle")
}

fn nearby_second_option(lines: &[&str], selected_index: usize) -> bool {
    let start = selected_index.saturating_sub(2);
    let end = lines.len().min(selected_index.saturating_add(4));
    lines[start..end]
        .iter()
        .any(|line| line_has_numbered_option(line, "2."))
}

fn line_has_numbered_option(line: &str, option: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with(option)
        || trimmed.contains(&format!(" {option}"))
        || trimmed.contains(&format!("\t{option}"))
}

fn trust_directory_prompt_response(submit_sequence: &str) -> String {
    submit_sequence_text(submit_sequence).to_string()
}

fn terminal_view_visible_text(view: &TerminalView) -> String {
    if view.rows == 0 || view.cols == 0 {
        return String::new();
    }
    let mut text = String::new();
    for row in 0..view.rows {
        if row > 0 {
            text.push('\n');
        }
        let start = row.saturating_mul(view.cols);
        let end = start.saturating_add(view.cols).min(view.cells.len());
        let line = view.cells[start..end]
            .iter()
            .filter(|cell| !cell.hidden && !cell.wide_spacer)
            .map(|cell| cell.c)
            .collect::<String>();
        text.push_str(line.trim_end());
    }
    text
}

struct CodexCurrentInput {
    text: String,
    placeholder: bool,
}

fn terminal_view_current_codex_input(view: &TerminalView) -> Option<CodexCurrentInput> {
    if view.rows == 0 || view.cols == 0 {
        return None;
    }
    for row in (0..view.rows).rev() {
        let start = row.saturating_mul(view.cols);
        let end = start.saturating_add(view.cols).min(view.cells.len());
        let cells = &view.cells[start..end];
        let Some(prompt_col) = cells
            .iter()
            .position(|cell| !cell.hidden && !cell.wide_spacer && cell.c == '›')
        else {
            continue;
        };
        let input_cells = &cells[prompt_col.saturating_add(1)..];
        let first = input_cells
            .iter()
            .position(|cell| !cell.hidden && !cell.wide_spacer && !cell.c.is_whitespace())?;
        let last = input_cells
            .iter()
            .rposition(|cell| !cell.hidden && !cell.wide_spacer && !cell.c.is_whitespace())?;
        let visible = &input_cells[first..=last];
        let text = visible
            .iter()
            .filter(|cell| !cell.hidden && !cell.wide_spacer)
            .map(|cell| cell.c)
            .collect::<String>();
        let placeholder = visible
            .iter()
            .filter(|cell| !cell.hidden && !cell.wide_spacer && !cell.c.is_whitespace())
            .all(|cell| cell.dim || is_muted_placeholder_rgb(cell.fg));
        return Some(CodexCurrentInput { text, placeholder });
    }
    None
}

fn is_muted_placeholder_rgb(rgb: crate::terminal_emulator::TerminalRgb) -> bool {
    let max = rgb.r.max(rgb.g).max(rgb.b);
    let min = rgb.r.min(rgb.g).min(rgb.b);
    max <= 180 && min >= 70 && max.saturating_sub(min) <= 40
}

fn is_endpoint_failure_text(text: &str) -> bool {
    let haystack = text.to_ascii_lowercase();
    if endpoint_failure_status_code(&haystack).is_some() {
        return true;
    }
    if endpoint_failure_cooldown_seconds(text).is_some()
        && endpoint_failure_cooldown_marker_visible(text, &haystack)
    {
        return true;
    }
    [
        "insufficient quota",
        "insufficient_quota",
        "quota exceeded",
        "quota_exceeded",
        "insufficient balance",
        "余额不足",
        "额度不足",
        "无可用额度",
        "daily limit",
        "usage limit",
        "billing",
        "payment required",
        "rate limit",
        "rate_limit",
        "key_switch_cooldown",
        "切换key需要冷却",
        "connection error",
        "connection reset",
        "econnreset",
        "unexpected status 502",
        "unexpected status 503",
        "unexpected status 504",
        "guard proxy local failure",
        "smart proxy local failure",
        "smart proxy upstream unavailable",
        "aggregate upstream unavailable",
        "upstream unavailable",
        "bad gateway",
        "service unavailable",
    ]
    .iter()
    .any(|keyword| haystack.contains(keyword))
}

fn endpoint_failure_cooldown_seconds(text: &str) -> Option<u64> {
    cooldown_seconds_from_text(text, 20)
}

fn endpoint_failure_cooldown_marker_visible(text: &str, haystack: &str) -> bool {
    haystack.contains("error")
        || haystack.contains("cooldown")
        || haystack.contains("rate limit")
        || haystack.contains("rate_limit")
        || haystack.contains("retry after")
        || haystack.contains("retry-after")
        || haystack.contains("retry in")
        || haystack.contains("try again")
        || haystack.contains("too many requests")
        || haystack.contains("limit_type")
        || haystack.contains("\"code\"")
        || text.contains("冷却")
        || text.contains("限流")
}

fn endpoint_failure_status_code(text: &str) -> Option<u16> {
    let haystack = text.to_ascii_lowercase();
    for marker in [
        "unexpected status",
        "http status",
        "status code",
        "status:",
        "status ",
        "http/",
        "http ",
    ] {
        let mut rest = haystack.as_str();
        while let Some(index) = rest.find(marker) {
            let after = &rest[index + marker.len()..];
            let status_code = if marker == "http/" {
                http_protocol_status_code(after)
            } else {
                first_http_error_status_code(after)
            };
            if let Some(code) = status_code {
                return Some(code);
            }
            rest = &after[after.char_indices().nth(1).map_or(after.len(), |(i, _)| i)..];
        }
    }
    None
}

fn first_http_error_status_code(text: &str) -> Option<u16> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len()
        && (bytes[index].is_ascii_whitespace()
            || matches!(bytes[index], b':' | b'=' | b'-' | b'(' | b'['))
    {
        index += 1;
    }
    if index + 3 <= bytes.len()
        && bytes[index].is_ascii_digit()
        && bytes[index + 1].is_ascii_digit()
        && bytes[index + 2].is_ascii_digit()
    {
        let after_is_digit = index + 3 < bytes.len() && bytes[index + 3].is_ascii_digit();
        if !after_is_digit {
            let code = std::str::from_utf8(&bytes[index..index + 3])
                .ok()
                .and_then(|value| value.parse::<u16>().ok())?;
            if (400..600).contains(&code) {
                return Some(code);
            }
        }
    }
    None
}

fn http_protocol_status_code(text: &str) -> Option<u16> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
        index += 1;
    }
    first_http_error_status_code(&text[index..])
}

fn is_transient_endpoint_failure_text(text: &str) -> bool {
    let haystack = text.to_ascii_lowercase();
    [
        "stream disconnected",
        "error sending request",
        "etimedout",
        "econnaborted",
        "broken pipe",
        "os error 10035",
        "os error 10054",
        "os error 10053",
        "gateway timeout",
        "timed out",
        "timeout",
    ]
    .iter()
    .any(|keyword| haystack.contains(keyword))
}

#[allow(dead_code)]
fn _launch_started_at() -> chrono::DateTime<Utc> {
    Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentCommand, AgentDriver};
    use chrono::Utc;
    use serde_json::json;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    fn endpoint(workdir: PathBuf) -> EndpointConfig {
        EndpointConfig {
            name: "primary".to_string(),
            base_url: "https://api.example.test".to_string(),
            api_key: "key".to_string(),
            model: "gpt-test".to_string(),
            probe_model: None,
            reasoning_effort: "high".to_string(),
            service_tier: Some("fast".to_string()),
            initial_prompt: "init".to_string(),
            auto_prompt: "auto".to_string(),
            workdir,
            weight: 100,
            enabled: true,
            probe_url: None,
            guard_proxy: Default::default(),
        }
    }

    fn config(
        workdir: PathBuf,
        driver: AgentDriver,
        command: AgentCommand,
        state_path: PathBuf,
        codex_home: PathBuf,
    ) -> AppConfig {
        AppConfig {
            agent_id: "default".to_string(),
            endpoints: vec![endpoint(workdir.clone())],
            config_path: None,
            workdir,
            continuation_mode: ContinuationMode::Auto,
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
            endpoint_failure_threshold: 3,
            endpoint_recovery_threshold: 2,
            agent_driver: driver,
            agent_command: command,
            agent_home: None,
            codex_config_path: PathBuf::from("config.toml"),
            codex_auth_path: PathBuf::from("auth.json"),
            codex_home,
            session_state_path: state_path,
            restore_sessions: true,
            codex_provider_name: "custom".to_string(),
            codex_model_context_window: None,
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

    fn assert_session_monitor_signals_are_consumed_once(
        driver: AgentDriver,
        monitor: AgentSessionMonitor,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let cfg = config(
            workdir.clone(),
            driver,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            tmp.path().join(".codex"),
        );
        let endpoint = cfg.endpoints[0].clone();
        let mut agent = AgentProcess::new(cfg, endpoint, false);
        agent.monitor = Some(monitor);

        agent.poll_monitor();
        assert!(agent.pollution_detected);
        assert!(agent.completion_pause_detected);

        agent.pollution_detected = false;
        agent.completion_pause_detected = false;
        agent.endpoint_failure_detected = false;
        agent.poll_monitor();
        assert!(!agent.pollution_detected);
        assert!(!agent.completion_pause_detected);
        assert!(!agent.endpoint_failure_detected);
    }

    #[test]
    fn session_monitor_pollution_and_pause_signals_are_consumed_once() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().join(".codex"),
            workdir.clone(),
            Utc::now(),
            None,
            vec![],
            vec![],
            0.35,
            12,
            300,
        );
        monitor.pollution_detected = true;
        monitor.completion_pause_detected = true;
        monitor.endpoint_failure_detected = true;
        assert_session_monitor_signals_are_consumed_once(
            AgentDriver::Codex,
            AgentSessionMonitor::Codex(monitor),
        );

        let mut monitor = ClaudeSessionMonitor::new(
            tmp.path().join(".claude"),
            workdir.clone(),
            Utc::now(),
            None,
            vec![],
            vec![],
            0.35,
            12,
            300,
        );
        monitor.pollution_detected = true;
        monitor.completion_pause_detected = true;
        assert_session_monitor_signals_are_consumed_once(
            AgentDriver::ClaudeCode,
            AgentSessionMonitor::Claude(monitor),
        );

        let mut monitor = OpenCodeSessionMonitor::new(
            vec!["opencode".to_string()],
            workdir,
            Utc::now(),
            None,
            vec![],
            vec![],
            0.35,
            12,
            300,
        );
        monitor.pollution_detected = true;
        monitor.completion_pause_detected = true;
        assert_session_monitor_signals_are_consumed_once(
            AgentDriver::OpenCode,
            AgentSessionMonitor::OpenCode(monitor),
        );
    }

    #[test]
    fn codex_session_monitor_endpoint_failure_signal_is_consumed_once() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            tmp.path().join(".codex"),
        );
        let endpoint = cfg.endpoints[0].clone();
        let mut agent = AgentProcess::new(cfg, endpoint, false);
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().join(".codex"),
            workdir,
            Utc::now(),
            None,
            vec![],
            vec![],
            0.35,
            12,
            300,
        );
        monitor.endpoint_failure_detected = true;
        agent.monitor = Some(AgentSessionMonitor::Codex(monitor));

        agent.poll_monitor();
        assert!(agent.endpoint_failure_detected);

        agent.endpoint_failure_detected = false;
        agent.poll_monitor();
        assert!(!agent.endpoint_failure_detected);
    }

    #[test]
    fn codex_start_forces_tui_status_before_terminal_launch() {
        let source = include_str!("agent.rs");
        let start_block = source
            .split("pub fn start(&mut self) -> Result<()>")
            .nth(1)
            .and_then(|tail| tail.split("pub fn stop(&mut self)").next())
            .expect("AgentProcess::start block should be discoverable");

        let apply_pos = start_block
            .find("apply_codex_endpoint_with_model_context_window(")
            .expect("Codex startup must write isolated config before launching");
        let override_pos = start_block
            .find("codex_command_with_cli_overrides(")
            .expect("Codex startup must force CLI config overrides");
        let terminal_pos = start_block
            .find("TerminalSession::start_with_env(")
            .expect("terminal launch should be discoverable");

        assert!(apply_pos < terminal_pos);
        assert!(override_pos < terminal_pos);
        assert!(start_block.contains("launch_config.agent_driver == AgentDriverKind::Codex"));
    }

    #[test]
    fn codex_launch_without_binding_starts_new_session_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        let session_file = codex_home.join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            serde_json::json!({"type": "session_meta", "payload": {"id": "latest-session", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        let cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string(), "--no-alt-screen".to_string()]),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        let endpoint = endpoint(workdir.clone());
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        store.set_session_id(&workdir, "missing-session").unwrap();
        let index = CodexSessionIndex::new(codex_home);

        let launch = build_agent_launch(&cfg, &endpoint, &mut store, &index, false).unwrap();

        assert_eq!(
            launch.command,
            AgentCommand::Args(vec!["codex".to_string(), "--no-alt-screen".to_string()])
        );
        assert!(!launch.resumed);
    }

    #[test]
    fn discovered_session_id_is_bound_before_idle_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            tmp.path().join(".codex"),
        );
        cfg.config_path = Some(tmp.path().join("config.json"));
        let endpoint = endpoint(workdir.clone());
        let mut agent = AgentProcess::new(cfg.clone(), endpoint.clone(), true);
        agent.launch = Some(AgentLaunch {
            command: cfg.agent_command.clone(),
            resumed: false,
            session_id: None,
        });
        agent.monitor = Some(AgentSessionMonitor::Codex(CodexSessionMonitor::new(
            cfg.codex_home.clone(),
            workdir.clone(),
            Utc::now(),
            None,
            vec![],
            vec![],
            0.35,
            12,
            300,
        )));
        if let Some(AgentSessionMonitor::Codex(monitor)) = agent.monitor.as_mut() {
            monitor.session_id = Some("new-session".to_string());
        }

        agent.poll_monitor();

        let reloaded = SessionStore::new(cfg.session_state_path.clone());
        assert_eq!(
            reloaded.get_bound_session_id(&session_binding_key(&cfg, &endpoint)),
            Some("new-session".to_string())
        );
    }

    #[test]
    fn duplicate_bound_codex_session_starts_new_config_session() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        let session_file = codex_home.join("sessions/2026/05/17/shared.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            serde_json::json!({"type": "session_meta", "payload": {"id": "shared-session", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        let mut cfg_a = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg_a.config_path = Some(tmp.path().join("a.json"));
        let mut cfg_b = cfg_a.clone();
        cfg_b.config_path = Some(tmp.path().join("b.json"));
        let endpoint = endpoint(workdir);
        let mut store = SessionStore::new(cfg_a.session_state_path.clone());
        store
            .set_bound_session_id(
                &session_binding_key(&cfg_a, &endpoint),
                "shared-session",
                None,
            )
            .unwrap();
        store
            .set_bound_session_id(
                &session_binding_key(&cfg_b, &endpoint),
                "shared-session",
                None,
            )
            .unwrap();
        let index = CodexSessionIndex::new(codex_home);

        let launch = build_agent_launch(&cfg_b, &endpoint, &mut store, &index, false).unwrap();

        assert_eq!(
            launch.command,
            AgentCommand::Args(vec!["codex".to_string()])
        );
        assert!(!launch.resumed);
        assert!(store
            .get_bound_session_id(&session_binding_key(&cfg_b, &endpoint))
            .is_none());
    }

    #[test]
    fn legacy_policy_can_fall_back_to_latest_codex_workdir_session() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        let session_file = codex_home.join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            serde_json::json!({"type": "session_meta", "payload": {"id": "latest-session", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        let cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            codex_home,
        );
        let endpoint = endpoint(workdir);
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let index = CodexSessionIndex::new(cfg.codex_home.clone());

        let launch = build_agent_launch_with_policy(
            &cfg,
            &endpoint,
            &mut store,
            &index,
            false,
            MissingSessionPolicy::LegacyLatest,
        )
        .unwrap();

        assert_eq!(
            launch.command,
            AgentCommand::Args(vec![
                "codex".to_string(),
                "resume".to_string(),
                "-C".to_string(),
                cfg.workdir.to_string_lossy().to_string(),
                "latest-session".to_string()
            ])
        );
        assert!(launch.resumed);
    }

    #[test]
    fn codex_restore_lookup_uses_source_home_for_isolated_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let source_home = tmp.path().join(".codex");
        let session_file = source_home.join("sessions/2026/05/17/source-only.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            serde_json::json!({"type": "session_meta", "payload": {"id": "source-session", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        fs::write(
            source_home.join("config.toml"),
            "model_provider = \"custom\"\n",
        )
        .unwrap();
        fs::write(
            source_home.join("auth.json"),
            "{\"OPENAI_API_KEY\":\"old\"}\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            source_home.clone(),
        );
        cfg.config_path = Some(tmp.path().join("config.json"));
        cfg.codex_config_path = source_home.join("config.toml");
        cfg.codex_auth_path = source_home.join("auth.json");
        let isolated = prepare_isolated_codex_home(&cfg).unwrap();
        let mut runtime_cfg = cfg.clone();
        runtime_cfg.codex_home = isolated.home.clone();
        runtime_cfg.codex_config_path = isolated.home.join("config.toml");
        runtime_cfg.codex_auth_path = isolated.home.join("auth.json");
        let endpoint = endpoint(workdir.clone());
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        store
            .set_bound_session_id(
                &session_binding_key(&cfg, &endpoint),
                "source-session",
                None,
            )
            .unwrap();

        let launch = build_agent_launch_for_codex_restore_home(
            &runtime_cfg,
            &cfg,
            &endpoint,
            &mut store,
            false,
            MissingSessionPolicy::New,
        )
        .unwrap();

        assert_eq!(launch.session_id, Some("source-session".to_string()));
        assert!(launch.resumed);
        assert_eq!(
            launch.command,
            AgentCommand::Args(vec![
                "codex".to_string(),
                "resume".to_string(),
                "-C".to_string(),
                workdir.to_string_lossy().to_string(),
                "source-session".to_string()
            ])
        );
        assert!(!isolated
            .home
            .join("sessions/2026/05/17/source-only.jsonl")
            .exists());
        let _ = fs::remove_dir_all(isolated.home);
    }

    #[test]
    fn resuming_from_source_home_copies_only_selected_session_to_isolated_home() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let source_home = tmp.path().join(".codex");
        let selected = source_home.join("sessions/2026/05/17/selected.jsonl");
        let other = source_home.join("sessions/2026/05/17/other.jsonl");
        fs::create_dir_all(selected.parent().unwrap()).unwrap();
        fs::write(
            &selected,
            serde_json::json!({"type": "session_meta", "payload": {"id": "selected-session", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        fs::write(
            &other,
            serde_json::json!({"type": "session_meta", "payload": {"id": "other-session", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        let isolated_home = tmp.path().join("isolated");

        let copied = copy_codex_resume_session_to_isolated_home(
            &source_home,
            &isolated_home,
            &workdir,
            "selected-session",
            None,
        )
        .unwrap();

        assert_eq!(
            copied,
            isolated_home.join("sessions/2026/05/17/selected.jsonl")
        );
        assert_eq!(
            fs::read_to_string(&copied).unwrap(),
            fs::read_to_string(&selected).unwrap()
        );
        assert!(!isolated_home
            .join("sessions/2026/05/17/other.jsonl")
            .exists());
    }

    #[test]
    fn bound_codex_session_path_outside_source_home_can_resume_and_copy_to_isolated_home() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let source_home = tmp.path().join(".codex");
        let historical_home = tmp.path().join("Runtime/codex-homes/old-config/codex-main");
        let historical_file = historical_home.join("sessions/2026/05/29/historical.jsonl");
        fs::create_dir_all(historical_file.parent().unwrap()).unwrap();
        fs::write(
            &historical_file,
            serde_json::json!({"type": "session_meta", "payload": {"id": "historical-session", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        let isolated_home = tmp.path().join("isolated");
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            source_home.clone(),
        );
        cfg.config_path = Some(tmp.path().join("config.json"));
        let mut runtime_cfg = cfg.clone();
        runtime_cfg.codex_home = isolated_home.clone();
        let endpoint = endpoint(workdir.clone());
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let binding = session_binding_key(&cfg, &endpoint);
        store
            .set_bound_session_id(&binding, "historical-session", Some(&historical_file))
            .unwrap();

        let launch = build_agent_launch_for_codex_restore_home(
            &runtime_cfg,
            &cfg,
            &endpoint,
            &mut store,
            false,
            MissingSessionPolicy::New,
        )
        .unwrap();
        let copied = copy_codex_resume_session_to_isolated_home(
            &source_home,
            &isolated_home,
            &workdir,
            "historical-session",
            store.get_bound_session_path(&binding).as_deref(),
        )
        .unwrap();

        assert_eq!(launch.session_id, Some("historical-session".to_string()));
        assert!(launch.resumed);
        assert_eq!(
            copied,
            isolated_home.join("sessions/2026/05/29/historical.jsonl")
        );
        assert_eq!(
            fs::read_to_string(&copied).unwrap(),
            fs::read_to_string(&historical_file).unwrap()
        );
    }

    #[test]
    fn codex_resume_command_pins_current_workdir_to_avoid_directory_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let stale_workdir = tmp.path().join("old-project");
        fs::create_dir_all(&stale_workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        let session_file = codex_home.join("sessions/2026/05/17/bound.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            serde_json::json!({"type": "session_meta", "payload": {"id": "bound-session", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        let cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec![
                "codex".to_string(),
                "--no-alt-screen".to_string(),
                "--cd".to_string(),
                stale_workdir.to_string_lossy().to_string(),
            ]),
            tmp.path().join("state.json"),
            codex_home,
        );
        let endpoint = endpoint(workdir.clone());
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        store
            .set_bound_session_id(&session_binding_key(&cfg, &endpoint), "bound-session", None)
            .unwrap();
        let index = CodexSessionIndex::new(cfg.codex_home.clone());

        let launch = build_agent_launch(&cfg, &endpoint, &mut store, &index, false).unwrap();

        assert_eq!(
            launch.command,
            AgentCommand::Args(vec![
                "codex".to_string(),
                "resume".to_string(),
                "-C".to_string(),
                workdir.to_string_lossy().to_string(),
                "--no-alt-screen".to_string(),
                "bound-session".to_string()
            ])
        );
        assert!(launch.resumed);
    }

    #[test]
    fn codex_goal_mode_enables_goals_feature_on_launch() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string(), "--no-alt-screen".to_string()]),
            tmp.path().join("state.json"),
            tmp.path().join(".codex"),
        );
        cfg.continuation_mode = ContinuationMode::Goal;
        cfg.agent_goal.enabled = true;
        cfg.agent_goal.text = "修复终端渲染".to_string();
        let endpoint = endpoint(workdir);
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let index = CodexSessionIndex::new(cfg.codex_home.clone());

        let launch = build_agent_launch(&cfg, &endpoint, &mut store, &index, false).unwrap();

        assert_eq!(
            launch.command,
            AgentCommand::Args(vec![
                "codex".to_string(),
                "--enable".to_string(),
                "goals".to_string(),
                "--no-alt-screen".to_string()
            ])
        );
        assert!(!launch.resumed);
    }

    #[test]
    fn opencode_launch_uses_bound_session_or_fresh_command() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::OpenCode,
            AgentCommand::Args(vec!["opencode".to_string()]),
            tmp.path().join("state.json"),
            tmp.path().join(".codex"),
        );
        cfg.config_path = Some(tmp.path().join("config-a.json"));
        let endpoint = endpoint(workdir.clone());
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let index = CodexSessionIndex::new(cfg.codex_home.clone());

        let launch = build_agent_launch(&cfg, &endpoint, &mut store, &index, false).unwrap();
        assert_eq!(
            launch.command,
            AgentCommand::Args(vec!["opencode".to_string()])
        );

        store
            .set_bound_session_id(
                &session_binding_key(&cfg, &endpoint),
                "opencode-session-1",
                None,
            )
            .unwrap();
        let launch = build_agent_launch(&cfg, &endpoint, &mut store, &index, false).unwrap();
        assert_eq!(
            launch.command,
            AgentCommand::Args(vec![
                "opencode".to_string(),
                "--session".to_string(),
                "opencode-session-1".to_string()
            ])
        );
    }

    #[test]
    fn legacy_policy_can_fall_back_to_latest_claude_workdir_session() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let claude_home = tmp.path().join(".claude");
        let session_file = claude_home
            .join("projects/-tmp-project")
            .join("claude-session-1.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            serde_json::json!({"cwd": workdir.to_string_lossy(), "type": "summary"}).to_string()
                + "\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::ClaudeCode,
            AgentCommand::Args(vec!["claude".to_string()]),
            tmp.path().join("state.json"),
            tmp.path().join(".codex"),
        );
        cfg.agent_home = Some(claude_home);
        let endpoint = endpoint(workdir.clone());
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let index = CodexSessionIndex::new(cfg.codex_home.clone());

        let launch = build_agent_launch_with_policy(
            &cfg,
            &endpoint,
            &mut store,
            &index,
            false,
            MissingSessionPolicy::LegacyLatest,
        )
        .unwrap();

        assert_eq!(launch.session_id, Some("claude-session-1".to_string()));
        assert!(launch.resumed);
        assert_eq!(
            launch.command,
            AgentCommand::Args(vec![
                "claude".to_string(),
                "--resume".to_string(),
                "claude-session-1".to_string()
            ])
        );
        assert_eq!(
            store.get_session_id(&workdir),
            Some("claude-session-1".to_string())
        );
    }

    #[test]
    fn output_keyword_helpers_match_python_failure_markers() {
        assert!(is_endpoint_failure_text(
            "Error: insufficient_quota, billing required"
        ));
        assert!(is_endpoint_failure_text("余额不足，请充值"));
        assert!(is_endpoint_failure_text("upstream unavailable"));
        assert!(is_endpoint_failure_text(
            "unexpected status 502 Bad Gateway: Unknown error"
        ));
        assert!(is_endpoint_failure_text("unexpected status 503"));
        assert!(is_endpoint_failure_text("unexpected status 504"));
        assert!(is_endpoint_failure_text(
            "Unexpected status 400 Bad Request: invalid request"
        ));
        assert!(is_endpoint_failure_text(
            "unexpected status 401 Unauthorized: Invalid API key, url: https://ai.hhhl.cc/v1/responses, cf-ray: a00964f6f8af84e4-HKG"
        ));
        assert!(is_endpoint_failure_text(
            "unexpected status 403 Forbidden: Cloudflare blocked request, cf-ray: a00964f6f8af84e4-HKG"
        ));
        assert!(is_endpoint_failure_text(
            "unexpected status 429 Too Many Requests"
        ));
        assert!(is_endpoint_failure_text(
            "smart proxy upstream unavailable: no available key"
        ));
        assert!(is_endpoint_failure_text("aggregate upstream unavailable"));
        assert!(is_endpoint_failure_text(
            "guard proxy local failure: os error 10035"
        ));
        assert!(is_endpoint_failure_text(
            r#"{"error":{"message":"切换key需要冷却1秒","type":"invalid_request_error","code":"key_switch_cooldown"}}"#
        ));
        let rate_limit_cooldown = r#"{"error":{"message":"一分钟30次，冷却20秒","type":"invalid_request_error","code":"rate_limit_cooldown"},"message":"一分钟30次，冷却20秒","code":"rate_limit_cooldown","limit_type":"cooldown"}"#;
        assert!(is_endpoint_failure_text(rate_limit_cooldown));
        assert_eq!(endpoint_failure_status_code(rate_limit_cooldown), None);
        assert_eq!(
            endpoint_failure_cooldown_seconds(rate_limit_cooldown),
            Some(40)
        );
        let cooldown_without_error =
            r#"{"message":"一分钟30次，冷却20秒","code":"cooldown","limit_type":"cooldown"}"#;
        assert!(is_endpoint_failure_text(cooldown_without_error));
        assert_eq!(
            endpoint_failure_cooldown_seconds(cooldown_without_error),
            Some(40)
        );
        assert!(is_endpoint_failure_text(
            "Too many requests, please try again after 20s"
        ));
        assert!(is_transient_endpoint_failure_text(
            "stream disconnected before completion"
        ));
        assert!(is_transient_endpoint_failure_text("request timed out"));
        assert!(is_transient_endpoint_failure_text("broken pipe"));
        assert!(is_transient_endpoint_failure_text("os error 10054"));
        assert!(!is_endpoint_failure_text("正常回复内容"));
        assert_eq!(
            endpoint_failure_status_code("Unexpected status 503 Service Unavailable"),
            Some(503)
        );
        assert_eq!(
            endpoint_failure_status_code("HTTP status code: 429, rate limited"),
            Some(429)
        );
        assert_eq!(
            endpoint_failure_status_code("unexpected status 400 Bad Request"),
            Some(400)
        );
        assert_eq!(
            endpoint_failure_status_code(
                "unexpected status 401 Unauthorized: Invalid API key, url: https://ai.hhhl.cc/v1/responses"
            ),
            Some(401)
        );
        assert_eq!(
            endpoint_failure_status_code("HTTP/1.1 503 Service Unavailable"),
            Some(503)
        );
        assert_eq!(
            endpoint_failure_status_code("状态 503 但是没有英文 marker"),
            None
        );
        assert_eq!(
            endpoint_failure_status_code(
                "EnumMemberResolveStatus status 字段；这是 Round 545 正在删除的 wrapper 字段"
            ),
            None
        );
        assert!(!is_endpoint_failure_text(
            "EnumMemberResolveStatus status 字段；这是 Round 545 正在删除的 wrapper 字段"
        ));
    }

    #[test]
    fn endpoint_failure_releases_awaiting_turn_completion() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = true;
        agent.submit_retry_count = 1;
        let failure_markers = [
            "unexpected status 502 Bad Gateway: Unknown error",
            "guard proxy local failure: os error 10035",
            "stream disconnected before completion",
            "request timed out",
            "upstream unavailable",
            "connection reset",
        ];
        agent.recent_output = failure_markers.join("\n");
        agent.endpoint_failure_status_code = Some(503);
        agent.endpoint_failure_retry_after_seconds = Some(40);

        agent.mark_current_turn_failed();

        assert!(!agent.awaiting_turn_completion);
        assert_eq!(agent.submit_retry_count, 0);
        assert!(agent.recent_output.is_empty());
        assert_eq!(agent.endpoint_failure_status_code, None);
        assert_eq!(agent.endpoint_failure_retry_after_seconds, None);
    }

    #[test]
    fn new_prompt_clears_stale_terminal_failure_context() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.recent_output = "unexpected status 503\nstream disconnected".to_string();
        agent.endpoint_failure_detected = true;
        agent.transient_endpoint_failure_detected = true;
        agent.endpoint_failure_status_code = Some(503);
        agent.endpoint_failure_retry_after_seconds = Some(40);
        agent.pollution_detected = true;
        agent.completion_pause_detected = true;

        agent.clear_stale_terminal_failure_signals();

        assert!(agent.recent_output.is_empty());
        assert!(!agent.endpoint_failure_detected);
        assert!(!agent.transient_endpoint_failure_detected);
        assert_eq!(agent.endpoint_failure_status_code, None);
        assert_eq!(agent.endpoint_failure_retry_after_seconds, None);
        assert!(agent.pollution_detected);
        assert!(agent.completion_pause_detected);
    }

    #[test]
    fn send_prompt_resets_terminal_failure_context_after_successful_write() {
        let source = include_str!("agent.rs");
        let send_block = source
            .split("pub fn send_prompt(&mut self, prompt: &str)")
            .nth(1)
            .and_then(|tail| tail.split("pub fn retry_submit").next())
            .expect("send prompt block should be discoverable");

        assert!(send_block.contains("terminal.send_prompt("));
        assert!(send_block.contains("self.clear_stale_terminal_failure_signals();"));
        assert!(
            send_block.find("terminal.send_prompt(")
                < send_block.find("self.clear_stale_terminal_failure_signals();"),
            "旧终端失败上下文只能在新 prompt 成功写入后清掉，避免写入失败时丢失错误证据"
        );
    }

    #[test]
    fn submit_retry_continues_while_turn_never_starts() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = true;
        agent.saw_ready_banner = true;
        agent.last_submit_attempt_at = Some(Instant::now() - Duration::from_secs(6));
        agent.submit_retry_count = 1;

        assert!(agent.needs_submit_retry(5.0));
    }

    #[test]
    fn submit_retry_uses_visible_prefilled_input_over_stale_monitor_state() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir.clone()),
            false,
        );
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().join(".codex"),
            workdir,
            Utc::now(),
            None,
            Vec::new(),
            Vec::new(),
            0.35,
            12,
            300,
        );
        monitor.last_task_started_at = Some(Instant::now());
        agent.monitor = Some(AgentSessionMonitor::Codex(monitor));
        agent.awaiting_turn_completion = true;
        agent.saw_ready_banner = true;
        agent.last_submit_attempt_at = Some(Instant::now() - Duration::from_secs(6));
        agent.observed_terminal_view_text = "› 我打算离开电脑一段时间，需要你进入无人值守模式\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\XAgent"
            .to_string();

        assert!(agent.needs_submit_retry(5.0));

        agent.observed_terminal_view_text = "• Working (12s • esc to interrupt)\n\
             › 我打算离开电脑一段时间，需要你进入无人值守模式"
            .to_string();

        assert!(!agent.needs_submit_retry(5.0));
    }

    #[test]
    fn submit_retry_resubmits_visible_prefilled_input_after_wait_gate_released() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.last_submit_attempt_at = Some(Instant::now() - Duration::from_secs(6));
        agent.observed_terminal_view_text = "› 你现在是一个新会话。先初始化上下文\n\
             继续执行当前任务。如果已经完成，就简要说明结果"
            .to_string();

        assert!(agent.needs_submit_retry(5.0));
    }

    #[test]
    fn codex_ready_view_rejects_prompt_still_visible_in_input() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.observed_terminal_view_text = "Sandbox ready\n\
             › 继续执行当前任务。如果已经完成，就简要说明结果\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\XAgent"
            .to_string();

        assert!(ready_banner_visible(&agent.observed_terminal_view_text));
        assert!(!agent.current_terminal_view_ready());
    }

    #[test]
    fn turn_stall_detection_does_not_mark_endpoint_request_failure() {
        let source = include_str!("agent.rs");
        let block = source
            .split("pub fn is_turn_stalled(&mut self")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub fn has_assistant_message_since_prompt")
                    .next()
            })
            .expect("turn stall helper should be discoverable");

        assert!(
            !block.contains("endpoint_failure_detected"),
            "响应卡死应走 stall 计数，不应污染 endpoint 请求失败计数，否则可用接口会显示请求失败 1/3"
        );
    }

    #[test]
    fn turn_stall_detection_checks_session_tail_before_terminal_activity() {
        let source = include_str!("agent.rs");
        let block = source
            .split("pub fn is_turn_stalled(&mut self")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub fn has_assistant_message_since_prompt")
                    .next()
            })
            .expect("turn stall helper should be discoverable");

        let session_pos = block
            .find("monitor.session_tail_stalled(stall_after)")
            .expect("turn stall must check session tail watchdog");
        let terminal_pos = block
            .find("self.recent_activity_elapsed() >= stall_after")
            .expect("turn stall should keep terminal fallback");
        assert!(
            session_pos < terminal_pos,
            "session 文件尾部静默应优先于终端 Working 输出，否则 Working 动画会掩盖卡死"
        );
    }

    #[test]
    fn assistant_progress_detection_falls_back_to_terminal_activity() {
        let source = include_str!("agent.rs");
        let block = source
            .split("pub fn has_assistant_message_since_prompt")
            .nth(1)
            .and_then(|tail| tail.split("pub fn clear_completion_pause_detected").next())
            .expect("assistant progress helper should be discoverable");

        assert!(
            block.contains("self.has_session_assistant_message_since_prompt()"),
            "应优先使用 Codex session jsonl 判断 assistant 是否回复"
        );
        assert!(
            block.contains("self.terminal_had_activity_since_prompt()"),
            "session monitor 漏掉回复时，必须用终端输出活动兜底，否则屏幕已有 ok 仍会卡住自动续航"
        );
        assert!(
            block.find("self.has_session_assistant_message_since_prompt()")
                < block.find("self.terminal_had_activity_since_prompt()"),
            "终端活动兜底只能在 session monitor 未确认 assistant 回复后使用"
        );
    }

    #[test]
    fn request_failure_success_evidence_uses_codex_session_assistant_message_only() {
        let source = include_str!("agent.rs");
        let helper = source
            .split("pub fn has_session_assistant_message_since_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn terminal_had_activity_since_prompt").next())
            .expect("session assistant helper should be discoverable");

        assert!(
            helper.contains("has_codex_assistant_message_since_wait_start"),
            "清请求失败计数只能用 Codex 会话文件里的 assistant 回复，不能用终端输出或非 Codex 默认 true"
        );
        assert!(
            !helper.contains("terminal_had_activity_since_prompt"),
            "终端错误码输出也是活动，不能作为清请求失败计数的成功证据"
        );
    }

    #[test]
    fn codex_task_complete_requires_assistant_message_or_ready_prompt_to_unlock_auto_prompt() {
        let source = include_str!("agent.rs");
        let block = source
            .split("if monitor.last_task_finished()")
            .nth(1)
            .and_then(|tail| tail.split("if monitor.last_task_started()").next())
            .expect("last_task_finished branch should be discoverable");

        assert!(
            block.contains("monitor.has_assistant_message_since_wait_start()"),
            "Codex may emit task_complete before the assistant turn is actually done; auto continuation must wait for an assistant message before writing the next prompt"
        );
        assert!(
            block.contains("self.saw_ready_banner"),
            "When Codex session files omit the assistant message, a finished task may unlock only after the terminal visibly returns to the ready prompt"
        );
    }

    #[test]
    fn codex_started_task_does_not_unlock_after_short_idle_seconds() {
        let source = include_str!("agent.rs");
        let block = source
            .split("if monitor.last_task_started()")
            .nth(1)
            .and_then(|tail| tail.split("if !self.awaiting_turn_completion").next())
            .expect("last_task_started branch should be discoverable");

        assert!(
            !block.contains("Duration::from_secs_f64(idle_seconds)"),
            "Codex Working 过程中可能短时间无输出，不能用 idle_seconds 解锁自动续航"
        );
        assert!(
            block.contains("inflight_idle_fallback_seconds"),
            "已开始但未完成的 Codex turn 只能走更长的 inflight fallback 或 visible ready 解锁"
        );
    }

    #[test]
    fn codex_unstarted_turn_does_not_unlock_after_short_idle_seconds() {
        let source = include_str!("agent.rs");
        let block = source
            .split("if self.awaiting_turn_completion {")
            .nth(1)
            .and_then(|tail| tail.split("if !self.awaiting_turn_completion").next())
            .expect("awaiting turn branch should be discoverable");

        assert!(
            !block.contains("return terminal.last_activity_elapsed() >= Duration::from_secs_f64(idle_seconds);"),
            "Codex 没检测到 task_started 时也不能用短 idle_seconds 解锁，否则 Working 启动事件丢失会误续航"
        );
        assert!(
            block.matches("inflight_idle_fallback_seconds").count() >= 4,
            "inflight、finished、started、unstarted 四种 awaiting 分支都应走长 fallback"
        );
    }

    #[test]
    fn codex_inflight_fallback_rechecks_visible_working_screen() {
        let source = include_str!("agent.rs");
        let block = source
            .split("if self.awaiting_turn_completion {")
            .nth(1)
            .and_then(|tail| tail.split("if !self.awaiting_turn_completion").next())
            .expect("awaiting turn branch should be discoverable");

        assert!(
            block.contains("current_view_busy"),
            "长 fallback 解锁前必须读取当前屏幕 busy 状态，不能只靠计时"
        );
        assert!(
            block.find("if current_view_busy") < block.find("monitor.has_inflight_turn()"),
            "Working/esc to interrupt 可见时必须先拒绝 fallback 解锁"
        );
    }

    #[test]
    fn codex_ready_prompt_unlocks_even_without_session_completion_event() {
        let source = include_str!("agent.rs");
        let block = source
            .split("if self.awaiting_turn_completion {")
            .nth(1)
            .and_then(|tail| tail.split("if monitor.has_inflight_turn()").next())
            .expect("awaiting turn branch should check ready prompt before session state");

        assert!(
            block.contains("if self.saw_ready_banner"),
            "Codex may return to the visible idle prompt without task_complete; auto continuation should unlock from the ready prompt before trusting stale session state"
        );
        assert!(
            block.contains("current_view_ready"),
            "ready prompt unlock must re-check the current visible view so stale ready state cannot submit while Codex is still Working"
        );
        assert!(
            block.contains("ready_unlock_allowed"),
            "ready prompt unlock must wait out the post-send grace period so a long prompt being rendered in the input box cannot trigger another auto prompt"
        );
        assert!(
            block.contains("self.awaiting_turn_completion = false"),
            "visible ready prompt must release the current auto prompt wait"
        );
    }

    #[test]
    fn codex_ready_prompt_unlock_has_post_send_grace_period() {
        let source = include_str!("agent.rs");
        let block = source
            .split("fn codex_ready_unlock_grace_active(&self)")
            .nth(1)
            .and_then(|tail| tail.split("fn startup_ready_for_prompt").next())
            .expect("ready unlock grace helper should be discoverable");

        assert!(
            source.contains("const CODEX_READY_UNLOCK_GRACE: Duration = Duration::from_secs(2);")
        );
        assert!(block.contains("self.config.agent_driver == AgentDriverKind::Codex"));
        assert!(block.contains("last_prompt_sent_at"));
        assert!(block.contains("at.elapsed() < CODEX_READY_UNLOCK_GRACE"));
    }

    #[test]
    fn auto_wait_watchdog_uses_safe_completion_signals_not_writable_prompt() {
        let source = include_str!("agent.rs");
        let block = source
            .split("pub fn auto_wait_safely_released(&self)")
            .nth(1)
            .and_then(|tail| tail.split("pub fn needs_submit_retry").next())
            .expect("auto wait watchdog helper should be discoverable");

        assert!(block.contains("self.awaiting_turn_completion"));
        assert!(block.contains("AgentSessionMonitor::has_assistant_message_since_wait_start"));
        assert!(block.contains("self.saw_ready_banner"));
        assert!(block.contains("self.current_terminal_view_ready()"));
        assert!(block.contains("!self.codex_ready_unlock_grace_active()"));
        assert!(
            !block.contains("startup_ready_for_prompt"),
            "watchdog 不能把输入框可写当成任务结束；Codex Working 时也可能可输入"
        );
    }

    #[test]
    fn final_send_gate_rejects_visible_working_without_completion_evidence() {
        let source = include_str!("agent.rs");
        let block = source
            .split("pub fn can_send_prompt(&self)")
            .nth(1)
            .and_then(|tail| tail.split("pub fn auto_wait_safely_released").next())
            .expect("can_send_prompt block should be discoverable");

        assert!(block.contains("self.current_terminal_view_busy()"));
        assert!(
            block.contains("AgentSessionMonitor::has_completed_assistant_message_since_wait_start")
        );
        assert!(
            block.find("self.current_terminal_view_busy()")
                < block
                    .find("AgentSessionMonitor::has_completed_assistant_message_since_wait_start"),
            "最终发送门必须先识别 Working，再用 assistant 完成证据放行残留 Working"
        );
    }

    #[test]
    fn auto_wait_watchdog_rejects_visible_working_screen() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.last_prompt_sent_at = Some(Instant::now() - Duration::from_secs(10));
        agent.observed_terminal_view_text = "• Working (12s • esc to interrupt)\n\
             › Summarize recent commits\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\ModernUI"
            .to_string();

        assert!(!agent.auto_wait_safely_released());
    }

    #[test]
    fn auto_wait_watchdog_rejects_localized_working_screen() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.last_prompt_sent_at = Some(Instant::now() - Duration::from_secs(10));
        agent.observed_terminal_view_text = "• 运行中 (12s • esc 中断)\n\
             › Summarize recent commits\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\ModernUI"
            .to_string();

        assert!(!agent.auto_wait_safely_released());
        assert!(!agent.can_send_prompt());
    }

    #[test]
    fn auto_wait_watchdog_rejects_visible_working_with_only_assistant_message() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp.path().join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            json!({"type": "session_meta", "timestamp": "2026-05-17T16:29:00.000Z", "payload": {"id": "session-1", "cwd": workdir.to_string_lossy()}}).to_string()
                + "\n",
        )
        .unwrap();
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir.clone(),
            chrono::DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
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
        monitor.begin_waiting_for_new_turn();
        fs::OpenOptions::new()
            .append(true)
            .open(&session_file)
            .unwrap()
            .write_all(
                (json!({"timestamp": "2026-05-17T16:29:06.000Z", "type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"text": "partial"}]}}).to_string()
                    + "\n")
                    .as_bytes(),
            )
            .unwrap();
        monitor.poll();

        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.monitor = Some(AgentSessionMonitor::Codex(monitor));
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.observed_terminal_view_text = "• Working (12s • esc to interrupt)\n\
             › 我打算离开电脑一段时间，需要你进入无人值守模式"
            .to_string();

        assert!(!agent.auto_wait_safely_released());
        assert!(!agent.can_send_prompt());
    }

    #[test]
    fn pre_prompt_restore_working_reports_waiting_ready_not_working_error() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.last_prompt_sent_at = None;
        agent.observed_terminal_view_text = "• Working (12s • esc to interrupt)\n\
             ›"
        .to_string();

        assert!(!agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), Some("等待 Codex 就绪"));
    }
    #[test]
    fn can_send_prompt_rejects_visible_working_without_completion_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.last_prompt_sent_at = Some(Instant::now() - Duration::from_secs(10));
        agent.observed_terminal_view_text = "• Working (12s • esc to interrupt)\n\
             › 我打算离开电脑一段时间，需要你进入无人值守模式"
            .to_string();

        assert!(!agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), Some("检测到 Working"));
    }

    #[test]
    fn can_send_prompt_rejects_esc_to_interrupt_without_working_word() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.last_prompt_sent_at = Some(Instant::now() - Duration::from_secs(10));
        agent.observed_terminal_view_text = "• Thinking (12s • esc to interrupt)\n\
             › 我打算离开电脑一段时间，需要你进入无人值守模式"
            .to_string();

        assert!(!agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), Some("检测到 Working"));
        assert!(!agent.auto_wait_safely_released());
    }

    #[test]
    fn stale_working_prompt_unlocks_after_quiet_ready_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.last_prompt_sent_at = Some(Instant::now() - Duration::from_secs(30));
        agent.observed_terminal_view_text = "• Working (2m 01s • esc to interrupt)\n\
             ›\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\XAgent"
            .to_string();

        assert!(agent.auto_wait_safely_released());
        assert!(agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), None);
    }

    #[test]
    fn stale_working_prompt_does_not_unlock_queued_message() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.last_prompt_sent_at = Some(Instant::now() - Duration::from_secs(30));
        agent.observed_terminal_view_text = "›\n\n\
             • Messages to be submitted after next tool call (press esc to interrupt and send immediately)\n\
             ↳ 继续\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\XAgent"
            .to_string();

        assert!(!agent.auto_wait_safely_released());
        assert!(!agent.can_send_prompt());
    }

    #[test]
    fn can_send_prompt_rejects_visible_queued_message() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.observed_terminal_view_text = "› 继续\n\n\
             • Messages to be submitted after next tool call (press esc to interrupt and send immediately)\n\
             ↳ 继续\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\XAgent"
            .to_string();

        assert!(!agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), Some("已有排队消息"));
    }

    #[test]
    fn can_send_prompt_rejects_visible_prefilled_input() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.observed_terminal_view_text = "› 你现在是一个新会话。先初始化上下文\n\
             继续执行当前任务。如果已经完成，就简要说明结果\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\WatchApi"
            .to_string();

        assert!(!agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), Some("输入框已有内容"));
    }

    #[test]
    fn can_send_prompt_ignores_old_prompt_when_current_input_is_placeholder() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.observed_terminal_view_text = "› 继续执行当前任务。如果已经完成，就简要说明结果\n\
             • 已完成。当前没有可继续推进的任务。\n\
             › Write tests for @filename\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\WatchApi"
            .to_string();

        assert!(agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), None);
    }

    #[test]
    fn can_send_prompt_rejects_current_english_user_input() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.observed_terminal_view_text = "› 继续执行当前任务。如果已经完成，就简要说明结果\n\
             • 已完成。当前没有可继续推进的任务。\n\
             › fix terminal rendering bug\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\WatchApi"
            .to_string();

        assert!(!agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), Some("输入框已有内容"));
    }

    #[test]
    fn terminal_view_classifies_random_dim_codex_suggestion_as_placeholder() {
        use crate::terminal_emulator::{
            TerminalCellView, TerminalCursorShape, TerminalModeView, TerminalRgb, TerminalView,
        };

        fn cell(c: char, dim: bool) -> TerminalCellView {
            TerminalCellView {
                c,
                fg: if dim {
                    TerminalRgb {
                        r: 130,
                        g: 130,
                        b: 130,
                    }
                } else {
                    TerminalRgb {
                        r: 220,
                        g: 220,
                        b: 220,
                    }
                },
                bg: TerminalRgb { r: 0, g: 0, b: 0 },
                bold: false,
                dim,
                italic: false,
                underline: false,
                strikeout: false,
                inverse: false,
                hidden: false,
                wide: false,
                wide_spacer: false,
                wrapline: false,
            }
        }

        let mut chars = "› Any rotating Codex suggestion"
            .chars()
            .collect::<Vec<_>>();
        chars.resize(40, ' ');
        let view = TerminalView {
            revision: 1,
            rows: 1,
            cols: 40,
            scrollback_lines: 0,
            cursor_row: 0,
            cursor_col: 2,
            cursor_shape: TerminalCursorShape::Block,
            display_offset: 0,
            modes: TerminalModeView::default(),
            cells: chars
                .into_iter()
                .enumerate()
                .map(|(index, c)| cell(c, index > 0 && !c.is_whitespace()))
                .collect(),
        };

        let input = terminal_view_current_codex_input(&view).unwrap();
        assert_eq!(input.text, "Any rotating Codex suggestion");
        assert!(input.placeholder);
    }

    #[test]
    fn terminal_view_does_not_classify_normal_english_input_as_placeholder() {
        use crate::terminal_emulator::{
            TerminalCellView, TerminalCursorShape, TerminalModeView, TerminalRgb, TerminalView,
        };

        let mut chars = "› fix terminal rendering bug".chars().collect::<Vec<_>>();
        chars.resize(40, ' ');
        let cells = chars
            .into_iter()
            .map(|c| TerminalCellView {
                c,
                fg: TerminalRgb {
                    r: 220,
                    g: 220,
                    b: 220,
                },
                bg: TerminalRgb { r: 0, g: 0, b: 0 },
                bold: false,
                dim: false,
                italic: false,
                underline: false,
                strikeout: false,
                inverse: false,
                hidden: false,
                wide: false,
                wide_spacer: false,
                wrapline: false,
            })
            .collect();
        let view = TerminalView {
            revision: 1,
            rows: 1,
            cols: 40,
            scrollback_lines: 0,
            cursor_row: 0,
            cursor_col: 2,
            cursor_shape: TerminalCursorShape::Block,
            display_offset: 0,
            modes: TerminalModeView::default(),
            cells,
        };

        let input = terminal_view_current_codex_input(&view).unwrap();
        assert_eq!(input.text, "fix terminal rendering bug");
        assert!(!input.placeholder);
    }

    #[test]
    fn can_send_prompt_block_reason_reports_startup_not_ready() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = false;
        agent.launched_at = Some(Instant::now());

        assert!(!agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), Some("等待 Codex 就绪"));
    }

    #[test]
    fn submit_retry_rejects_visible_working_or_queued_message() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = true;
        agent.last_submit_attempt_at = Some(Instant::now() - Duration::from_secs(30));
        agent.observed_terminal_view_text = "• Working (12s • esc to interrupt)\n\
             › 继续"
            .to_string();
        assert!(!agent.needs_submit_retry(5.0));

        agent.observed_terminal_view_text = "› 继续\n\n\
             • Messages to be submitted after next tool call (press esc to interrupt and send immediately)\n\
             ↳ 继续"
            .to_string();
        assert!(!agent.needs_submit_retry(5.0));
    }

    #[test]
    fn mark_current_turn_failed_preserves_visible_working_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.awaiting_turn_completion = true;
        agent.saw_ready_banner = true;
        agent.last_prompt_sent_at = Some(Instant::now() - Duration::from_secs(10));
        agent.observed_terminal_view_revision = 42;
        agent.observed_terminal_view_text = "• Working (47s • esc to interrupt)\n\
             › 我打算离开电脑一段时间，需要你进入无人值守模式"
            .to_string();

        agent.mark_current_turn_failed();

        assert!(!agent.can_send_prompt());
    }

    #[test]
    fn can_send_prompt_allows_stale_working_after_assistant_completion_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let session_file = tmp.path().join("sessions/2026/05/17/rollout.jsonl");
        fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        fs::write(
            &session_file,
            json!({"type": "session_meta", "timestamp": "2026-05-17T16:29:00.000Z", "payload": {"id": "session-1", "cwd": workdir.to_string_lossy()}}).to_string()
                + "\n",
        )
        .unwrap();
        let mut monitor = CodexSessionMonitor::new(
            tmp.path().to_path_buf(),
            workdir.clone(),
            chrono::DateTime::parse_from_rfc3339("2026-05-17T16:29:00.000Z")
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
        monitor.begin_waiting_for_new_turn();
        fs::OpenOptions::new()
            .append(true)
            .open(&session_file)
            .unwrap()
            .write_all(
                (json!({"timestamp": "2026-05-17T16:29:06.000Z", "type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"text": "ok"}]}}).to_string()
                    + "\n")
                    .as_bytes(),
            )
            .unwrap();
        monitor.poll();
        monitor.last_task_finished_at = Some(Instant::now());

        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::Codex,
                AgentCommand::Args(vec!["codex".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.monitor = Some(AgentSessionMonitor::Codex(monitor));
        agent.awaiting_turn_completion = false;
        agent.saw_ready_banner = true;
        agent.last_prompt_sent_at = Some(Instant::now() - Duration::from_secs(10));
        agent.observed_terminal_view_text = "• Working (12s • esc to interrupt)\n\
             › 我打算离开电脑一段时间，需要你进入无人值守模式"
            .to_string();

        assert!(agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), None);
    }

    #[test]
    fn codex_ready_prompt_from_terminal_view_ignores_stale_pre_send_screen() {
        let source = include_str!("agent.rs");
        let send_block = source
            .split("pub fn send_prompt(&mut self, prompt: &str)")
            .nth(1)
            .and_then(|tail| tail.split("pub fn retry_submit").next())
            .expect("send prompt block should be discoverable");
        let refresh_block = source
            .split("fn refresh_observed_terminal_view_text(&mut self)")
            .nth(1)
            .and_then(|tail| tail.split("fn write_auto_terminal_input").next())
            .expect("observed view refresh block should be discoverable");

        assert!(send_block.contains("let sent_view_revision = terminal.view_revision();"));
        assert!(
            send_block.contains("self.last_prompt_sent_view_revision = Some(sent_view_revision)")
        );
        assert!(send_block.contains("self.poll_monitor();"));
        assert!(send_block.contains("if !self.can_send_prompt()"));
        assert!(refresh_block.contains("last_prompt_sent_view_revision"));
        assert!(refresh_block.contains("revision > sent_revision"));
        assert!(refresh_block.contains("view_updated_after_prompt"));
    }

    #[test]
    fn recent_output_tail_never_splits_utf8() {
        let text = "甲".repeat(2000);

        let tail = utf8_tail(&text, 4096);

        assert!(tail.len() <= 4096);
        assert!(tail.chars().all(|ch| ch == '甲'));
    }

    #[test]
    fn isolated_codex_home_copies_config_and_merges_sessions_back() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(codex_home.join("sessions/2026/05/19")).unwrap();
        fs::write(
            codex_home.join("config.toml"),
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n",
        )
        .unwrap();
        fs::write(
            codex_home.join("auth.json"),
            "{\"OPENAI_API_KEY\":\"old\"}\n",
        )
        .unwrap();
        fs::write(codex_home.join("sessions/2026/05/19/old.jsonl"), "{}\n").unwrap();
        fs::create_dir_all(codex_home.join("archived_sessions/2026/05/18")).unwrap();
        fs::write(
            codex_home.join("archived_sessions/2026/05/18/archived.jsonl"),
            "archived\n",
        )
        .unwrap();
        fs::write(codex_home.join("state_5.sqlite"), "sqlite").unwrap();
        fs::write(
            codex_home.join(".codex-global-state.json"),
            "{\"provider\":\"custom\"}\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir,
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = codex_home.join("config.toml");
        cfg.codex_auth_path = codex_home.join("auth.json");

        let isolated = prepare_isolated_codex_home(&cfg).unwrap();
        assert!(isolated
            .home
            .starts_with(app_runtime_dir().join("codex-homes")));
        assert!(isolated.home.ends_with("default"));
        assert!(!isolated.home.starts_with(std::env::temp_dir()));
        assert!(!isolated
            .home
            .join("archived_sessions/2026/05/18/archived.jsonl")
            .exists());
        assert_eq!(
            fs::read_to_string(isolated.home.join("state_5.sqlite")).unwrap(),
            "sqlite"
        );
        assert_eq!(
            fs::read_to_string(isolated.home.join(".codex-global-state.json")).unwrap(),
            "{\"provider\":\"custom\"}\n"
        );
        fs::write(isolated.home.join("config.toml"), "changed").unwrap();
        fs::create_dir_all(isolated.home.join("sessions/2026/05/19")).unwrap();
        fs::write(isolated.home.join("sessions/2026/05/19/new.jsonl"), "new\n").unwrap();
        fs::create_dir_all(isolated.home.join("archived_sessions/2026/05/18")).unwrap();
        fs::write(
            isolated
                .home
                .join("archived_sessions/2026/05/18/new-archived.jsonl"),
            "new archived\n",
        )
        .unwrap();
        fs::write(isolated.home.join("state_5.sqlite"), "updated sqlite").unwrap();
        fs::write(
            isolated.home.join(".codex-global-state.json"),
            "{\"provider\":\"custom\",\"visible\":true}\n",
        )
        .unwrap();
        merge_codex_sessions_back_with_baseline(
            &isolated.home,
            &isolated.source_home,
            &isolated.session_baseline,
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(codex_home.join("config.toml")).unwrap(),
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n"
        );
        assert!(codex_home.join("sessions/2026/05/19/old.jsonl").exists());
        assert!(codex_home.join("sessions/2026/05/19/new.jsonl").exists());
        assert!(codex_home
            .join("archived_sessions/2026/05/18/new-archived.jsonl")
            .exists());
        assert_eq!(
            fs::read_to_string(codex_home.join("state_5.sqlite")).unwrap(),
            "updated sqlite"
        );
        assert_eq!(
            fs::read_to_string(codex_home.join(".codex-global-state.json")).unwrap(),
            "{\"provider\":\"custom\",\"visible\":true}\n"
        );
        let _ = fs::remove_dir_all(isolated.home);
    }

    #[test]
    fn isolated_codex_home_does_not_bulk_copy_historical_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(codex_home.join("sessions/2026/05/19")).unwrap();
        fs::create_dir_all(codex_home.join("archived_sessions/2026/05/18")).unwrap();
        fs::write(
            codex_home.join("config.toml"),
            "model_provider = \"custom\"\n",
        )
        .unwrap();
        fs::write(
            codex_home.join("auth.json"),
            "{\"OPENAI_API_KEY\":\"old\"}\n",
        )
        .unwrap();
        fs::write(codex_home.join("sessions/2026/05/19/old.jsonl"), "old\n").unwrap();
        fs::write(
            codex_home.join("archived_sessions/2026/05/18/archived.jsonl"),
            "archived\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir,
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            codex_home,
        );
        cfg.codex_config_path = cfg.codex_home.join("config.toml");
        cfg.codex_auth_path = cfg.codex_home.join("auth.json");

        let isolated = prepare_isolated_codex_home(&cfg).unwrap();

        assert!(isolated.home.join("config.toml").exists());
        assert!(isolated.home.join("auth.json").exists());
        assert!(!isolated.home.join("sessions/2026/05/19/old.jsonl").exists());
        assert!(!isolated
            .home
            .join("archived_sessions/2026/05/18/archived.jsonl")
            .exists());
        let _ = fs::remove_dir_all(isolated.home);
    }

    #[test]
    fn merge_codex_sessions_back_skips_unchanged_precopied_history() {
        let tmp = tempfile::tempdir().unwrap();
        let isolated_home = tmp.path().join("isolated");
        let source_home = tmp.path().join("source");
        let historical = isolated_home.join("sessions/2026/05/17/history.jsonl");
        let changed = isolated_home.join("sessions/2026/05/17/changed.jsonl");
        let created = isolated_home.join("sessions/2026/05/17/new.jsonl");
        fs::create_dir_all(historical.parent().unwrap()).unwrap();
        fs::write(&historical, "history\n").unwrap();
        fs::write(&changed, "before\n").unwrap();
        let baseline = collect_codex_session_baseline(&isolated_home);
        fs::write(&changed, "after\n").unwrap();
        fs::write(&created, "new\n").unwrap();

        merge_codex_sessions_back_with_baseline(&isolated_home, &source_home, &baseline).unwrap();

        assert!(!source_home
            .join("sessions/2026/05/17/history.jsonl")
            .exists());
        assert_eq!(
            fs::read_to_string(source_home.join("sessions/2026/05/17/changed.jsonl")).unwrap(),
            "after\n"
        );
        assert_eq!(
            fs::read_to_string(source_home.join("sessions/2026/05/17/new.jsonl")).unwrap(),
            "new\n"
        );
    }

    #[test]
    fn codex_session_fingerprint_uses_metadata_instead_of_full_file_reads() {
        let source = include_str!("agent.rs");
        let block = source
            .split("fn session_file_fingerprint")
            .nth(1)
            .and_then(|tail| tail.split("fn jsonl_files_under").next())
            .expect("session fingerprint helper should be discoverable");

        assert!(block.contains("fs::metadata(path)"));
        assert!(
            !block.contains("fs::read(path)"),
            "启动/退出时会遍历所有 Codex jsonl，会话文件不能整文件读入算指纹"
        );
    }

    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    fn isolated_codex_home_skips_unwritable_existing_session_files() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(codex_home.join("sessions/2026/05/19")).unwrap();
        fs::write(
            codex_home.join("config.toml"),
            "model_provider = \"custom\"\n",
        )
        .unwrap();
        fs::write(
            codex_home.join("auth.json"),
            "{\"OPENAI_API_KEY\":\"old\"}\n",
        )
        .unwrap();
        fs::write(codex_home.join("sessions/2026/05/19/old.jsonl"), "source\n").unwrap();
        let mut cfg = config(
            workdir,
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = codex_home.join("config.toml");
        cfg.codex_auth_path = codex_home.join("auth.json");

        let isolated_home = stable_isolated_codex_home_path(&cfg);
        let target_file = isolated_home.join("sessions/2026/05/19/old.jsonl");
        fs::create_dir_all(target_file.parent().unwrap()).unwrap();
        fs::write(&target_file, "existing\n").unwrap();
        let mut perms = fs::metadata(&target_file).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&target_file, perms).unwrap();

        let isolated = prepare_isolated_codex_home(&cfg).unwrap();

        assert_eq!(isolated.home, isolated_home);
        assert_eq!(fs::read_to_string(&target_file).unwrap(), "existing\n");
        let mut perms = fs::metadata(&target_file).unwrap().permissions();
        perms.set_readonly(false);
        fs::set_permissions(&target_file, perms).unwrap();
        let _ = fs::remove_dir_all(isolated.home);
    }

    #[test]
    fn isolated_codex_home_preserves_existing_session_files_when_syncing_source() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(codex_home.join("sessions/2026/05/19")).unwrap();
        fs::write(
            codex_home.join("config.toml"),
            "model_provider = \"custom\"\n",
        )
        .unwrap();
        fs::write(
            codex_home.join("auth.json"),
            "{\"OPENAI_API_KEY\":\"old\"}\n",
        )
        .unwrap();
        fs::write(codex_home.join("sessions/2026/05/19/old.jsonl"), "source\n").unwrap();
        let mut cfg = config(
            workdir,
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = codex_home.join("config.toml");
        cfg.codex_auth_path = codex_home.join("auth.json");

        let isolated_home = stable_isolated_codex_home_path(&cfg);
        let target_file = isolated_home.join("sessions/2026/05/19/old.jsonl");
        fs::create_dir_all(target_file.parent().unwrap()).unwrap();
        fs::write(&target_file, "isolated-newer\n").unwrap();

        let isolated = prepare_isolated_codex_home(&cfg).unwrap();

        assert_eq!(isolated.home, isolated_home);
        assert_eq!(
            fs::read_to_string(&target_file).unwrap(),
            "isolated-newer\n"
        );
        let _ = fs::remove_dir_all(isolated.home);
    }

    #[test]
    fn isolated_codex_home_path_is_stable_per_config_and_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        let mut cfg = config(
            workdir,
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            codex_home,
        );
        cfg.config_path = Some(tmp.path().join("Configs").join("我的 配置.json"));
        cfg.agent_id = "frontend/agent".to_string();

        let first = stable_isolated_codex_home_path(&cfg);
        let second = stable_isolated_codex_home_path(&cfg);

        assert_eq!(first, second);
        assert!(first.starts_with(app_runtime_dir().join("codex-homes")));
        assert!(first.to_string_lossy().contains("我的_配置-"));
        assert!(first.ends_with("frontend_agent"));
        assert!(!first.starts_with(std::env::temp_dir()));
    }

    #[test]
    fn codex_cli_overrides_are_inserted_after_executable() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(&codex_home).unwrap();
        let config_path = codex_home.join("config.toml");
        fs::write(
            &config_path,
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec![
                "codex".to_string(),
                "resume".to_string(),
                "--no-alt-screen".to_string(),
                "session-1".to_string(),
            ]),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = config_path;
        let endpoint = endpoint(workdir);

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected args command");
        };
        assert_eq!(items[0], "codex");
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "model=\"gpt-test\""]));
        assert!(items.windows(2).any(|pair| pair
            == [
                "-c",
                "model_providers.custom.base_url=\"https://api.example.test\""
            ]));
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "service_tier=\"fast\""]));
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "tui.animations=true"]));
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "tui.raw_output_mode=false"]));
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "tui.show_tooltips=true"]));
        assert!(items.windows(2).any(|pair| pair[0] == "-c"
            && pair[1].starts_with("tui.status_line=[")
            && pair[1].contains("\"context-window\"")
            && pair[1].contains("\"run-state\"")
            && pair[1].contains("\"task-progress\"")
            && pair[1].contains(concat!("\"used-", "to", "kens\""))
            && pair[1].contains("\"fast-mode\"")));
        assert!(items.iter().any(|item| item == "resume"));
        assert!(items.iter().any(|item| item == "session-1"));
    }

    #[test]
    fn codex_cli_overrides_preserve_no_alt_screen_for_scrollback() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(&codex_home).unwrap();
        let config_path = codex_home.join("config.toml");
        fs::write(
            &config_path,
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec![
                "codex".to_string(),
                "resume".to_string(),
                "--no-alt-screen".to_string(),
                "session-1".to_string(),
            ]),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = config_path;
        let endpoint = endpoint(workdir);

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected args command");
        };
        assert!(items.iter().any(|item| item == "--no-alt-screen"));
        assert_eq!(items[0], "codex");
        assert!(items.iter().any(|item| item == "resume"));
        assert!(items.iter().any(|item| item == "session-1"));
    }

    #[test]
    fn codex_cli_overrides_include_model_context_window_when_configured() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(&codex_home).unwrap();
        let config_path = codex_home.join("config.toml");
        fs::write(
            &config_path,
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string(), "--no-alt-screen".to_string()]),
            tmp.path().join("state.json"),
            codex_home,
        );
        cfg.codex_config_path = config_path;
        cfg.codex_model_context_window = Some(128000);
        let endpoint = endpoint(workdir);

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected args command");
        };
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "model_context_window=128000"]));
    }

    #[test]
    fn codex_shell_cli_overrides_are_inserted_before_resume_subcommand() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(&codex_home).unwrap();
        let config_path = codex_home.join("config.toml");
        fs::write(
            &config_path,
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Shell("codex resume --no-alt-screen session-1".to_string()),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = config_path;
        let endpoint = endpoint(workdir);

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected shell command to be normalized to args command");
        };
        let resume_pos = items
            .iter()
            .position(|item| item == "resume")
            .expect("resume subcommand should be preserved");
        let animation_override_pos = items
            .windows(2)
            .position(|pair| pair == ["-c", "tui.animations=true"])
            .expect("Codex TUI animation override should be present");

        assert_eq!(items[0], "codex");
        assert!(animation_override_pos < resume_pos);
        assert!(items.iter().any(|item| item == "--no-alt-screen"));
        assert!(items.iter().any(|item| item == "session-1"));
    }

    #[test]
    fn codex_shell_cli_overrides_preserve_single_quoted_arguments() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(&codex_home).unwrap();
        let config_path = codex_home.join("config.toml");
        fs::write(
            &config_path,
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Shell("codex --profile 'team space' resume session-1".to_string()),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = config_path;
        let endpoint = endpoint(workdir);

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected shell command to be normalized to args command");
        };
        assert_eq!(items[0], "codex");
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "tui.show_tooltips=true"]));
        assert!(items
            .windows(2)
            .any(|pair| pair == ["--profile", "team space"]));
        assert!(!items.iter().any(|item| item == "'team" || item == "space'"));
    }

    #[test]
    fn codex_shell_cli_overrides_target_codex_inside_cmd_wrapper() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(&codex_home).unwrap();
        let config_path = codex_home.join("config.toml");
        fs::write(
            &config_path,
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Shell("cmd /d /c codex resume session-1".to_string()),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = config_path;
        let endpoint = endpoint(workdir);

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected shell command to be normalized to args command");
        };
        let cmd_switch_pos = items.iter().position(|item| item == "/c").unwrap();
        let codex_pos = items.iter().position(|item| item == "codex").unwrap();
        let override_pos = items
            .windows(2)
            .position(|pair| pair == ["-c", "tui.animations=true"])
            .unwrap();
        let resume_pos = items.iter().position(|item| item == "resume").unwrap();

        assert!(cmd_switch_pos < codex_pos);
        assert!(codex_pos < override_pos);
        assert!(override_pos < resume_pos);
        assert_eq!(items[0], "cmd");
        assert!(items.iter().any(|item| item == "session-1"));
    }

    #[test]
    fn codex_shell_cli_overrides_expand_quoted_cmd_script() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(&codex_home).unwrap();
        let config_path = codex_home.join("config.toml");
        fs::write(
            &config_path,
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Shell(r#"cmd /d /c "codex resume session-1""#.to_string()),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = config_path;
        let endpoint = endpoint(workdir);

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected shell command to be normalized to args command");
        };
        let codex_pos = items.iter().position(|item| item == "codex").unwrap();
        let override_pos = items
            .windows(2)
            .position(|pair| pair == ["-c", "tui.raw_output_mode=false"])
            .unwrap();
        let resume_pos = items.iter().position(|item| item == "resume").unwrap();

        assert!(codex_pos < override_pos);
        assert!(override_pos < resume_pos);
        assert!(!items.iter().any(|item| item == "codex resume session-1"));
    }

    #[test]
    fn codex_shell_cli_overrides_target_codex_inside_powershell_wrapper() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(&codex_home).unwrap();
        let config_path = codex_home.join("config.toml");
        fs::write(
            &config_path,
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Shell(
                r#"powershell -NoProfile -Command "codex resume session-1""#.to_string(),
            ),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = config_path;
        let endpoint = endpoint(workdir);

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected shell command to be normalized to args command");
        };
        let command_pos = items.iter().position(|item| item == "-Command").unwrap();
        let codex_pos = items.iter().position(|item| item == "codex").unwrap();
        let override_pos = items
            .windows(2)
            .position(|pair| pair == ["-c", "tui.show_tooltips=true"])
            .unwrap();
        let resume_pos = items.iter().position(|item| item == "resume").unwrap();

        assert!(command_pos < codex_pos);
        assert!(codex_pos < override_pos);
        assert!(override_pos < resume_pos);
        assert_eq!(items[0], "powershell");
        assert!(items.iter().any(|item| item == "session-1"));
    }

    #[test]
    fn codex_shell_cli_overrides_target_codex_inside_bash_login_wrapper() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let codex_home = tmp.path().join(".codex");
        fs::create_dir_all(&codex_home).unwrap();
        let config_path = codex_home.join("config.toml");
        fs::write(
            &config_path,
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Shell(r#"bash -lc "codex resume session-1""#.to_string()),
            tmp.path().join("state.json"),
            codex_home.clone(),
        );
        cfg.codex_config_path = config_path;
        let endpoint = endpoint(workdir);

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected shell command to be normalized to args command");
        };
        let shell_option_pos = items.iter().position(|item| item == "-lc").unwrap();
        let codex_pos = items.iter().position(|item| item == "codex").unwrap();
        let override_pos = items
            .windows(2)
            .position(|pair| pair == ["-c", "tui.animations=true"])
            .unwrap();
        let resume_pos = items.iter().position(|item| item == "resume").unwrap();

        assert!(shell_option_pos < codex_pos);
        assert!(codex_pos < override_pos);
        assert!(override_pos < resume_pos);
        assert_eq!(items[0], "bash");
        assert!(items.iter().any(|item| item == "session-1"));
        assert!(!items.iter().any(|item| item == "codex resume session-1"));
    }

    #[test]
    fn ready_and_model_upgrade_markers_are_detected() {
        assert!(ready_banner_visible("abc Sandbox ready xyz"));
        assert!(ready_banner_visible("› Explain this codebase"));
        assert!(ready_banner_visible("› Write tests for @filename"));
        assert!(ready_banner_visible(
            "› Implement {feature}\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\XAgent"
        ));
        assert!(ready_banner_visible(
            "› Find and fix a bug in @filename\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\XAgent"
        ));
        assert!(ready_banner_visible(
            "› Improve documentation in @filename\ngpt-5.5 xhigh · D:\\Works\\SelfWorks\\ModernUI"
        ));
        assert!(!ready_banner_visible(
            "• Working (12s • esc to interrupt)\n› Explain this codebase\ngpt-5.5 xhigh · D:\\Works\\SelfWorks\\ModernUI"
        ));
        assert!(!ready_banner_visible(
            "› 只回复ok\n\n• Messages to be submitted after next tool call (press esc to interrupt and send immediately)\n  ↳ 只回复ok\ngpt-5.5 xhigh · D:\\Works\\SelfWorks\\ModernUI"
        ));
        assert!(!ready_banner_visible(
            "› 我打算离开电脑一段时间，需要你进入无人值守模式，继续吧\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\XAgent"
        ));
        assert!(!ready_banner_visible(
            "› Implement auth retry logic\n\
             gpt-5.5 xhigh · D:\\Works\\SelfWorks\\XAgent"
        ));
        assert!(model_upgrade_prompt_visible(
            "Introducing GPT-5.4\nChoose how you'd like Codex to proceed.\nTry new model"
        ));
        assert!(model_upgrade_prompt_visible(
            "Introducing GPT-5.9\nChoose how you'd like Codex to proceed.\nTry new model"
        ));
        assert!(!model_upgrade_prompt_visible("Introducing GPT-5.4 only"));
        assert!(codex_update_prompt_visible(
            "Update available! 0.131.0 -> 0.132.0\n1. Update now\n2. Skip\n3. Skip until next version\nPress enter to continue"
        ));
        assert!(!codex_update_prompt_visible("Update available only"));
        assert!(trust_directory_prompt_visible(
            "Do you \u{1b}[36mtrust\u{1b}[0m the contents of this directory? Working with untrusted contents comes with higher risk of prompt injection.\n\u{1b}[36m1. Yes, continue\u{1b}[0m\n2. No, quit\nPress enter to continue and create a sandbox..."
        ));
        assert_eq!(trust_directory_prompt_response("control-m"), "\r");
        assert_eq!(trust_directory_prompt_response("crlf"), "\r\n");
        assert!(sandbox_setup_prompt_visible(
            "Set up the Codex agent sandbox to protect your files\n2. Use non-admin sandbox\nPress enter to confirm"
        ));
        assert!(!sandbox_setup_prompt_visible(
            "Set up the Codex agent sandbox only"
        ));
        assert!(codex_repair_prompt_visible(
            "Codex couldn't start because its local database appears to be damaged.\n\
             Codex can try a safe repair by backing up those files and rebuilding them.\n\
             Technical details:\n\
               Location: C:\\Users\\WPX\\Desktop\\WatchApiRust-portable-litellm\\Runtime\\codex-homes\\新配置_3\\codex-新配置\\state_5.sqlite\n\
               Cause: failed to initialize state runtime at C:\\Users\\WPX\\Desktop\\WatchApiRust-portable-litellm\\Runtime\\codex-homes\\新配置_3\\codex-新配置: error returned from database: (code: 11) database disk image is malformed\n\
             Repair Codex local data now? [y/N]:"
        ));
        assert!(codex_repair_prompt_visible(
            "Cause: failed to initialize state runtime at C:\\tmp\\codex-home: error returned from database: (code: 11) database disk image is malformed\n\
             Repair Codex local data now? [y/N]:"
        ));
        assert!(!codex_repair_prompt_visible("Codex couldn't start only"));
        assert!(generic_first_option_prompt_visible(
            "Choose an option:\n> 1. Continue with current settings\n  2. Quit\nPress enter to confirm"
        ));
        assert!(generic_first_option_prompt_visible(
            "Select how to continue\n❯ 1. Use recommended defaults\n  2. Cancel"
        ));
        assert!(generic_first_option_prompt_visible(
            "Some startup screen\nrandom text > 1. Continue with defaults\n  2. Cancel"
        ));
        assert!(generic_first_option_prompt_visible(
            "新的启动选项\n➜ 1. 使用推荐配置  2. 退出"
        ));
        assert!(generic_first_option_prompt_visible(
            "Resume paused goal?\n\
             Goal: Continue the AutoEngine project from the current workspace state\n\n\
             › 1. Resume goal   Mark it active and continue when idle\n\
               2. Start without this goal"
        ));
        assert!(!generic_first_option_prompt_visible(
            "› 1. 这是用户输入框里的普通内容\n2. 不应该自动选择"
        ));
        assert!(!generic_first_option_prompt_visible(
            "Output summary:\n> 1. This is just rendered text without a second option"
        ));
        assert!(!generic_first_option_prompt_visible(
            "Output summary:\n› 1. This is just rendered text\n  2. Also rendered text"
        ));
    }

    #[test]
    fn codex_auto_prompt_is_flattened_before_terminal_submit() {
        let prompt = "我打算离开电脑一段时间\n1. 继续上一次;\n2. 使用git-commit提交;\n";

        assert_eq!(
            codex_auto_prompt_input_text(prompt),
            "我打算离开电脑一段时间 1. 继续上一次; 2. 使用git-commit提交;"
        );
        assert!(!codex_auto_prompt_input_text(prompt).contains('\n'));
    }

    #[test]
    fn trust_directory_prompt_is_detected_from_terminal_view_text() {
        use crate::terminal_emulator::{
            TerminalCellView, TerminalCursorShape, TerminalModeView, TerminalRgb,
        };

        let lines = [
            "Welcome to Codex, OpenAI's command-line coding agent",
            "",
            "> You are in C:\\Users\\WPX\\Desktop\\TEST",
            "",
            "Do you trust the contents of this directory? Working with untrusted contents comes with higher risk of prompt injection.",
            "",
            "> 1. Yes, continue",
            "  2. No, quit",
            "",
            "Press enter to continue",
        ];
        let cols = 128;
        let rows = lines.len();
        let mut cells = Vec::new();
        for line in lines {
            let mut chars = line.chars().collect::<Vec<_>>();
            chars.resize(cols, ' ');
            cells.extend(chars.into_iter().map(|c| TerminalCellView {
                c,
                fg: TerminalRgb {
                    r: 255,
                    g: 255,
                    b: 255,
                },
                bg: TerminalRgb { r: 0, g: 0, b: 0 },
                bold: false,
                dim: false,
                italic: false,
                underline: false,
                strikeout: false,
                inverse: false,
                hidden: false,
                wide: false,
                wide_spacer: false,
                wrapline: false,
            }));
        }
        let view = TerminalView {
            revision: 1,
            rows,
            cols,
            scrollback_lines: 0,
            cursor_row: rows - 1,
            cursor_col: 0,
            cursor_shape: TerminalCursorShape::Block,
            display_offset: 0,
            modes: TerminalModeView::default(),
            cells,
        };

        assert!(trust_directory_prompt_visible(&terminal_view_visible_text(
            &view
        )));
    }

    #[test]
    fn terminal_prompt_detection_uses_cached_view_text() {
        let source = include_str!("agent.rs");
        let observe_block = source
            .split("fn observe_output_text(&mut self, text: &str)")
            .nth(1)
            .and_then(|tail| tail.split("fn handle_terminal_prompts").next())
            .expect("observe output block should be discoverable");
        let poll_block = source
            .split("pub fn poll_monitor(&mut self)")
            .nth(1)
            .and_then(|tail| tail.split("pub fn terminal_snapshot").next())
            .expect("poll monitor block should be discoverable");
        let refresh_block = source
            .split("fn refresh_observed_terminal_view_text(&mut self)")
            .nth(1)
            .and_then(|tail| tail.split("fn observed_terminal_text_for_test").next())
            .expect("observed view refresh block should be discoverable");

        assert!(!observe_block.contains("TerminalSession::view"));
        assert!(!observe_block.contains("terminal_view_visible_text"));
        assert!(!observe_block.contains("handle_terminal_prompts"));
        assert!(poll_block.contains("self.refresh_observed_terminal_view_text();"));
        assert!(poll_block.contains("self.handle_terminal_prompts();"));
        assert!(refresh_block.contains("terminal.view_revision()"));
        assert!(refresh_block.contains("if revision == self.observed_terminal_view_revision"));
        assert!(refresh_block.contains("ready_banner_visible(&self.observed_terminal_view_text)"));
    }
}
