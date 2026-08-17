use crate::codex_files::{
    apply_codex_endpoint_with_model_limits, ensure_codex_unattended_state,
    get_current_model_provider,
};
use crate::config::{
    agent_driver_from_command_part, shell_wrapper_command_start, split_shell_like_command,
    AgentCommand, AgentDriver as AgentDriverKind, AppConfig, ContinuationMode, EndpointConfig,
};
use crate::cooldown::cooldown_seconds_from_text;
use crate::sessions::{
    codex_session_file_matches, ClaudeSessionIndex, ClaudeSessionMonitor, CodexSessionIndex,
    CodexSessionMonitor, OpenCodeSessionMonitor, SessionBindingKey, SessionStore,
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
use std::time::{Duration, Instant};

const INTERACTIVE_AGENT_READY_UNLOCK_GRACE: Duration = Duration::from_secs(2);
const CODEX_STALE_WORKING_UNLOCK_GRACE: Duration = Duration::from_secs(20);
const CODEX_ISOLATED_RUNTIME_DIR: &str = "runtime-v2";
const OPENCODE_PROMPT_SUBMIT_DELAY: Duration = Duration::from_millis(80);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLaunch {
    pub command: AgentCommand,
    pub resumed: bool,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentForkSource {
    session_id: String,
    session_path: Option<PathBuf>,
}

pub struct AgentProcess {
    config: AppConfig,
    endpoint: EndpointConfig,
    store: SessionStore,
    force_new_session: bool,
    fork_source: Option<AgentForkSource>,
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
    handled_command_approval_prompt: bool,
    handled_claude_terms_prompt: bool,
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

    fn session_path(&self) -> Option<PathBuf> {
        match self {
            Self::Codex(monitor) => monitor.session_path.clone(),
            Self::Claude(monitor) => monitor.session_path(),
            Self::OpenCode(_) => None,
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
            Self::Claude(monitor) => monitor.token_usage_total,
            Self::OpenCode(monitor) => monitor.token_usage_total,
        }
    }

    fn begin_waiting_for_new_turn(&mut self) {
        match self {
            Self::Codex(monitor) => monitor.begin_waiting_for_new_turn(),
            Self::Claude(monitor) => monitor.begin_waiting_for_new_turn(),
            Self::OpenCode(monitor) => monitor.begin_waiting_for_new_turn(),
        }
    }

    fn has_inflight_turn(&self) -> bool {
        match self {
            Self::Codex(monitor) => monitor.has_inflight_turn(),
            Self::Claude(monitor) => monitor.has_inflight_turn(),
            Self::OpenCode(monitor) => monitor.has_inflight_turn(),
        }
    }

    fn last_task_started(&self) -> bool {
        match self {
            Self::Codex(monitor) => monitor.last_task_started_at.is_some(),
            Self::Claude(monitor) => monitor.has_assistant_message_since_wait_start(),
            Self::OpenCode(monitor) => monitor.has_assistant_message_since_wait_start(),
        }
    }

    fn last_task_finished(&self) -> bool {
        match self {
            Self::Codex(monitor) => monitor.last_task_finished_at.is_some(),
            Self::Claude(monitor) => monitor.has_completed_assistant_message_since_wait_start(),
            Self::OpenCode(monitor) => monitor.has_completed_assistant_message_since_wait_start(),
        }
    }

    fn mark_turn_completed_by_idle(&mut self) {
        if let Self::Codex(monitor) = self {
            monitor.mark_turn_completed_by_idle();
        }
    }

    fn has_assistant_message_since_wait_start(&self) -> bool {
        match self {
            Self::Codex(monitor) => monitor.has_assistant_message_since_wait_start(),
            Self::Claude(monitor) => monitor.has_assistant_message_since_wait_start(),
            Self::OpenCode(monitor) => monitor.has_assistant_message_since_wait_start(),
        }
    }

    fn has_completed_assistant_message_since_wait_start(&self) -> bool {
        match self {
            Self::Codex(monitor) => {
                monitor.last_task_finished_at.is_some()
                    && !monitor.has_inflight_turn()
                    && monitor.has_assistant_message_since_wait_start()
            }
            Self::Claude(monitor) => monitor.has_completed_assistant_message_since_wait_start(),
            Self::OpenCode(monitor) => monitor.has_completed_assistant_message_since_wait_start(),
        }
    }

    fn has_session_assistant_message_since_wait_start(&self) -> bool {
        self.has_assistant_message_since_wait_start()
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
            Self::Claude(monitor) => monitor.last_session_append_at.map(|at| at.elapsed()),
            Self::OpenCode(monitor) => monitor.last_session_append_at.map(|at| at.elapsed()),
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
            Self::Claude(monitor) => monitor.last_session_append_at,
            Self::OpenCode(monitor) => monitor.last_session_append_at,
        }
    }
}

impl AgentProcess {
    pub fn new(config: AppConfig, endpoint: EndpointConfig, force_new_session: bool) -> Self {
        Self::with_fork_source(config, endpoint, force_new_session, None)
    }

    pub fn new_fork(
        config: AppConfig,
        endpoint: EndpointConfig,
        source_session_id: String,
        source_session_path: Option<PathBuf>,
    ) -> Self {
        Self::with_fork_source(
            config,
            endpoint,
            false,
            Some(AgentForkSource {
                session_id: source_session_id,
                session_path: source_session_path,
            }),
        )
    }

    fn with_fork_source(
        config: AppConfig,
        endpoint: EndpointConfig,
        force_new_session: bool,
        fork_source: Option<AgentForkSource>,
    ) -> Self {
        let handled_claude_terms_prompt = config.agent_driver != AgentDriverKind::ClaudeCode;
        let store = SessionStore::new(config.session_state_path.clone());
        Self {
            config,
            endpoint,
            store,
            force_new_session,
            fork_source,
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
            handled_command_approval_prompt: false,
            handled_claude_terms_prompt,
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
        let mut launch = if let Some(source) = self.fork_source.as_ref() {
            let command = match launch_config.agent_driver {
                AgentDriverKind::Codex => codex_fork_command(
                    &codex_goal_feature_command(&launch_config),
                    &self.endpoint.workdir,
                    &source.session_id,
                )?,
                AgentDriverKind::ClaudeCode => {
                    claude_fork_command(&launch_config.agent_command, &source.session_id)?
                }
                AgentDriverKind::OpenCode => {
                    opencode_fork_command(&launch_config.agent_command, &source.session_id)?
                }
                AgentDriverKind::Generic => {
                    anyhow::bail!("Generic 驱动不支持分叉会话");
                }
            };
            AgentLaunch {
                command,
                // A fork has inherited history, but must discover and bind its new session ID.
                resumed: true,
                session_id: None,
            }
        } else {
            self.build_launch_for_runtime_config(&launch_config, &self.config.clone())?
        };
        if launch_config.agent_driver == AgentDriverKind::Codex {
            if let Some(source) = self.fork_source.as_ref() {
                copy_codex_resume_session_to_isolated_home(
                    &self.config.codex_home,
                    &launch_config.codex_home,
                    &self.endpoint.workdir,
                    &source.session_id,
                    source.session_path.as_deref(),
                )?;
            } else if let Some(session_id) = launch.session_id.as_deref().filter(|_| launch.resumed)
            {
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
            }
            ensure_codex_unattended_state(&launch_config.codex_home)?;
            let codex_model_limits =
                launch_config.effective_codex_model_limits(&self.endpoint.name);
            apply_codex_endpoint_with_model_limits(
                &self.endpoint,
                &launch_config.codex_config_path,
                &launch_config.codex_auth_path,
                &launch_config.codex_provider_name,
                codex_model_limits.model_context_window,
                codex_model_limits.model_auto_compact_token_limit,
            )?;
            terminal_env.insert("OPENAI_API_KEY".to_string(), self.endpoint.api_key.clone());
            launch.command =
                codex_command_with_cli_overrides(launch.command, &self.endpoint, &launch_config);
        }
        match launch_config.agent_driver {
            AgentDriverKind::ClaudeCode => {
                terminal_env.insert(
                    "ANTHROPIC_BASE_URL".to_string(),
                    anthropic_base_url(&self.endpoint.base_url),
                );
                terminal_env.insert(
                    "ANTHROPIC_AUTH_TOKEN".to_string(),
                    self.endpoint.api_key.clone(),
                );
                terminal_env.insert(
                    "ANTHROPIC_API_KEY".to_string(),
                    self.endpoint.api_key.clone(),
                );
                terminal_env.insert("ANTHROPIC_MODEL".to_string(), self.endpoint.model.clone());
                launch.command =
                    claude_command_with_endpoint_overrides(launch.command, &self.endpoint);
            }
            AgentDriverKind::OpenCode => {
                terminal_env.insert("OPENAI_API_KEY".to_string(), self.endpoint.api_key.clone());
                terminal_env.insert(
                    "OPENAI_BASE_URL".to_string(),
                    self.endpoint.base_url.clone(),
                );
                terminal_env.insert(
                    "OPENCODE_CONFIG_CONTENT".to_string(),
                    opencode_endpoint_config_content(
                        &self.endpoint,
                        &launch_config.probe_path,
                        launch_config.codex_model_context_window,
                    ),
                );
                launch.command =
                    opencode_command_with_endpoint_overrides(launch.command, &self.endpoint);
            }
            AgentDriverKind::Codex | AgentDriverKind::Generic => {}
        }
        let opencode_session_baseline = if launch_config.agent_driver == AgentDriverKind::OpenCode
            && launch.session_id.is_none()
        {
            OpenCodeSessionMonitor::capture_session_baseline(
                &command_args(&launch.command),
                &self.endpoint.workdir,
            )
        } else {
            None
        };
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
                )
                .with_session_baseline(opencode_session_baseline),
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
        self.isolated_codex_home = None;
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
        match &self.config.agent_driver {
            AgentDriverKind::Codex => terminal.send_prompt(
                &codex_auto_prompt_input_text(prompt),
                &self.config.prompt_submit_sequence,
                InputSource::Auto,
            )?,
            AgentDriverKind::OpenCode => terminal.send_pasted_prompt(
                prompt,
                &self.config.prompt_submit_sequence,
                OPENCODE_PROMPT_SUBMIT_DELAY,
                InputSource::Auto,
            )?,
            AgentDriverKind::ClaudeCode | AgentDriverKind::Generic => terminal.send_prompt(
                prompt,
                &self.config.prompt_submit_sequence,
                InputSource::Auto,
            )?,
        }
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
        let ready_unlock_allowed = !self.ready_unlock_grace_active();
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
        if self.current_terminal_prefilled_input_visible() {
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
            return Some(match &self.config.agent_driver {
                AgentDriverKind::Codex => "等待 Codex 就绪",
                AgentDriverKind::ClaudeCode => "等待 Claude 就绪",
                AgentDriverKind::OpenCode => "等待 OpenCode 输入框就绪",
                AgentDriverKind::Generic => "等待 Agent 就绪",
            });
        }
        if self.current_terminal_prefilled_input_visible() {
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
            if self.config.agent_driver == AgentDriverKind::Codex
                && codex_queued_message_visible(&self.observed_terminal_view_text)
            {
                return Some("已有排队消息");
            }
            if (self.config.agent_driver == AgentDriverKind::Codex
                && codex_working_prompt_visible(&self.observed_terminal_view_text))
                || (self.config.agent_driver == AgentDriverKind::OpenCode
                    && opencode_busy_prompt_visible(&self.observed_terminal_view_text))
            {
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
            && !self.ready_unlock_grace_active()
    }

    pub fn needs_submit_retry(&self, retry_seconds: f64) -> bool {
        if !self.startup_ready_for_prompt() {
            return false;
        }
        if self.current_terminal_view_busy() {
            return false;
        }
        let visible_prefilled_input = self.current_terminal_prefilled_input_visible();
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
            .is_some_and(AgentSessionMonitor::has_session_assistant_message_since_wait_start)
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
            let session_path = self
                .monitor
                .as_ref()
                .and_then(AgentSessionMonitor::session_path)
                .or_else(|| self.store.get_bound_session_path(&key));
            self.store
                .set_bound_session_id(&key, session_id, session_path.as_deref())?;
        }
        Ok(())
    }

    pub fn active_session(&self) -> Option<(String, Option<PathBuf>)> {
        let session_id = self
            .launch
            .as_ref()
            .and_then(|launch| launch.session_id.clone())?;
        let key = session_binding_key(&self.config, &self.endpoint);
        let session_path = self
            .monitor
            .as_ref()
            .and_then(AgentSessionMonitor::session_path)
            .or_else(|| self.store.get_bound_session_path(&key));
        Some((session_id, session_path))
    }

    pub fn active_codex_session(&self) -> Option<(String, Option<PathBuf>)> {
        (self.config.agent_driver == AgentDriverKind::Codex)
            .then(|| self.active_session())
            .flatten()
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
        if !self.saw_ready_banner && self.ready_banner_visible(&self.recent_output) {
            self.saw_ready_banner = true;
        }
    }

    fn handle_terminal_prompts(&mut self) {
        if self.handled_model_upgrade_prompt
            && self.handled_codex_update_prompt
            && self.handled_trust_directory_prompt
            && self.handled_sandbox_setup_prompt
            && self.handled_codex_repair_prompt
            && self.handled_command_approval_prompt
            && self.handled_claude_terms_prompt
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
        if !self.handled_command_approval_prompt
            && codex_command_approval_prompt_visible(observed)
            && self.write_auto_terminal_input(format!(
                "2{}",
                submit_sequence_text(&self.config.prompt_submit_sequence)
            ))
        {
            self.handled_command_approval_prompt = true;
        }
        if !self.handled_claude_terms_prompt
            && claude_terms_acceptance_prompt_visible(observed)
            && self.write_auto_terminal_input(format!(
                "{}{}",
                claude_terms_acceptance_prompt_navigation(observed),
                submit_sequence_text(&self.config.prompt_submit_sequence)
            ))
        {
            self.handled_claude_terms_prompt = true;
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
                && self.ready_banner_visible(&self.observed_terminal_view_text)
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
        if self.observed_terminal_view_text.trim().is_empty() {
            return false;
        }
        match &self.config.agent_driver {
            AgentDriverKind::Codex => {
                ready_banner_visible(&self.observed_terminal_view_text)
                    && !codex_prefilled_input_visible(
                        &self.observed_terminal_view_text,
                        self.observed_current_input_placeholder,
                    )
            }
            AgentDriverKind::OpenCode => {
                opencode_idle_prompt_visible(&self.observed_terminal_view_text)
            }
            AgentDriverKind::ClaudeCode | AgentDriverKind::Generic => {
                ready_banner_visible(&self.observed_terminal_view_text)
            }
        }
    }

    fn current_terminal_prefilled_input_visible(&self) -> bool {
        match &self.config.agent_driver {
            AgentDriverKind::Codex => codex_prefilled_input_visible(
                &self.observed_terminal_view_text,
                self.observed_current_input_placeholder,
            ),
            AgentDriverKind::OpenCode => {
                opencode_prefilled_input_visible(&self.observed_terminal_view_text)
            }
            AgentDriverKind::ClaudeCode | AgentDriverKind::Generic => false,
        }
    }

    fn ready_banner_visible(&self, text: &str) -> bool {
        match &self.config.agent_driver {
            AgentDriverKind::OpenCode => opencode_idle_prompt_visible(text),
            AgentDriverKind::Codex | AgentDriverKind::ClaudeCode | AgentDriverKind::Generic => {
                ready_banner_visible(text)
            }
        }
    }

    fn current_terminal_view_busy(&self) -> bool {
        if self.observed_terminal_view_text.trim().is_empty() {
            return false;
        }
        match &self.config.agent_driver {
            AgentDriverKind::OpenCode => {
                opencode_busy_prompt_visible(&self.observed_terminal_view_text)
            }
            AgentDriverKind::Codex | AgentDriverKind::ClaudeCode | AgentDriverKind::Generic => {
                codex_busy_prompt_visible(&self.observed_terminal_view_text)
            }
        }
    }

    fn stale_working_prompt_can_unlock(&self) -> bool {
        if self.config.agent_driver != AgentDriverKind::Codex {
            return false;
        }
        let text = self.observed_terminal_view_text.as_str();
        if text.trim().is_empty()
            || codex_queued_message_visible(text)
            || !codex_working_prompt_visible(text)
            || !codex_idle_prompt_visible(text)
            || self.ready_unlock_grace_active()
        {
            return false;
        }
        self.last_prompt_sent_at
            .is_some_and(|at| at.elapsed() >= CODEX_STALE_WORKING_UNLOCK_GRACE)
            && self.recent_activity_elapsed() >= CODEX_STALE_WORKING_UNLOCK_GRACE
    }

    fn ready_unlock_grace_active(&self) -> bool {
        self.config.agent_driver != AgentDriverKind::Generic
            && self
                .last_prompt_sent_at
                .is_some_and(|at| at.elapsed() < INTERACTIVE_AGENT_READY_UNLOCK_GRACE)
    }

    fn startup_ready_for_prompt(&self) -> bool {
        match &self.config.agent_driver {
            AgentDriverKind::Codex => {
                if codex_update_prompt_visible(&self.recent_output) {
                    return false;
                }
                self.saw_ready_banner
                    || self
                        .launched_at
                        .is_some_and(|at| at.elapsed() >= Duration::from_secs(12))
            }
            AgentDriverKind::OpenCode => {
                opencode_prompt_footer_visible(&self.observed_terminal_view_text)
            }
            AgentDriverKind::ClaudeCode | AgentDriverKind::Generic => true,
        }
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
                false,
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
    build_agent_launch_for_codex_restore_home_in(
        &app_runtime_dir(),
        runtime_config,
        restore_config,
        endpoint,
        store,
        force_new_session,
        missing_policy,
    )
}

fn build_agent_launch_for_codex_restore_home_in(
    runtime_dir: &Path,
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
    // The isolated home belongs to this configuration. Do not search other
    // configurations' homes by workdir because that can import their session ID
    // into this configuration and create another history branch. Keep the global
    // home only as a fallback for an already-bound session during migration.
    let binding = session_binding_key(restore_config, endpoint);
    if restore_config.restore_sessions && !force_new_session {
        prefer_config_owned_legacy_session_binding_in(
            runtime_dir,
            restore_config,
            endpoint,
            store,
            &binding,
        )?;
    }
    let mut fallback_homes = Vec::new();
    if let Some(session_id) = store.get_bound_session_id(&binding) {
        let isolated_index = CodexSessionIndex::new(runtime_config.codex_home.clone());
        if isolated_index
            .find_latest_session_file_for_workdir(&endpoint.workdir, Some(&session_id))
            .is_none()
        {
            fallback_homes.push(restore_config.codex_home.clone());
        }
    }
    let codex_index = CodexSessionIndex::new(runtime_config.codex_home.clone())
        .with_additional_homes(fallback_homes);
    let session_id = resume_session_id(
        restore_config,
        endpoint,
        store,
        &codex_index,
        force_new_session,
        missing_policy,
        // Each isolated runtime owns its own JSONL copy. Two configurations can
        // legitimately retain an older branch with the same Codex session ID.
        true,
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

fn prefer_config_owned_legacy_session_binding_in(
    runtime_dir: &Path,
    config: &AppConfig,
    endpoint: &EndpointConfig,
    store: &mut SessionStore,
    binding: &SessionBindingKey,
) -> Result<()> {
    let config_root = isolated_codex_config_root_path_in(runtime_dir, config);
    // Prefer this configuration's private history before using its original
    // source home. The lookup is confined to the current configuration root,
    // so it cannot adopt another configuration's branch.
    let owned_homes = config_owned_codex_homes_in(runtime_dir, config);
    let Some(session_id) = store.get_bound_session_id(binding) else {
        if let Some((private_session_id, private_path)) =
            find_latest_config_owned_session_binding(&owned_homes, endpoint)
        {
            store.set_bound_session_id(binding, &private_session_id, Some(&private_path))?;
        }
        return Ok(());
    };
    let bound_path = store.get_bound_session_path(binding);
    if bound_path.as_deref().is_some_and(|path| {
        path_is_within(path, &config_root)
            && codex_session_file_matches(path, &endpoint.workdir, &session_id)
    }) {
        return Ok(());
    }

    for legacy_home in &owned_homes {
        if prefer_config_owned_session_binding_from_home(
            legacy_home,
            endpoint,
            store,
            binding,
            &session_id,
        )? {
            return Ok(());
        }
    }

    // A stale cache can carry a completely foreign session ID, not just a
    // foreign path. When this configuration has a private history for the
    // workdir, it is the only safe automatic recovery candidate. Do not scan
    // global or sibling configuration homes before using it.
    if let Some((private_session_id, private_path)) =
        find_latest_config_owned_session_binding(&owned_homes, endpoint)
    {
        return store.set_bound_session_id(binding, &private_session_id, Some(&private_path));
    }

    match bound_path {
        // No private history exists yet. Retain an ID-only binding so the
        // configured source home can complete the older migration path below.
        None => Ok(()),
        Some(path)
            if path_is_within(&path, &config.codex_home)
                && codex_session_file_matches(&path, &endpoint.workdir, &session_id) =>
        {
            Ok(())
        }
        // No configuration-owned history exists and this explicit path is
        // stale or belongs to a different profile. Start fresh instead of
        // importing an untrusted branch.
        Some(_) => store.delete_bound_session_id(binding),
    }
}

fn find_latest_config_owned_session_binding(
    homes: &[PathBuf],
    endpoint: &EndpointConfig,
) -> Option<(String, PathBuf)> {
    let (first, rest) = homes.split_first()?;
    CodexSessionIndex::new(first.clone())
        .with_additional_homes(rest.to_vec())
        .find_latest_session_for_workdir(&endpoint.workdir, None)
}

fn prefer_config_owned_session_binding_from_home(
    legacy_home: &Path,
    endpoint: &EndpointConfig,
    store: &mut SessionStore,
    binding: &SessionBindingKey,
    session_id: &str,
) -> Result<bool> {
    let Some(private_path) = CodexSessionIndex::new(legacy_home.to_path_buf())
        .find_latest_session_file_for_workdir(&endpoint.workdir, Some(session_id))
    else {
        return Ok(false);
    };
    if store
        .get_bound_session_path(binding)
        .as_deref()
        .is_some_and(|path| paths_equivalent(path, &private_path))
    {
        return Ok(true);
    }
    store.set_bound_session_id(binding, session_id, Some(&private_path))?;
    Ok(true)
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
    allow_config_scoped_duplicate: bool,
) -> Result<Option<String>> {
    if !config.restore_sessions || force_new_session {
        return Ok(None);
    }
    let binding = session_binding_key(config, endpoint);
    if let Some(session_id) = store.get_bound_session_id(&binding) {
        if !allow_config_scoped_duplicate && store.session_id_bound_to_other(&binding, &session_id)
        {
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

fn codex_fork_command(
    command: &AgentCommand,
    workdir: &Path,
    source_session_id: &str,
) -> Result<AgentCommand> {
    match command {
        AgentCommand::Args(items) => {
            let Some(first) = items.first() else {
                anyhow::bail!("Codex 分叉失败：agent_command 不能为空");
            };
            let mut out = Vec::new();
            out.push(first.clone());
            out.push("fork".to_string());
            out.push("-C".to_string());
            out.push(workdir.to_string_lossy().to_string());
            out.extend(strip_codex_cd_args(items.iter().skip(1)));
            out.push(source_session_id.to_string());
            Ok(AgentCommand::Args(out))
        }
        AgentCommand::Shell(_) => {
            anyhow::bail!("Codex 分叉要求 agent_command 使用数组命令，不能使用 shell 字符串")
        }
    }
}

fn claude_fork_command(command: &AgentCommand, source_session_id: &str) -> Result<AgentCommand> {
    match normalize_agent_shell_command(command.clone(), "claude-code") {
        AgentCommand::Args(items) => {
            if items.is_empty() {
                anyhow::bail!("Claude 分叉失败：agent_command 不能为空");
            }
            let mut out = strip_claude_session_args(&items);
            out.extend([
                "--resume".to_string(),
                source_session_id.to_string(),
                "--fork-session".to_string(),
            ]);
            Ok(AgentCommand::Args(out))
        }
        AgentCommand::Shell(_) => {
            anyhow::bail!("Claude 分叉要求 agent_command 使用数组命令，不能使用 shell 字符串")
        }
    }
}

fn opencode_fork_command(command: &AgentCommand, source_session_id: &str) -> Result<AgentCommand> {
    match normalize_agent_shell_command(command.clone(), "opencode") {
        AgentCommand::Args(items) => {
            if items.is_empty() {
                anyhow::bail!("OpenCode 分叉失败：agent_command 不能为空");
            }
            let mut out = strip_opencode_session_args(&items);
            out.extend([
                "--session".to_string(),
                source_session_id.to_string(),
                "--fork".to_string(),
            ]);
            Ok(AgentCommand::Args(out))
        }
        AgentCommand::Shell(_) => {
            anyhow::bail!("OpenCode 分叉要求 agent_command 使用数组命令，不能使用 shell 字符串")
        }
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
    match normalize_agent_shell_command(command.clone(), "claude-code") {
        AgentCommand::Args(items) => {
            let mut out = strip_claude_session_args(&items);
            if !out.is_empty() {
                out.extend(["--resume".to_string(), session_id.to_string()]);
            }
            AgentCommand::Args(out)
        }
        AgentCommand::Shell(_) => command.clone(),
    }
}

fn opencode_command(command: &AgentCommand, session_id: Option<&str>) -> AgentCommand {
    match normalize_agent_shell_command(command.clone(), "opencode") {
        AgentCommand::Args(items) => {
            let mut out = strip_opencode_session_args(&items);
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

fn strip_claude_session_args(items: &[String]) -> Vec<String> {
    strip_agent_session_args(
        items,
        "claude-code",
        &["--resume", "-r", "--session-id"],
        &["--continue", "-c", "--fork-session"],
        &["--resume=", "--session-id="],
    )
}

fn strip_opencode_session_args(items: &[String]) -> Vec<String> {
    strip_agent_session_args(
        items,
        "opencode",
        &["--session", "-s"],
        &["--continue", "-c", "--fork"],
        &["--session="],
    )
}

fn strip_agent_session_args(
    items: &[String],
    driver: &str,
    options_with_value: &[&str],
    flags: &[&str],
    option_prefixes: &[&str],
) -> Vec<String> {
    let agent_args_start = agent_cli_insert_index(items, driver);
    let mut out = items[..agent_args_start].to_vec();
    let mut skip_next = false;
    for item in items.iter().skip(agent_args_start) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if options_with_value.contains(&item.as_str()) {
            skip_next = true;
            continue;
        }
        if flags.contains(&item.as_str())
            || option_prefixes
                .iter()
                .any(|prefix| item.starts_with(prefix))
        {
            continue;
        }
        out.push(item.clone());
    }
    out
}

fn normalize_agent_shell_command(command: AgentCommand, driver: &str) -> AgentCommand {
    let AgentCommand::Shell(text) = command else {
        return command;
    };
    let items = split_shell_like_command(&text);
    let targets_agent = items
        .first()
        .is_some_and(|item| agent_driver_from_command_part(item) == Some(driver))
        || shell_wrapper_command_start(&items).is_some_and(|start| {
            items
                .get(start)
                .is_some_and(|item| agent_driver_from_command_part(item) == Some(driver))
        });
    if targets_agent {
        AgentCommand::Args(items)
    } else {
        AgentCommand::Shell(text)
    }
}

fn command_with_required_agent_flag(
    command: AgentCommand,
    driver: &str,
    required_flag: &str,
) -> AgentCommand {
    let mut items = match normalize_agent_shell_command(command, driver) {
        AgentCommand::Args(items) => items,
        AgentCommand::Shell(text) => return AgentCommand::Shell(text),
    };
    if items.is_empty() {
        return AgentCommand::Args(items);
    }
    items.retain(|item| item != required_flag);
    let insert_at = if agent_driver_from_command_part(&items[0]) == Some(driver) {
        1
    } else if let Some(start) = shell_wrapper_command_start(&items) {
        if items
            .get(start)
            .is_some_and(|item| agent_driver_from_command_part(item) == Some(driver))
        {
            start + 1
        } else {
            1
        }
    } else {
        1
    };
    items.insert(insert_at.min(items.len()), required_flag.to_string());
    AgentCommand::Args(items)
}

fn command_with_agent_option_override(
    command: AgentCommand,
    driver: &str,
    long_option: &str,
    short_option: Option<&str>,
    value: &str,
) -> AgentCommand {
    let mut items = match normalize_agent_shell_command(command, driver) {
        AgentCommand::Args(items) => items,
        AgentCommand::Shell(text) => return AgentCommand::Shell(text),
    };
    if items.is_empty() {
        return AgentCommand::Args(items);
    }
    let mut filtered = Vec::with_capacity(items.len() + 2);
    let mut skip_next = false;
    for item in items.drain(..) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if item == long_option || short_option.is_some_and(|short| item == short) {
            skip_next = true;
            continue;
        }
        if item.starts_with(&format!("{long_option}=")) {
            continue;
        }
        filtered.push(item);
    }
    if filtered.is_empty() {
        return AgentCommand::Args(filtered);
    }
    let insert_at = agent_cli_insert_index(&filtered, driver);
    filtered.splice(
        insert_at..insert_at,
        [long_option.to_string(), value.to_string()],
    );
    AgentCommand::Args(filtered)
}

fn agent_cli_insert_index(items: &[String], driver: &str) -> usize {
    if items
        .first()
        .is_some_and(|item| agent_driver_from_command_part(item) == Some(driver))
    {
        return 1;
    }
    if let Some(start) = shell_wrapper_command_start(items) {
        if items
            .get(start)
            .is_some_and(|item| agent_driver_from_command_part(item) == Some(driver))
        {
            return (start + 1).min(items.len());
        }
    }
    1.min(items.len())
}

fn claude_command_with_endpoint_overrides(
    command: AgentCommand,
    endpoint: &EndpointConfig,
) -> AgentCommand {
    let command = command_with_agent_option_override(
        command,
        "claude-code",
        "--model",
        None,
        &endpoint.model,
    );
    let command = match endpoint
        .reasoning_effort
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "minimal" | "low" => {
            command_with_agent_option_override(command, "claude-code", "--effort", None, "low")
        }
        effort @ ("medium" | "high" | "xhigh" | "max") => {
            command_with_agent_option_override(command, "claude-code", "--effort", None, effort)
        }
        _ => command,
    };
    let command = command_with_agent_option_override(
        command,
        "claude-code",
        "--permission-mode",
        None,
        "bypassPermissions",
    );
    command_with_required_agent_flag(command, "claude-code", "--dangerously-skip-permissions")
}

fn opencode_command_with_endpoint_overrides(
    command: AgentCommand,
    endpoint: &EndpointConfig,
) -> AgentCommand {
    let model = format!("watchapi-runtime/{}", endpoint.model);
    let command =
        command_with_agent_option_override(command, "opencode", "--model", Some("-m"), &model);
    command_with_required_agent_flag(command, "opencode", "--auto")
}

fn anthropic_base_url(base_url: &str) -> String {
    let base = base_url.trim().trim_end_matches('/');
    base.strip_suffix("/v1").unwrap_or(base).to_string()
}

fn opencode_endpoint_config_content(
    endpoint: &EndpointConfig,
    probe_path: &str,
    model_context_window: Option<usize>,
) -> String {
    let normalized_probe_path = probe_path.trim_matches('/').to_ascii_lowercase();
    let responses_api =
        normalized_probe_path == "responses" || normalized_probe_path.ends_with("/responses");
    let provider_npm = if responses_api {
        "@ai-sdk/openai"
    } else {
        "@ai-sdk/openai-compatible"
    };
    let mut model = serde_json::json!({
        "name": endpoint.model,
        "attachment": true,
        "modalities": {
            "input": ["text", "image"],
            "output": ["text"]
        }
    });
    if responses_api {
        let mut options = serde_json::Map::new();
        let effort = endpoint.reasoning_effort.trim().to_ascii_lowercase();
        if matches!(
            effort.as_str(),
            "minimal" | "low" | "medium" | "high" | "xhigh"
        ) {
            options.insert("reasoningEffort".to_string(), serde_json::json!(effort));
        }
        if let Some(service_tier) = endpoint
            .service_tier
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            options.insert("serviceTier".to_string(), serde_json::json!(service_tier));
        }
        if !options.is_empty() {
            model["options"] = serde_json::Value::Object(options);
        }
    }
    if let Some(context) = model_context_window.filter(|context| *context > 0) {
        model["limit"] = serde_json::json!({"context": context});
    }
    let mut models = serde_json::Map::new();
    models.insert(endpoint.model.clone(), model);
    serde_json::json!({
        "model": format!("watchapi-runtime/{}", endpoint.model),
        "provider": {
            "watchapi-runtime": {
                "name": "WatchApi Runtime",
                "npm": provider_npm,
                "options": {
                    "baseURL": opencode_provider_base_url(&endpoint.base_url, probe_path),
                    "apiKey": endpoint.api_key
                },
                "models": serde_json::Value::Object(models)
            }
        }
    })
    .to_string()
}

fn opencode_provider_base_url(base_url: &str, probe_path: &str) -> String {
    let base = base_url.trim().trim_end_matches('/');
    let path = format!("/{}", probe_path.trim_matches('/'));
    let endpoint_suffix = if path.to_ascii_lowercase().ends_with("/responses") {
        "/responses"
    } else if path.to_ascii_lowercase().ends_with("/chat/completions") {
        "/chat/completions"
    } else {
        return base.to_string();
    };
    let full_url = if base.to_ascii_lowercase().ends_with("/v1")
        && path.to_ascii_lowercase().starts_with("/v1/")
    {
        format!("{base}{}", &path[3..])
    } else {
        format!("{base}{path}")
    };
    full_url[..full_url.len().saturating_sub(endpoint_suffix.len())]
        .trim_end_matches('/')
        .to_string()
}

fn submit_sequence_text(sequence: &str) -> &'static str {
    match sequence {
        "crlf" => "\r\n",
        "lf" => "\n",
        _ => "\r",
    }
}

fn prepare_isolated_codex_home(config: &AppConfig) -> Result<IsolatedCodexHome> {
    prepare_isolated_codex_home_in(&app_runtime_dir(), config)
}

fn prepare_isolated_codex_home_in(
    runtime_dir: &Path,
    config: &AppConfig,
) -> Result<IsolatedCodexHome> {
    let home = stable_isolated_codex_home_path_in(runtime_dir, config);
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
    Ok(IsolatedCodexHome { home })
}

#[cfg(test)]
fn stable_isolated_codex_home_path(config: &AppConfig) -> PathBuf {
    stable_isolated_codex_home_path_in(&app_runtime_dir(), config)
}

fn stable_isolated_codex_home_path_in(runtime_dir: &Path, config: &AppConfig) -> PathBuf {
    isolated_codex_config_root_path_in(runtime_dir, config)
        // Existing homes can contain a stale Codex SQLite projection that points
        // at a global or another configuration's rollout. A new runtime root keeps
        // those caches out of the process while preserving their sessions intact.
        .join(CODEX_ISOLATED_RUNTIME_DIR)
        .join(sanitize_path_segment(&config.agent_id))
}

fn legacy_isolated_codex_home_path_in(runtime_dir: &Path, config: &AppConfig) -> PathBuf {
    isolated_codex_config_root_path_in(runtime_dir, config)
        .join(sanitize_path_segment(&config.agent_id))
}

fn config_owned_codex_homes_in(runtime_dir: &Path, config: &AppConfig) -> Vec<PathBuf> {
    let config_root = isolated_codex_config_root_path_in(runtime_dir, config);
    let preferred = legacy_isolated_codex_home_path_in(runtime_dir, config);
    let runtime_home = stable_isolated_codex_home_path_in(runtime_dir, config);
    let mut homes = vec![runtime_home.clone(), preferred.clone()];
    let historical_runtime_root = config_root.join(CODEX_ISOLATED_RUNTIME_DIR);
    if let Ok(entries) = fs::read_dir(&historical_runtime_root) {
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let path = entry.path();
            if !paths_equivalent(&path, &runtime_home) {
                homes.push(path);
            }
        }
    }
    let Ok(entries) = fs::read_dir(&config_root) else {
        return homes;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() || entry.file_name() == CODEX_ISOLATED_RUNTIME_DIR {
            continue;
        }
        let path = entry.path();
        if !paths_equivalent(&path, &preferred) {
            homes.push(path);
        }
    }
    homes
}

fn isolated_codex_config_root_path_in(runtime_dir: &Path, config: &AppConfig) -> PathBuf {
    runtime_dir
        .join("codex-homes")
        .join(stable_config_key(config))
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    if path.starts_with(root) {
        return true;
    }
    match (path.canonicalize(), root.canonicalize()) {
        (Ok(path), Ok(root)) => path.starts_with(root),
        _ => false,
    }
}

fn app_runtime_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .join("Runtime")
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
        "--dangerously-bypass-approvals-and-sandbox".to_string(),
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
    let codex_model_limits = config.effective_codex_model_limits(&endpoint.name);
    if let Some(model_context_window) = codex_model_limits.model_context_window {
        overrides.push("-c".to_string());
        overrides.push(format!("model_context_window={model_context_window}"));
    }
    if let Some(model_auto_compact_token_limit) = codex_model_limits.model_auto_compact_token_limit
    {
        overrides.push("-c".to_string());
        overrides.push(format!(
            "model_auto_compact_token_limit={model_auto_compact_token_limit}"
        ));
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
    parts.retain(|part| part != "--dangerously-bypass-approvals-and-sandbox");
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
    // A config-owned copy is authoritative, even when an older synchronization run
    // stored the same session ID beneath a different dated filename.
    if let Some(existing) = CodexSessionIndex::new(isolated_home.to_path_buf())
        .find_latest_session_file_for_workdir(workdir, Some(session_id))
    {
        return Ok(existing);
    }
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
    if target.exists() {
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

fn opencode_prompt_footer_visible(text: &str) -> bool {
    opencode_current_prompt_input(text).is_some()
}

fn opencode_idle_prompt_visible(text: &str) -> bool {
    if opencode_busy_prompt_visible(text) {
        return false;
    }
    opencode_current_prompt_input(text)
        .is_some_and(|input| input.is_empty() || opencode_placeholder_input_visible(&input))
}

fn opencode_prefilled_input_visible(text: &str) -> bool {
    if opencode_busy_prompt_visible(text) {
        return false;
    }
    opencode_current_prompt_input(text)
        .is_some_and(|input| !input.is_empty() && !opencode_placeholder_input_visible(&input))
}

fn opencode_current_prompt_input(text: &str) -> Option<String> {
    let lines = text.lines().collect::<Vec<_>>();
    let footer_index = lines
        .iter()
        .rposition(|line| opencode_prompt_bottom_visible(line))?;
    if footer_index == 0 {
        return None;
    }

    let mut box_lines = Vec::new();
    let mut index = footer_index;
    while index > 0 {
        let Some(content) = opencode_prompt_line_content(lines[index - 1]) else {
            break;
        };
        box_lines.push(content);
        index -= 1;
    }
    box_lines.reverse();

    let metadata_index = box_lines.iter().rposition(|line| line.contains('·'));
    if metadata_index.is_none() {
        let has_placeholder = box_lines
            .iter()
            .any(|line| opencode_placeholder_input_visible(line));
        let has_controls = lines[footer_index + 1..].iter().any(|line| {
            let lowered = line.to_ascii_lowercase();
            lowered.contains("tab agents") && lowered.contains("commands")
        });
        if !has_placeholder && !has_controls {
            return None;
        }
    }
    let metadata_index = metadata_index.unwrap_or(box_lines.len());
    let mut input_lines = box_lines[..metadata_index].to_vec();
    while input_lines.first().is_some_and(|line| line.is_empty()) {
        input_lines.remove(0);
    }
    while input_lines.last().is_some_and(|line| line.is_empty()) {
        input_lines.pop();
    }
    Some(input_lines.join("\n"))
}

fn opencode_prompt_bottom_visible(line: &str) -> bool {
    let line = line.trim_start();
    let mut chars = line.chars();
    let Some(marker) = chars.next() else {
        return false;
    };
    if !matches!(marker, '╹' | '└' | '╰' | '╚' | '┕' | '┗' | '┙' | '╘') {
        return false;
    }
    let bottom = chars.as_str().trim_end();
    bottom.chars().count() >= 3
        && bottom
            .chars()
            .all(|ch| matches!(ch, '▀' | '─' | '━' | '═' | '-' | '_' | '▔' | '▄'))
}

fn opencode_prompt_line_content(line: &str) -> Option<String> {
    let line = line.trim_start();
    let mut chars = line.chars();
    let marker = chars.next()?;
    if !matches!(marker, '┃' | '│' | '║' | '|' | '▕' | '▐') {
        return None;
    }
    let content = chars.as_str();
    let content = content
        .strip_prefix("  ")
        .or_else(|| content.strip_prefix(' '))
        .unwrap_or(content);
    Some(content.trim_end().to_string())
}

fn opencode_placeholder_input_visible(input: &str) -> bool {
    input
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("ask anything...")
}

fn opencode_busy_prompt_visible(text: &str) -> bool {
    text.lines().any(|line| {
        let lowered = line
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        lowered.contains("esc interrupt")
            || lowered.contains("esc to interrupt")
            || lowered.contains("ctrl+c to interrupt")
            || lowered.contains("ctrl-c to interrupt")
            || ((lowered.contains("retry") || lowered.contains("retrying"))
                && (lowered.contains(" in ")
                    || lowered.contains("attempt")
                    || lowered.contains("failed")))
    })
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

fn codex_command_approval_prompt_visible(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    let has_approval_choices = lowered.contains("1. yes, proceed")
        && (lowered.contains("2. yes, and don't ask again")
            || lowered.contains("2. yes, and do not ask again"))
        && lowered.contains("3. no");
    has_approval_choices
        && text.lines().any(|line| {
            let trimmed = line.trim_start();
            (trimmed.starts_with('>') || trimmed.starts_with('❯') || trimmed.starts_with('➜'))
                && trimmed.contains("2.")
                && trimmed.to_ascii_lowercase().contains("don't ask again")
        })
}

fn generic_first_option_prompt_visible(text: &str) -> bool {
    if claude_terms_acceptance_prompt_visible(text) {
        return false;
    }
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

fn claude_terms_acceptance_prompt_visible(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("1. no, exit") && lowered.contains("2. yes, i accept")
}

fn claude_terms_acceptance_prompt_navigation(text: &str) -> &'static str {
    let selected = text.lines().rev().find_map(|line| {
        let trimmed = line.trim_start();
        [">", "❯", "➜", "›"].iter().find_map(|marker| {
            let rest = trimmed.strip_prefix(marker)?.trim_start();
            if rest.starts_with("1.") {
                Some(1)
            } else if rest.starts_with("2.") {
                Some(2)
            } else {
                None
            }
        })
    });
    if selected == Some(2) {
        ""
    } else {
        "\x1b[B"
    }
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
    use crate::config::{AgentCommand, AgentDriver, CodexModelLimits};
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
            .find("apply_codex_endpoint_with_model_limits(")
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
    fn codex_restore_lookup_uses_global_home_only_for_a_bound_session() {
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
    fn isolated_restore_does_not_resume_session_from_another_configuration() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let global_home = tmp.path().join(".codex");
        let other_home = tmp
            .path()
            .join("Runtime/codex-homes/other-config/codex-main");
        let other_session = other_home.join("sessions/2026/05/17/other.jsonl");
        fs::create_dir_all(other_session.parent().unwrap()).unwrap();
        fs::write(
            &other_session,
            serde_json::json!({"type": "session_meta", "payload": {"id": "other-session", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            global_home,
        );
        cfg.config_path = Some(tmp.path().join("config.json"));
        let isolated_home = tmp
            .path()
            .join("Runtime/codex-homes/current-config/codex-main");
        let mut runtime_cfg = cfg.clone();
        runtime_cfg.codex_home = isolated_home;
        let endpoint = endpoint(workdir);
        let mut store = SessionStore::new(cfg.session_state_path.clone());

        let launch = build_agent_launch_for_codex_restore_home(
            &runtime_cfg,
            &cfg,
            &endpoint,
            &mut store,
            false,
            MissingSessionPolicy::New,
        )
        .unwrap();

        assert!(!launch.resumed);
        assert_eq!(launch.session_id, None);
        assert_eq!(
            launch.command,
            AgentCommand::Args(vec!["codex".to_string()])
        );
    }

    #[test]
    fn isolated_restore_reclaims_a_global_binding_from_its_own_legacy_home() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("Runtime");
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let global_home = tmp.path().join(".codex");
        let global_file = global_home.join("sessions/2026/08/13/global-branch.jsonl");
        fs::create_dir_all(global_file.parent().unwrap()).unwrap();
        let session_id = "selected-session";
        let metadata = serde_json::json!({
            "type": "session_meta",
            "payload": {"id": session_id, "cwd": workdir.to_string_lossy()}
        })
        .to_string();
        fs::write(&global_file, format!("{metadata}\nglobal branch\n")).unwrap();

        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            global_home.clone(),
        );
        cfg.config_path = Some(tmp.path().join("config.json"));
        let legacy_home = legacy_isolated_codex_home_path_in(&runtime_dir, &cfg);
        let private_file = legacy_home.join("sessions/2026/08/10/private-history.jsonl");
        fs::create_dir_all(private_file.parent().unwrap()).unwrap();
        fs::write(&private_file, format!("{metadata}\nprivate history\n")).unwrap();
        let isolated_home = stable_isolated_codex_home_path_in(&runtime_dir, &cfg);
        let mut runtime_cfg = cfg.clone();
        runtime_cfg.codex_home = isolated_home.clone();
        let endpoint = endpoint(workdir.clone());
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let binding = session_binding_key(&cfg, &endpoint);
        store
            .set_bound_session_id(&binding, session_id, Some(&global_file))
            .unwrap();

        let launch = build_agent_launch_for_codex_restore_home_in(
            &runtime_dir,
            &runtime_cfg,
            &cfg,
            &endpoint,
            &mut store,
            false,
            MissingSessionPolicy::New,
        )
        .unwrap();
        let copied = copy_codex_resume_session_to_isolated_home(
            &global_home,
            &isolated_home,
            &workdir,
            session_id,
            store.get_bound_session_path(&binding).as_deref(),
        )
        .unwrap();

        assert_eq!(launch.session_id, Some(session_id.to_string()));
        assert!(launch.resumed);
        assert_eq!(store.get_bound_session_path(&binding), Some(private_file));
        assert_eq!(
            fs::read_to_string(&copied).unwrap(),
            format!("{metadata}\nprivate history\n")
        );
        assert!(!fs::read_to_string(&copied)
            .unwrap()
            .contains("global branch"));
    }

    #[test]
    fn isolated_restore_reclaims_private_history_when_the_bound_session_id_is_foreign() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("Runtime");
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let source_home = tmp.path().join(".codex");
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            source_home,
        );
        cfg.config_path = Some(tmp.path().join("config.json"));
        let endpoint = endpoint(workdir.clone());
        let private_session_id = "private-session";
        let private_file = legacy_isolated_codex_home_path_in(&runtime_dir, &cfg)
            .join("sessions/2026/08/10/private-history.jsonl");
        fs::create_dir_all(private_file.parent().unwrap()).unwrap();
        fs::write(
            &private_file,
            serde_json::json!({
                "type": "session_meta",
                "payload": {"id": private_session_id, "cwd": workdir.to_string_lossy()}
            })
            .to_string()
                + "\nprivate history\n",
        )
        .unwrap();
        let foreign_home = tmp.path().join("foreign");
        let foreign_file = foreign_home.join("sessions/2026/08/10/foreign-history.jsonl");
        fs::create_dir_all(foreign_file.parent().unwrap()).unwrap();
        fs::write(
            &foreign_file,
            serde_json::json!({
                "type": "session_meta",
                "payload": {"id": "foreign-session", "cwd": workdir.to_string_lossy()}
            })
            .to_string()
                + "\nforeign history\n",
        )
        .unwrap();
        let isolated_home = stable_isolated_codex_home_path_in(&runtime_dir, &cfg);
        let mut runtime_cfg = cfg.clone();
        runtime_cfg.codex_home = isolated_home;
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let binding = session_binding_key(&cfg, &endpoint);
        store
            .set_bound_session_id(&binding, "foreign-session", Some(&foreign_file))
            .unwrap();

        let launch = build_agent_launch_for_codex_restore_home_in(
            &runtime_dir,
            &runtime_cfg,
            &cfg,
            &endpoint,
            &mut store,
            false,
            MissingSessionPolicy::New,
        )
        .unwrap();

        assert_eq!(launch.session_id, Some(private_session_id.to_string()));
        assert!(launch.resumed);
        assert_eq!(store.get_bound_session_path(&binding), Some(private_file));
    }

    #[test]
    fn isolated_restore_reclaims_private_history_without_a_saved_binding() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("Runtime");
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let source_home = tmp.path().join(".codex");
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            source_home,
        );
        cfg.config_path = Some(tmp.path().join("config.json"));
        let endpoint = endpoint(workdir.clone());
        let private_session_id = "private-session";
        let private_file = legacy_isolated_codex_home_path_in(&runtime_dir, &cfg)
            .join("sessions/2026/08/10/private-history.jsonl");
        fs::create_dir_all(private_file.parent().unwrap()).unwrap();
        fs::write(
            &private_file,
            serde_json::json!({
                "type": "session_meta",
                "payload": {"id": private_session_id, "cwd": workdir.to_string_lossy()}
            })
            .to_string()
                + "\nprivate history\n",
        )
        .unwrap();
        let isolated_home = stable_isolated_codex_home_path_in(&runtime_dir, &cfg);
        let mut runtime_cfg = cfg.clone();
        runtime_cfg.codex_home = isolated_home;
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let binding = session_binding_key(&cfg, &endpoint);

        let launch = build_agent_launch_for_codex_restore_home_in(
            &runtime_dir,
            &runtime_cfg,
            &cfg,
            &endpoint,
            &mut store,
            false,
            MissingSessionPolicy::New,
        )
        .unwrap();

        assert_eq!(launch.session_id, Some(private_session_id.to_string()));
        assert!(launch.resumed);
        assert_eq!(store.get_bound_session_path(&binding), Some(private_file));
    }

    #[test]
    fn isolated_restore_reclaims_runtime_v2_history_without_a_saved_binding() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("Runtime");
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let source_home = tmp.path().join(".codex");
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            source_home,
        );
        cfg.config_path = Some(tmp.path().join("config.json"));
        let endpoint = endpoint(workdir.clone());
        let private_session_id = "runtime-session";
        let private_file = stable_isolated_codex_home_path_in(&runtime_dir, &cfg)
            .join("sessions/2026/08/13/runtime-history.jsonl");
        fs::create_dir_all(private_file.parent().unwrap()).unwrap();
        fs::write(
            &private_file,
            serde_json::json!({
                "type": "session_meta",
                "payload": {"id": private_session_id, "cwd": workdir.to_string_lossy()}
            })
            .to_string()
                + "\nruntime history\n",
        )
        .unwrap();
        let mut runtime_cfg = cfg.clone();
        runtime_cfg.codex_home = stable_isolated_codex_home_path_in(&runtime_dir, &cfg);
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let binding = session_binding_key(&cfg, &endpoint);

        let launch = build_agent_launch_for_codex_restore_home_in(
            &runtime_dir,
            &runtime_cfg,
            &cfg,
            &endpoint,
            &mut store,
            false,
            MissingSessionPolicy::New,
        )
        .unwrap();

        assert_eq!(launch.session_id, Some(private_session_id.to_string()));
        assert!(launch.resumed);
        assert_eq!(store.get_bound_session_path(&binding), Some(private_file));
    }

    #[test]
    fn isolated_restore_recovers_runtime_v2_history_after_agent_id_rename() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("Runtime");
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let source_home = tmp.path().join(".codex");
        let mut old_cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            source_home,
        );
        old_cfg.config_path = Some(tmp.path().join("config.json"));
        old_cfg.agent_id = "codex-before-rename".to_string();
        let endpoint = endpoint(workdir.clone());
        let session_id = "session-created-before-rename";
        let old_runtime_file = stable_isolated_codex_home_path_in(&runtime_dir, &old_cfg)
            .join("sessions/2026/08/14/runtime-history.jsonl");
        fs::create_dir_all(old_runtime_file.parent().unwrap()).unwrap();
        fs::write(
            &old_runtime_file,
            serde_json::json!({
                "type": "session_meta",
                "payload": {"id": session_id, "cwd": workdir.to_string_lossy()}
            })
            .to_string()
                + "\nlatest runtime history\n",
        )
        .unwrap();

        let mut renamed_cfg = old_cfg.clone();
        renamed_cfg.agent_id = "codex-after-rename".to_string();
        let mut runtime_cfg = renamed_cfg.clone();
        runtime_cfg.codex_home = stable_isolated_codex_home_path_in(&runtime_dir, &renamed_cfg);
        let mut store = SessionStore::new(renamed_cfg.session_state_path.clone());
        store
            .set_bound_session_id(
                &session_binding_key(&old_cfg, &endpoint),
                session_id,
                Some(&old_runtime_file),
            )
            .unwrap();
        let renamed_binding = session_binding_key(&renamed_cfg, &endpoint);
        assert_eq!(store.get_bound_session_id(&renamed_binding), None);

        let launch = build_agent_launch_for_codex_restore_home_in(
            &runtime_dir,
            &runtime_cfg,
            &renamed_cfg,
            &endpoint,
            &mut store,
            false,
            MissingSessionPolicy::New,
        )
        .unwrap();

        assert_eq!(launch.session_id, Some(session_id.to_string()));
        assert!(launch.resumed);
        assert_eq!(
            store.get_bound_session_path(&renamed_binding),
            Some(old_runtime_file)
        );
    }

    #[test]
    fn isolated_restore_keeps_same_session_id_private_to_each_configuration() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("Runtime");
        let workdir = tmp.path().join("project");
        let source_home = tmp.path().join(".codex");
        fs::create_dir_all(&workdir).unwrap();
        let session_id = "shared-session";
        let metadata = serde_json::json!({
            "type": "session_meta",
            "payload": {"id": session_id, "cwd": workdir.to_string_lossy()}
        })
        .to_string();

        let mut cfg_a = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            source_home.clone(),
        );
        cfg_a.config_path = Some(tmp.path().join("a.json"));
        let mut cfg_b = cfg_a.clone();
        cfg_b.config_path = Some(tmp.path().join("b.json"));
        let endpoint = endpoint(workdir.clone());
        let private_a = legacy_isolated_codex_home_path_in(&runtime_dir, &cfg_a)
            .join("sessions/2026/08/10/a.jsonl");
        let private_b = legacy_isolated_codex_home_path_in(&runtime_dir, &cfg_b)
            .join("sessions/2026/08/10/b.jsonl");
        fs::create_dir_all(private_a.parent().unwrap()).unwrap();
        fs::create_dir_all(private_b.parent().unwrap()).unwrap();
        fs::write(&private_a, format!("{metadata}\nconfiguration a\n")).unwrap();
        fs::write(&private_b, format!("{metadata}\nconfiguration b\n")).unwrap();

        let mut store = SessionStore::new(cfg_a.session_state_path.clone());
        let binding_a = session_binding_key(&cfg_a, &endpoint);
        let binding_b = session_binding_key(&cfg_b, &endpoint);
        // Simulate stale bindings that were accidentally pointed at each other.
        store
            .set_bound_session_id(&binding_a, session_id, Some(&private_b))
            .unwrap();
        store
            .set_bound_session_id(&binding_b, session_id, Some(&private_a))
            .unwrap();

        prefer_config_owned_legacy_session_binding_in(
            &runtime_dir,
            &cfg_a,
            &endpoint,
            &mut store,
            &binding_a,
        )
        .unwrap();
        prefer_config_owned_legacy_session_binding_in(
            &runtime_dir,
            &cfg_b,
            &endpoint,
            &mut store,
            &binding_b,
        )
        .unwrap();

        assert_eq!(store.get_bound_session_path(&binding_a), Some(private_a));
        assert_eq!(store.get_bound_session_path(&binding_b), Some(private_b));
    }

    #[test]
    fn isolated_restore_discards_binding_that_only_points_to_another_configuration() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("Runtime");
        let workdir = tmp.path().join("project");
        let source_home = tmp.path().join(".codex");
        fs::create_dir_all(&workdir).unwrap();
        let session_id = "other-session";
        let metadata = serde_json::json!({
            "type": "session_meta",
            "payload": {"id": session_id, "cwd": workdir.to_string_lossy()}
        })
        .to_string();

        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            source_home,
        );
        cfg.config_path = Some(tmp.path().join("current.json"));
        let mut other_cfg = cfg.clone();
        other_cfg.config_path = Some(tmp.path().join("other.json"));
        let endpoint = endpoint(workdir);
        let foreign_path = legacy_isolated_codex_home_path_in(&runtime_dir, &other_cfg)
            .join("sessions/2026/08/10/foreign.jsonl");
        fs::create_dir_all(foreign_path.parent().unwrap()).unwrap();
        fs::write(
            &foreign_path,
            format!("{metadata}\nforeign configuration\n"),
        )
        .unwrap();

        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let binding = session_binding_key(&cfg, &endpoint);
        store
            .set_bound_session_id(&binding, session_id, Some(&foreign_path))
            .unwrap();

        prefer_config_owned_legacy_session_binding_in(
            &runtime_dir,
            &cfg,
            &endpoint,
            &mut store,
            &binding,
        )
        .unwrap();

        assert_eq!(store.get_bound_session_id(&binding), None);
        assert_eq!(store.get_bound_session_path(&binding), None);
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
    fn resuming_preserves_existing_isolated_session_history() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let source_home = tmp.path().join(".codex");
        let isolated_home = tmp.path().join("isolated");
        let source = source_home.join("sessions/2026/05/17/selected.jsonl");
        let target = isolated_home.join("sessions/2026/05/17/selected.jsonl");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let metadata = serde_json::json!({
            "type": "session_meta",
            "payload": {"id": "selected-session", "cwd": workdir.to_string_lossy()}
        })
        .to_string();
        fs::write(&source, format!("{metadata}\nsource continuation\n")).unwrap();
        let isolated_history = format!("{metadata}\nisolated continuation\n");
        fs::write(&target, &isolated_history).unwrap();

        let copied = copy_codex_resume_session_to_isolated_home(
            &source_home,
            &isolated_home,
            &workdir,
            "selected-session",
            Some(&source),
        )
        .unwrap();

        assert_eq!(copied, target);
        assert_eq!(fs::read_to_string(&target).unwrap(), isolated_history);
    }

    #[test]
    fn resuming_prefers_existing_isolated_session_when_its_path_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let source_home = tmp.path().join(".codex");
        let isolated_home = tmp.path().join("isolated");
        let source = source_home.join("sessions/2026/05/17/source-path.jsonl");
        let existing = isolated_home.join("sessions/2026/05/18/private-path.jsonl");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::create_dir_all(existing.parent().unwrap()).unwrap();
        let metadata = serde_json::json!({
            "type": "session_meta",
            "payload": {"id": "selected-session", "cwd": workdir.to_string_lossy()}
        })
        .to_string();
        fs::write(&source, format!("{metadata}\nsource continuation\n")).unwrap();
        let private_history = format!("{metadata}\nprivate continuation\n");
        fs::write(&existing, &private_history).unwrap();

        let copied = copy_codex_resume_session_to_isolated_home(
            &source_home,
            &isolated_home,
            &workdir,
            "selected-session",
            Some(&source),
        )
        .unwrap();

        assert_eq!(copied, existing);
        assert_eq!(fs::read_to_string(&existing).unwrap(), private_history);
        assert!(!isolated_home
            .join("sessions/2026/05/17/source-path.jsonl")
            .exists());
    }

    #[test]
    fn config_owned_bound_codex_session_path_can_resume_and_copy_to_isolated_home() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("Runtime");
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let source_home = tmp.path().join(".codex");
        let mut cfg = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            source_home.clone(),
        );
        cfg.config_path = Some(tmp.path().join("config.json"));
        let historical_file = legacy_isolated_codex_home_path_in(&runtime_dir, &cfg)
            .join("sessions/2026/05/29/historical.jsonl");
        fs::create_dir_all(historical_file.parent().unwrap()).unwrap();
        fs::write(
            &historical_file,
            serde_json::json!({"type": "session_meta", "payload": {"id": "historical-session", "cwd": workdir.to_string_lossy()}}).to_string() + "\n",
        )
        .unwrap();
        let isolated_home = stable_isolated_codex_home_path_in(&runtime_dir, &cfg);
        let mut runtime_cfg = cfg.clone();
        runtime_cfg.codex_home = isolated_home.clone();
        let endpoint = endpoint(workdir.clone());
        let mut store = SessionStore::new(cfg.session_state_path.clone());
        let binding = session_binding_key(&cfg, &endpoint);
        store
            .set_bound_session_id(&binding, "historical-session", Some(&historical_file))
            .unwrap();

        let launch = build_agent_launch_for_codex_restore_home_in(
            &runtime_dir,
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
    fn codex_fork_command_pins_workdir_and_rejects_shell_commands() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let stale_workdir = tmp.path().join("old-project");
        let command = AgentCommand::Args(vec![
            "codex".to_string(),
            "--no-alt-screen".to_string(),
            "--cd".to_string(),
            stale_workdir.to_string_lossy().to_string(),
        ]);

        let fork = codex_fork_command(&command, &workdir, "source-session").unwrap();

        assert_eq!(
            fork,
            AgentCommand::Args(vec![
                "codex".to_string(),
                "fork".to_string(),
                "-C".to_string(),
                workdir.to_string_lossy().to_string(),
                "--no-alt-screen".to_string(),
                "source-session".to_string(),
            ])
        );
        assert!(codex_fork_command(
            &AgentCommand::Shell("codex --no-alt-screen".to_string()),
            &workdir,
            "source-session",
        )
        .is_err());
    }

    #[test]
    fn claude_and_opencode_fork_commands_use_native_fork_flags() {
        let claude = claude_fork_command(
            &AgentCommand::Args(vec![
                "claude".to_string(),
                "--continue".to_string(),
                "--model".to_string(),
                "sonnet".to_string(),
            ]),
            "claude-source",
        )
        .unwrap();
        assert_eq!(
            claude,
            AgentCommand::Args(vec![
                "claude".to_string(),
                "--model".to_string(),
                "sonnet".to_string(),
                "--resume".to_string(),
                "claude-source".to_string(),
                "--fork-session".to_string(),
            ])
        );

        let opencode = opencode_fork_command(
            &AgentCommand::Args(vec![
                "opencode".to_string(),
                "--session=old".to_string(),
                "--auto".to_string(),
            ]),
            "opencode-source",
        )
        .unwrap();
        assert_eq!(
            opencode,
            AgentCommand::Args(vec![
                "opencode".to_string(),
                "--auto".to_string(),
                "--session".to_string(),
                "opencode-source".to_string(),
                "--fork".to_string(),
            ])
        );
    }

    #[test]
    fn claude_and_opencode_session_args_follow_shell_wrapped_agent_command() {
        let claude = claude_resume_command(
            &AgentCommand::Args(vec![
                "pwsh.exe".to_string(),
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "claude".to_string(),
                "--continue".to_string(),
                "--model".to_string(),
                "sonnet".to_string(),
            ]),
            Some("claude-session"),
        );
        assert_eq!(
            claude,
            AgentCommand::Args(vec![
                "pwsh.exe".to_string(),
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "claude".to_string(),
                "--model".to_string(),
                "sonnet".to_string(),
                "--resume".to_string(),
                "claude-session".to_string(),
            ])
        );

        let opencode = opencode_command(
            &AgentCommand::Args(vec![
                "cmd.exe".to_string(),
                "/d".to_string(),
                "/c".to_string(),
                "opencode".to_string(),
                "--continue".to_string(),
                "--session=old".to_string(),
                "--auto".to_string(),
            ]),
            Some("opencode-session"),
        );
        assert_eq!(
            opencode,
            AgentCommand::Args(vec![
                "cmd.exe".to_string(),
                "/d".to_string(),
                "/c".to_string(),
                "opencode".to_string(),
                "--auto".to_string(),
                "--session".to_string(),
                "opencode-session".to_string(),
            ])
        );

        assert_eq!(
            opencode_command(
                &AgentCommand::Shell("opencode".to_string()),
                Some("bound-session")
            ),
            AgentCommand::Args(vec![
                "opencode".to_string(),
                "--session".to_string(),
                "bound-session".to_string(),
            ])
        );
    }

    #[test]
    fn claude_and_opencode_runtime_commands_force_unattended_mode_once() {
        let claude = command_with_required_agent_flag(
            AgentCommand::Args(vec![
                "claude".to_string(),
                "--resume".to_string(),
                "session-1".to_string(),
                "--dangerously-skip-permissions".to_string(),
            ]),
            "claude-code",
            "--dangerously-skip-permissions",
        );
        let opencode = command_with_required_agent_flag(
            AgentCommand::Args(vec![
                "opencode".to_string(),
                "--session".to_string(),
                "session-1".to_string(),
            ]),
            "opencode",
            "--auto",
        );

        let AgentCommand::Args(claude) = claude else {
            panic!("expected args command");
        };
        let AgentCommand::Args(opencode) = opencode else {
            panic!("expected args command");
        };
        assert_eq!(
            claude
                .iter()
                .filter(|item| item.as_str() == "--dangerously-skip-permissions")
                .count(),
            1
        );
        assert_eq!(claude[1], "--dangerously-skip-permissions");
        assert_eq!(
            claude
                .iter()
                .filter(|item| item.as_str() == "--permission-mode")
                .count(),
            0,
            "the low-level required-flag helper must not add unrelated options"
        );
        assert_eq!(opencode[1], "--auto");
    }

    #[test]
    fn claude_and_opencode_endpoint_overrides_pin_selected_model() {
        let endpoint = endpoint(PathBuf::from("D:/project"));
        let claude = claude_command_with_endpoint_overrides(
            AgentCommand::Args(vec![
                "claude".to_string(),
                "--model".to_string(),
                "old-model".to_string(),
            ]),
            &endpoint,
        );
        let opencode = opencode_command_with_endpoint_overrides(
            AgentCommand::Args(vec![
                "opencode".to_string(),
                "-m".to_string(),
                "old-provider/old-model".to_string(),
            ]),
            &endpoint,
        );

        assert_eq!(
            claude,
            AgentCommand::Args(vec![
                "claude".to_string(),
                "--dangerously-skip-permissions".to_string(),
                "--permission-mode".to_string(),
                "bypassPermissions".to_string(),
                "--effort".to_string(),
                "high".to_string(),
                "--model".to_string(),
                "gpt-test".to_string(),
            ])
        );
        assert_eq!(
            opencode,
            AgentCommand::Args(vec![
                "opencode".to_string(),
                "--auto".to_string(),
                "--model".to_string(),
                "watchapi-runtime/gpt-test".to_string(),
            ])
        );
        assert_eq!(
            opencode_command_with_endpoint_overrides(
                AgentCommand::Shell("opencode".to_string()),
                &endpoint,
            ),
            AgentCommand::Args(vec![
                "opencode".to_string(),
                "--auto".to_string(),
                "--model".to_string(),
                "watchapi-runtime/gpt-test".to_string(),
            ])
        );
    }

    #[test]
    fn opencode_runtime_provider_is_process_local_and_uses_selected_endpoint() {
        let endpoint = endpoint(PathBuf::from("D:/project"));

        let config: serde_json::Value = serde_json::from_str(&opencode_endpoint_config_content(
            &endpoint,
            "/v1/responses",
            Some(128_000),
        ))
        .unwrap();

        assert_eq!(config["model"], "watchapi-runtime/gpt-test");
        assert_eq!(
            config["provider"]["watchapi-runtime"]["options"]["baseURL"],
            "https://api.example.test/v1"
        );
        assert_eq!(
            config["provider"]["watchapi-runtime"]["options"]["apiKey"],
            endpoint.api_key
        );
        assert_eq!(
            config["provider"]["watchapi-runtime"]["models"]["gpt-test"]["name"],
            "gpt-test"
        );
        assert_eq!(
            config["provider"]["watchapi-runtime"]["npm"],
            "@ai-sdk/openai"
        );
        assert_eq!(
            config["provider"]["watchapi-runtime"]["models"]["gpt-test"]["options"]
                ["reasoningEffort"],
            "high"
        );
        assert_eq!(
            config["provider"]["watchapi-runtime"]["models"]["gpt-test"]["options"]["serviceTier"],
            "fast"
        );
        assert_eq!(
            config["provider"]["watchapi-runtime"]["models"]["gpt-test"]["limit"]["context"],
            128_000
        );

        let chat_config: serde_json::Value = serde_json::from_str(
            &opencode_endpoint_config_content(&endpoint, "/v1/chat/completions", None),
        )
        .unwrap();
        assert_eq!(
            chat_config["provider"]["watchapi-runtime"]["npm"],
            "@ai-sdk/openai-compatible"
        );
        assert_eq!(
            chat_config["provider"]["watchapi-runtime"]["options"]["baseURL"],
            "https://api.example.test/v1"
        );
        assert!(
            chat_config["provider"]["watchapi-runtime"]["models"]["gpt-test"]
                .get("options")
                .is_none()
        );
        assert_eq!(
            opencode_provider_base_url("https://api.example.test/v1/", "/v1/responses"),
            "https://api.example.test/v1"
        );
        assert_eq!(
            anthropic_base_url("https://api.example.test/v1/"),
            "https://api.example.test"
        );
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
        assert!(send_block.contains("AgentDriverKind::OpenCode"));
        assert!(send_block.contains("terminal.send_pasted_prompt("));
        assert!(send_block.contains("OPENCODE_PROMPT_SUBMIT_DELAY"));
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
    fn request_failure_success_evidence_uses_agent_session_assistant_messages() {
        let source = include_str!("agent.rs");
        let helper = source
            .split("pub fn has_session_assistant_message_since_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn terminal_had_activity_since_prompt").next())
            .expect("session assistant helper should be discoverable");

        assert!(
            helper.contains("has_session_assistant_message_since_wait_start"),
            "清请求失败计数必须使用 Agent 会话里的 assistant 回复，不能使用终端活动"
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
    fn interactive_agent_ready_prompt_unlock_has_post_send_grace_period() {
        let source = include_str!("agent.rs");
        let block = source
            .split("fn ready_unlock_grace_active(&self)")
            .nth(1)
            .and_then(|tail| tail.split("fn startup_ready_for_prompt").next())
            .expect("ready unlock grace helper should be discoverable");

        assert!(source.contains(
            "const INTERACTIVE_AGENT_READY_UNLOCK_GRACE: Duration = Duration::from_secs(2);"
        ));
        assert!(block.contains("self.config.agent_driver != AgentDriverKind::Generic"));
        assert!(block.contains("last_prompt_sent_at"));
        assert!(block.contains("at.elapsed() < INTERACTIVE_AGENT_READY_UNLOCK_GRACE"));
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
        assert!(block.contains("!self.ready_unlock_grace_active()"));
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
    fn isolated_codex_home_keeps_runtime_state_and_sessions_private() {
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
        assert!(!isolated.home.join("state_5.sqlite").exists());
        assert!(!isolated.home.join("state_5.sqlite-wal").exists());
        assert!(!isolated.home.join(".codex-global-state.json").exists());
        fs::create_dir_all(isolated.home.join("sessions/2026/05/19")).unwrap();
        fs::write(isolated.home.join("sessions/2026/05/19/new.jsonl"), "new\n").unwrap();
        fs::write(isolated.home.join("state_5.sqlite"), "updated sqlite").unwrap();
        fs::write(
            isolated.home.join(".codex-global-state.json"),
            "{\"provider\":\"custom\",\"visible\":true}\n",
        )
        .unwrap();
        let isolated_home = isolated.home.clone();
        let endpoint = endpoint(cfg.workdir.clone());
        let mut agent = AgentProcess::new(cfg, endpoint, false);
        agent.isolated_codex_home = Some(isolated);
        agent.stop();

        assert_eq!(
            fs::read_to_string(codex_home.join("config.toml")).unwrap(),
            "model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"old\"\n"
        );
        assert!(codex_home.join("sessions/2026/05/19/old.jsonl").exists());
        assert!(!codex_home.join("sessions/2026/05/19/new.jsonl").exists());
        assert_eq!(
            fs::read_to_string(codex_home.join("state_5.sqlite")).unwrap(),
            "sqlite"
        );
        assert_eq!(
            fs::read_to_string(codex_home.join(".codex-global-state.json")).unwrap(),
            "{\"provider\":\"custom\"}\n"
        );
        let _ = fs::remove_dir_all(isolated_home);
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
    fn stopping_codex_does_not_export_isolated_history() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let isolated_home = tmp.path().join("isolated");
        let source_home = tmp.path().join("source");
        let private_session = isolated_home.join("sessions/2026/05/17/new.jsonl");
        fs::create_dir_all(private_session.parent().unwrap()).unwrap();
        fs::write(&private_session, "private\n").unwrap();
        fs::write(isolated_home.join("state_5.sqlite"), "private sqlite").unwrap();
        fs::write(
            isolated_home.join(".codex-global-state.json"),
            "private state\n",
        )
        .unwrap();

        let config = config(
            workdir.clone(),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            source_home.clone(),
        );
        let endpoint = endpoint(workdir);
        let mut agent = AgentProcess::new(config, endpoint, false);
        agent.isolated_codex_home = Some(IsolatedCodexHome {
            home: isolated_home,
        });
        agent.stop();

        assert!(!source_home.join("sessions/2026/05/17/new.jsonl").exists());
        assert!(!source_home.join("state_5.sqlite").exists());
        assert!(!source_home.join(".codex-global-state.json").exists());
    }

    #[test]
    fn isolated_codex_runtime_v2_ignores_legacy_cache_without_touching_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy_home = tmp.path().join("Runtime/codex-homes/config/codex-main");
        let legacy_session = legacy_home.join("sessions/2026/08/13/authoritative.jsonl");
        fs::create_dir_all(legacy_session.parent().unwrap()).unwrap();
        fs::write(&legacy_session, "authoritative history\n").unwrap();
        fs::write(legacy_home.join("state_5.sqlite"), "stale state\n").unwrap();
        fs::write(
            legacy_home.join("thread_history_1.sqlite"),
            "stale projection\n",
        )
        .unwrap();

        let config_home = tmp.path().join(".codex");
        fs::create_dir_all(&config_home).unwrap();
        fs::write(config_home.join("config.toml"), "model = \"test\"\n").unwrap();
        fs::write(config_home.join("auth.json"), "{}\n").unwrap();
        let mut cfg = config(
            tmp.path().join("project"),
            AgentDriver::Codex,
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            config_home.clone(),
        );
        cfg.config_path = Some(tmp.path().join("config.json"));
        cfg.agent_id = "codex-main".to_string();
        cfg.codex_config_path = config_home.join("config.toml");
        cfg.codex_auth_path = config_home.join("auth.json");

        let runtime = stable_isolated_codex_home_path(&cfg);
        let expected_runtime_suffix = Path::new(CODEX_ISOLATED_RUNTIME_DIR).join("codex-main");
        assert!(runtime.ends_with(expected_runtime_suffix));
        let isolated = prepare_isolated_codex_home(&cfg).unwrap();

        assert_eq!(isolated.home, runtime);
        assert!(isolated.home.exists());
        assert!(!isolated.home.join("state_5.sqlite").exists());
        assert!(!isolated.home.join("thread_history_1.sqlite").exists());
        assert_eq!(
            fs::read_to_string(legacy_home.join("state_5.sqlite")).unwrap(),
            "stale state\n"
        );
        assert_eq!(
            fs::read_to_string(&legacy_session).unwrap(),
            "authoritative history\n"
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
    fn codex_cli_overrides_force_full_access_for_every_launch_shape() {
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
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            codex_home,
        );
        cfg.codex_config_path = config_path;
        let endpoint = endpoint(workdir.clone());
        let commands = [
            AgentCommand::Args(vec!["codex".to_string()]),
            AgentCommand::Args(vec![
                "codex".to_string(),
                "resume".to_string(),
                "session-1".to_string(),
            ]),
            AgentCommand::Args(vec![
                "codex".to_string(),
                "fork".to_string(),
                "session-1".to_string(),
            ]),
        ];

        for command in commands {
            let AgentCommand::Args(items) =
                codex_command_with_cli_overrides(command, &endpoint, &cfg)
            else {
                panic!("expected Codex command to remain an args command");
            };
            assert_eq!(
                items
                    .iter()
                    .filter(|item| *item == "--dangerously-bypass-approvals-and-sandbox")
                    .count(),
                1,
                "Codex launch must contain exactly one full-access flag: {items:?}"
            );
            let full_access_pos = items
                .iter()
                .position(|item| item == "--dangerously-bypass-approvals-and-sandbox")
                .unwrap();
            assert!(full_access_pos > 0);
            if let Some(subcommand_pos) = items
                .iter()
                .position(|item| item == "resume" || item == "fork")
            {
                assert!(full_access_pos < subcommand_pos);
            }
        }
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
    fn codex_cli_overrides_forward_custom_model_and_reasoning_effort() {
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
            AgentCommand::Args(vec!["codex".to_string()]),
            tmp.path().join("state.json"),
            codex_home,
        );
        cfg.codex_config_path = config_path;
        let mut endpoint = endpoint(workdir);
        endpoint.model = "partner/custom-codex-model".to_string();
        endpoint.reasoning_effort = "adaptive".to_string();

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected args command");
        };
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "model=\"partner/custom-codex-model\""]));
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "model_reasoning_effort=\"adaptive\""]));
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
    fn codex_cli_overrides_include_provider_model_limits_when_configured() {
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
        cfg.codex_model_context_window = Some(65536);
        cfg.codex_provider_model_limits.insert(
            "primary".to_string(),
            CodexModelLimits {
                model_context_window: Some(128000),
                model_auto_compact_token_limit: Some(112000),
            },
        );
        let endpoint = endpoint(workdir);

        let command = codex_command_with_cli_overrides(cfg.agent_command.clone(), &endpoint, &cfg);

        let AgentCommand::Args(items) = command else {
            panic!("expected args command");
        };
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "model_context_window=128000"]));
        assert!(items
            .windows(2)
            .any(|pair| pair == ["-c", "model_auto_compact_token_limit=112000"]));
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
        let claude_terms = "Bypass permissions mode requires confirmation\n\
             1. No, exit\n\
             > 2. Yes, I accept";
        assert!(claude_terms_acceptance_prompt_visible(claude_terms));
        assert_eq!(claude_terms_acceptance_prompt_navigation(claude_terms), "");
        assert_eq!(
            claude_terms_acceptance_prompt_navigation(
                "Bypass permissions mode requires confirmation\n\
                 > 1. No, exit\n\
                   2. Yes, I accept"
            ),
            "\x1b[B"
        );
        assert!(!generic_first_option_prompt_visible(claude_terms));
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
        let command_approval =
            "$ Get-Location; Get-ChildItem -Force; Get-ChildItem -LiteralPath 'D:\\Works\\SelfWorks\\SimEngine' -Force | Select-Object Name,Mode,Length\n\n\
             1. Yes, proceed (y)\n\
             > 2. Yes, and don't ask again for commands that start with `Get-Location; Get-ChildItem -Force; Get-ChildItem -LiteralPath 'D:\\Works\\SelfWorks\\SimEngine' -Force | Select-Object Name,Mode,Length` (p)\n\
             3. No, and tell Codex what to do differently (esc)";
        assert!(codex_command_approval_prompt_visible(command_approval));
        assert!(!generic_first_option_prompt_visible(command_approval));
    }

    #[test]
    fn opencode_prompt_box_distinguishes_idle_prefilled_and_busy_states() {
        let idle = "OpenCode\n\
            ┃\n\
            ┃  Ask anything... \"What is the tech stack of this project?\"\n\
            ┃\n\
            ┃  Build auto · gpt-5.6-terra WatchApi Runtime\n\
            ╹▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀\n\
            tab agents  ctrl+p commands";
        let prefilled = "OpenCode\n\
            ┃  Continue the current task\n\
            ┃  and run the tests\n\
            ┃  Build auto · claude-opus-5 New API Local\n\
            ╹▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀\n\
            tab agents  ctrl+p commands";
        let busy = format!("{idle}\nesc interrupt");
        let retrying = format!("{idle}\nRetrying in 3s (attempt 2)");

        assert!(opencode_prompt_footer_visible(idle));
        assert!(opencode_idle_prompt_visible(idle));
        assert!(!opencode_prefilled_input_visible(idle));
        assert_eq!(
            opencode_current_prompt_input(prefilled).as_deref(),
            Some("Continue the current task\nand run the tests")
        );
        assert!(opencode_prefilled_input_visible(prefilled));
        assert!(!opencode_idle_prompt_visible(prefilled));
        assert!(opencode_busy_prompt_visible(&busy));
        assert!(opencode_busy_prompt_visible(&retrying));
        assert!(!opencode_idle_prompt_visible(&busy));
        assert!(!opencode_prompt_footer_visible(
            "┃  Not an OpenCode prompt\n╹────────"
        ));

        let alternate_idle = "│  Ask anything... \"Fix a TODO in the codebase\"\n\
            └────────────────";
        let alternate_prefilled = "│  Continue the current task\n\
            └────────────────\n\
            tab agents  ctrl+p commands";
        assert!(opencode_idle_prompt_visible(alternate_idle));
        assert_eq!(
            opencode_current_prompt_input(alternate_prefilled).as_deref(),
            Some("Continue the current task")
        );
        assert!(opencode_prefilled_input_visible(alternate_prefilled));
    }

    #[test]
    fn opencode_auto_input_uses_mounted_empty_prompt_without_bracketed_paste() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::OpenCode,
                AgentCommand::Args(vec!["opencode".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        let idle = "┃  Ask anything... \"Fix a TODO in the codebase\"\n\
            ┃  Build auto · claude-opus-5 New API Local\n\
            ╹▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀\n\
            tab agents  ctrl+p commands";
        agent.observed_terminal_view_text = idle.to_string();

        assert!(agent.startup_ready_for_prompt());
        assert!(agent.current_terminal_view_ready());
        assert!(agent.can_send_prompt());

        agent.observed_terminal_view_text = idle.replace(
            "Ask anything... \"Fix a TODO in the codebase\"",
            "Continue the current task",
        );
        assert!(agent.current_terminal_prefilled_input_visible());
        assert!(!agent.can_send_prompt());
        assert_eq!(agent.auto_input_block_reason(), Some("输入框已有内容"));

        agent.observed_terminal_view_text = format!("{idle}\nesc interrupt");
        assert!(agent.current_terminal_view_busy());
        assert!(!agent.can_send_prompt());
    }

    #[test]
    fn opencode_submit_retry_detects_prompt_left_in_input_box() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        let mut agent = AgentProcess::new(
            config(
                workdir.clone(),
                AgentDriver::OpenCode,
                AgentCommand::Args(vec!["opencode".to_string()]),
                tmp.path().join("state.json"),
                tmp.path().join(".codex"),
            ),
            endpoint(workdir),
            false,
        );
        agent.observed_terminal_view_text = "┃  Continue the current task\n\
            ┃  Build auto · claude-opus-5 New API Local\n\
            ╹▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
            .to_string();
        agent.awaiting_turn_completion = true;
        agent.last_submit_attempt_at = Some(Instant::now() - Duration::from_secs(6));

        assert!(agent.needs_submit_retry(5.0));

        agent
            .observed_terminal_view_text
            .push_str("\nesc interrupt");
        assert!(!agent.needs_submit_retry(5.0));
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
