use crate::config::{split_shell_like_command, AgentCommand};
use crate::terminal_emulator::{TerminalEmulator, TerminalView};
use crossbeam_channel::{unbounded, Receiver, Sender};
use parking_lot::Mutex;
use portable_pty::{native_pty_system, Child, CommandBuilder, ExitStatus, MasterPty, PtySize};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TerminalError {
    #[error("agent command is empty")]
    EmptyCommand,
    #[error("agent command program was not found: {0}")]
    ProgramNotFound(String),
    #[error("pty operation failed: {0}")]
    Pty(String),
    #[error("terminal is not running")]
    NotRunning,
    #[error("automatic input is blocked while user is typing")]
    UserInputActive,
    #[error("automatic input is blocked: {0}")]
    AutoInputBlocked(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSource {
    User,
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalEvent {
    Output(String),
    Exit(Option<String>),
}

pub type TerminalActivityWakeup = Arc<dyn Fn() + Send + Sync + 'static>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSnapshot {
    pub output: String,
    pub view: TerminalView,
    pub is_running: bool,
    pub user_input_active: bool,
}

pub struct TerminalSession {
    backend: TerminalBackend,
    output: Arc<Mutex<RingTextBuffer>>,
    emulator: Arc<Mutex<TerminalEmulator>>,
    user_input_active: Arc<Mutex<bool>>,
    last_activity_at: Arc<Mutex<Instant>>,
    last_output_at: Arc<Mutex<Instant>>,
    activity_wakeup: Arc<Mutex<Option<TerminalActivityWakeup>>>,
    events: Receiver<TerminalEvent>,
    _event_tx: Sender<TerminalEvent>,
}

#[derive(Clone)]
pub struct TerminalControl {
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Arc<Mutex<Option<Box<dyn Child + Send + Sync>>>>,
    output: Arc<Mutex<RingTextBuffer>>,
    emulator: Arc<Mutex<TerminalEmulator>>,
    user_input_active: Arc<Mutex<bool>>,
    last_activity_at: Arc<Mutex<Instant>>,
    activity_wakeup: Arc<Mutex<Option<TerminalActivityWakeup>>>,
}

impl std::fmt::Debug for TerminalControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalControl").finish_non_exhaustive()
    }
}

impl PartialEq for TerminalControl {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.master, &other.master)
            && Arc::ptr_eq(&self.writer, &other.writer)
            && Arc::ptr_eq(&self.child, &other.child)
    }
}

impl Eq for TerminalControl {}

enum TerminalBackend {
    Pty {
        master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
        writer: Arc<Mutex<Box<dyn Write + Send>>>,
        child: Arc<Mutex<Option<Box<dyn Child + Send + Sync>>>>,
    },
}

impl TerminalControl {
    pub fn clear_local_view(&self) {
        self.output.lock().clear();
        self.emulator.lock().clear_screen_and_scrollback();
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn set_activity_wakeup(&self, wakeup: Option<TerminalActivityWakeup>) {
        *self.activity_wakeup.lock() = wakeup;
    }

    pub fn mark_user_input_active(&self, active: bool) {
        *self.user_input_active.lock() = active;
    }

    pub fn write_input(&self, text: &str, source: InputSource) -> Result<(), TerminalError> {
        if source == InputSource::Auto && *self.user_input_active.lock() {
            return Err(TerminalError::UserInputActive);
        }
        {
            let mut writer = self.writer.lock();
            writer
                .write_all(text.as_bytes())
                .map_err(|err| TerminalError::Pty(err.to_string()))?;
            writer
                .flush()
                .map_err(|err| TerminalError::Pty(err.to_string()))?;
        }
        *self.last_activity_at.lock() = Instant::now();
        wake_terminal_activity(&self.activity_wakeup);
        Ok(())
    }

    pub fn write_user_input(&self, text: &str) -> Result<(), TerminalError> {
        self.write_input(text, InputSource::User)
    }

    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), TerminalError> {
        self.master
            .lock()
            .resize(PtySize {
                rows: rows.max(1),
                cols: cols.max(1),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| TerminalError::Pty(err.to_string()))?;
        self.emulator.lock().resize(rows as usize, cols as usize);
        wake_terminal_activity(&self.activity_wakeup);
        Ok(())
    }

    pub fn scroll_display(&self, delta: i32) {
        self.emulator.lock().scroll_display(delta);
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn scroll_bottom(&self) {
        self.emulator.lock().scroll_bottom();
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn scroll_to_offset(&self, offset: usize) {
        self.emulator.lock().scroll_to_offset(offset);
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn stop_process(&self) {
        let mut guard = self.child.lock();
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn is_running(&self) -> bool {
        let mut guard = self.child.lock();
        let Some(child) = guard.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(_) => false,
        }
    }

    pub fn process_id(&self) -> Option<u32> {
        child_process_id_if_running(&self.child)
    }

    pub fn snapshot(&self) -> TerminalSnapshot {
        TerminalSnapshot {
            output: self.output.lock().text(),
            view: self.emulator.lock().view(),
            is_running: self.is_running(),
            user_input_active: *self.user_input_active.lock(),
        }
    }

    pub fn output_text(&self) -> String {
        self.output.lock().text()
    }

    pub fn output_delta_from(&self, start: usize) -> (String, usize) {
        self.output.lock().text_delta_from(start)
    }

    pub fn output_revision(&self) -> u64 {
        self.output.lock().revision()
    }

    pub fn view_revision(&self) -> u64 {
        self.emulator.lock().revision()
    }

    pub fn view(&self) -> TerminalView {
        self.emulator.lock().view()
    }
}

impl TerminalSession {
    pub fn start(
        command: &AgentCommand,
        workdir: PathBuf,
        rows: u16,
        cols: u16,
        max_bytes: usize,
    ) -> Result<Self, TerminalError> {
        Self::start_with_env(command, workdir, rows, cols, max_bytes, &HashMap::new())
    }

    pub fn start_with_env(
        command: &AgentCommand,
        workdir: PathBuf,
        rows: u16,
        cols: u16,
        max_bytes: usize,
        env: &HashMap<String, String>,
    ) -> Result<Self, TerminalError> {
        let resolved = resolve_command(command)?;
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| TerminalError::Pty(err.to_string()))?;

        let mut builder = CommandBuilder::new(&resolved.program);
        for arg in &resolved.args {
            builder.arg(arg);
        }
        for (key, value) in env {
            builder.env(key, value);
        }
        for (key, value) in &resolved.env {
            builder.env(key, value);
        }
        builder.cwd(workdir);

        let child = pair
            .slave
            .spawn_command(builder)
            .map_err(|err| TerminalError::Pty(err.to_string()))?;
        drop(pair.slave);

        let writer = pair
            .master
            .take_writer()
            .map_err(|err| TerminalError::Pty(err.to_string()))?;
        let writer = Arc::new(Mutex::new(writer));
        let writer_for_thread = Arc::clone(&writer);
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|err| TerminalError::Pty(err.to_string()))?;

        let output = Arc::new(Mutex::new(RingTextBuffer::new(max_bytes)));
        let output_for_thread = Arc::clone(&output);
        let emulator = Arc::new(Mutex::new(TerminalEmulator::new(
            rows as usize,
            cols as usize,
        )));
        let emulator_for_thread = Arc::clone(&emulator);
        let last_activity_at = Arc::new(Mutex::new(Instant::now()));
        let last_activity_for_thread = Arc::clone(&last_activity_at);
        let last_output_at = Arc::new(Mutex::new(Instant::now()));
        let last_output_for_thread = Arc::clone(&last_output_at);
        let activity_wakeup = Arc::new(Mutex::new(None));
        let activity_wakeup_for_thread = Arc::clone(&activity_wakeup);
        let child = Arc::new(Mutex::new(Some(child)));
        let child_for_thread = Arc::clone(&child);
        let (event_tx, events) = unbounded();
        let event_tx_for_thread = event_tx.clone();

        thread::spawn(move || {
            let mut buffer = [0_u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        let status = child_exit_status_text(&child_for_thread);
                        let _ = event_tx_for_thread.send(TerminalEvent::Exit(status));
                        wake_terminal_activity(&activity_wakeup_for_thread);
                        break;
                    }
                    Ok(count) => {
                        let text = String::from_utf8_lossy(&buffer[..count]).to_string();
                        *last_activity_for_thread.lock() = Instant::now();
                        *last_output_for_thread.lock() = Instant::now();
                        output_for_thread.lock().push(&text);
                        let pty_writes = emulator_for_thread.lock().advance(&buffer[..count]);
                        if !pty_writes.is_empty() {
                            let mut writer = writer_for_thread.lock();
                            for text in pty_writes {
                                let _ = writer.write_all(text.as_bytes());
                            }
                            let _ = writer.flush();
                        }
                        let _ = event_tx_for_thread.send(TerminalEvent::Output(text));
                        wake_terminal_activity(&activity_wakeup_for_thread);
                    }
                    Err(_) => {
                        let status = child_exit_status_text(&child_for_thread);
                        let _ = event_tx_for_thread.send(TerminalEvent::Exit(status));
                        wake_terminal_activity(&activity_wakeup_for_thread);
                        break;
                    }
                }
            }
        });

        Ok(Self {
            backend: TerminalBackend::Pty {
                master: Arc::new(Mutex::new(pair.master)),
                writer,
                child,
            },
            output,
            emulator,
            user_input_active: Arc::new(Mutex::new(false)),
            last_activity_at,
            last_output_at,
            activity_wakeup,
            events,
            _event_tx: event_tx,
        })
    }

    pub fn push_local_output(&self, text: &str) {
        if text.is_empty() {
            return;
        }
        self.output.lock().push(text);
        *self.last_activity_at.lock() = Instant::now();
        *self.last_output_at.lock() = Instant::now();
        let _ = self._event_tx.send(TerminalEvent::Output(text.to_string()));
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn clear_local_view(&self) {
        self.output.lock().clear();
        self.emulator.lock().clear_screen_and_scrollback();
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn events(&self) -> Receiver<TerminalEvent> {
        self.events.clone()
    }

    pub fn set_activity_wakeup(&self, wakeup: Option<TerminalActivityWakeup>) {
        *self.activity_wakeup.lock() = wakeup;
    }

    pub fn mark_user_input_active(&self, active: bool) {
        *self.user_input_active.lock() = active;
    }

    pub fn write_input(&self, text: &str, source: InputSource) -> Result<(), TerminalError> {
        if source == InputSource::Auto && *self.user_input_active.lock() {
            return Err(TerminalError::UserInputActive);
        }
        match &self.backend {
            TerminalBackend::Pty { writer, .. } => {
                let mut writer = writer.lock();
                writer
                    .write_all(text.as_bytes())
                    .map_err(|err| TerminalError::Pty(err.to_string()))?;
                writer
                    .flush()
                    .map_err(|err| TerminalError::Pty(err.to_string()))?;
            }
        }
        *self.last_activity_at.lock() = Instant::now();
        wake_terminal_activity(&self.activity_wakeup);
        Ok(())
    }

    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), TerminalError> {
        match &self.backend {
            TerminalBackend::Pty { master, .. } => master
                .lock()
                .resize(PtySize {
                    rows: rows.max(1),
                    cols: cols.max(1),
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|err| TerminalError::Pty(err.to_string()))?,
        };
        self.emulator.lock().resize(rows as usize, cols as usize);
        wake_terminal_activity(&self.activity_wakeup);
        Ok(())
    }

    pub fn scroll_display(&self, delta: i32) {
        self.emulator.lock().scroll_display(delta);
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn scroll_bottom(&self) {
        self.emulator.lock().scroll_bottom();
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn scroll_to_offset(&self, offset: usize) {
        self.emulator.lock().scroll_to_offset(offset);
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn send_prompt(
        &self,
        prompt: &str,
        submit_sequence: &str,
        source: InputSource,
    ) -> Result<(), TerminalError> {
        let text = format!(
            "{}{}",
            prompt.trim_end(),
            submit_sequence_text(submit_sequence)
        );
        self.write_input(&text, source)
    }

    pub fn is_running(&self) -> bool {
        match &self.backend {
            TerminalBackend::Pty { child, .. } => {
                let mut guard = child.lock();
                let Some(child) = guard.as_mut() else {
                    return false;
                };
                match child.try_wait() {
                    Ok(Some(_)) => false,
                    Ok(None) => true,
                    Err(_) => false,
                }
            }
        }
    }

    pub fn stop(&self) {
        match &self.backend {
            TerminalBackend::Pty { child, .. } => {
                let mut guard = child.lock();
                if let Some(mut child) = guard.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        wake_terminal_activity(&self.activity_wakeup);
    }

    pub fn process_id(&self) -> Option<u32> {
        match &self.backend {
            TerminalBackend::Pty { child, .. } => child_process_id_if_running(child),
        }
    }

    pub fn last_activity_elapsed(&self) -> Duration {
        self.last_activity_at.lock().elapsed()
    }

    pub fn last_activity_instant(&self) -> Instant {
        *self.last_activity_at.lock()
    }

    pub fn last_output_instant(&self) -> Instant {
        *self.last_output_at.lock()
    }

    pub fn snapshot(&self) -> TerminalSnapshot {
        TerminalSnapshot {
            output: self.output.lock().text(),
            view: self.emulator.lock().view(),
            is_running: self.is_running(),
            user_input_active: *self.user_input_active.lock(),
        }
    }

    pub fn output_text(&self) -> String {
        self.output.lock().text()
    }

    pub fn output_delta_from(&self, start: usize) -> (String, usize) {
        self.output.lock().text_delta_from(start)
    }

    pub fn output_revision(&self) -> u64 {
        self.output.lock().revision()
    }

    pub fn view_revision(&self) -> u64 {
        self.emulator.lock().revision()
    }

    pub fn view(&self) -> TerminalView {
        self.emulator.lock().view()
    }

    pub fn control(&self) -> TerminalControl {
        match &self.backend {
            TerminalBackend::Pty {
                master,
                writer,
                child,
            } => TerminalControl {
                master: Arc::clone(master),
                writer: Arc::clone(writer),
                child: Arc::clone(child),
                output: Arc::clone(&self.output),
                emulator: Arc::clone(&self.emulator),
                user_input_active: Arc::clone(&self.user_input_active),
                last_activity_at: Arc::clone(&self.last_activity_at),
                activity_wakeup: Arc::clone(&self.activity_wakeup),
            },
        }
    }
}

fn wake_terminal_activity(activity_wakeup: &Arc<Mutex<Option<TerminalActivityWakeup>>>) {
    let wakeup = activity_wakeup.lock().clone();
    if let Some(wakeup) = wakeup {
        wakeup();
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        self.stop();
    }
}

fn split_command(command: &AgentCommand) -> Result<(String, Vec<String>), TerminalError> {
    Ok(resolve_command(command)?.into_parts())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedCommand {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
}

impl ResolvedCommand {
    fn new(program: String, args: Vec<String>) -> Self {
        Self {
            program,
            args,
            env: Vec::new(),
        }
    }

    fn into_parts(self) -> (String, Vec<String>) {
        (self.program, self.args)
    }
}

fn resolve_command(command: &AgentCommand) -> Result<ResolvedCommand, TerminalError> {
    match command {
        AgentCommand::Args(items) => {
            let program = items.first().cloned().ok_or(TerminalError::EmptyCommand)?;
            let resolved = resolve_program(program)?;
            Ok(adapt_windows_wrapper_command(resolved, items[1..].to_vec()))
        }
        AgentCommand::Shell(text) => {
            let parts = split_shell_like_command(text);
            let program = parts.first().cloned().ok_or(TerminalError::EmptyCommand)?;
            let resolved = resolve_program(program)?;
            Ok(adapt_windows_wrapper_command(resolved, parts[1..].to_vec()))
        }
    }
}

pub fn resolved_command_parts(
    command: &AgentCommand,
) -> Result<(String, Vec<String>), TerminalError> {
    split_command(command)
}

#[cfg(test)]
fn adapt_windows_wrapper(program: String, args: Vec<String>) -> (String, Vec<String>) {
    adapt_windows_wrapper_command(program, args).into_parts()
}

fn adapt_windows_wrapper_command(program: String, args: Vec<String>) -> ResolvedCommand {
    #[cfg(windows)]
    {
        if let Some(unwrapped) = unwrap_windows_codex_shim(&program, &args) {
            return unwrapped;
        }
        let lower = program.to_ascii_lowercase();
        if lower.ends_with(".cmd") || lower.ends_with(".bat") {
            let mut wrapped = vec!["/d".to_string(), "/c".to_string(), program];
            wrapped.extend(args);
            return ResolvedCommand::new("cmd.exe".to_string(), wrapped);
        }
    }
    ResolvedCommand::new(program, args)
}

#[cfg(windows)]
fn unwrap_windows_codex_shim(program: &str, args: &[String]) -> Option<ResolvedCommand> {
    let path = PathBuf::from(program);
    let file_name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if file_name != "codex" && file_name != "codex.cmd" && file_name != "codex.ps1" {
        return None;
    }
    let base_dir = path.parent()?;
    let package_root = base_dir.join("node_modules").join("@openai").join("codex");
    let (native_exe, arch_root) = codex_native_exe_from_package_root(&package_root)?;
    let mut command = ResolvedCommand::new(native_exe.to_string_lossy().to_string(), args.to_vec());
    if let Some(path) = codex_path_with_vendor_tools(&arch_root) {
        command.env.push(("PATH".to_string(), path));
    }
    command
        .env
        .push(("CODEX_MANAGED_BY_NPM".to_string(), "1".to_string()));
    command.env.push((
        "CODEX_MANAGED_PACKAGE_ROOT".to_string(),
        package_root
            .canonicalize()
            .unwrap_or(package_root)
            .to_string_lossy()
            .to_string(),
    ));
    Some(command)
}

#[cfg(windows)]
fn codex_native_exe_from_package_root(
    package_root: &std::path::Path,
) -> Option<(PathBuf, PathBuf)> {
    let target = if cfg!(target_arch = "aarch64") {
        "aarch64-pc-windows-msvc"
    } else {
        "x86_64-pc-windows-msvc"
    };
    let direct_vendor = package_root
        .join("vendor")
        .join(target)
        .join("codex")
        .join("codex.exe");
    if direct_vendor.exists() {
        return direct_vendor
            .parent()
            .and_then(|path| path.parent())
            .map(|arch_root| (direct_vendor.clone(), arch_root.to_path_buf()));
    }

    let package_name = if cfg!(target_arch = "aarch64") {
        "codex-win32-arm64"
    } else {
        "codex-win32-x64"
    };
    let optional_vendor = package_root
        .join("node_modules")
        .join("@openai")
        .join(package_name)
        .join("vendor")
        .join(target)
        .join("codex")
        .join("codex.exe");
    if optional_vendor.exists() {
        return optional_vendor
            .parent()
            .and_then(|path| path.parent())
            .map(|arch_root| (optional_vendor.clone(), arch_root.to_path_buf()));
    }
    None
}

#[cfg(windows)]
fn codex_path_with_vendor_tools(arch_root: &std::path::Path) -> Option<String> {
    let path_dir = arch_root.join("path");
    if !path_dir.exists() {
        return None;
    }
    let mut paths = vec![path_dir];
    if let Some(current) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&current));
    }
    std::env::join_paths(paths)
        .ok()
        .map(|value| value.to_string_lossy().to_string())
}

fn child_exit_status_text(
    child: &Arc<Mutex<Option<Box<dyn Child + Send + Sync>>>>,
) -> Option<String> {
    let mut guard = child.lock();
    let child = guard.as_mut()?;
    match child.try_wait() {
        Ok(Some(status)) => Some(exit_status_text(status)),
        Ok(None) => None,
        Err(err) => Some(format!("状态读取失败：{err}")),
    }
}

fn child_process_id_if_running(
    child: &Arc<Mutex<Option<Box<dyn Child + Send + Sync>>>>,
) -> Option<u32> {
    let mut guard = child.lock();
    let child = guard.as_mut()?;
    match child.try_wait() {
        Ok(Some(_)) | Err(_) => None,
        Ok(None) => child.process_id(),
    }
}

fn exit_status_text(status: ExitStatus) -> String {
    if status.success() {
        "退出码 0".to_string()
    } else {
        status.to_string()
    }
}

fn submit_sequence_text(sequence: &str) -> &'static str {
    match sequence {
        "cr" | "control-m" => "\r",
        "crlf" => "\r\n",
        "lf" => "\n",
        _ => "\r",
    }
}

fn resolve_program(program: String) -> Result<String, TerminalError> {
    if has_path_part(&program) {
        if PathBuf::from(&program).exists() {
            return Ok(program);
        }
        return Err(TerminalError::ProgramNotFound(program));
    }
    if let Some(found) = find_in_path(&program) {
        return Ok(found);
    }
    if cfg!(windows) {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            let npm = PathBuf::from(appdata).join("npm");
            for suffix in [".cmd", ".exe", ".bat", ""] {
                let candidate = npm.join(format!("{program}{suffix}"));
                if candidate.exists() {
                    return Ok(candidate.to_string_lossy().into_owned());
                }
            }
        }
    }
    Err(TerminalError::ProgramNotFound(program))
}

fn has_path_part(program: &str) -> bool {
    program.contains('/') || program.contains('\\')
}

fn find_in_path(program: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    let suffixes: Vec<String> = if cfg!(windows) {
        let pathext =
            std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
        pathext
            .split(';')
            .filter(|suffix| !suffix.trim().is_empty())
            .map(str::to_string)
            .chain([".CMD".to_string(), ".EXE".to_string(), ".BAT".to_string()])
            .chain(std::iter::once(String::new()))
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        for suffix in &suffixes {
            let candidate = dir.join(format!("{program}{suffix}"));
            if candidate.exists() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

#[derive(Debug)]
struct RingTextBuffer {
    chunks: VecDeque<String>,
    bytes: usize,
    max_bytes: usize,
    revision: u64,
}

impl RingTextBuffer {
    fn new(max_bytes: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            bytes: 0,
            max_bytes: max_bytes.max(1),
            revision: 0,
        }
    }

    fn push(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        self.revision = self.revision.wrapping_add(1).max(1);
        let text = utf8_tail(text, self.max_bytes);
        self.bytes += text.len();
        self.chunks.push_back(text);
        while self.bytes > self.max_bytes {
            let Some(front) = self.chunks.pop_front() else {
                self.bytes = 0;
                break;
            };
            if self.bytes.saturating_sub(front.len()) >= self.max_bytes {
                self.bytes = self.bytes.saturating_sub(front.len());
                continue;
            }
            let keep = self
                .max_bytes
                .saturating_sub(self.bytes.saturating_sub(front.len()));
            let tail = utf8_tail(&front, keep);
            self.bytes = self.bytes.saturating_sub(front.len()) + tail.len();
            if !tail.is_empty() {
                self.chunks.push_front(tail);
            }
            break;
        }
    }

    fn text(&self) -> String {
        let mut out = String::with_capacity(self.bytes);
        for chunk in &self.chunks {
            out.push_str(chunk);
        }
        out
    }

    fn text_delta_from(&self, start: usize) -> (String, usize) {
        if start == self.bytes {
            return (String::new(), self.bytes);
        }
        if start > self.bytes || !self.is_char_boundary(start) {
            return (self.text(), self.bytes);
        }
        let mut remaining = start;
        let delta_len = self.bytes - start;
        let mut out = String::with_capacity(delta_len);
        for chunk in &self.chunks {
            if remaining >= chunk.len() {
                remaining -= chunk.len();
                continue;
            }
            out.push_str(&chunk[remaining..]);
            remaining = 0;
        }
        (out, self.bytes)
    }

    fn is_char_boundary(&self, index: usize) -> bool {
        if index == 0 || index == self.bytes {
            return true;
        }
        let mut offset = 0;
        for chunk in &self.chunks {
            let next = offset + chunk.len();
            if index < next {
                return chunk.is_char_boundary(index - offset);
            }
            if index == next {
                return true;
            }
            offset = next;
        }
        false
    }

    fn revision(&self) -> u64 {
        self.revision
    }

    fn clear(&mut self) {
        if self.bytes == 0 {
            return;
        }
        self.chunks.clear();
        self.bytes = 0;
        self.revision = self.revision.wrapping_add(1).max(1);
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Error;
    use std::io;

    #[derive(Debug)]
    struct TestMasterPty;

    impl MasterPty for TestMasterPty {
        fn resize(&self, _size: PtySize) -> Result<(), Error> {
            Ok(())
        }

        fn get_size(&self) -> Result<PtySize, Error> {
            Ok(PtySize {
                rows: 30,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
        }

        fn try_clone_reader(&self) -> Result<Box<dyn io::Read + Send>, Error> {
            Ok(Box::new(io::empty()))
        }

        fn take_writer(&self) -> Result<Box<dyn io::Write + Send>, Error> {
            Ok(Box::new(Vec::<u8>::new()))
        }
    }

    #[derive(Debug)]
    struct FailingResizeMasterPty;

    impl MasterPty for FailingResizeMasterPty {
        fn resize(&self, _size: PtySize) -> Result<(), Error> {
            Err(Error::msg("resize failed"))
        }

        fn get_size(&self) -> Result<PtySize, Error> {
            Ok(PtySize {
                rows: 30,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
        }

        fn try_clone_reader(&self) -> Result<Box<dyn io::Read + Send>, Error> {
            Ok(Box::new(io::empty()))
        }

        fn take_writer(&self) -> Result<Box<dyn io::Write + Send>, Error> {
            Ok(Box::new(Vec::<u8>::new()))
        }
    }

    fn test_terminal_session() -> TerminalSession {
        let (_tx, rx) = unbounded();
        TerminalSession {
            backend: TerminalBackend::Pty {
                master: Arc::new(Mutex::new(Box::new(TestMasterPty))),
                writer: Arc::new(Mutex::new(Box::new(Vec::<u8>::new()))),
                child: Arc::new(Mutex::new(None)),
            },
            output: Arc::new(Mutex::new(RingTextBuffer::new(1024))),
            emulator: Arc::new(Mutex::new(TerminalEmulator::new(30, 120))),
            user_input_active: Arc::new(Mutex::new(false)),
            last_activity_at: Arc::new(Mutex::new(Instant::now())),
            last_output_at: Arc::new(Mutex::new(Instant::now())),
            activity_wakeup: Arc::new(Mutex::new(None)),
            events: rx,
            _event_tx: _tx,
        }
    }

    fn terminal_session_with_master(master: Box<dyn MasterPty + Send>) -> TerminalSession {
        let (_tx, rx) = unbounded();
        TerminalSession {
            backend: TerminalBackend::Pty {
                master: Arc::new(Mutex::new(master)),
                writer: Arc::new(Mutex::new(Box::new(Vec::<u8>::new()))),
                child: Arc::new(Mutex::new(None)),
            },
            output: Arc::new(Mutex::new(RingTextBuffer::new(1024))),
            emulator: Arc::new(Mutex::new(TerminalEmulator::new(30, 120))),
            user_input_active: Arc::new(Mutex::new(false)),
            last_activity_at: Arc::new(Mutex::new(Instant::now())),
            last_output_at: Arc::new(Mutex::new(Instant::now())),
            activity_wakeup: Arc::new(Mutex::new(None)),
            events: rx,
            _event_tx: _tx,
        }
    }

    #[test]
    fn auto_input_is_blocked_while_user_is_typing() {
        let session = test_terminal_session();

        session.mark_user_input_active(true);

        assert!(matches!(
            session.write_input("auto\r", InputSource::Auto),
            Err(TerminalError::UserInputActive)
        ));
        assert!(session.write_input("manual", InputSource::User).is_ok());
    }

    #[test]
    fn local_output_does_not_pollute_terminal_screen_view() {
        let session = test_terminal_session();

        session.push_local_output("> 启动 Agent: codex\r\n");

        assert!(session.output_text().contains("启动 Agent"));
        let view_text = session
            .view()
            .cells
            .iter()
            .filter(|cell| !cell.c.is_whitespace())
            .map(|cell| cell.c)
            .collect::<String>();
        assert!(
            !view_text.contains('启') && !view_text.contains("Agent"),
            "local diagnostic output should not be written into the PTY screen buffer"
        );
    }

    #[test]
    fn ring_buffer_keeps_recent_output() {
        let mut buffer = RingTextBuffer::new(5);

        buffer.push("abc");
        buffer.push("def");

        assert_eq!(buffer.text(), "bcdef");
    }

    #[test]
    fn ring_buffer_reads_delta_without_joining_full_output() {
        let mut buffer = RingTextBuffer::new(16);
        buffer.push("abc");
        let start = buffer.text().len();
        buffer.push("甲乙");

        let (delta, next_len) = buffer.text_delta_from(start);

        assert_eq!(delta, "甲乙");
        assert_eq!(next_len, buffer.text().len());
        assert_eq!(buffer.text_delta_from(next_len), (String::new(), next_len));
    }

    #[test]
    fn ring_buffer_delta_falls_back_after_truncation_or_split_utf8() {
        let mut buffer = RingTextBuffer::new(8);
        buffer.push("abc");
        let old_start = buffer.text().len();
        buffer.push("甲乙丙丁");

        let current = buffer.text();
        assert_eq!(
            buffer.text_delta_from(old_start),
            (current.clone(), current.len())
        );
        assert_eq!(buffer.text_delta_from(3), (current.clone(), current.len()));
    }

    #[test]
    fn ring_buffer_keeps_tail_of_large_utf8_chunk() {
        let mut buffer = RingTextBuffer::new(8);

        buffer.push("甲乙丙丁");

        assert_eq!(buffer.text(), "丙丁");
    }

    #[test]
    fn ring_buffer_revision_changes_only_when_output_changes() {
        let mut buffer = RingTextBuffer::new(8);

        assert_eq!(buffer.revision(), 0);
        buffer.push("");
        assert_eq!(buffer.revision(), 0);
        buffer.push("abc");
        assert_eq!(buffer.revision(), 1);
        buffer.push("def");
        assert_eq!(buffer.revision(), 2);
    }

    #[test]
    fn ring_buffer_clear_removes_text_and_bumps_revision_once() {
        let mut buffer = RingTextBuffer::new(8);
        buffer.push("abc");
        let revision = buffer.revision();

        buffer.clear();

        assert_eq!(buffer.text(), "");
        assert!(buffer.revision() > revision);
        let clear_revision = buffer.revision();
        buffer.clear();
        assert_eq!(buffer.revision(), clear_revision);
    }

    #[test]
    fn terminal_control_clear_local_view_clears_output_and_screen() {
        let session = test_terminal_session();
        session.push_local_output("old log");
        session.emulator.lock().advance(b"old");
        let output_revision = session.output_revision();
        let view_revision = session.view_revision();

        session.control().clear_local_view();

        assert_eq!(session.output_text(), "");
        assert!(session.output_revision() > output_revision);
        assert!(session.view_revision() > view_revision);
        let view_text = session
            .view()
            .cells
            .iter()
            .map(|cell| cell.c)
            .collect::<String>();
        assert!(view_text.trim().is_empty());
    }

    #[test]
    fn terminal_activity_wakeup_runs_on_local_output_and_control_mutations() {
        let session = test_terminal_session();
        let wakeups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wakeups_for_callback = Arc::clone(&wakeups);
        session.set_activity_wakeup(Some(Arc::new(move || {
            wakeups_for_callback.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })));

        session.push_local_output("new output");
        session.control().clear_local_view();

        assert_eq!(wakeups.load(std::sync::atomic::Ordering::SeqCst), 2);

        session.set_activity_wakeup(None);
        session.push_local_output("after disabled");

        assert_eq!(wakeups.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn terminal_resize_failure_does_not_mutate_local_emulator_view() {
        let session = terminal_session_with_master(Box::new(FailingResizeMasterPty));
        let initial_view = session.view();
        let initial_revision = session.view_revision();

        assert!(matches!(
            session.resize(20, 80),
            Err(TerminalError::Pty(message)) if message.contains("resize failed")
        ));

        let after_session_resize = session.view();
        assert_eq!(after_session_resize.rows, initial_view.rows);
        assert_eq!(after_session_resize.cols, initial_view.cols);
        assert_eq!(session.view_revision(), initial_revision);

        let control = session.control();
        assert!(matches!(
            control.resize(20, 80),
            Err(TerminalError::Pty(message)) if message.contains("resize failed")
        ));

        let after_control_resize = session.view();
        assert_eq!(after_control_resize.rows, initial_view.rows);
        assert_eq!(after_control_resize.cols, initial_view.cols);
        assert_eq!(session.view_revision(), initial_revision);
    }

    #[test]
    fn terminal_control_stop_process_kills_child_without_runtime_lock() {
        let command = if cfg!(windows) {
            AgentCommand::Args(vec![
                "cmd.exe".to_string(),
                "/d".to_string(),
                "/c".to_string(),
                "ping -n 30 127.0.0.1 >nul".to_string(),
            ])
        } else {
            AgentCommand::Args(vec![
                "sh".to_string(),
                "-c".to_string(),
                "sleep 30".to_string(),
            ])
        };
        let session =
            TerminalSession::start(&command, std::env::temp_dir(), 8, 80, 16_384).unwrap();
        let control = session.control();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && control.process_id().is_none() {
            std::thread::sleep(Duration::from_millis(20));
        }

        assert!(control.process_id().is_some());
        control.stop_process();

        assert_eq!(control.process_id(), None);
        assert!(!session.is_running());
    }

    #[test]
    fn split_shell_command_handles_quotes() {
        let parts = split_shell_like_command(r#"codex "--no-alt-screen" test"#);

        assert_eq!(parts, vec!["codex", "--no-alt-screen", "test"]);
    }

    #[test]
    fn split_shell_command_handles_single_quotes_empty_args_and_escaped_spaces() {
        let parts = split_shell_like_command(
            r#"codex 'resume session' "" escaped\ space "C:\Users\WPX\Codex""#,
        );

        assert_eq!(
            parts,
            vec![
                "codex",
                "resume session",
                "",
                "escaped space",
                r"C:\Users\WPX\Codex"
            ]
        );
    }

    #[test]
    fn missing_program_fails_before_pty_starts() {
        let command = AgentCommand::Args(vec!["definitely-missing-watchapi-command".to_string()]);

        assert!(matches!(
            resolved_command_parts(&command),
            Err(TerminalError::ProgramNotFound(program))
                if program == "definitely-missing-watchapi-command"
        ));
    }

    #[test]
    fn pty_reads_child_process_output() {
        let command = if cfg!(windows) {
            AgentCommand::Args(vec![
                "cmd.exe".to_string(),
                "/d".to_string(),
                "/c".to_string(),
                "echo watchapi-pty-smoke".to_string(),
            ])
        } else {
            AgentCommand::Args(vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf watchapi-pty-smoke".to_string(),
            ])
        };
        let session =
            TerminalSession::start(&command, std::env::temp_dir(), 8, 80, 16_384).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !session.output_text().contains("watchapi-pty-smoke") {
            std::thread::sleep(Duration::from_millis(20));
        }

        assert!(
            session.output_text().contains("watchapi-pty-smoke"),
            "PTY reader should receive child process stdout"
        );
    }

    #[test]
    fn process_id_is_none_after_child_exits() {
        let command = if cfg!(windows) {
            AgentCommand::Args(vec![
                "cmd.exe".to_string(),
                "/d".to_string(),
                "/c".to_string(),
                "exit 0".to_string(),
            ])
        } else {
            AgentCommand::Args(vec![
                "sh".to_string(),
                "-c".to_string(),
                "exit 0".to_string(),
            ])
        };
        let session =
            TerminalSession::start(&command, std::env::temp_dir(), 8, 80, 16_384).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && session.is_running() {
            std::thread::sleep(Duration::from_millis(20));
        }

        assert!(!session.is_running());
        assert_eq!(session.process_id(), None);
    }

    #[test]
    fn portable_pty_example_pattern_reads_child_process_output() {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 8,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let mut builder = if cfg!(windows) {
            let mut builder = CommandBuilder::new("cmd.exe");
            builder.arg("/d");
            builder.arg("/c");
            builder.arg("echo watchapi-pty-smoke");
            builder
        } else {
            let mut builder = CommandBuilder::new("sh");
            builder.arg("-c");
            builder.arg("printf watchapi-pty-smoke");
            builder
        };
        builder.cwd(std::env::temp_dir());
        let mut child = pair.slave.spawn_command(builder).unwrap();
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut output = String::new();
            let read_result = reader
                .read_to_string(&mut output)
                .map(|count| format!("ok:{count}"))
                .unwrap_or_else(|err| format!("err:{err:?}"));
            let _ = tx.send((output, read_result));
        });
        drop(pair.master.take_writer().unwrap());
        let status = child.wait().unwrap();
        drop(pair.master);
        let (output, read_result) = rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| (String::new(), "recv-timeout".to_string()));

        assert!(
            output.contains("watchapi-pty-smoke"),
            "portable-pty example pattern should read child stdout, status: {status:?}, read: {read_result}, got: {output:?}"
        );
    }

    #[test]
    fn windows_path_resolution_prefers_cmd_shim_over_extensionless_shell_script() {
        #[cfg(windows)]
        {
            let root = std::env::temp_dir().join(format!(
                "watchapi-path-test-{}-{}",
                std::process::id(),
                Instant::now().elapsed().as_nanos()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(
                root.join("node_modules")
                    .join("@openai")
                    .join("codex")
                    .join("node_modules")
                    .join("@openai")
                    .join("codex-win32-x64")
                    .join("vendor")
                    .join("x86_64-pc-windows-msvc")
                    .join("codex"),
            )
            .unwrap();
            std::fs::write(root.join("codex"), "#!/bin/sh\n").unwrap();
            std::fs::write(root.join("codex.cmd"), "@echo off\r\n").unwrap();
            std::fs::write(
                root.join("node_modules")
                    .join("@openai")
                    .join("codex")
                    .join("node_modules")
                    .join("@openai")
                    .join("codex-win32-x64")
                    .join("vendor")
                    .join("x86_64-pc-windows-msvc")
                    .join("codex")
                    .join("codex.exe"),
                "",
            )
            .unwrap();
            let old_path = std::env::var_os("PATH");
            let old_pathext = std::env::var_os("PATHEXT");
            std::env::set_var("PATH", root.to_string_lossy().to_string());
            std::env::set_var("PATHEXT", ".COM;.EXE;.BAT;.CMD");

            let (program, args) =
                resolved_command_parts(&AgentCommand::Args(vec!["codex".to_string()])).unwrap();

            let expected = root
                .join("node_modules")
                .join("@openai")
                .join("codex")
                .join("node_modules")
                .join("@openai")
                .join("codex-win32-x64")
                .join("vendor")
                .join("x86_64-pc-windows-msvc")
                .join("codex")
                .join("codex.exe");
            assert_eq!(program, expected.to_string_lossy());
            assert_eq!(
                args,
                Vec::<String>::new(),
                "codex shim should resolve directly to the native TUI binary"
            );

            if let Some(path) = old_path {
                std::env::set_var("PATH", path);
            } else {
                std::env::remove_var("PATH");
            }
            if let Some(pathext) = old_pathext {
                std::env::set_var("PATHEXT", pathext);
            } else {
                std::env::remove_var("PATHEXT");
            }
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn submit_sequence_text_supports_configured_variants() {
        assert_eq!(submit_sequence_text("control-m"), "\r");
        assert_eq!(submit_sequence_text("cr"), "\r");
        assert_eq!(submit_sequence_text("crlf"), "\r\n");
        assert_eq!(submit_sequence_text("lf"), "\n");
    }

    #[test]
    fn wraps_windows_cmd_shim_for_pty_spawn() {
        let (program, args) = adapt_windows_wrapper(
            r"C:\Users\ExampleUser\AppData\Roaming\npm\some-tool.cmd".to_string(),
            vec!["--no-alt-screen".to_string()],
        );

        if cfg!(windows) {
            assert_eq!(program, "cmd.exe");
            assert_eq!(
                args,
                vec![
                    "/d".to_string(),
                    "/c".to_string(),
                    r"C:\Users\ExampleUser\AppData\Roaming\npm\some-tool.cmd".to_string(),
                    "--no-alt-screen".to_string()
                ]
            );
        } else {
            assert_eq!(
                program,
                r"C:\Users\ExampleUser\AppData\Roaming\npm\some-tool.cmd"
            );
            assert_eq!(args, vec!["--no-alt-screen".to_string()]);
        }
    }

    #[test]
    fn unwraps_windows_codex_npm_shim_to_node_script() {
        #[cfg(windows)]
        {
            let root = std::env::temp_dir().join(format!("watchapi-test-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let npm = root.join("npm");
            std::fs::create_dir_all(
                npm.join("node_modules")
                    .join("@openai")
                    .join("codex")
                    .join("node_modules")
                    .join("@openai")
                    .join("codex-win32-x64")
                    .join("vendor")
                    .join("x86_64-pc-windows-msvc")
                    .join("codex"),
            )
            .unwrap();
            std::fs::write(npm.join("codex.cmd"), "@echo off").unwrap();
            std::fs::write(
                npm.join("node_modules")
                    .join("@openai")
                    .join("codex")
                    .join("node_modules")
                    .join("@openai")
                    .join("codex-win32-x64")
                    .join("vendor")
                    .join("x86_64-pc-windows-msvc")
                    .join("codex")
                    .join("codex.exe"),
                "",
            )
            .unwrap();

            let (program, args) = adapt_windows_wrapper(
                npm.join("codex.cmd").to_string_lossy().to_string(),
                vec!["--no-alt-screen".to_string(), "hi".to_string()],
            );
            assert_eq!(
                program,
                npm.join("node_modules")
                    .join("@openai")
                    .join("codex")
                    .join("node_modules")
                    .join("@openai")
                    .join("codex-win32-x64")
                    .join("vendor")
                    .join("x86_64-pc-windows-msvc")
                    .join("codex")
                    .join("codex.exe")
                    .to_string_lossy()
            );
            assert_eq!(args, vec!["--no-alt-screen".to_string(), "hi".to_string()]);
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn terminal_backend_has_no_native_console_compatibility_layer() {
        let source = include_str!("terminal.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("terminal production source should be discoverable");

        assert!(
            !production.contains("NativeConsole"),
            "终端后端应只走 PTY/ConPTY，不保留 Windows 原生控制台兼容层"
        );
        assert!(
            !production.contains("WATCHAPI_NATIVE_CONSOLE")
                && !production.contains("WATCHAPI_DISABLE_NATIVE_CONSOLE"),
            "不能再通过环境变量切回原生 cmd 窗口"
        );
        assert!(
            !production.contains("CreateProcessW")
                && !production.contains("ReadConsoleOutputCharacterW"),
            "不应再启动或读取真实 Windows 控制台窗口"
        );
    }
}
