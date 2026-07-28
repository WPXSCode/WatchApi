use crate::atomic_write::write_text_atomic;
use crate::config::EndpointConfig;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const CODEX_UNATTENDED_MODEL_UPGRADES: &[&str] = &["gpt-5.4"];
const CODEX_DEFAULT_STATUS_LINE: &str = "true";
const CODEX_DEFAULT_STATUS_LINE_USE_COLORS: &str = "true";
const CODEX_DEFAULT_TUI_STATUS_LINE_ITEMS: &str =
    concat!(
        "[\"model-with-reasoning\", \"context-window\", \"context-remaining\", \"current-dir\", \"git-branch\", \"context-used\", \"run-state\", \"task-progress\", \"used-",
        "to",
        "kens\", \"fast-mode\"]"
    );
const CODEX_DEFAULT_TUI_SHOW_TOOLTIPS: &str = "true";
const CODEX_DEFAULT_TUI_ANIMATIONS: &str = "true";
const CODEX_DEFAULT_TUI_RAW_OUTPUT_MODE: &str = "false";

pub struct CodexConfigBackup {
    state_path: PathBuf,
    captured: bool,
}

impl CodexConfigBackup {
    pub fn new(state_path: PathBuf) -> Self {
        Self {
            state_path,
            captured: false,
        }
    }

    pub fn restore_pending(&mut self) -> Result<()> {
        if self.state_path.exists() {
            self.restore()?;
        }
        Ok(())
    }

    pub fn capture(&mut self, files: &[(PathBuf, String)]) -> Result<()> {
        if self.captured {
            return Ok(());
        }
        self.restore_pending()?;
        let mut entries = Vec::new();
        for (path, label) in files {
            let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
            let exists = resolved.exists();
            entries.push(json!({
                "label": label,
                "path": resolved.to_string_lossy(),
                "exists": exists,
                "content": if exists { Some(fs::read_to_string(&resolved)?) } else { None },
            }));
        }
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_text_atomic(
            &self.state_path,
            &(serde_json::to_string_pretty(&json!({"version": 1, "files": entries}))? + "\n"),
        )?;
        self.captured = true;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        let Ok(text) = fs::read_to_string(&self.state_path) else {
            self.captured = false;
            return Ok(());
        };
        let Ok(payload) = serde_json::from_str::<Value>(&text) else {
            self.captured = false;
            let _ = fs::remove_file(&self.state_path);
            return Ok(());
        };
        if let Some(files) = payload.get("files").and_then(Value::as_array) {
            for item in files {
                let Some(path) = item
                    .get("path")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                let path = PathBuf::from(path);
                let existed = item.get("exists").and_then(Value::as_bool).unwrap_or(false);
                if existed {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    write_text_atomic(
                        &path,
                        item.get("content").and_then(Value::as_str).unwrap_or(""),
                    )?;
                } else {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        let _ = fs::remove_file(&self.state_path);
        self.captured = false;
        Ok(())
    }
}

pub fn ensure_codex_permission_config(config_path: &Path) -> Result<()> {
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let config_text = fs::read_to_string(config_path).unwrap_or_default();
    let updated =
        set_top_level_codex_config_values(&config_text, Some("danger-full-access"), Some("never"));
    if updated != config_text {
        write_text_atomic(config_path, &updated)?;
    }
    Ok(())
}

pub fn ensure_codex_unattended_state(codex_home: &Path) -> Result<()> {
    let state_path = codex_home.join(".codex-global-state.json");
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut state: Value = fs::read_to_string(&state_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| json!({}));
    if !state.is_object() {
        state = json!({});
    }
    let Some(object) = state.as_object_mut() else {
        return Ok(());
    };
    let atom_state = object
        .entry("electron-persisted-atom-state")
        .or_insert_with(|| json!({}));
    if !atom_state.is_object() {
        *atom_state = json!({});
    }
    let Some(atom) = atom_state.as_object_mut() else {
        return Ok(());
    };
    let seen = atom
        .entry("seen-model-upgrade-list")
        .or_insert_with(|| json!([]));
    if !seen.is_array() {
        *seen = json!([]);
    }
    let Some(seen_items) = seen.as_array_mut() else {
        return Ok(());
    };
    for model in CODEX_UNATTENDED_MODEL_UPGRADES {
        if !seen_items.iter().any(|item| item.as_str() == Some(model)) {
            seen_items.push(json!(model));
        }
    }
    atom.insert("skip-full-access-confirm".to_string(), json!(true));
    write_text_atomic(&state_path, &(serde_json::to_string(&state)? + "\n"))?;
    Ok(())
}

pub fn apply_codex_endpoint(
    endpoint: &EndpointConfig,
    config_path: &Path,
    auth_path: &Path,
    provider_name: &str,
) -> Result<()> {
    apply_codex_endpoint_with_model_context_window(
        endpoint,
        config_path,
        auth_path,
        provider_name,
        None,
    )
}

pub fn apply_codex_endpoint_with_model_context_window(
    endpoint: &EndpointConfig,
    config_path: &Path,
    auth_path: &Path,
    provider_name: &str,
    model_context_window: Option<usize>,
) -> Result<()> {
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = auth_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let config_text = fs::read_to_string(config_path).unwrap_or_else(|_| {
        format!(
            "model_provider = \"{}\"\n[model_providers.{}]\nbase_url = \"\"\n",
            toml_string(provider_name),
            provider_name
        )
    });
    let effective_provider_name = get_current_model_provider(&config_text)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| provider_name.to_string());
    let updated = set_codex_config_values(
        &config_text,
        &effective_provider_name,
        CodexConfigValues {
            base_url: &endpoint.base_url,
            api_key: &endpoint.api_key,
            model: Some(&endpoint.model),
            reasoning_effort: Some(&endpoint.reasoning_effort),
            service_tier: endpoint.service_tier.as_deref(),
            model_context_window,
            sandbox_mode: Some("danger-full-access"),
            approval_policy: Some("never"),
        },
    )?;
    write_text_atomic(config_path, &updated)?;

    let mut auth: Value = fs::read_to_string(auth_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    let Some(map) = auth.as_object_mut() else {
        return Err(anyhow!(
            "{} must contain a JSON object",
            auth_path.display()
        ));
    };
    map.insert(
        "OPENAI_API_KEY".to_string(),
        Value::String(endpoint.api_key.clone()),
    );
    write_text_atomic(auth_path, &(serde_json::to_string_pretty(&auth)? + "\n"))?;
    Ok(())
}

pub fn get_current_model_provider(config_text: &str) -> Option<String> {
    let lines: Vec<&str> = config_text.lines().collect();
    let search_end = find_first_section(&lines).unwrap_or(lines.len());
    for line in lines.iter().take(search_end) {
        let trimmed = line.trim();
        if !trimmed.starts_with("model_provider") {
            continue;
        }
        let value = quoted_assignment_value(trimmed)?;
        return Some(value);
    }
    None
}

pub fn set_top_level_codex_config_values(
    config_text: &str,
    sandbox_mode: Option<&str>,
    approval_policy: Option<&str>,
) -> String {
    let mut lines = split_keep_newlines(config_text);
    if let Some(value) = sandbox_mode {
        set_top_level_assignment(&mut lines, "sandbox_mode", value);
    }
    if let Some(value) = approval_policy {
        set_top_level_assignment(&mut lines, "approval_policy", value);
    }
    lines.concat()
}

pub struct CodexConfigValues<'a> {
    pub base_url: &'a str,
    pub api_key: &'a str,
    pub model: Option<&'a str>,
    pub reasoning_effort: Option<&'a str>,
    pub service_tier: Option<&'a str>,
    pub model_context_window: Option<usize>,
    pub sandbox_mode: Option<&'a str>,
    pub approval_policy: Option<&'a str>,
}

pub fn set_codex_config_values(
    config_text: &str,
    provider_name: &str,
    values: CodexConfigValues<'_>,
) -> Result<String> {
    let mut lines = split_keep_newlines(config_text);
    if let Some(value) = values.model {
        set_top_level_assignment(&mut lines, "model", value);
    }
    if let Some(value) = values.reasoning_effort {
        set_top_level_assignment(&mut lines, "model_reasoning_effort", value);
    }
    set_optional_top_level_assignment(&mut lines, "service_tier", values.service_tier);
    set_optional_top_level_usize_assignment(
        &mut lines,
        "model_context_window",
        values.model_context_window,
    );
    if let Some(value) = values.sandbox_mode {
        set_top_level_assignment(&mut lines, "sandbox_mode", value);
    }
    if let Some(value) = values.approval_policy {
        set_top_level_assignment(&mut lines, "approval_policy", value);
    }
    force_codex_tui_status_values(&mut lines);

    let header = format!("[model_providers.{provider_name}]");
    let section_start = find_or_insert_section(&mut lines, &header);
    set_section_assignment(
        &mut lines,
        section_start,
        "base_url",
        &format!("\"{}\"", toml_string(values.base_url)),
    );
    set_section_assignment(
        &mut lines,
        section_start,
        "experimental_bearer_token",
        &format!("\"{}\"", toml_string(values.api_key)),
    );
    set_section_assignment(&mut lines, section_start, "wire_api", "\"responses\"");
    set_section_assignment(&mut lines, section_start, "requires_openai_auth", "false");
    Ok(lines.concat())
}

fn force_codex_tui_status_values(lines: &mut Vec<String>) {
    set_top_level_raw_assignment(lines, "status_line", CODEX_DEFAULT_STATUS_LINE);
    set_top_level_raw_assignment(
        lines,
        "status_line_use_colors",
        CODEX_DEFAULT_STATUS_LINE_USE_COLORS,
    );

    let section_start = find_or_insert_section(lines, "[tui]");
    set_section_assignment(
        lines,
        section_start,
        "status_line",
        CODEX_DEFAULT_TUI_STATUS_LINE_ITEMS,
    );
    set_section_assignment(
        lines,
        section_start,
        "show_tooltips",
        CODEX_DEFAULT_TUI_SHOW_TOOLTIPS,
    );
    set_section_assignment(
        lines,
        section_start,
        "animations",
        CODEX_DEFAULT_TUI_ANIMATIONS,
    );
    set_section_assignment(
        lines,
        section_start,
        "raw_output_mode",
        CODEX_DEFAULT_TUI_RAW_OUTPUT_MODE,
    );
}

fn set_top_level_raw_assignment(lines: &mut Vec<String>, name: &str, value: &str) {
    let search_end = find_first_section(lines).unwrap_or(lines.len());
    if set_assignment_in_range(lines, 0, search_end, name, value) {
        return;
    }
    lines.insert(search_end, format!("{name} = {value}\n"));
}

fn find_or_insert_section(lines: &mut Vec<String>, header: &str) -> usize {
    if let Some(index) = find_section(lines, header) {
        merge_duplicate_sections(lines, header, index);
        return index;
    }
    if let Some(prefix) = nested_section_prefix(header) {
        if let Some(index) = find_first_nested_section(lines, &prefix) {
            lines.insert(index, format!("{header}\n"));
            return index;
        }
    }
    if lines.last().is_some_and(|line| !line.ends_with('\n')) {
        lines.push("\n".to_string());
    }
    if lines.last().is_some_and(|line| !line.trim().is_empty()) {
        lines.push("\n".to_string());
    }
    let index = lines.len();
    lines.push(format!("{header}\n"));
    index
}

fn merge_duplicate_sections(lines: &mut Vec<String>, header: &str, keep_start: usize) {
    let duplicate_ranges = duplicate_section_ranges(lines, header, keep_start);
    if duplicate_ranges.is_empty() {
        return;
    }
    let duplicate_bodies = duplicate_ranges
        .iter()
        .map(|(start, end)| lines[start + 1..*end].to_vec())
        .collect::<Vec<_>>();
    for (start, end) in duplicate_ranges.into_iter().rev() {
        lines.drain(start..end);
    }

    let mut seen_keys = section_assignment_keys(lines, keep_start);
    for body in duplicate_bodies {
        for mut line in body {
            let Some(key) = assignment_key(&line) else {
                continue;
            };
            if !seen_keys.insert(key) {
                continue;
            }
            if !line.ends_with('\n') {
                line.push('\n');
            }
            let insert_at = find_section_end(lines, keep_start + 1);
            lines.insert(insert_at, line);
        }
    }
}

fn duplicate_section_ranges(
    lines: &[String],
    header: &str,
    keep_start: usize,
) -> Vec<(usize, usize)> {
    lines
        .iter()
        .enumerate()
        .skip(keep_start + 1)
        .filter(|(_, line)| line.trim() == header)
        .map(|(index, _)| (index, find_section_end(lines, index + 1)))
        .collect()
}

fn section_assignment_keys(lines: &[String], section_start: usize) -> HashSet<String> {
    let section_end = find_section_end(lines, section_start + 1);
    lines[section_start + 1..section_end]
        .iter()
        .filter_map(|line| assignment_key(line))
        .collect()
}

fn assignment_key(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return None;
    }
    let (key, _) = trimmed.split_once('=')?;
    let key = key.trim();
    (!key.is_empty() && !key.starts_with('[')).then(|| key.to_string())
}

fn nested_section_prefix(header: &str) -> Option<String> {
    header
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .filter(|value| !value.is_empty())
        .map(|value| format!("[{value}."))
}

fn find_first_nested_section(lines: &[String], prefix: &str) -> Option<usize> {
    lines.iter().position(|line| {
        let trimmed = line.trim();
        trimmed.starts_with(prefix) && trimmed.ends_with(']')
    })
}
fn set_top_level_assignment(lines: &mut Vec<String>, key: &str, value: &str) {
    let search_end = find_first_section(lines).unwrap_or(lines.len());
    let value = format!("\"{}\"", toml_string(value));
    if set_assignment_in_range(lines, 0, search_end, key, &value) {
        return;
    }
    lines.insert(search_end, format!("{key} = {value}\n"));
}

fn set_optional_top_level_assignment(lines: &mut Vec<String>, key: &str, value: Option<&str>) {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        remove_top_level_assignment(lines, key);
        return;
    };
    set_top_level_assignment(lines, key, value);
}

fn set_optional_top_level_usize_assignment(
    lines: &mut Vec<String>,
    key: &str,
    value: Option<usize>,
) {
    let Some(value) = value else {
        remove_top_level_assignment(lines, key);
        return;
    };
    set_top_level_raw_assignment(lines, key, &value.to_string());
}

fn remove_top_level_assignment(lines: &mut Vec<String>, key: &str) {
    let search_end = find_first_section(lines).unwrap_or(lines.len());
    for index in matching_assignment_indexes(lines, 0, search_end, key)
        .into_iter()
        .rev()
    {
        lines.remove(index);
    }
}

fn set_section_assignment(lines: &mut Vec<String>, section_start: usize, key: &str, value: &str) {
    let section_end = find_section_end(lines, section_start + 1);
    if set_assignment_in_range(lines, section_start + 1, section_end, key, value) {
        return;
    }
    lines.insert(section_end, format!("{key} = {value}\n"));
}

fn set_assignment_in_range(
    lines: &mut Vec<String>,
    start: usize,
    end: usize,
    key: &str,
    value: &str,
) -> bool {
    let matches = matching_assignment_indexes(lines, start, end, key);
    let Some(first) = matches.first().copied() else {
        return false;
    };
    lines[first] = format_assignment_like(&lines[first], key, value);
    for index in matches.into_iter().skip(1).rev() {
        lines.remove(index);
    }
    true
}

fn matching_assignment_indexes(
    lines: &[String],
    start: usize,
    end: usize,
    key: &str,
) -> Vec<usize> {
    lines
        .iter()
        .enumerate()
        .take(end)
        .skip(start)
        .filter_map(|(index, line)| assignment_matches(line, key).then_some(index))
        .collect()
}

fn assignment_matches(line: &str, key: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with(key) && trimmed[key.len()..].trim_start().starts_with('=')
}

fn format_assignment_like(line: &str, key: &str, value: &str) -> String {
    let trimmed = line.trim_start();
    let indent_len = line.len() - trimmed.len();
    let indent = &line[..indent_len];
    let newline = if line.ends_with('\n') { "\n" } else { "" };
    format!("{indent}{key} = {value}{newline}")
}

fn split_keep_newlines(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    text.split_inclusive('\n').map(str::to_string).collect()
}

fn find_first_section<T: AsRef<str>>(lines: &[T]) -> Option<usize> {
    lines.iter().position(|line| {
        let trimmed = line.as_ref().trim();
        trimmed.starts_with('[') && trimmed.ends_with(']')
    })
}

fn find_section<T: AsRef<str>>(lines: &[T], header: &str) -> Option<usize> {
    lines.iter().position(|line| line.as_ref().trim() == header)
}

fn find_section_end<T: AsRef<str>>(lines: &[T], start: usize) -> usize {
    lines
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, line)| {
            let trimmed = line.as_ref().trim();
            (trimmed.starts_with('[') && trimmed.ends_with(']')).then_some(index)
        })
        .unwrap_or(lines.len())
}

fn quoted_assignment_value(line: &str) -> Option<String> {
    let value = line.split_once('=')?.1.trim();
    let inner = value.strip_prefix('"')?.split('"').next()?;
    Some(inner.trim().to_string())
}

fn toml_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn endpoint() -> EndpointConfig {
        EndpointConfig {
            name: "primary".to_string(),
            base_url: "https://new.example.test".to_string(),
            api_key: "new-key".to_string(),
            model: "new-model".to_string(),
            probe_model: None,
            reasoning_effort: "high".to_string(),
            service_tier: Some("fast".to_string()),
            initial_prompt: "bootstrap".to_string(),
            auto_prompt: "continue".to_string(),
            workdir: PathBuf::from("."),
            weight: 100,
            enabled: true,
            probe_url: None,
            guard_proxy: Default::default(),
        }
    }

    #[test]
    fn config_backup_restores_original_files() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");
        let state_path = tmp.path().join("backup.json");
        fs::write(&config_path, "original config").unwrap();
        fs::write(&auth_path, "original auth").unwrap();
        let mut backup = CodexConfigBackup::new(state_path.clone());

        backup
            .capture(&[
                (config_path.clone(), "config".to_string()),
                (auth_path.clone(), "auth".to_string()),
            ])
            .unwrap();
        fs::write(&config_path, "changed config").unwrap();
        fs::write(&auth_path, "changed auth").unwrap();
        backup.restore().unwrap();

        assert_eq!(fs::read_to_string(config_path).unwrap(), "original config");
        assert_eq!(fs::read_to_string(auth_path).unwrap(), "original auth");
        assert!(!state_path.exists());
    }

    #[test]
    fn apply_codex_endpoint_updates_current_provider_and_key() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");
        fs::write(
            &config_path,
            [
                "model_provider = \"openrouter\"",
                "[model_providers.custom]",
                "base_url = \"https://custom.example.test\"",
                "",
                "[model_providers.openrouter]",
                "base_url = \"https://old.example.test\"",
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        fs::write(
            &auth_path,
            json!({"OPENAI_API_KEY": "old-key", "OTHER": "keep"}).to_string(),
        )
        .unwrap();

        apply_codex_endpoint(&endpoint(), &config_path, &auth_path, "custom").unwrap();

        let config_text = fs::read_to_string(config_path).unwrap();
        let auth: Value = serde_json::from_str(&fs::read_to_string(auth_path).unwrap()).unwrap();
        assert!(config_text.contains("base_url = \"https://custom.example.test\""));
        assert!(config_text.contains("base_url = \"https://new.example.test\""));
        assert!(config_text.contains("wire_api = \"responses\""));
        assert!(config_text.contains("service_tier = \"fast\""));
        assert!(config_text.contains("requires_openai_auth = false"));
        assert!(config_text.contains("sandbox_mode = \"danger-full-access\""));
        assert!(config_text.contains("approval_policy = \"never\""));
        assert_eq!(auth["OPENAI_API_KEY"], "new-key");
        assert_eq!(auth["OTHER"], "keep");
    }

    #[test]
    fn apply_codex_endpoint_adds_codex_tui_status_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");
        fs::write(
            &config_path,
            [
                "model_provider = \"custom\"",
                "[model_providers.custom]",
                "base_url = \"https://old.example.test\"",
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        apply_codex_endpoint(&endpoint(), &config_path, &auth_path, "custom").unwrap();

        let config_text = fs::read_to_string(config_path).unwrap();
        assert!(config_text.contains("status_line = true"));
        assert!(config_text.contains("status_line_use_colors = true"));
        assert!(config_text.contains("[tui]"));
        assert!(config_text.contains(&format!(
            "status_line = {CODEX_DEFAULT_TUI_STATUS_LINE_ITEMS}"
        )));
        assert!(config_text.contains("show_tooltips = true"));
        assert!(config_text.contains("animations = true"));
        assert!(config_text.contains("raw_output_mode = false"));
    }

    #[test]
    fn apply_codex_endpoint_forces_codex_tui_status_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");
        fs::write(
            &config_path,
            [
                "status_line = false",
                "status_line_use_colors = false",
                "model_provider = \"custom\"",
                "[tui]",
                "show_tooltips = false",
                "animations = false",
                "raw_output_mode = true",
                "status_line = [\"current-dir\"]",
                "",
                "[model_providers.custom]",
                "base_url = \"https://old.example.test\"",
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        apply_codex_endpoint(&endpoint(), &config_path, &auth_path, "custom").unwrap();

        let config_text = fs::read_to_string(config_path).unwrap();
        assert!(config_text.contains("status_line = true"));
        assert!(config_text.contains("status_line_use_colors = true"));
        assert!(config_text.contains(&format!(
            "status_line = {CODEX_DEFAULT_TUI_STATUS_LINE_ITEMS}"
        )));
        assert!(config_text.contains("show_tooltips = true"));
        assert!(config_text.contains("animations = true"));
        assert!(config_text.contains("raw_output_mode = false"));
        assert!(!config_text.contains("status_line = false"));
        assert!(!config_text.contains("status_line_use_colors = false"));
        assert!(!config_text.contains("show_tooltips = false"));
        assert!(!config_text.contains("animations = false"));
        assert!(!config_text.contains("raw_output_mode = true"));
        assert!(!config_text.contains("status_line = [\"current-dir\"]"));
    }

    #[test]
    fn apply_codex_endpoint_deduplicates_codex_tui_status_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");
        fs::write(
            &config_path,
            [
                "status_line = false",
                "status_line = false",
                "status_line_use_colors = false",
                "status_line_use_colors = false",
                "model_provider = \"custom\"",
                "[tui]",
                "status_line = [\"current-dir\"]",
                "show_tooltips = false",
                "animations = false",
                "raw_output_mode = true",
                "status_line = [\"git-branch\"]",
                "show_tooltips = false",
                "animations = false",
                "raw_output_mode = true",
                "",
                "[model_providers.custom]",
                "base_url = \"https://old.example.test\"",
                "base_url = \"https://stale.example.test\"",
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        apply_codex_endpoint(&endpoint(), &config_path, &auth_path, "custom").unwrap();

        let config_text = fs::read_to_string(config_path).unwrap();
        assert_eq!(config_text.matches("status_line = true").count(), 1);
        assert_eq!(
            config_text.matches("status_line_use_colors = true").count(),
            1
        );
        assert_eq!(
            config_text
                .matches(&format!(
                    "status_line = {CODEX_DEFAULT_TUI_STATUS_LINE_ITEMS}"
                ))
                .count(),
            1
        );
        assert_eq!(config_text.matches("show_tooltips = true").count(), 1);
        assert_eq!(config_text.matches("animations = true").count(), 1);
        assert_eq!(config_text.matches("raw_output_mode = false").count(), 1);
        assert_eq!(
            config_text
                .matches("base_url = \"https://new.example.test\"")
                .count(),
            1
        );
        assert!(!config_text.contains("status_line = false"));
        assert!(!config_text.contains("status_line_use_colors = false"));
        assert!(!config_text.contains("status_line = [\"current-dir\"]"));
        assert!(!config_text.contains("status_line = [\"git-branch\"]"));
        assert!(!config_text.contains("show_tooltips = false"));
        assert!(!config_text.contains("animations = false"));
        assert!(!config_text.contains("raw_output_mode = true"));
        assert!(!config_text.contains("https://old.example.test"));
        assert!(!config_text.contains("https://stale.example.test"));
    }

    #[test]
    fn apply_codex_endpoint_merges_duplicate_sections_before_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");
        fs::write(
            &config_path,
            [
                "model_provider = \"custom\"",
                "[tui]",
                "show_tooltips = false",
                "",
                "[tui]",
                "theme = \"compact\"",
                "status_line = [\"stale\"]",
                "",
                "[model_providers.custom]",
                "base_url = \"https://old.example.test\"",
                "extra_first = \"keep\"",
                "",
                "[model_providers.custom]",
                "base_url = \"https://stale.example.test\"",
                "extra_second = \"keep\"",
                "",
                "[model_providers.other]",
                "base_url = \"https://other.example.test\"",
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        apply_codex_endpoint(&endpoint(), &config_path, &auth_path, "custom").unwrap();

        let config_text = fs::read_to_string(config_path).unwrap();
        assert_eq!(
            config_text
                .lines()
                .filter(|line| line.trim() == "[tui]")
                .count(),
            1
        );
        assert_eq!(
            config_text
                .lines()
                .filter(|line| line.trim() == "[model_providers.custom]")
                .count(),
            1
        );
        assert!(config_text.contains("theme = \"compact\""));
        assert!(config_text.contains("extra_first = \"keep\""));
        assert!(config_text.contains("extra_second = \"keep\""));
        assert!(config_text.contains("[model_providers.other]"));
        assert!(config_text.contains("base_url = \"https://other.example.test\""));
        assert_eq!(
            config_text
                .matches("base_url = \"https://new.example.test\"")
                .count(),
            1
        );
        assert!(!config_text.contains("https://old.example.test"));
        assert!(!config_text.contains("https://stale.example.test"));
        assert!(!config_text.contains("status_line = [\"stale\"]"));
    }

    #[test]
    fn apply_codex_endpoint_inserts_tui_parent_before_nested_tui_sections() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");
        fs::write(
            &config_path,
            [
                "model_provider = \"custom\"",
                "[tui.model_availability_nux]",
                "\"gpt-5.5\" = 4",
                "",
                "[model_providers.custom]",
                "base_url = \"old\"",
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        apply_codex_endpoint(&endpoint(), &config_path, &auth_path, "custom").unwrap();

        let config_text = fs::read_to_string(config_path).unwrap();
        let tui_pos = config_text.find("[tui]\n").unwrap();
        let nested_pos = config_text.find("[tui.model_availability_nux]").unwrap();
        assert!(tui_pos < nested_pos);
        assert!(config_text.contains(&format!(
            "status_line = {CODEX_DEFAULT_TUI_STATUS_LINE_ITEMS}"
        )));
        assert!(config_text.contains("\"gpt-5.5\" = 4"));
    }

    #[test]
    fn apply_codex_endpoint_replaces_current_provider_bearer_token() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");
        fs::write(
            &config_path,
            [
                "model_provider = \"custom\"",
                "[model_providers.custom]",
                "base_url = \"https://old.example.test\"",
                "experimental_bearer_token = \"old-key\"",
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        apply_codex_endpoint(&endpoint(), &config_path, &auth_path, "custom").unwrap();

        let config_text = fs::read_to_string(config_path).unwrap();
        assert!(config_text.contains("experimental_bearer_token = \"new-key\""));
        assert!(!config_text.contains("experimental_bearer_token = \"old-key\""));
    }

    #[test]
    fn apply_codex_endpoint_creates_missing_current_provider_section() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");
        let endpoint = endpoint();
        fs::write(
            &config_path,
            [
                "model_provider = \"stale\"",
                "[model_providers.custom]",
                "base_url = \"old-base\"",
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        apply_codex_endpoint(&endpoint, &config_path, &auth_path, "custom").unwrap();

        let config_text = fs::read_to_string(config_path).unwrap();
        assert!(config_text.contains("[model_providers.stale]"));
        assert!(config_text.contains(&format!("base_url = \"{}\"", endpoint.base_url)));
        assert!(config_text.contains("experimental_bearer_token = \"new-key\""));
        assert!(config_text.contains("wire_api = \"responses\""));
        assert!(config_text.contains("requires_openai_auth = false"));
    }

    #[test]
    fn apply_codex_endpoint_bootstraps_missing_files() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("nested/config.toml");
        let auth_path = tmp.path().join("nested/auth.json");

        apply_codex_endpoint(&endpoint(), &config_path, &auth_path, "custom").unwrap();

        let config_text = fs::read_to_string(config_path).unwrap();
        let auth: Value = serde_json::from_str(&fs::read_to_string(auth_path).unwrap()).unwrap();
        assert!(config_text.contains("model_provider = \"custom\""));
        assert!(config_text.contains("wire_api = \"responses\""));
        assert!(config_text.contains("requires_openai_auth = false"));
        assert_eq!(auth["OPENAI_API_KEY"], "new-key");
    }

    #[test]
    fn apply_codex_endpoint_replaces_chatgpt_auth_for_custom_provider() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");
        fs::write(
            &config_path,
            [
                "model_provider = \"custom\"",
                "[model_providers.custom]",
                "base_url = \"https://old.example.test\"",
                "wire_api = \"chat\"",
                "requires_openai_auth = true",
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();

        apply_codex_endpoint(&endpoint(), &config_path, &auth_path, "custom").unwrap();

        let config_text = fs::read_to_string(config_path).unwrap();
        assert!(config_text.contains("base_url = \"https://new.example.test\""));
        assert!(config_text.contains("wire_api = \"responses\""));
        assert!(config_text.contains("requires_openai_auth = false"));
    }

    #[test]
    fn apply_codex_endpoint_can_write_and_clear_model_context_window() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let auth_path = tmp.path().join("auth.json");

        apply_codex_endpoint_with_model_context_window(
            &endpoint(),
            &config_path,
            &auth_path,
            "custom",
            Some(128000),
        )
        .unwrap();

        let config_text = fs::read_to_string(&config_path).unwrap();
        assert!(config_text.contains("model_context_window = 128000"));

        apply_codex_endpoint_with_model_context_window(
            &endpoint(),
            &config_path,
            &auth_path,
            "custom",
            None,
        )
        .unwrap();

        let cleared = fs::read_to_string(&config_path).unwrap();
        assert!(!cleared.contains("model_context_window = 128000"));
        assert!(!cleared.contains("model_context_window = "));
    }

    #[test]
    fn ensure_permission_config_adds_top_level_values_before_sections() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        fs::write(
            &config_path,
            "[model_providers.custom]\nbase_url = \"https://example.test\"\n",
        )
        .unwrap();

        ensure_codex_permission_config(&config_path).unwrap();

        let text = fs::read_to_string(config_path).unwrap();
        assert!(text.contains("sandbox_mode = \"danger-full-access\""));
        assert!(text.contains("approval_policy = \"never\""));
        assert!(
            text.find("sandbox_mode").unwrap() < text.find("[model_providers.custom]").unwrap()
        );
    }

    #[test]
    fn ensure_unattended_state_marks_upgrade_seen() {
        let tmp = tempfile::tempdir().unwrap();

        ensure_codex_unattended_state(tmp.path()).unwrap();

        let state: Value = serde_json::from_str(
            &fs::read_to_string(tmp.path().join(".codex-global-state.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            state["electron-persisted-atom-state"]["skip-full-access-confirm"],
            true
        );
        assert!(
            state["electron-persisted-atom-state"]["seen-model-upgrade-list"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str() == Some("gpt-5.4"))
        );
    }
}
