use crate::atomic_write::write_text_atomic;
use crate::config::EndpointConfig;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const CODEX_UNATTENDED_MODEL_UPGRADES: &[&str] = &["gpt-5.4"];

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
            model: Some(&endpoint.model),
            reasoning_effort: Some(&endpoint.reasoning_effort),
            service_tier: endpoint.service_tier.as_deref(),
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
    pub model: Option<&'a str>,
    pub reasoning_effort: Option<&'a str>,
    pub service_tier: Option<&'a str>,
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
    if let Some(value) = values.sandbox_mode {
        set_top_level_assignment(&mut lines, "sandbox_mode", value);
    }
    if let Some(value) = values.approval_policy {
        set_top_level_assignment(&mut lines, "approval_policy", value);
    }

    let header = format!("[model_providers.{provider_name}]");
    let section_start =
        find_section(&lines, &header).ok_or_else(|| anyhow!("missing {header} section"))?;
    set_section_assignment(
        &mut lines,
        section_start,
        "base_url",
        &format!("\"{}\"", toml_string(values.base_url)),
    );
    set_section_assignment(&mut lines, section_start, "wire_api", "\"responses\"");
    set_section_assignment(&mut lines, section_start, "requires_openai_auth", "false");
    Ok(lines.concat())
}

fn set_top_level_assignment(lines: &mut Vec<String>, key: &str, value: &str) {
    let search_end = find_first_section(lines).unwrap_or(lines.len());
    for line in lines.iter_mut().take(search_end) {
        let trimmed = line.trim_start();
        if trimmed.starts_with(key) && trimmed[key.len()..].trim_start().starts_with('=') {
            let indent_len = line.len() - trimmed.len();
            let indent = &line[..indent_len];
            let newline = if line.ends_with('\n') { "\n" } else { "" };
            *line = format!("{indent}{key} = \"{}\"{newline}", toml_string(value));
            return;
        }
    }
    lines.insert(search_end, format!("{key} = \"{}\"\n", toml_string(value)));
}

fn set_optional_top_level_assignment(lines: &mut Vec<String>, key: &str, value: Option<&str>) {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        remove_top_level_assignment(lines, key);
        return;
    };
    set_top_level_assignment(lines, key, value);
}

fn remove_top_level_assignment(lines: &mut Vec<String>, key: &str) {
    let search_end = find_first_section(lines).unwrap_or(lines.len());
    if let Some(index) = lines.iter().take(search_end).position(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with(key) && trimmed[key.len()..].trim_start().starts_with('=')
    }) {
        lines.remove(index);
    }
}

fn set_section_assignment(lines: &mut Vec<String>, section_start: usize, key: &str, value: &str) {
    let section_end = find_section_end(lines, section_start + 1);
    for line in lines.iter_mut().take(section_end).skip(section_start + 1) {
        let trimmed = line.trim_start();
        if trimmed.starts_with(key) && trimmed[key.len()..].trim_start().starts_with('=') {
            let indent_len = line.len() - trimmed.len();
            let indent = &line[..indent_len];
            let newline = if line.ends_with('\n') { "\n" } else { "" };
            *line = format!("{indent}{key} = {value}{newline}");
            return;
        }
    }
    lines.insert(section_end, format!("{key} = {value}\n"));
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
