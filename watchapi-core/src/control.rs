use crate::atomic_write::write_text_atomic;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static CONTROL_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn control_file_lock() -> &'static Mutex<()> {
    CONTROL_FILE_LOCK.get_or_init(|| Mutex::new(()))
}

pub fn control_dir() -> PathBuf {
    let path = std::env::temp_dir().join("watchapi-control");
    let _ = fs::create_dir_all(&path);
    path
}

pub fn config_key(config_path: &Path) -> String {
    let normalized = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf())
        .to_string_lossy()
        .to_ascii_lowercase();
    let mut hasher = DefaultHasher::new();
    normalized.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

pub fn prompt_queue_path(config_path: &Path) -> PathBuf {
    control_dir().join(format!("{}-manual-prompts.jsonl", config_key(config_path)))
}

pub fn control_state_path(config_path: &Path) -> PathBuf {
    control_dir().join(format!("{}-state.json", config_key(config_path)))
}

pub fn enqueue_manual_prompt(config_path: &Path, prompt: &str) -> Result<()> {
    let text = prompt.trim();
    if text.is_empty() {
        return Err(anyhow!("manual prompt must not be empty"));
    }
    let item = json!({"created_at": now_seconds(), "prompt": text});
    let path = prompt_queue_path(config_path);
    let _guard = control_file_lock()
        .lock()
        .map_err(|_| anyhow!("control file lock poisoned"))?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", serde_json::to_string(&item)?)?;
    Ok(())
}

pub fn pop_manual_prompt(config_path: &Path) -> Option<String> {
    pop_manual_prompt_result(config_path).ok().flatten()
}

fn pop_manual_prompt_result(config_path: &Path) -> Result<Option<String>> {
    let path = prompt_queue_path(config_path);
    let _guard = control_file_lock()
        .lock()
        .map_err(|_| anyhow!("control file lock poisoned"))?;
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(None);
    };
    let mut prompts = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let Ok(item) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(prompt) = item
            .get("prompt")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|prompt| !prompt.is_empty())
        {
            prompts.push(prompt.to_string());
        }
    }
    if prompts.is_empty() {
        return Ok(None);
    }
    let mut prompts = prompts.into_iter();
    let Some(first) = prompts.next() else {
        return Ok(None);
    };
    let remaining = prompts
        .map(|prompt| json!({"created_at": now_seconds(), "prompt": prompt}).to_string())
        .collect::<Vec<_>>();
    write_text_atomic(
        &path,
        &if remaining.is_empty() {
            String::new()
        } else {
            remaining.join("\n") + "\n"
        },
    )?;
    Ok(Some(first))
}

pub fn read_control_state(config_path: &Path) -> Value {
    let path = control_state_path(config_path);
    let Ok(_guard) = control_file_lock().lock() else {
        return json!({});
    };
    read_control_state_file(&path)
}

fn read_control_state_file(path: &Path) -> Value {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

pub fn update_control_state(config_path: &Path, updates: &[(&str, Value)]) -> Result<Value> {
    let path = control_state_path(config_path);
    let _guard = control_file_lock()
        .lock()
        .map_err(|_| anyhow!("control file lock poisoned"))?;
    let mut state = read_control_state_file(&path);
    if !state.is_object() {
        state = json!({});
    }
    let Some(map) = state.as_object_mut() else {
        return Ok(state);
    };
    for (key, value) in updates {
        map.insert((*key).to_string(), value.clone());
    }
    write_text_atomic(&path, &(serde_json::to_string_pretty(&state)? + "\n"))?;
    Ok(state)
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_prompt_queue_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.json");

        enqueue_manual_prompt(&config, "first").unwrap();
        enqueue_manual_prompt(&config, "second").unwrap();

        assert_eq!(pop_manual_prompt(&config), Some("first".to_string()));
        assert_eq!(pop_manual_prompt(&config), Some("second".to_string()));
        assert_eq!(pop_manual_prompt(&config), None);
    }

    #[test]
    fn control_state_updates_json_object() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.json");

        update_control_state(&config, &[("auto_paused", json!(true))]).unwrap();

        assert_eq!(read_control_state(&config)["auto_paused"], true);
    }

    #[test]
    fn control_state_concurrent_updates_preserve_independent_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.json");
        let left = config.clone();
        let right = config.clone();

        let a = std::thread::spawn(move || {
            for index in 0..50 {
                update_control_state(&left, &[("left", json!(index))]).unwrap();
            }
        });
        let b = std::thread::spawn(move || {
            for index in 0..50 {
                update_control_state(&right, &[("right", json!(index))]).unwrap();
            }
        });

        a.join().unwrap();
        b.join().unwrap();
        let state = read_control_state(&config);

        assert!(state.get("left").is_some());
        assert!(state.get("right").is_some());
    }

    #[test]
    fn manual_prompt_queue_concurrent_appends_are_not_lost() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.json");
        let left = config.clone();
        let right = config.clone();

        let a = std::thread::spawn(move || {
            for index in 0..25 {
                enqueue_manual_prompt(&left, &format!("left-{index}")).unwrap();
            }
        });
        let b = std::thread::spawn(move || {
            for index in 0..25 {
                enqueue_manual_prompt(&right, &format!("right-{index}")).unwrap();
            }
        });

        a.join().unwrap();
        b.join().unwrap();
        let mut count = 0;
        while pop_manual_prompt(&config).is_some() {
            count += 1;
        }

        assert_eq!(count, 50);
    }

    #[test]
    fn manual_prompt_pop_does_not_ignore_queue_rewrite_errors() {
        let source = include_str!("control.rs");
        let block = source
            .split("fn pop_manual_prompt_result")
            .nth(1)
            .and_then(|tail| tail.split("pub fn read_control_state").next())
            .expect("manual prompt pop helper should be discoverable");

        assert!(block.contains("write_text_atomic("));
        assert!(block.contains(")?;"));
        assert!(!block.contains("let _ = write_text_atomic"));
    }
}
