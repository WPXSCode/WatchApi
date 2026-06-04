use crate::atomic_write::write_text_atomic;
use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST,
    TRANSFER_ENCODING,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::time;
use url::Url;
use wreq::{Client as EmulatedClient, Proxy as EmulatedProxy};
use wreq_util::Emulation;

use crate::guard_proxy::{
    responses_api_stream_requires_completed, GUARD_STREAM_HEARTBEAT_INTERVAL,
    GUARD_UPSTREAM_CONNECT_TIMEOUT, GUARD_UPSTREAM_TOTAL_TIMEOUT,
};

const MIN_KEY_EXPLORATION_REQUESTS: u64 = 2;
const MIN_FINGERPRINT_EXPLORATION_REQUESTS: u64 = 2;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AggregateFingerprint {
    Chrome132,
    Chrome133,
    Chrome134,
    Chrome135,
    Chrome136,
    Chrome137,
    Edge131,
    Edge134,
    Edge135,
    Edge136,
    Edge137,
    Firefox128,
    Firefox133,
    Firefox135,
    Firefox136,
    Firefox139,
}

impl AggregateFingerprint {
    fn emulation(self) -> Emulation {
        match self {
            Self::Chrome132 => Emulation::Chrome132,
            Self::Chrome133 => Emulation::Chrome133,
            Self::Chrome134 => Emulation::Chrome134,
            Self::Chrome135 => Emulation::Chrome135,
            Self::Chrome136 => Emulation::Chrome136,
            Self::Chrome137 => Emulation::Chrome137,
            Self::Edge131 => Emulation::Edge131,
            Self::Edge134 => Emulation::Edge134,
            Self::Edge135 => Emulation::Edge135,
            Self::Edge136 => Emulation::Edge136,
            Self::Edge137 => Emulation::Edge137,
            Self::Firefox128 => Emulation::Firefox128,
            Self::Firefox133 => Emulation::Firefox133,
            Self::Firefox135 => Emulation::Firefox135,
            Self::Firefox136 => Emulation::Firefox136,
            Self::Firefox139 => Emulation::Firefox139,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregateEgressConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_enabled_fingerprints")]
    pub fingerprints: Vec<AggregateFingerprint>,
    #[serde(default = "default_recent_fingerprint_window")]
    pub recent_fingerprint_window: u32,
    #[serde(default = "default_recent_fingerprint_ttl_seconds")]
    pub recent_fingerprint_ttl_seconds: u32,
}

impl Default for AggregateEgressConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fingerprints: default_enabled_fingerprints(),
            recent_fingerprint_window: default_recent_fingerprint_window(),
            recent_fingerprint_ttl_seconds: default_recent_fingerprint_ttl_seconds(),
        }
    }
}

impl AggregateEgressConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.fingerprints.is_empty() {
            return Err(anyhow!("共享最终出口已启用，但指纹池为空"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AggregateDeploymentSeed {
    pub upstream: String,
    pub base_url: String,
    pub public_model: String,
    pub actual_model: String,
    pub max_qps: Option<u32>,
    pub max_rpm: Option<u32>,
    pub max_concurrency: u32,
    pub upstream_cooldown_seconds: Option<u32>,
    pub egress_note: String,
    pub key: String,
    pub key_label: String,
    pub quality_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregateClashConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_clash_controller_url")]
    pub controller_url: String,
    #[serde(default = "default_clash_proxy_url")]
    pub proxy_url: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub group_name: String,
    #[serde(default = "default_ip_switch_cooldown_seconds")]
    pub ip_switch_cooldown_seconds: u32,
    #[serde(default = "default_recent_node_window")]
    pub recent_node_window: u32,
    #[serde(default = "default_recent_node_ttl_seconds")]
    pub recent_node_ttl_seconds: u32,
}

impl Default for AggregateClashConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            controller_url: default_clash_controller_url(),
            proxy_url: default_clash_proxy_url(),
            secret: String::new(),
            group_name: String::new(),
            ip_switch_cooldown_seconds: default_ip_switch_cooldown_seconds(),
            recent_node_window: default_recent_node_window(),
            recent_node_ttl_seconds: default_recent_node_ttl_seconds(),
        }
    }
}

impl AggregateClashConfig {
    fn effective_proxy_url(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }
        trimmed(&self.proxy_url)
            .map(str::to_string)
            .or_else(|| Some(default_clash_proxy_url()))
    }

    fn can_control_nodes(&self) -> bool {
        trimmed(&self.controller_url).is_some() && trimmed(&self.group_name).is_some()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AggregateKeyRow {
    pub upstream: String,
    pub base_url: String,
    pub key_label: String,
    pub egress_note: String,
    pub recent_clash_node: String,
    pub recent_clash_egress_ip: String,
    pub score: f64,
    pub total_requests: u64,
    pub success_requests: u64,
    pub failure_requests: u64,
    pub consecutive_failures: u32,
    pub average_latency_ms: Option<f64>,
    pub last_status: String,
    pub cooldown_remaining_seconds: u64,
    pub in_flight: u32,
    pub limit_status: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AggregateEgressSnapshot {
    pub rows: Vec<AggregateKeyRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AggregateResponse {
    pub status: u16,
    pub reason: String,
    pub headers: HeaderMap,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct AggregateEgressRuntime {
    deployments: Arc<Mutex<Vec<AggregateDeploymentRuntime>>>,
    upstreams: Arc<Mutex<HashMap<String, AggregateUpstreamRuntime>>>,
    fingerprints: Arc<Mutex<Vec<AggregateFingerprintRuntime>>>,
    recent_fingerprints: Arc<Mutex<Vec<(AggregateFingerprint, Instant)>>>,
    quality_writer: QualityWriteHandle,
    clash: Option<Arc<AggregateClashController>>,
    clash_proxy_url: Option<String>,
    last_request_egress: Mutex<Option<AggregateRequestEgress>>,
    request_egress_ip_cache: Mutex<HashMap<String, (String, Instant)>>,
    combos: Arc<Mutex<AggregateComboState>>,
    cooldown_seconds: u32,
    config: AggregateEgressConfig,
    rotation: AtomicU64,
    tokio_runtime: Runtime,
}

#[derive(Debug, Clone)]
struct AggregateDeploymentRuntime {
    upstream: String,
    base_url: String,
    public_model: String,
    actual_model: String,
    max_qps: Option<u32>,
    max_rpm: Option<u32>,
    max_concurrency: u32,
    upstream_cooldown_seconds: Option<u32>,
    egress_note: String,
    key: String,
    key_label: String,
    quality_key: String,
    stats: AggregateQualityStats,
    last_request_egress: Option<AggregateRequestEgress>,
}

#[derive(Debug, Clone)]
struct AggregateFingerprintRuntime {
    fingerprint: AggregateFingerprint,
    stats: AggregateQualityStats,
}

#[derive(Debug, Clone)]
struct AggregateQualityStats {
    score: f64,
    total_requests: u64,
    success_requests: u64,
    failure_requests: u64,
    consecutive_failures: u32,
    latency_ema_ms: Option<f64>,
    last_status: String,
    cooldown_until: Option<Instant>,
}

#[derive(Debug, Clone)]
struct AggregateUpstreamRuntime {
    recent_request_times: Vec<Instant>,
    in_flight: u32,
    cooldown_until: Option<Instant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct KeyQualityStore {
    #[serde(default)]
    keys: HashMap<String, PersistedKeyQuality>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedKeyQuality {
    #[serde(default = "default_persisted_key_score")]
    score: f64,
    #[serde(default)]
    total_requests: u64,
    #[serde(default)]
    success_requests: u64,
    #[serde(default)]
    failure_requests: u64,
    #[serde(default)]
    consecutive_failures: u32,
    #[serde(default)]
    latency_ema_ms: Option<f64>,
    #[serde(default)]
    last_status: String,
}

#[derive(Debug, Clone)]
struct QualityWriteHandle {
    tx: Sender<QualityWriteCommand>,
}

#[derive(Debug, Clone)]
struct QualityWrite {
    quality_key: String,
    quality: PersistedKeyQuality,
}

const QUALITY_FLUSH_ATTEMPTS: usize = 40;
const QUALITY_FAST_FLUSH_ATTEMPTS: usize = 2;

#[derive(Debug)]
enum QualityWriteCommand {
    Write(QualityWrite),
    Flush { done: Sender<()>, attempts: usize },
}

#[derive(Debug)]
struct AggregateClashController {
    config: AggregateClashConfig,
    client: Client,
    last_switch_at: Mutex<Option<Instant>>,
    group_rotations: Mutex<HashMap<String, usize>>,
    recent_nodes: Mutex<HashMap<String, Vec<(String, Instant)>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AggregateEgressCombo {
    node: Option<String>,
    fingerprint: AggregateFingerprint,
}

#[derive(Debug)]
struct AggregateComboState {
    combos: Vec<AggregateEgressCombo>,
    current_index: usize,
    next_index: usize,
    recent: Vec<(AggregateEgressCombo, Instant)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AggregateRequestEgress {
    node: Option<String>,
    ip: Option<String>,
    seen_at: Instant,
}

#[derive(Debug, Clone)]
struct AggregateClashGroupSnapshot {
    name: String,
    current: Option<String>,
    nodes: Vec<String>,
}

impl Default for AggregateQualityStats {
    fn default() -> Self {
        Self {
            score: default_persisted_key_score(),
            total_requests: 0,
            success_requests: 0,
            failure_requests: 0,
            consecutive_failures: 0,
            latency_ema_ms: None,
            last_status: String::new(),
            cooldown_until: None,
        }
    }
}

impl AggregateQualityStats {
    fn observe_latency(&mut self, latency: Duration) {
        let millis = latency.as_secs_f64() * 1000.0;
        self.latency_ema_ms = Some(match self.latency_ema_ms {
            Some(previous) => previous * 0.75 + millis * 0.25,
            None => millis,
        });
    }

    fn recalculate_score(&mut self) {
        let success_rate = if self.total_requests == 0 {
            0.0
        } else {
            self.success_requests as f64 / self.total_requests as f64
        };
        let confidence_bonus = (self.total_requests.min(20) as f64) / 20.0 * 5.0;
        let failure_penalty = (self.consecutive_failures.min(5) as f64) * 6.0;
        let latency_penalty = latency_quality_penalty(self.latency_ema_ms.unwrap_or(0.0));
        self.score = (success_rate * 100.0 - latency_penalty - failure_penalty + confidence_bonus)
            .clamp(0.0, 100.0);
    }
}

impl KeyQualityStore {
    fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string()) + "\n";
        write_text_atomic(path, &text)
    }

    fn apply_to_deployments(&self, deployments: &mut [AggregateDeploymentRuntime]) {
        for deployment in deployments {
            if let Some(saved) = self.keys.get(&deployment.quality_key) {
                deployment.stats.score = saved.score.clamp(0.0, 100.0);
                deployment.stats.total_requests = saved.total_requests;
                deployment.stats.success_requests = saved.success_requests;
                deployment.stats.failure_requests = saved.failure_requests;
                deployment.stats.consecutive_failures = saved.consecutive_failures;
                deployment.stats.latency_ema_ms = saved.latency_ema_ms;
                deployment.stats.last_status = saved.last_status.clone();
            }
        }
    }
}

impl QualityWriteHandle {
    fn new(path: PathBuf) -> Self {
        let (tx, rx) = mpsc::channel::<QualityWriteCommand>();
        thread::spawn(move || {
            let mut store = KeyQualityStore::load(&path);
            let mut pending = 0usize;
            let mut last_flush = Instant::now();
            while let Ok(command) = rx.recv() {
                match command {
                    QualityWriteCommand::Write(write) => {
                        store.keys.insert(write.quality_key, write.quality);
                        pending += 1;
                    }
                    QualityWriteCommand::Flush { done, attempts } => {
                        flush_quality_pending(
                            &store,
                            &path,
                            &mut pending,
                            &mut last_flush,
                            attempts,
                        );
                        let _ = done.send(());
                        continue;
                    }
                }
                while let Ok(command) = rx.try_recv() {
                    match command {
                        QualityWriteCommand::Write(write) => {
                            store.keys.insert(write.quality_key, write.quality);
                            pending += 1;
                        }
                        QualityWriteCommand::Flush { done, attempts } => {
                            flush_quality_pending(
                                &store,
                                &path,
                                &mut pending,
                                &mut last_flush,
                                attempts,
                            );
                            let _ = done.send(());
                        }
                    }
                }
                let should_flush = pending >= 16 || last_flush.elapsed() >= Duration::from_secs(1);
                if should_flush && store.save(&path).is_ok() {
                    pending = 0;
                    last_flush = Instant::now();
                }
            }
            for _ in 0..5 {
                if pending == 0 || store.save(&path).is_ok() {
                    break;
                } else {
                    thread::sleep(Duration::from_millis(50));
                }
            }
        });
        Self { tx }
    }

    fn persist(&self, quality_key: String, quality: PersistedKeyQuality) {
        let _ = self.tx.send(QualityWriteCommand::Write(QualityWrite {
            quality_key,
            quality,
        }));
    }

    fn flush(&self) {
        self.flush_with_timeout(Duration::from_secs(2), QUALITY_FLUSH_ATTEMPTS);
    }

    fn flush_with_timeout(&self, timeout: Duration, attempts: usize) {
        let (tx, rx) = mpsc::channel();
        if self
            .tx
            .send(QualityWriteCommand::Flush {
                done: tx,
                attempts: attempts.max(1),
            })
            .is_ok()
        {
            let _ = rx.recv_timeout(timeout);
        }
    }
}

fn flush_quality_pending(
    store: &KeyQualityStore,
    path: &Path,
    pending: &mut usize,
    last_flush: &mut Instant,
    attempts: usize,
) {
    for _ in 0..attempts.max(1) {
        if *pending == 0 {
            return;
        }
        if store.save(path).is_ok() {
            *pending = 0;
            *last_flush = Instant::now();
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

impl AggregateClashController {
    fn new(config: AggregateClashConfig) -> Result<Self> {
        Ok(Self {
            config,
            client: Client::builder().timeout(Duration::from_secs(1)).build()?,
            last_switch_at: Mutex::new(None),
            group_rotations: Mutex::new(HashMap::new()),
            recent_nodes: Mutex::new(HashMap::new()),
        })
    }

    fn rotate_after_failure(&self) {
        let Some(group) = self.group_snapshot().ok().flatten() else {
            return;
        };
        let current = group.current.as_deref().unwrap_or_default();
        let candidates = group
            .nodes
            .iter()
            .map(String::as_str)
            .filter(|node| *node != current)
            .collect::<Vec<_>>();
        let Some(next) = self.next_group_candidate(&group.name, &candidates) else {
            return;
        };
        let _ = self.switch_to_node_force(&group.name, next);
    }

    #[cfg(test)]
    fn switch_to_node(&self, group_name: &str, node: &str) -> Result<()> {
        self.switch_to_node_inner(group_name, node, false)
    }

    fn switch_to_node_force(&self, group_name: &str, node: &str) -> Result<()> {
        self.switch_to_node_inner(group_name, node, true)
    }

    fn switch_to_node_inner(&self, group_name: &str, node: &str, force: bool) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        let Some(controller_url) = trimmed(&self.config.controller_url) else {
            return Ok(());
        };
        let cooldown = Duration::from_secs(self.config.ip_switch_cooldown_seconds as u64);
        let Ok(mut last_switch_at) = self.last_switch_at.lock() else {
            return Ok(());
        };
        if !force && last_switch_at.is_some_and(|last| last.elapsed() < cooldown) {
            return Ok(());
        }
        let group = url_encode_component(group_name);
        let url = format!("{}/proxies/{}", controller_url.trim_end_matches('/'), group);
        let body = json!({ "name": node });
        let response = self.authorized(self.client.put(&url).json(&body)).send()?;
        if !response.status().is_success() {
            return Err(anyhow!("clash switch failed: {}", response.status()));
        }
        self.remember_group_node(group_name, node);
        *last_switch_at = Some(Instant::now());
        Ok(())
    }

    fn group_snapshot(&self) -> Result<Option<AggregateClashGroupSnapshot>> {
        if !self.config.enabled {
            return Ok(None);
        }
        let Some(group_name) = trimmed(&self.config.group_name) else {
            return Ok(None);
        };
        let Some(controller_url) = trimmed(&self.config.controller_url) else {
            return Ok(None);
        };
        let group = url_encode_component(group_name);
        let url = format!("{}/proxies/{}", controller_url.trim_end_matches('/'), group);
        let response = self.authorized(self.client.get(&url)).send()?;
        let payload: Value = response.json()?;
        let all = payload
            .get("all")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("clash group missing all"))?;
        let current = payload
            .get("now")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string);
        let nodes = all
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .filter(|name| self.node_is_usable(controller_url, name))
            .map(str::to_string)
            .collect::<Vec<_>>();
        Ok(Some(AggregateClashGroupSnapshot {
            name: group_name.to_string(),
            current,
            nodes,
        }))
    }

    fn node_is_usable(&self, controller_url: &str, node: &str) -> bool {
        match self.node_history_delay(controller_url, node) {
            Some(delay) => delay > 0,
            None => self
                .probe_node_delay(controller_url, node)
                .is_some_and(|delay| delay > 0),
        }
    }

    fn node_history_delay(&self, controller_url: &str, node: &str) -> Option<u64> {
        let node = url_encode_component(node);
        let url = format!("{}/proxies/{}", controller_url.trim_end_matches('/'), node);
        let response = self.authorized(self.client.get(&url)).send().ok()?;
        if !response.status().is_success() {
            return None;
        }
        let payload: Value = response.json().ok()?;
        payload
            .get("history")
            .and_then(Value::as_array)?
            .iter()
            .rev()
            .filter_map(|entry| entry.get("delay").and_then(Value::as_u64))
            .find(|delay| *delay > 0)
    }

    fn probe_node_delay(&self, controller_url: &str, node: &str) -> Option<u64> {
        let node = url_encode_component(node);
        let url = format!(
            "{}/proxies/{}/delay?timeout=1000&url={}",
            controller_url.trim_end_matches('/'),
            node,
            url_encode_component("https://www.gstatic.com/generate_204")
        );
        let response = self.authorized(self.client.get(&url)).send().ok()?;
        if !response.status().is_success() {
            return None;
        }
        let payload: Value = response.json().ok()?;
        payload.get("delay").and_then(Value::as_u64)
    }

    fn authorized(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        if let Some(secret) = trimmed(&self.config.secret) {
            builder.bearer_auth(secret)
        } else {
            builder
        }
    }

    fn next_group_candidate<'a>(
        &self,
        group_name: &str,
        candidates: &'a [&'a str],
    ) -> Option<&'a str> {
        if candidates.is_empty() {
            return None;
        }
        let filtered = self.filter_recent_group_candidates(group_name, candidates);
        let candidates = if filtered.is_empty() {
            candidates.to_vec()
        } else {
            filtered
        };
        let Ok(mut rotations) = self.group_rotations.lock() else {
            return candidates.first().copied();
        };
        let rotation = rotations.entry(group_name.to_string()).or_insert(0);
        let index = *rotation % candidates.len();
        let selected = candidates[index];
        *rotation = rotation.saturating_add(1);
        Some(selected)
    }

    fn filter_recent_group_candidates<'a>(
        &self,
        group_name: &str,
        candidates: &[&'a str],
    ) -> Vec<&'a str> {
        let ttl = Duration::from_secs(self.config.recent_node_ttl_seconds.max(1) as u64);
        let window = self.config.recent_node_window.max(1) as usize;
        let Ok(mut recent_nodes) = self.recent_nodes.lock() else {
            return candidates.to_vec();
        };
        let entries = recent_nodes.entry(group_name.to_string()).or_default();
        let now = Instant::now();
        entries.retain(|(_, seen_at)| now.duration_since(*seen_at) < ttl);
        if entries.len() > window {
            let keep_from = entries.len() - window;
            entries.drain(0..keep_from);
        }
        let recent = entries
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        candidates
            .iter()
            .copied()
            .filter(|candidate| !recent.contains(candidate))
            .collect()
    }

    fn remember_group_node(&self, group_name: &str, node: &str) {
        let ttl = Duration::from_secs(self.config.recent_node_ttl_seconds.max(1) as u64);
        let window = self.config.recent_node_window.max(1) as usize;
        let Ok(mut recent_nodes) = self.recent_nodes.lock() else {
            return;
        };
        let entries = recent_nodes.entry(group_name.to_string()).or_default();
        let now = Instant::now();
        entries.retain(|(_, seen_at)| now.duration_since(*seen_at) < ttl);
        entries.retain(|(name, _)| name != node);
        entries.push((node.to_string(), now));
        if entries.len() > window {
            let drop_count = entries.len() - window;
            entries.drain(0..drop_count);
        }
    }
}

impl AggregateEgressRuntime {
    pub fn new(
        config: AggregateEgressConfig,
        seeds: Vec<AggregateDeploymentSeed>,
        quality_path: PathBuf,
        clash: Option<AggregateClashConfig>,
        cooldown_seconds: u32,
    ) -> Result<Self> {
        config.validate()?;
        if !config.enabled {
            return Err(anyhow!("共享最终出口未启用"));
        }
        if seeds.is_empty() {
            return Err(anyhow!("没有可用 Key，无法创建共享最终出口"));
        }
        let mut deployments = seeds
            .into_iter()
            .map(|seed| AggregateDeploymentRuntime {
                upstream: seed.upstream,
                base_url: seed.base_url.trim_end_matches('/').to_string(),
                public_model: seed.public_model,
                actual_model: seed.actual_model,
                max_qps: seed.max_qps,
                max_rpm: seed.max_rpm,
                max_concurrency: seed.max_concurrency,
                upstream_cooldown_seconds: seed.upstream_cooldown_seconds,
                egress_note: seed.egress_note,
                key: seed.key,
                key_label: seed.key_label,
                quality_key: seed.quality_key,
                stats: AggregateQualityStats::default(),
                last_request_egress: None,
            })
            .collect::<Vec<_>>();
        KeyQualityStore::load(&quality_path).apply_to_deployments(&mut deployments);
        let upstreams = deployments
            .iter()
            .map(|deployment| {
                (
                    deployment.base_url.clone(),
                    AggregateUpstreamRuntime {
                        recent_request_times: Vec::new(),
                        in_flight: 0,
                        cooldown_until: None,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let fingerprints = config
            .fingerprints
            .iter()
            .copied()
            .map(|fingerprint| AggregateFingerprintRuntime {
                fingerprint,
                stats: AggregateQualityStats::default(),
            })
            .collect::<Vec<_>>();
        let clash_controller = clash
            .as_ref()
            .filter(|item| item.enabled)
            .and_then(|item| item.can_control_nodes().then(|| item.clone()))
            .map(AggregateClashController::new)
            .transpose()?
            .map(Arc::new);
        let combos = build_egress_combos(&config.fingerprints, clash_controller.as_deref());
        Ok(Self {
            deployments: Arc::new(Mutex::new(deployments)),
            upstreams: Arc::new(Mutex::new(upstreams)),
            fingerprints: Arc::new(Mutex::new(fingerprints)),
            recent_fingerprints: Arc::new(Mutex::new(Vec::new())),
            quality_writer: QualityWriteHandle::new(quality_path.clone()),
            clash: clash_controller,
            clash_proxy_url: clash
                .as_ref()
                .filter(|item| item.enabled)
                .and_then(|item| item.effective_proxy_url()),
            last_request_egress: Mutex::new(None),
            request_egress_ip_cache: Mutex::new(HashMap::new()),
            combos: Arc::new(Mutex::new(AggregateComboState {
                combos,
                current_index: 0,
                next_index: 0,
                recent: Vec::new(),
            })),
            cooldown_seconds: cooldown_seconds.max(1),
            config,
            rotation: AtomicU64::new(0),
            tokio_runtime: Runtime::new()?,
        })
    }

    pub fn forward_once(
        &self,
        raw_request: &[u8],
        body: &[u8],
        method: &str,
        path: &str,
    ) -> Result<AggregateResponse> {
        let request_body = AggregateRequestBody::parse(body);
        self.forward_once_prepared(raw_request, &request_body, method, path)
    }

    fn forward_once_prepared(
        &self,
        raw_request: &[u8],
        request_body: &AggregateRequestBody<'_>,
        method: &str,
        path: &str,
    ) -> Result<AggregateResponse> {
        let Some((deployment_index, deployment)) =
            self.select_deployment(&request_body.requested_model)
        else {
            return Err(anyhow!("no available key for requested model"));
        };
        let Some((fingerprint_index, fingerprint, combo)) = self.select_combo_fingerprint() else {
            return Err(anyhow!("no available fingerprint"));
        };
        let upstream_request_started_at =
            mark_upstream_request_started(&self.upstreams, &deployment.base_url);
        let forwarded_body = request_body.rewrite_model(&deployment.actual_model);
        let headers = forward_headers(raw_request, &deployment.key, forwarded_body.len(), true)?;
        let started_at = Instant::now();
        self.activate_combo_node(&combo);
        self.record_request_egress(deployment_index, &combo);
        let request = EmulatedRequest {
            base_url: &deployment.base_url,
            method,
            path,
            headers,
            body: forwarded_body,
            fingerprint: fingerprint.fingerprint,
            proxy_url: self.clash_proxy_url.as_deref(),
            runtime: &self.tokio_runtime,
        };
        let result = send_emulated_request(request);
        let latency = started_at.elapsed();
        mark_upstream_request_finished(&self.upstreams, &deployment.base_url);
        match result {
            Ok(response) => {
                if (200..300).contains(&response.status) {
                    self.record_success(deployment_index, fingerprint_index, &combo, latency);
                } else if is_invalid_encrypted_content_response(&response) {
                    forget_upstream_recent_request(
                        &self.upstreams,
                        &deployment.base_url,
                        upstream_request_started_at,
                    );
                    // This is tied to the caller's conversation state, not key health.
                } else {
                    self.record_failure(
                        deployment_index,
                        fingerprint_index,
                        &combo,
                        response.status,
                        latency,
                    );
                }
                Ok(response)
            }
            Err(err) => {
                if should_suppress_local_failure_response(&err) {
                    return Err(err);
                }
                if is_invalid_encrypted_content_text(&err.to_string()) {
                    forget_upstream_recent_request(
                        &self.upstreams,
                        &deployment.base_url,
                        upstream_request_started_at,
                    );
                } else {
                    self.record_transport_failure(
                        deployment_index,
                        fingerprint_index,
                        &combo,
                        latency,
                    );
                }
                Err(err)
            }
        }
    }

    pub fn forward_with_failover(
        &self,
        raw_request: &[u8],
        body: &[u8],
        method: &str,
        path: &str,
        attempts: u32,
    ) -> Result<AggregateResponse> {
        let attempts = attempts.max(1);
        let request_body = AggregateRequestBody::parse(body);
        let mut last_response = None;
        let mut last_error = None;
        for _ in 0..attempts {
            match self.forward_once_prepared(raw_request, &request_body, method, path) {
                Ok(response) => {
                    if (200..300).contains(&response.status) {
                        return Ok(response);
                    }
                    let stop_retrying = is_invalid_encrypted_content_response(&response);
                    last_response = Some(response);
                    if stop_retrying {
                        break;
                    }
                }
                Err(err) => {
                    if last_response.is_some()
                        && err
                            .to_string()
                            .contains("no available key for requested model")
                    {
                        break;
                    }
                    last_error = Some(err);
                }
            }
        }
        if let Some(response) = last_response {
            Ok(response)
        } else {
            Err(last_error.unwrap_or_else(|| anyhow!("aggregate upstream unavailable")))
        }
    }

    pub fn forward_stream_with_failover<W: Write>(
        &self,
        writer: &mut W,
        raw_request: &[u8],
        body: &[u8],
        method: &str,
        path: &str,
        attempts: u32,
    ) -> Result<()> {
        let attempts = attempts.max(1);
        let request_body = AggregateRequestBody::parse(body);
        let mut last_error = None;
        for _ in 0..attempts {
            match self.forward_stream_once_prepared(
                writer,
                raw_request,
                &request_body,
                method,
                path,
            ) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    let err_text = err.to_string();
                    if last_error.is_some()
                        && err_text.contains("no available key for requested model")
                    {
                        break;
                    }
                    let stop_retrying = should_suppress_local_failure_response(&err)
                        || is_incomplete_stream_error(&err)
                        || is_invalid_encrypted_content_text(&err_text);
                    last_error = Some(err);
                    if stop_retrying {
                        break;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("aggregate upstream unavailable")))
    }

    fn forward_stream_once_prepared<W: Write>(
        &self,
        writer: &mut W,
        raw_request: &[u8],
        request_body: &AggregateRequestBody<'_>,
        method: &str,
        path: &str,
    ) -> Result<()> {
        let Some((deployment_index, deployment)) =
            self.select_deployment(&request_body.requested_model)
        else {
            return Err(anyhow!("no available key for requested model"));
        };
        let Some((fingerprint_index, fingerprint, combo)) = self.select_combo_fingerprint() else {
            return Err(anyhow!("no available fingerprint"));
        };
        let upstream_request_started_at =
            mark_upstream_request_started(&self.upstreams, &deployment.base_url);
        let forwarded_body = request_body.rewrite_model(&deployment.actual_model);
        let headers = forward_headers(raw_request, &deployment.key, forwarded_body.len(), true)?;
        let started_at = Instant::now();
        self.activate_combo_node(&combo);
        self.record_request_egress(deployment_index, &combo);
        let request = EmulatedRequest {
            base_url: &deployment.base_url,
            method,
            path,
            headers,
            body: forwarded_body,
            fingerprint: fingerprint.fingerprint,
            proxy_url: self.clash_proxy_url.as_deref(),
            runtime: &self.tokio_runtime,
        };
        let result = stream_emulated_request(writer, request);
        let latency = started_at.elapsed();
        mark_upstream_request_finished(&self.upstreams, &deployment.base_url);
        match result {
            Ok(status) => {
                if (200..300).contains(&status) {
                    self.record_success(deployment_index, fingerprint_index, &combo, latency);
                    Ok(())
                } else {
                    self.record_failure(
                        deployment_index,
                        fingerprint_index,
                        &combo,
                        status,
                        latency,
                    );
                    Err(anyhow!("aggregate upstream returned {status}"))
                }
            }
            Err(err) => {
                if should_suppress_local_failure_response(&err) {
                    return Err(err);
                }
                if is_invalid_encrypted_content_text(&err.to_string()) {
                    forget_upstream_recent_request(
                        &self.upstreams,
                        &deployment.base_url,
                        upstream_request_started_at,
                    );
                } else {
                    self.record_transport_failure(
                        deployment_index,
                        fingerprint_index,
                        &combo,
                        latency,
                    );
                }
                Err(err)
            }
        }
    }

    pub fn snapshot(&self) -> AggregateEgressSnapshot {
        let now = Instant::now();
        let upstream_state = self.upstreams.lock().ok();
        let rows = self
            .deployments
            .lock()
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        let state = upstream_state
                            .as_ref()
                            .and_then(|map| map.get(&item.base_url));
                        let upstream_cooldown = state
                            .and_then(|state| state.cooldown_until)
                            .map(|until| until.saturating_duration_since(now).as_secs())
                            .unwrap_or(0);
                        let key_cooldown = item
                            .stats
                            .cooldown_until
                            .map(|until| until.saturating_duration_since(now).as_secs())
                            .unwrap_or(0);
                        let row_egress = item.last_request_egress.clone().filter(|egress| {
                            now.duration_since(egress.seen_at) < Duration::from_secs(24 * 60 * 60)
                        });
                        let row_clash_node = row_egress
                            .as_ref()
                            .and_then(|egress| egress.node.clone())
                            .unwrap_or_default();
                        let row_clash_egress_ip =
                            row_egress.and_then(|egress| egress.ip).unwrap_or_default();
                        AggregateKeyRow {
                            upstream: item.upstream.clone(),
                            base_url: item.base_url.clone(),
                            key_label: item.key_label.clone(),
                            egress_note: item.egress_note.clone(),
                            recent_clash_node: row_clash_node,
                            recent_clash_egress_ip: row_clash_egress_ip,
                            score: item.stats.score,
                            total_requests: item.stats.total_requests,
                            success_requests: item.stats.success_requests,
                            failure_requests: item.stats.failure_requests,
                            consecutive_failures: item.stats.consecutive_failures,
                            average_latency_ms: item.stats.latency_ema_ms,
                            last_status: item.stats.last_status.clone(),
                            cooldown_remaining_seconds: upstream_cooldown.max(key_cooldown),
                            in_flight: state.map(|state| state.in_flight).unwrap_or(0),
                            limit_status: upstream_limit_status(state, item, now),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        AggregateEgressSnapshot { rows }
    }

    fn record_request_egress(&self, deployment_index: usize, combo: &AggregateEgressCombo) {
        let ip = self
            .clash_proxy_url
            .as_deref()
            .and_then(|proxy_url| self.request_proxy_egress_ip(proxy_url, combo.node.as_deref()));
        if combo.node.is_none() && ip.is_none() {
            return;
        }
        let egress = AggregateRequestEgress {
            node: combo.node.clone(),
            ip,
            seen_at: Instant::now(),
        };
        if let Ok(mut items) = self.deployments.lock() {
            if let Some(item) = items.get_mut(deployment_index) {
                item.last_request_egress = Some(egress.clone());
            }
        }
        if let Ok(mut last) = self.last_request_egress.lock() {
            *last = Some(egress);
        }
    }

    fn activate_combo_node(&self, combo: &AggregateEgressCombo) {
        let (Some(clash), Some(node)) = (&self.clash, combo.node.as_deref()) else {
            return;
        };
        if clash
            .switch_to_node_force(clash.config.group_name.trim(), node)
            .is_ok()
        {
            self.clear_cached_combo_egress_ip(combo);
        }
    }

    fn request_proxy_egress_ip(&self, proxy_url: &str, node: Option<&str>) -> Option<String> {
        let proxy_url = trimmed(proxy_url)?;
        let node = node.and_then(trimmed);
        if node.is_none() {
            return lookup_proxy_egress_ip(proxy_url);
        }
        let cache_key = format!("{}\n{}", proxy_url, node.unwrap_or_default());
        let ttl = Duration::from_secs(10);
        let now = Instant::now();
        if let Ok(mut cache) = self.request_egress_ip_cache.lock() {
            cache.retain(|_, (_, seen_at)| now.duration_since(*seen_at) < ttl);
            if let Some((ip, _)) = cache.get(&cache_key) {
                return Some(ip.clone());
            }
        }
        let ip = lookup_proxy_egress_ip(proxy_url)?;
        if let Ok(mut cache) = self.request_egress_ip_cache.lock() {
            cache.insert(cache_key, (ip.clone(), Instant::now()));
        }
        Some(ip)
    }

    pub fn flush_quality(&self) {
        self.quality_writer.flush();
    }

    pub fn flush_quality_with_timeout(&self, timeout: Duration, attempts: usize) {
        self.quality_writer.flush_with_timeout(timeout, attempts);
    }

    pub fn flush_quality_fast(&self) {
        self.flush_quality_with_timeout(Duration::from_millis(150), QUALITY_FAST_FLUSH_ATTEMPTS);
    }

    fn select_deployment(
        &self,
        requested_model: &str,
    ) -> Option<(usize, AggregateDeploymentRuntime)> {
        let now = Instant::now();
        let upstream_state = self.upstreams.lock().ok()?;
        let items = self.deployments.lock().ok()?;
        let mut candidates = items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                requested_model.is_empty()
                    || item.public_model.eq_ignore_ascii_case(requested_model)
            })
            .filter(|(_, item)| item.stats.cooldown_until.is_none_or(|until| now >= until))
            .filter(|(_, item)| {
                upstream_available(
                    upstream_state.get(&item.base_url),
                    item.max_qps,
                    item.max_rpm,
                    item.max_concurrency,
                    now,
                )
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return None;
        }
        candidates = select_quality_exploration_pool(candidates, MIN_KEY_EXPLORATION_REQUESTS);
        candidates.sort_by(|(left_index, left), (right_index, right)| {
            right
                .stats
                .score
                .partial_cmp(&left.stats.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.stats.total_requests.cmp(&right.stats.total_requests))
                .then_with(|| left_index.cmp(right_index))
        });
        let offset = self.next_rotation() % candidates.len();
        candidates
            .get(offset)
            .copied()
            .map(|(index, item)| (index, item.clone()))
    }

    fn select_fingerprint(&self) -> Option<(usize, AggregateFingerprintRuntime)> {
        let now = Instant::now();
        let items = self.fingerprints.lock().ok()?;
        let mut candidates = items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.stats.cooldown_until.is_none_or(|until| now >= until))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            candidates = items.iter().enumerate().collect::<Vec<_>>();
        }
        let filtered = self.filter_recent_fingerprints(&candidates);
        if !filtered.is_empty() {
            candidates = filtered;
        }
        candidates =
            select_quality_exploration_pool(candidates, MIN_FINGERPRINT_EXPLORATION_REQUESTS);
        candidates.sort_by(|(left_index, left), (right_index, right)| {
            right
                .stats
                .score
                .partial_cmp(&left.stats.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.stats.total_requests.cmp(&right.stats.total_requests))
                .then_with(|| left_index.cmp(right_index))
        });
        let offset = self.next_rotation() % candidates.len();
        candidates
            .get(offset)
            .copied()
            .map(|(index, item)| (index, item.clone()))
    }

    fn select_combo_fingerprint(
        &self,
    ) -> Option<(usize, AggregateFingerprintRuntime, AggregateEgressCombo)> {
        let combo = self.select_combo()?;
        let items = self.fingerprints.lock().ok()?;
        let (index, fingerprint) = items
            .iter()
            .enumerate()
            .find(|(_, item)| item.fingerprint == combo.fingerprint)
            .or_else(|| items.iter().enumerate().next())?;
        Some((index, fingerprint.clone(), combo))
    }

    fn select_combo(&self) -> Option<AggregateEgressCombo> {
        let Ok(mut state) = self.combos.lock() else {
            return self
                .select_fingerprint()
                .map(|(_, item)| AggregateEgressCombo {
                    node: None,
                    fingerprint: item.fingerprint,
                });
        };
        if state.combos.is_empty() {
            return self
                .select_fingerprint()
                .map(|(_, item)| AggregateEgressCombo {
                    node: None,
                    fingerprint: item.fingerprint,
                });
        }
        let now = Instant::now();
        let ttl = Duration::from_secs(self.config.recent_fingerprint_ttl_seconds as u64);
        if ttl.is_zero() {
            state.recent.clear();
        } else {
            state
                .recent
                .retain(|(_, seen_at)| now.duration_since(*seen_at) < ttl);
        }
        let window = self.combo_recent_window();
        if window == 0 {
            state.recent.clear();
        } else if state.recent.len() > window {
            let keep_from = state.recent.len() - window;
            state.recent.drain(0..keep_from);
        }

        let len = state.combos.len();
        let start = state.current_index % len;
        let mut selected_index = start;
        for step in 0..len {
            let index = (start + step) % len;
            let combo = &state.combos[index];
            if !state.recent.iter().any(|(recent, _)| recent == combo) {
                selected_index = index;
                break;
            }
        }
        state.current_index = selected_index;
        Some(state.combos[selected_index].clone())
    }

    fn filter_recent_fingerprints<'a>(
        &self,
        candidates: &[(usize, &'a AggregateFingerprintRuntime)],
    ) -> Vec<(usize, &'a AggregateFingerprintRuntime)> {
        let ttl = Duration::from_secs(self.config.recent_fingerprint_ttl_seconds.max(1) as u64);
        let window = self.config.recent_fingerprint_window.max(1) as usize;
        let Ok(mut recent) = self.recent_fingerprints.lock() else {
            return candidates.to_vec();
        };
        let now = Instant::now();
        recent.retain(|(_, seen_at)| now.duration_since(*seen_at) < ttl);
        if recent.len() > window {
            let keep_from = recent.len() - window;
            recent.drain(0..keep_from);
        }
        candidates
            .iter()
            .copied()
            .filter(|(_, item)| {
                !recent
                    .iter()
                    .any(|(fingerprint, _)| *fingerprint == item.fingerprint)
            })
            .collect()
    }

    fn record_success(
        &self,
        deployment_index: usize,
        fingerprint_index: usize,
        combo: &AggregateEgressCombo,
        latency: Duration,
    ) {
        let mut base_url = None;
        if let Ok(mut items) = self.deployments.lock() {
            if let Some(item) = items.get_mut(deployment_index) {
                base_url = Some(item.base_url.clone());
                item.stats.total_requests += 1;
                item.stats.success_requests += 1;
                item.stats.consecutive_failures = 0;
                item.stats.last_status = "200".to_string();
                item.stats.observe_latency(latency);
                item.stats.recalculate_score();
                item.stats.cooldown_until = None;
                persist_deployment_quality(&self.quality_writer, item);
            }
        }
        if let Ok(mut items) = self.fingerprints.lock() {
            if let Some(item) = items.get_mut(fingerprint_index) {
                item.stats.total_requests += 1;
                item.stats.success_requests += 1;
                item.stats.consecutive_failures = 0;
                item.stats.last_status = "200".to_string();
                item.stats.observe_latency(latency);
                item.stats.recalculate_score();
                item.stats.cooldown_until = None;
                self.remember_fingerprint(item.fingerprint);
            }
        }
        if let Some(base_url) = base_url {
            clear_aggregate_upstream_cooldown(&self.upstreams, &base_url);
        }
        self.remember_combo(combo);
    }

    fn record_failure(
        &self,
        deployment_index: usize,
        fingerprint_index: usize,
        combo: &AggregateEgressCombo,
        status: u16,
        latency: Duration,
    ) {
        let now = Instant::now();
        if let Ok(mut items) = self.deployments.lock() {
            if let Some(item) = items.get_mut(deployment_index) {
                let effective_cooldown = item
                    .upstream_cooldown_seconds
                    .unwrap_or(self.cooldown_seconds);
                let cooldown_until = now + Duration::from_secs(effective_cooldown as u64);
                item.stats.total_requests += 1;
                item.stats.failure_requests += 1;
                item.stats.consecutive_failures += 1;
                item.stats.last_status = status.to_string();
                item.stats.observe_latency(latency);
                item.stats.recalculate_score();
                item.stats.cooldown_until = Some(cooldown_until);
                persist_deployment_quality(&self.quality_writer, item);
            }
        }
        let cooldown_until = now + Duration::from_secs(self.cooldown_seconds as u64);
        if let Ok(mut items) = self.fingerprints.lock() {
            if let Some(item) = items.get_mut(fingerprint_index) {
                item.stats.total_requests += 1;
                item.stats.failure_requests += 1;
                item.stats.consecutive_failures += 1;
                item.stats.last_status = status.to_string();
                item.stats.observe_latency(latency);
                item.stats.recalculate_score();
                item.stats.cooldown_until = Some(cooldown_until);
                self.remember_fingerprint(item.fingerprint);
            }
        }
        if let Some(clash) = &self.clash {
            if let Some(next_combo) = self.advance_combo_after_failure(combo) {
                if let Some(node) = next_combo.node.as_deref() {
                    let _ = clash.switch_to_node_force(clash.config.group_name.trim(), node);
                }
            } else {
                clash.rotate_after_failure();
            }
        } else {
            let _ = self.advance_combo_after_failure(combo);
        }
    }

    fn record_transport_failure(
        &self,
        deployment_index: usize,
        fingerprint_index: usize,
        combo: &AggregateEgressCombo,
        latency: Duration,
    ) {
        let now = Instant::now();
        if let Ok(mut items) = self.deployments.lock() {
            if let Some(item) = items.get_mut(deployment_index) {
                let effective_cooldown = item
                    .upstream_cooldown_seconds
                    .unwrap_or(self.cooldown_seconds);
                let cooldown_until = now + Duration::from_secs(effective_cooldown as u64);
                item.stats.total_requests += 1;
                item.stats.failure_requests += 1;
                item.stats.consecutive_failures += 1;
                item.stats.last_status = "transport".to_string();
                item.stats.observe_latency(latency);
                item.stats.recalculate_score();
                item.stats.cooldown_until = Some(cooldown_until);
                persist_deployment_quality(&self.quality_writer, item);
            }
        }
        let cooldown_until = now + Duration::from_secs(self.cooldown_seconds as u64);
        if let Ok(mut items) = self.fingerprints.lock() {
            if let Some(item) = items.get_mut(fingerprint_index) {
                item.stats.total_requests += 1;
                item.stats.failure_requests += 1;
                item.stats.consecutive_failures += 1;
                item.stats.last_status = "transport".to_string();
                item.stats.observe_latency(latency);
                item.stats.recalculate_score();
                item.stats.cooldown_until = Some(cooldown_until);
                self.remember_fingerprint(item.fingerprint);
            }
        }
        if let Some(clash) = &self.clash {
            if let Some(next_combo) = self.advance_combo_after_failure(combo) {
                if let Some(node) = next_combo.node.as_deref() {
                    let _ = clash.switch_to_node_force(clash.config.group_name.trim(), node);
                }
            } else {
                clash.rotate_after_failure();
            }
        } else {
            let _ = self.advance_combo_after_failure(combo);
        }
    }

    fn remember_fingerprint(&self, fingerprint: AggregateFingerprint) {
        let ttl = Duration::from_secs(self.config.recent_fingerprint_ttl_seconds.max(1) as u64);
        let window = self.config.recent_fingerprint_window.max(1) as usize;
        let Ok(mut recent) = self.recent_fingerprints.lock() else {
            return;
        };
        let now = Instant::now();
        recent.retain(|(_, seen_at)| now.duration_since(*seen_at) < ttl);
        recent.retain(|(current, _)| *current != fingerprint);
        recent.push((fingerprint, now));
        if recent.len() > window {
            let drop_count = recent.len() - window;
            recent.drain(0..drop_count);
        }
    }

    fn remember_combo(&self, combo: &AggregateEgressCombo) {
        let ttl = Duration::from_secs(self.config.recent_fingerprint_ttl_seconds as u64);
        let window = self.combo_recent_window();
        let Ok(mut state) = self.combos.lock() else {
            return;
        };
        if ttl.is_zero() || window == 0 {
            state.recent.clear();
            return;
        }
        let now = Instant::now();
        state
            .recent
            .retain(|(_, seen_at)| now.duration_since(*seen_at) < ttl);
        state.recent.retain(|(current, _)| current != combo);
        state.recent.push((combo.clone(), now));
        if state.recent.len() > window {
            let drop_count = state.recent.len() - window;
            state.recent.drain(0..drop_count);
        }
    }

    fn advance_combo_after_failure(
        &self,
        failed_combo: &AggregateEgressCombo,
    ) -> Option<AggregateEgressCombo> {
        let mut state = self.combos.lock().ok()?;
        if state.combos.is_empty() {
            return None;
        }
        let now = Instant::now();
        let ttl = Duration::from_secs(self.config.recent_fingerprint_ttl_seconds as u64);
        let window = self.combo_recent_window();
        if ttl.is_zero() || window == 0 {
            state.recent.clear();
        } else {
            state
                .recent
                .retain(|(_, seen_at)| now.duration_since(*seen_at) < ttl);
            state.recent.retain(|(combo, _)| combo != failed_combo);
            state.recent.push((failed_combo.clone(), now));
            if state.recent.len() > window {
                let drop_count = state.recent.len() - window;
                state.recent.drain(0..drop_count);
            }
        }

        let len = state.combos.len();
        let start = state
            .combos
            .iter()
            .position(|combo| combo == failed_combo)
            .map(|index| index.saturating_add(1))
            .unwrap_or(state.next_index)
            % len;
        let failed_ip = self.cached_combo_egress_ip(failed_combo);
        let selected_index = self
            .find_combo_candidate_index(&state, start, failed_ip.as_deref(), true)
            .or_else(|| self.find_combo_candidate_index(&state, start, failed_ip.as_deref(), false))
            .unwrap_or(start);
        state.current_index = selected_index;
        state.next_index = (selected_index + 1) % len;
        state.combos.get(selected_index).cloned()
    }

    fn find_combo_candidate_index(
        &self,
        state: &AggregateComboState,
        start: usize,
        failed_ip: Option<&str>,
        avoid_recent: bool,
    ) -> Option<usize> {
        let len = state.combos.len();
        if len == 0 {
            return None;
        }
        let mut unknown_ip = None;
        let mut same_ip = None;
        for step in 0..len {
            let index = (start + step) % len;
            let combo = &state.combos[index];
            if avoid_recent && state.recent.iter().any(|(recent, _)| recent == combo) {
                continue;
            }
            match (failed_ip, self.cached_combo_egress_ip(combo)) {
                (Some(failed), Some(candidate)) if candidate != failed => return Some(index),
                (Some(_), Some(_)) => same_ip.get_or_insert(index),
                (Some(_), None) => unknown_ip.get_or_insert(index),
                (None, _) => return Some(index),
            };
        }
        unknown_ip.or(same_ip)
    }

    fn cached_combo_egress_ip(&self, combo: &AggregateEgressCombo) -> Option<String> {
        let proxy_url = trimmed(self.clash_proxy_url.as_deref()?)?;
        let node = trimmed(combo.node.as_deref()?)?;
        let cache_key = format!("{proxy_url}\n{node}");
        let ttl = Duration::from_secs(10);
        let now = Instant::now();
        let mut cache = self.request_egress_ip_cache.lock().ok()?;
        cache.retain(|_, (_, seen_at)| now.duration_since(*seen_at) < ttl);
        cache.get(&cache_key).map(|(ip, _)| ip.clone())
    }

    fn clear_cached_combo_egress_ip(&self, combo: &AggregateEgressCombo) {
        let Some(proxy_url) = trimmed(self.clash_proxy_url.as_deref().unwrap_or_default()) else {
            return;
        };
        let Some(node) = trimmed(combo.node.as_deref().unwrap_or_default()) else {
            return;
        };
        let cache_key = format!("{proxy_url}\n{node}");
        if let Ok(mut cache) = self.request_egress_ip_cache.lock() {
            cache.remove(&cache_key);
        }
    }

    fn combo_recent_window(&self) -> usize {
        let fingerprints = self.config.recent_fingerprint_window as usize;
        let nodes = self
            .clash
            .as_ref()
            .map(|clash| clash.config.recent_node_window as usize)
            .unwrap_or(0);
        fingerprints.max(nodes)
    }

    fn next_rotation(&self) -> usize {
        self.rotation.fetch_add(1, Ordering::Relaxed) as usize
    }
}

static REGISTRY: OnceLock<Mutex<HashMap<String, Weak<AggregateEgressRuntime>>>> = OnceLock::new();

pub fn register_runtime(base_url: &str, runtime: &Arc<AggregateEgressRuntime>) -> Result<()> {
    let key = normalize_base_url(base_url)?;
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry
        .lock()
        .map_err(|_| anyhow!("aggregate egress registry lock poisoned"))?;
    registry.insert(key, Arc::downgrade(runtime));
    Ok(())
}

pub fn unregister_runtime(base_url: &str) {
    let Ok(key) = normalize_base_url(base_url) else {
        return;
    };
    let Some(registry) = REGISTRY.get() else {
        return;
    };
    if let Ok(mut registry) = registry.lock() {
        registry.remove(&key);
    }
}

pub fn lookup_runtime(base_url: &str) -> Option<Arc<AggregateEgressRuntime>> {
    let key = normalize_base_url(base_url).ok()?;
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock().ok()?;
    let runtime = registry.get(&key).and_then(Weak::upgrade);
    if runtime.is_none() {
        registry.remove(&key);
    }
    runtime
}

fn normalize_base_url(base_url: &str) -> Result<String> {
    let mut url = Url::parse(base_url)?;
    url.set_query(None);
    url.set_fragment(None);
    let normalized = url.to_string();
    Ok(normalized.trim_end_matches('/').to_string())
}

fn persist_deployment_quality(
    writer: &QualityWriteHandle,
    deployment: &AggregateDeploymentRuntime,
) {
    writer.persist(
        deployment.quality_key.clone(),
        persisted_quality_from_stats(&deployment.stats),
    );
}

fn persisted_quality_from_stats(stats: &AggregateQualityStats) -> PersistedKeyQuality {
    PersistedKeyQuality {
        score: stats.score,
        total_requests: stats.total_requests,
        success_requests: stats.success_requests,
        failure_requests: stats.failure_requests,
        consecutive_failures: stats.consecutive_failures,
        latency_ema_ms: stats.latency_ema_ms,
        last_status: stats.last_status.clone(),
    }
}

fn build_egress_combos(
    fingerprints: &[AggregateFingerprint],
    clash: Option<&AggregateClashController>,
) -> Vec<AggregateEgressCombo> {
    let nodes = clash
        .and_then(|controller| controller.group_snapshot().ok().flatten())
        .map(|snapshot| {
            let mut nodes = snapshot.nodes;
            if let Some(current) = snapshot.current {
                nodes.retain(|node| node != &current);
                nodes.insert(0, current);
            }
            nodes
        })
        .unwrap_or_default();
    if nodes.is_empty() {
        return fingerprints
            .iter()
            .copied()
            .map(|fingerprint| AggregateEgressCombo {
                node: None,
                fingerprint,
            })
            .collect();
    }
    nodes
        .into_iter()
        .flat_map(|node| {
            fingerprints
                .iter()
                .copied()
                .map(move |fingerprint| AggregateEgressCombo {
                    node: Some(node.clone()),
                    fingerprint,
                })
        })
        .collect()
}

struct EmulatedRequest<'a> {
    base_url: &'a str,
    method: &'a str,
    path: &'a str,
    headers: HeaderMap,
    body: Vec<u8>,
    fingerprint: AggregateFingerprint,
    proxy_url: Option<&'a str>,
    runtime: &'a Runtime,
}

fn send_emulated_request(request: EmulatedRequest<'_>) -> Result<AggregateResponse> {
    let url = upstream_url(request.base_url, request.path)?;
    let method =
        reqwest::Method::from_bytes(request.method.as_bytes()).unwrap_or(reqwest::Method::POST);
    let client = emulated_client(request.fingerprint, request.proxy_url)?;
    let response = request.runtime.block_on(async {
        client
            .request(method, url)
            .headers(request.headers)
            .body(request.body)
            .send()
            .await
    })?;
    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("OK").to_string();
    let headers = response.headers().clone();
    let payload = request
        .runtime
        .block_on(async { response.bytes().await })?
        .to_vec();
    Ok(AggregateResponse {
        status: status.as_u16(),
        reason,
        headers,
        payload,
    })
}

fn stream_emulated_request<W: Write>(writer: &mut W, request: EmulatedRequest<'_>) -> Result<u16> {
    let url = upstream_url(request.base_url, request.path)?;
    let method =
        reqwest::Method::from_bytes(request.method.as_bytes()).unwrap_or(reqwest::Method::POST);
    let client = emulated_client(request.fingerprint, request.proxy_url)?;
    let mut response = request.runtime.block_on(async {
        client
            .request(method, url)
            .headers(request.headers)
            .body(request.body)
            .send()
            .await
    })?;
    let status = response.status();
    if !status.is_success() {
        let payload = request
            .runtime
            .block_on(async { response.bytes().await })?
            .to_vec();
        let preview = aggregate_error_preview(&payload);
        if preview.trim().is_empty() {
            return Err(anyhow!("aggregate upstream returned {}", status.as_u16()));
        }
        return Err(anyhow!(
            "aggregate upstream returned {}: {}",
            status.as_u16(),
            preview
        ));
    }
    request.runtime.block_on(async {
        let mut terminal_tracker =
            SseTerminalTracker::new(responses_api_stream_requires_completed(request.path));
        let mut forwarded_bytes = 0_usize;
        loop {
            match time::timeout(GUARD_STREAM_HEARTBEAT_INTERVAL, response.chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    terminal_tracker.observe(&chunk);
                    writer.write_all(&chunk)?;
                    writer.flush()?;
                    forwarded_bytes += chunk.len();
                }
                Ok(Ok(None)) => break,
                Ok(Err(err)) if forwarded_bytes > 0 => {
                    return Err(anyhow!(
                        "stream upstream interrupted after partial response: {err}"
                    ));
                }
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => {
                    write_sse_heartbeat(writer)?;
                }
            }
        }
        terminal_tracker.finish();
        match terminal_tracker.terminal {
            SseTerminalOutcome::Pending => {
                return Err(anyhow!("stream upstream closed before response.completed"));
            }
            SseTerminalOutcome::Failed(detail) => {
                return Err(anyhow!("stream upstream returned terminal error: {detail}"));
            }
            SseTerminalOutcome::Completed => {}
        }
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(status.as_u16())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SseTerminalOutcome {
    Pending,
    Completed,
    Failed(String),
}

struct SseTerminalTracker {
    carry: String,
    terminal: SseTerminalOutcome,
    require_response_event: bool,
    event: Option<String>,
    data_lines: Vec<String>,
}

impl SseTerminalTracker {
    fn new(require_response_event: bool) -> Self {
        Self {
            carry: String::new(),
            terminal: SseTerminalOutcome::Pending,
            require_response_event,
            event: None,
            data_lines: Vec::new(),
        }
    }

    fn observe(&mut self, chunk: &[u8]) {
        self.carry.push_str(&String::from_utf8_lossy(chunk));
        while let Some(index) = self.carry.find('\n') {
            let line = self.carry[..index].trim_end_matches('\r').to_string();
            self.carry.drain(..=index);
            self.observe_line(&line);
        }
    }

    fn finish(&mut self) {
        if !self.carry.is_empty() {
            let line = self.carry.trim_end_matches('\r').to_string();
            self.carry.clear();
            self.observe_line(&line);
        }
        self.dispatch_event();
    }

    fn observe_line(&mut self, line: &str) {
        if let Some(event) = line.strip_prefix("event:") {
            let event = event.trim();
            self.event = Some(event.to_string());
            if let Some(outcome) = terminal_sse_event_outcome(event) {
                self.set_terminal(outcome);
            }
            return;
        }
        if let Some(data) = line.strip_prefix("data:") {
            self.data_lines
                .push(data.strip_prefix(' ').unwrap_or(data).to_string());
            return;
        }
        if line.is_empty() {
            self.dispatch_event();
        }
    }

    fn dispatch_event(&mut self) {
        if !self.data_lines.is_empty() {
            let data = self.data_lines.join("\n");
            if let Some(outcome) = terminal_sse_data_outcome(
                data.trim(),
                self.require_response_event,
                self.event.as_deref(),
            ) {
                self.set_terminal(outcome);
            }
            self.data_lines.clear();
        }
        self.event = None;
    }

    fn set_terminal(&mut self, outcome: SseTerminalOutcome) {
        match (&mut self.terminal, outcome) {
            (SseTerminalOutcome::Failed(current), SseTerminalOutcome::Failed(next)) => {
                if current.starts_with("stream upstream returned ") && !next.trim().is_empty() {
                    *current = next;
                }
            }
            (SseTerminalOutcome::Failed(_), _) => {}
            (_, next) => self.terminal = next,
        }
    }
}

fn terminal_sse_event_outcome(event: &str) -> Option<SseTerminalOutcome> {
    match event {
        "response.completed" => Some(SseTerminalOutcome::Completed),
        "response.failed" | "response.incomplete" | "error" => Some(SseTerminalOutcome::Failed(
            format!("stream upstream returned {event}"),
        )),
        _ => None,
    }
}

fn terminal_sse_data_outcome(
    data: &str,
    require_response_event: bool,
    event: Option<&str>,
) -> Option<SseTerminalOutcome> {
    if data == "[DONE]" {
        return (!require_response_event).then_some(SseTerminalOutcome::Completed);
    }
    let Ok(value) = serde_json::from_str::<Value>(data) else {
        return None;
    };
    if let Some(event_type) = value.get("type").and_then(Value::as_str) {
        if let Some(outcome) = terminal_sse_event_outcome(event_type) {
            return Some(terminal_outcome_with_payload_detail(outcome, &value));
        }
    }
    if let Some(outcome) = event.and_then(terminal_sse_event_outcome) {
        return Some(terminal_outcome_with_payload_detail(outcome, &value));
    }
    (!require_response_event && json_has_terminal_chat_finish_reason(&value))
        .then_some(SseTerminalOutcome::Completed)
}

fn terminal_outcome_with_payload_detail(
    outcome: SseTerminalOutcome,
    value: &Value,
) -> SseTerminalOutcome {
    match outcome {
        SseTerminalOutcome::Failed(fallback) => {
            SseTerminalOutcome::Failed(sse_error_detail(value).unwrap_or(fallback))
        }
        other => other,
    }
}

fn sse_error_detail(value: &Value) -> Option<String> {
    value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .pointer("/response/error/message")
                .and_then(Value::as_str)
        })
        .or_else(|| value.get("message").and_then(Value::as_str))
        .map(str::trim)
        .filter(|message| !message.is_empty())
        .map(str::to_string)
}

fn json_has_terminal_chat_finish_reason(value: &Value) -> bool {
    value
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| {
            choices.iter().any(|choice| {
                choice
                    .get("finish_reason")
                    .and_then(Value::as_str)
                    .is_some_and(|reason| !reason.is_empty())
            })
        })
}

fn is_incomplete_stream_error(err: &anyhow::Error) -> bool {
    let text = err.to_string();
    text.contains("stream upstream closed before response.completed")
        || text.contains("stream upstream interrupted after partial response")
        || text.contains("stream upstream returned terminal error")
}

fn aggregate_error_preview(payload: &[u8]) -> String {
    let text = String::from_utf8_lossy(payload);
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .or_else(|| value.get("message").and_then(Value::as_str))
                .map(str::to_string)
        })
        .unwrap_or_else(|| text.to_string())
}

fn is_invalid_encrypted_content_response(response: &AggregateResponse) -> bool {
    response.status == 400
        && is_invalid_encrypted_content_text(&aggregate_error_preview(&response.payload))
}

fn is_invalid_encrypted_content_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("invalid_encrypted_content")
        || (lower.contains("encrypted content") && lower.contains("could not be decrypted"))
        || (lower.contains("encrypted content") && lower.contains("could not be verified"))
}

fn write_sse_heartbeat<W: Write>(writer: &mut W) -> Result<()> {
    writer.write_all(b": watchapi heartbeat\n\n")?;
    writer.flush()?;
    Ok(())
}

fn should_suppress_local_failure_response(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| {
            matches!(
                io.kind(),
                ErrorKind::WouldBlock
                    | ErrorKind::TimedOut
                    | ErrorKind::BrokenPipe
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
            )
        })
}

fn emulated_client(
    fingerprint: AggregateFingerprint,
    proxy_url: Option<&str>,
) -> Result<EmulatedClient> {
    let mut builder = EmulatedClient::builder()
        .connect_timeout(GUARD_UPSTREAM_CONNECT_TIMEOUT)
        .timeout(GUARD_UPSTREAM_TOTAL_TIMEOUT)
        .emulation(fingerprint.emulation());
    if let Some(proxy_url) = proxy_url.and_then(trimmed) {
        builder = builder.proxy(EmulatedProxy::all(proxy_url)?);
    }
    Ok(builder.build()?)
}

fn lookup_proxy_egress_ip(proxy_url: &str) -> Option<String> {
    let proxy = reqwest::Proxy::all(proxy_url).ok()?;
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .proxy(proxy)
        .build()
        .ok()?;
    let text = client
        .get("http://api.ipify.org")
        .send()
        .ok()?
        .text()
        .ok()?;
    let ip = text.trim();
    ip.parse::<std::net::IpAddr>().ok()?;
    Some(ip.to_string())
}

fn upstream_url(upstream: &str, path: &str) -> Result<String> {
    let base_text = upstream.trim_end_matches('/');
    let base = Url::parse(&format!("{base_text}/"))?;
    let path = path.trim_start_matches('/');
    let path = if base.path().trim_end_matches('/').ends_with("/v1") {
        path.strip_prefix("v1/").unwrap_or(path)
    } else {
        path
    };
    Ok(base.join(path)?.to_string())
}

struct AggregateRequestBody<'a> {
    body: &'a [u8],
    parsed: Option<Value>,
    requested_model: String,
}

impl<'a> AggregateRequestBody<'a> {
    fn parse(body: &'a [u8]) -> Self {
        let parsed = serde_json::from_slice::<Value>(body).ok();
        let requested_model = parsed
            .as_ref()
            .and_then(|value| value.get("model").and_then(Value::as_str))
            .map(str::to_string)
            .unwrap_or_default();
        Self {
            body,
            parsed,
            requested_model,
        }
    }

    fn rewrite_model(&self, model: &str) -> Vec<u8> {
        let Some(mut value) = self.parsed.clone() else {
            return self.body.to_vec();
        };
        value["model"] = json!(model);
        serde_json::to_vec(&value).unwrap_or_else(|_| self.body.to_vec())
    }
}

fn forward_headers(
    raw_request: &[u8],
    upstream_key: &str,
    content_length: usize,
    emulation_managed: bool,
) -> Result<HeaderMap> {
    let header_end = find_body(raw_request).ok_or_else(|| anyhow!("invalid http request"))?;
    let text = String::from_utf8_lossy(&raw_request[..header_end]);
    let mut headers = HeaderMap::new();
    for line in text.lines().skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let name = HeaderName::from_bytes(key.trim().as_bytes())?;
        if name == HOST
            || name == AUTHORIZATION
            || name == CONNECTION
            || name == CONTENT_LENGTH
            || name == TRANSFER_ENCODING
            || (emulation_managed && is_emulation_managed_header(name.as_str()))
        {
            continue;
        }
        headers.insert(name, HeaderValue::from_str(value.trim())?);
    }
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {upstream_key}"))?,
    );
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string())?,
    );
    Ok(headers)
}

fn is_emulation_managed_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "user-agent"
        || lower == "accept"
        || lower == "accept-language"
        || lower == "accept-encoding"
        || lower == "priority"
        || lower == "sec-fetch-site"
        || lower == "sec-fetch-mode"
        || lower == "sec-fetch-dest"
        || lower == "sec-fetch-user"
        || lower == "sec-ch-ua"
        || lower == "sec-ch-ua-mobile"
        || lower == "sec-ch-ua-platform"
        || lower == "upgrade-insecure-requests"
}

fn select_quality_exploration_pool<T>(
    candidates: Vec<(usize, &T)>,
    min_requests_threshold: u64,
) -> Vec<(usize, &T)>
where
    T: HasQualityStats,
{
    let min_requests = candidates
        .iter()
        .map(|(_, item)| item.quality_stats().total_requests)
        .min()
        .unwrap_or(0);
    if min_requests < min_requests_threshold {
        candidates
            .into_iter()
            .filter(|(_, item)| item.quality_stats().total_requests == min_requests)
            .collect()
    } else {
        candidates
    }
}

trait HasQualityStats {
    fn quality_stats(&self) -> &AggregateQualityStats;
}

impl HasQualityStats for AggregateDeploymentRuntime {
    fn quality_stats(&self) -> &AggregateQualityStats {
        &self.stats
    }
}

impl HasQualityStats for AggregateFingerprintRuntime {
    fn quality_stats(&self) -> &AggregateQualityStats {
        &self.stats
    }
}

fn upstream_available(
    state: Option<&AggregateUpstreamRuntime>,
    max_qps: Option<u32>,
    max_rpm: Option<u32>,
    max_concurrency: u32,
    now: Instant,
) -> bool {
    let Some(state) = state else {
        return true;
    };
    if state.cooldown_until.is_some_and(|until| now < until) {
        return false;
    }
    if state.in_flight >= max_concurrency {
        return false;
    }
    if let Some(max_qps) = max_qps {
        let recent = state
            .recent_request_times
            .iter()
            .filter(|at| now.duration_since(**at) < Duration::from_secs(1))
            .count() as u32;
        if recent >= max_qps {
            return false;
        }
    }
    if let Some(max_rpm) = max_rpm {
        let recent = state
            .recent_request_times
            .iter()
            .filter(|at| now.duration_since(**at) < Duration::from_secs(60))
            .count() as u32;
        if recent >= max_rpm {
            return false;
        }
    }
    true
}

fn mark_upstream_request_started(
    upstreams: &Arc<Mutex<HashMap<String, AggregateUpstreamRuntime>>>,
    base_url: &str,
) -> Instant {
    let now = Instant::now();
    let Ok(mut upstreams) = upstreams.lock() else {
        return now;
    };
    let state = upstreams
        .entry(base_url.to_string())
        .or_insert_with(|| AggregateUpstreamRuntime {
            recent_request_times: Vec::new(),
            in_flight: 0,
            cooldown_until: None,
        });
    state.in_flight = state.in_flight.saturating_add(1);
    state.recent_request_times.push(now);
    state
        .recent_request_times
        .retain(|at| now.duration_since(*at) < Duration::from_secs(60));
    now
}

fn mark_upstream_request_finished(
    upstreams: &Arc<Mutex<HashMap<String, AggregateUpstreamRuntime>>>,
    base_url: &str,
) {
    let Ok(mut upstreams) = upstreams.lock() else {
        return;
    };
    if let Some(state) = upstreams.get_mut(base_url) {
        state.in_flight = state.in_flight.saturating_sub(1);
    }
}

fn forget_upstream_recent_request(
    upstreams: &Arc<Mutex<HashMap<String, AggregateUpstreamRuntime>>>,
    base_url: &str,
    started_at: Instant,
) {
    let Ok(mut upstreams) = upstreams.lock() else {
        return;
    };
    if let Some(state) = upstreams.get_mut(base_url) {
        if let Some(index) = state
            .recent_request_times
            .iter()
            .rposition(|at| *at == started_at)
        {
            state.recent_request_times.remove(index);
        }
    }
}

fn clear_aggregate_upstream_cooldown(
    upstreams: &Arc<Mutex<HashMap<String, AggregateUpstreamRuntime>>>,
    base_url: &str,
) {
    let Ok(mut upstreams) = upstreams.lock() else {
        return;
    };
    if let Some(state) = upstreams.get_mut(base_url) {
        state.cooldown_until = None;
    }
}

fn upstream_limit_status(
    state: Option<&AggregateUpstreamRuntime>,
    item: &AggregateDeploymentRuntime,
    now: Instant,
) -> String {
    let Some(state) = state else {
        return "-".to_string();
    };
    if state.cooldown_until.is_some_and(|until| now < until) {
        return "冷却".to_string();
    }
    if state.in_flight >= item.max_concurrency {
        return "并发满".to_string();
    }
    let mut parts = Vec::new();
    if let Some(limit) = item.max_qps {
        let used = state
            .recent_request_times
            .iter()
            .filter(|at| now.duration_since(**at) < Duration::from_secs(1))
            .count();
        parts.push(format!("QPS {used}/{limit}"));
    }
    if let Some(limit) = item.max_rpm {
        let used = state
            .recent_request_times
            .iter()
            .filter(|at| now.duration_since(**at) < Duration::from_secs(60))
            .count();
        parts.push(format!("RPM {used}/{limit}"));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

fn latency_quality_penalty(latency_ms: f64) -> f64 {
    if latency_ms <= 1_000.0 {
        0.0
    } else if latency_ms <= 3_000.0 {
        (latency_ms - 1_000.0) / 2_000.0 * 10.0
    } else if latency_ms <= 10_000.0 {
        10.0 + (latency_ms - 3_000.0) / 7_000.0 * 20.0
    } else {
        30.0 + ((latency_ms - 10_000.0) / 10_000.0 * 20.0).min(20.0)
    }
}

fn find_body(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|chunk| chunk == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn trimmed(text: &str) -> Option<&str> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn url_encode_component(text: &str) -> String {
    let mut out = String::new();
    for byte in text.as_bytes() {
        let ch = *byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

fn default_enabled_fingerprints() -> Vec<AggregateFingerprint> {
    vec![
        AggregateFingerprint::Chrome132,
        AggregateFingerprint::Chrome133,
        AggregateFingerprint::Chrome134,
        AggregateFingerprint::Chrome135,
        AggregateFingerprint::Chrome136,
        AggregateFingerprint::Chrome137,
        AggregateFingerprint::Edge131,
        AggregateFingerprint::Edge134,
        AggregateFingerprint::Edge135,
        AggregateFingerprint::Edge136,
        AggregateFingerprint::Edge137,
        AggregateFingerprint::Firefox128,
        AggregateFingerprint::Firefox133,
        AggregateFingerprint::Firefox135,
        AggregateFingerprint::Firefox136,
        AggregateFingerprint::Firefox139,
    ]
}

fn default_recent_fingerprint_window() -> u32 {
    0
}

fn default_recent_fingerprint_ttl_seconds() -> u32 {
    0
}

fn default_clash_controller_url() -> String {
    "http://127.0.0.1:9097".to_string()
}

fn default_clash_proxy_url() -> String {
    "http://127.0.0.1:7897".to_string()
}

fn default_ip_switch_cooldown_seconds() -> u32 {
    0
}

fn default_recent_node_window() -> u32 {
    0
}

fn default_recent_node_ttl_seconds() -> u32 {
    0
}

fn default_persisted_key_score() -> f64 {
    80.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    fn seed(upstream: &str, base_url: &str, key: &str) -> AggregateDeploymentSeed {
        AggregateDeploymentSeed {
            upstream: upstream.to_string(),
            base_url: base_url.to_string(),
            public_model: "gpt-5.5".to_string(),
            actual_model: "gpt-5.5".to_string(),
            max_qps: None,
            max_rpm: None,
            max_concurrency: 1,
            upstream_cooldown_seconds: None,
            egress_note: String::new(),
            key: key.to_string(),
            key_label: format!("{}***{}", &key[..2], &key[key.len().saturating_sub(2)..]),
            quality_key: format!("{base_url}|{key}|gpt-5.5"),
        }
    }

    fn raw_request(body: &str) -> Vec<u8> {
        format!(
            "POST /v1/responses HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer local-key\r\nUser-Agent: Local/0\r\nAccept: application/x-local\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn invalid_encrypted_content_body() -> &'static str {
        r#"{"error":{"message":"The encrypted content gAAA... could not be verified. Reason: Encrypted content could not be decrypted or parsed.","type":"invalid_request_error","code":"invalid_encrypted_content"}}"#
    }

    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "client disconnected",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn aggregate_stream_reports_missing_completed_as_failure() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let _ = read_http_request(&mut socket).unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            socket
                .write_all(b"event: response.output_text.delta\ndata: {\"delta\":\"partial\"}\n\n")
                .unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-stream",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let mut out = Vec::new();

        let err = runtime
            .forward_stream_with_failover(
                &mut out,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/responses",
                1,
            )
            .unwrap_err();
        handle.join().unwrap();

        assert!(
            err.to_string()
                .contains("stream upstream closed before response.completed"),
            "{err}"
        );
        assert!(String::from_utf8(out).unwrap().contains("partial"));
        assert_eq!(runtime.snapshot().rows[0].failure_requests, 1);
    }

    #[test]
    fn aggregate_stream_does_not_retry_after_partial_body_error() {
        let first_upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_port = first_upstream.local_addr().unwrap().port();
        let first_handle = thread::spawn(move || {
            let (mut socket, _) = first_upstream.accept().unwrap();
            let _ = read_http_request(&mut socket).unwrap();
            let payload =
                b"event: response.output_text.delta\ndata: {\"delta\":\"FIRST_PARTIAL\"}\n\n";
            let response_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                payload.len()
            );
            socket.write_all(response_head.as_bytes()).unwrap();
            socket.write_all(payload).unwrap();
            socket.write_all(b"\r\nzz\r\n").unwrap();
            socket.flush().unwrap();
        });
        let second_upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        second_upstream.set_nonblocking(true).unwrap();
        let second_port = second_upstream.local_addr().unwrap().port();
        let second_handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                match second_upstream.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_nonblocking(false).unwrap();
                        let _ = read_http_request(&mut socket).unwrap();
                        socket
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                            )
                            .unwrap();
                        socket
                            .write_all(
                                b"event: response.output_text.delta\ndata: {\"delta\":\"SECOND_OK\"}\n\n",
                            )
                            .unwrap();
                        socket
                            .write_all(b"event: response.completed\ndata: {}\n\n")
                            .unwrap();
                        socket.flush().unwrap();
                        return true;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => panic!("accept failed: {err}"),
                }
            }
            false
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![
                seed(
                    "first",
                    &format!("http://127.0.0.1:{first_port}/v1"),
                    "sk-first",
                ),
                seed(
                    "second",
                    &format!("http://127.0.0.1:{second_port}/v1"),
                    "sk-second",
                ),
            ],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        {
            let mut deployments = runtime.deployments.lock().unwrap();
            deployments[1].stats.total_requests = 1;
            deployments[1].stats.success_requests = 1;
            deployments[1].stats.recalculate_score();
        }
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let mut out = Vec::new();

        let err = runtime
            .forward_stream_with_failover(
                &mut out,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/responses",
                2,
            )
            .unwrap_err();
        first_handle.join().unwrap();
        let retried_second = second_handle.join().unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(
            err.to_string()
                .contains("stream upstream interrupted after partial response"),
            "{err}"
        );
        assert!(text.contains("FIRST_PARTIAL"), "{text}");
        assert!(
            !retried_second && !text.contains("SECOND_OK"),
            "retrying after partial bytes corrupts the client stream: {text}"
        );
    }

    #[test]
    fn aggregate_stream_reports_done_only_responses_stream_as_failure() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let _ = read_http_request(&mut socket).unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            socket.write_all(b"data: [DONE]\n\n").unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-done-only",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let mut out = Vec::new();

        let err = runtime
            .forward_stream_with_failover(
                &mut out,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/responses",
                1,
            )
            .unwrap_err();
        handle.join().unwrap();

        assert!(
            err.to_string()
                .contains("stream upstream closed before response.completed"),
            "{err}"
        );
        assert!(String::from_utf8(out).unwrap().contains("[DONE]"));
    }

    #[test]
    fn aggregate_stream_accepts_chat_finish_reason_without_done_marker() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let _ = read_http_request(&mut socket).unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            socket
                .write_all(
                    concat!(
                        "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\n",
                        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-chat",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body =
            r#"{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}],"stream":true}"#;
        let mut out = Vec::new();

        runtime
            .forward_stream_with_failover(
                &mut out,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/chat/completions",
                1,
            )
            .unwrap();
        handle.join().unwrap();

        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\"finish_reason\":\"stop\""), "{text}");
        let row = &runtime.snapshot().rows[0];
        assert_eq!(row.success_requests, 1);
        assert_eq!(row.failure_requests, 0);
    }

    #[test]
    fn aggregate_stream_accepts_multiline_chat_finish_reason_without_done_marker() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let _ = read_http_request(&mut socket).unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            socket
                .write_all(
                    concat!(
                        "data: {\"choices\":[\n",
                        "data: {\"delta\":{},\"finish_reason\":\"stop\"}\n",
                        "data: ]}\n\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-chat",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body =
            r#"{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}],"stream":true}"#;
        let mut out = Vec::new();

        runtime
            .forward_stream_with_failover(
                &mut out,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/chat/completions",
                1,
            )
            .unwrap();
        handle.join().unwrap();

        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\"finish_reason\":\"stop\""), "{text}");
        let row = &runtime.snapshot().rows[0];
        assert_eq!(row.success_requests, 1);
        assert_eq!(row.failure_requests, 0);
    }

    #[test]
    fn aggregate_stream_counts_sse_failed_event_as_failure() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let _ = read_http_request(&mut socket).unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            socket
                .write_all(
                    concat!(
                        "event: response.failed\n",
                        "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"quota exhausted\"}}}\n\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-failed-event",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let mut out = Vec::new();

        let err = runtime
            .forward_stream_with_failover(
                &mut out,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/responses",
                1,
            )
            .unwrap_err();
        handle.join().unwrap();

        assert!(err.to_string().contains("quota exhausted"), "{err}");
        assert!(String::from_utf8(out).unwrap().contains("response.failed"));
        let row = &runtime.snapshot().rows[0];
        assert_eq!(row.success_requests, 0);
        assert_eq!(row.failure_requests, 1);
    }

    #[test]
    fn aggregate_stream_keeps_failed_terminal_state_when_completed_follows() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let _ = read_http_request(&mut socket).unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            socket
                .write_all(
                    concat!(
                        "event: response.failed\n",
                        "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"quota exhausted\"}}}\n\n",
                        "event: response.completed\n",
                        "data: {}\n\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-failed-then-completed",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let mut out = Vec::new();

        let err = runtime
            .forward_stream_with_failover(
                &mut out,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/responses",
                1,
            )
            .unwrap_err();
        handle.join().unwrap();

        assert!(err.to_string().contains("quota exhausted"), "{err}");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("response.failed"), "{text}");
        assert!(text.contains("response.completed"), "{text}");
        let row = &runtime.snapshot().rows[0];
        assert_eq!(row.success_requests, 0);
        assert_eq!(row.failure_requests, 1);
    }

    #[test]
    fn aggregate_stream_keeps_failed_terminal_state_when_failed_follows_completed() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let _ = read_http_request(&mut socket).unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            socket
                .write_all(
                    concat!(
                        "event: response.completed\n",
                        "data: {}\n\n",
                        "event: response.failed\n",
                        "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"late failure\"}}}\n\n",
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-completed-then-failed",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let mut out = Vec::new();

        let err = runtime
            .forward_stream_with_failover(
                &mut out,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/responses",
                1,
            )
            .unwrap_err();
        handle.join().unwrap();

        assert!(err.to_string().contains("late failure"), "{err}");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("response.completed"), "{text}");
        assert!(text.contains("response.failed"), "{text}");
        let row = &runtime.snapshot().rows[0];
        assert_eq!(row.success_requests, 0);
        assert_eq!(row.failure_requests, 1);
    }

    #[test]
    fn aggregate_stream_non_success_preserves_error_message() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let _ = read_http_request(&mut socket).unwrap();
            let body = r#"{"error":{"message":"quota exhausted","code":"insufficient_quota"}}"#;
            let response = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-stream",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let mut out = Vec::new();

        let err = runtime
            .forward_stream_with_failover(
                &mut out,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/responses",
                1,
            )
            .unwrap_err();
        handle.join().unwrap();

        let text = err.to_string();
        assert!(text.contains("aggregate upstream returned 400"), "{text}");
        assert!(text.contains("quota exhausted"), "{text}");
        assert!(out.is_empty());
    }

    #[test]
    fn aggregate_invalid_encrypted_content_response_does_not_retry_or_penalize_key() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let port = upstream.local_addr().unwrap().port();
        let (done_tx, done_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            while done_rx.try_recv().is_err() {
                match upstream.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_nonblocking(false).unwrap();
                        let raw = read_http_request(&mut socket).unwrap();
                        requests.push(String::from_utf8_lossy(&raw).to_string());
                        let body = invalid_encrypted_content_body();
                        let response = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        socket.write_all(response.as_bytes()).unwrap();
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("accept failed: {err}"),
                }
            }
            requests
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-bad-blob",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello"}"#;

        let response = runtime
            .forward_with_failover(
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/responses",
                2,
            )
            .unwrap();
        done_tx.send(()).unwrap();
        let requests = handle.join().unwrap();

        assert_eq!(response.status, 400);
        assert_eq!(requests.len(), 1);
        assert_eq!(runtime.snapshot().rows[0].failure_requests, 0);
    }

    #[test]
    fn aggregate_invalid_encrypted_content_does_not_block_immediate_stripped_retry() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(2);
            while requests.len() < 2 && Instant::now() < deadline {
                match upstream.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_nonblocking(false).unwrap();
                        let raw = read_http_request(&mut socket).unwrap();
                        requests.push(String::from_utf8_lossy(&raw).to_string());
                        if requests.len() == 1 {
                            let body = invalid_encrypted_content_body();
                            let response = format!(
                                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            socket.write_all(response.as_bytes()).unwrap();
                        } else {
                            let body = r#"{"output_text":"ok"}"#;
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            socket.write_all(response.as_bytes()).unwrap();
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => panic!("accept failed: {err}"),
                }
            }
            requests
        });
        let temp = tempfile::tempdir().unwrap();
        let mut seed = seed("dc", &format!("http://127.0.0.1:{port}/v1"), "sk-bad");
        seed.max_qps = Some(1);
        seed.max_rpm = Some(1);
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let bad_body = r#"{"model":"gpt-5.5","input":[{"type":"reasoning","encrypted_content":"bad-token"},{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}"#;
        let stripped_body = r#"{"model":"gpt-5.5","input":[{"type":"reasoning"},{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}"#;

        let first = runtime
            .forward_with_failover(
                &raw_request(bad_body),
                bad_body.as_bytes(),
                "POST",
                "/v1/responses",
                1,
            )
            .unwrap();
        assert_eq!(first.status, 400);
        let second = runtime
            .forward_with_failover(
                &raw_request(stripped_body),
                stripped_body.as_bytes(),
                "POST",
                "/v1/responses",
                1,
            )
            .unwrap();
        let requests = handle.join().unwrap();

        assert_eq!(second.status, 200);
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("encrypted_content"));
        assert!(!requests[1].contains("encrypted_content"));
    }

    #[test]
    fn aggregate_stream_invalid_encrypted_content_does_not_retry_or_penalize_key() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let port = upstream.local_addr().unwrap().port();
        let (done_tx, done_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            while done_rx.try_recv().is_err() {
                match upstream.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_nonblocking(false).unwrap();
                        let raw = read_http_request(&mut socket).unwrap();
                        requests.push(String::from_utf8_lossy(&raw).to_string());
                        let body = invalid_encrypted_content_body();
                        let response = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        socket.write_all(response.as_bytes()).unwrap();
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("accept failed: {err}"),
                }
            }
            requests
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-bad-stream",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let mut out = Vec::new();

        let err = runtime
            .forward_stream_with_failover(
                &mut out,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/responses",
                2,
            )
            .unwrap_err();
        done_tx.send(()).unwrap();
        let requests = handle.join().unwrap();

        let text = err.to_string();
        assert!(text.contains("encrypted content"), "{text}");
        assert_eq!(requests.len(), 1);
        assert!(out.is_empty());
        assert_eq!(runtime.snapshot().rows[0].failure_requests, 0);
    }

    #[test]
    fn aggregate_stream_local_disconnect_does_not_retry_or_penalize_key() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let port = upstream.local_addr().unwrap().port();
        let (done_tx, done_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            while done_rx.try_recv().is_err() {
                match upstream.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_nonblocking(false).unwrap();
                        let raw = read_http_request(&mut socket).unwrap();
                        requests.push(String::from_utf8_lossy(&raw).to_string());
                        socket
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                            .unwrap();
                        socket
                            .write_all(b"event: response.completed\ndata: {}\n\n")
                            .unwrap();
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("accept failed: {err}"),
                }
            }
            requests
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed(
                "dc",
                &format!("http://127.0.0.1:{port}/v1"),
                "sk-local-disconnect",
            )],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let mut writer = BrokenPipeWriter;

        let err = runtime
            .forward_stream_with_failover(
                &mut writer,
                &raw_request(body),
                body.as_bytes(),
                "POST",
                "/v1/responses",
                2,
            )
            .unwrap_err();
        done_tx.send(()).unwrap();
        let requests = handle.join().unwrap();

        assert!(err.to_string().contains("client disconnected"), "{err}");
        assert_eq!(requests.len(), 1);
        assert_eq!(runtime.snapshot().rows[0].failure_requests, 0);
    }

    #[test]
    fn aggregate_egress_rotates_key_and_fingerprint_after_non_2xx() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for status in [429_u16, 200_u16] {
                let (mut socket, _) = upstream.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let raw = read_http_request(&mut socket).unwrap();
                requests.push(String::from_utf8_lossy(&raw).to_string());
                let body = if status == 200 {
                    r#"{"output_text":"ok"}"#
                } else {
                    r#"{"error":"cooldown"}"#
                };
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    status,
                    if status == 200 { "OK" } else { "Too Many Requests" },
                    body.len()
                );
                socket.write_all(response.as_bytes()).unwrap();
            }
            requests
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![
                    AggregateFingerprint::Chrome132,
                    AggregateFingerprint::Firefox128,
                ],
                recent_fingerprint_window: 2,
                recent_fingerprint_ttl_seconds: 300,
            },
            vec![
                seed("dc", &format!("http://127.0.0.1:{port}/v1"), "sk-first"),
                seed("dc", &format!("http://127.0.0.1:{port}/v1"), "sk-second"),
            ],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        {
            let mut deployments = runtime.deployments.lock().unwrap();
            deployments[1].stats.total_requests = 1;
            deployments[1].stats.success_requests = 1;
            deployments[1].stats.recalculate_score();
        }
        {
            let mut fingerprints = runtime.fingerprints.lock().unwrap();
            fingerprints[1].stats.total_requests = 1;
            fingerprints[1].stats.success_requests = 1;
            fingerprints[1].stats.recalculate_score();
        }
        let body = r#"{"model":"gpt-5.5","input":"hello"}"#;
        let first = runtime
            .forward_once(&raw_request(body), body.as_bytes(), "POST", "/v1/responses")
            .unwrap();
        let second = runtime
            .forward_once(&raw_request(body), body.as_bytes(), "POST", "/v1/responses")
            .unwrap();

        assert_eq!(first.status, 429);
        assert_eq!(second.status, 200);
        let requests = handle.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("authorization: Bearer sk-first"));
        assert!(requests[1].contains("authorization: Bearer sk-second"));
        let lowered_first = requests[0].to_ascii_lowercase();
        let lowered_second = requests[1].to_ascii_lowercase();
        assert!(lowered_first.contains("chrome/132"));
        assert!(lowered_second.contains("firefox/128"));
        assert!(!lowered_first.contains("Local/0"));
        assert!(!lowered_second.contains("Local/0"));
    }

    #[test]
    fn aggregate_runtime_registry_normalizes_base_url() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = Arc::new(
            AggregateEgressRuntime::new(
                AggregateEgressConfig {
                    enabled: true,
                    ..AggregateEgressConfig::default()
                },
                vec![seed("dc", "http://127.0.0.1:1/v1", "sk-first")],
                temp.path().join("quality.json"),
                None,
                35,
            )
            .unwrap(),
        );
        register_runtime("http://127.0.0.1:4000/v1/", &runtime).unwrap();

        let loaded = lookup_runtime("http://127.0.0.1:4000/v1").unwrap();
        assert!(Arc::ptr_eq(&runtime, &loaded));

        unregister_runtime("http://127.0.0.1:4000/v1/");
        assert!(lookup_runtime("http://127.0.0.1:4000/v1").is_none());
    }

    #[test]
    fn aggregate_upstream_url_preserves_v1_base_when_client_sends_endpoint_path() {
        let url = upstream_url("https://api.example.test/v1", "/responses").unwrap();

        assert_eq!(url, "https://api.example.test/v1/responses");
    }

    #[test]
    fn aggregate_upstream_url_deduplicates_v1_when_client_sends_full_path() {
        let url = upstream_url("https://api.example.test/v1", "/v1/responses").unwrap();

        assert_eq!(url, "https://api.example.test/v1/responses");
    }

    #[test]
    fn aggregate_local_client_io_failures_do_not_poison_upstream_quality() {
        let would_block = anyhow!(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        assert!(should_suppress_local_failure_response(&would_block));

        let timed_out = anyhow!(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert!(should_suppress_local_failure_response(&timed_out));

        let invalid_request = anyhow!(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        assert!(!should_suppress_local_failure_response(&invalid_request));
    }

    #[test]
    fn aggregate_success_clears_deployment_and_upstream_cooldown() {
        let temp = tempfile::tempdir().unwrap();
        let base_url = "https://cooldown.example/v1";
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                ..AggregateEgressConfig::default()
            },
            vec![seed("dc", base_url, "sk-first")],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        {
            let mut deployments = runtime.deployments.lock().unwrap();
            deployments[0].stats.cooldown_until = Some(Instant::now() + Duration::from_secs(60));
        }
        {
            let mut upstreams = runtime.upstreams.lock().unwrap();
            upstreams.insert(
                base_url.to_string(),
                AggregateUpstreamRuntime {
                    recent_request_times: Vec::new(),
                    in_flight: 0,
                    cooldown_until: Some(Instant::now() + Duration::from_secs(60)),
                },
            );
        }
        let combo = AggregateEgressCombo {
            node: None,
            fingerprint: AggregateFingerprint::Chrome132,
        };

        runtime.record_success(0, 0, &combo, Duration::from_millis(10));

        assert!(runtime.deployments.lock().unwrap()[0]
            .stats
            .cooldown_until
            .is_none());
        assert!(runtime
            .upstreams
            .lock()
            .unwrap()
            .get(base_url)
            .is_some_and(|state| state.cooldown_until.is_none()));
    }

    #[test]
    fn aggregate_selection_uses_direct_offset_lookup() {
        let source = include_str!("aggregate_egress.rs");
        let deployment_block = source
            .split("fn select_deployment(")
            .nth(1)
            .and_then(|tail| tail.split("fn select_fingerprint").next())
            .expect("deployment selection block should be discoverable");
        let fingerprint_block = source
            .split("fn select_fingerprint(&self)")
            .nth(1)
            .and_then(|tail| tail.split("fn select_combo_fingerprint").next())
            .expect("fingerprint selection block should be discoverable");

        assert!(deployment_block.contains(".get(offset)"));
        assert!(fingerprint_block.contains(".get(offset)"));
        assert!(!deployment_block.contains(".cycle()"));
        assert!(!fingerprint_block.contains(".cycle()"));
    }

    #[test]
    fn aggregate_selection_rotates_all_keys_and_fingerprints_even_with_score_gap() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![
                    AggregateFingerprint::Chrome132,
                    AggregateFingerprint::Firefox128,
                ],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![
                seed("dc", "http://upstream.example/v1", "sk-first"),
                seed("dc", "http://upstream.example/v1", "sk-second"),
            ],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        {
            let mut deployments = runtime.deployments.lock().unwrap();
            deployments[0].stats.total_requests = 4;
            deployments[0].stats.score = 100.0;
            deployments[1].stats.total_requests = 4;
            deployments[1].stats.score = 10.0;
        }
        {
            let mut fingerprints = runtime.fingerprints.lock().unwrap();
            fingerprints[0].stats.total_requests = 4;
            fingerprints[0].stats.score = 100.0;
            fingerprints[1].stats.total_requests = 4;
            fingerprints[1].stats.score = 10.0;
        }

        let first_key = runtime.select_deployment("gpt-5.5").unwrap().1.key;
        let second_key = runtime.select_deployment("gpt-5.5").unwrap().1.key;
        let first_fingerprint = runtime.select_fingerprint().unwrap().1.fingerprint;
        let second_fingerprint = runtime.select_fingerprint().unwrap().1.fingerprint;

        assert_ne!(first_key, second_key);
        assert_ne!(first_fingerprint, second_fingerprint);
    }

    #[test]
    fn aggregate_failure_prefers_combo_with_different_cached_egress_ip() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 3,
                recent_fingerprint_ttl_seconds: 300,
            },
            vec![seed("dc", "http://upstream.example/v1", "sk-first")],
            temp.path().join("quality.json"),
            Some(AggregateClashConfig {
                enabled: true,
                controller_url: String::new(),
                proxy_url: "http://127.0.0.1:7897".to_string(),
                secret: String::new(),
                group_name: String::new(),
                ip_switch_cooldown_seconds: 0,
                recent_node_window: 3,
                recent_node_ttl_seconds: 300,
            }),
            35,
        )
        .unwrap();
        {
            let mut state = runtime.combos.lock().unwrap();
            state.combos = vec![
                AggregateEgressCombo {
                    node: Some("node-a".to_string()),
                    fingerprint: AggregateFingerprint::Chrome132,
                },
                AggregateEgressCombo {
                    node: Some("node-b".to_string()),
                    fingerprint: AggregateFingerprint::Chrome132,
                },
                AggregateEgressCombo {
                    node: Some("node-c".to_string()),
                    fingerprint: AggregateFingerprint::Chrome132,
                },
            ];
            state.current_index = 0;
            state.next_index = 0;
            state.recent.clear();
        }
        {
            let now = Instant::now();
            let mut cache = runtime.request_egress_ip_cache.lock().unwrap();
            cache.insert(
                "http://127.0.0.1:7897\nnode-a".to_string(),
                ("198.51.100.1".to_string(), now),
            );
            cache.insert(
                "http://127.0.0.1:7897\nnode-b".to_string(),
                ("198.51.100.1".to_string(), now),
            );
            cache.insert(
                "http://127.0.0.1:7897\nnode-c".to_string(),
                ("198.51.100.2".to_string(), now),
            );
        }
        let failed = AggregateEgressCombo {
            node: Some("node-a".to_string()),
            fingerprint: AggregateFingerprint::Chrome132,
        };

        let next = runtime.advance_combo_after_failure(&failed).unwrap();

        assert_eq!(next.node.as_deref(), Some("node-c"));
    }

    #[test]
    fn aggregate_quality_writer_keeps_pending_on_save_failure() {
        let source = include_str!("aggregate_egress.rs");
        let block = source
            .split("impl QualityWriteHandle")
            .nth(1)
            .and_then(|tail| tail.split("impl AggregateClashController").next())
            .expect("quality writer block should be discoverable");

        assert!(block.contains("flush_quality_pending"));
        assert!(!block.contains("let _ = store.save"));
        assert!(source.contains("if store.save(path).is_ok()"));
        assert!(source.contains("for _ in 0..attempts.max(1)"));
        assert!(source.contains("const QUALITY_FLUSH_ATTEMPTS: usize = 40"));
    }

    #[test]
    fn aggregate_quality_writer_fast_flush_is_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let blocked_parent = temp.path().join("blocked-parent");
        fs::write(&blocked_parent, "not a directory").unwrap();
        let writer = QualityWriteHandle::new(blocked_parent.join("quality.json"));
        writer.persist("key-a".to_string(), PersistedKeyQuality::default());

        let started = Instant::now();
        writer.flush_with_timeout(Duration::from_millis(80), 1);

        assert!(
            started.elapsed() < Duration::from_millis(500),
            "fast aggregate quality flush must not wait for the full retry window"
        );
    }

    #[test]
    fn aggregate_request_hot_path_reuses_tokio_runtime() {
        let source = include_str!("aggregate_egress.rs");
        let runtime_struct = source
            .split("pub struct AggregateEgressRuntime")
            .nth(1)
            .and_then(|tail| tail.split("struct AggregateDeploymentRuntime").next())
            .expect("aggregate runtime struct should be discoverable");
        let new_block = source
            .split("pub fn new(")
            .nth(1)
            .and_then(|tail| tail.split("pub fn forward_once").next())
            .expect("aggregate runtime new block should be discoverable");
        let request_struct = source
            .split("struct EmulatedRequest")
            .nth(1)
            .and_then(|tail| tail.split("fn send_emulated_request").next())
            .expect("aggregate emulated request struct should be discoverable");
        let send_block = source
            .split("fn send_emulated_request")
            .nth(1)
            .and_then(|tail| tail.split("fn stream_emulated_request").next())
            .expect("aggregate send block should be discoverable");
        let stream_block = source
            .split("fn stream_emulated_request")
            .nth(1)
            .and_then(|tail| tail.split("fn write_sse_heartbeat").next())
            .expect("aggregate stream block should be discoverable");

        assert!(runtime_struct.contains("tokio_runtime: Runtime"));
        assert!(new_block.contains("tokio_runtime: Runtime::new()?"));
        assert!(request_struct.contains("runtime: &'a Runtime"));
        assert!(!send_block.contains("Runtime::new()"));
        assert!(!stream_block.contains("Runtime::new()"));
        assert!(send_block.contains("request.runtime.block_on"));
        assert!(stream_block.contains("request.runtime.block_on"));
    }

    #[test]
    fn aggregate_combos_exclude_unusable_clash_nodes_from_history() {
        let controller_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = controller_server.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            for _ in 0..3 {
                let (mut socket, _) = controller_server.accept().unwrap();
                let raw = read_http_request(&mut socket).unwrap();
                let request = String::from_utf8_lossy(&raw);
                let body = if request.starts_with("GET /proxies/%E8%87%AA%E5%8A%A8") {
                    r#"{"now":"node-good","all":["node-good","node-dead"]}"#
                } else if request.starts_with("GET /proxies/node-good") {
                    r#"{"history":[{"delay":120}]}"#
                } else {
                    r#"{"history":[{"delay":0}]}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).unwrap();
            }
        });
        let controller = AggregateClashController::new(AggregateClashConfig {
            enabled: true,
            controller_url: format!("http://127.0.0.1:{port}"),
            proxy_url: String::new(),
            secret: String::new(),
            group_name: "自动选择".to_string(),
            ip_switch_cooldown_seconds: 0,
            recent_node_window: 0,
            recent_node_ttl_seconds: 0,
        })
        .unwrap();

        let combos = build_egress_combos(&[AggregateFingerprint::Chrome132], Some(&controller));

        handle.join().unwrap();
        assert_eq!(
            combos,
            vec![AggregateEgressCombo {
                node: Some("node-good".to_string()),
                fingerprint: AggregateFingerprint::Chrome132,
            }]
        );
    }

    #[test]
    fn aggregate_selected_combo_switches_clash_node_before_request() {
        let controller_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = controller_server.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..5 {
                let (mut socket, _) = controller_server.accept().unwrap();
                let raw = read_http_request(&mut socket).unwrap();
                let request = String::from_utf8_lossy(&raw).to_string();
                let body = if request.starts_with("GET /proxies/%E8%87%AA%E5%8A%A8") {
                    r#"{"now":"node-a","all":["node-a","node-b"]}"#
                } else if request.starts_with("GET /proxies/node-a")
                    || request.starts_with("GET /proxies/node-b")
                {
                    r#"{"history":[{"delay":120}]}"#
                } else {
                    r#"{"ok":true}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).unwrap();
                requests.push(request);
            }
            requests
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 1,
                recent_fingerprint_ttl_seconds: 300,
            },
            vec![seed("dc", "http://upstream.example/v1", "sk-first")],
            temp.path().join("quality.json"),
            Some(AggregateClashConfig {
                enabled: true,
                controller_url: format!("http://127.0.0.1:{port}"),
                proxy_url: String::new(),
                secret: String::new(),
                group_name: "自动选择".to_string(),
                ip_switch_cooldown_seconds: 0,
                recent_node_window: 1,
                recent_node_ttl_seconds: 300,
            }),
            35,
        )
        .unwrap();

        let first = runtime.select_combo().unwrap();
        runtime.activate_combo_node(&first);
        runtime.remember_combo(&first);
        let second = runtime.select_combo().unwrap();
        runtime.activate_combo_node(&second);

        let requests = handle.join().unwrap();
        assert_eq!(first.node.as_deref(), Some("node-a"));
        assert_eq!(second.node.as_deref(), Some("node-b"));
        assert!(requests.iter().any(|request| request
            .starts_with("PUT /proxies/%E8%87%AA%E5%8A%A8")
            && request.contains(r#""name":"node-a""#)));
        assert!(requests.iter().any(|request| request
            .starts_with("PUT /proxies/%E8%87%AA%E5%8A%A8")
            && request.contains(r#""name":"node-b""#)));
    }

    #[test]
    fn aggregate_force_switch_bypasses_ip_switch_cooldown() {
        let controller_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = controller_server.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut socket, _) = controller_server.accept().unwrap();
                let raw = read_http_request(&mut socket).unwrap();
                let request = String::from_utf8_lossy(&raw).to_string();
                let body = r#"{"ok":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).unwrap();
                requests.push(request);
            }
            requests
        });
        let controller = AggregateClashController::new(AggregateClashConfig {
            enabled: true,
            controller_url: format!("http://127.0.0.1:{port}"),
            proxy_url: String::new(),
            secret: String::new(),
            group_name: "自动选择".to_string(),
            ip_switch_cooldown_seconds: 3600,
            recent_node_window: 0,
            recent_node_ttl_seconds: 0,
        })
        .unwrap();

        controller
            .switch_to_node("自动选择", "node-a")
            .expect("first switch should be sent");
        controller
            .switch_to_node_force("自动选择", "node-b")
            .expect("forced switch should bypass cooldown");

        let requests = handle.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains(r#""name":"node-a""#));
        assert!(requests[1].contains(r#""name":"node-b""#));
    }

    #[test]
    fn aggregate_forced_combo_activation_clears_cached_node_egress_ip() {
        let controller_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = controller_server.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..4 {
                let (mut socket, _) = controller_server.accept().unwrap();
                let raw = read_http_request(&mut socket).unwrap();
                let request = String::from_utf8_lossy(&raw).to_string();
                let body = if request.starts_with("GET /proxies/%E8%87%AA%E5%8A%A8") {
                    r#"{"now":"node-a","all":["node-a","node-b"]}"#
                } else if request.starts_with("GET /proxies/node-a")
                    || request.starts_with("GET /proxies/node-b")
                {
                    r#"{"history":[{"delay":120}]}"#
                } else {
                    r#"{"ok":true}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).unwrap();
                requests.push(request);
            }
            requests
        });
        let temp = tempfile::tempdir().unwrap();
        let proxy_url = "http://127.0.0.1:7897".to_string();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                fingerprints: vec![AggregateFingerprint::Chrome132],
                recent_fingerprint_window: 0,
                recent_fingerprint_ttl_seconds: 0,
            },
            vec![seed("dc", "http://upstream.example/v1", "sk-first")],
            temp.path().join("quality.json"),
            Some(AggregateClashConfig {
                enabled: true,
                controller_url: format!("http://127.0.0.1:{port}"),
                proxy_url: proxy_url.clone(),
                secret: String::new(),
                group_name: "自动选择".to_string(),
                ip_switch_cooldown_seconds: 3600,
                recent_node_window: 0,
                recent_node_ttl_seconds: 0,
            }),
            35,
        )
        .unwrap();
        let combo = AggregateEgressCombo {
            node: Some("node-b".to_string()),
            fingerprint: AggregateFingerprint::Chrome132,
        };
        let cache_key = format!("{proxy_url}\nnode-b");
        runtime.request_egress_ip_cache.lock().unwrap().insert(
            cache_key.clone(),
            ("198.51.100.9".to_string(), Instant::now()),
        );

        runtime.activate_combo_node(&combo);

        let requests = handle.join().unwrap();
        assert!(requests
            .iter()
            .any(|request| request.contains(r#""name":"node-b""#)));
        assert!(!runtime
            .request_egress_ip_cache
            .lock()
            .unwrap()
            .contains_key(&cache_key));
    }

    #[test]
    fn aggregate_snapshot_uses_request_time_proxy_egress_without_group() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = proxy.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut socket, _) = proxy.accept().unwrap();
                let raw = read_http_request(&mut socket).unwrap();
                let request = String::from_utf8_lossy(&raw).to_string();
                let body = if request.starts_with("GET http://api.ipify.org/") {
                    "203.0.113.11".to_string()
                } else {
                    r#"{"output_text":"ok"}"#.to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).unwrap();
                requests.push(request);
            }
            requests
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                ..AggregateEgressConfig::default()
            },
            vec![seed("dc", "http://upstream.example/v1", "sk-first")],
            temp.path().join("quality.json"),
            Some(AggregateClashConfig {
                enabled: true,
                controller_url: String::new(),
                proxy_url: format!("http://127.0.0.1:{port}"),
                secret: String::new(),
                group_name: String::new(),
                ip_switch_cooldown_seconds: 0,
                recent_node_window: 0,
                recent_node_ttl_seconds: 0,
            }),
            35,
        )
        .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello"}"#;

        let response = runtime
            .forward_once(&raw_request(body), body.as_bytes(), "POST", "/v1/responses")
            .unwrap();
        let snapshot = runtime.snapshot();

        let requests = handle.join().unwrap();
        assert_eq!(response.status, 200);
        assert!(requests[0].starts_with("GET http://api.ipify.org/"));
        assert!(requests[1].starts_with("POST http://upstream.example/v1/responses"));
        assert_eq!(snapshot.rows[0].recent_clash_node, "");
        assert_eq!(snapshot.rows[0].recent_clash_egress_ip, "203.0.113.11");
        assert_eq!(snapshot.rows[0].base_url, "http://upstream.example/v1");
    }

    #[test]
    fn aggregate_snapshot_keeps_request_egress_per_key_row() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                ..AggregateEgressConfig::default()
            },
            vec![
                seed("dc", "http://upstream-a.example/v1", "sk-first"),
                seed("dc", "http://upstream-b.example/v1", "sk-second"),
            ],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        {
            let mut deployments = runtime.deployments.lock().unwrap();
            deployments[0].last_request_egress = Some(AggregateRequestEgress {
                node: Some("node-a".to_string()),
                ip: Some("203.0.113.21".to_string()),
                seen_at: Instant::now(),
            });
            deployments[1].last_request_egress = Some(AggregateRequestEgress {
                node: Some("node-b".to_string()),
                ip: Some("203.0.113.22".to_string()),
                seen_at: Instant::now(),
            });
        }

        let snapshot = runtime.snapshot();

        let first = snapshot
            .rows
            .iter()
            .find(|row| row.base_url == "http://upstream-a.example/v1")
            .unwrap();
        let second = snapshot
            .rows
            .iter()
            .find(|row| row.base_url == "http://upstream-b.example/v1")
            .unwrap();
        assert_eq!(first.recent_clash_node, "node-a");
        assert_eq!(first.recent_clash_egress_ip, "203.0.113.21");
        assert_eq!(second.recent_clash_node, "node-b");
        assert_eq!(second.recent_clash_egress_ip, "203.0.113.22");
    }

    #[test]
    fn aggregate_snapshot_does_not_copy_global_egress_to_unused_key_rows() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                ..AggregateEgressConfig::default()
            },
            vec![
                seed("dc", "http://upstream-a.example/v1", "sk-first"),
                seed("dc", "http://upstream-b.example/v1", "sk-second"),
            ],
            temp.path().join("quality.json"),
            None,
            35,
        )
        .unwrap();
        {
            let egress = AggregateRequestEgress {
                node: Some("node-a".to_string()),
                ip: Some("203.0.113.21".to_string()),
                seen_at: Instant::now(),
            };
            runtime.deployments.lock().unwrap()[0].last_request_egress = Some(egress.clone());
            *runtime.last_request_egress.lock().unwrap() = Some(egress);
        }

        let snapshot = runtime.snapshot();

        let unused = snapshot
            .rows
            .iter()
            .find(|row| row.base_url == "http://upstream-b.example/v1")
            .unwrap();
        assert_eq!(unused.recent_clash_node, "");
        assert_eq!(unused.recent_clash_egress_ip, "");
    }

    #[test]
    fn aggregate_request_egress_cache_is_scoped_by_clash_node() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = proxy.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            for body in ["203.0.113.31", "203.0.113.32"] {
                let (mut socket, _) = proxy.accept().unwrap();
                let _ = read_http_request(&mut socket).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).unwrap();
            }
        });
        let temp = tempfile::tempdir().unwrap();
        let runtime = AggregateEgressRuntime::new(
            AggregateEgressConfig {
                enabled: true,
                ..AggregateEgressConfig::default()
            },
            vec![seed("dc", "http://upstream.example/v1", "sk-first")],
            temp.path().join("quality.json"),
            Some(AggregateClashConfig {
                enabled: true,
                controller_url: String::new(),
                proxy_url: format!("http://127.0.0.1:{port}"),
                secret: String::new(),
                group_name: String::new(),
                ip_switch_cooldown_seconds: 0,
                recent_node_window: 0,
                recent_node_ttl_seconds: 0,
            }),
            35,
        )
        .unwrap();
        let proxy_url = format!("http://127.0.0.1:{port}");

        let first = runtime.request_proxy_egress_ip(&proxy_url, Some("node-a"));
        let second = runtime.request_proxy_egress_ip(&proxy_url, Some("node-b"));

        handle.join().unwrap();
        assert_eq!(first.as_deref(), Some("203.0.113.31"));
        assert_eq!(second.as_deref(), Some("203.0.113.32"));
    }

    fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut raw = Vec::new();
        let mut buffer = [0_u8; 8192];
        let mut body_start = None;
        let mut content_length = 0usize;
        loop {
            let size = stream.read(&mut buffer)?;
            if size == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..size]);
            if body_start.is_none() {
                if let Some(index) = find_body(&raw) {
                    body_start = Some(index);
                    content_length = parse_content_length(&raw[..index]).unwrap_or(0);
                }
            }
            if let Some(index) = body_start {
                if raw.len().saturating_sub(index) >= content_length {
                    break;
                }
            }
            if raw.len() > 16 * 1024 * 1024 {
                return Err(anyhow!("request too large"));
            }
        }
        Ok(raw)
    }

    fn parse_content_length(headers: &[u8]) -> Option<usize> {
        let text = String::from_utf8_lossy(headers);
        for line in text.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if key.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
        None
    }
}
