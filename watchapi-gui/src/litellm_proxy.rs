#![allow(clippy::too_many_arguments)]

use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST,
    TRANSFER_ENCODING,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use watchapi_core::aggregate_egress::{
    register_runtime, unregister_runtime, AggregateClashConfig, AggregateDeploymentSeed,
    AggregateEgressConfig, AggregateEgressRuntime, AggregateFingerprint,
};

const MIN_KEY_EXPLORATION_REQUESTS: u64 = 2;
const KEY_QUALITY_DOMINANCE_MARGIN: f64 = 12.0;
const SMART_PROXY_RETRYABLE_MIN_ATTEMPTS: u32 = 6;
const SMART_PROXY_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SMART_PROXY_UPSTREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const LOCAL_HTTP_REQUEST_MAX_BYTES: usize = 16 * 1024 * 1024;
const SMART_PROXY_MAX_ACTIVE_CLIENTS: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ProxyRegistry {
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyConfig {
    pub name: String,
    #[serde(default = "default_host")]
    pub host: String,
    pub port: u16,
    #[serde(default = "default_master_key")]
    pub master_key: String,
    #[serde(default = "default_litellm_command")]
    pub litellm_command: String,
    #[serde(default)]
    pub engine: ProxyEngine,
    #[serde(default = "default_sticky_keys")]
    pub sticky_keys: bool,
    #[serde(default = "default_router_cooldown_seconds")]
    pub router_cooldown_seconds: u32,
    #[serde(default)]
    pub router_allowed_fails: u32,
    #[serde(default)]
    pub router_num_retries: u32,
    #[serde(default)]
    pub clash_verge: ClashVergeConfig,
    #[serde(default)]
    pub aggregate_egress: SharedAggregateEgressConfig,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashVergeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_clash_verge_controller_url")]
    pub controller_url: String,
    #[serde(default = "default_clash_verge_proxy_url")]
    pub proxy_url: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub group_name: String,
    #[serde(default = "default_rotate_ip_on_key_failure")]
    pub rotate_ip_on_key_failure: bool,
    #[serde(default = "default_rotate_ip_on_rate_limit")]
    pub rotate_ip_on_rate_limit: bool,
    #[serde(default = "default_ip_switch_cooldown_seconds")]
    pub ip_switch_cooldown_seconds: u32,
    #[serde(default = "default_recent_node_window")]
    pub recent_node_window: u32,
    #[serde(default = "default_recent_node_ttl_seconds")]
    pub recent_node_ttl_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedAggregateEgressConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_shared_aggregate_fingerprints")]
    pub fingerprints: Vec<AggregateFingerprint>,
    #[serde(default = "default_recent_fingerprint_window")]
    pub recent_fingerprint_window: u32,
    #[serde(default = "default_recent_fingerprint_ttl_seconds")]
    pub recent_fingerprint_ttl_seconds: u32,
}

impl Default for SharedAggregateEgressConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fingerprints: default_shared_aggregate_fingerprints(),
            recent_fingerprint_window: default_recent_fingerprint_window(),
            recent_fingerprint_ttl_seconds: default_recent_fingerprint_ttl_seconds(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyEngine {
    #[default]
    Smart,
    LiteLlm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub name: String,
    pub base_url: String,
    #[serde(default)]
    pub provider_prefix: String,
    #[serde(default)]
    pub max_qps: Option<u32>,
    #[serde(default)]
    pub max_rpm: Option<u32>,
    #[serde(default = "default_upstream_concurrency")]
    pub max_concurrency: u32,
    #[serde(default)]
    pub cooldown_seconds: Option<u32>,
    #[serde(default)]
    pub egress_note: String,
    #[serde(default)]
    pub key_batches: Vec<KeyBatchConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyBatchConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub format: KeyBatchFormat,
    #[serde(default)]
    pub rpm: Option<u32>,
    #[serde(default)]
    pub tpm: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyBatchFormat {
    #[default]
    Txt,
    Csv,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    pub public_model: String,
    #[serde(default)]
    pub actual_model: String,
    #[serde(default)]
    pub upstreams: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub key: String,
    pub rpm: Option<u32>,
    pub tpm: Option<u32>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySummary {
    pub upstream_count: usize,
    pub route_count: usize,
    pub key_count: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SmartProxySnapshot {
    pub rows: Vec<SmartProxyKeyRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SmartProxyKeyRow {
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

impl SmartProxyKeyRow {
    pub fn egress_display_text(&self) -> String {
        if let Some(node) = non_empty_trimmed(&self.recent_clash_node) {
            if let Some(ip) = non_empty_trimmed(&self.recent_clash_egress_ip) {
                return format!("{node} / {ip}");
            }
            return node.to_string();
        }
        if let Some(ip) = non_empty_trimmed(&self.recent_clash_egress_ip) {
            return ip.to_string();
        }
        non_empty_trimmed(&self.egress_note)
            .or_else(|| non_empty_trimmed(&self.base_url))
            .unwrap_or("-")
            .to_string()
    }

    pub fn egress_hover_text(&self) -> String {
        format!(
            "上游名：{}\nBase URL：{}\n最近 Clash 节点：{}\nClash 出口 IP：{}\n出口备注：{}",
            non_empty_trimmed(&self.upstream).unwrap_or("-"),
            non_empty_trimmed(&self.base_url).unwrap_or("-"),
            non_empty_trimmed(&self.recent_clash_node).unwrap_or("-"),
            non_empty_trimmed(&self.recent_clash_egress_ip).unwrap_or("-"),
            non_empty_trimmed(&self.egress_note).unwrap_or("-")
        )
    }
}

#[derive(Debug, Clone)]
struct SmartDeployment {
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
    stats: SmartKeyStats,
}

#[derive(Debug, Clone)]
struct SmartKeyStats {
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
struct SmartUpstreamRuntime {
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

#[derive(Debug)]
enum QualityWriteCommand {
    Write(QualityWrite),
    #[allow(dead_code)]
    Flush(Sender<()>),
}

#[derive(Debug)]
struct ClashVergeController {
    config: ClashVergeConfig,
    client: Client,
    last_switch_at: Mutex<Option<Instant>>,
    group_rotations: Mutex<HashMap<String, usize>>,
    recent_nodes: Mutex<HashMap<String, Vec<(String, Instant)>>>,
    egress_ip_cache: Mutex<HashMap<String, (String, Instant)>>,
}

impl Default for SmartKeyStats {
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

impl SmartKeyStats {
    fn observe_latency(&mut self, latency: Duration) {
        let millis = latency.as_secs_f64() * 1000.0;
        self.latency_ema_ms = Some(match self.latency_ema_ms {
            Some(previous) => previous * 0.75 + millis * 0.25,
            None => millis,
        });
    }

    fn recalculate_score(&mut self) {
        let success_rate = if self.total_requests == 0 {
            1.0
        } else {
            self.success_requests as f64 / self.total_requests as f64
        };
        let latency_penalty = self
            .latency_ema_ms
            .map(latency_quality_penalty)
            .unwrap_or(0.0);
        let failure_penalty = (self.consecutive_failures as f64 * 8.0).min(30.0);
        let volume_confidence = (self.total_requests as f64).min(50.0) / 50.0;
        let confidence_bonus = volume_confidence * 6.0;
        self.score = (success_rate * 100.0 - latency_penalty - failure_penalty + confidence_bonus)
            .clamp(0.0, 100.0);
    }
}

impl Default for ClashVergeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            controller_url: default_clash_verge_controller_url(),
            proxy_url: default_clash_verge_proxy_url(),
            secret: String::new(),
            group_name: String::new(),
            rotate_ip_on_key_failure: default_rotate_ip_on_key_failure(),
            rotate_ip_on_rate_limit: default_rotate_ip_on_rate_limit(),
            ip_switch_cooldown_seconds: default_ip_switch_cooldown_seconds(),
            recent_node_window: default_recent_node_window(),
            recent_node_ttl_seconds: default_recent_node_ttl_seconds(),
        }
    }
}

impl ClashVergeConfig {
    fn is_effective(&self) -> bool {
        self.enabled
    }

    fn can_control_nodes(&self) -> bool {
        non_empty_trimmed(&self.controller_url).is_some()
            && non_empty_trimmed(&self.group_name).is_some()
    }
}

pub fn discover_clash_verge_group(config: &ClashVergeConfig) -> Result<Option<String>> {
    let Some(controller_url) = non_empty_trimmed(&config.controller_url) else {
        return Ok(None);
    };
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("{}/proxies", controller_url.trim_end_matches('/'));
    let mut request = client.get(&url);
    if let Some(secret) = non_empty_trimmed(&config.secret) {
        request = request.bearer_auth(secret);
    }
    let response = request.send()?;
    if !response.status().is_success() {
        return Err(anyhow!("Clash Verge 控制接口返回 {}", response.status()));
    }
    let payload: Value = response.json()?;
    Ok(first_switchable_clash_group(&payload))
}

fn first_switchable_clash_group(payload: &Value) -> Option<String> {
    let proxies = payload.get("proxies").and_then(Value::as_object)?;
    let mut candidates = proxies
        .iter()
        .filter_map(|(name, value)| {
            let switchable_count = value
                .get("all")
                .and_then(Value::as_array)?
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .count();
            (switchable_count > 1).then(|| {
                (
                    name.trim().to_string(),
                    value
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_ascii_lowercase(),
                )
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|(left_name, left_type), (right_name, right_type)| {
        clash_group_rank(left_name, left_type)
            .cmp(&clash_group_rank(right_name, right_type))
            .then_with(|| left_name.cmp(right_name))
    });
    candidates.into_iter().next().map(|(name, _)| name)
}

fn clash_group_rank(name: &str, group_type: &str) -> u8 {
    if group_type == "selector" {
        0
    } else if name.contains("自动") || name.to_ascii_lowercase().contains("select") {
        1
    } else if name.contains("代理") || name.to_ascii_lowercase().contains("proxy") {
        2
    } else {
        3
    }
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

impl ClashVergeController {
    fn new(config: ClashVergeConfig) -> Result<Self> {
        let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
        Ok(Self {
            config,
            client,
            last_switch_at: Mutex::new(None),
            group_rotations: Mutex::new(HashMap::new()),
            recent_nodes: Mutex::new(HashMap::new()),
            egress_ip_cache: Mutex::new(HashMap::new()),
        })
    }

    fn maybe_rotate_for_failure(&self, reason: FailureKind) {
        if !self.config.enabled {
            return;
        }
        let should_rotate = match reason {
            FailureKind::KeyFailure => self.config.rotate_ip_on_key_failure,
            FailureKind::RateLimited => self.config.rotate_ip_on_rate_limit,
            FailureKind::Transport => false,
        };
        if !should_rotate {
            return;
        }
        let Some(group_name) = non_empty_trimmed(&self.config.group_name) else {
            return;
        };
        let Some(controller_url) = non_empty_trimmed(&self.config.controller_url) else {
            return;
        };
        let cooldown = Duration::from_secs(self.config.ip_switch_cooldown_seconds as u64);
        let Ok(mut last_switch_at) = self.last_switch_at.lock() else {
            return;
        };
        if last_switch_at.is_some_and(|last| last.elapsed() < cooldown) {
            return;
        }
        if self.switch_group(group_name, controller_url).is_ok() {
            *last_switch_at = Some(Instant::now());
        }
    }

    fn switch_group(&self, group_name: &str, controller_url: &str) -> Result<()> {
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
            .unwrap_or_default();
        let candidates = all
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .filter(|name| *name != current)
            .collect::<Vec<_>>();
        let Some(next) = self.next_group_candidate(group_name, &candidates) else {
            return Ok(());
        };
        let body = json!({ "name": next });
        let response = self.authorized(self.client.put(&url).json(&body)).send()?;
        if !response.status().is_success() {
            return Err(anyhow!("clash switch failed: {}", response.status()));
        }
        self.remember_group_node(group_name, next);
        Ok(())
    }

    fn authorized(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        if let Some(secret) = non_empty_trimmed(&self.config.secret) {
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
        let now = Instant::now();
        let Ok(mut recent_nodes) = self.recent_nodes.lock() else {
            return candidates.to_vec();
        };
        let entries = recent_nodes
            .entry(group_name.to_string())
            .or_insert_with(Vec::new);
        entries.retain(|(_, seen_at)| now.duration_since(*seen_at) < ttl);
        if entries.len() > window {
            let drop_count = entries.len() - window;
            entries.drain(0..drop_count);
        }
        let recent = entries
            .iter()
            .rev()
            .take(window)
            .map(|(name, _)| name.as_str())
            .collect::<HashSet<_>>();
        candidates
            .iter()
            .copied()
            .filter(|candidate| !recent.contains(candidate))
            .collect()
    }

    fn remember_group_node(&self, group_name: &str, node: &str) {
        let ttl = Duration::from_secs(self.config.recent_node_ttl_seconds.max(1) as u64);
        let window = self.config.recent_node_window.max(1) as usize;
        let now = Instant::now();
        let Ok(mut recent_nodes) = self.recent_nodes.lock() else {
            return;
        };
        let entries = recent_nodes
            .entry(group_name.to_string())
            .or_insert_with(Vec::new);
        entries.retain(|(_, seen_at)| now.duration_since(*seen_at) < ttl);
        entries.retain(|(name, _)| name != node);
        entries.push((node.to_string(), now));
        if entries.len() > window {
            let drop_count = entries.len() - window;
            entries.drain(0..drop_count);
        }
    }

    fn latest_group_node(&self) -> Option<String> {
        let group_name = non_empty_trimmed(&self.config.group_name)?;
        let ttl = Duration::from_secs(self.config.recent_node_ttl_seconds.max(1) as u64);
        let now = Instant::now();
        if let Ok(mut recent_nodes) = self.recent_nodes.lock() {
            if let Some(entries) = recent_nodes.get_mut(group_name) {
                entries.retain(|(_, seen_at)| now.duration_since(*seen_at) < ttl);
                if let Some((name, _)) = entries.last() {
                    return Some(name.clone());
                }
            }
        }
        self.current_group_node()
    }

    fn current_group_node(&self) -> Option<String> {
        let group_name = non_empty_trimmed(&self.config.group_name)?;
        let controller_url = non_empty_trimmed(&self.config.controller_url)?;
        let group = url_encode_component(group_name);
        let url = format!("{}/proxies/{}", controller_url.trim_end_matches('/'), group);
        let response = self.authorized(self.client.get(&url)).send().ok()?;
        if !response.status().is_success() {
            return None;
        }
        let payload: Value = response.json().ok()?;
        payload
            .get("now")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
    }

    fn latest_group_node_egress_ip(&self, node: &str) -> Option<String> {
        let node = non_empty_trimmed(node)?;
        let proxy_url = non_empty_trimmed(&self.config.proxy_url)?;
        let cache_key = format!("{proxy_url}\n{node}");
        let ttl = Duration::from_secs(60);
        let now = Instant::now();
        if let Ok(mut cache) = self.egress_ip_cache.lock() {
            cache.retain(|_, (_, seen_at)| now.duration_since(*seen_at) < ttl);
            if let Some((ip, _)) = cache.get(&cache_key) {
                return Some(ip.clone());
            }
        }
        let ip = lookup_proxy_egress_ip(proxy_url)?;
        if let Ok(mut cache) = self.egress_ip_cache.lock() {
            cache.insert(cache_key, (ip.clone(), Instant::now()));
        }
        Some(ip)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    KeyFailure,
    RateLimited,
    Transport,
}

pub struct SmartProxyServer {
    listen_host: String,
    listen_port: u16,
    master_key: String,
    deployments: Arc<Mutex<Vec<SmartDeployment>>>,
    upstreams: Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    quality_writer: QualityWriteHandle,
    clash_verge: Option<Arc<ClashVergeController>>,
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    bound_port: Option<u16>,
    cooldown_seconds: u32,
    retry_count: u32,
    aggregate_runtime: Option<Arc<AggregateEgressRuntime>>,
    http_client: Client,
}

impl ProxyRegistry {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string()) + "\n";
        write_text_atomic(path, &text)
    }
}

pub fn next_available_proxy_port(proxies: &[ProxyConfig]) -> Option<u16> {
    next_available_proxy_port_from(proxies, 4000)
}

fn next_available_proxy_port_from(proxies: &[ProxyConfig], start_port: u16) -> Option<u16> {
    let configured_ports = proxies
        .iter()
        .map(|proxy| proxy.port)
        .collect::<HashSet<_>>();
    (start_port..=u16::MAX).find(|port| {
        !configured_ports.contains(port) && TcpListener::bind(("127.0.0.1", *port)).is_ok()
    })
}

fn write_text_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("watchapi-quality.json");
    let tmp_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&tmp_path, text)?;
    replace_file_atomic(&tmp_path, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp_path);
    })
}

#[cfg(windows)]
fn replace_file_atomic(source: &Path, target: &Path) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target_wide = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file_atomic(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::rename(source, target)
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

    fn apply_to_deployments(&self, deployments: &mut [SmartDeployment]) {
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
                    QualityWriteCommand::Flush(done) => {
                        flush_quality_pending(&store, &path, &mut pending, &mut last_flush, 40);
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
                        QualityWriteCommand::Flush(done) => {
                            flush_quality_pending(&store, &path, &mut pending, &mut last_flush, 40);
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

    #[allow(dead_code)]
    fn flush(&self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(QualityWriteCommand::Flush(tx)).is_ok() {
            let _ = rx.recv_timeout(Duration::from_secs(2));
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

impl ProxyConfig {
    pub fn blank(index: usize) -> Self {
        Self {
            name: format!("本地代理{index}"),
            host: default_host(),
            port: 4000 + index.saturating_sub(1) as u16,
            master_key: format!("sk-watchapi-local-{index}"),
            litellm_command: default_litellm_command(),
            engine: ProxyEngine::Smart,
            sticky_keys: default_sticky_keys(),
            router_cooldown_seconds: default_router_cooldown_seconds(),
            router_allowed_fails: 0,
            router_num_retries: 0,
            clash_verge: ClashVergeConfig::default(),
            aggregate_egress: SharedAggregateEgressConfig::default(),
            upstreams: vec![UpstreamConfig::blank()],
            routes: vec![RouteConfig {
                public_model: "gpt-5.5".to_string(),
                actual_model: "gpt-5.5".to_string(),
                upstreams: vec![UpstreamConfig::blank().name],
            }],
        }
    }

    pub fn endpoint_base_url(&self) -> String {
        format!("http://{}:{}/v1", self.host.trim(), self.port)
    }

    pub fn local_endpoint_base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }

    pub fn summary(&self, base_dir: &Path) -> ProxySummary {
        ProxySummary {
            upstream_count: self.upstreams.len(),
            route_count: self.routes.len(),
            key_count: self
                .upstreams
                .iter()
                .map(|upstream| upstream_key_count(upstream, base_dir))
                .sum(),
        }
    }

    pub fn validate(&self, base_dir: &Path) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(anyhow!("代理名称不能为空"));
        }
        if self.host.trim().is_empty() {
            return Err(anyhow!("监听地址不能为空"));
        }
        if self.port == 0 {
            return Err(anyhow!("监听端口必须大于 0"));
        }
        if self.master_key.trim().is_empty() {
            return Err(anyhow!("本地访问 Key 不能为空"));
        }
        if self.litellm_command.trim().is_empty() {
            return Err(anyhow!("LiteLLM 命令不能为空"));
        }
        if self.clash_verge.is_effective() {
            let proxy_url = non_empty_trimmed(&self.clash_verge.proxy_url)
                .map(str::to_string)
                .unwrap_or_else(default_clash_verge_proxy_url);
            url::Url::parse(&proxy_url)
                .with_context(|| "Clash Verge 数据代理地址不合法".to_string())?;
        }
        if self.clash_verge.can_control_nodes() {
            url::Url::parse(self.clash_verge.controller_url.trim())
                .with_context(|| "Clash Verge 控制地址不合法".to_string())?;
        }
        if self.aggregate_egress.enabled && self.aggregate_egress.fingerprints.is_empty() {
            return Err(anyhow!("共享最终出口已启用，但指纹池为空"));
        }
        if self.upstreams.is_empty() {
            return Err(anyhow!("至少需要一个上游 URL"));
        }
        if self.routes.is_empty() {
            return Err(anyhow!("至少需要一个模型路由"));
        }

        let mut upstream_names = HashSet::new();
        for upstream in &self.upstreams {
            if upstream.name.trim().is_empty() {
                return Err(anyhow!("上游名称不能为空"));
            }
            if !upstream_names.insert(upstream.name.trim().to_string()) {
                return Err(anyhow!("上游名称重复：{}", upstream.name));
            }
            if upstream.base_url.trim().is_empty() {
                return Err(anyhow!("上游 {} 缺少 URL", upstream.name));
            }
            url::Url::parse(upstream.base_url.trim())
                .with_context(|| format!("上游 {} URL 不合法", upstream.name))?;
            if upstream.max_concurrency == 0 {
                return Err(anyhow!("上游 {} 最大并发必须大于 0", upstream.name));
            }
            if upstream.key_batches.is_empty() {
                return Err(anyhow!("上游 {} 至少需要一批 Key", upstream.name));
            }
            for batch in &upstream.key_batches {
                let path = resolve_relative_path(base_dir, &batch.path);
                if !path.exists() {
                    return Err(anyhow!("Key 文件不存在：{}", path.display()));
                }
            }
        }

        for route in &self.routes {
            if route.public_model.trim().is_empty() {
                return Err(anyhow!("模型路由的对外模型不能为空"));
            }
            if route.upstreams.is_empty() {
                return Err(anyhow!("模型 {} 至少需要选择一个上游", route.public_model));
            }
            for name in &route.upstreams {
                if !upstream_names.contains(name.trim()) {
                    return Err(anyhow!(
                        "模型 {} 引用了不存在的上游：{}",
                        route.public_model,
                        name
                    ));
                }
            }
        }
        Ok(())
    }
}

pub fn rename_upstream_references(routes: &mut [RouteConfig], old_name: &str, new_name: &str) {
    let old_name = old_name.trim();
    let new_name = new_name.trim();
    if old_name.is_empty() || new_name.is_empty() || old_name == new_name {
        return;
    }
    for route in routes {
        for upstream in &mut route.upstreams {
            if upstream.trim() == old_name {
                *upstream = new_name.to_string();
            }
        }
        route.upstreams.dedup();
    }
}

pub fn prune_missing_route_upstreams(proxy: &mut ProxyConfig) {
    let upstream_names = proxy
        .upstreams
        .iter()
        .map(|upstream| upstream.name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect::<HashSet<_>>();
    for route in &mut proxy.routes {
        route
            .upstreams
            .retain(|name| upstream_names.contains(name.trim()));
    }
}

impl UpstreamConfig {
    pub fn blank() -> Self {
        Self {
            name: "dc".to_string(),
            base_url: "https://dc.hhhl.cc/v1".to_string(),
            provider_prefix: "openai".to_string(),
            max_qps: None,
            max_rpm: None,
            max_concurrency: default_upstream_concurrency(),
            cooldown_seconds: None,
            egress_note: String::new(),
            key_batches: Vec::new(),
        }
    }
}

impl SmartProxyServer {
    pub fn from_config(proxy: &ProxyConfig, base_dir: &Path) -> Result<Self> {
        proxy.validate(base_dir)?;
        let quality_path = key_quality_path(base_dir, proxy);
        let quality_writer = QualityWriteHandle::new(quality_path.clone());
        let mut deployments = build_smart_deployments(proxy, base_dir)?;
        KeyQualityStore::load(&quality_path).apply_to_deployments(&mut deployments);
        if deployments.is_empty() {
            return Err(anyhow!("没有可用 Key，无法启动内置智能代理"));
        }
        let upstreams = deployments
            .iter()
            .map(|deployment| {
                (
                    deployment.base_url.clone(),
                    SmartUpstreamRuntime {
                        recent_request_times: Vec::new(),
                        in_flight: 0,
                        cooldown_until: None,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let aggregate_runtime = if proxy.aggregate_egress.enabled {
            Some(Arc::new(AggregateEgressRuntime::new(
                AggregateEgressConfig {
                    enabled: true,
                    fingerprints: proxy.aggregate_egress.fingerprints.clone(),
                    recent_fingerprint_window: proxy.aggregate_egress.recent_fingerprint_window,
                    recent_fingerprint_ttl_seconds: proxy
                        .aggregate_egress
                        .recent_fingerprint_ttl_seconds,
                },
                deployments
                    .iter()
                    .map(|deployment| AggregateDeploymentSeed {
                        upstream: deployment.upstream.clone(),
                        base_url: deployment.base_url.clone(),
                        public_model: deployment.public_model.clone(),
                        actual_model: deployment.actual_model.clone(),
                        max_qps: deployment.max_qps,
                        max_rpm: deployment.max_rpm,
                        max_concurrency: deployment.max_concurrency,
                        upstream_cooldown_seconds: deployment.upstream_cooldown_seconds,
                        egress_note: deployment.egress_note.clone(),
                        key: deployment.key.clone(),
                        key_label: deployment.key_label.clone(),
                        quality_key: deployment.quality_key.clone(),
                    })
                    .collect(),
                quality_path.clone(),
                if proxy.clash_verge.is_effective() {
                    Some(AggregateClashConfig {
                        enabled: true,
                        controller_url: proxy.clash_verge.controller_url.clone(),
                        proxy_url: proxy.clash_verge.proxy_url.clone(),
                        secret: proxy.clash_verge.secret.clone(),
                        group_name: proxy.clash_verge.group_name.clone(),
                        ip_switch_cooldown_seconds: proxy.clash_verge.ip_switch_cooldown_seconds,
                        recent_node_window: proxy.clash_verge.recent_node_window,
                        recent_node_ttl_seconds: proxy.clash_verge.recent_node_ttl_seconds,
                    })
                } else {
                    None
                },
                proxy.router_cooldown_seconds,
            )?))
        } else {
            None
        };
        let http_client = Client::builder()
            .connect_timeout(SMART_PROXY_UPSTREAM_CONNECT_TIMEOUT)
            .timeout(smart_proxy_upstream_timeout())
            .build()?;
        Ok(Self {
            listen_host: proxy.host.trim().to_string(),
            listen_port: proxy.port,
            master_key: proxy.master_key.clone(),
            deployments: Arc::new(Mutex::new(deployments)),
            upstreams: Arc::new(Mutex::new(upstreams)),
            quality_writer,
            clash_verge: if proxy.clash_verge.is_effective()
                && proxy.clash_verge.can_control_nodes()
            {
                Some(Arc::new(ClashVergeController::new(
                    proxy.clash_verge.clone(),
                )?))
            } else {
                None
            },
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
            bound_port: None,
            cooldown_seconds: proxy.router_cooldown_seconds,
            retry_count: proxy.router_num_retries,
            aggregate_runtime,
            http_client,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        let listener = TcpListener::bind((self.listen_host.as_str(), self.listen_port))
            .with_context(|| {
                format!(
                    "绑定 {}:{} 失败，端口可能已被其他程序占用",
                    self.listen_host, self.listen_port
                )
            })?;
        listener.set_nonblocking(true)?;
        self.bound_port = Some(listener.local_addr()?.port());
        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let deployments = Arc::clone(&self.deployments);
        let upstreams = Arc::clone(&self.upstreams);
        let quality_writer = self.quality_writer.clone();
        let clash_verge = self.clash_verge.clone();
        let aggregate_runtime = self.aggregate_runtime.clone();
        let master_key = self.master_key.clone();
        let cooldown_seconds = self.cooldown_seconds;
        let retry_count = self.retry_count;
        let http_client = self.http_client.clone();
        let active_clients = Arc::new(AtomicUsize::new(0));
        if let Some(runtime) = &aggregate_runtime {
            register_runtime(&self.endpoint_base_url(), runtime)?;
        }
        self.handle = Some(thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(40));
                        continue;
                    }
                    Err(_) => break,
                };
                let Some(active_guard) = try_acquire_active_client(&active_clients) else {
                    let _ = stream.set_nonblocking(false);
                    let _ = write_json(
                        &mut stream,
                        503,
                        &smart_proxy_overloaded_body(SMART_PROXY_MAX_ACTIVE_CLIENTS),
                    );
                    continue;
                };
                let deployments = Arc::clone(&deployments);
                let upstreams = Arc::clone(&upstreams);
                let quality_writer = quality_writer.clone();
                let clash_verge = clash_verge.clone();
                let aggregate_runtime = aggregate_runtime.clone();
                let master_key = master_key.clone();
                let http_client = http_client.clone();
                thread::spawn(move || {
                    let _active_guard = active_guard;
                    let mut stream = stream;
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
                    let _ = stream.set_write_timeout(None);
                    if let Err(err) = handle_smart_proxy_client(
                        &mut stream,
                        deployments,
                        upstreams,
                        quality_writer,
                        clash_verge,
                        aggregate_runtime,
                        http_client,
                        &master_key,
                        cooldown_seconds,
                        retry_count,
                    ) {
                        if !should_suppress_local_failure_response(&err) {
                            let _ = write_json(
                                &mut stream,
                                502,
                                &smart_proxy_local_failure_body(err.to_string()),
                            );
                        }
                    }
                });
            }
        }));
        Ok(())
    }

    pub fn stop(&mut self) {
        self.quality_writer.flush();
        if let Some(runtime) = &self.aggregate_runtime {
            runtime.flush_quality();
        }
        self.running.store(false, Ordering::SeqCst);
        unregister_runtime(&self.endpoint_base_url());
        if let Some(handle) = self.handle.take() {
            if let Some(port) = self.bound_port {
                let _ = TcpStream::connect((self.listen_host.as_str(), port));
            }
            let _ = handle.join();
        }
    }

    pub fn snapshot(&self) -> SmartProxySnapshot {
        if let Some(runtime) = &self.aggregate_runtime {
            return SmartProxySnapshot {
                rows: runtime
                    .snapshot()
                    .rows
                    .into_iter()
                    .map(|row| SmartProxyKeyRow {
                        upstream: row.upstream,
                        base_url: row.base_url,
                        key_label: row.key_label,
                        egress_note: row.egress_note,
                        recent_clash_node: row.recent_clash_node,
                        recent_clash_egress_ip: row.recent_clash_egress_ip,
                        score: row.score,
                        total_requests: row.total_requests,
                        success_requests: row.success_requests,
                        failure_requests: row.failure_requests,
                        consecutive_failures: row.consecutive_failures,
                        average_latency_ms: row.average_latency_ms,
                        last_status: row.last_status,
                        cooldown_remaining_seconds: row.cooldown_remaining_seconds,
                        in_flight: row.in_flight,
                        limit_status: row.limit_status,
                    })
                    .collect(),
            };
        }
        snapshot_from_deployments(
            &self.deployments,
            &self.upstreams,
            self.clash_verge.as_ref(),
        )
    }

    pub fn endpoint_base_url(&self) -> String {
        format!(
            "http://{}:{}/v1",
            self.listen_host.trim(),
            self.bound_port.unwrap_or(self.listen_port)
        )
    }
}

impl Drop for SmartProxyServer {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn load_key_batch(batch: &KeyBatchConfig, base_dir: &Path) -> Result<Vec<KeyRecord>> {
    let path = resolve_relative_path(base_dir, &batch.path);
    let text = fs::read_to_string(&path)
        .with_context(|| format!("读取 Key 文件失败：{}", path.display()))?;
    let mut keys = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match batch.format {
            KeyBatchFormat::Txt => {
                if !seen.insert(line.to_string()) {
                    continue;
                }
                keys.push(KeyRecord {
                    key: line.to_string(),
                    rpm: batch.rpm,
                    tpm: batch.tpm,
                    note: String::new(),
                });
            }
            KeyBatchFormat::Csv => {
                let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
                let Some(key) = parts.first().filter(|value| !value.is_empty()) else {
                    continue;
                };
                if !seen.insert((*key).to_string()) {
                    continue;
                }
                keys.push(KeyRecord {
                    key: (*key).to_string(),
                    rpm: parts
                        .get(1)
                        .and_then(|value| value.parse::<u32>().ok())
                        .or(batch.rpm),
                    tpm: parts
                        .get(2)
                        .and_then(|value| value.parse::<u32>().ok())
                        .or(batch.tpm),
                    note: parts.get(3).copied().unwrap_or("").to_string(),
                });
            }
        }
    }
    Ok(keys)
}

pub fn generate_litellm_yaml(proxy: &ProxyConfig, base_dir: &Path) -> Result<String> {
    proxy.validate(base_dir)?;
    let mut model_list = Vec::new();
    let upstreams = proxy
        .upstreams
        .iter()
        .map(|item| (item.name.trim().to_string(), item))
        .collect::<HashMap<_, _>>();

    for route in &proxy.routes {
        let public_model = route.public_model.trim();
        for upstream_name in &route.upstreams {
            let upstream = upstreams
                .get(upstream_name.trim())
                .ok_or_else(|| anyhow!("路由引用了不存在的上游：{upstream_name}"))?;
            let actual_model = if route.actual_model.trim().is_empty() {
                public_model.to_string()
            } else {
                route.actual_model.trim().to_string()
            };
            let litellm_model = litellm_model_name(&upstream.provider_prefix, &actual_model);
            let mut key_written = false;
            for batch in &upstream.key_batches {
                for record in load_key_batch(batch, base_dir)? {
                    if proxy.sticky_keys && key_written {
                        continue;
                    }
                    let mut params = BTreeMap::new();
                    params.insert("model".to_string(), Value::String(litellm_model.clone()));
                    params.insert(
                        "api_base".to_string(),
                        Value::String(upstream.base_url.trim_end_matches('/').to_string()),
                    );
                    params.insert("api_key".to_string(), Value::String(record.key));
                    if let Some(rpm) = record.rpm {
                        params.insert("rpm".to_string(), Value::Number(rpm.into()));
                    }
                    if let Some(tpm) = record.tpm {
                        params.insert("tpm".to_string(), Value::Number(tpm.into()));
                    }

                    let mut item = BTreeMap::new();
                    item.insert(
                        "model_name".to_string(),
                        Value::String(public_model.to_string()),
                    );
                    item.insert(
                        "litellm_params".to_string(),
                        serde_json::to_value(params).unwrap_or(Value::Null),
                    );
                    model_list.push(serde_json::to_value(item).unwrap_or(Value::Null));
                    key_written = true;
                }
            }
        }
    }

    if model_list.is_empty() {
        return Err(anyhow!("没有可用 Key，无法生成 LiteLLM 配置"));
    }

    let mut root = BTreeMap::new();
    root.insert("model_list".to_string(), Value::Array(model_list));
    root.insert(
        "general_settings".to_string(),
        serde_json::json!({
            "master_key": proxy.master_key,
        }),
    );
    root.insert(
        "router_settings".to_string(),
        serde_json::json!({
            "routing_strategy": "simple-shuffle",
            "allowed_fails": proxy.router_allowed_fails,
            "cooldown_time": proxy.router_cooldown_seconds,
            "num_retries": proxy.router_num_retries,
            "enable_weighted_failover": false,
        }),
    );
    serde_yaml::to_string(&root).map_err(Into::into)
}

pub fn write_litellm_config(proxy: &ProxyConfig, base_dir: &Path, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let yaml = generate_litellm_yaml(proxy, base_dir)?;
    write_text_atomic(path, &yaml)?;
    Ok(())
}

pub fn resolve_relative_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

pub fn portable_path(base_dir: &Path, path: &Path) -> PathBuf {
    let abs = normalize_portable_path(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
    let base = normalize_portable_path(
        base_dir
            .canonicalize()
            .unwrap_or_else(|_| base_dir.to_path_buf()),
    );
    abs.strip_prefix(&base).unwrap_or(&abs).to_path_buf()
}

fn normalize_portable_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest.to_string());
    }
    path
}

fn build_smart_deployments(proxy: &ProxyConfig, base_dir: &Path) -> Result<Vec<SmartDeployment>> {
    let upstreams = proxy
        .upstreams
        .iter()
        .map(|item| (item.name.trim().to_string(), item))
        .collect::<HashMap<_, _>>();
    let mut deployments = Vec::new();
    for route in &proxy.routes {
        let public_model = route.public_model.trim();
        let actual_model = if route.actual_model.trim().is_empty() {
            public_model
        } else {
            route.actual_model.trim()
        };
        for upstream_name in &route.upstreams {
            let upstream = upstreams
                .get(upstream_name.trim())
                .ok_or_else(|| anyhow!("路由引用了不存在的上游：{upstream_name}"))?;
            for batch in &upstream.key_batches {
                for record in load_key_batch(batch, base_dir)? {
                    let upstream_name = upstream.name.trim();
                    let egress_note = upstream.egress_note.trim().to_string();
                    deployments.push(SmartDeployment {
                        upstream: upstream_name.to_string(),
                        base_url: upstream.base_url.trim_end_matches('/').to_string(),
                        public_model: public_model.to_string(),
                        actual_model: actual_model.to_string(),
                        max_qps: upstream.max_qps,
                        max_rpm: upstream.max_rpm,
                        max_concurrency: upstream.max_concurrency,
                        upstream_cooldown_seconds: upstream.cooldown_seconds,
                        egress_note,
                        key_label: mask_key(&record.key),
                        quality_key: key_quality_key(
                            upstream.base_url.trim_end_matches('/'),
                            &record.key,
                            public_model,
                        ),
                        key: record.key,
                        stats: SmartKeyStats::default(),
                    });
                }
            }
        }
    }
    Ok(deployments)
}

fn handle_smart_proxy_client(
    stream: &mut TcpStream,
    deployments: Arc<Mutex<Vec<SmartDeployment>>>,
    upstreams: Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    quality_writer: QualityWriteHandle,
    clash_verge: Option<Arc<ClashVergeController>>,
    aggregate_runtime: Option<Arc<AggregateEgressRuntime>>,
    http_client: Client,
    master_key: &str,
    cooldown_seconds: u32,
    retry_count: u32,
) -> Result<()> {
    let raw = read_http_request(stream)?;
    if raw.is_empty() {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&raw);
    let request_line = request.lines().next().unwrap_or_default();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default();
    let path = request_parts.next().unwrap_or("/");
    if method == "GET" && path == "/_watchapi/smart/status" {
        let snapshot = snapshot_from_deployments(&deployments, &upstreams, clash_verge.as_ref());
        return write_json(stream, 200, &snapshot_to_json(&snapshot).to_string());
    }
    if method != "POST" {
        return write_json(stream, 404, r#"{"error":"not found"}"#);
    }
    if !authorized(&raw, master_key) {
        return write_json(stream, 401, r#"{"error":"unauthorized"}"#);
    }
    let body_start = find_body(&raw).ok_or_else(|| anyhow!("invalid http request"))?;
    let body = raw[body_start..].to_vec();
    let request_body = SmartRequestBody::parse(body);
    let attempts = smart_proxy_attempt_budget(retry_count);
    if let Some(runtime) = aggregate_runtime {
        if request_body.stream {
            write_sse_stream_response_head(stream)?;
            stream.write_all(b": watchapi upstream pending\n\n")?;
            stream.flush()?;
            return match runtime.forward_stream_with_failover(
                stream,
                &raw,
                &request_body.body,
                method,
                path,
                attempts,
            ) {
                Ok(()) => Ok(()),
                Err(err) => write_sse_error_event(stream, &err.to_string()),
            };
        }
        return match runtime.forward_with_failover(&raw, &request_body.body, method, path, attempts)
        {
            Ok(response) => write_raw_response(
                stream,
                response.status,
                &response.reason,
                &response.headers,
                &response.payload,
            ),
            Err(err) => write_json(stream, 502, &smart_proxy_unavailable_body(err.to_string())),
        };
    }
    if request_body.stream {
        write_sse_stream_response_head(stream)?;
        stream.write_all(b": watchapi upstream pending\n\n")?;
        stream.flush()?;
        let mut last_error = None;
        for attempt in 0..attempts {
            let Some((index, deployment)) =
                select_deployment(&deployments, &upstreams, &request_body.requested_model)
            else {
                let detail = last_error
                    .unwrap_or_else(|| "no available key for requested model".to_string());
                return write_sse_error_event(stream, &detail);
            };
            mark_upstream_request_started(&upstreams, &deployment.base_url);
            let forwarded_body = request_body.rewrite_model(&deployment.actual_model);
            let started_at = Instant::now();
            let result = forward_smart_stream_request(
                stream,
                &http_client,
                &raw,
                &forwarded_body,
                &deployment,
                method,
                path,
            );
            let latency = started_at.elapsed();
            mark_upstream_request_finished(&upstreams, &deployment.base_url);
            match result {
                Ok(SmartStreamResult::Success { status }) => {
                    update_deployment_result(
                        &deployments,
                        &upstreams,
                        clash_verge.as_deref(),
                        &quality_writer,
                        index,
                        status,
                        "",
                        latency,
                        cooldown_seconds,
                    );
                    return Ok(());
                }
                Ok(SmartStreamResult::UpstreamFailure { status, payload }) => {
                    let payload_text = String::from_utf8_lossy(&payload);
                    update_deployment_result(
                        &deployments,
                        &upstreams,
                        clash_verge.as_deref(),
                        &quality_writer,
                        index,
                        status,
                        &payload_text,
                        latency,
                        cooldown_seconds,
                    );
                    last_error = Some(format!("smart upstream returned {status}: {payload_text}"));
                    if !smart_proxy_retryable_status(status) || attempt + 1 >= attempts {
                        return write_sse_error_event(
                            stream,
                            last_error
                                .as_deref()
                                .unwrap_or("smart proxy upstream unavailable"),
                        );
                    }
                }
                Err(err) => {
                    if should_suppress_local_failure_response(&err) {
                        return Err(err);
                    }
                    update_deployment_transport_failure(
                        &deployments,
                        &upstreams,
                        clash_verge.as_deref(),
                        &quality_writer,
                        index,
                        latency,
                        cooldown_seconds,
                    );
                    last_error = Some(err.to_string());
                    if attempt + 1 >= attempts {
                        break;
                    }
                }
            }
        }
        return write_sse_error_event(
            stream,
            &last_error.unwrap_or_else(|| "smart proxy upstream unavailable".to_string()),
        );
    }
    let mut last_response: Option<(u16, String, HeaderMap, Vec<u8>)> = None;
    let mut last_error: Option<String> = None;
    for attempt in 0..attempts {
        let Some((index, deployment)) =
            select_deployment(&deployments, &upstreams, &request_body.requested_model)
        else {
            if let Some((status, reason, headers, payload)) = last_response {
                return write_raw_response(stream, status, &reason, &headers, &payload);
            }
            if last_error.is_some() {
                break;
            }
            return write_json(
                stream,
                503,
                r#"{"error":"no available key for requested model"}"#,
            );
        };
        mark_upstream_request_started(&upstreams, &deployment.base_url);
        let forwarded_body = request_body.rewrite_model(&deployment.actual_model);
        let started_at = Instant::now();
        let response = forward_smart_request(
            &http_client,
            &raw,
            &forwarded_body,
            &deployment,
            method,
            path,
        );
        let latency = started_at.elapsed();
        mark_upstream_request_finished(&upstreams, &deployment.base_url);
        match response {
            Ok((status, reason, headers, payload)) => {
                update_deployment_result(
                    &deployments,
                    &upstreams,
                    clash_verge.as_deref(),
                    &quality_writer,
                    index,
                    status,
                    &String::from_utf8_lossy(&payload),
                    latency,
                    cooldown_seconds,
                );
                if !smart_proxy_retryable_status(status) || attempt + 1 >= attempts {
                    return write_raw_response(stream, status, &reason, &headers, &payload);
                }
                last_response = Some((status, reason, headers, payload));
            }
            Err(err) => {
                update_deployment_transport_failure(
                    &deployments,
                    &upstreams,
                    clash_verge.as_deref(),
                    &quality_writer,
                    index,
                    latency,
                    cooldown_seconds,
                );
                last_error = Some(err.to_string());
                if attempt + 1 >= attempts {
                    break;
                }
            }
        }
    }
    if let Some((status, reason, headers, payload)) = last_response {
        return write_raw_response(stream, status, &reason, &headers, &payload);
    }
    write_json(
        stream,
        502,
        &smart_proxy_unavailable_body(last_error.unwrap_or_default()),
    )
}

struct SmartRequestBody {
    body: Vec<u8>,
    parsed: Option<Value>,
    requested_model: String,
    stream: bool,
}

impl SmartRequestBody {
    fn parse(body: Vec<u8>) -> Self {
        let parsed = serde_json::from_slice::<Value>(&body).ok();
        let requested_model = parsed
            .as_ref()
            .and_then(|value| value.get("model").and_then(Value::as_str))
            .map(str::to_string)
            .unwrap_or_default();
        let stream = parsed
            .as_ref()
            .and_then(|value| value.get("stream").and_then(Value::as_bool))
            .unwrap_or(false);
        Self {
            body,
            parsed,
            requested_model,
            stream,
        }
    }

    fn rewrite_model(&self, model: &str) -> Vec<u8> {
        rewrite_model_in_parsed_body(&self.body, self.parsed.as_ref(), model)
    }
}

fn smart_proxy_unavailable_body(detail: String) -> String {
    let message = if detail.trim().is_empty() {
        "smart proxy upstream unavailable".to_string()
    } else {
        format!("smart proxy upstream unavailable: {detail}")
    };
    json!({
        "error": {
            "message": message,
            "type": "watchapi_smart_proxy_upstream",
            "code": "upstream_unavailable"
        },
        "detail": detail
    })
    .to_string()
}

fn smart_proxy_local_failure_body(detail: String) -> String {
    let message = if detail.trim().is_empty() {
        "smart proxy local failure".to_string()
    } else {
        format!("smart proxy local failure: {detail}")
    };
    json!({
        "error": {
            "message": message,
            "type": "watchapi_smart_proxy_local",
            "code": "local_failure"
        },
        "detail": detail
    })
    .to_string()
}

fn smart_proxy_overloaded_body(active_clients: usize) -> String {
    json!({
        "error": {
            "message": format!(
                "smart proxy overloaded: {active_clients} active local clients"
            ),
            "type": "watchapi_smart_proxy_local",
            "code": "local_overloaded"
        },
        "detail": {
            "active_clients": active_clients,
            "limit": SMART_PROXY_MAX_ACTIVE_CLIENTS
        }
    })
    .to_string()
}

struct ActiveClientGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ActiveClientGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

fn try_acquire_active_client(counter: &Arc<AtomicUsize>) -> Option<ActiveClientGuard> {
    let mut current = counter.load(Ordering::SeqCst);
    loop {
        if current >= SMART_PROXY_MAX_ACTIVE_CLIENTS {
            return None;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                return Some(ActiveClientGuard {
                    counter: Arc::clone(counter),
                });
            }
            Err(next) => current = next,
        }
    }
}

fn write_sse_stream_response_head(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
    )?;
    stream.flush()?;
    Ok(())
}

fn write_sse_error_event(stream: &mut TcpStream, detail: &str) -> Result<()> {
    let payload = json!({"type":"error","error":{"message":detail}}).to_string();
    write!(stream, "event: error\ndata: {payload}\n\n")?;
    stream.flush()?;
    Ok(())
}

fn should_suppress_local_failure_response(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            )
        })
}

fn smart_proxy_attempt_budget(configured_retries: u32) -> u32 {
    configured_retries
        .saturating_add(1)
        .max(SMART_PROXY_RETRYABLE_MIN_ATTEMPTS)
}

fn smart_proxy_retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

fn smart_proxy_upstream_timeout() -> Duration {
    SMART_PROXY_UPSTREAM_TOTAL_TIMEOUT
}

fn select_deployment(
    deployments: &Arc<Mutex<Vec<SmartDeployment>>>,
    upstreams: &Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    requested_model: &str,
) -> Option<(usize, SmartDeployment)> {
    let rotation = next_selection_rotation();
    select_deployment_rotated(deployments, upstreams, requested_model, rotation)
}

fn select_deployment_rotated(
    deployments: &Arc<Mutex<Vec<SmartDeployment>>>,
    upstreams: &Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    requested_model: &str,
    rotation: usize,
) -> Option<(usize, SmartDeployment)> {
    let now = Instant::now();
    let upstream_state = upstreams.lock().ok()?;
    let items = deployments.lock().ok()?;
    let mut candidates = items
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            requested_model.is_empty() || item.public_model.eq_ignore_ascii_case(requested_model)
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
    candidates = select_key_exploration_pool(candidates);
    candidates.sort_by(|(left_index, left), (right_index, right)| {
        right
            .stats
            .score
            .partial_cmp(&left.stats.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.stats.total_requests.cmp(&right.stats.total_requests))
            .then_with(|| left_index.cmp(right_index))
    });
    let offset = if key_quality_dominates(&candidates) {
        0
    } else {
        rotation % candidates.len()
    };
    let (index, item) = candidates.get(offset).copied()?;
    let item = item.clone();
    Some((index, item))
}

fn select_key_exploration_pool(
    candidates: Vec<(usize, &SmartDeployment)>,
) -> Vec<(usize, &SmartDeployment)> {
    let min_requests = candidates
        .iter()
        .map(|(_, item)| item.stats.total_requests)
        .min()
        .unwrap_or(0);
    if min_requests < MIN_KEY_EXPLORATION_REQUESTS {
        candidates
            .into_iter()
            .filter(|(_, item)| item.stats.total_requests == min_requests)
            .collect()
    } else {
        candidates
    }
}

fn key_quality_dominates(candidates: &[(usize, &SmartDeployment)]) -> bool {
    if candidates.len() <= 1 {
        return true;
    }
    let first = candidates[0].1.stats.score;
    let second = candidates[1].1.stats.score;
    first - second >= KEY_QUALITY_DOMINANCE_MARGIN
}

fn next_selection_rotation() -> usize {
    static ROTATION: OnceLock<AtomicU64> = OnceLock::new();
    let counter = ROTATION.get_or_init(|| AtomicU64::new(initial_selection_seed()));
    counter.fetch_add(1, Ordering::Relaxed) as usize
}

fn initial_selection_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64 ^ u64::from(std::process::id()))
        .unwrap_or_else(|_| u64::from(std::process::id()))
}

fn upstream_available(
    state: Option<&SmartUpstreamRuntime>,
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
    upstreams: &Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    base_url: &str,
) {
    let Ok(mut upstreams) = upstreams.lock() else {
        return;
    };
    let now = Instant::now();
    let state = upstreams
        .entry(base_url.to_string())
        .or_insert_with(|| SmartUpstreamRuntime {
            recent_request_times: Vec::new(),
            in_flight: 0,
            cooldown_until: None,
        });
    state.in_flight = state.in_flight.saturating_add(1);
    state.recent_request_times.push(now);
    state
        .recent_request_times
        .retain(|at| now.duration_since(*at) < Duration::from_secs(60));
}

fn mark_upstream_request_finished(
    upstreams: &Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    base_url: &str,
) {
    let Ok(mut upstreams) = upstreams.lock() else {
        return;
    };
    if let Some(state) = upstreams.get_mut(base_url) {
        state.in_flight = state.in_flight.saturating_sub(1);
    }
}

fn forward_smart_request(
    client: &Client,
    raw_request: &[u8],
    body: &[u8],
    deployment: &SmartDeployment,
    method: &str,
    path: &str,
) -> Result<(u16, String, HeaderMap, Vec<u8>)> {
    let url = upstream_url(&deployment.base_url, path)?;
    let headers = forward_headers(raw_request, &deployment.key, body.len())?;
    let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST);
    let response = client
        .request(method, url)
        .headers(headers)
        .body(body.to_vec())
        .send()?;
    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("OK").to_string();
    let headers = response.headers().clone();
    let payload = response
        .bytes()
        .map(|bytes| bytes.to_vec())
        .unwrap_or_default();
    Ok((status.as_u16(), reason, headers, payload))
}

enum SmartStreamResult {
    Success { status: u16 },
    UpstreamFailure { status: u16, payload: Vec<u8> },
}

fn forward_smart_stream_request<W: Write>(
    writer: &mut W,
    client: &Client,
    raw_request: &[u8],
    body: &[u8],
    deployment: &SmartDeployment,
    method: &str,
    path: &str,
) -> Result<SmartStreamResult> {
    let url = upstream_url(&deployment.base_url, path)?;
    let headers = forward_headers(raw_request, &deployment.key, body.len())?;
    let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut response = client
        .request(method, url)
        .headers(headers)
        .body(body.to_vec())
        .send()?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        let payload = response
            .bytes()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        return Ok(SmartStreamResult::UpstreamFailure { status, payload });
    }

    let mut buffer = [0_u8; 8192];
    loop {
        let size = response.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        writer.write_all(&buffer[..size])?;
        writer.flush()?;
    }
    Ok(SmartStreamResult::Success { status })
}

fn update_deployment_result(
    deployments: &Arc<Mutex<Vec<SmartDeployment>>>,
    upstreams: &Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    clash_verge: Option<&ClashVergeController>,
    quality_writer: &QualityWriteHandle,
    index: usize,
    status: u16,
    payload_text: &str,
    latency: Duration,
    cooldown_seconds: u32,
) {
    let Ok(mut items) = deployments.lock() else {
        return;
    };
    if index >= items.len() {
        return;
    }
    let now = Instant::now();
    let base_url = items[index].base_url.clone();
    let effective_cooldown = items[index]
        .upstream_cooldown_seconds
        .unwrap_or(cooldown_seconds);
    let successful = (200..300).contains(&status) && !key_failure_text(payload_text);
    let ip_cooldown = status == 403 || status == 429 || ip_cooldown_text(payload_text);
    let key_failure = key_failure_text(payload_text) || matches!(status, 401 | 402);
    let failure_kind = if key_failure {
        Some(FailureKind::KeyFailure)
    } else if ip_cooldown {
        Some(FailureKind::RateLimited)
    } else {
        None
    };
    let item = &mut items[index];
    item.stats.total_requests += 1;
    item.stats.last_status = status.to_string();
    item.stats.observe_latency(latency);
    if successful {
        item.stats.success_requests += 1;
        item.stats.consecutive_failures = 0;
        item.stats.cooldown_until = None;
        item.stats.recalculate_score();
        persist_deployment_quality(quality_writer, item);
        drop(items);
        clear_upstream_cooldown(upstreams, &base_url);
        return;
    }
    item.stats.failure_requests += 1;
    item.stats.consecutive_failures += 1;
    item.stats.cooldown_until = Some(now + Duration::from_secs(effective_cooldown as u64));
    item.stats.recalculate_score();
    persist_deployment_quality(quality_writer, item);
    let upstream_cooldown = if ip_cooldown {
        Some((base_url.clone(), effective_cooldown))
    } else {
        None
    };
    if ip_cooldown {
        for candidate in items
            .iter_mut()
            .filter(|candidate| candidate.base_url == base_url)
        {
            candidate.stats.cooldown_until =
                Some(now + Duration::from_secs(effective_cooldown as u64));
        }
    }
    drop(items);
    if let Some((base_url, effective_cooldown)) = upstream_cooldown {
        set_upstream_cooldown(upstreams, &base_url, effective_cooldown);
    }
    if let (Some(controller), Some(kind)) = (clash_verge, failure_kind) {
        controller.maybe_rotate_for_failure(kind);
    }
}

fn update_deployment_transport_failure(
    deployments: &Arc<Mutex<Vec<SmartDeployment>>>,
    upstreams: &Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    clash_verge: Option<&ClashVergeController>,
    quality_writer: &QualityWriteHandle,
    index: usize,
    latency: Duration,
    cooldown_seconds: u32,
) {
    let mut upstream_cooldown = None;
    let Ok(mut items) = deployments.lock() else {
        return;
    };
    if let Some(item) = items.get_mut(index) {
        item.stats.total_requests += 1;
        item.stats.failure_requests += 1;
        item.stats.consecutive_failures += 1;
        item.stats.last_status = "transport".to_string();
        item.stats.observe_latency(latency);
        item.stats.recalculate_score();
        let effective_cooldown = item.upstream_cooldown_seconds.unwrap_or(cooldown_seconds);
        item.stats.cooldown_until =
            Some(Instant::now() + Duration::from_secs(effective_cooldown as u64));
        persist_deployment_quality(quality_writer, item);
        upstream_cooldown = Some((item.base_url.clone(), effective_cooldown));
    }
    drop(items);
    if let Some((base_url, effective_cooldown)) = upstream_cooldown {
        set_upstream_cooldown(upstreams, &base_url, effective_cooldown);
    }
    if let Some(controller) = clash_verge {
        controller.maybe_rotate_for_failure(FailureKind::Transport);
    }
}

fn persist_deployment_quality(writer: &QualityWriteHandle, deployment: &SmartDeployment) {
    writer.persist(
        deployment.quality_key.clone(),
        persisted_quality_from_stats(&deployment.stats),
    );
}

fn persisted_quality_from_stats(stats: &SmartKeyStats) -> PersistedKeyQuality {
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

fn key_quality_path(base_dir: &Path, proxy: &ProxyConfig) -> PathBuf {
    base_dir
        .join("key-stats")
        .join(format!("{}.json", sanitize_stats_filename(&proxy.name)))
}

fn key_quality_key(base_url: &str, key: &str, public_model: &str) -> String {
    format!(
        "{}|{}|{}",
        base_url.trim_end_matches('/').to_ascii_lowercase(),
        key_fingerprint(key),
        public_model.trim().to_ascii_lowercase()
    )
}

fn key_fingerprint(key: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn sanitize_stats_filename(name: &str) -> String {
    let clean = name
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
        "proxy".to_string()
    } else {
        clean
    }
}

fn set_upstream_cooldown(
    upstreams: &Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    base_url: &str,
    cooldown_seconds: u32,
) {
    let Ok(mut upstreams) = upstreams.lock() else {
        return;
    };
    let state = upstreams
        .entry(base_url.to_string())
        .or_insert_with(|| SmartUpstreamRuntime {
            recent_request_times: Vec::new(),
            in_flight: 0,
            cooldown_until: None,
        });
    state.cooldown_until = Some(Instant::now() + Duration::from_secs(cooldown_seconds as u64));
}

fn clear_upstream_cooldown(
    upstreams: &Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    base_url: &str,
) {
    let Ok(mut upstreams) = upstreams.lock() else {
        return;
    };
    if let Some(state) = upstreams.get_mut(base_url) {
        state.cooldown_until = None;
    }
}

fn snapshot_from_deployments(
    deployments: &Arc<Mutex<Vec<SmartDeployment>>>,
    upstreams: &Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>>,
    clash_verge: Option<&Arc<ClashVergeController>>,
) -> SmartProxySnapshot {
    let now = Instant::now();
    let upstream_state = upstreams.lock().ok();
    let recent_clash_node = clash_verge
        .and_then(|controller| controller.latest_group_node())
        .unwrap_or_default();
    let recent_clash_egress_ip = clash_verge
        .and_then(|controller| controller.latest_group_node_egress_ip(&recent_clash_node))
        .unwrap_or_default();
    let rows = deployments
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
                    SmartProxyKeyRow {
                        upstream: item.upstream.clone(),
                        base_url: item.base_url.clone(),
                        key_label: item.key_label.clone(),
                        egress_note: item.egress_note.clone(),
                        recent_clash_node: recent_clash_node.clone(),
                        recent_clash_egress_ip: recent_clash_egress_ip.clone(),
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
    SmartProxySnapshot { rows }
}

fn snapshot_to_json(snapshot: &SmartProxySnapshot) -> Value {
    json!({
        "keys": snapshot.rows.iter().map(|row| json!({
            "upstream": row.upstream,
            "base_url": row.base_url,
            "key": row.key_label,
            "egress_note": row.egress_note,
            "recent_clash_node": row.recent_clash_node,
            "recent_clash_egress_ip": row.recent_clash_egress_ip,
            "egress_display": row.egress_display_text(),
            "score": row.score,
            "total_requests": row.total_requests,
            "success_requests": row.success_requests,
            "failure_requests": row.failure_requests,
            "consecutive_failures": row.consecutive_failures,
            "average_latency_ms": row.average_latency_ms,
            "last_status": row.last_status,
            "cooldown_remaining_seconds": row.cooldown_remaining_seconds,
            "in_flight": row.in_flight,
            "limit_status": row.limit_status,
        })).collect::<Vec<_>>()
    })
}

fn upstream_limit_status(
    state: Option<&SmartUpstreamRuntime>,
    item: &SmartDeployment,
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

fn rewrite_model_in_parsed_body(body: &[u8], parsed: Option<&Value>, model: &str) -> Vec<u8> {
    let Some(mut value) = parsed.cloned() else {
        return body.to_vec();
    };
    rewrite_model_value(body, &mut value, model)
}

fn rewrite_model_value(body: &[u8], value: &mut Value, model: &str) -> Vec<u8> {
    value["model"] = json!(model);
    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
}

fn authorized(raw: &[u8], master_key: &str) -> bool {
    let Some(header_end) = find_body(raw) else {
        return false;
    };
    let text = String::from_utf8_lossy(&raw[..header_end]);
    let expected = format!("authorization: bearer {}", master_key.trim());
    text.lines()
        .any(|line| line.trim().eq_ignore_ascii_case(&expected))
}

fn key_failure_text(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    [
        "insufficient_quota",
        "quota exceeded",
        "balance",
        "余额",
        "额度",
        "invalid api key",
        "incorrect api key",
        "unauthorized",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

fn ip_cooldown_text(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    ["ja4", "cooldown", "冷却", "too many requests", "rate limit"]
        .iter()
        .any(|marker| lowered.contains(marker))
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
        if raw.len() > LOCAL_HTTP_REQUEST_MAX_BYTES {
            return Err(anyhow!("request too large"));
        }
    }
    Ok(raw)
}

fn forward_headers(
    raw_request: &[u8],
    upstream_key: &str,
    content_length: usize,
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

fn write_raw_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    headers: &HeaderMap,
    payload: &[u8],
) -> Result<()> {
    let mut raw = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "transfer-encoding" | "connection" | "content-length"
        ) {
            continue;
        }
        raw.extend_from_slice(name.as_str().as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(value.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        )
        .as_bytes(),
    );
    raw.extend_from_slice(payload);
    stream.write_all(&raw)?;
    Ok(())
}

fn write_json(stream: &mut TcpStream, status: u16, body: &str) -> Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn upstream_url(upstream: &str, path: &str) -> Result<String> {
    let base = url::Url::parse(upstream.trim_end_matches('/'))?;
    let joined = if path.starts_with('/') {
        base.join(path.trim_start_matches('/'))?
    } else {
        base.join(path)?
    };
    Ok(joined.to_string())
}

fn find_body(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
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

fn mask_key(key: &str) -> String {
    let clean = key.trim();
    if clean.len() <= 10 {
        return "***".to_string();
    }
    format!(
        "{}...{}",
        &clean[..6],
        &clean[clean.len().saturating_sub(4)..]
    )
}

fn upstream_key_count(upstream: &UpstreamConfig, base_dir: &Path) -> usize {
    upstream
        .key_batches
        .iter()
        .filter_map(|batch| load_key_batch(batch, base_dir).ok())
        .map(|items| items.len())
        .sum()
}

fn litellm_model_name(prefix: &str, model: &str) -> String {
    let prefix = prefix.trim().trim_end_matches('/');
    if prefix.is_empty() || model.contains('/') {
        model.to_string()
    } else {
        format!("{prefix}/{model}")
    }
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_master_key() -> String {
    "sk-watchapi-local".to_string()
}

fn default_litellm_command() -> String {
    "litellm".to_string()
}

fn default_sticky_keys() -> bool {
    true
}

fn default_clash_verge_controller_url() -> String {
    "http://127.0.0.1:9097".to_string()
}

fn default_clash_verge_proxy_url() -> String {
    "http://127.0.0.1:7897".to_string()
}

fn default_rotate_ip_on_key_failure() -> bool {
    true
}

fn default_rotate_ip_on_rate_limit() -> bool {
    true
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

fn default_shared_aggregate_fingerprints() -> Vec<AggregateFingerprint> {
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

fn default_router_cooldown_seconds() -> u32 {
    35
}

fn default_persisted_key_score() -> f64 {
    80.0
}

fn default_upstream_concurrency() -> u32 {
    1
}

fn non_empty_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn url_encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let ch = *byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_batch_uses_default_limits() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("keys.txt");
        fs::write(&path, "sk-a\n\n# comment\nsk-b\nsk-a\n").unwrap();
        let batch = KeyBatchConfig {
            path,
            format: KeyBatchFormat::Txt,
            rpm: Some(30),
            tpm: Some(1000),
        };

        let keys = load_key_batch(&batch, temp.path()).unwrap();

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].key, "sk-a");
        assert_eq!(keys[0].rpm, Some(30));
        assert_eq!(keys[1].key, "sk-b");
        assert_eq!(keys[1].tpm, Some(1000));
    }

    #[test]
    fn smart_proxy_request_line_is_split_once_on_hot_path() {
        let source = include_str!("litellm_proxy.rs");
        let block = source
            .split("fn handle_smart_proxy_client")
            .nth(1)
            .and_then(|tail| tail.split("fn authorized").next())
            .expect("smart proxy request handler should be discoverable");

        assert!(!block.contains("split_whitespace().nth(1)"));
        assert!(block.contains("let mut request_parts = request_line.split_whitespace();"));
    }

    #[test]
    fn smart_proxy_reuses_http_client_per_server() {
        let source = include_str!("litellm_proxy.rs");
        let server_struct = source
            .split("pub struct SmartProxyServer")
            .nth(1)
            .and_then(|tail| tail.split("impl ProxyRegistry").next())
            .expect("smart proxy server struct should be discoverable");
        let constructor_block = source
            .split("pub fn from_config")
            .nth(1)
            .and_then(|tail| tail.split("pub fn start").next())
            .expect("smart proxy constructor should be discoverable");
        let forward_block = source
            .split("fn forward_smart_request")
            .nth(1)
            .and_then(|tail| tail.split("enum SmartStreamResult").next())
            .expect("smart proxy forward block should be discoverable");
        let stream_block = source
            .split("fn forward_smart_stream_request")
            .nth(1)
            .and_then(|tail| tail.split("fn update_deployment_result").next())
            .expect("smart proxy stream forward block should be discoverable");

        assert!(server_struct.contains("http_client: Client"));
        assert!(constructor_block.contains("let http_client = Client::builder()"));
        assert!(constructor_block.contains("http_client,"));
        assert!(!forward_block.contains("Client::builder()"));
        assert!(!stream_block.contains("Client::builder()"));
        assert!(forward_block.contains("client: &Client"));
        assert!(stream_block.contains("client: &Client"));
    }

    #[test]
    fn csv_batch_allows_per_key_limits() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("keys.csv");
        fs::write(&path, "sk-a,30,1000,a\nsk-b,60,2000,b\n").unwrap();
        let batch = KeyBatchConfig {
            path,
            format: KeyBatchFormat::Csv,
            rpm: Some(10),
            tpm: None,
        };

        let keys = load_key_batch(&batch, temp.path()).unwrap();

        assert_eq!(keys[0].rpm, Some(30));
        assert_eq!(keys[0].tpm, Some(1000));
        assert_eq!(keys[1].rpm, Some(60));
        assert_eq!(keys[1].note, "b");
    }

    #[test]
    fn blank_proxy_route_matches_default_upstream() {
        let proxy = ProxyConfig::blank(1);

        assert_eq!(proxy.upstreams[0].name, "dc");
        assert_eq!(proxy.routes[0].upstreams, vec!["dc".to_string()]);
    }

    #[test]
    fn local_endpoint_base_url_uses_loopback_even_when_bind_host_is_remote_name() {
        let proxy = ProxyConfig {
            host: "dc.hhhl.cc".to_string(),
            port: 4000,
            ..ProxyConfig::blank(1)
        };

        assert_eq!(proxy.endpoint_base_url(), "http://dc.hhhl.cc:4000/v1");
        assert_eq!(proxy.local_endpoint_base_url(), "http://127.0.0.1:4000/v1");
    }

    #[test]
    fn next_available_proxy_port_skips_configured_and_bound_ports() {
        let mut ports = None;
        for start in 41000..65000 {
            let Ok(occupied_listener) = TcpListener::bind(("127.0.0.1", start)) else {
                continue;
            };
            let Ok(configured_listener) = TcpListener::bind(("127.0.0.1", start + 1)) else {
                continue;
            };
            let Ok(expected_listener) = TcpListener::bind(("127.0.0.1", start + 2)) else {
                continue;
            };
            drop(configured_listener);
            drop(expected_listener);
            ports = Some((occupied_listener, start, start + 1, start + 2));
            break;
        }
        let (listener, occupied_port, configured_port, expected_port) =
            ports.expect("test needs three consecutive free local ports");
        let proxies = vec![ProxyConfig {
            port: configured_port,
            ..ProxyConfig::blank(1)
        }];

        let port = next_available_proxy_port_from(&proxies, occupied_port).unwrap();

        assert_eq!(port, expected_port);
        drop(listener);
    }

    #[test]
    fn portable_path_strips_windows_verbatim_prefix() {
        let base = PathBuf::from(r"C:\Users\ExampleUser\Downloads");
        let path = PathBuf::from(r"\\?\C:\Users\ExampleUser\Downloads\keys.txt");
        let unc_path = PathBuf::from(r"\\?\UNC\server\share\keys.txt");

        assert_eq!(portable_path(&base, &path), PathBuf::from("keys.txt"));
        assert_eq!(
            portable_path(&base, &unc_path),
            PathBuf::from(r"\\server\share\keys.txt")
        );
    }

    #[test]
    fn validate_rejects_invalid_upstream_url() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("keys.txt"), "sk-a\n").unwrap();
        let proxy = ProxyConfig {
            upstreams: vec![UpstreamConfig {
                base_url: "not a url".to_string(),
                key_batches: vec![KeyBatchConfig {
                    path: PathBuf::from("keys.txt"),
                    format: KeyBatchFormat::Txt,
                    rpm: None,
                    tpm: None,
                }],
                ..UpstreamConfig::blank()
            }],
            ..ProxyConfig::blank(1)
        };

        let err = proxy.validate(temp.path()).unwrap_err().to_string();

        assert!(err.contains("URL 不合法"));
    }

    #[test]
    fn validate_allows_zero_router_cooldown() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("keys.txt"), "sk-a\n").unwrap();
        let mut proxy = ProxyConfig::blank(1);
        proxy.router_cooldown_seconds = 0;
        proxy.upstreams[0].key_batches = vec![KeyBatchConfig {
            path: PathBuf::from("keys.txt"),
            format: KeyBatchFormat::Txt,
            rpm: None,
            tpm: None,
        }];

        proxy.validate(temp.path()).unwrap();
    }

    #[test]
    fn renaming_upstream_updates_route_references() {
        let mut proxy = ProxyConfig::blank(1);
        proxy.upstreams[0].name = "聚合ai2".to_string();
        proxy.routes[0].upstreams = vec!["聚合ai2".to_string()];

        rename_upstream_references(&mut proxy.routes, "聚合ai2", "主线路");

        assert_eq!(proxy.routes[0].upstreams, vec!["主线路".to_string()]);
    }

    #[test]
    fn prune_missing_route_upstreams_removes_hidden_stale_history() {
        let mut proxy = ProxyConfig::blank(1);
        proxy.upstreams[0].name = "主线路".to_string();
        proxy.routes[0].upstreams = vec!["聚合ai2".to_string(), "主线路".to_string()];

        prune_missing_route_upstreams(&mut proxy);

        assert_eq!(proxy.routes[0].upstreams, vec!["主线路".to_string()]);
    }

    #[test]
    fn validate_allows_enabled_clash_verge_without_group_name() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("keys.txt"), "sk-a\n").unwrap();
        let mut proxy = ProxyConfig::blank(1);
        proxy.clash_verge.enabled = true;
        proxy.clash_verge.group_name.clear();
        proxy.upstreams[0].key_batches = vec![KeyBatchConfig {
            path: PathBuf::from("keys.txt"),
            format: KeyBatchFormat::Txt,
            rpm: None,
            tpm: None,
        }];

        proxy.validate(temp.path()).unwrap();
        assert!(SmartProxyServer::from_config(&proxy, temp.path()).is_ok());
    }

    #[test]
    fn new_proxy_defaults_to_immediate_combo_rotation_with_expanded_fingerprints() {
        let proxy = ProxyConfig::blank(1);

        assert_eq!(proxy.clash_verge.ip_switch_cooldown_seconds, 0);
        assert_eq!(proxy.clash_verge.recent_node_window, 0);
        assert_eq!(proxy.clash_verge.recent_node_ttl_seconds, 0);
        assert_eq!(proxy.aggregate_egress.recent_fingerprint_window, 0);
        assert_eq!(proxy.aggregate_egress.recent_fingerprint_ttl_seconds, 0);
        assert!(proxy.aggregate_egress.fingerprints.len() > 3);
        assert!(proxy
            .aggregate_egress
            .fingerprints
            .contains(&AggregateFingerprint::Chrome137));
        assert!(proxy
            .aggregate_egress
            .fingerprints
            .contains(&AggregateFingerprint::Firefox139));
    }

    #[test]
    fn smart_proxy_starts_when_clash_controller_is_unreachable() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("keys.txt"), "sk-a\n").unwrap();
        let mut proxy = ProxyConfig::blank(1);
        proxy.clash_verge.enabled = true;
        proxy.clash_verge.controller_url = "http://127.0.0.1:1".to_string();
        proxy.clash_verge.group_name = "自动选择".to_string();
        proxy.upstreams[0].key_batches = vec![KeyBatchConfig {
            path: PathBuf::from("keys.txt"),
            format: KeyBatchFormat::Txt,
            rpm: None,
            tpm: None,
        }];

        let server = SmartProxyServer::from_config(&proxy, temp.path());

        assert!(server.is_ok());
    }

    #[test]
    fn clash_group_discovery_picks_first_switchable_group() {
        let payload = json!({
            "proxies": {
                "DIRECT": {"type": "Direct"},
                "自动选择": {"type": "Selector", "now": "节点A", "all": ["节点A", "节点B"]},
                "故障转移": {"type": "Fallback", "now": "节点C", "all": ["节点C", "节点D"]}
            }
        });

        assert_eq!(
            first_switchable_clash_group(&payload).as_deref(),
            Some("自动选择")
        );
    }

    #[test]
    fn unreachable_clash_controller_does_not_block_key_failure_accounting() {
        let deployments = Arc::new(Mutex::new(vec![smart_test_deployment(
            "dc",
            "https://first.example/v1",
            "sk-first",
        )]));
        let upstreams = smart_test_upstreams(&deployments);
        let temp = tempfile::tempdir().unwrap();
        let quality_path = temp.path().join("key-stats.json");
        let quality_writer = QualityWriteHandle::new(quality_path);
        let controller = ClashVergeController::new(ClashVergeConfig {
            enabled: true,
            controller_url: "http://127.0.0.1:1".to_string(),
            proxy_url: default_clash_verge_proxy_url(),
            secret: String::new(),
            group_name: "自动选择".to_string(),
            rotate_ip_on_key_failure: true,
            rotate_ip_on_rate_limit: true,
            ip_switch_cooldown_seconds: 1,
            recent_node_window: default_recent_node_window(),
            recent_node_ttl_seconds: default_recent_node_ttl_seconds(),
        })
        .unwrap();

        update_deployment_result(
            &deployments,
            &upstreams,
            Some(&controller),
            &quality_writer,
            0,
            402,
            "insufficient_quota",
            Duration::from_millis(500),
            35,
        );

        let snapshot = snapshot_from_deployments(&deployments, &upstreams, None);
        assert_eq!(snapshot.rows[0].failure_requests, 1);
        assert_eq!(snapshot.rows[0].last_status, "402");
    }

    #[test]
    fn generate_yaml_expands_routes_upstreams_and_keys() {
        let temp = tempfile::tempdir().unwrap();
        let dc_keys = temp.path().join("dc.txt");
        let hanhe_keys = temp.path().join("hanhe.csv");
        fs::write(&dc_keys, "sk-dc-a\nsk-dc-b\n").unwrap();
        fs::write(&hanhe_keys, "sk-hanhe,60,2000\n").unwrap();
        let proxy = ProxyConfig {
            name: "主代理".to_string(),
            host: "127.0.0.1".to_string(),
            port: 4000,
            master_key: "sk-local".to_string(),
            litellm_command: "litellm".to_string(),
            engine: ProxyEngine::LiteLlm,
            sticky_keys: true,
            router_cooldown_seconds: 35,
            router_allowed_fails: 0,
            router_num_retries: 0,
            clash_verge: ClashVergeConfig::default(),
            aggregate_egress: SharedAggregateEgressConfig::default(),
            upstreams: vec![
                UpstreamConfig {
                    name: "dc".to_string(),
                    base_url: "https://dc.hhhl.cc/v1".to_string(),
                    provider_prefix: "openai".to_string(),
                    max_qps: None,
                    max_rpm: None,
                    max_concurrency: 1,
                    cooldown_seconds: None,
                    egress_note: String::new(),
                    key_batches: vec![KeyBatchConfig {
                        path: dc_keys,
                        format: KeyBatchFormat::Txt,
                        rpm: Some(30),
                        tpm: None,
                    }],
                },
                UpstreamConfig {
                    name: "hanhe".to_string(),
                    base_url: "https://api.hanhegufei.online/v1".to_string(),
                    provider_prefix: "openai".to_string(),
                    max_qps: None,
                    max_rpm: None,
                    max_concurrency: 1,
                    cooldown_seconds: None,
                    egress_note: String::new(),
                    key_batches: vec![KeyBatchConfig {
                        path: hanhe_keys,
                        format: KeyBatchFormat::Csv,
                        rpm: None,
                        tpm: None,
                    }],
                },
            ],
            routes: vec![RouteConfig {
                public_model: "gpt-5.5".to_string(),
                actual_model: "gpt-5.5".to_string(),
                upstreams: vec!["dc".to_string(), "hanhe".to_string()],
            }],
        };

        let yaml = generate_litellm_yaml(&proxy, temp.path()).unwrap();

        assert!(yaml.contains("model_name: gpt-5.5"));
        assert_eq!(yaml.matches("model_name: gpt-5.5").count(), 2);
        assert!(yaml.contains("api_base: https://dc.hhhl.cc/v1"));
        assert!(yaml.contains("api_base: https://api.hanhegufei.online/v1"));
        assert!(yaml.contains("api_key: sk-dc-a"));
        assert!(!yaml.contains("api_key: sk-dc-b"));
        assert!(yaml.contains("api_key: sk-hanhe"));
        assert!(yaml.contains("master_key: sk-local"));
        assert!(yaml.contains("router_settings:"));
        assert!(yaml.contains("cooldown_time: 35"));
        assert!(yaml.contains("allowed_fails: 0"));
        assert!(yaml.contains("num_retries: 0"));
    }

    #[test]
    fn smart_deployments_keep_blank_egress_note_for_url_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let keys = temp.path().join("keys.txt");
        fs::write(&keys, "sk-first\n").unwrap();
        let mut proxy = ProxyConfig::blank(1);
        proxy.upstreams[0].name = "聚合出口A".to_string();
        proxy.upstreams[0].egress_note = String::new();
        proxy.upstreams[0].key_batches = vec![KeyBatchConfig {
            path: keys,
            format: KeyBatchFormat::Txt,
            rpm: None,
            tpm: None,
        }];
        proxy.routes[0].upstreams = vec!["聚合出口A".to_string()];

        let deployments = build_smart_deployments(&proxy, temp.path()).unwrap();

        assert_eq!(deployments[0].egress_note, "");
    }

    #[test]
    fn smart_proxy_row_egress_display_prefers_clash_then_note_then_base_url() {
        let row = SmartProxyKeyRow {
            upstream: "上游A".to_string(),
            base_url: "https://upstream.example/v1".to_string(),
            key_label: "sk-1".to_string(),
            egress_note: "出口备注A".to_string(),
            recent_clash_node: "香港 01".to_string(),
            recent_clash_egress_ip: "203.0.113.8".to_string(),
            score: 100.0,
            total_requests: 0,
            success_requests: 0,
            failure_requests: 0,
            consecutive_failures: 0,
            average_latency_ms: None,
            last_status: String::new(),
            cooldown_remaining_seconds: 0,
            in_flight: 0,
            limit_status: "-".to_string(),
        };

        assert_eq!(row.egress_display_text(), "香港 01 / 203.0.113.8");
        assert!(row.egress_hover_text().contains("上游名：上游A"));
        assert!(row
            .egress_hover_text()
            .contains("Base URL：https://upstream.example/v1"));
        assert!(row.egress_hover_text().contains("最近 Clash 节点：香港 01"));
        assert!(row
            .egress_hover_text()
            .contains("Clash 出口 IP：203.0.113.8"));
        assert!(row.egress_hover_text().contains("出口备注：出口备注A"));

        let mut without_clash = row.clone();
        without_clash.recent_clash_node.clear();
        without_clash.recent_clash_egress_ip.clear();
        assert_eq!(without_clash.egress_display_text(), "出口备注A");

        without_clash.recent_clash_egress_ip = "203.0.113.9".to_string();
        assert_eq!(without_clash.egress_display_text(), "203.0.113.9");

        without_clash.recent_clash_egress_ip.clear();
        without_clash.egress_note.clear();
        assert_eq!(
            without_clash.egress_display_text(),
            "https://upstream.example/v1"
        );
    }

    #[test]
    fn proxy_egress_ip_lookup_uses_configured_clash_proxy() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = proxy.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = proxy.accept().unwrap();
            let raw = read_http_request(&mut socket).unwrap();
            let request = String::from_utf8_lossy(&raw).to_string();
            let body = "203.0.113.9";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).unwrap();
            request
        });

        let ip = lookup_proxy_egress_ip(&format!("http://127.0.0.1:{port}"));

        let request = handle.join().unwrap();
        assert_eq!(ip.as_deref(), Some("203.0.113.9"));
        assert!(request.starts_with("GET http://api.ipify.org/"));
    }

    fn smart_test_deployment(upstream: &str, base_url: &str, key: &str) -> SmartDeployment {
        SmartDeployment {
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
            key_label: mask_key(key),
            quality_key: key_quality_key(base_url, key, "gpt-5.5"),
            stats: SmartKeyStats::default(),
        }
    }

    fn smart_test_http_client() -> Client {
        Client::builder()
            .connect_timeout(SMART_PROXY_UPSTREAM_CONNECT_TIMEOUT)
            .timeout(smart_proxy_upstream_timeout())
            .build()
            .unwrap()
    }

    #[test]
    fn smart_proxy_failure_update_releases_deployments_before_waiting_on_upstreams() {
        let deployments = Arc::new(Mutex::new(vec![smart_test_deployment(
            "dc",
            "https://same.example/v1",
            "sk-first",
        )]));
        let upstreams = smart_test_upstreams(&deployments);
        let temp = tempfile::tempdir().unwrap();
        let quality_writer = QualityWriteHandle::new(temp.path().join("key-stats.json"));
        let upstream_guard = upstreams.lock().unwrap();
        let worker_deployments = Arc::clone(&deployments);
        let worker_upstreams = Arc::clone(&upstreams);
        let handle = thread::spawn(move || {
            update_deployment_result(
                &worker_deployments,
                &worker_upstreams,
                None,
                &quality_writer,
                0,
                429,
                "ja4 cooldown",
                Duration::from_millis(500),
                35,
            );
        });

        thread::sleep(Duration::from_millis(50));

        assert!(
            deployments.try_lock().is_ok(),
            "failure update must not hold deployments while blocked on upstreams"
        );

        drop(upstream_guard);
        handle.join().unwrap();
    }

    #[test]
    fn smart_proxy_transport_failure_update_releases_deployments_before_waiting_on_upstreams() {
        let deployments = Arc::new(Mutex::new(vec![smart_test_deployment(
            "dc",
            "https://same.example/v1",
            "sk-first",
        )]));
        let upstreams = smart_test_upstreams(&deployments);
        let temp = tempfile::tempdir().unwrap();
        let quality_writer = QualityWriteHandle::new(temp.path().join("key-stats.json"));
        let upstream_guard = upstreams.lock().unwrap();
        let worker_deployments = Arc::clone(&deployments);
        let worker_upstreams = Arc::clone(&upstreams);
        let handle = thread::spawn(move || {
            update_deployment_transport_failure(
                &worker_deployments,
                &worker_upstreams,
                None,
                &quality_writer,
                0,
                Duration::from_millis(500),
                35,
            );
        });

        thread::sleep(Duration::from_millis(50));

        assert!(
            deployments.try_lock().is_ok(),
            "transport failure update must not hold deployments while blocked on upstreams"
        );

        drop(upstream_guard);
        handle.join().unwrap();
    }

    #[test]
    fn smart_proxy_ranks_keys_and_cools_same_url_on_ip_limit() {
        let deployments = Arc::new(Mutex::new(vec![
            smart_test_deployment("dc", "https://same.example/v1", "sk-first"),
            smart_test_deployment("dc", "https://same.example/v1", "sk-second"),
        ]));
        let temp = tempfile::tempdir().unwrap();
        let quality_path = temp.path().join("key-stats.json");
        let quality_writer = QualityWriteHandle::new(quality_path);

        let upstreams = smart_test_upstreams(&deployments);
        let (index, first) =
            select_deployment_rotated(&deployments, &upstreams, "gpt-5.5", 0).unwrap();
        assert_eq!(index, 0);
        assert_eq!(first.key, "sk-first");

        update_deployment_result(
            &deployments,
            &upstreams,
            None,
            &quality_writer,
            0,
            429,
            "ja4 cooldown",
            Duration::from_millis(500),
            35,
        );

        let snapshot = snapshot_from_deployments(&deployments, &upstreams, None);
        assert!(snapshot
            .rows
            .iter()
            .all(|row| row.cooldown_remaining_seconds > 0));
        assert!(select_deployment(&deployments, &upstreams, "gpt-5.5").is_none());
    }

    #[test]
    fn smart_proxy_rotates_equal_score_keys_from_offset() {
        let deployments = Arc::new(Mutex::new(vec![
            smart_test_deployment("dc", "https://same.example/v1", "sk-first"),
            smart_test_deployment("dc", "https://same.example/v1", "sk-second"),
        ]));

        let upstreams = smart_test_upstreams(&deployments);

        let (_, first) = select_deployment_rotated(&deployments, &upstreams, "gpt-5.5", 0).unwrap();
        let (_, second) =
            select_deployment_rotated(&deployments, &upstreams, "gpt-5.5", 1).unwrap();
        let (_, wrapped) =
            select_deployment_rotated(&deployments, &upstreams, "gpt-5.5", 2).unwrap();

        assert_eq!(first.key, "sk-first");
        assert_eq!(second.key, "sk-second");
        assert_eq!(wrapped.key, "sk-first");
    }

    #[test]
    fn smart_proxy_selection_uses_direct_offset_lookup() {
        let source = include_str!("litellm_proxy.rs");
        let block = source
            .split("fn select_deployment_rotated(")
            .nth(1)
            .and_then(|tail| tail.split("fn select_key_exploration_pool").next())
            .expect("selection block should be discoverable");

        assert!(block.contains("candidates.get(offset)"));
        assert!(!block.contains(".cycle()"));
    }

    #[test]
    fn smart_proxy_uses_next_ranked_key_after_key_failure() {
        let deployments = Arc::new(Mutex::new(vec![
            smart_test_deployment("dc", "https://first.example/v1", "sk-first"),
            smart_test_deployment("other", "https://other.example/v1", "sk-second"),
        ]));

        let upstreams = smart_test_upstreams(&deployments);
        let temp = tempfile::tempdir().unwrap();
        let quality_path = temp.path().join("key-stats.json");
        let quality_writer = QualityWriteHandle::new(quality_path);
        update_deployment_result(
            &deployments,
            &upstreams,
            None,
            &quality_writer,
            0,
            402,
            "insufficient_quota",
            Duration::from_millis(500),
            35,
        );

        let (index, selected) = select_deployment(&deployments, &upstreams, "gpt-5.5").unwrap();
        assert_eq!(index, 1);
        assert_eq!(selected.key, "sk-second");
    }

    #[test]
    fn smart_proxy_retries_retryable_http_status_with_next_deployment() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let port = upstream.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(3);
            while requests.len() < 2 && Instant::now() < deadline {
                match upstream.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_nonblocking(false).unwrap();
                        socket
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        socket
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let raw = read_http_request(&mut socket).unwrap();
                        requests.push(String::from_utf8_lossy(&raw).to_string());
                        let (status, reason, body) = if requests.len() == 1 {
                            (502_u16, "Bad Gateway", r#"{"error":"transient"}"#)
                        } else {
                            (200_u16, "OK", r#"{"output_text":"ok"}"#)
                        };
                        let response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        socket.write_all(response.as_bytes()).unwrap();
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => panic!("accept failed: {err}"),
                }
            }
            requests
        });
        let base_url = format!("http://127.0.0.1:{port}/v1");
        let deployments = Arc::new(Mutex::new(vec![
            smart_test_deployment("dc", &base_url, "sk-first"),
            smart_test_deployment("dc", &base_url, "sk-second"),
        ]));
        let upstreams = smart_test_upstreams(&deployments);
        let temp = tempfile::tempdir().unwrap();
        let quality_writer = QualityWriteHandle::new(temp.path().join("key-stats.json"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_port = listener.local_addr().unwrap().port();
        let http_client = smart_test_http_client();
        let server_handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_smart_proxy_client(
                &mut stream,
                deployments,
                upstreams,
                quality_writer,
                None,
                None,
                http_client,
                "sk-local",
                35,
                0,
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(("127.0.0.1", listen_port)).unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello"}"#;
        let request = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer sk-local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        client.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server_handle.join().unwrap();
        let requests = handle.join().unwrap();

        assert_eq!(requests.len(), 2, "{response}");
        assert!(response.contains("200 OK"), "{response}");
    }

    #[test]
    fn smart_proxy_shared_aggregate_streaming_response_is_flushed_before_completion() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let (first_chunk_tx, first_chunk_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let upstream_handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let raw = read_http_request(&mut socket).unwrap();
            let request = String::from_utf8_lossy(&raw).to_string();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                .unwrap();
            socket
                .write_all(
                    b"event: response.output_text.delta\ndata: {\"delta\":\"WATCHAPI_SMART_OK\"}\n\n",
                )
                .unwrap();
            socket.flush().unwrap();
            first_chunk_tx.send(()).unwrap();
            finish_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            socket
                .write_all(b"event: response.completed\ndata: {}\n\n")
                .unwrap();
            socket.flush().unwrap();
            request
        });
        let temp = tempfile::tempdir().unwrap();
        let aggregate_runtime = Arc::new(
            AggregateEgressRuntime::new(
                AggregateEgressConfig {
                    enabled: true,
                    fingerprints: vec![AggregateFingerprint::Chrome132],
                    recent_fingerprint_window: 0,
                    recent_fingerprint_ttl_seconds: 0,
                },
                vec![watchapi_core::aggregate_egress::AggregateDeploymentSeed {
                    upstream: "dc".to_string(),
                    base_url: format!("http://127.0.0.1:{port}/v1"),
                    public_model: "gpt-5.5".to_string(),
                    actual_model: "gpt-5.5".to_string(),
                    max_qps: None,
                    max_rpm: None,
                    max_concurrency: 1,
                    upstream_cooldown_seconds: None,
                    egress_note: String::new(),
                    key: "real-key-stream".to_string(),
                    key_label: "re***am".to_string(),
                    quality_key: "stream".to_string(),
                }],
                temp.path().join("aggregate-quality.json"),
                None,
                35,
            )
            .unwrap(),
        );
        let deployments = Arc::new(Mutex::new(Vec::new()));
        let upstreams = Arc::new(Mutex::new(HashMap::new()));
        let quality_writer = QualityWriteHandle::new(temp.path().join("smart-quality.json"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_port = listener.local_addr().unwrap().port();
        let http_client = smart_test_http_client();
        let server_handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_smart_proxy_client(
                &mut stream,
                deployments,
                upstreams,
                quality_writer,
                None,
                Some(aggregate_runtime),
                http_client,
                "sk-local",
                35,
                0,
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(("127.0.0.1", listen_port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let request = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer sk-local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        client.write_all(request.as_bytes()).unwrap();
        first_chunk_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let mut received = Vec::new();
        let mut buffer = [0_u8; 256];
        loop {
            let size = client.read(&mut buffer).unwrap();
            received.extend_from_slice(&buffer[..size]);
            if String::from_utf8_lossy(&received).contains("WATCHAPI_SMART_OK") {
                break;
            }
        }
        finish_tx.send(()).unwrap();
        server_handle.join().unwrap();
        let upstream_request = upstream_handle.join().unwrap();

        let response = String::from_utf8_lossy(&received);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("text/event-stream"));
        assert!(response.contains("WATCHAPI_SMART_OK"));
        assert!(upstream_request.contains("authorization: Bearer real-key-stream"));
    }

    #[test]
    fn smart_proxy_direct_streaming_response_is_flushed_before_completion() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let (first_chunk_tx, first_chunk_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let upstream_handle = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let raw = read_http_request(&mut socket).unwrap();
            let request = String::from_utf8_lossy(&raw).to_string();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                .unwrap();
            socket
                .write_all(
                    b"event: response.output_text.delta\ndata: {\"delta\":\"WATCHAPI_DIRECT_OK\"}\n\n",
                )
                .unwrap();
            socket.flush().unwrap();
            first_chunk_tx.send(()).unwrap();
            finish_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            socket
                .write_all(b"event: response.completed\ndata: {}\n\n")
                .unwrap();
            socket.flush().unwrap();
            request
        });
        let base_url = format!("http://127.0.0.1:{port}/v1");
        let deployments = Arc::new(Mutex::new(vec![smart_test_deployment(
            "dc",
            &base_url,
            "sk-direct-stream",
        )]));
        let upstreams = smart_test_upstreams(&deployments);
        let temp = tempfile::tempdir().unwrap();
        let quality_writer = QualityWriteHandle::new(temp.path().join("smart-quality.json"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_port = listener.local_addr().unwrap().port();
        let http_client = smart_test_http_client();
        let server_handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_smart_proxy_client(
                &mut stream,
                deployments,
                upstreams,
                quality_writer,
                None,
                None,
                http_client,
                "sk-local",
                35,
                0,
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(("127.0.0.1", listen_port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let body = r#"{"model":"gpt-5.5","input":"hello","stream":true}"#;
        let request = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer sk-local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        client.write_all(request.as_bytes()).unwrap();
        first_chunk_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let mut received = Vec::new();
        let mut buffer = [0_u8; 256];
        loop {
            let size = client.read(&mut buffer).unwrap();
            received.extend_from_slice(&buffer[..size]);
            if String::from_utf8_lossy(&received).contains("WATCHAPI_DIRECT_OK") {
                break;
            }
        }
        finish_tx.send(()).unwrap();
        server_handle.join().unwrap();
        let upstream_request = upstream_handle.join().unwrap();

        let response = String::from_utf8_lossy(&received);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("text/event-stream"));
        assert!(response.contains("WATCHAPI_DIRECT_OK"));
        assert!(upstream_request.contains("authorization: Bearer sk-direct-stream"));
    }

    #[test]
    fn smart_proxy_uses_six_attempt_minimum_for_retryable_failures() {
        assert_eq!(smart_proxy_attempt_budget(0), 6);
        assert_eq!(smart_proxy_attempt_budget(4), 6);
        assert_eq!(smart_proxy_attempt_budget(6), 7);
    }

    #[test]
    fn smart_proxy_upstream_timeout_allows_long_agent_turns() {
        assert!(
            smart_proxy_upstream_timeout() >= Duration::from_secs(900),
            "SmartProxy 不能用 120s 短总超时截断长任务"
        );
    }

    #[test]
    fn smart_proxy_unavailable_body_is_openai_compatible() {
        let body = smart_proxy_unavailable_body("connect reset".to_string());
        let value: Value = serde_json::from_str(&body).unwrap();

        assert_eq!(
            value.pointer("/error/type").and_then(Value::as_str),
            Some("watchapi_smart_proxy_upstream")
        );
        assert!(value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap()
            .contains("connect reset"));
    }

    #[test]
    fn smart_proxy_local_failure_body_is_openai_compatible() {
        let body = smart_proxy_local_failure_body("invalid request".to_string());
        let value: Value = serde_json::from_str(&body).unwrap();

        assert_eq!(
            value.pointer("/error/code").and_then(Value::as_str),
            Some("local_failure")
        );
        assert!(value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap()
            .contains("invalid request"));
    }

    #[test]
    fn smart_proxy_active_client_guard_caps_and_releases_connections() {
        let counter = Arc::new(AtomicUsize::new(SMART_PROXY_MAX_ACTIVE_CLIENTS - 1));
        let guard = try_acquire_active_client(&counter).expect("last slot should be available");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            SMART_PROXY_MAX_ACTIVE_CLIENTS
        );
        assert!(try_acquire_active_client(&counter).is_none());

        drop(guard);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            SMART_PROXY_MAX_ACTIVE_CLIENTS - 1
        );

        let body = smart_proxy_overloaded_body(SMART_PROXY_MAX_ACTIVE_CLIENTS);
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            value.pointer("/error/code").and_then(Value::as_str),
            Some("local_overloaded")
        );
    }

    #[test]
    fn accepted_smart_proxy_client_stream_is_forced_blocking() {
        let source = include_str!("litellm_proxy.rs");
        let accept_worker = source
            .split("let master_key = master_key.clone();")
            .nth(1)
            .and_then(|tail| tail.split("handle_smart_proxy_client").next())
            .expect("smart proxy accept worker should be discoverable");

        assert!(
            accept_worker.contains("stream.set_nonblocking(false)"),
            "accepted client sockets must be forced back to blocking mode to avoid Windows WSAEWOULDBLOCK 10035"
        );
    }

    #[test]
    fn smart_proxy_client_write_side_has_no_short_local_timeout() {
        let source = include_str!("litellm_proxy.rs");
        let accept_worker = source
            .split("let master_key = master_key.clone();")
            .nth(1)
            .and_then(|tail| tail.split("handle_smart_proxy_client").next())
            .expect("smart proxy accept worker should be discoverable");

        assert!(
            accept_worker.contains("stream.set_write_timeout(None)"),
            "SmartProxy 本地写回不能设置短写超时，否则 Windows loopback 阻塞写会变成 10035 并被下游看成 502"
        );
    }

    #[test]
    fn smart_proxy_local_client_io_failures_are_not_reported_as_502() {
        let would_block = anyhow!(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        assert!(should_suppress_local_failure_response(&would_block));

        let timed_out = anyhow!(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert!(should_suppress_local_failure_response(&timed_out));

        let invalid_request = anyhow!("invalid http request");
        assert!(!should_suppress_local_failure_response(&invalid_request));
    }

    #[test]
    fn persisted_key_quality_waits_for_exploration_before_preferring_winner() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("keys.txt"), "sk-slow\nsk-good\n").unwrap();
        let mut proxy = ProxyConfig::blank(1);
        proxy.name = "质量代理".to_string();
        proxy.upstreams[0].base_url = "https://quality.example/v1".to_string();
        proxy.upstreams[0].key_batches = vec![KeyBatchConfig {
            path: PathBuf::from("keys.txt"),
            format: KeyBatchFormat::Txt,
            rpm: None,
            tpm: None,
        }];
        let quality_path = key_quality_path(temp.path(), &proxy);
        let good_key = key_quality_key("https://quality.example/v1", "sk-good", "gpt-5.5");
        KeyQualityStore {
            keys: HashMap::from([(
                good_key,
                PersistedKeyQuality {
                    score: 97.0,
                    total_requests: 30,
                    success_requests: 30,
                    failure_requests: 0,
                    consecutive_failures: 0,
                    latency_ema_ms: Some(600.0),
                    last_status: "200".to_string(),
                },
            )]),
        }
        .save(&quality_path)
        .unwrap();

        let server = SmartProxyServer::from_config(&proxy, temp.path()).unwrap();
        let upstreams = smart_test_upstreams(&server.deployments);
        let (_, selected) =
            select_deployment_rotated(&server.deployments, &upstreams, "gpt-5.5", 0).unwrap();

        assert_eq!(selected.key, "sk-slow");

        {
            let mut items = server.deployments.lock().unwrap();
            items[0].stats.total_requests = MIN_KEY_EXPLORATION_REQUESTS;
            items[0].stats.success_requests = MIN_KEY_EXPLORATION_REQUESTS;
            items[0].stats.score = 82.0;
        }
        let (_, selected) =
            select_deployment_rotated(&server.deployments, &upstreams, "gpt-5.5", 0).unwrap();

        assert_eq!(selected.key, "sk-good");
        assert_eq!(selected.stats.total_requests, 30);
        assert_eq!(selected.stats.latency_ema_ms, Some(600.0));
    }

    #[test]
    fn key_selection_explores_all_keys_before_quality_winner() {
        let deployments = Arc::new(Mutex::new(vec![
            smart_test_deployment("dc", "https://quality.example/v1", "sk-good"),
            smart_test_deployment("dc", "https://quality.example/v1", "sk-new"),
        ]));
        {
            let mut items = deployments.lock().unwrap();
            items[0].stats.score = 98.0;
            items[0].stats.total_requests = 10;
            items[0].stats.success_requests = 10;
            items[1].stats.score = 80.0;
            items[1].stats.total_requests = 0;
        }
        let upstreams = smart_test_upstreams(&deployments);

        let (_, selected) =
            select_deployment_rotated(&deployments, &upstreams, "gpt-5.5", 0).unwrap();

        assert_eq!(selected.key, "sk-new");
    }

    #[test]
    fn key_selection_uses_quality_after_exploration_floor() {
        let deployments = Arc::new(Mutex::new(vec![
            smart_test_deployment("dc", "https://quality.example/v1", "sk-good"),
            smart_test_deployment("dc", "https://quality.example/v1", "sk-bad"),
        ]));
        {
            let mut items = deployments.lock().unwrap();
            items[0].stats.score = 98.0;
            items[0].stats.total_requests = MIN_KEY_EXPLORATION_REQUESTS;
            items[0].stats.success_requests = MIN_KEY_EXPLORATION_REQUESTS;
            items[1].stats.score = 70.0;
            items[1].stats.total_requests = MIN_KEY_EXPLORATION_REQUESTS;
            items[1].stats.success_requests = MIN_KEY_EXPLORATION_REQUESTS / 2;
        }
        let upstreams = smart_test_upstreams(&deployments);

        let (_, selected) =
            select_deployment_rotated(&deployments, &upstreams, "gpt-5.5", 1).unwrap();

        assert_eq!(selected.key, "sk-good");
    }

    #[test]
    fn key_quality_score_penalizes_slow_successes() {
        let mut fast = SmartKeyStats {
            total_requests: 10,
            success_requests: 10,
            ..Default::default()
        };
        fast.observe_latency(Duration::from_millis(400));
        fast.recalculate_score();

        let mut slow = SmartKeyStats {
            total_requests: 10,
            success_requests: 10,
            ..Default::default()
        };
        slow.observe_latency(Duration::from_secs(12));
        slow.recalculate_score();

        assert!(fast.score > slow.score);
        assert!(slow.score < 90.0);
    }

    #[test]
    fn update_deployment_result_persists_key_quality() {
        let temp = tempfile::tempdir().unwrap();
        let quality_path = temp.path().join("key-stats.json");
        let deployments = Arc::new(Mutex::new(vec![smart_test_deployment(
            "dc",
            "https://persist.example/v1",
            "sk-persist",
        )]));
        let upstreams = smart_test_upstreams(&deployments);
        let quality_writer = QualityWriteHandle::new(quality_path.clone());

        update_deployment_result(
            &deployments,
            &upstreams,
            None,
            &quality_writer,
            0,
            200,
            r#"{"ok":true}"#,
            Duration::from_millis(750),
            35,
        );
        quality_writer.flush();

        let store = KeyQualityStore::load(&quality_path);
        let quality_key = key_quality_key("https://persist.example/v1", "sk-persist", "gpt-5.5");
        let saved = store
            .keys
            .get(&quality_key)
            .expect("quality should persist");
        assert_eq!(saved.total_requests, 1);
        assert_eq!(saved.success_requests, 1);
        assert_eq!(saved.latency_ema_ms, Some(750.0));
    }

    #[test]
    fn smart_proxy_success_clears_key_and_upstream_cooldown() {
        let temp = tempfile::tempdir().unwrap();
        let quality_writer = QualityWriteHandle::new(temp.path().join("key-stats.json"));
        let deployments = Arc::new(Mutex::new(vec![smart_test_deployment(
            "dc",
            "https://cooldown.example/v1",
            "sk-a",
        )]));
        let upstreams = smart_test_upstreams(&deployments);

        update_deployment_result(
            &deployments,
            &upstreams,
            None,
            &quality_writer,
            0,
            429,
            "rate limit",
            Duration::from_millis(10),
            60,
        );
        update_deployment_result(
            &deployments,
            &upstreams,
            None,
            &quality_writer,
            0,
            200,
            r#"{"ok":true}"#,
            Duration::from_millis(10),
            60,
        );

        assert!(deployments.lock().unwrap()[0]
            .stats
            .cooldown_until
            .is_none());
        assert!(upstreams
            .lock()
            .unwrap()
            .get("https://cooldown.example/v1")
            .is_some_and(|state| state.cooldown_until.is_none()));
    }

    #[test]
    fn smart_proxy_quality_writer_keeps_pending_on_save_failure() {
        let source = include_str!("litellm_proxy.rs");
        let block = source
            .split("impl QualityWriteHandle")
            .nth(1)
            .and_then(|tail| tail.split("impl ProxyConfig").next())
            .expect("quality writer block should be discoverable");

        assert!(block.contains("flush_quality_pending"));
        assert!(!block.contains("let _ = store.save"));
        assert!(source.contains("if store.save(path).is_ok()"));
        assert!(source.contains("for _ in 0..attempts.max(1)"));
        assert!(block.contains("40"));
    }

    #[test]
    fn smart_proxy_respects_upstream_rpm_limit() {
        let mut deployment = smart_test_deployment("dc", "https://limited.example/v1", "sk-first");
        deployment.max_rpm = Some(1);
        deployment.max_concurrency = 2;
        deployment.egress_note = "出口A".to_string();
        let deployments = Arc::new(Mutex::new(vec![deployment]));
        let upstreams = smart_test_upstreams(&deployments);

        assert!(select_deployment(&deployments, &upstreams, "gpt-5.5").is_some());
        mark_upstream_request_started(&upstreams, "https://limited.example/v1");

        assert!(select_deployment(&deployments, &upstreams, "gpt-5.5").is_none());
        let snapshot = snapshot_from_deployments(&deployments, &upstreams, None);
        assert_eq!(snapshot.rows[0].egress_note, "出口A");
        assert!(snapshot.rows[0].limit_status.contains("RPM 1/1"));
    }

    #[test]
    fn key_failure_rotates_clash_verge_group_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let mut first_buf = [0_u8; 4096];
            let first_size = first.read(&mut first_buf).unwrap();
            let first_text = String::from_utf8_lossy(&first_buf[..first_size]).to_string();
            let first_body = br#"{"all":["node-a","node-b"],"now":"node-a"}"#;
            let first_response = format!(
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                first_body.len(),
                String::from_utf8_lossy(first_body)
            );
            first.write_all(first_response.as_bytes()).unwrap();
            first.flush().unwrap();
            drop(first);

            let (mut second, _) = listener.accept().unwrap();
            let mut second_buf = [0_u8; 4096];
            let second_size = second.read(&mut second_buf).unwrap();
            let second_text = String::from_utf8_lossy(&second_buf[..second_size]).to_string();
            let second_body = br#"{}"#;
            let second_response = format!(
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                second_body.len(),
                String::from_utf8_lossy(second_body)
            );
            second.write_all(second_response.as_bytes()).unwrap();
            second.flush().unwrap();
            (first_text, second_text)
        });

        let deployments = Arc::new(Mutex::new(vec![smart_test_deployment(
            "dc",
            "https://first.example/v1",
            "sk-first",
        )]));
        let upstreams = smart_test_upstreams(&deployments);
        let temp = tempfile::tempdir().unwrap();
        let quality_path = temp.path().join("key-stats.json");
        let quality_writer = QualityWriteHandle::new(quality_path);
        let controller = ClashVergeController::new(ClashVergeConfig {
            enabled: true,
            controller_url: format!("http://127.0.0.1:{port}"),
            proxy_url: default_clash_verge_proxy_url(),
            secret: "secret-1".to_string(),
            group_name: "自动选择".to_string(),
            rotate_ip_on_key_failure: true,
            rotate_ip_on_rate_limit: true,
            ip_switch_cooldown_seconds: 15,
            recent_node_window: default_recent_node_window(),
            recent_node_ttl_seconds: default_recent_node_ttl_seconds(),
        })
        .unwrap();

        update_deployment_result(
            &deployments,
            &upstreams,
            Some(&controller),
            &quality_writer,
            0,
            402,
            "insufficient_quota",
            Duration::from_millis(500),
            35,
        );

        let (first_request, second_request) = handle.join().unwrap();
        assert!(
            first_request.starts_with("GET /proxies/%E8%87%AA%E5%8A%A8%E9%80%89%E6%8B%A9 HTTP/1.1")
        );
        assert!(first_request
            .to_ascii_lowercase()
            .contains("authorization: bearer secret-1"));
        assert!(second_request
            .starts_with("PUT /proxies/%E8%87%AA%E5%8A%A8%E9%80%89%E6%8B%A9 HTTP/1.1"));
        assert!(second_request.contains("\"name\":\"node-b\""));
    }

    #[test]
    fn clash_verge_rotation_obeys_switch_cooldown() {
        let controller = ClashVergeController::new(ClashVergeConfig {
            enabled: true,
            controller_url: "http://127.0.0.1:1".to_string(),
            proxy_url: default_clash_verge_proxy_url(),
            secret: "secret-1".to_string(),
            group_name: "自动选择".to_string(),
            rotate_ip_on_key_failure: true,
            rotate_ip_on_rate_limit: true,
            ip_switch_cooldown_seconds: 60,
            recent_node_window: default_recent_node_window(),
            recent_node_ttl_seconds: default_recent_node_ttl_seconds(),
        })
        .unwrap();
        *controller.last_switch_at.lock().unwrap() = Some(Instant::now());

        controller.maybe_rotate_for_failure(FailureKind::KeyFailure);

        assert!(controller.last_switch_at.lock().unwrap().is_some());
    }

    #[test]
    fn clash_verge_zero_switch_cooldown_allows_immediate_retry() {
        let source = include_str!("litellm_proxy.rs");
        let block = source
            .split("fn maybe_rotate_for_failure")
            .nth(1)
            .and_then(|tail| tail.split("fn switch_group").next())
            .expect("clash rotate helper should be discoverable");

        assert!(
            block.contains("Duration::from_secs(self.config.ip_switch_cooldown_seconds as u64)")
        );
        assert!(
            !block.contains("ip_switch_cooldown_seconds.max(1)"),
            "0 秒 IP 切换冷却必须真正允许立即再次切换"
        );
    }

    #[test]
    fn clash_verge_group_candidates_rotate_in_order() {
        let controller = ClashVergeController::new(ClashVergeConfig::default()).unwrap();
        let candidates = vec!["node-a", "node-b", "node-c"];

        let first = controller
            .next_group_candidate("自动选择", &candidates)
            .unwrap();
        let second = controller
            .next_group_candidate("自动选择", &candidates)
            .unwrap();
        let third = controller
            .next_group_candidate("自动选择", &candidates)
            .unwrap();
        let wrapped = controller
            .next_group_candidate("自动选择", &candidates)
            .unwrap();

        assert_eq!(first, "node-a");
        assert_eq!(second, "node-b");
        assert_eq!(third, "node-c");
        assert_eq!(wrapped, "node-a");
    }

    #[test]
    fn clash_verge_skips_recent_nodes_before_fallback_rotation() {
        let controller = ClashVergeController::new(ClashVergeConfig {
            recent_node_window: 2,
            recent_node_ttl_seconds: 300,
            ..ClashVergeConfig::default()
        })
        .unwrap();
        controller.remember_group_node("自动选择", "node-a");
        controller.remember_group_node("自动选择", "node-b");
        let candidates = vec!["node-a", "node-b", "node-c"];

        let selected = controller
            .next_group_candidate("自动选择", &candidates)
            .unwrap();

        assert_eq!(selected, "node-c");
    }

    #[test]
    fn clash_verge_falls_back_to_rotation_when_all_candidates_are_recent() {
        let controller = ClashVergeController::new(ClashVergeConfig {
            recent_node_window: 3,
            recent_node_ttl_seconds: 300,
            ..ClashVergeConfig::default()
        })
        .unwrap();
        controller.remember_group_node("自动选择", "node-a");
        controller.remember_group_node("自动选择", "node-b");
        let candidates = vec!["node-a", "node-b"];

        let selected = controller
            .next_group_candidate("自动选择", &candidates)
            .unwrap();

        assert_eq!(selected, "node-a");
    }

    fn smart_test_upstreams(
        deployments: &Arc<Mutex<Vec<SmartDeployment>>>,
    ) -> Arc<Mutex<HashMap<String, SmartUpstreamRuntime>>> {
        let map = deployments
            .lock()
            .unwrap()
            .iter()
            .map(|deployment| {
                (
                    deployment.base_url.clone(),
                    SmartUpstreamRuntime {
                        recent_request_times: Vec::new(),
                        in_flight: 0,
                        cooldown_until: None,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        Arc::new(Mutex::new(map))
    }
}
