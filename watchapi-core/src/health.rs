use crate::config::EndpointConfig;
use crate::probe::ProbeResult;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EndpointHealth {
    pub effective_available: bool,
    pub raw_available: bool,
    pub seen: bool,
    pub consecutive_successes: u32,
    pub consecutive_failures: u32,
    pub last_polluted: bool,
    pub last_quota_limited: bool,
    pub last_error: String,
}

#[derive(Debug, Clone)]
pub struct EndpointHealthTracker {
    failure_threshold: u32,
    recovery_threshold: u32,
    states: HashMap<String, EndpointHealth>,
}

impl EndpointHealthTracker {
    pub fn new(failure_threshold: u32, recovery_threshold: u32) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            recovery_threshold: recovery_threshold.max(1),
            states: HashMap::new(),
        }
    }

    pub fn update(
        &mut self,
        endpoints: &[EndpointConfig],
        raw_availability: &HashMap<String, ProbeResult>,
    ) -> HashMap<String, bool> {
        self.states
            .retain(|name, _| endpoints.iter().any(|endpoint| endpoint.name == *name));

        for endpoint in endpoints {
            let state = self.states.entry(endpoint.name.clone()).or_default();
            let Some(result) = raw_availability.get(&endpoint.name) else {
                continue;
            };
            state.raw_available = result.available;
            state.last_polluted = result.polluted;
            state.last_quota_limited = result.quota_limited;
            state.last_error = result.error.clone();

            if result.available {
                state.consecutive_successes += 1;
                state.consecutive_failures = 0;
                if !state.seen
                    || state.effective_available
                    || state.consecutive_successes >= self.recovery_threshold
                {
                    state.effective_available = true;
                }
            } else {
                state.consecutive_failures += 1;
                state.consecutive_successes = 0;
                if state.effective_available
                    && (state.last_polluted
                        || state.last_quota_limited
                        || state.consecutive_failures >= self.failure_threshold)
                {
                    state.effective_available = false;
                }
            }
            state.seen = true;
        }

        endpoints
            .iter()
            .map(|endpoint| {
                (
                    endpoint.name.clone(),
                    self.is_effectively_available(&endpoint.name),
                )
            })
            .collect()
    }

    pub fn is_effectively_available(&self, endpoint_name: &str) -> bool {
        self.states
            .get(endpoint_name)
            .map(|state| state.effective_available)
            .unwrap_or(false)
    }

    pub fn reset(&mut self, endpoint_name: &str) {
        self.states.remove(endpoint_name);
    }

    pub fn status_label(&self, endpoint_name: &str) -> String {
        let Some(state) = self.states.get(endpoint_name) else {
            return "未知".to_string();
        };
        if !state.seen {
            return "未知".to_string();
        }
        if state.raw_available {
            if state.effective_available {
                return "正常".to_string();
            }
            return format!(
                "恢复中 {}/{}",
                state.consecutive_successes, self.recovery_threshold
            );
        }
        if state.last_polluted {
            return if state.effective_available {
                "污染"
            } else {
                "污染不可用"
            }
            .to_string();
        }
        if state.last_quota_limited {
            return if state.effective_available {
                "额度不足"
            } else {
                "额度不可用"
            }
            .to_string();
        }
        if state.effective_available {
            return format!(
                "失败 {}/{}",
                state.consecutive_failures, self.failure_threshold
            );
        }
        "不可用".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn endpoint(name: &str) -> EndpointConfig {
        EndpointConfig {
            name: name.to_string(),
            base_url: "https://example.test/v1".to_string(),
            api_key: "key".to_string(),
            model: "gpt-test".to_string(),
            reasoning_effort: "high".to_string(),
            service_tier: None,
            initial_prompt: "init".to_string(),
            auto_prompt: "auto".to_string(),
            workdir: PathBuf::from("."),
            weight: 100,
            enabled: true,
            probe_url: None,
            guard_proxy: Default::default(),
        }
    }

    #[test]
    fn failure_threshold_requires_consecutive_failures_to_mark_down() {
        let endpoints = vec![endpoint("high")];
        let mut health = EndpointHealthTracker::new(3, 2);
        let mut raw = HashMap::new();
        raw.insert("high".to_string(), ProbeResult::available());
        health.update(&endpoints, &raw);

        raw.insert("high".to_string(), ProbeResult::unavailable());
        health.update(&endpoints, &raw);
        assert_eq!(health.status_label("high"), "失败 1/3");
        health.update(&endpoints, &raw);
        assert_eq!(health.status_label("high"), "失败 2/3");
        health.update(&endpoints, &raw);
        assert_eq!(health.status_label("high"), "不可用");
    }

    #[test]
    fn polluted_result_marks_down_immediately() {
        let endpoints = vec![endpoint("high")];
        let mut health = EndpointHealthTracker::new(3, 2);
        let mut raw = HashMap::new();
        raw.insert("high".to_string(), ProbeResult::available());
        health.update(&endpoints, &raw);

        raw.insert("high".to_string(), ProbeResult::polluted());
        health.update(&endpoints, &raw);

        assert_eq!(health.status_label("high"), "污染不可用");
        assert!(!health.is_effectively_available("high"));
    }
}
