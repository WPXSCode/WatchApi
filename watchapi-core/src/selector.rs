use crate::config::EndpointConfig;
use std::collections::HashMap;

pub fn choose_best_endpoint<'a>(
    endpoints: &'a [EndpointConfig],
    availability: &HashMap<String, bool>,
) -> Option<&'a EndpointConfig> {
    endpoints
        .iter()
        .filter(|endpoint| endpoint.enabled)
        .filter(|endpoint| availability.get(&endpoint.name).copied().unwrap_or(false))
        .max_by_key(|endpoint| endpoint.weight)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn endpoint(name: &str, weight: i64, enabled: bool) -> EndpointConfig {
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
            weight,
            enabled,
            probe_url: None,
            guard_proxy: Default::default(),
        }
    }

    #[test]
    fn chooses_highest_weight_available_endpoint() {
        let endpoints = vec![endpoint("low", 10, true), endpoint("high", 100, true)];
        let availability = HashMap::from([("low".to_string(), true), ("high".to_string(), true)]);

        assert_eq!(
            choose_best_endpoint(&endpoints, &availability)
                .unwrap()
                .name,
            "high"
        );
    }

    #[test]
    fn ignores_disabled_endpoints() {
        let endpoints = vec![endpoint("low", 10, true), endpoint("high", 100, false)];
        let availability = HashMap::from([("low".to_string(), true), ("high".to_string(), true)]);

        assert_eq!(
            choose_best_endpoint(&endpoints, &availability)
                .unwrap()
                .name,
            "low"
        );
    }
}
