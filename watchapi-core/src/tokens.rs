use serde_json::Value;
use std::collections::HashMap;
use std::ops::Add;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_output_tokens: u64,
    pub total_tokens: u64,
}

impl TokenUsage {
    pub fn is_empty(&self) -> bool {
        self.input_tokens == 0
            && self.cached_input_tokens == 0
            && self.output_tokens == 0
            && self.total_tokens == 0
    }

    pub fn delta_from(&self, previous: TokenUsage) -> TokenUsage {
        TokenUsage {
            input_tokens: self.input_tokens.saturating_sub(previous.input_tokens),
            cached_input_tokens: self
                .cached_input_tokens
                .saturating_sub(previous.cached_input_tokens),
            output_tokens: self.output_tokens.saturating_sub(previous.output_tokens),
            reasoning_output_tokens: self
                .reasoning_output_tokens
                .saturating_sub(previous.reasoning_output_tokens),
            total_tokens: self.total_tokens.saturating_sub(previous.total_tokens),
        }
    }
}

impl Add for TokenUsage {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self {
            input_tokens: self.input_tokens + other.input_tokens,
            cached_input_tokens: self.cached_input_tokens + other.cached_input_tokens,
            output_tokens: self.output_tokens + other.output_tokens,
            reasoning_output_tokens: self.reasoning_output_tokens + other.reasoning_output_tokens,
            total_tokens: self.total_tokens + other.total_tokens,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelTokenPrice {
    pub input_per_million: f64,
    pub cached_input_per_million: f64,
    pub output_per_million: f64,
}

pub fn format_token_cost(model: &str, usage: TokenUsage) -> String {
    let tokens = compact_tokens(
        usage
            .total_tokens
            .max(usage.input_tokens + usage.output_tokens),
    );
    let Some(cost) = calculate_token_cost_usd(model, usage) else {
        return format!("{tokens}/未知");
    };
    format!("{tokens}/{}", format_usd(cost))
}

pub fn calculate_token_cost_usd(model: &str, usage: TokenUsage) -> Option<f64> {
    let price = model_token_price(model)?;
    let uncached_input = usage.input_tokens.saturating_sub(usage.cached_input_tokens);
    Some(
        uncached_input as f64 * price.input_per_million / 1_000_000.0
            + usage.cached_input_tokens as f64 * price.cached_input_per_million / 1_000_000.0
            + usage.output_tokens as f64 * price.output_per_million / 1_000_000.0,
    )
}

pub fn model_probe_price_score(model: &str) -> Option<f64> {
    let price = model_token_price(model)?;
    Some(price.input_per_million + price.output_per_million)
}

pub fn model_token_price(model: &str) -> Option<ModelTokenPrice> {
    let key = model_key(model);
    let table = price_table();
    if let Some(price) = table.get(key.as_str()).copied() {
        return Some(price);
    }
    let normalized = normalize_model_id_for_price(&key);
    if normalized != key {
        if let Some(price) = table.get(normalized.as_str()).copied() {
            return Some(price);
        }
    }
    let mut candidates: Vec<_> = table.keys().copied().collect();
    candidates.sort_by_key(|item| std::cmp::Reverse(item.len()));
    for candidate in candidates {
        if key.starts_with(&(candidate.to_string() + "-")) {
            return table.get(candidate).copied();
        }
    }
    None
}

pub fn normalize_model_id_for_price(model: &str) -> String {
    let mut value = model_key(model);
    for marker in ["-preview", "-latest"] {
        if let Some(index) = value.rfind(marker) {
            let tail = &value[index + marker.len()..];
            if tail.is_empty() || is_dash_date(tail) {
                value.truncate(index);
                break;
            }
        }
    }
    if let Some(prefix) = strip_ascii_suffix(&value, 11, |suffix| {
        suffix.starts_with('-') && is_yyyy_mm_dd(&suffix[1..])
    }) {
        value = prefix;
    }
    if let Some(prefix) = strip_ascii_suffix(&value, 9, |suffix| {
        suffix.starts_with('-') && suffix[1..].chars().all(|ch| ch.is_ascii_digit())
    }) {
        value = prefix;
    }
    value
}

fn strip_ascii_suffix(
    value: &str,
    suffix_len: usize,
    predicate: impl FnOnce(&str) -> bool,
) -> Option<String> {
    if value.len() <= suffix_len {
        return None;
    }
    let start = value.len().checked_sub(suffix_len)?;
    if !value.is_char_boundary(start) {
        return None;
    }
    let suffix = &value[start..];
    predicate(suffix).then(|| value[..start].to_string())
}

pub fn extract_token_usage(payload: &Value) -> TokenUsage {
    let Some(usage) = payload.get("usage").and_then(Value::as_object) else {
        return TokenUsage::default();
    };
    let input_tokens = int_value([usage.get("input_tokens"), usage.get("prompt_tokens")]);
    let output_tokens = int_value([usage.get("output_tokens"), usage.get("completion_tokens")]);
    let total_tokens = int_value([usage.get("total_tokens")]).max(input_tokens + output_tokens);
    let cached_input_tokens = usage
        .get("input_tokens_details")
        .or_else(|| usage.get("prompt_tokens_details"))
        .and_then(Value::as_object)
        .map(|details| {
            int_value([
                details.get("cached_tokens"),
                details.get("cached_input_tokens"),
            ])
        })
        .unwrap_or_default();
    let reasoning_output_tokens = usage
        .get("output_tokens_details")
        .or_else(|| usage.get("completion_tokens_details"))
        .and_then(Value::as_object)
        .map(|details| int_value([details.get("reasoning_tokens")]))
        .unwrap_or_default();

    TokenUsage {
        input_tokens,
        cached_input_tokens,
        output_tokens,
        reasoning_output_tokens,
        total_tokens,
    }
}

fn compact_tokens(tokens: u64) -> String {
    if tokens >= 1_000_000 {
        format!("{:.2}M", tokens as f64 / 1_000_000.0)
    } else if tokens >= 1_000 {
        format!("{:.1}k", tokens as f64 / 1_000.0).replace(".0k", "k")
    } else {
        tokens.to_string()
    }
}

fn format_usd(cost: f64) -> String {
    if cost < 0.01 {
        format!("${cost:.4}")
    } else if cost < 1.0 {
        format!("${cost:.3}")
    } else {
        format!("${cost:.2}")
    }
}

fn price_table() -> HashMap<&'static str, ModelTokenPrice> {
    use ModelTokenPrice as P;
    HashMap::from([
        (
            "gpt-5.5",
            P {
                input_per_million: 5.00,
                cached_input_per_million: 0.50,
                output_per_million: 30.00,
            },
        ),
        (
            "gpt-5.5-pro",
            P {
                input_per_million: 30.00,
                cached_input_per_million: 30.00,
                output_per_million: 180.00,
            },
        ),
        (
            "gpt-5.4",
            P {
                input_per_million: 2.50,
                cached_input_per_million: 0.25,
                output_per_million: 15.00,
            },
        ),
        (
            "gpt-5.4-mini",
            P {
                input_per_million: 0.75,
                cached_input_per_million: 0.075,
                output_per_million: 4.50,
            },
        ),
        (
            "gpt-5.4-pro",
            P {
                input_per_million: 30.00,
                cached_input_per_million: 30.00,
                output_per_million: 180.00,
            },
        ),
        (
            "gpt-5.2",
            P {
                input_per_million: 1.75,
                cached_input_per_million: 0.175,
                output_per_million: 14.00,
            },
        ),
        (
            "gpt-5.2-chat-latest",
            P {
                input_per_million: 1.75,
                cached_input_per_million: 0.175,
                output_per_million: 14.00,
            },
        ),
        (
            "gpt-5.2-codex",
            P {
                input_per_million: 1.75,
                cached_input_per_million: 0.175,
                output_per_million: 14.00,
            },
        ),
        (
            "gpt-5.2-pro",
            P {
                input_per_million: 21.00,
                cached_input_per_million: 21.00,
                output_per_million: 168.00,
            },
        ),
        (
            "gpt-5.1",
            P {
                input_per_million: 1.25,
                cached_input_per_million: 0.125,
                output_per_million: 10.00,
            },
        ),
        (
            "gpt-5.1-chat-latest",
            P {
                input_per_million: 1.25,
                cached_input_per_million: 0.125,
                output_per_million: 10.00,
            },
        ),
        (
            "gpt-5.1-codex",
            P {
                input_per_million: 1.25,
                cached_input_per_million: 0.125,
                output_per_million: 10.00,
            },
        ),
        (
            "gpt-5.1-codex-mini",
            P {
                input_per_million: 0.25,
                cached_input_per_million: 0.025,
                output_per_million: 2.00,
            },
        ),
        (
            "gpt-5.1-codex-max",
            P {
                input_per_million: 1.25,
                cached_input_per_million: 0.125,
                output_per_million: 10.00,
            },
        ),
        (
            "gpt-5",
            P {
                input_per_million: 1.25,
                cached_input_per_million: 0.125,
                output_per_million: 10.00,
            },
        ),
        (
            "gpt-5-chat-latest",
            P {
                input_per_million: 1.25,
                cached_input_per_million: 0.125,
                output_per_million: 10.00,
            },
        ),
        (
            "gpt-5-codex",
            P {
                input_per_million: 1.25,
                cached_input_per_million: 0.125,
                output_per_million: 10.00,
            },
        ),
        (
            "gpt-5-mini",
            P {
                input_per_million: 0.25,
                cached_input_per_million: 0.025,
                output_per_million: 2.00,
            },
        ),
        (
            "gpt-5-nano",
            P {
                input_per_million: 0.05,
                cached_input_per_million: 0.005,
                output_per_million: 0.40,
            },
        ),
        (
            "gpt-5-pro",
            P {
                input_per_million: 15.00,
                cached_input_per_million: 15.00,
                output_per_million: 120.00,
            },
        ),
        (
            "gpt-4.1",
            P {
                input_per_million: 2.00,
                cached_input_per_million: 0.50,
                output_per_million: 8.00,
            },
        ),
        (
            "gpt-4.1-mini",
            P {
                input_per_million: 0.40,
                cached_input_per_million: 0.10,
                output_per_million: 1.60,
            },
        ),
        (
            "gpt-4.1-nano",
            P {
                input_per_million: 0.10,
                cached_input_per_million: 0.025,
                output_per_million: 0.40,
            },
        ),
        (
            "gpt-4o",
            P {
                input_per_million: 2.50,
                cached_input_per_million: 1.25,
                output_per_million: 10.00,
            },
        ),
        (
            "gpt-4o-mini",
            P {
                input_per_million: 0.15,
                cached_input_per_million: 0.075,
                output_per_million: 0.60,
            },
        ),
        (
            "gpt-realtime",
            P {
                input_per_million: 4.00,
                cached_input_per_million: 0.40,
                output_per_million: 16.00,
            },
        ),
        (
            "gpt-realtime-2",
            P {
                input_per_million: 4.00,
                cached_input_per_million: 0.40,
                output_per_million: 24.00,
            },
        ),
        (
            "claude-haiku-3.5",
            P {
                input_per_million: 0.80,
                cached_input_per_million: 0.08,
                output_per_million: 4.00,
            },
        ),
        (
            "claude-3-5-haiku-latest",
            P {
                input_per_million: 0.80,
                cached_input_per_million: 0.08,
                output_per_million: 4.00,
            },
        ),
        (
            "claude-haiku-4.5",
            P {
                input_per_million: 1.00,
                cached_input_per_million: 0.10,
                output_per_million: 5.00,
            },
        ),
        (
            "claude-4-5-haiku-latest",
            P {
                input_per_million: 1.00,
                cached_input_per_million: 0.10,
                output_per_million: 5.00,
            },
        ),
        (
            "claude-sonnet-4",
            P {
                input_per_million: 3.00,
                cached_input_per_million: 0.30,
                output_per_million: 15.00,
            },
        ),
        (
            "claude-sonnet-4-5",
            P {
                input_per_million: 3.00,
                cached_input_per_million: 0.30,
                output_per_million: 15.00,
            },
        ),
        (
            "claude-sonnet-4-6",
            P {
                input_per_million: 3.00,
                cached_input_per_million: 0.30,
                output_per_million: 15.00,
            },
        ),
        (
            "claude-4-sonnet-latest",
            P {
                input_per_million: 3.00,
                cached_input_per_million: 0.30,
                output_per_million: 15.00,
            },
        ),
        (
            "claude-opus-4",
            P {
                input_per_million: 15.00,
                cached_input_per_million: 1.50,
                output_per_million: 75.00,
            },
        ),
        (
            "claude-opus-4-1",
            P {
                input_per_million: 15.00,
                cached_input_per_million: 1.50,
                output_per_million: 75.00,
            },
        ),
        (
            "claude-opus-4.1",
            P {
                input_per_million: 15.00,
                cached_input_per_million: 1.50,
                output_per_million: 75.00,
            },
        ),
        (
            "claude-opus-4-5",
            P {
                input_per_million: 5.00,
                cached_input_per_million: 0.50,
                output_per_million: 25.00,
            },
        ),
        (
            "claude-opus-4-6",
            P {
                input_per_million: 5.00,
                cached_input_per_million: 0.50,
                output_per_million: 25.00,
            },
        ),
        (
            "claude-opus-4-7",
            P {
                input_per_million: 5.00,
                cached_input_per_million: 0.50,
                output_per_million: 25.00,
            },
        ),
        (
            "gemini-2.0-flash-lite",
            P {
                input_per_million: 0.075,
                cached_input_per_million: 0.075,
                output_per_million: 0.30,
            },
        ),
        (
            "gemini-2.0-flash",
            P {
                input_per_million: 0.10,
                cached_input_per_million: 0.025,
                output_per_million: 0.40,
            },
        ),
        (
            "gemini-2.5-flash-lite",
            P {
                input_per_million: 0.10,
                cached_input_per_million: 0.01,
                output_per_million: 0.40,
            },
        ),
        (
            "gemini-2.5-flash-lite-preview-06-17",
            P {
                input_per_million: 0.10,
                cached_input_per_million: 0.01,
                output_per_million: 0.40,
            },
        ),
        (
            "gemini-3.1-flash-lite",
            P {
                input_per_million: 0.10,
                cached_input_per_million: 0.01,
                output_per_million: 0.40,
            },
        ),
        (
            "gemini-3-flash",
            P {
                input_per_million: 0.50,
                cached_input_per_million: 0.05,
                output_per_million: 3.00,
            },
        ),
        (
            "gemini-2.5-flash",
            P {
                input_per_million: 0.30,
                cached_input_per_million: 0.03,
                output_per_million: 2.50,
            },
        ),
        (
            "gemini-2.5-pro",
            P {
                input_per_million: 1.25,
                cached_input_per_million: 0.125,
                output_per_million: 10.00,
            },
        ),
        (
            "gemini-2.5-computer-use-preview-10-2025",
            P {
                input_per_million: 1.25,
                cached_input_per_million: 0.125,
                output_per_million: 10.00,
            },
        ),
        (
            "gemini-3.1-pro",
            P {
                input_per_million: 2.00,
                cached_input_per_million: 0.20,
                output_per_million: 12.00,
            },
        ),
        (
            "grok-3-mini",
            P {
                input_per_million: 0.30,
                cached_input_per_million: 0.075,
                output_per_million: 0.50,
            },
        ),
        (
            "grok-3-mini-fast",
            P {
                input_per_million: 0.60,
                cached_input_per_million: 0.15,
                output_per_million: 4.00,
            },
        ),
        (
            "grok-3",
            P {
                input_per_million: 3.00,
                cached_input_per_million: 0.75,
                output_per_million: 15.00,
            },
        ),
        (
            "grok-3-fast",
            P {
                input_per_million: 5.00,
                cached_input_per_million: 1.25,
                output_per_million: 25.00,
            },
        ),
        (
            "grok-4",
            P {
                input_per_million: 3.00,
                cached_input_per_million: 0.75,
                output_per_million: 15.00,
            },
        ),
        (
            "grok-4-0709",
            P {
                input_per_million: 3.00,
                cached_input_per_million: 0.75,
                output_per_million: 15.00,
            },
        ),
        (
            "grok-4-latest",
            P {
                input_per_million: 3.00,
                cached_input_per_million: 0.75,
                output_per_million: 15.00,
            },
        ),
        (
            "deepseek-chat",
            P {
                input_per_million: 0.27,
                cached_input_per_million: 0.07,
                output_per_million: 1.10,
            },
        ),
        (
            "deepseek-reasoner",
            P {
                input_per_million: 0.55,
                cached_input_per_million: 0.14,
                output_per_million: 2.19,
            },
        ),
        (
            "qwen3-vl-flash",
            P {
                input_per_million: 0.05,
                cached_input_per_million: 0.05,
                output_per_million: 0.40,
            },
        ),
        (
            "qwen3-vl-plus",
            P {
                input_per_million: 0.20,
                cached_input_per_million: 0.20,
                output_per_million: 1.60,
            },
        ),
        (
            "qwen3.6-flash",
            P {
                input_per_million: 0.25,
                cached_input_per_million: 0.25,
                output_per_million: 1.50,
            },
        ),
        (
            "qwen3.6-plus",
            P {
                input_per_million: 0.50,
                cached_input_per_million: 0.50,
                output_per_million: 3.00,
            },
        ),
        (
            "qwen3.6-max-preview",
            P {
                input_per_million: 1.30,
                cached_input_per_million: 1.30,
                output_per_million: 7.80,
            },
        ),
    ])
}

fn model_key(model: &str) -> String {
    model.trim().to_ascii_lowercase()
}

fn is_dash_date(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    let text = text.trim_start_matches('-');
    text.len() == 5
        && text.as_bytes().get(2) == Some(&b'-')
        && text
            .chars()
            .enumerate()
            .all(|(index, ch)| index == 2 || ch.is_ascii_digit())
}

fn is_yyyy_mm_dd(text: &str) -> bool {
    text.len() == 10
        && text.as_bytes().get(4) == Some(&b'-')
        && text.as_bytes().get(7) == Some(&b'-')
        && text
            .chars()
            .enumerate()
            .all(|(index, ch)| index == 4 || index == 7 || ch.is_ascii_digit())
}

fn int_value<const N: usize>(values: [Option<&Value>; N]) -> u64 {
    for value in values.into_iter().flatten() {
        if let Some(number) = value.as_u64() {
            return number;
        }
        if let Some(number) = value.as_i64() {
            return number.max(0) as u64;
        }
        if let Some(text) = value.as_str() {
            if let Ok(number) = text.parse::<i64>() {
                return number.max(0) as u64;
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_token_cost_with_compact_units() {
        let usage = TokenUsage {
            input_tokens: 1_000,
            cached_input_tokens: 400,
            output_tokens: 250,
            total_tokens: 1_250,
            ..Default::default()
        };

        assert_eq!(format_token_cost("gpt-5.5", usage), "1.2k/$0.011");
    }

    #[test]
    fn formats_unknown_price() {
        assert_eq!(
            format_token_cost(
                "unknown",
                TokenUsage {
                    total_tokens: 1_000,
                    ..Default::default()
                }
            ),
            "1k/未知"
        );
    }

    #[test]
    fn delta_is_saturating() {
        let current = TokenUsage {
            input_tokens: 10,
            output_tokens: 5,
            total_tokens: 15,
            cached_input_tokens: 2,
            ..Default::default()
        };
        let previous = TokenUsage {
            input_tokens: 7,
            output_tokens: 10,
            total_tokens: 17,
            cached_input_tokens: 1,
            ..Default::default()
        };

        assert_eq!(
            current.delta_from(previous),
            TokenUsage {
                input_tokens: 3,
                output_tokens: 0,
                total_tokens: 0,
                cached_input_tokens: 1,
                reasoning_output_tokens: 0
            }
        );
    }

    #[test]
    fn calculates_cost_for_common_dated_models() {
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 100_000,
            ..Default::default()
        };

        assert_eq!(
            calculate_token_cost_usd("gpt-4o-2024-08-06", usage),
            Some(3.5)
        );
        assert_eq!(
            calculate_token_cost_usd("claude-sonnet-4-5-20250929", usage),
            Some(4.5)
        );
        assert_eq!(
            calculate_token_cost_usd("gemini-2.5-pro-preview-06-05", usage),
            Some(2.25)
        );
    }

    #[test]
    fn normalizes_non_ascii_model_prefix_without_panicking() {
        assert_eq!(
            normalize_model_id_for_price("自定义-gpt-5-2026-05-19"),
            "自定义-gpt-5"
        );
        assert_eq!(
            normalize_model_id_for_price("模型-claude-sonnet-4-5-20250929"),
            "模型-claude-sonnet-4-5"
        );
    }

    #[test]
    fn extracts_usage_from_responses_payload() {
        let payload = serde_json::json!({
            "usage": {
                "input_tokens": 1000,
                "input_tokens_details": {"cached_tokens": 400},
                "output_tokens": 250,
                "output_tokens_details": {"reasoning_tokens": 50},
                "total_tokens": 1250
            }
        });

        assert_eq!(
            extract_token_usage(&payload),
            TokenUsage {
                input_tokens: 1000,
                cached_input_tokens: 400,
                output_tokens: 250,
                reasoning_output_tokens: 50,
                total_tokens: 1250
            }
        );
    }
}
