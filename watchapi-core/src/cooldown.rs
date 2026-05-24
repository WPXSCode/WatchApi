pub fn cooldown_seconds_from_text(text: &str, tolerance_seconds: u64) -> Option<u64> {
    if !has_cooldown_context(text) {
        return None;
    }
    let chars = text.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < chars.len() {
        if digit_value(chars[index]).is_none() {
            index += 1;
            continue;
        }
        let start = index;
        while index < chars.len() && digit_value(chars[index]).is_some() {
            index += 1;
        }
        let suffix_start = index;
        while index < chars.len() && chars[index].is_ascii_whitespace() {
            index += 1;
        }
        let suffix = chars[index..].iter().take(7).collect::<String>();
        if !is_seconds_suffix(&suffix) {
            continue;
        }
        if preceding_text_contains_cooldown(&chars, start)
            || following_text_contains_retry(&chars, suffix_start)
            || has_global_rate_limit_context(text)
        {
            if let Some(seconds) = parse_digit_chars(&chars[start..suffix_start]) {
                return Some(seconds.saturating_add(tolerance_seconds));
            }
        }
    }
    None
}

fn has_cooldown_context(text: &str) -> bool {
    text.contains("冷却")
        || (text.contains("等待") && text.contains("重试"))
        || has_global_rate_limit_context(text)
}

fn has_global_rate_limit_context(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("cooldown")
        || lowered.contains("rate limit")
        || lowered.contains("rate_limit")
        || lowered.contains("retry after")
        || lowered.contains("retry-after")
        || lowered.contains("retry in")
        || lowered.contains("try again")
        || lowered.contains("too many requests")
        || text.contains("限流")
}

fn is_seconds_suffix(suffix: &str) -> bool {
    suffix.starts_with('秒')
        || suffix.starts_with('s')
        || suffix.starts_with("sec")
        || suffix.starts_with("second")
}

fn preceding_text_contains_cooldown(chars: &[char], number_start: usize) -> bool {
    chars[..number_start]
        .iter()
        .rev()
        .take(12)
        .any(|ch| *ch == '冷' || *ch == '却')
}

fn following_text_contains_retry(chars: &[char], suffix_start: usize) -> bool {
    chars[suffix_start..]
        .iter()
        .take(12)
        .collect::<String>()
        .contains("重试")
}

fn digit_value(ch: char) -> Option<u64> {
    if ch.is_ascii_digit() {
        return Some(ch as u64 - '0' as u64);
    }
    if ('０'..='９').contains(&ch) {
        return Some(ch as u64 - '０' as u64);
    }
    None
}

fn parse_digit_chars(chars: &[char]) -> Option<u64> {
    let mut value = 0_u64;
    for ch in chars {
        value = value.checked_mul(10)?.checked_add(digit_value(*ch)?)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_chinese_cooldown_seconds_with_tolerance() {
        assert_eq!(
            cooldown_seconds_from_text("一分钟30次，冷却20秒", 20),
            Some(40)
        );
    }

    #[test]
    fn ignores_seconds_without_cooldown_context() {
        assert_eq!(cooldown_seconds_from_text("普通错误 41秒后重试", 20), None);
    }

    #[test]
    fn extracts_english_cooldown_seconds_with_tolerance() {
        assert_eq!(
            cooldown_seconds_from_text("rate_limit_cooldown: cooldown 20 seconds", 20),
            Some(40)
        );
    }

    #[test]
    fn extracts_compact_seconds_when_cooldown_context_exists() {
        assert_eq!(
            cooldown_seconds_from_text(
                r#"{"error":{"message":"rate limit, retry after 20s"},"code":"rate_limit_cooldown"}"#,
                20
            ),
            Some(40)
        );
    }

    #[test]
    fn extracts_retry_and_wait_variants() {
        assert_eq!(
            cooldown_seconds_from_text("Too many requests, retry in 20 seconds", 20),
            Some(40)
        );
        assert_eq!(
            cooldown_seconds_from_text("please try again after 20s", 20),
            Some(40)
        );
        assert_eq!(
            cooldown_seconds_from_text("请等待２０秒后重试", 20),
            Some(40)
        );
    }
}
