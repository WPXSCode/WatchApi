use crate::tokens::TokenUsage;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbeResult {
    pub available: bool,
    pub polluted: bool,
    pub quota_limited: bool,
    pub retry_after_seconds: Option<u64>,
    pub usage: TokenUsage,
    pub status_code: Option<u16>,
    pub request_made: bool,
    pub error: String,
}

impl ProbeResult {
    pub fn available() -> Self {
        Self {
            available: true,
            request_made: true,
            ..Self::default()
        }
    }

    pub fn unavailable() -> Self {
        Self {
            available: false,
            request_made: true,
            ..Self::default()
        }
    }

    pub fn polluted() -> Self {
        Self {
            available: false,
            polluted: true,
            request_made: true,
            ..Self::default()
        }
    }

    pub fn quota_limited() -> Self {
        Self {
            available: false,
            quota_limited: true,
            request_made: true,
            ..Self::default()
        }
    }

    pub fn cached_available() -> Self {
        Self {
            available: true,
            request_made: false,
            ..Self::default()
        }
    }

    pub fn synthetic_unavailable() -> Self {
        Self {
            available: false,
            request_made: false,
            ..Self::default()
        }
    }

    pub fn synthetic_polluted() -> Self {
        Self {
            available: false,
            polluted: true,
            request_made: false,
            ..Self::default()
        }
    }
}
