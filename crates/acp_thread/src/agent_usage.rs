use std::time::SystemTime;

use agent_client_protocol::{v1::schema as acp_v1, v2::schema as acp_v2};
use serde_json::Value;

/// Key under which claude-agent-acp attaches the Claude SDK `SDKRateLimitInfo` to a
/// `usage_update`.
pub const CLAUDE_RATE_LIMIT_META_KEY: &str = "_claude/rateLimit";

const MAX_RATE_LIMIT_STRING_BYTES: usize = 64;

/// A plan rate-limit observation reported by the agent. Only these fields are copied out
/// of the agent's metadata, so no unvetted agent data is kept or forwarded.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentRateLimit {
    pub status: String,
    pub resets_at: Option<i64>,
    pub rate_limit_type: Option<String>,
    pub utilization: Option<f64>,
    pub surpassed_threshold: Option<f64>,
    pub is_using_overage: Option<bool>,
    pub observed_at: SystemTime,
}

impl AgentRateLimit {
    pub fn from_meta(meta: &acp_v2::Meta, observed_at: SystemTime) -> Option<Self> {
        let info = meta.get(CLAUDE_RATE_LIMIT_META_KEY)?.as_object()?;
        let short_string = |key: &str| {
            info.get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= MAX_RATE_LIMIT_STRING_BYTES)
                .map(str::to_string)
        };
        let finite_number = |key: &str| {
            info.get(key)
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite())
        };
        Some(Self {
            status: short_string("status")?,
            resets_at: finite_number("resetsAt").map(|value| value as i64),
            rate_limit_type: short_string("rateLimitType"),
            utilization: finite_number("utilization"),
            surpassed_threshold: finite_number("surpassedThreshold"),
            is_using_overage: info.get("isUsingOverage").and_then(Value::as_bool),
            observed_at,
        })
    }
}

/// Token usage the agent reported for one completed turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub thought_tokens: Option<u64>,
}

impl From<&acp_v2::Usage> for TurnUsage {
    fn from(usage: &acp_v2::Usage) -> Self {
        Self {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cache_read_tokens: usage.cached_read_tokens,
            cache_write_tokens: usage.cached_write_tokens,
            thought_tokens: usage.thought_tokens,
        }
    }
}

impl From<&acp_v1::Usage> for TurnUsage {
    fn from(usage: &acp_v1::Usage) -> Self {
        Self {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cache_read_tokens: usage.cached_read_tokens,
            cache_write_tokens: usage.cached_write_tokens,
            thought_tokens: usage.thought_tokens,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta(value: Value) -> acp_v2::Meta {
        match value {
            Value::Object(map) => map,
            _ => acp_v2::Meta::new(),
        }
    }

    #[test]
    fn copies_whitelisted_fields() {
        let observed_at = SystemTime::UNIX_EPOCH;
        let limit = AgentRateLimit::from_meta(
            &meta(json!({"_claude/rateLimit": {
                "status": "allowed_warning",
                "resetsAt": 1795787661,
                "rateLimitType": "five_hour",
                "utilization": 0.91,
                "surpassedThreshold": 0.9,
                "isUsingOverage": false,
                "overageDisabledReason": "secret",
            }})),
            observed_at,
        );
        assert_eq!(
            limit,
            Some(AgentRateLimit {
                status: "allowed_warning".to_string(),
                resets_at: Some(1795787661),
                rate_limit_type: Some("five_hour".to_string()),
                utilization: Some(0.91),
                surpassed_threshold: Some(0.9),
                is_using_overage: Some(false),
                observed_at,
            })
        );
    }

    #[test]
    fn requires_status() {
        let observed_at = SystemTime::UNIX_EPOCH;
        assert_eq!(
            AgentRateLimit::from_meta(&meta(json!({})), observed_at),
            None
        );
        assert_eq!(
            AgentRateLimit::from_meta(
                &meta(json!({"_claude/rateLimit": {"rateLimitType": "five_hour"}})),
                observed_at
            ),
            None
        );
        assert_eq!(
            AgentRateLimit::from_meta(
                &meta(json!({"_claude/rateLimit": {"status": "x".repeat(65)}})),
                observed_at
            ),
            None
        );
        let minimal = AgentRateLimit::from_meta(
            &meta(json!({"_claude/rateLimit": {"status": "allowed", "utilization": "high"}})),
            observed_at,
        );
        assert_eq!(minimal.map(|limit| limit.utilization), Some(None));
    }
}
