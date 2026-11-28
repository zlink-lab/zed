use std::time::SystemTime;

use agent_client_protocol::{v1::schema as acp_v1, v2::schema as acp_v2};
use serde_json::{Map, Value};

/// Key under which claude-agent-acp attaches the Claude SDK `SDKRateLimitInfo` to a
/// `usage_update`.
pub const CLAUDE_RATE_LIMIT_META_KEY: &str = "_claude/rateLimit";

const MAX_RATE_LIMIT_STRING_BYTES: usize = 64;
const MAX_RATE_LIMIT_WINDOWS: usize = 8;

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
    /// One observation per plan window. The top-level fields describe a single window and
    /// carry `utilization` only near a warning threshold; `unifiedWindows` has the
    /// utilization of every window on each event.
    pub fn from_meta(meta: &acp_v2::Meta, observed_at: SystemTime) -> Vec<Self> {
        let Some(info) = meta
            .get(CLAUDE_RATE_LIMIT_META_KEY)
            .and_then(Value::as_object)
        else {
            return Vec::new();
        };
        let Some(status) = short_string(info, "status") else {
            return Vec::new();
        };
        let current = Self {
            status,
            resets_at: finite_number(info, "resetsAt").map(|value| value as i64),
            rate_limit_type: short_string(info, "rateLimitType"),
            utilization: finite_number(info, "utilization"),
            surpassed_threshold: finite_number(info, "surpassedThreshold"),
            is_using_overage: info.get("isUsingOverage").and_then(Value::as_bool),
            observed_at,
        };
        let mut limits = info
            .get("unifiedWindows")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter(|(kind, _)| !kind.is_empty() && kind.len() <= MAX_RATE_LIMIT_STRING_BYTES)
            .filter_map(|(kind, window)| {
                let window = window.as_object()?;
                let utilization = finite_number(window, "utilization")?;
                let is_current = current.rate_limit_type.as_deref() == Some(kind.as_str());
                Some(Self {
                    status: short_string(window, "status").unwrap_or_else(|| {
                        if is_current {
                            current.status.clone()
                        } else {
                            "allowed".to_string()
                        }
                    }),
                    resets_at: finite_number(window, "resetsAt").map(|value| value as i64),
                    rate_limit_type: Some(kind.clone()),
                    utilization: Some(utilization),
                    surpassed_threshold: finite_number(window, "surpassedThreshold"),
                    is_using_overage: current.is_using_overage,
                    observed_at,
                })
            })
            .take(MAX_RATE_LIMIT_WINDOWS)
            .collect::<Vec<_>>();
        if !limits
            .iter()
            .any(|limit| limit.rate_limit_type == current.rate_limit_type)
        {
            limits.push(current);
        }
        limits
    }
}

fn short_string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_RATE_LIMIT_STRING_BYTES)
        .map(str::to_string)
}

fn finite_number(object: &Map<String, Value>, key: &str) -> Option<f64> {
    object
        .get(key)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
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
            vec![AgentRateLimit {
                status: "allowed_warning".to_string(),
                resets_at: Some(1795787661),
                rate_limit_type: Some("five_hour".to_string()),
                utilization: Some(0.91),
                surpassed_threshold: Some(0.9),
                is_using_overage: Some(false),
                observed_at,
            }]
        );
    }

    #[test]
    fn reads_every_unified_window() {
        // The event Claude sends while far from any limit: no top-level utilization.
        let limits = AgentRateLimit::from_meta(
            &meta(json!({"_claude/rateLimit": {
                "status": "allowed",
                "resetsAt": 1795849800,
                "rateLimitType": "five_hour",
                "isUsingOverage": false,
                "unifiedWindows": {
                    "five_hour": {"utilization": 0.18, "resetsAt": 1795849800, "status": "allowed"},
                    "seven_day": {"utilization": 0.61, "resetsAt": 1796209200},
                },
            }})),
            SystemTime::UNIX_EPOCH,
        );
        let mut summary = limits
            .iter()
            .map(|limit| {
                (
                    limit.rate_limit_type.as_deref(),
                    limit.utilization,
                    limit.resets_at,
                    limit.status.as_str(),
                )
            })
            .collect::<Vec<_>>();
        summary.sort_by_key(|row| row.0);
        assert_eq!(
            summary,
            vec![
                (Some("five_hour"), Some(0.18), Some(1795849800), "allowed"),
                (Some("seven_day"), Some(0.61), Some(1796209200), "allowed"),
            ]
        );
    }

    #[test]
    fn requires_status() {
        let observed_at = SystemTime::UNIX_EPOCH;
        assert_eq!(
            AgentRateLimit::from_meta(&meta(json!({})), observed_at),
            Vec::new()
        );
        assert_eq!(
            AgentRateLimit::from_meta(
                &meta(json!({"_claude/rateLimit": {"rateLimitType": "five_hour"}})),
                observed_at
            ),
            Vec::new()
        );
        assert_eq!(
            AgentRateLimit::from_meta(
                &meta(json!({"_claude/rateLimit": {"status": "x".repeat(65)}})),
                observed_at
            ),
            Vec::new()
        );
        let minimal = AgentRateLimit::from_meta(
            &meta(json!({"_claude/rateLimit": {"status": "allowed", "utilization": "high"}})),
            observed_at,
        );
        assert_eq!(minimal.first().map(|limit| limit.utilization), Some(None));
    }
}
