//! Provider-neutral quota evidence used by adaptive routing.
//!
//! Quota is an optional routing signal, never a synthetic health score. Missing
//! or stale evidence stays unknown.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use reqwest::header::HeaderMap;
use serde::Serialize;

const DEFAULT_MAX_AGE: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Serialize)]
pub struct QuotaSnapshot {
    pub remaining_fraction: Option<f64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
    pub source: String,
    pub max_age_secs: u64,
}

impl QuotaSnapshot {
    pub fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        if self.reset_at.is_some_and(|reset_at| reset_at <= now) {
            return false;
        }
        now.signed_duration_since(self.observed_at)
            .to_std()
            .map(|age| age <= Duration::from_secs(self.max_age_secs))
            .unwrap_or(true)
    }

    /// Unknown quota is neutral. Known headroom above 50% is positive evidence;
    /// known low headroom is negative evidence. A near reset can only make a
    /// small bounded adjustment.
    pub fn preference(&self, now: DateTime<Utc>) -> f64 {
        if !self.is_fresh(now) {
            return 0.0;
        }
        let Some(remaining) = self.remaining_fraction else {
            return 0.0;
        };
        let mut score = remaining.clamp(0.0, 1.0) - 0.5;
        if score < 0.0 {
            if let Some(reset_at) = self.reset_at {
                let secs = (reset_at - now).num_seconds().max(0);
                let reset_bonus = if secs <= 60 {
                    0.10
                } else if secs <= 5 * 60 {
                    0.05
                } else {
                    0.0
                };
                score += reset_bonus;
            }
        }
        score.clamp(-0.5, 0.5)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QuotaHeaderObservation {
    pub remaining_fraction: f64,
    pub reset_at: Option<DateTime<Utc>>,
    pub exhausted: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct QuotaPluginObservation {
    pub remaining_fraction: Option<f64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub exhausted: bool,
}

#[derive(Clone, Default)]
pub struct QuotaRegistry {
    inner: Arc<DashMap<(String, String), QuotaSnapshot>>,
}

impl QuotaRegistry {
    pub fn observe(
        &self,
        provider_id: &str,
        account_id: &str,
        remaining_fraction: Option<f64>,
        reset_at: Option<DateTime<Utc>>,
        source: impl Into<String>,
        max_age: Duration,
    ) {
        let remaining_fraction = remaining_fraction
            .filter(|value| value.is_finite())
            .map(|value| value.clamp(0.0, 1.0));
        self.inner.insert(
            (provider_id.to_string(), account_id.to_string()),
            QuotaSnapshot {
                remaining_fraction,
                reset_at,
                observed_at: Utc::now(),
                source: source.into(),
                max_age_secs: max_age.as_secs().max(1),
            },
        );
    }

    pub fn observe_exhausted(
        &self,
        provider_id: &str,
        account_id: &str,
        reset_at: Option<DateTime<Utc>>,
        source: &str,
    ) {
        self.observe(
            provider_id,
            account_id,
            Some(0.0),
            reset_at,
            source,
            DEFAULT_MAX_AGE,
        );
    }

    pub fn observe_plugin(
        &self,
        provider_id: &str,
        account_id: &str,
        quota_state: Option<&str>,
        reset_at: Option<&str>,
    ) -> Option<QuotaPluginObservation> {
        let reset_at = reset_at.and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|value| value.with_timezone(&Utc))
        });
        let remaining_fraction = quota_state
            .and_then(parse_quota_state)
            .filter(|value| value.is_finite())
            .map(|value| value.clamp(0.0, 1.0));
        let exhausted = remaining_fraction.is_some_and(|remaining| remaining <= 0.0);
        if quota_state.is_some() || reset_at.is_some() {
            self.observe(
                provider_id,
                account_id,
                remaining_fraction,
                reset_at,
                "plugin_health_probe",
                Duration::from_secs(45),
            );
            Some(QuotaPluginObservation {
                remaining_fraction,
                reset_at,
                exhausted,
            })
        } else {
            None
        }
    }

    pub fn observe_headers(
        &self,
        provider_id: &str,
        account_id: &str,
        headers: &HeaderMap,
    ) -> Option<QuotaHeaderObservation> {
        let pairs = [
            (
                "anthropic-ratelimit-requests-remaining",
                "anthropic-ratelimit-requests-limit",
            ),
            (
                "x-ratelimit-remaining-requests",
                "x-ratelimit-limit-requests",
            ),
            ("x-ratelimit-remaining", "x-ratelimit-limit"),
            ("ratelimit-remaining", "ratelimit-limit"),
        ];
        for (remaining_name, limit_name) in pairs {
            let Some(remaining) = header_f64(headers, remaining_name) else {
                continue;
            };
            let reset_at = parse_reset_header(headers);
            let (remaining_fraction, exhausted) = if remaining <= 0.0 {
                (0.0, true)
            } else {
                let Some(limit) = header_f64(headers, limit_name) else {
                    continue;
                };
                if limit <= 0.0 {
                    continue;
                }
                ((remaining / limit).clamp(0.0, 1.0), false)
            };
            self.observe(
                provider_id,
                account_id,
                Some(remaining_fraction),
                reset_at,
                format!("response_header:{remaining_name}"),
                DEFAULT_MAX_AGE,
            );
            return Some(QuotaHeaderObservation {
                remaining_fraction,
                reset_at,
                exhausted,
            });
        }
        None
    }

    pub fn snapshot(&self, provider_id: &str, account_id: &str) -> Option<QuotaSnapshot> {
        let key = (provider_id.to_string(), account_id.to_string());
        let value = self.inner.get(&key)?.clone();
        value.is_fresh(Utc::now()).then_some(value)
    }

    pub fn snapshots(&self) -> Vec<(String, String, QuotaSnapshot)> {
        self.observations()
            .into_iter()
            .filter_map(|(provider_id, account_id, snapshot, fresh)| {
                fresh.then_some((provider_id, account_id, snapshot))
            })
            .collect()
    }

    /// Operator-facing view retains stale observations so the dashboard can
    /// distinguish stale evidence from a source that has never reported quota.
    /// Routing still consumes only `snapshot()` / `snapshots()`, which fail
    /// stale data closed to unknown.
    pub fn observations(&self) -> Vec<(String, String, QuotaSnapshot, bool)> {
        let now = Utc::now();
        self.inner
            .iter()
            .map(|entry| {
                let value = entry.value().clone();
                (
                    entry.key().0.clone(),
                    entry.key().1.clone(),
                    value.clone(),
                    value.is_fresh(now),
                )
            })
            .collect()
    }
}

fn parse_quota_state(value: &str) -> Option<f64> {
    let normalized = value.trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "exhausted" | "empty" | "depleted" | "none"
    ) {
        return Some(0.0);
    }
    if let Some(percent) = normalized.strip_suffix('%') {
        return percent
            .trim()
            .parse::<f64>()
            .ok()
            .map(|value| value / 100.0);
    }
    normalized
        .parse::<f64>()
        .ok()
        .map(|value| if value > 1.0 { value / 100.0 } else { value })
}

fn header_f64(headers: &HeaderMap, name: &str) -> Option<f64> {
    headers.get(name)?.to_str().ok()?.trim().parse().ok()
}

fn parse_reset_header(headers: &HeaderMap) -> Option<DateTime<Utc>> {
    for name in [
        "anthropic-ratelimit-requests-reset",
        "x-ratelimit-reset-requests",
        "x-ratelimit-reset",
        "ratelimit-reset",
    ] {
        let Some(raw) = headers.get(name).and_then(|value| value.to_str().ok()) else {
            continue;
        };
        if let Ok(value) = DateTime::parse_from_rfc3339(raw) {
            return Some(value.with_timezone(&Utc));
        }
        if let Ok(epoch) = raw.trim().parse::<i64>() {
            if let Some(value) = DateTime::from_timestamp(epoch, 0) {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_neutral_and_known_headroom_is_evidence() {
        let now = Utc::now();
        let unknown = QuotaSnapshot {
            remaining_fraction: None,
            reset_at: None,
            observed_at: now,
            source: "test".into(),
            max_age_secs: 60,
        };
        let healthy = QuotaSnapshot {
            remaining_fraction: Some(0.8),
            reset_at: None,
            observed_at: now,
            source: "test".into(),
            max_age_secs: 60,
        };
        let low = QuotaSnapshot {
            remaining_fraction: Some(0.1),
            reset_at: None,
            observed_at: now,
            source: "test".into(),
            max_age_secs: 60,
        };

        assert_eq!(unknown.preference(now), 0.0);
        assert!(healthy.preference(now) > unknown.preference(now));
        assert!(low.preference(now) < unknown.preference(now));
    }

    #[test]
    fn near_reset_adjustment_is_bounded() {
        let now = Utc::now();
        let snapshot = QuotaSnapshot {
            remaining_fraction: Some(0.1),
            reset_at: Some(now + chrono::Duration::seconds(30)),
            observed_at: now,
            source: "test".into(),
            max_age_secs: 60,
        };
        assert!((-0.5..=0.5).contains(&snapshot.preference(now)));
        assert!(snapshot.preference(now) < 0.0);
    }

    #[test]
    fn expired_reset_makes_recent_quota_unknown_immediately() {
        let now = Utc::now();
        let snapshot = QuotaSnapshot {
            remaining_fraction: Some(0.05),
            reset_at: Some(now - chrono::Duration::seconds(1)),
            observed_at: now,
            source: "test".into(),
            max_age_secs: 300,
        };

        assert!(!snapshot.is_fresh(now));
        assert_eq!(snapshot.preference(now), 0.0);
    }

    #[test]
    fn plugin_numeric_zero_variants_are_reported_as_hard_exhaustion() {
        for quota_state in ["0", "0%", "0.0", "0.00%", " exhausted "] {
            let registry = QuotaRegistry::default();
            let observation = registry
                .observe_plugin("p", "a", Some(quota_state), None)
                .unwrap();

            assert!(observation.exhausted, "quota_state={quota_state:?}");
            assert_eq!(
                observation.remaining_fraction,
                Some(0.0),
                "quota_state={quota_state:?}"
            );
            assert_eq!(
                registry.snapshot("p", "a").unwrap().remaining_fraction,
                Some(0.0),
                "quota_state={quota_state:?}"
            );
        }

        let registry = QuotaRegistry::default();
        let observation = registry
            .observe_plugin("p", "a", Some("0.1"), None)
            .unwrap();
        assert!(!observation.exhausted);
        assert_eq!(observation.remaining_fraction, Some(0.1));
    }

    #[test]
    fn zero_remaining_header_is_reported_as_hard_exhaustion() {
        let registry = QuotaRegistry::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", "0".parse().unwrap());

        let observation = registry.observe_headers("p", "a", &headers).unwrap();
        assert!(observation.exhausted);
        assert_eq!(observation.remaining_fraction, 0.0);
        assert_eq!(
            registry.snapshot("p", "a").unwrap().remaining_fraction,
            Some(0.0)
        );
    }

    #[test]
    fn stale_quota_is_unknown_for_routing_but_retained_for_diagnostics() {
        let registry = QuotaRegistry::default();
        registry.inner.insert(
            ("p".into(), "a".into()),
            QuotaSnapshot {
                remaining_fraction: Some(0.9),
                reset_at: None,
                observed_at: Utc::now() - chrono::Duration::seconds(2),
                source: "test".into(),
                max_age_secs: 1,
            },
        );

        assert!(registry.snapshot("p", "a").is_none());

        let observations = registry.observations();
        assert_eq!(observations.len(), 1);
        assert!(!observations[0].3, "stale evidence must be marked stale");
    }

    #[test]
    fn plugin_percent_is_normalized() {
        assert_eq!(parse_quota_state("80%"), Some(0.8));
        assert_eq!(parse_quota_state("0.25"), Some(0.25));
        assert_eq!(parse_quota_state("exhausted"), Some(0.0));
    }
}
