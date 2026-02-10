use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::util::lock_unpoisoned;

const PER_HOST_RATE_LIMIT_ENTRY_TTL: Duration = Duration::from_secs(300);
const PER_HOST_RATE_LIMIT_MAX_ENTRIES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateLimitPolicy {
    requests_per_second: f64,
    burst: usize,
    max_throttle_delay: Duration,
}

impl RateLimitPolicy {
    pub const fn standard() -> Self {
        Self {
            requests_per_second: 50.0,
            burst: 50,
            max_throttle_delay: Duration::from_secs(30),
        }
    }

    pub fn requests_per_second(mut self, requests_per_second: f64) -> Self {
        self.requests_per_second = if requests_per_second.is_finite() && requests_per_second > 0.0 {
            requests_per_second
        } else {
            1.0
        };
        self
    }

    pub const fn burst(mut self, burst: usize) -> Self {
        self.burst = burst;
        self
    }

    pub const fn max_throttle_delay(mut self, max_throttle_delay: Duration) -> Self {
        self.max_throttle_delay = max_throttle_delay;
        self
    }

    fn normalize(self) -> Self {
        Self {
            requests_per_second: if self.requests_per_second.is_finite()
                && self.requests_per_second > 0.0
            {
                self.requests_per_second
            } else {
                1.0
            },
            burst: self.burst.max(1),
            max_throttle_delay: self.max_throttle_delay,
        }
    }

    fn requests_per_second_value(self) -> f64 {
        self.requests_per_second
    }

    fn burst_value(self) -> usize {
        self.burst
    }

    fn max_throttle_delay_value(self) -> Duration {
        self.max_throttle_delay
    }
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

#[derive(Debug)]
struct TokenBucket {
    policy: RateLimitPolicy,
    tokens: f64,
    last_refill_at: Instant,
    throttle_until: Option<Instant>,
}

impl TokenBucket {
    fn new(policy: RateLimitPolicy, now: Instant) -> Self {
        let policy = policy.normalize();
        Self {
            policy,
            tokens: policy.burst_value() as f64,
            last_refill_at: now,
            throttle_until: None,
        }
    }

    fn refill(&mut self, now: Instant) {
        if now <= self.last_refill_at {
            return;
        }
        let elapsed_secs = now.duration_since(self.last_refill_at).as_secs_f64();
        self.last_refill_at = now;
        let replenished = elapsed_secs * self.policy.requests_per_second_value();
        self.tokens = (self.tokens + replenished).min(self.policy.burst_value() as f64);
        if let Some(throttle_until) = self.throttle_until
            && now >= throttle_until
        {
            self.throttle_until = None;
        }
    }

    fn wait_duration(&mut self, now: Instant) -> Duration {
        self.refill(now);
        if let Some(throttle_until) = self.throttle_until
            && now < throttle_until
        {
            return throttle_until.saturating_duration_since(now);
        }
        if self.tokens >= 1.0 {
            return Duration::ZERO;
        }

        let rate = self.policy.requests_per_second_value();
        if rate <= f64::EPSILON {
            return Duration::from_secs(60);
        }
        let needed_tokens = (1.0 - self.tokens).max(0.0);
        let delay_secs = needed_tokens / rate;
        if delay_secs <= f64::EPSILON {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(delay_secs)
        }
    }

    fn consume_if_available(&mut self, now: Instant) -> bool {
        self.refill(now);
        if let Some(throttle_until) = self.throttle_until
            && now < throttle_until
        {
            return false;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return true;
        }
        false
    }

    fn apply_throttle(&mut self, now: Instant, delay: Duration) {
        let capped_delay = delay.min(self.policy.max_throttle_delay_value());
        if capped_delay.is_zero() {
            return;
        }
        let throttle_until = now + capped_delay;
        self.throttle_until = Some(match self.throttle_until {
            Some(existing) => existing.max(throttle_until),
            None => throttle_until,
        });
    }
}

#[derive(Debug)]
struct PerHostRateLimitEntry {
    bucket: TokenBucket,
    last_used_at: Instant,
}

#[derive(Debug)]
pub(crate) struct RateLimiter {
    global: Option<Mutex<TokenBucket>>,
    per_host_policy: Option<RateLimitPolicy>,
    per_host: Mutex<BTreeMap<String, PerHostRateLimitEntry>>,
}

impl RateLimiter {
    pub(crate) fn new(
        global_policy: Option<RateLimitPolicy>,
        per_host_policy: Option<RateLimitPolicy>,
    ) -> Option<Self> {
        if global_policy.is_none() && per_host_policy.is_none() {
            return None;
        }

        let now = Instant::now();
        Some(Self {
            global: global_policy.map(|policy| Mutex::new(TokenBucket::new(policy, now))),
            per_host_policy: per_host_policy.map(RateLimitPolicy::normalize),
            per_host: Mutex::new(BTreeMap::new()),
        })
    }

    pub(crate) fn acquire_delay(&self, host: Option<&str>) -> Duration {
        let now = Instant::now();
        let host_key = host.map(|item| item.to_ascii_lowercase());

        let mut global_bucket = self.global.as_ref().map(lock_unpoisoned);
        let mut per_host = lock_unpoisoned(&self.per_host);
        cleanup_stale_per_host_rate_limits(&mut per_host, now);

        let global_wait = global_bucket
            .as_mut()
            .map_or(Duration::ZERO, |bucket| bucket.wait_duration(now));

        let per_host_wait = match (self.per_host_policy, host_key.as_ref()) {
            (Some(policy), Some(host)) => {
                let entry = per_host
                    .entry(host.clone())
                    .or_insert_with(|| PerHostRateLimitEntry {
                        bucket: TokenBucket::new(policy, now),
                        last_used_at: now,
                    });
                entry.last_used_at = now;
                entry.bucket.wait_duration(now)
            }
            _ => Duration::ZERO,
        };

        let wait = global_wait.max(per_host_wait);
        if !wait.is_zero() {
            return wait;
        }

        if let Some(bucket) = global_bucket.as_mut() {
            debug_assert!(bucket.consume_if_available(now));
        }
        if let Some(host) = host_key
            && let Some(entry) = per_host.get_mut(&host)
        {
            entry.last_used_at = now;
            debug_assert!(entry.bucket.consume_if_available(now));
        }

        Duration::ZERO
    }

    pub(crate) fn observe_server_throttle(&self, host: Option<&str>, delay: Duration) {
        if delay.is_zero() {
            return;
        }

        let now = Instant::now();
        let host_key = host.map(|item| item.to_ascii_lowercase());

        if let Some(global) = &self.global {
            let mut bucket = lock_unpoisoned(global);
            bucket.apply_throttle(now, delay);
        }

        if let (Some(policy), Some(host)) = (self.per_host_policy, host_key) {
            let mut per_host = lock_unpoisoned(&self.per_host);
            cleanup_stale_per_host_rate_limits(&mut per_host, now);
            let entry = per_host
                .entry(host)
                .or_insert_with(|| PerHostRateLimitEntry {
                    bucket: TokenBucket::new(policy, now),
                    last_used_at: now,
                });
            entry.last_used_at = now;
            entry.bucket.apply_throttle(now, delay);
        }
    }
}

fn cleanup_stale_per_host_rate_limits(
    entries: &mut BTreeMap<String, PerHostRateLimitEntry>,
    now: Instant,
) {
    entries
        .retain(|_, entry| now.duration_since(entry.last_used_at) <= PER_HOST_RATE_LIMIT_ENTRY_TTL);

    while entries.len() > PER_HOST_RATE_LIMIT_MAX_ENTRIES {
        let oldest_key = entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_used_at)
            .map(|(host, _)| host.clone());
        let Some(oldest_key) = oldest_key else {
            break;
        };
        entries.remove(&oldest_key);
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::{RateLimitPolicy, RateLimiter};

    #[test]
    fn global_rate_limiter_respects_burst_and_refill() {
        let limiter = RateLimiter::new(
            Some(
                RateLimitPolicy::standard()
                    .requests_per_second(20.0)
                    .burst(1),
            ),
            None,
        )
        .expect("global limiter should be built");

        assert_eq!(limiter.acquire_delay(None), std::time::Duration::ZERO);
        let wait = limiter.acquire_delay(None);
        assert!(wait >= std::time::Duration::from_millis(45));

        sleep(wait);
        assert_eq!(limiter.acquire_delay(None), std::time::Duration::ZERO);
    }

    #[test]
    fn throttle_delay_is_applied_for_host_bucket() {
        let limiter = RateLimiter::new(
            None,
            Some(
                RateLimitPolicy::standard()
                    .requests_per_second(100.0)
                    .burst(10)
                    .max_throttle_delay(std::time::Duration::from_millis(500)),
            ),
        )
        .expect("per-host limiter should be built");

        assert_eq!(
            limiter.acquire_delay(Some("api.example.com")),
            std::time::Duration::ZERO
        );
        limiter.observe_server_throttle(
            Some("api.example.com"),
            std::time::Duration::from_millis(120),
        );
        assert!(
            limiter.acquire_delay(Some("api.example.com")) >= std::time::Duration::from_millis(110)
        );
    }
}
