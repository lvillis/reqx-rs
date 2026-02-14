use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::util::lock_unpoisoned;

const PER_HOST_RATE_LIMIT_ENTRY_TTL: Duration = Duration::from_secs(300);
const PER_HOST_RATE_LIMIT_MAX_ENTRIES: usize = 1024;
const PER_HOST_RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ServerThrottleScope {
    #[default]
    Auto,
    Host,
    Global,
    Both,
}

pub(crate) fn server_throttle_scope_from_headers(
    headers: &http::HeaderMap,
) -> Option<ServerThrottleScope> {
    const RATE_LIMIT_SCOPE_HEADERS: [&str; 3] =
        ["x-ratelimit-scope", "ratelimit-scope", "x-rate-limit-scope"];

    for header_name in RATE_LIMIT_SCOPE_HEADERS {
        let Some(value) = headers.get(header_name).and_then(|raw| raw.to_str().ok()) else {
            continue;
        };

        let normalized = value.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        if normalized.contains("both") || normalized.contains("all") {
            return Some(ServerThrottleScope::Both);
        }
        if normalized.contains("global") || normalized.contains("shared") {
            return Some(ServerThrottleScope::Global);
        }
        if normalized.contains("host")
            || normalized.contains("resource")
            || normalized.contains("bucket")
            || normalized.contains("user")
            || normalized.contains("local")
        {
            return Some(ServerThrottleScope::Host);
        }
    }

    None
}

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

    fn configured_requests_per_second(self) -> f64 {
        self.requests_per_second
    }

    fn configured_burst(self) -> usize {
        self.burst
    }

    fn configured_max_throttle_delay(self) -> Duration {
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
            tokens: policy.configured_burst() as f64,
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
        let replenished = elapsed_secs * self.policy.configured_requests_per_second();
        self.tokens = (self.tokens + replenished).min(self.policy.configured_burst() as f64);
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

        let rate = self.policy.configured_requests_per_second();
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

    fn can_consume_now(&mut self, now: Instant) -> bool {
        self.refill(now);
        if let Some(throttle_until) = self.throttle_until
            && now < throttle_until
        {
            return false;
        }
        self.tokens >= 1.0
    }

    fn consume_ready_token(&mut self) {
        debug_assert!(self.tokens >= 1.0);
        self.tokens = (self.tokens - 1.0).max(0.0);
    }

    fn apply_throttle(&mut self, now: Instant, delay: Duration) {
        let capped_delay = delay.min(self.policy.configured_max_throttle_delay());
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
    per_host_cleanup_origin: Instant,
    per_host_last_cleanup_ms: AtomicU64,
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
            per_host_cleanup_origin: now,
            per_host_last_cleanup_ms: AtomicU64::new(0),
        })
    }

    pub(crate) fn acquire_delay(&self, host: Option<&str>) -> Duration {
        let now = Instant::now();
        let host_key = host.map(|item| item.to_ascii_lowercase());

        let mut global_bucket = self.global.as_ref().map(lock_unpoisoned);
        let mut per_host = lock_unpoisoned(&self.per_host);
        self.maybe_cleanup_stale_per_host_rate_limits(&mut per_host, now);

        let global_ready = global_bucket
            .as_mut()
            .is_none_or(|bucket| bucket.can_consume_now(now));
        let per_host_ready = match (self.per_host_policy, host_key.as_ref()) {
            (Some(policy), Some(host)) => {
                let entry = per_host
                    .entry(host.clone())
                    .or_insert_with(|| PerHostRateLimitEntry {
                        bucket: TokenBucket::new(policy, now),
                        last_used_at: now,
                    });
                entry.last_used_at = now;
                entry.bucket.can_consume_now(now)
            }
            _ => true,
        };

        if !global_ready || !per_host_ready {
            let global_wait = if global_ready {
                Duration::ZERO
            } else {
                global_bucket
                    .as_mut()
                    .map_or(Duration::ZERO, |bucket| bucket.wait_duration(now))
            };
            let per_host_wait = if per_host_ready {
                Duration::ZERO
            } else {
                match (self.per_host_policy, host_key.as_ref()) {
                    (Some(policy), Some(host)) => {
                        let entry =
                            per_host
                                .entry(host.clone())
                                .or_insert_with(|| PerHostRateLimitEntry {
                                    bucket: TokenBucket::new(policy, now),
                                    last_used_at: now,
                                });
                        entry.last_used_at = now;
                        entry.bucket.wait_duration(now)
                    }
                    _ => Duration::ZERO,
                }
            };
            return global_wait.max(per_host_wait);
        }

        if let Some(bucket) = global_bucket.as_mut() {
            bucket.consume_ready_token();
        }
        if let Some(host) = host_key.as_ref()
            && let Some(entry) = per_host.get_mut(host)
        {
            entry.last_used_at = now;
            entry.bucket.consume_ready_token();
        }

        Duration::ZERO
    }

    pub(crate) fn observe_server_throttle(
        &self,
        host: Option<&str>,
        delay: Duration,
        configured_scope: ServerThrottleScope,
        header_scope_hint: Option<ServerThrottleScope>,
    ) {
        if delay.is_zero() {
            return;
        }

        let now = Instant::now();
        let host_key = host.map(|item| item.to_ascii_lowercase());
        let resolved_scope = self.resolve_server_throttle_scope(
            configured_scope,
            header_scope_hint,
            host_key.is_some(),
        );

        let mut applied = false;

        if resolved_scope.apply_global()
            && let Some(global) = &self.global
        {
            let mut bucket = lock_unpoisoned(global);
            bucket.apply_throttle(now, delay);
            applied = true;
        }

        if resolved_scope.apply_host()
            && let (Some(policy), Some(host)) = (self.per_host_policy, host_key.clone())
        {
            let mut per_host = lock_unpoisoned(&self.per_host);
            self.maybe_cleanup_stale_per_host_rate_limits(&mut per_host, now);
            let entry = per_host
                .entry(host)
                .or_insert_with(|| PerHostRateLimitEntry {
                    bucket: TokenBucket::new(policy, now),
                    last_used_at: now,
                });
            entry.last_used_at = now;
            entry.bucket.apply_throttle(now, delay);
            applied = true;
        }

        if !applied {
            if let (Some(policy), Some(host)) = (self.per_host_policy, host_key) {
                let mut per_host = lock_unpoisoned(&self.per_host);
                self.maybe_cleanup_stale_per_host_rate_limits(&mut per_host, now);
                let entry = per_host
                    .entry(host)
                    .or_insert_with(|| PerHostRateLimitEntry {
                        bucket: TokenBucket::new(policy, now),
                        last_used_at: now,
                    });
                entry.last_used_at = now;
                entry.bucket.apply_throttle(now, delay);
            } else if let Some(global) = &self.global {
                let mut bucket = lock_unpoisoned(global);
                bucket.apply_throttle(now, delay);
            }
        }
    }

    fn maybe_cleanup_stale_per_host_rate_limits(
        &self,
        entries: &mut BTreeMap<String, PerHostRateLimitEntry>,
        now: Instant,
    ) {
        let now_ms = now
            .saturating_duration_since(self.per_host_cleanup_origin)
            .as_millis()
            .min(u64::MAX as u128) as u64;
        if entries.len() > PER_HOST_RATE_LIMIT_MAX_ENTRIES {
            cleanup_stale_per_host_rate_limits(entries, now);
            self.per_host_last_cleanup_ms
                .store(now_ms, Ordering::Relaxed);
            return;
        }

        let cleanup_interval_ms = PER_HOST_RATE_LIMIT_CLEANUP_INTERVAL
            .as_millis()
            .min(u64::MAX as u128) as u64;

        loop {
            let last_cleanup_ms = self.per_host_last_cleanup_ms.load(Ordering::Relaxed);
            if now_ms.saturating_sub(last_cleanup_ms) < cleanup_interval_ms {
                return;
            }
            if self
                .per_host_last_cleanup_ms
                .compare_exchange(
                    last_cleanup_ms,
                    now_ms,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }

        cleanup_stale_per_host_rate_limits(entries, now);
    }

    fn resolve_server_throttle_scope(
        &self,
        configured_scope: ServerThrottleScope,
        header_scope_hint: Option<ServerThrottleScope>,
        has_host: bool,
    ) -> ServerThrottleScope {
        match configured_scope {
            ServerThrottleScope::Auto => match header_scope_hint {
                Some(ServerThrottleScope::Host) => ServerThrottleScope::Host,
                Some(ServerThrottleScope::Global) => ServerThrottleScope::Global,
                Some(ServerThrottleScope::Both) => ServerThrottleScope::Both,
                _ => {
                    if has_host && self.per_host_policy.is_some() {
                        ServerThrottleScope::Host
                    } else if self.global.is_some() {
                        ServerThrottleScope::Global
                    } else {
                        ServerThrottleScope::Host
                    }
                }
            },
            other => other,
        }
    }
}

impl ServerThrottleScope {
    const fn apply_host(self) -> bool {
        matches!(self, Self::Host | Self::Both)
    }

    const fn apply_global(self) -> bool {
        matches!(self, Self::Global | Self::Both)
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

    use super::{
        RateLimitPolicy, RateLimiter, ServerThrottleScope, server_throttle_scope_from_headers,
    };

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
            ServerThrottleScope::Auto,
            None,
        );
        assert!(
            limiter.acquire_delay(Some("api.example.com")) >= std::time::Duration::from_millis(110)
        );
    }

    #[test]
    fn auto_server_throttle_scope_prefers_host_bucket_when_available() {
        let limiter = RateLimiter::new(
            Some(
                RateLimitPolicy::standard()
                    .requests_per_second(500.0)
                    .burst(100),
            ),
            Some(
                RateLimitPolicy::standard()
                    .requests_per_second(500.0)
                    .burst(100),
            ),
        )
        .expect("limiter should be built");

        limiter.observe_server_throttle(
            Some("api-a.example.com"),
            std::time::Duration::from_millis(120),
            ServerThrottleScope::Auto,
            None,
        );

        let host_a_wait = limiter.acquire_delay(Some("api-a.example.com"));
        let host_b_wait = limiter.acquire_delay(Some("api-b.example.com"));
        assert!(host_a_wait >= std::time::Duration::from_millis(110));
        assert!(host_b_wait <= std::time::Duration::from_millis(20));
    }

    #[test]
    fn global_server_throttle_scope_backpressures_all_hosts() {
        let limiter = RateLimiter::new(
            Some(
                RateLimitPolicy::standard()
                    .requests_per_second(500.0)
                    .burst(100),
            ),
            Some(
                RateLimitPolicy::standard()
                    .requests_per_second(500.0)
                    .burst(100),
            ),
        )
        .expect("limiter should be built");

        limiter.observe_server_throttle(
            Some("api-a.example.com"),
            std::time::Duration::from_millis(120),
            ServerThrottleScope::Global,
            None,
        );

        let host_b_wait = limiter.acquire_delay(Some("api-b.example.com"));
        assert!(host_b_wait >= std::time::Duration::from_millis(110));
    }

    #[test]
    fn scope_header_is_parsed() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-ratelimit-scope",
            http::HeaderValue::from_static("global"),
        );
        assert_eq!(
            server_throttle_scope_from_headers(&headers),
            Some(ServerThrottleScope::Global)
        );
    }
}
