use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub(crate) const PER_HOST_LIMITER_ENTRY_TTL: Duration = Duration::from_secs(300);
pub(crate) const PER_HOST_LIMITER_MAX_ENTRIES: usize = 1024;

pub(crate) trait PerHostLimiterEntry: Sized {
    fn is_idle(&self) -> bool;
    fn last_used_at(&self) -> Instant;
}

pub(crate) fn cleanup_stale_per_host_limiters<E: PerHostLimiterEntry>(
    entries: &mut BTreeMap<String, E>,
    now: Instant,
    entry_ttl: Duration,
    max_entries: usize,
) {
    entries.retain(|_, entry| {
        !entry.is_idle() || now.duration_since(entry.last_used_at()) <= entry_ttl
    });

    while entries.len() > max_entries {
        let oldest_key = entries
            .iter()
            .filter(|(_, entry)| entry.is_idle())
            .min_by_key(|(_, entry)| entry.last_used_at())
            .map(|(host, _)| host.clone());
        let Some(oldest_key) = oldest_key else {
            break;
        };
        entries.remove(&oldest_key);
    }
}
