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
        !entry.is_idle() || now.saturating_duration_since(entry.last_used_at()) <= entry_ttl
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

#[cfg(test)]
mod tests {
    use super::{
        PER_HOST_LIMITER_ENTRY_TTL, PER_HOST_LIMITER_MAX_ENTRIES, PerHostLimiterEntry,
        cleanup_stale_per_host_limiters,
    };
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy)]
    struct TestEntry {
        idle: bool,
        last_used_at: Instant,
    }

    impl PerHostLimiterEntry for TestEntry {
        fn is_idle(&self) -> bool {
            self.idle
        }

        fn last_used_at(&self) -> Instant {
            self.last_used_at
        }
    }

    #[test]
    fn cleanup_tolerates_entries_newer_than_now() {
        let now = Instant::now();
        let future = now + Duration::from_secs(1);
        let mut entries = BTreeMap::from([(
            "future.example.com".to_owned(),
            TestEntry {
                idle: true,
                last_used_at: future,
            },
        )]);

        cleanup_stale_per_host_limiters(
            &mut entries,
            now,
            PER_HOST_LIMITER_ENTRY_TTL,
            PER_HOST_LIMITER_MAX_ENTRIES,
        );

        assert!(entries.contains_key("future.example.com"));
    }
}
