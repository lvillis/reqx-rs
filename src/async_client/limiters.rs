use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::core::limiters::{
    PER_HOST_LIMITER_ENTRY_TTL, PER_HOST_LIMITER_MAX_ENTRIES,
    PerHostLimiterEntry as PerHostLimiterEntryState, cleanup_stale_per_host_limiters,
};
use crate::error::Error;
use crate::util::lock_unpoisoned;

#[derive(Clone)]
pub(crate) struct RequestLimiters {
    global: Option<Arc<Semaphore>>,
    per_host_limit: Option<usize>,
    per_host: Arc<Mutex<BTreeMap<String, PerHostLimiterEntry>>>,
}

#[derive(Clone)]
struct PerHostLimiterEntry {
    semaphore: Arc<Semaphore>,
    limit: usize,
    last_used_at: Instant,
}

#[derive(Debug)]
pub(crate) struct GlobalRequestPermit {
    pub(crate) _permit: Option<OwnedSemaphorePermit>,
}

#[derive(Debug)]
pub(crate) struct HostRequestPermit {
    pub(crate) _permit: Option<OwnedSemaphorePermit>,
}

impl PerHostLimiterEntryState for PerHostLimiterEntry {
    fn is_idle(&self) -> bool {
        self.semaphore.available_permits() == self.limit
    }

    fn last_used_at(&self) -> Instant {
        self.last_used_at
    }
}

impl RequestLimiters {
    pub(crate) fn new(max_in_flight: Option<usize>, per_host_limit: Option<usize>) -> Option<Self> {
        if max_in_flight.is_none() && per_host_limit.is_none() {
            return None;
        }

        Some(Self {
            global: max_in_flight.map(|limit| Arc::new(Semaphore::new(limit))),
            per_host_limit,
            per_host: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    pub(crate) async fn acquire_global(&self) -> Result<GlobalRequestPermit, Error> {
        let permit = if let Some(semaphore) = &self.global {
            Some(
                semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| Error::ConcurrencyLimitClosed)?,
            )
        } else {
            None
        };
        Ok(GlobalRequestPermit { _permit: permit })
    }

    pub(crate) async fn acquire_host(
        &self,
        host: Option<&str>,
    ) -> Result<HostRequestPermit, Error> {
        let host = host.map(|item| item.to_ascii_lowercase());
        let permit = match (self.per_host_limit, host) {
            (Some(limit), Some(host)) => {
                let semaphore = {
                    let mut guard = lock_unpoisoned(&self.per_host);
                    let now = Instant::now();
                    cleanup_stale_per_host_limiters(
                        &mut guard,
                        now,
                        PER_HOST_LIMITER_ENTRY_TTL,
                        PER_HOST_LIMITER_MAX_ENTRIES,
                    );
                    let entry = guard.entry(host).or_insert_with(|| PerHostLimiterEntry {
                        semaphore: Arc::new(Semaphore::new(limit)),
                        limit,
                        last_used_at: now,
                    });
                    entry.last_used_at = now;
                    entry.semaphore.clone()
                };
                Some(
                    semaphore
                        .acquire_owned()
                        .await
                        .map_err(|_| Error::ConcurrencyLimitClosed)?,
                )
            }
            _ => None,
        };

        Ok(HostRequestPermit { _permit: permit })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_keeps_stale_entry_while_permit_is_active() {
        let now = Instant::now();
        let stale = now
            .checked_sub(PER_HOST_LIMITER_ENTRY_TTL + Duration::from_secs(1))
            .expect("stale instant");
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore
            .clone()
            .try_acquire_owned()
            .expect("acquire active permit");

        let mut entries = BTreeMap::new();
        entries.insert(
            "active.example.com".to_owned(),
            PerHostLimiterEntry {
                semaphore: Arc::clone(&semaphore),
                limit: 1,
                last_used_at: stale,
            },
        );

        cleanup_stale_per_host_limiters(
            &mut entries,
            now,
            PER_HOST_LIMITER_ENTRY_TTL,
            PER_HOST_LIMITER_MAX_ENTRIES,
        );
        assert!(entries.contains_key("active.example.com"));

        drop(permit);
        cleanup_stale_per_host_limiters(
            &mut entries,
            now,
            PER_HOST_LIMITER_ENTRY_TTL,
            PER_HOST_LIMITER_MAX_ENTRIES,
        );
        assert!(!entries.contains_key("active.example.com"));
    }

    #[test]
    fn cleanup_does_not_evict_active_entries_when_over_capacity() {
        let now = Instant::now();
        let active_semaphore = Arc::new(Semaphore::new(1));
        let _active_permit = active_semaphore
            .clone()
            .try_acquire_owned()
            .expect("acquire active permit");

        let mut entries = BTreeMap::new();
        entries.insert(
            "active.example.com".to_owned(),
            PerHostLimiterEntry {
                semaphore: Arc::clone(&active_semaphore),
                limit: 1,
                last_used_at: now,
            },
        );

        for index in 0..PER_HOST_LIMITER_MAX_ENTRIES {
            entries.insert(
                format!("idle-{index}.example.com"),
                PerHostLimiterEntry {
                    semaphore: Arc::new(Semaphore::new(1)),
                    limit: 1,
                    last_used_at: now,
                },
            );
        }

        cleanup_stale_per_host_limiters(
            &mut entries,
            now,
            PER_HOST_LIMITER_ENTRY_TTL,
            PER_HOST_LIMITER_MAX_ENTRIES,
        );
        assert!(entries.contains_key("active.example.com"));
        assert_eq!(entries.len(), PER_HOST_LIMITER_MAX_ENTRIES);
    }
}
