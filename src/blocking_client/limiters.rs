use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::util::lock_unpoisoned;

const PER_HOST_LIMITER_ENTRY_TTL: Duration = Duration::from_secs(300);
const PER_HOST_LIMITER_MAX_ENTRIES: usize = 1024;

#[derive(Clone)]
pub(crate) struct RequestLimiters {
    global: Option<Arc<BlockingSemaphore>>,
    per_host_limit: Option<usize>,
    per_host: Arc<Mutex<BTreeMap<String, PerHostLimiterEntry>>>,
}

#[derive(Clone)]
struct PerHostLimiterEntry {
    semaphore: Arc<BlockingSemaphore>,
    limit: usize,
    last_used_at: Instant,
}

#[derive(Debug)]
pub(crate) struct GlobalRequestPermit {
    _permit: Option<BlockingSemaphorePermit>,
}

#[derive(Debug)]
pub(crate) struct HostRequestPermit {
    _permit: Option<BlockingSemaphorePermit>,
}

#[derive(Debug)]
struct BlockingSemaphore {
    state: Mutex<usize>,
    condvar: Condvar,
}

impl BlockingSemaphore {
    fn new(permits: usize) -> Self {
        Self {
            state: Mutex::new(permits.max(1)),
            condvar: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> BlockingSemaphorePermit {
        let mut state = lock_unpoisoned(&self.state);
        while *state == 0 {
            state = match self.condvar.wait(state) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        *state -= 1;
        drop(state);
        BlockingSemaphorePermit {
            semaphore: Arc::clone(self),
            released: false,
        }
    }

    fn release(&self) {
        let mut state = lock_unpoisoned(&self.state);
        *state = state.saturating_add(1);
        self.condvar.notify_one();
    }

    fn available_permits(&self) -> usize {
        *lock_unpoisoned(&self.state)
    }
}

#[derive(Debug)]
struct BlockingSemaphorePermit {
    semaphore: Arc<BlockingSemaphore>,
    released: bool,
}

impl Drop for BlockingSemaphorePermit {
    fn drop(&mut self) {
        if !self.released {
            self.semaphore.release();
            self.released = true;
        }
    }
}

impl RequestLimiters {
    pub(crate) fn new(max_in_flight: Option<usize>, per_host_limit: Option<usize>) -> Option<Self> {
        if max_in_flight.is_none() && per_host_limit.is_none() {
            return None;
        }

        Some(Self {
            global: max_in_flight.map(|limit| Arc::new(BlockingSemaphore::new(limit))),
            per_host_limit,
            per_host: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    pub(crate) fn acquire_global(&self) -> Result<GlobalRequestPermit, Error> {
        let permit = self.global.as_ref().map(|semaphore| semaphore.acquire());
        Ok(GlobalRequestPermit { _permit: permit })
    }

    pub(crate) fn acquire_host(&self, host: Option<&str>) -> Result<HostRequestPermit, Error> {
        let host = host.map(|item| item.to_ascii_lowercase());
        let permit = match (self.per_host_limit, host) {
            (Some(limit), Some(host)) => {
                let semaphore = {
                    let mut guard = lock_unpoisoned(&self.per_host);
                    let now = Instant::now();
                    cleanup_stale_per_host_limiters(&mut guard, now);
                    let entry = guard.entry(host).or_insert_with(|| PerHostLimiterEntry {
                        semaphore: Arc::new(BlockingSemaphore::new(limit)),
                        limit,
                        last_used_at: now,
                    });
                    entry.last_used_at = now;
                    Arc::clone(&entry.semaphore)
                };
                Some(semaphore.acquire())
            }
            _ => None,
        };
        Ok(HostRequestPermit { _permit: permit })
    }
}

impl GlobalRequestPermit {
    pub(crate) const fn none() -> Self {
        Self { _permit: None }
    }
}

impl HostRequestPermit {
    pub(crate) const fn none() -> Self {
        Self { _permit: None }
    }
}

fn cleanup_stale_per_host_limiters(
    entries: &mut BTreeMap<String, PerHostLimiterEntry>,
    now: Instant,
) {
    entries.retain(|_, entry| {
        entry.semaphore.available_permits() < entry.limit
            || now.duration_since(entry.last_used_at) <= PER_HOST_LIMITER_ENTRY_TTL
    });

    while entries.len() > PER_HOST_LIMITER_MAX_ENTRIES {
        let oldest_key = entries
            .iter()
            .filter(|(_, entry)| entry.semaphore.available_permits() == entry.limit)
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
    use super::*;

    #[test]
    fn cleanup_keeps_stale_entry_while_permit_is_active() {
        let now = Instant::now();
        let stale = now
            .checked_sub(PER_HOST_LIMITER_ENTRY_TTL + Duration::from_secs(1))
            .expect("stale instant");
        let semaphore = Arc::new(BlockingSemaphore::new(1));
        let permit = semaphore.acquire();

        let mut entries = BTreeMap::new();
        entries.insert(
            "active.example.com".to_owned(),
            PerHostLimiterEntry {
                semaphore: Arc::clone(&semaphore),
                limit: 1,
                last_used_at: stale,
            },
        );

        cleanup_stale_per_host_limiters(&mut entries, now);
        assert!(entries.contains_key("active.example.com"));

        drop(permit);
        cleanup_stale_per_host_limiters(&mut entries, now);
        assert!(!entries.contains_key("active.example.com"));
    }

    #[test]
    fn cleanup_does_not_evict_active_entries_when_over_capacity() {
        let now = Instant::now();
        let active_semaphore = Arc::new(BlockingSemaphore::new(1));
        let _active_permit = active_semaphore.acquire();

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
                    semaphore: Arc::new(BlockingSemaphore::new(1)),
                    limit: 1,
                    last_used_at: now,
                },
            );
        }

        cleanup_stale_per_host_limiters(&mut entries, now);
        assert!(entries.contains_key("active.example.com"));
        assert_eq!(entries.len(), PER_HOST_LIMITER_MAX_ENTRIES);
    }
}
