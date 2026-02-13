use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use crate::core::limiters::{
    PER_HOST_LIMITER_ENTRY_TTL, PER_HOST_LIMITER_MAX_ENTRIES,
    PerHostLimiterEntry as PerHostLimiterEntryState, cleanup_stale_per_host_limiters,
};
use crate::util::lock_unpoisoned;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcquirePermitError {
    Timeout,
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

    fn acquire(
        self: &Arc<Self>,
        deadline_at: Option<Instant>,
    ) -> Result<BlockingSemaphorePermit, AcquirePermitError> {
        let mut state = lock_unpoisoned(&self.state);
        loop {
            if *state > 0 {
                *state -= 1;
                drop(state);
                return Ok(BlockingSemaphorePermit {
                    semaphore: Arc::clone(self),
                    released: false,
                });
            }

            state = match deadline_at {
                Some(deadline_at) => {
                    let now = Instant::now();
                    if now >= deadline_at {
                        return Err(AcquirePermitError::Timeout);
                    }
                    let wait_for = deadline_at.duration_since(now);
                    let (next_state, wait_result) = match self.condvar.wait_timeout(state, wait_for)
                    {
                        Ok(result) => result,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if wait_result.timed_out() && *next_state == 0 && Instant::now() >= deadline_at
                    {
                        return Err(AcquirePermitError::Timeout);
                    }
                    next_state
                }
                None => match self.condvar.wait(state) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                },
            };
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

    pub(crate) fn acquire_global(
        &self,
        deadline_at: Option<Instant>,
    ) -> Result<GlobalRequestPermit, AcquirePermitError> {
        let permit = match &self.global {
            Some(semaphore) => Some(semaphore.acquire(deadline_at)?),
            None => None,
        };
        Ok(GlobalRequestPermit { _permit: permit })
    }

    pub(crate) fn acquire_host(
        &self,
        host: Option<&str>,
        deadline_at: Option<Instant>,
    ) -> Result<HostRequestPermit, AcquirePermitError> {
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
                        semaphore: Arc::new(BlockingSemaphore::new(limit)),
                        limit,
                        last_used_at: now,
                    });
                    entry.last_used_at = now;
                    Arc::clone(&entry.semaphore)
                };
                Some(semaphore.acquire(deadline_at)?)
            }
            _ => None,
        };
        Ok(HostRequestPermit { _permit: permit })
    }
}

impl PerHostLimiterEntryState for PerHostLimiterEntry {
    fn is_idle(&self) -> bool {
        self.semaphore.available_permits() == self.limit
    }

    fn last_used_at(&self) -> Instant {
        self.last_used_at
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
        let permit = semaphore
            .acquire(None)
            .expect("acquire active permit without deadline");

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
        let active_semaphore = Arc::new(BlockingSemaphore::new(1));
        let _active_permit = active_semaphore
            .acquire(None)
            .expect("acquire active permit without deadline");

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
