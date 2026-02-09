use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::HttpClientError;
use crate::util::lock_unpoisoned;

const PER_HOST_LIMITER_ENTRY_TTL: Duration = Duration::from_secs(300);
const PER_HOST_LIMITER_MAX_ENTRIES: usize = 1024;

#[derive(Clone)]
pub(crate) struct RequestLimiters {
    global: Option<Arc<Semaphore>>,
    per_host_limit: Option<usize>,
    per_host: Arc<Mutex<BTreeMap<String, PerHostLimiterEntry>>>,
}

#[derive(Clone)]
struct PerHostLimiterEntry {
    semaphore: Arc<Semaphore>,
    last_used_at: Instant,
}

pub(crate) struct RequestPermits {
    pub(crate) _global: Option<OwnedSemaphorePermit>,
    pub(crate) _host: Option<OwnedSemaphorePermit>,
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

    pub(crate) async fn acquire(
        &self,
        host: Option<&str>,
    ) -> Result<RequestPermits, HttpClientError> {
        let global = if let Some(semaphore) = &self.global {
            Some(
                semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| HttpClientError::ConcurrencyLimitClosed)?,
            )
        } else {
            None
        };

        let host = host.map(|item| item.to_ascii_lowercase());
        let host_semaphore = match (self.per_host_limit, host) {
            (Some(limit), Some(host)) => {
                let semaphore = {
                    let mut guard = lock_unpoisoned(&self.per_host);
                    let now = Instant::now();
                    cleanup_stale_per_host_limiters(&mut guard, now);
                    let entry = guard.entry(host).or_insert_with(|| PerHostLimiterEntry {
                        semaphore: Arc::new(Semaphore::new(limit)),
                        last_used_at: now,
                    });
                    entry.last_used_at = now;
                    entry.semaphore.clone()
                };
                Some(
                    semaphore
                        .acquire_owned()
                        .await
                        .map_err(|_| HttpClientError::ConcurrencyLimitClosed)?,
                )
            }
            _ => None,
        };

        Ok(RequestPermits {
            _global: global,
            _host: host_semaphore,
        })
    }
}

fn cleanup_stale_per_host_limiters(
    entries: &mut BTreeMap<String, PerHostLimiterEntry>,
    now: Instant,
) {
    entries.retain(|_, entry| now.duration_since(entry.last_used_at) <= PER_HOST_LIMITER_ENTRY_TTL);

    while entries.len() > PER_HOST_LIMITER_MAX_ENTRIES {
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
