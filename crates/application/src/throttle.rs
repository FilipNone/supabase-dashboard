//! Sign-in throttling keyed by normalized email.
//!
//! After `max_failures` failed attempts within `window`, further attempts
//! for that email are refused until the window ends, without checking the
//! password. A success clears the counter. State is in memory and bounded:
//! restarting the server resets it, and with several server replicas each
//! keeps its own count.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy)]
pub struct ThrottleConfig {
    pub max_failures: u32,
    pub window: Duration,
    /// Most distinct keys tracked at once.
    pub capacity: usize,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            window: Duration::from_secs(15 * 60),
            capacity: 10_000,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    window_start: Instant,
    failures: u32,
}

pub struct LoginThrottle {
    config: ThrottleConfig,
    entries: Mutex<HashMap<String, Entry>>,
}

impl LoginThrottle {
    pub fn new(config: ThrottleConfig) -> Self {
        Self {
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// `Err(retry_after)` when `key` is currently blocked.
    pub fn check(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let entries = self.lock();
        match entries.get(key) {
            Some(entry) if entry.failures >= self.config.max_failures => {
                let ends = entry.window_start + self.config.window;
                if now < ends { Err(ends - now) } else { Ok(()) }
            }
            _ => Ok(()),
        }
    }

    pub fn record_failure(&self, key: &str, now: Instant) {
        let mut entries = self.lock();
        if !entries.contains_key(key) && entries.len() >= self.config.capacity {
            self.evict(&mut entries, now);
        }
        let window = self.config.window;
        let entry = entries.entry(key.to_owned()).or_insert(Entry {
            window_start: now,
            failures: 0,
        });
        if now.duration_since(entry.window_start) >= window {
            *entry = Entry {
                window_start: now,
                failures: 0,
            };
        }
        entry.failures = entry.failures.saturating_add(1);
    }

    pub fn record_success(&self, key: &str) {
        self.lock().remove(key);
    }

    /// Drops expired entries; if none expired, drops the oldest one so the
    /// map never exceeds its capacity.
    fn evict(&self, entries: &mut HashMap<String, Entry>, now: Instant) {
        let window = self.config.window;
        entries.retain(|_, entry| now.duration_since(entry.window_start) < window);
        if entries.len() >= self.config.capacity {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.window_start)
                .map(|(key, _)| key.clone());
            if let Some(key) = oldest {
                entries.remove(&key);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        // A poisoned lock only means another thread panicked mid-update; the
        // counters are still usable.
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn throttle(capacity: usize) -> LoginThrottle {
        LoginThrottle::new(ThrottleConfig {
            max_failures: 3,
            window: Duration::from_secs(60),
            capacity,
        })
    }

    #[test]
    fn blocks_after_max_failures_until_window_ends() {
        let t = throttle(10);
        let start = Instant::now();
        for _ in 0..3 {
            assert!(t.check("a", start).is_ok());
            t.record_failure("a", start);
        }
        let retry = t.check("a", start + Duration::from_secs(10)).unwrap_err();
        assert_eq!(retry, Duration::from_secs(50));
        assert!(t.check("b", start).is_ok(), "other keys are unaffected");
        assert!(t.check("a", start + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn success_clears_and_new_window_resets() {
        let t = throttle(10);
        let start = Instant::now();
        t.record_failure("a", start);
        t.record_failure("a", start);
        t.record_success("a");
        t.record_failure("a", start);
        t.record_failure("a", start);
        assert!(t.check("a", start).is_ok());
        // A failure after the window starts a fresh count.
        t.record_failure("a", start + Duration::from_secs(61));
        assert!(t.check("a", start + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn capacity_is_bounded() {
        let t = throttle(2);
        let now = Instant::now();
        for key in ["a", "b", "c", "d"] {
            t.record_failure(key, now);
        }
        assert!(t.lock().len() <= 2);
    }
}
