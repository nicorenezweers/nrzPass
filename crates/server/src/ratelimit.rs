//! Einfacher Token-Bucket je Schluessel (IP oder Benutzer), nur im Speicher.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_per_sec: f64) -> RateLimiter {
        RateLimiter { capacity: capacity.max(1) as f64, refill_per_sec, buckets: Mutex::new(HashMap::new()) }
    }

    /// `true`, wenn die Anfrage erlaubt ist (verbraucht ein Token).
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut m = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 10_000 {
            // Volle Buckets vergessen, damit der Speicher nicht waechst
            let (cap, rate) = (self.capacity, self.refill_per_sec);
            m.retain(|_, (t, at)| *t + now.duration_since(*at).as_secs_f64() * rate < cap);
        }
        let e = m.entry(key.to_string()).or_insert((self.capacity, now));
        e.0 = (e.0 + now.duration_since(e.1).as_secs_f64() * self.refill_per_sec).min(self.capacity);
        e.1 = now;
        if e.0 >= 1.0 {
            e.0 -= 1.0;
            true
        } else {
            false
        }
    }
}
