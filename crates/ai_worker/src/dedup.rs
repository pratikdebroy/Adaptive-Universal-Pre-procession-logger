use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Deduplication buffer for anomalous log lines.
/// Collapses volume spikes of identical unknown structures into a single representative AI request.
pub struct AnomalyDeduplicator {
    seen_hashes: Mutex<HashMap<String, Instant>>,
    ttl: Duration,
}

impl Default for AnomalyDeduplicator {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl AnomalyDeduplicator {
    pub fn new(ttl: Duration) -> Self {
        Self {
            seen_hashes: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Compute the structural hash of an anomaly.
    pub fn compute_structural_hash(skeleton: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(skeleton.trim().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Check if this structural hash should be forwarded to AI discovery.
    /// Returns `true` if this is the first occurrence within the TTL window.
    pub fn should_process(&self, skeleton: &str) -> bool {
        let hash = Self::compute_structural_hash(skeleton);
        let now = Instant::now();

        let mut seen = self.seen_hashes.lock().unwrap();

        // Evict expired entries if table grows
        if seen.len() > 1000 {
            seen.retain(|_, time| now.duration_since(*time) < self.ttl);
        }

        if let Some(prev_time) = seen.get(&hash) {
            if now.duration_since(*prev_time) < self.ttl {
                return false; // Collapsed! Already in-flight or recently processed
            }
        }

        seen.insert(hash, now);
        true
    }
}
