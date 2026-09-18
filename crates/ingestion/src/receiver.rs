use crate::vault::EvidenceVault;
use aegislog_engine::{ProcessingCopy, RawEvent};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

pub const MAX_PAYLOAD_BYTES: usize = 65536; // 64 KB

/// Ingestion receiver enforcing defensive bounding, SHA-256 hash generation,
/// Evidence Vault archiving, and unmasked processing copy creation.
pub struct IngestionReceiver {
    vault: Arc<EvidenceVault>,
}

impl IngestionReceiver {
    pub fn new(vault: Arc<EvidenceVault>) -> Self {
        Self { vault }
    }

    /// Ingest a raw payload string from transport (Syslog TCP/UDP).
    ///
    /// Bounding Rule:
    /// - If payload > 64 KB, reject immediately with Error (Event Quarantine).
    ///
    /// Success Rule:
    /// - Generate SHA-256 hash.
    /// - Store immutable untouched raw event in Evidence Vault.
    /// - Return unmasked ProcessingCopy for downstream pipeline execution.
    pub fn ingest(
        &self,
        raw_message: &str,
        source_addr: &str,
    ) -> Result<ProcessingCopy, String> {
        let byte_len = raw_message.len();
        if byte_len > MAX_PAYLOAD_BYTES {
            return Err(format!(
                "Payload size ({} bytes) exceeds strict bounding limit of {} bytes",
                byte_len, MAX_PAYLOAD_BYTES
            ));
        }

        if raw_message.trim().is_empty() {
            return Err("Empty or whitespace-only log message rejected".to_string());
        }

        // 1. Calculate SHA-256
        let mut hasher = Sha256::new();
        hasher.update(raw_message.as_bytes());
        let raw_sha256 = hex::encode(hasher.finalize());

        let event_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let raw_event = RawEvent {
            event_id: event_id.clone(),
            raw_payload: raw_message.to_string(),
            raw_sha256: raw_sha256.clone(),
            timestamp: now,
            source: source_addr.to_string(),
        };

        // 2. Append exact original untouched log to Evidence Vault
        self.vault.append(&raw_event)?;

        // 3. Create unmasked processing copy
        let copy = ProcessingCopy::from(raw_event);

        Ok(copy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingest_payload_bounding() {
        let temp_dir = std::env::temp_dir().join(format!("receiver_test_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let vault = Arc::new(EvidenceVault::new(&temp_dir).unwrap());
        let receiver = IngestionReceiver::new(vault);

        // 1. Valid payload
        let valid = "SRC=10.0.0.1 DST=10.0.0.2 DPT=80";
        let res = receiver.ingest(valid, "127.0.0.1:514");
        assert!(res.is_ok());
        let copy = res.unwrap();
        assert_eq!(copy.unmasked_payload, valid);

        // 2. Oversized payload (> 64 KB)
        let oversized = "A".repeat(MAX_PAYLOAD_BYTES + 1);
        let over_res = receiver.ingest(&oversized, "127.0.0.1:514");
        assert!(over_res.is_err());
        assert!(over_res.unwrap_err().contains("exceeds strict bounding limit"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
