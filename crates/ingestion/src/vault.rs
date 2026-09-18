use aegislog_engine::RawEvent;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Append-only Evidence Vault.
/// Preserves exact, untouched raw logs along with their SHA-256 hash and ingestion timestamp.
/// Uses an embedded SQLite table for indexing and an append-only raw payload journal file.
pub struct EvidenceVault {
    db_conn: Arc<Mutex<Connection>>,
    journal_file: Arc<Mutex<File>>,
}

impl EvidenceVault {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self, String> {
        let base = base_dir.as_ref();
        std::fs::create_dir_all(base).map_err(|e| format!("Failed to create vault dir: {}", e))?;

        let db_path = base.join("evidence_vault.db");
        let conn = Connection::open(&db_path).map_err(|e| format!("Failed to open vault db: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence_vault (
                event_id TEXT PRIMARY KEY,
                raw_sha256 TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                payload_len INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("Failed to create vault schema: {}", e))?;

        let journal_path = base.join("raw_evidence.journal");
        let journal_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal_path)
            .map_err(|e| format!("Failed to open journal file: {}", e))?;

        Ok(Self {
            db_conn: Arc::new(Mutex::new(conn)),
            journal_file: Arc::new(Mutex::new(journal_file)),
        })
    }

    /// Append an immutable raw event to the vault.
    pub fn append(&self, event: &RawEvent) -> Result<(), String> {
        // Verify hash integrity before storing
        let mut hasher = Sha256::new();
        hasher.update(event.raw_payload.as_bytes());
        let computed_hash = hex::encode(hasher.finalize());

        if !computed_hash.eq_ignore_ascii_case(&event.raw_sha256) {
            return Err("Computed hash does not match provided raw_sha256".to_string());
        }

        // 1. Write to append-only raw journal
        {
            let mut journal = self.journal_file.lock().unwrap();
            writeln!(
                journal,
                "[{}] {} | SHA256:{} | PAYLOAD:{}",
                event.timestamp.to_rfc3339(),
                event.event_id,
                event.raw_sha256,
                event.raw_payload
            )
            .map_err(|e| format!("Journal write failed: {}", e))?;
            journal.flush().map_err(|e| format!("Journal flush failed: {}", e))?;
        }

        // 2. Insert into index
        let conn = self.db_conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO evidence_vault (event_id, raw_sha256, timestamp, source, payload_len)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.event_id,
                event.raw_sha256,
                event.timestamp.to_rfc3339(),
                event.source,
                event.raw_payload.len() as i64
            ],
        )
        .map_err(|e| format!("Vault DB insert failed: {}", e))?;

        Ok(())
    }

    /// Verify whether a raw SHA-256 exists and matches in the vault.
    pub fn verify_integrity(&self, raw_sha256: &str) -> bool {
        let conn = self.db_conn.lock().unwrap();
        let exists: Result<i64, _> = conn.query_row(
            "SELECT COUNT(*) FROM evidence_vault WHERE raw_sha256 = ?1",
            params![raw_sha256],
            |r| r.get(0),
        );
        exists.map(|c| c > 0).unwrap_or(false)
    }

    /// Total count of archived raw logs.
    pub fn total_archived(&self) -> usize {
        let conn = self.db_conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM evidence_vault", [], |r| r.get(0))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_vault_append_and_verify() {
        let temp_dir = std::env::temp_dir().join(format!("vault_test_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let vault = EvidenceVault::new(&temp_dir).unwrap();

        let raw_text = "<134>Sep 18 01:00:00 firewall-gw kernel: ACCEPT IN=eth0 OUT=eth1 SRC=192.168.1.50 DST=10.0.0.1";
        let mut hasher = Sha256::new();
        hasher.update(raw_text.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let raw_event = RawEvent {
            event_id: "evt_test_1".to_string(),
            raw_payload: raw_text.to_string(),
            raw_sha256: hash.clone(),
            timestamp: Utc::now(),
            source: "192.168.1.50:514".to_string(),
        };

        assert!(vault.append(&raw_event).is_ok());
        assert!(vault.verify_integrity(&hash));
        assert!(!vault.verify_integrity("0000000000000000000000000000000000000000000000000000000000000000"));
        assert_eq!(vault.total_archived(), 1);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
