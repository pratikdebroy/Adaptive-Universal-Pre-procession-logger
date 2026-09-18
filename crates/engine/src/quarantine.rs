use crate::models::{EventQuarantineEntry, ParserQuarantineEntry};
use chrono::Utc;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Dual quarantine manager that keeps Event Quarantine and Parser Quarantine strictly separated.
#[derive(Clone)]
pub struct QuarantineManager {
    db_conn: Arc<Mutex<Connection>>,
}

impl QuarantineManager {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;

        // Table A: Event Quarantine (individual invalid/unparseable events)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS event_quarantine (
                quarantine_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                raw_sha256 TEXT NOT NULL,
                raw_message TEXT NOT NULL,
                failure_reason TEXT NOT NULL,
                failed_check TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )",
            [],
        )?;

        // Table B: Parser Quarantine (rejected candidate parser specifications)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS parser_quarantine (
                quarantine_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL,
                target_skeleton TEXT NOT NULL,
                raw_spec_json TEXT NOT NULL,
                rejection_stage TEXT NOT NULL,
                rejection_reason TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )",
            [],
        )?;

        Ok(Self {
            db_conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Quarantine an individual event that failed parsing, invariant checks, or normalization.
    pub fn quarantine_event(
        &self,
        event_id: &str,
        raw_sha256: &str,
        raw_message: &str,
        failure_reason: &str,
        failed_check: &str,
    ) -> Result<EventQuarantineEntry, String> {
        let entry = EventQuarantineEntry {
            quarantine_id: Uuid::new_v4().to_string(),
            event_id: event_id.to_string(),
            raw_sha256: raw_sha256.to_string(),
            raw_message: raw_message.to_string(),
            failure_reason: failure_reason.to_string(),
            failed_check: failed_check.to_string(),
            timestamp: Utc::now(),
        };

        let conn = self.db_conn.lock().unwrap();
        conn.execute(
            "INSERT INTO event_quarantine (quarantine_id, event_id, raw_sha256, raw_message, failure_reason, failed_check, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.quarantine_id,
                entry.event_id,
                entry.raw_sha256,
                entry.raw_message,
                entry.failure_reason,
                entry.failed_check,
                entry.timestamp.to_rfc3339()
            ],
        )
        .map_err(|e| format!("Failed to record event quarantine: {}", e))?;

        Ok(entry)
    }

    /// Quarantine a candidate parser specification rejected by the Trust Gate.
    pub fn quarantine_parser(
        &self,
        candidate_id: &str,
        target_skeleton: &str,
        raw_spec_json: &str,
        rejection_stage: &str,
        rejection_reason: &str,
    ) -> Result<ParserQuarantineEntry, String> {
        let entry = ParserQuarantineEntry {
            quarantine_id: Uuid::new_v4().to_string(),
            candidate_id: candidate_id.to_string(),
            target_skeleton: target_skeleton.to_string(),
            raw_spec_json: raw_spec_json.to_string(),
            rejection_stage: rejection_stage.to_string(),
            rejection_reason: rejection_reason.to_string(),
            timestamp: Utc::now(),
        };

        let conn = self.db_conn.lock().unwrap();
        conn.execute(
            "INSERT INTO parser_quarantine (quarantine_id, candidate_id, target_skeleton, raw_spec_json, rejection_stage, rejection_reason, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.quarantine_id,
                entry.candidate_id,
                entry.target_skeleton,
                entry.raw_spec_json,
                entry.rejection_stage,
                entry.rejection_reason,
                entry.timestamp.to_rfc3339()
            ],
        )
        .map_err(|e| format!("Failed to record parser quarantine: {}", e))?;

        Ok(entry)
    }

    /// Count quarantined events.
    pub fn event_quarantine_count(&self) -> usize {
        let conn = self.db_conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM event_quarantine", [], |r| r.get(0))
            .unwrap_or(0)
    }

    /// Count quarantined parsers.
    pub fn parser_quarantine_count(&self) -> usize {
        let conn = self.db_conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM parser_quarantine", [], |r| r.get(0))
            .unwrap_or(0)
    }

    /// List recent quarantined events.
    pub fn list_event_quarantine(&self, limit: usize) -> Result<Vec<EventQuarantineEntry>, String> {
        let conn = self.db_conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT quarantine_id, event_id, raw_sha256, raw_message, failure_reason, failed_check, timestamp FROM event_quarantine ORDER BY id DESC LIMIT ?1")
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map(params![limit], |r| {
                let ts_str: String = r.get(6)?;
                let ts = chrono::DateTime::parse_from_rfc3339(&ts_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                Ok(EventQuarantineEntry {
                    quarantine_id: r.get(0)?,
                    event_id: r.get(1)?,
                    raw_sha256: r.get(2)?,
                    raw_message: r.get(3)?,
                    failure_reason: r.get(4)?,
                    failed_check: r.get(5)?,
                    timestamp: ts,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut list = Vec::new();
        for row in rows {
            if let Ok(entry) = row {
                list.push(entry);
            }
        }
        Ok(list)
    }

    /// List recent quarantined parser specifications.
    pub fn list_parser_quarantine(&self, limit: usize) -> Result<Vec<ParserQuarantineEntry>, String> {
        let conn = self.db_conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT quarantine_id, candidate_id, target_skeleton, raw_spec_json, rejection_stage, rejection_reason, timestamp FROM parser_quarantine ORDER BY id DESC LIMIT ?1")
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map(params![limit], |r| {
                let ts_str: String = r.get(6)?;
                let ts = chrono::DateTime::parse_from_rfc3339(&ts_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                Ok(ParserQuarantineEntry {
                    quarantine_id: r.get(0)?,
                    candidate_id: r.get(1)?,
                    target_skeleton: r.get(2)?,
                    raw_spec_json: r.get(3)?,
                    rejection_stage: r.get(4)?,
                    rejection_reason: r.get(5)?,
                    timestamp: ts,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut list = Vec::new();
        for row in rows {
            if let Ok(entry) = row {
                list.push(entry);
            }
        }
        Ok(list)
    }
}
