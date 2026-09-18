use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Raw unmasked event as received at ingestion boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub event_id: String,
    pub raw_payload: String,
    pub raw_sha256: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
}

/// Unmasked processing copy.
/// The raw original is preserved untouched in the Evidence Vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingCopy {
    pub event_id: String,
    pub unmasked_payload: String,
    pub raw_sha256: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
}

impl From<RawEvent> for ProcessingCopy {
    fn from(raw: RawEvent) -> Self {
        Self {
            event_id: raw.event_id,
            unmasked_payload: raw.raw_payload,
            raw_sha256: raw.raw_sha256,
            timestamp: raw.timestamp,
            source: raw.source,
        }
    }
}

/// Type constraint rating used to strictly sort leaf variants.
/// More constrained types rank higher (tried first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TypeConstraint {
    /// Generic string catch-all (least constrained)
    GenericString = 1,
    /// Numeric integer/port
    Integer = 2,
    /// Hex / MAC / Timestamp
    HexMacTime = 3,
    /// IP Address (IPv4 / IPv6) (most constrained)
    IpAddress = 4,
}

/// A complete, validated parser variant associated with a BPT leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserVariant {
    pub variant_id: String,
    pub version: u32,
    pub name: String,
    pub regex_pattern: String,
    #[serde(skip)]
    pub compiled_regex: Option<Regex>,
    pub field_mappings: HashMap<String, String>, // capture_name -> ocsf_target (e.g. "src_ip" -> "src_endpoint.ip")
    pub field_types: HashMap<String, String>,    // capture_name -> type (e.g. "src_ip" -> "ip")
    pub type_constraint: TypeConstraint,         // Highest constraint in variant
    pub match_count: u64,                        // Secondary tie-breaker
    pub is_active: bool,
}

impl ParserVariant {
    pub fn new(
        variant_id: impl Into<String>,
        name: impl Into<String>,
        regex_pattern: impl Into<String>,
        field_mappings: HashMap<String, String>,
        field_types: HashMap<String, String>,
        type_constraint: TypeConstraint,
    ) -> Result<Self, regex::Error> {
        let pat = regex_pattern.into();
        let re = Regex::new(&pat)?;
        Ok(Self {
            variant_id: variant_id.into(),
            version: 1,
            name: name.into(),
            regex_pattern: pat,
            compiled_regex: Some(re),
            field_mappings,
            field_types,
            type_constraint,
            match_count: 0,
            is_active: true,
        })
    }

    pub fn compile(&mut self) -> Result<(), regex::Error> {
        if self.compiled_regex.is_none() {
            self.compiled_regex = Some(Regex::new(&self.regex_pattern)?);
        }
        Ok(())
    }
}

/// Structural representation retaining both skeleton and actual values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralSkeleton {
    /// Tokenized skeleton: e.g. "<VAR> <VAR> logins from device <VAR>"
    pub skeleton: String,
    /// Preserved actual values: e.g. [("VAR1", "john"), ("VAR2", "Tuesday"), ("VAR3", "6799")]
    pub variables: Vec<(String, String)>,
    /// Individual tokens of the skeleton (for bidirectional pattern tree matching)
    pub tokens: Vec<String>,
}

/// Result of Stage B runtime field/domain validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldValidationResult {
    pub is_valid: bool,
    pub failed_field: Option<String>,
    pub failed_value: Option<String>,
    pub failure_reason: Option<String>,
}

impl FieldValidationResult {
    pub fn success() -> Self {
        Self {
            is_valid: true,
            failed_field: None,
            failed_value: None,
            failure_reason: None,
        }
    }

    pub fn failure(field: impl Into<String>, value: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            is_valid: false,
            failed_field: Some(field.into()),
            failed_value: Some(value.into()),
            failure_reason: Some(reason.into()),
        }
    }
}

/// Evaluation result for candidate parser specs in the Trust Gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGateResult {
    pub approved: bool,
    pub rejection_stage: Option<String>,
    pub rejection_reason: Option<String>,
    pub confidence_score: f64,
}

/// Event-level quarantine entry for individual invalid or unparseable events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventQuarantineEntry {
    pub quarantine_id: String,
    pub event_id: String,
    pub raw_sha256: String,
    pub raw_message: String,
    pub failure_reason: String,
    pub failed_check: String,
    pub timestamp: DateTime<Utc>,
}

/// Parser-level quarantine entry for rejected AI-generated parser specifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserQuarantineEntry {
    pub quarantine_id: String,
    pub candidate_id: String,
    pub target_skeleton: String,
    pub raw_spec_json: String,
    pub rejection_stage: String,
    pub rejection_reason: String,
    pub timestamp: DateTime<Utc>,
}

/// Standardized OCSF v1.1.0 output structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSFEvent {
    pub class_uid: u32,
    pub activity_id: u32,
    pub severity_id: u32,
    pub time: i64,
    pub message: String,
    pub metadata: OCSFMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_endpoint: Option<OCSFEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_endpoint: Option<OCSFEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<OCSFActor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<OCSFDevice>,
    pub unmapped: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSFMetadata {
    pub version: String,
    pub product: String,
    pub original_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSFEndpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSFActor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSFDevice {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// Provenance batch record anchored to local append-only provenance ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub batch_id: String,
    pub start_index: u64,
    pub event_count: usize,
    pub merkle_root: String,
    pub timestamp: DateTime<Utc>,
}
