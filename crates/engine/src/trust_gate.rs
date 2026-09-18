use crate::models::{FieldValidationResult, TrustGateResult};
use chrono::{DateTime, Utc};
use regex_syntax::ast::Ast;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Unified Validation / Trust Gate.
/// Handles two distinct validation concerns:
/// 1. Candidate Parser Specification Safety & Integrity (AST ReDoS check, schema allowlist, evidence threshold).
/// 2. Event Runtime Field/Domain Validation & In-Place PII Masking.
pub struct TrustGate {
    pub min_confidence_threshold: f64,
    pub allowlisted_target_fields: HashSet<String>,
}

impl Default for TrustGate {
    fn default() -> Self {
        let mut allowlisted = HashSet::new();
        for field in [
            "src_endpoint.ip",
            "src_endpoint.port",
            "src_endpoint.hostname",
            "src_endpoint.mac",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "dst_endpoint.hostname",
            "dst_endpoint.mac",
            "actor.user.name",
            "device.uid",
            "device.hostname",
            "network.transport",
            "action",
            "message",
            "time",
            "severity_id",
            "status",
        ] {
            allowlisted.insert(field.to_string());
        }

        Self {
            min_confidence_threshold: 0.85,
            allowlisted_target_fields: allowlisted,
        }
    }
}

impl TrustGate {
    pub fn new(min_confidence_threshold: f64) -> Self {
        Self {
            min_confidence_threshold,
            ..Default::default()
        }
    }

    // ========================================================================
    // 1. CANDIDATE PARSER VALIDATION (AI PROPOSALS)
    // ========================================================================

    /// Validate an AI-proposed parser specification through AST spec safety,
    /// field mapping allowlist, and confidence/evidence threshold.
    pub fn validate_candidate_spec(
        &self,
        regex_pattern: &str,
        field_mappings: &HashMap<String, String>,
        confidence_score: f64,
    ) -> TrustGateResult {
        // Stage A: Spec Safety (AST ReDoS Check)
        if let Err(reason) = self.check_ast_redos(regex_pattern) {
            return TrustGateResult {
                approved: false,
                rejection_stage: Some("STAGE_A_SPEC_SAFETY".to_string()),
                rejection_reason: Some(reason),
                confidence_score,
            };
        }

        // Stage B: Field Mapping Allowlist & Schema Alignment
        if field_mappings.is_empty() {
            return TrustGateResult {
                approved: false,
                rejection_stage: Some("STAGE_B_SCHEMA_ALLOWLIST".to_string()),
                rejection_reason: Some("Parser specification must define at least one field mapping".to_string()),
                confidence_score,
            };
        }

        for (capture_group, target_field) in field_mappings {
            if !self.allowlisted_target_fields.contains(target_field) {
                return TrustGateResult {
                    approved: false,
                    rejection_stage: Some("STAGE_B_SCHEMA_ALLOWLIST".to_string()),
                    rejection_reason: Some(format!(
                        "Target field '{}' for capture '{}' is not in the OCSF allowlist",
                        target_field, capture_group
                    )),
                    confidence_score,
                };
            }
        }

        // Stage C: Confidence / Evidence Threshold Check
        if confidence_score < self.min_confidence_threshold {
            return TrustGateResult {
                approved: false,
                rejection_stage: Some("STAGE_C_EVIDENCE_THRESHOLD".to_string()),
                rejection_reason: Some(format!(
                    "Confidence score {:.2} is below the required threshold of {:.2}",
                    confidence_score, self.min_confidence_threshold
                )),
                confidence_score,
            };
        }

        TrustGateResult {
            approved: true,
            rejection_stage: None,
            rejection_reason: None,
            confidence_score,
        }
    }

    /// Inspect regex AST for catastrophic backtracking risks (nested repetitions, dangerous loops).
    pub fn check_ast_redos(&self, pattern: &str) -> Result<(), String> {
        let ast = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .map_err(|e| format!("Invalid regex syntax: {}", e))?;

        if self.has_nested_repetition(&ast, false) {
            return Err(format!(
                "Catastrophic backtracking risk detected: nested repetition in regex '{}'",
                pattern
            ));
        }

        Ok(())
    }

    fn has_nested_repetition(&self, ast: &Ast, inside_repetition: bool) -> bool {
        match ast {
            Ast::Repetition(rep) => {
                if inside_repetition {
                    // Nested repetition found: e.g. (a+)+ or (.*\s*)*
                    return true;
                }
                self.has_nested_repetition(&rep.ast, true)
            }
            Ast::Group(group) => self.has_nested_repetition(&group.ast, inside_repetition),
            Ast::Concat(concat) => concat
                .asts
                .iter()
                .any(|child| self.has_nested_repetition(child, inside_repetition)),
            Ast::Alternation(alt) => alt
                .asts
                .iter()
                .any(|child| self.has_nested_repetition(child, inside_repetition)),
            _ => false,
        }
    }

    // ========================================================================
    // 2. RUNTIME EVENT FIELD/DOMAIN VALIDATION
    // ========================================================================

    /// Validate extracted runtime values (IP, port, timestamp) against field invariants.
    pub fn validate_extracted_fields(
        &self,
        extracted: &HashMap<String, String>,
    ) -> FieldValidationResult {
        for (target_field, val) in extracted {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                continue;
            }

            // 1. IP Invariant
            if target_field.ends_with(".ip") {
                if trimmed.parse::<IpAddr>().is_err() {
                    return FieldValidationResult::failure(
                        target_field,
                        trimmed,
                        format!("Invalid IP address format: '{}'", trimmed),
                    );
                }
            }

            // 2. Port Invariant
            if target_field.ends_with(".port") {
                match trimmed.parse::<u32>() {
                    Ok(port) if port <= 65535 => {}
                    _ => {
                        return FieldValidationResult::failure(
                            target_field,
                            trimmed,
                            format!("Port out of valid range (0-65535): '{}'", trimmed),
                        );
                    }
                }
            }

            // 3. Timestamp Invariant
            if target_field == "time" {
                if let Err(err) = self.validate_timestamp_plausibility(trimmed) {
                    return FieldValidationResult::failure(target_field, trimmed, err);
                }
            }
        }

        FieldValidationResult::success()
    }

    fn validate_timestamp_plausibility(&self, val: &str) -> Result<(), String> {
        // Try RFC3339 / ISO-8601
        let ts = if let Ok(dt) = DateTime::parse_from_rfc3339(val) {
            dt.with_timezone(&Utc).timestamp()
        } else if let Ok(num) = val.parse::<i64>() {
            // Epoch seconds or milliseconds
            if num > 1_000_000_000_000 {
                num / 1000
            } else {
                num
            }
        } else {
            return Err(format!("Unparseable timestamp: '{}'", val));
        };

        let now = Utc::now().timestamp();
        let max_future = now + 86400; // 24 hours
        let max_past = now - (10 * 365 * 86400); // 10 years

        if ts < max_past || ts > max_future {
            return Err(format!(
                "Timestamp '{}' outside plausible temporal window (-10y to +24h)",
                val
            ));
        }

        Ok(())
    }

    // ========================================================================
    // 3. ZERO-ALLOCATION FIELD-LEVEL PII MASKING
    // ========================================================================

    /// Mask isolated sensitive fields in-place (`Cow<str>`).
    /// Targets only high-risk fields: `actor.user.name`, `credentials`, `auth_token`.
    /// Does NOT re-scan the entire raw message.
    pub fn mask_sensitive_field<'a>(&self, target_field: &str, value: &'a str) -> Cow<'a, str> {
        if target_field == "actor.user.name"
            || target_field.contains("token")
            || target_field.contains("password")
            || target_field.contains("secret")
        {
            Cow::Borrowed("[REDACTED]")
        } else {
            Cow::Borrowed(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redos_detection() {
        let gate = TrustGate::default();

        // Catastrophic backtracking patterns: (a+)+, (.*\s*)*
        let dangerous_1 = r"^([a-z]+)+$";
        assert!(gate.check_ast_redos(dangerous_1).is_err());

        let dangerous_2 = r"^(.*\s*)*$";
        assert!(gate.check_ast_redos(dangerous_2).is_err());

        // Safe patterns
        let safe_1 = r"^SRC=(?P<src>\d+\.\d+\.\d+\.\d+) DST=(?P<dst>\d+\.\d+\.\d+\.\d+)$";
        assert!(gate.check_ast_redos(safe_1).is_ok());
    }

    #[test]
    fn test_field_invariants() {
        let gate = TrustGate::default();

        let mut valid_fields = HashMap::new();
        valid_fields.insert("src_endpoint.ip".to_string(), "10.0.0.1".to_string());
        valid_fields.insert("src_endpoint.port".to_string(), "8080".to_string());
        assert!(gate.validate_extracted_fields(&valid_fields).is_valid);

        let mut bad_ip = HashMap::new();
        bad_ip.insert("src_endpoint.ip".to_string(), "999.999.999.999".to_string());
        assert!(!gate.validate_extracted_fields(&bad_ip).is_valid);

        let mut bad_port = HashMap::new();
        bad_port.insert("src_endpoint.port".to_string(), "99999".to_string());
        assert!(!gate.validate_extracted_fields(&bad_port).is_valid);
    }
}
