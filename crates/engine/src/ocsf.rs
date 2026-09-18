use crate::models::{OCSFActor, OCSFDevice, OCSFEndpoint, OCSFEvent, OCSFMetadata};
use chrono::Utc;
use std::collections::HashMap;

/// Normalizes extracted and validated fields into strongly-typed OCSF v1.1.0 events.
#[derive(Debug, Default, Clone)]
pub struct OcsfNormalizer;

impl OcsfNormalizer {
    pub fn new() -> Self {
        Self
    }

    /// Build a standard OCSF v1.1.0 event from mapped fields, linking the immutable Evidence Vault hash.
    pub fn build_event(
        &self,
        fields: &HashMap<String, String>,
        raw_sha256: &str,
        raw_message: &str,
    ) -> OCSFEvent {
        let now = Utc::now();
        let time_sec = if let Some(t_str) = fields.get("time") {
            t_str.parse::<i64>().unwrap_or_else(|_| now.timestamp())
        } else {
            now.timestamp()
        };

        // Standard OCSF Class 4001: Network Activity, Class 3001: System Activity
        let is_network = fields.keys().any(|k| k.starts_with("src_endpoint") || k.starts_with("dst_endpoint"));
        let class_uid = if is_network { 4001 } else { 3001 };

        let src_ip = fields.get("src_endpoint.ip").cloned();
        let src_port = fields.get("src_endpoint.port").and_then(|p| p.parse::<u16>().ok());
        let src_host = fields.get("src_endpoint.hostname").cloned();
        let src_mac = fields.get("src_endpoint.mac").cloned();

        let src_endpoint = if src_ip.is_some() || src_port.is_some() || src_host.is_some() || src_mac.is_some() {
            Some(OCSFEndpoint {
                ip: src_ip,
                port: src_port,
                hostname: src_host,
                mac: src_mac,
            })
        } else {
            None
        };

        let dst_ip = fields.get("dst_endpoint.ip").cloned();
        let dst_port = fields.get("dst_endpoint.port").and_then(|p| p.parse::<u16>().ok());
        let dst_host = fields.get("dst_endpoint.hostname").cloned();
        let dst_mac = fields.get("dst_endpoint.mac").cloned();

        let dst_endpoint = if dst_ip.is_some() || dst_port.is_some() || dst_host.is_some() || dst_mac.is_some() {
            Some(OCSFEndpoint {
                ip: dst_ip,
                port: dst_port,
                hostname: dst_host,
                mac: dst_mac,
            })
        } else {
            None
        };

        let actor = fields.get("actor.user.name").map(|u| OCSFActor {
            user_name: Some(u.clone()),
        });

        let device = if fields.contains_key("device.uid") || fields.contains_key("device.hostname") {
            Some(OCSFDevice {
                uid: fields.get("device.uid").cloned(),
                hostname: fields.get("device.hostname").cloned(),
            })
        } else {
            None
        };

        let mut unmapped = HashMap::new();
        // Cryptographic pointer back to immutable raw log in Evidence Vault
        unmapped.insert(
            "raw_event_hash".to_string(),
            serde_json::Value::String(raw_sha256.to_string()),
        );

        // Store any unmapped fields
        for (k, v) in fields {
            if !k.starts_with("src_endpoint")
                && !k.starts_with("dst_endpoint")
                && k != "actor.user.name"
                && k != "device.uid"
                && k != "device.hostname"
                && k != "time"
            {
                unmapped.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
        }

        OCSFEvent {
            class_uid,
            activity_id: 1,
            severity_id: 1,
            time: time_sec,
            message: raw_message.to_string(),
            metadata: OCSFMetadata {
                version: "1.1.0".to_string(),
                product: "AegisLog".to_string(),
                original_time: now.to_rfc3339(),
            },
            src_endpoint,
            dst_endpoint,
            actor,
            device,
            unmapped,
        }
    }
}
