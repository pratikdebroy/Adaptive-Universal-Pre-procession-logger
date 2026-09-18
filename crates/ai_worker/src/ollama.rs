use crate::dedup::AnomalyDeduplicator;
use crate::rag::ParserRagIndex;
use aegislog_engine::models::{ParserVariant, TypeConstraint};
use aegislog_engine::AiDiscoveryProvider;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Ollama API request payload
#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
    format: String,
}

/// Ollama API response payload
#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

/// Declarative Parser Specification JSON response expected from SLM
#[derive(Deserialize)]
struct DeclarativeSpecJson {
    name: Option<String>,
    regex_pattern: String,
    field_mappings: HashMap<String, String>,
    field_types: HashMap<String, String>,
    confidence: Option<f64>,
}

/// Ollama AI worker proposing declarative parser specifications using local SLM.
pub struct OllamaAiWorker {
    pub ollama_url: String,
    pub model: String,
    client: Client,
    pub rag: Arc<std::sync::Mutex<ParserRagIndex>>,
    pub dedup: AnomalyDeduplicator,
}

impl OllamaAiWorker {
    pub fn new(ollama_url: impl Into<String>, model: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        Self {
            ollama_url: ollama_url.into(),
            model: model.into(),
            client,
            rag: Arc::new(std::sync::Mutex::new(ParserRagIndex::new())),
            dedup: AnomalyDeduplicator::default(),
        }
    }

    /// Build the strict JSON schema prompt for Ollama.
    fn build_prompt(&self, raw_log: &str, skeleton: &str) -> String {
        let similar = {
            let rag_guard = self.rag.lock().unwrap();
            rag_guard.retrieve_similar(skeleton, 2)
        };

        let mut examples_text = String::new();
        for (i, ex) in similar.iter().enumerate() {
            examples_text.push_str(&format!(
                "\nExample {}:\n  Skeleton: {}\n  Regex: {}\n  Mappings: {:?}\n",
                i + 1,
                ex.skeleton,
                ex.regex_pattern,
                ex.field_mappings
            ));
        }

        format!(
            r#"You are an expert cybersecurity log parser generator.
Analyze the following raw log line and its structural skeleton, then output a declarative JSON parser specification.

Raw Log Line:
{}

Structural Skeleton:
{}

Similar Validated Historical Examples:
{}

CRITICAL RULES:
1. Output ONLY a valid JSON object. Do not include markdown codeblocks, explanatory text, or code.
2. The regex_pattern MUST be safe with named capture groups (?P<name>...) matching the log line.
3. Target fields in field_mappings must use valid OCSF v1.1.0 paths (e.g. "src_endpoint.ip", "dst_endpoint.ip", "src_endpoint.port", "dst_endpoint.port", "actor.user.name", "message", "action").
4. field_types must map each capture group to one of: "ip", "port", "string", "timestamp".

JSON Schema:
{{
  "name": "Descriptive Parser Name",
  "regex_pattern": "^...$",
  "field_mappings": {{ "capture_name": "ocsf.target.field" }},
  "field_types": {{ "capture_name": "type" }},
  "confidence": 0.90
}}
"#,
            raw_log, skeleton, examples_text
        )
    }

    /// Query Ollama with up to 2 retries (circuit breaker).
    async fn call_ollama(&self, prompt: &str) -> Result<DeclarativeSpecJson, String> {
        let req_body = OllamaRequest {
            model: self.model.clone(),
            prompt: prompt.to_string(),
            stream: false,
            format: "json".to_string(),
        };

        let mut attempts = 0;
        let mut last_err = String::new();

        while attempts < 2 {
            attempts += 1;
            let res = self
                .client
                .post(format!("{}/api/generate", self.ollama_url))
                .json(&req_body)
                .send()
                .await;

            match res {
                Ok(resp) if resp.status().is_success() => {
                    let ollama_resp: OllamaResponse = resp
                        .json()
                        .await
                        .map_err(|e| format!("Failed to parse Ollama JSON: {}", e))?;

                    let spec: DeclarativeSpecJson = serde_json::from_str(&ollama_resp.response)
                        .map_err(|e| format!("Failed to parse declarative spec: {}", e))?;

                    return Ok(spec);
                }
                Ok(resp) => {
                    last_err = format!("Ollama returned status {}", resp.status());
                }
                Err(e) => {
                    last_err = format!("Ollama connection error: {}", e);
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Err(last_err)
    }

    /// Deterministic fallback synthesis when Ollama is offline or uninstalled.
    /// Safely synthesizes regex from key=value and standard syslog patterns without blocking line rate.
    fn synthesize_deterministic_spec(&self, raw_log: &str) -> DeclarativeSpecJson {
        let mut field_mappings = HashMap::new();
        let mut field_types = HashMap::new();
        let mut regex_parts = Vec::new();

        for word in raw_log.split_whitespace() {
            if let Some(eq_pos) = word.find('=') {
                let key = &word[..eq_pos];
                let _val = &word[eq_pos + 1..];
                let key_clean = key.trim().to_lowercase();
                let capture_name = key_clean.replace('.', "_").replace('-', "_");

                let (target_field, field_type) = match key_clean.as_str() {
                    "src" | "src_ip" | "srcip" | "source_ip" => ("src_endpoint.ip", "ip"),
                    "dst" | "dst_ip" | "dstip" | "destination_ip" => ("dst_endpoint.ip", "ip"),
                    "spt" | "src_port" | "sport" => ("src_endpoint.port", "port"),
                    "dpt" | "dst_port" | "dport" => ("dst_endpoint.port", "port"),
                    "user" | "username" => ("actor.user.name", "string"),
                    "action" | "act" => ("action", "string"),
                    _ => ("message", "string"),
                };

                let pattern_part = if field_type == "ip" {
                    format!(r"{}=(?P<{}>\d+\.\d+\.\d+\.\d+)", key, capture_name)
                } else if field_type == "port" {
                    format!(r"{}=(?P<{}>\d+)", key, capture_name)
                } else {
                    format!(r"{}=(?P<{}>\S+)", key, capture_name)
                };

                field_mappings.insert(capture_name.clone(), target_field.to_string());
                field_types.insert(capture_name, field_type.to_string());
                regex_parts.push(pattern_part);
            } else {
                regex_parts.push(regex::escape(word));
            }
        }

        let full_pattern = format!("^{}$", regex_parts.join(r"\s+"));

        DeclarativeSpecJson {
            name: Some("Synthesized Key-Value Parser".to_string()),
            regex_pattern: full_pattern,
            field_mappings,
            field_types,
            confidence: Some(0.90),
        }
    }
}

impl AiDiscoveryProvider for OllamaAiWorker {
    fn propose_variant<'a>(
        &'a self,
        raw_log: &'a str,
        skeleton: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(ParserVariant, f64), String>> + Send + 'a>> {
        Box::pin(async move {
            let prompt = self.build_prompt(raw_log, skeleton);

            // Try Ollama first; if offline, synthesize deterministic fallback
            let spec_json = match self.call_ollama(&prompt).await {
                Ok(spec) => spec,
                Err(_) => self.synthesize_deterministic_spec(raw_log),
            };

            let confidence = spec_json.confidence.unwrap_or(0.90);
            let variant_id = format!("var_{}", Uuid::new_v4().simple());
            let name = spec_json.name.unwrap_or_else(|| "Discovered Variant".to_string());

            // Determine highest type constraint
            let mut highest_constraint = TypeConstraint::GenericString;
            for t in spec_json.field_types.values() {
                match t.as_str() {
                    "ip" => highest_constraint = TypeConstraint::IpAddress,
                    "port" | "integer" if highest_constraint < TypeConstraint::Integer => {
                        highest_constraint = TypeConstraint::Integer;
                    }
                    "hex" | "mac" | "timestamp" if highest_constraint < TypeConstraint::HexMacTime => {
                        highest_constraint = TypeConstraint::HexMacTime;
                    }
                    _ => {}
                }
            }

            let variant = ParserVariant::new(
                variant_id,
                name,
                spec_json.regex_pattern,
                spec_json.field_mappings,
                spec_json.field_types,
                highest_constraint,
            )
            .map_err(|e| format!("Compiled regex error in candidate spec: {}", e))?;

            Ok((variant, confidence))
        })
    }
}
