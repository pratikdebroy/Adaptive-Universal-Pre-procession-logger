use crate::bdpt::BidirectionalPatternTree;
use crate::merkle::MerkleTree;
use crate::models::{
    EventQuarantineEntry, OCSFEvent, ParserVariant, ProcessingCopy,
};
use crate::ocsf::OcsfNormalizer;
use crate::preprocessor::StructuralPreprocessor;
use crate::quarantine::QuarantineManager;
use crate::registry::ParserRegistry;
use crate::trust_gate::TrustGate;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

/// Trait for the AI discovery worker (implemented by `aegislog-ai-worker`).
pub trait AiDiscoveryProvider: Send + Sync {
    /// Request an AI-assisted parser variant proposal using RAG historical context and local SLM.
    fn propose_variant<'a>(
        &'a self,
        raw_log: &'a str,
        skeleton: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(ParserVariant, f64), String>> + Send + 'a>>;
}

/// Core AegisLog Pipeline engine.
pub struct AegisPipeline {
    pub preprocessor: StructuralPreprocessor,
    pub bdpt: Arc<Mutex<BidirectionalPatternTree>>,
    pub registry: Arc<Mutex<ParserRegistry>>,
    pub trust_gate: Arc<TrustGate>,
    pub normalizer: OcsfNormalizer,
    pub merkle_tree: Arc<Mutex<MerkleTree>>,
    pub quarantine: Arc<QuarantineManager>,
    pub ai_provider: Option<Arc<dyn AiDiscoveryProvider>>,
    pub slm_invocation_count: Arc<Mutex<usize>>,
}

impl AegisPipeline {
    pub fn new(
        merkle_tree: Arc<Mutex<MerkleTree>>,
        quarantine: Arc<QuarantineManager>,
    ) -> Self {
        Self {
            preprocessor: StructuralPreprocessor::new(),
            bdpt: Arc::new(Mutex::new(BidirectionalPatternTree::new())),
            registry: Arc::new(Mutex::new(ParserRegistry::new())),
            trust_gate: Arc::new(TrustGate::default()),
            normalizer: OcsfNormalizer::new(),
            merkle_tree,
            quarantine,
            ai_provider: None,
            slm_invocation_count: Arc::new(Mutex::new(0)),
        }
    }

    pub fn set_ai_provider(&mut self, provider: Arc<dyn AiDiscoveryProvider>) {
        self.ai_provider = Some(provider);
    }

    /// Process an ingested unmasked processing copy through the complete pipeline.
    ///
    /// Flow:
    /// 1. Structural Preprocessing (skeleton + actual values).
    /// 2. BDPT Structure Match.
    /// 3. Leaf Variant Sequential Trial (highest type constraint first, zero Cartesian product).
    /// 4. Field/Domain Validation (IP, Port, Timestamp).
    /// 5. In-Place Field-Level PII Masking.
    /// 6. OCSF v1.1.0 Normalization.
    /// 7. Cryptographic Provenance (Merkle Tree micro-batch).
    ///
    /// On Drift (variants exhausted or unknown structure):
    /// -> AI Discovery (RAG + SLM) -> Trust Gate -> Registry -> SAME BPT Leaf -> Process event.
    pub async fn process_event(
        &self,
        copy: ProcessingCopy,
    ) -> Result<OCSFEvent, EventQuarantineEntry> {
        let preprocessed = self.preprocessor.process(&copy.unmasked_payload);

        // 1. Match structure in BDPT
        let matched_skeleton = {
            let tree = self.bdpt.lock().unwrap();
            tree.match_tokens(&preprocessed.tokens).map(|leaf| leaf.skeleton_string.clone())
        };

        if let Some(skeleton_str) = matched_skeleton {
            // Case A: Known Structure -> retrieve variants from registry/leaf
            let variants = {
                let reg = self.registry.lock().unwrap();
                reg.get_variants_for_skeleton(&skeleton_str).into_iter().cloned().collect::<Vec<_>>()
            };

            // Sequential trial of compatible variants (highest constraint first)
            for variant in variants {
                if let Some(event) = self.try_execute_variant(&variant, &copy).await {
                    // Success! Increment match count
                    let mut reg = self.registry.lock().unwrap();
                    if let Some(reg_var) = reg.get_variant(&variant.variant_id) {
                        let mut updated = reg_var.clone();
                        updated.match_count += 1;
                        reg.register_variant(&skeleton_str, updated);
                    }
                    return Ok(event);
                }
            }

            // Case B: Known Structure, but all existing variants failed (Variant Drift)
            self.handle_drift_and_repair(&copy, &preprocessed.skeleton, true).await
        } else {
            // Case C: Completely Unknown Structure (Structural Drift)
            self.handle_drift_and_repair(&copy, &preprocessed.skeleton, false).await
        }
    }

    /// Deterministic variant trial: extracts fields, validates runtime invariants,
    /// applies field-level PII masking, and normalizes to OCSF.
    async fn try_execute_variant(
        &self,
        variant: &ParserVariant,
        copy: &ProcessingCopy,
    ) -> Option<OCSFEvent> {
        let regex = variant.compiled_regex.as_ref()?;
        let captures = regex.captures(&copy.unmasked_payload)?;

        // Extract captured fields mapped to OCSF targets
        let mut extracted: HashMap<String, String> = HashMap::new();
        for (capture_group, target_field) in &variant.field_mappings {
            if let Some(matched) = captures.name(capture_group) {
                extracted.insert(target_field.clone(), matched.as_str().to_string());
            }
        }

        // Field / Domain Runtime Validation (IP, Port, Timestamp)
        let validation = self.trust_gate.validate_extracted_fields(&extracted);
        if !validation.is_valid {
            // This variant does not match domain invariants for these values; try next variant
            return None;
        }

        // In-Place Field-Level PII Masking strictly after extraction
        for (target, val) in extracted.iter_mut() {
            let masked = self.trust_gate.mask_sensitive_field(target, val);
            *val = masked.into_owned();
        }

        // OCSF v1.1.0 Normalization
        let ocsf_event = self.normalizer.build_event(
            &extracted,
            &copy.raw_sha256,
            &copy.unmasked_payload,
        );

        // Cryptographic Provenance (Merkle Tree)
        {
            let mut merkle = self.merkle_tree.lock().unwrap();
            let _ = merkle.add_event_hash(&copy.raw_sha256);
        }

        Some(ocsf_event)
    }

    /// Self-healing drift repair: queries RAG + SLM, validates candidate spec in Trust Gate,
    /// registers approved variant on the SAME BPT leaf, and processes the current event.
    async fn handle_drift_and_repair(
        &self,
        copy: &ProcessingCopy,
        skeleton: &str,
        _is_known_structure: bool,
    ) -> Result<OCSFEvent, EventQuarantineEntry> {
        let provider = match &self.ai_provider {
            Some(p) => p.clone(),
            None => {
                let err = self.quarantine.quarantine_event(
                    &copy.event_id,
                    &copy.raw_sha256,
                    &copy.unmasked_payload,
                    "No matching parser variant and AI discovery provider unavailable",
                    "pipeline.drift_unresolved",
                ).unwrap();
                return Err(err);
            }
        };

        // Increment SLM invocation count metric
        {
            let mut count = self.slm_invocation_count.lock().unwrap();
            *count += 1;
        }

        // 1. Propose candidate parser variant via RAG context + SLM
        let (candidate_variant, confidence) = match provider.propose_variant(&copy.unmasked_payload, skeleton).await {
            Ok(res) => res,
            Err(e) => {
                let err = self.quarantine.quarantine_event(
                    &copy.event_id,
                    &copy.raw_sha256,
                    &copy.unmasked_payload,
                    &format!("AI discovery failed: {}", e),
                    "pipeline.ai_proposal_failed",
                ).unwrap();
                return Err(err);
            }
        };

        // 2. Trust Gate Candidate Spec Validation
        let tg_res = self.trust_gate.validate_candidate_spec(
            &candidate_variant.regex_pattern,
            &candidate_variant.field_mappings,
            confidence,
        );

        if !tg_res.approved {
            // Reject candidate -> route to PARSER QUARANTINE (NOT Event Quarantine!)
            let _ = self.quarantine.quarantine_parser(
                &candidate_variant.variant_id,
                skeleton,
                &candidate_variant.regex_pattern,
                &tg_res.rejection_stage.unwrap_or_default(),
                &tg_res.rejection_reason.unwrap_or_default(),
            );

            // The event itself cannot be parsed -> route event to EVENT QUARANTINE
            let err = self.quarantine.quarantine_event(
                &copy.event_id,
                &copy.raw_sha256,
                &copy.unmasked_payload,
                "Candidate parser variant rejected by Trust Gate",
                "trust_gate.spec_rejected",
            ).unwrap();
            return Err(err);
        }

        // 3. Approved! Register variant in authoritative Parser Registry
        {
            let mut reg = self.registry.lock().unwrap();
            reg.register_variant(skeleton, candidate_variant.clone());
        }

        // 4. Associate variant with BPT leaf
        // If known structure, links to the SAME BPT leaf!
        // If new structure, inserts new entry and links variant!
        {
            let mut tree = self.bdpt.lock().unwrap();
            tree.insert(skeleton, Some(candidate_variant.clone()));
        }

        // 5. Process current event using newly registered variant
        if let Some(event) = self.try_execute_variant(&candidate_variant, copy).await {
            Ok(event)
        } else {
            let err = self.quarantine.quarantine_event(
                &copy.event_id,
                &copy.raw_sha256,
                &copy.unmasked_payload,
                "Approved parser variant failed runtime invariant validation on event",
                "pipeline.runtime_invariant_failed",
            ).unwrap();
            Err(err)
        }
    }
}
