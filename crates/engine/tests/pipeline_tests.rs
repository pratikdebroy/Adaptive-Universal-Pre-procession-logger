use aegislog_engine::models::{
    ParserVariant, ProcessingCopy, TypeConstraint,
};
use aegislog_engine::pipeline::{AegisPipeline, AiDiscoveryProvider};
use aegislog_engine::{
    MerkleTree, ParserRegistry, QuarantineManager,
};
use aegislog_ingestion::{EvidenceVault, IngestionReceiver, MAX_PAYLOAD_BYTES};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

/// Mock AI Discovery Provider for deterministic testing of the self-healing loop.
struct MockAiDiscoveryProvider {
    pub custom_variant: Mutex<Option<(ParserVariant, f64)>>,
    pub invocations: Arc<Mutex<usize>>,
}

impl MockAiDiscoveryProvider {
    fn new(invocations: Arc<Mutex<usize>>) -> Self {
        Self {
            custom_variant: Mutex::new(None),
            invocations,
        }
    }

    fn set_proposal(&self, variant: ParserVariant, confidence: f64) {
        let mut guard = self.custom_variant.lock().unwrap();
        *guard = Some((variant, confidence));
    }
}

impl AiDiscoveryProvider for MockAiDiscoveryProvider {
    fn propose_variant<'a>(
        &'a self,
        _raw_log: &'a str,
        _skeleton: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(ParserVariant, f64), String>> + Send + 'a>> {
        Box::pin(async move {
            let mut count = self.invocations.lock().unwrap();
            *count += 1;

            let guard = self.custom_variant.lock().unwrap();
            if let Some((v, conf)) = guard.clone() {
                Ok((v, conf))
            } else {
                // Synthesize basic IP firewall variant
                let v = ParserVariant::new(
                    "discovered_fw_var",
                    "Discovered Firewall Variant",
                    r"^SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)\s+DPT=(?P<port>\d+)\s+ACTION=(?P<act>\S+)$",
                    HashMap::from([
                        ("src".into(), "src_endpoint.ip".into()),
                        ("dst".into(), "dst_endpoint.ip".into()),
                        ("port".into(), "src_endpoint.port".into()),
                        ("act".into(), "action".into()),
                    ]),
                    HashMap::from([
                        ("src".into(), "ip".into()),
                        ("dst".into(), "ip".into()),
                        ("port".into(), "port".into()),
                        ("act".into(), "string".into()),
                    ]),
                    TypeConstraint::IpAddress,
                )
                .unwrap();
                Ok((v, 0.92))
            }
        })
    }
}

fn setup_test_pipeline(test_name: &str) -> (AegisPipeline, Arc<EvidenceVault>, Arc<QuarantineManager>, Arc<Mutex<usize>>) {
    let temp_dir = std::env::temp_dir().join(format!("aegis_test_{}_{}", test_name, Utc::now().timestamp_nanos_opt().unwrap_or(0)));
    let _ = std::fs::create_dir_all(&temp_dir);

    let vault = Arc::new(EvidenceVault::new(&temp_dir).unwrap());
    let merkle_db = temp_dir.join("test_provenance.db");
    let merkle_tree = Arc::new(Mutex::new(MerkleTree::new(500, merkle_db).unwrap()));
    let quar_db = temp_dir.join("test_quarantine.db");
    let quarantine = Arc::new(QuarantineManager::new(quar_db).unwrap());

    let mut pipeline = AegisPipeline::new(merkle_tree, quarantine.clone());
    let slm_invocations = Arc::new(Mutex::new(0));
    let ai_provider = Arc::new(MockAiDiscoveryProvider::new(slm_invocations.clone()));
    pipeline.set_ai_provider(ai_provider);

    (pipeline, vault, quarantine, slm_invocations)
}

fn create_test_copy(raw_payload: &str) -> ProcessingCopy {
    let mut hasher = Sha256::new();
    hasher.update(raw_payload.as_bytes());
    let hash = hex::encode(hasher.finalize());

    ProcessingCopy {
        event_id: uuid::Uuid::new_v4().to_string(),
        unmasked_payload: raw_payload.to_string(),
        raw_sha256: hash,
        timestamp: Utc::now(),
        source: "127.0.0.1:514".to_string(),
    }
}

// ============================================================================
// 1. Known BPT structure + existing valid variant -> Fast Path, 0 SLM
// ============================================================================
#[tokio::test]
async fn test_1_known_structure_existing_variant_fast_path() {
    let (pipeline, _vault, _quar, slm_count) = setup_test_pipeline("test_1");

    let skeleton = "SRC=<VAR> DST=<VAR> DPT=<VAR> ACTION=<VAR>";
    let v1 = ParserVariant::new(
        "var_fw_v1",
        "Standard Firewall V1",
        r"^SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)\s+DPT=(?P<port>\d+)\s+ACTION=ALLOW$",
        HashMap::from([
            ("src".into(), "src_endpoint.ip".into()),
            ("dst".into(), "dst_endpoint.ip".into()),
            ("port".into(), "src_endpoint.port".into()),
        ]),
        HashMap::from([
            ("src".into(), "ip".into()),
            ("dst".into(), "ip".into()),
            ("port".into(), "port".into()),
        ]),
        TypeConstraint::IpAddress,
    ).unwrap();

    // Register on BDPT and Registry
    pipeline.registry.lock().unwrap().register_variant(skeleton, v1.clone());
    pipeline.bdpt.lock().unwrap().insert(skeleton, Some(v1));

    // Process event matching known structure
    let log = "SRC=192.168.1.100 DST=10.0.0.1 DPT=443 ACTION=ALLOW";
    let copy = create_test_copy(log);

    let res = pipeline.process_event(copy).await;
    assert!(res.is_ok(), "Event should be parsed successfully via fast path");
    let ocsf = res.unwrap();
    assert_eq!(ocsf.class_uid, 4001);
    assert_eq!(ocsf.src_endpoint.unwrap().ip.unwrap(), "192.168.1.100");

    // Zero SLM invocations!
    assert_eq!(*slm_count.lock().unwrap(), 0, "Fast path MUST NOT invoke SLM!");
}

// ============================================================================
// 2. Known structure + all existing variants fail (Variant Drift) -> AI Discovery -> SAME BPT Leaf
// ============================================================================
#[tokio::test]
async fn test_2_known_structure_variants_exhausted_links_same_bpt_leaf() {
    let (pipeline, _vault, _quar, slm_count) = setup_test_pipeline("test_2");

    let skeleton = "SRC=<VAR> DST=<VAR> DPT=<VAR> ACTION=<VAR>";

    // Existing variant 1 only matches ACTION=ALLOW
    let v1 = ParserVariant::new(
        "var_fw_allow",
        "Allow Variant",
        r"^SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)\s+DPT=(?P<port>\d+)\s+ACTION=ALLOW$",
        HashMap::from([("src".into(), "src_endpoint.ip".into()), ("dst".into(), "dst_endpoint.ip".into())]),
        HashMap::from([("src".into(), "ip".into()), ("dst".into(), "ip".into())]),
        TypeConstraint::IpAddress,
    ).unwrap();

    pipeline.registry.lock().unwrap().register_variant(skeleton, v1.clone());
    pipeline.bdpt.lock().unwrap().insert(skeleton, Some(v1));

    // New event arrives with ACTION=BLOCK (Variant Drift: same skeleton, but existing variants fail)
    let log = "SRC=192.168.1.100 DST=10.0.0.1 DPT=22 ACTION=BLOCK";
    let copy = create_test_copy(log);

    // AI Provider proposes new variant for ACTION=<VAR>
    let v2 = ParserVariant::new(
        "var_fw_generic_action",
        "Generic Action Variant",
        r"^SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)\s+DPT=(?P<port>\d+)\s+ACTION=(?P<act>\S+)$",
        HashMap::from([
            ("src".into(), "src_endpoint.ip".into()),
            ("dst".into(), "dst_endpoint.ip".into()),
            ("port".into(), "src_endpoint.port".into()),
            ("act".into(), "action".into()),
        ]),
        HashMap::from([
            ("src".into(), "ip".into()),
            ("dst".into(), "ip".into()),
            ("port".into(), "port".into()),
            ("act".into(), "string".into()),
        ]),
        TypeConstraint::IpAddress,
    ).unwrap();

    let ai_mock = Arc::new(MockAiDiscoveryProvider::new(slm_count.clone()));
    ai_mock.set_proposal(v2, 0.95);
    let mut pipeline_with_mock = pipeline;
    pipeline_with_mock.set_ai_provider(ai_mock);

    let res = pipeline_with_mock.process_event(copy).await;
    assert!(res.is_ok(), "Drifted event should be repaired and parsed");
    assert_eq!(*slm_count.lock().unwrap(), 1, "SLM should be invoked once on drift");

    // Verify the new variant was added to the SAME BPT leaf!
    let tree = pipeline_with_mock.bdpt.lock().unwrap();
    let preproc = pipeline_with_mock.preprocessor.process(log);
    let leaf = tree.match_tokens(&preproc.tokens).unwrap();
    assert_eq!(leaf.variants.len(), 2, "Both variants must coexist on the SAME BPT leaf!");
}

// ============================================================================
// 3. Completely new structure (Structural Drift) -> Registers new BPT leaf
// ============================================================================
#[tokio::test]
async fn test_3_completely_new_structure_registers_bpt_entry() {
    let (pipeline, _vault, _quar, slm_count) = setup_test_pipeline("test_3");

    // Fresh log format never seen before
    let new_log = "USER=admin SESS=9821 ACCESS=GRANTED HOST=dc01.corp";
    let copy = create_test_copy(new_log);

    let v_auth = ParserVariant::new(
        "var_auth_discovered",
        "Auth Session Discovered",
        r"^USER=(?P<usr>\S+)\s+SESS=(?P<sess>\d+)\s+ACCESS=(?P<act>\S+)\s+HOST=(?P<host>\S+)$",
        HashMap::from([
            ("usr".into(), "actor.user.name".into()),
            ("host".into(), "device.hostname".into()),
            ("act".into(), "action".into()),
        ]),
        HashMap::from([
            ("usr".into(), "string".into()),
            ("host".into(), "string".into()),
            ("act".into(), "string".into()),
        ]),
        TypeConstraint::GenericString,
    ).unwrap();

    let ai_mock = Arc::new(MockAiDiscoveryProvider::new(slm_count.clone()));
    ai_mock.set_proposal(v_auth, 0.93);
    let mut pipeline_with_mock = pipeline;
    pipeline_with_mock.set_ai_provider(ai_mock);

    let res = pipeline_with_mock.process_event(copy).await;
    assert!(res.is_ok(), "Completely new structure should be discovered and parsed");
    assert_eq!(*slm_count.lock().unwrap(), 1);

    // Verify it is now in the BPT
    let preproc = pipeline_with_mock.preprocessor.process(new_log);
    let tree = pipeline_with_mock.bdpt.lock().unwrap();
    assert!(tree.match_tokens(&preproc.tokens).is_some());
}

// ============================================================================
// 4. Future event using newly approved variant -> Fast Path, 0 SLM
// ============================================================================
#[tokio::test]
async fn test_4_future_event_uses_fast_path() {
    let (pipeline, _vault, _quar, slm_count) = setup_test_pipeline("test_4");

    let log1 = "USER=alice SESS=1111 ACCESS=GRANTED HOST=auth.corp";
    let v_auth = ParserVariant::new(
        "var_auth",
        "Auth Variant",
        r"^USER=(?P<usr>\S+)\s+SESS=(?P<sess>\d+)\s+ACCESS=(?P<act>\S+)\s+HOST=(?P<host>\S+)$",
        HashMap::from([("usr".into(), "actor.user.name".into()), ("host".into(), "device.hostname".into())]),
        HashMap::from([("usr".into(), "string".into()), ("host".into(), "string".into())]),
        TypeConstraint::GenericString,
    ).unwrap();

    let ai_mock = Arc::new(MockAiDiscoveryProvider::new(slm_count.clone()));
    ai_mock.set_proposal(v_auth, 0.95);
    let mut pipeline_with_mock = pipeline;
    pipeline_with_mock.set_ai_provider(ai_mock);

    // First event triggers discovery
    let _ = pipeline_with_mock.process_event(create_test_copy(log1)).await.unwrap();
    assert_eq!(*slm_count.lock().unwrap(), 1);

    // Subsequent event with different values but SAME structure
    let log2 = "USER=bob SESS=2222 ACCESS=GRANTED HOST=db.corp";
    let res2 = pipeline_with_mock.process_event(create_test_copy(log2)).await;
    assert!(res2.is_ok());

    // SLM count MUST still be 1 (0 additional SLM calls!)
    assert_eq!(*slm_count.lock().unwrap(), 1, "Subsequent event must use fast path with 0 SLM invocations!");
}

// ============================================================================
// 5. Multiple variants on one leaf -> More constrained variant is preferred
// ============================================================================
#[tokio::test]
async fn test_5_polymorphic_leaf_prefers_constrained_variant() {
    let (pipeline, _vault, _quar, _slm_count) = setup_test_pipeline("test_5");

    let skeleton = "CLIENT=<VAR> STATUS=<VAR>";

    // Generic string variant
    let v_generic = ParserVariant::new(
        "v_generic_client",
        "Generic Client",
        r"^CLIENT=(?P<client>\S+)\s+STATUS=OK$",
        HashMap::from([("client".into(), "actor.user.name".into())]),
        HashMap::from([("client".into(), "string".into())]),
        TypeConstraint::GenericString,
    ).unwrap();

    // Specific IP variant (higher constraint!)
    let v_ip = ParserVariant::new(
        "v_ip_client",
        "IP Client",
        r"^CLIENT=(?P<client>\d+\.\d+\.\d+\.\d+)\s+STATUS=OK$",
        HashMap::from([("client".into(), "src_endpoint.ip".into())]),
        HashMap::from([("client".into(), "ip".into())]),
        TypeConstraint::IpAddress,
    ).unwrap();

    // Register generic first, then IP
    pipeline.registry.lock().unwrap().register_variant(skeleton, v_generic.clone());
    pipeline.registry.lock().unwrap().register_variant(skeleton, v_ip.clone());

    let mut tree = pipeline.bdpt.lock().unwrap();
    let leaf = tree.insert(skeleton, Some(v_generic));
    leaf.add_or_update_variant(v_ip);
    drop(tree);

    // Log with IP address
    let log_ip = "CLIENT=10.20.30.40 STATUS=OK";
    let res = pipeline.process_event(create_test_copy(log_ip)).await.unwrap();

    // Must be parsed into src_endpoint.ip, NOT shadowed by generic actor.user.name!
    assert!(res.src_endpoint.is_some());
    assert_eq!(res.src_endpoint.unwrap().ip.unwrap(), "10.20.30.40");
}

// ============================================================================
// 6. No Cartesian-product generation -> Complete variants from Registry
// ============================================================================
#[tokio::test]
async fn test_6_no_cartesian_product_enumeration() {
    let (pipeline, _vault, _quar, _slm_count) = setup_test_pipeline("test_6");

    let skeleton = "VAR1=<VAR> VAR2=<VAR> VAR3=<VAR>";
    let v = ParserVariant::new(
        "complete_spec",
        "Complete Spec",
        r"^VAR1=(?P<v1>\S+)\s+VAR2=(?P<v2>\S+)\s+VAR3=(?P<v3>\S+)$",
        HashMap::from([
            ("v1".into(), "actor.user.name".into()),
            ("v2".into(), "action".into()),
            ("v3".into(), "message".into()),
        ]),
        HashMap::from([("v1".into(), "string".into()), ("v2".into(), "string".into()), ("v3".into(), "string".into())]),
        TypeConstraint::GenericString,
    ).unwrap();

    pipeline.registry.lock().unwrap().register_variant(skeleton, v.clone());
    pipeline.bdpt.lock().unwrap().insert(skeleton, Some(v));

    let reg = pipeline.registry.lock().unwrap();
    let variants = reg.get_variants_for_skeleton(skeleton);
    assert_eq!(variants.len(), 1, "Variants are complete specifications, NOT combinatorial permutations!");
}

// ============================================================================
// 7. Invalid IP -> Event Quarantine
// ============================================================================
#[tokio::test]
async fn test_7_invalid_ip_routes_to_event_quarantine() {
    let (pipeline, _vault, quar, _slm_count) = setup_test_pipeline("test_7");

    let skeleton = "SRC=<VAR> DST=<VAR>";
    let v = ParserVariant::new(
        "var_ip_test",
        "IP Test",
        r"^SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)$",
        HashMap::from([("src".into(), "src_endpoint.ip".into())]),
        HashMap::from([("src".into(), "ip".into())]),
        TypeConstraint::IpAddress,
    ).unwrap();

    pipeline.registry.lock().unwrap().register_variant(skeleton, v.clone());
    pipeline.bdpt.lock().unwrap().insert(skeleton, Some(v));

    // Invalid IP value: 999.999.999.999
    let bad_log = "SRC=999.999.999.999 DST=10.0.0.1";
    let res = pipeline.process_event(create_test_copy(bad_log)).await;

    assert!(res.is_err(), "Invalid IP must be rejected");
    let quar_entry = res.unwrap_err();
    assert_eq!(quar_entry.failed_check, "pipeline.runtime_invariant_failed");
    assert_eq!(quar.event_quarantine_count(), 1);
}

// ============================================================================
// 8. Invalid Port -> Event Quarantine
// ============================================================================
#[tokio::test]
async fn test_8_invalid_port_routes_to_event_quarantine() {
    let (pipeline, _vault, quar, _slm_count) = setup_test_pipeline("test_8");

    let skeleton = "HOST=<VAR> PORT=<VAR>";
    let v = ParserVariant::new(
        "var_port_test",
        "Port Test",
        r"^HOST=(?P<host>\S+)\s+PORT=(?P<port>\d+)$",
        HashMap::from([("port".into(), "src_endpoint.port".into())]),
        HashMap::from([("port".into(), "port".into())]),
        TypeConstraint::Integer,
    ).unwrap();

    pipeline.registry.lock().unwrap().register_variant(skeleton, v.clone());
    pipeline.bdpt.lock().unwrap().insert(skeleton, Some(v));

    // Port 99999 > 65535
    let bad_port_log = "HOST=web.local PORT=99999";
    let res = pipeline.process_event(create_test_copy(bad_port_log)).await;

    assert!(res.is_err());
    assert_eq!(quar.event_quarantine_count(), 1);
}

// ============================================================================
// 9. Malformed Event / Oversized -> Receiver Bounding
// ============================================================================
#[test]
fn test_9_malformed_and_oversized_events_rejected() {
    let temp_dir = std::env::temp_dir().join(format!("test_9_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
    let vault = Arc::new(EvidenceVault::new(&temp_dir).unwrap());
    let receiver = IngestionReceiver::new(vault);

    // Empty event rejected
    assert!(receiver.ingest("   ", "127.0.0.1").is_err());

    // Event > 64 KB rejected
    let oversized = "X".repeat(MAX_PAYLOAD_BYTES + 10);
    assert!(receiver.ingest(&oversized, "127.0.0.1").is_err());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ============================================================================
// 10. Unsafe Parser Specification (ReDoS) -> Parser Quarantine
// ============================================================================
#[tokio::test]
async fn test_10_unsafe_parser_spec_routes_to_parser_quarantine() {
    let (pipeline, _vault, quar, slm_count) = setup_test_pipeline("test_10");

    let log = "ANOMALY PAYLOAD 12345";
    let copy = create_test_copy(log);

    // SLM proposes an unsafe ReDoS regex: (a+)+
    let dangerous_variant = ParserVariant::new(
        "var_dangerous_redos",
        "Dangerous ReDoS Variant",
        r"^ANOMALY\s+(?P<tok>([a-z]+)+)\s+\d+$",
        HashMap::from([("tok".into(), "message".into())]),
        HashMap::from([("tok".into(), "string".into())]),
        TypeConstraint::GenericString,
    ).unwrap();

    let ai_mock = Arc::new(MockAiDiscoveryProvider::new(slm_count.clone()));
    ai_mock.set_proposal(dangerous_variant, 0.95);
    let mut pipeline_with_mock = pipeline;
    pipeline_with_mock.set_ai_provider(ai_mock);

    let res = pipeline_with_mock.process_event(copy).await;
    assert!(res.is_err());

    // Parser spec MUST be routed to Parser Quarantine!
    assert_eq!(quar.parser_quarantine_count(), 1, "Unsafe spec must be in Parser Quarantine!");
    assert_eq!(quar.event_quarantine_count(), 1, "Unparsed event must be in Event Quarantine!");
}

// ============================================================================
// 11. Raw Bytes Preserved Exactly in Evidence Vault
// ============================================================================
#[test]
fn test_11_raw_bytes_preserved_exactly() {
    let temp_dir = std::env::temp_dir().join(format!("test_11_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
    let vault = Arc::new(EvidenceVault::new(&temp_dir).unwrap());
    let receiver = IngestionReceiver::new(vault.clone());

    let raw = "exact raw bytes: \t\r\n <payload> with special chars & * %";
    let copy = receiver.ingest(raw, "10.0.0.5:514").unwrap();

    assert_eq!(copy.unmasked_payload, raw);
    assert!(vault.verify_integrity(&copy.raw_sha256));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ============================================================================
// 12. SHA-256 Integrity Verification
// ============================================================================
#[test]
fn test_12_sha256_integrity_verification() {
    let raw = "verification payload 123";
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let expected = hex::encode(hasher.finalize());

    let copy = create_test_copy(raw);
    assert_eq!(copy.raw_sha256, expected);
}

// ============================================================================
// 13. PII Masking Occurs Only After Extraction
// ============================================================================
#[tokio::test]
async fn test_13_pii_masking_only_after_extraction() {
    let (pipeline, _vault, _quar, _slm_count) = setup_test_pipeline("test_13");

    let skeleton = "LOGIN USER=<VAR> HOST=<VAR>";
    let v = ParserVariant::new(
        "var_login",
        "Login Variant",
        r"^LOGIN\s+USER=(?P<user>\S+)\s+HOST=(?P<host>\S+)$",
        HashMap::from([
            ("user".into(), "actor.user.name".into()),
            ("host".into(), "device.hostname".into()),
        ]),
        HashMap::from([("user".into(), "string".into()), ("host".into(), "string".into())]),
        TypeConstraint::GenericString,
    ).unwrap();

    pipeline.registry.lock().unwrap().register_variant(skeleton, v.clone());
    pipeline.bdpt.lock().unwrap().insert(skeleton, Some(v));

    let raw_log = "LOGIN USER=super_secret_admin HOST=srv01.corp";
    let copy = create_test_copy(raw_log);

    // Processing copy is completely unmasked beforehand
    assert_eq!(copy.unmasked_payload, raw_log);

    let res = pipeline.process_event(copy).await.unwrap();

    // After extraction and validation, sensitive user field is masked to [REDACTED]
    assert_eq!(res.actor.unwrap().user_name.unwrap(), "[REDACTED]");
    // Non-sensitive hostname is preserved
    assert_eq!(res.device.unwrap().hostname.unwrap(), "srv01.corp");
}

// ============================================================================
// 14. Merkle Proof Generation and Verification
// ============================================================================
#[test]
fn test_14_merkle_proof_generation_and_verification() {
    let mut leaves = Vec::new();
    for i in 0..16 {
        leaves.push(hex::encode(Sha256::digest(format!("event_{}", i).as_bytes())));
    }

    let proof = MerkleTree::generate_proof(&leaves, 5).unwrap();
    assert!(MerkleTree::verify_proof(&proof));
}

// ============================================================================
// 15. Merkle Tamper Detection
// ============================================================================
#[test]
fn test_15_merkle_tamper_detection() {
    let mut leaves = Vec::new();
    for i in 0..16 {
        leaves.push(hex::encode(Sha256::digest(format!("event_{}", i).as_bytes())));
    }

    let proof = MerkleTree::generate_proof(&leaves, 5).unwrap();

    // Tamper with root
    let mut tampered = proof.clone();
    tampered.root_hash = hex::encode(Sha256::digest(b"fake_root"));
    assert!(!MerkleTree::verify_proof(&tampered), "Tampered root must fail verification!");

    // Tamper with audit path
    let mut tampered_path = proof.clone();
    tampered_path.audit_path[0].0 = hex::encode(Sha256::digest(b"fake_sibling"));
    assert!(!MerkleTree::verify_proof(&tampered_path), "Tampered audit sibling must fail verification!");
}

// ============================================================================
// 16. Parser Rollback Restores Previous Version
// ============================================================================
#[test]
fn test_16_parser_rollback_restores_previous_version() {
    let mut registry = ParserRegistry::new();
    let skel = "ALERT ID=<VAR>";

    let v1 = ParserVariant::new(
        "var_alert",
        "Alert V1",
        r"^ALERT\s+ID=(?P<id>\d+)$",
        HashMap::from([("id".into(), "message".into())]),
        HashMap::from([("id".into(), "string".into())]),
        TypeConstraint::Integer,
    ).unwrap();

    registry.register_variant(skel, v1);
    assert_eq!(registry.get_variant("var_alert").unwrap().version, 1);

    // Roll out v2
    let mut v2 = registry.get_variant("var_alert").unwrap().clone();
    v2.name = "Alert V2 Broken".to_string();
    registry.register_variant(skel, v2);
    assert_eq!(registry.get_variant("var_alert").unwrap().version, 2);

    // Roll back to v1
    assert!(registry.rollback_variant("var_alert"));
    let restored = registry.get_variant("var_alert").unwrap();
    assert_eq!(restored.version, 1);
    assert_eq!(restored.name, "Alert V1");
}
