# AegisLog: Production-Oriented Architectural Prototype
### Autonomous, Self-Healing, High-Throughput OCSF Log Pipeline
**Theme**: Cybersecurity Schema Normalization & Cryptographic Provenance  
**Specification Standard**: OCSF v1.1.0 (Class 4001: Network Activity, Class 3001: Account Change, Authentication)  
**Core Motto**: *Deterministic when known · Adaptive on drift · Verified before trust · Learned parsers return to the fast path.*

---

## 1. Architectural Overview

AegisLog is a high-throughput, horizontally scalable, production-oriented prototype designed to ingest, normalize, and safeguard heterogeneous, drifting security telemetry without data loss or unvalidated bypasses.

```
RAW LOG INFLUX (Syslog UDP: 5140 / HTTP: 8080)
       │
       ▼
LAYER 1: LOSSLESS EVIDENCE VAULT (Verbatim Raw + SHA-256 Digest in Append-Only Journal)
       │
       ▼
LAYER 2: DEFENSIVE INGESTION BOUNDING (Max 64KB Payload Limit, Unmasked Processing Copy)
       │
       ▼
LAYER 3: STRUCTURAL PREPROCESSOR (Tokenizes Skeleton & Retains All Captured Variable Values)
       │
       ▼
BIDIRECTIONAL PATTERN TREE (BDPT Head-and-Tail Inward Match)
       ├── [Matched Leaf Node] ───────────────────────────────────────────┐
       │     │                                                            │
       │     ▼                                                            │
       │   SEQUENTIAL LEAF VARIANT TRIAL (Highest Type Constraint First) │
       │     • IPv4/IPv6 > Hex/MAC > Integer > GenericString              │
       │     • Match count as secondary tie-breaker                       │
       │     │                                                            │
       │     ├── [Variant Passes Validation]                              │
       │     │     │                                                      │
       │     │     ▼                                                      │
       │     │   DETERMINISTIC FAST PATH (Sub-millisecond, 0 AI Calls) ◄─┘
       │     │     │
       │     └── [All Variants Exhausted (Variant Drift)] ──┐
       │                                                    │
       └── [No Structural Match (Structural Drift)] ────────┤
                                                            │
                                                            ▼
                                           AI-ASSISTED PARSER DISCOVERY
                                             • Deduplication / Rate Limiter
                                             • RAG: Historical Validated Context
                                             • Local SLM (Ollama JSON Schema)
                                                            │
                                                            ▼
                                           UNIFIED TRUST GATE VALIDATION
                                             1. AST ReDoS Analysis (regex-syntax)
                                             2. OCSF Mapping Allowlist
                                             3. Target Schema Plausibility
                                             4. Confidence / Evidence Threshold
                                                            │
                     ┌──────────────────────────────────────┴──────────────────────────────────────┐
                     │                                                                            │
             [PASS (Approved)]                                                            [FAIL (Rejected)]
                     │                                                                            │
                     ▼                                                                            ▼
          AUTHORITATIVE PARSER REGISTRY                                                   PARSER QUARANTINE
          • Versioning & Rollback                                                         (Unsafe Regex AST /
          • Associated with SAME BPT Leaf                                                  Schema Violations)
                     │
                     ▼
          FIELD & DOMAIN RUNTIME VALIDATION (RFC IP, Port 0-65535, Timestamp)
                     │
                     ├── [Invalid Value] ─────────────────────────────────────────────────────────► EVENT QUARANTINE
                     │                                                                            (Corrupt / Malformed Logs)
                     ▼
          POST-EXTRACTION PII MASKING (Zero-Allocation In-Place Cow<str>)
                     │
                     ▼
          OCSF v1.1.0 NORMALIZATION (Class 4001 Network / Class 3001 Auth)
          (With Cryptographic Pointer: unmapped.raw_event_hash -> Evidence Vault)
                     │
                     ▼
          LAYER 4: CRYPTOGRAPHIC MERKLE PROVENANCE (Micro-Batches of 500 Events)
          (Root Hashes Anchored to Local Append-Only Provenance Ledger Adapter)
                     │
                     ▼
          BROKER TOPIC: parsed-logs
                     │
                     ▼
LAYER 5: REAL-TIME WEBSOCKET GATEWAY (:4000) & SOC DASHBOARD (:3000)
```

---

## 2. Key Architectural Guarantees

1. **Zero Unvalidated Fallback Bypass**: Drifted or unrecognized events never bypass validation into `parsed-logs`. If no valid parser variant exists and AI discovery fails or is rejected, the event is safely held in **Event Quarantine**.
2. **RAG & Local SLM Boundary**:
   - **Known Structure + Validated Variant**: Fast path. Variants tested sequentially. **Zero RAG, Zero SLM calls**.
   - **Known Structure + Variants Exhausted (Variant Drift)**: AI discovers new variant $\to$ Trust Gate validates $\to$ Registry links to the **SAME BPT leaf**.
   - **New Structure (Structural Drift)**: AI discovers new spec $\to$ Trust Gate validates $\to$ Registry creates a new structural entry in BDPT.
3. **Variable Preservation**: Preprocessor extracts static skeletons (e.g. `<VAR> <VAR> logins from device <VAR>`) while losslessly preserving all variable bindings (e.g. `[VAR1="john", VAR2="Tuesday", VAR3="6799"]`).
4. **No Cartesian-Product Permutations**: Leaf variants are complete, self-contained specifications evaluated in strict priority order (most constrained types first).
5. **Dual Quarantine Segregation**:
   - `event_quarantine`: Malformed payloads, invalid IP addresses, out-of-range ports, or unparseable event data.
   - `parser_quarantine`: Candidate parser specs that fail AST safety (ReDoS), invalid field mappings, or low confidence.
6. **PII Masking Order**: Applied in-place (`Cow<str>`) strictly **after** field extraction and domain validation. The raw payload in the Evidence Vault remains bit-for-bit verbatim and untouched.

---

## 3. Workspace Structure

```
SIH Logger/
├── Cargo.toml                    # Root Rust Workspace (edition 2021)
├── crates/
│   ├── engine/                   # Core pipeline, BDPT, Registry, Trust Gate, OCSF, Merkle, Quarantine
│   │   ├── src/
│   │   │   ├── bdpt.rs           # Bidirectional Pattern Tree (inward token matching)
│   │   │   ├── registry.rs       # Authoritative Parser Registry (versioning & rollback)
│   │   │   ├── trust_gate.rs     # AST ReDoS checking & runtime domain validation
│   │   │   ├── ocsf.rs           # OCSF v1.1.0 normalizer with cryptographic vault pointer
│   │   │   ├── merkle.rs         # Micro-batch Merkle Tree & local provenance ledger adapter
│   │   │   ├── quarantine.rs     # Dual quarantine database manager (SQLite)
│   │   │   ├── preprocessor.rs   # Skeletons + captured variable preservation
│   │   │   ├── pipeline.rs       # AegisPipeline orchestrator
│   │   │   └── models.rs         # Strongly typed data models
│   │   └── tests/
│   │       └── pipeline_tests.rs # 16-point comprehensive test suite
│   ├── ingestion/                # Lossless Evidence Vault & Syslog Ingestion Receiver
│   ├── ai_worker/                # RAG retrieval context, Ollama client, circuit breaker, dedup
│   └── server/                   # Standalone daemon, HTTP REST API (:8080), Syslog UDP (:5140)
├── services/
│   └── gateway/                  # Express & WebSocket Gateway (:4000)
├── ui/                           # Next.js 14 / Tailwind SOC Dashboard (:3000)
└── docker-compose.yml            # Multi-service container orchestration
```

---

## 4. Verification & Test Suite

All workspace components are validated with comprehensive automated test suites:

### A. Rust Engine & Ingestion Suite (25/25 Tests Passing)
```bash
cargo test --workspace
```
Covers:
1. `test_1_known_structure_existing_variant_fast_path`: Deterministic fast path (SLM invocations = 0).
2. `test_2_known_structure_variants_exhausted_links_same_bpt_leaf`: Variant drift repairs linked to same BPT leaf.
3. `test_3_completely_new_structure_registers_bpt_entry`: Structural drift registers new BDPT node.
4. `test_4_future_event_uses_fast_path`: Subsequent drifted events execute on fast path with 0 additional SLM calls.
5. `test_5_polymorphic_leaf_prefers_constrained_variant`: Priority trial selects constrained IP over generic string.
6. `test_6_no_cartesian_product_enumeration`: Complete parser specifications without combinatorial explosion.
7. `test_7_invalid_ip_routes_to_event_quarantine`: RFC IP violation safely quarantined in `event_quarantine`.
8. `test_8_invalid_port_routes_to_event_quarantine`: Out-of-range port quarantined in `event_quarantine`.
9. `test_9_malformed_and_oversized_events_rejected`: Payloads $> 64\text{KB}$ bounded and rejected at ingestion.
10. `test_10_unsafe_parser_spec_routes_to_parser_quarantine`: ReDoS pattern `(a+)+` rejected by AST checker into `parser_quarantine`.
11. `test_11_raw_bytes_preserved_exactly`: Verbatim bit-for-bit raw storage in Evidence Vault.
12. `test_12_sha256_integrity_verification`: Cryptographic hash verification.
13. `test_13_pii_masking_only_after_extraction`: PII redacted in-place without altering raw evidence.
14. `test_14_merkle_proof_generation_and_verification`: Micro-batch Merkle audit path generation and validation.
15. `test_15_merkle_tamper_detection`: Tampered leaf hashes immediately fail cryptographic verification.
16. `test_16_parser_rollback_restores_previous_version`: Versioned rollback restores known-good active parser.

### B. Gateway Test Suite (Passing)
```bash
cd services/gateway
npm test
```

### C. UI Production Build (Passing)
```bash
cd ui
npm run build
```

---

## 5. Quick Start (Running the System)

### Option 1: Docker Compose (Full Stack)
```bash
docker compose up --build
```
- **Next.js SOC Dashboard**: `http://localhost:3000`
- **Real-Time Gateway**: `http://localhost:4000` (WebSocket: `ws://localhost:4000`)
- **AegisLog Core Engine**: `http://localhost:8080` (Syslog UDP: `localhost:5140`)
- **Redpanda / Kafka**: `localhost:9092`
- **Ollama SLM**: `http://localhost:11434`

### Option 2: Native Local Execution

#### Terminal 1: AegisLog Engine
```bash
cargo run -p aegislog-server
```

#### Terminal 2: Gateway Server
```bash
cd services/gateway
npm start
```

#### Terminal 3: SOC Dashboard UI
```bash
cd ui
npm run dev
```
Open `http://localhost:3000` to monitor live log normalization, BDPT trees, dual quarantine states, and Merkle audit proofs.
