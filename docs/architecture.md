# Architecture Specification: Universal Log Pre-processing Framework (SIH26156)

**Organization**: National Technical Research Organisation (NTRO)  
**Theme**: Blockchain & Cybersecurity  
**System Classification**: Prototype Proof-of-Concept  

---

## 1. Core Engineering Principle

```
DETERMINISTIC WHEN KNOWN.
ADAPTIVE WHEN UNKNOWN.
VERIFIED BEFORE TRUST.
LEARNED PARSERS RETURN TO THE FAST PATH.
RAW EVIDENCE REMAINS TRACEABLE.

AI PROPOSES. TRUST GATE DECIDES. LEDGER PROVES.
```

---

## 2. End-to-End Ingestion & Adaptation Topology

```
             ┌─────────────────────────────┐
             │ Perimeter Raw Event Influx  │
             │   (Syslog, Firewalls, WAF)  │
             └──────────────┬──────────────┘
                            │
                            ▼
             ┌─────────────────────────────┐
             │    Raw Evidence Vault       │ <--- LOSSLESS PRESERVATION:
             │  Exact Message + SHA-256    │      Stored prior to any sanitization
             └──────────────┬──────────────┘
                            │
                            ▼
             ┌─────────────────────────────┐
             │    Sanitization Layer       │ <--- Separate Processing Copy Only:
             │  (Strip null/control chars) │      Raw evidence is never modified
             └──────────────┬──────────────┘
                            │
                            ▼
             ┌─────────────────────────────┐
             │   Defensive Ingestion Gate  │ <--- Size limits (64KB), rate-limiting,
             │   (Injection/Payload Scan)  │      SQL/Script pattern rejection
             └──────────────┬──────────────┘
                            │
                            ▼
                     Format Router
                   (Format Signature)
                     /             \
       Known Signature?             Unseen / Format Drift
          /                             \
         ▼                               ▼
 ┌───────────────┐           ┌────────────────────────────────┐
 │   FAST PATH   │           │         ADAPTIVE PATH          │
 │ Deterministic │           ├────────────────────────────────┤
 │ Regex / Rules │           │ Tier 1: Drain-style Miner      │
 │ In-Memory     │           │ Tier 2: Structural Analyzer    │
 │ Cache         │           │ Tier 3: Local SLM + RAG        │
 └───────┬───────┘           └───────────────┬────────────────┘
         │                                   │ Candidate Parser Spec
         │                                   ▼
         │                   ┌────────────────────────────────┐
         │                   │    Parser Safety Validation    │
         │                   │  (No code, allowlisted schema) │
         │                   └───────────────┬────────────────┘
         │                                   │ Safe Spec
         │                                   ▼
         │                   ┌────────────────────────────────┐
         │                   │    Sample Event Execution      │
         │                   └───────────────┬────────────────┘
         │                                   │
         └─────────────────┬─────────────────┘
                           │
                           ▼
             ┌─────────────────────────────┐
             │      HYBRID TRUST GATE      │
             │  1. Schema required fields  │
             │  2. Data type conformity    │
             │  3. RFC IP address validity │
             │  4. Port range (0 - 65535)  │
             │  5. Protocol allowlist      │
             │  6. Timestamp plausibility  │
             │  7. Action semantics        │
             │  8. Minimum confidence      │
             └──────────────┬──────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
          APPROVED                   REJECTED
              │                           │
              ▼                           ▼
 ┌─────────────────────────┐  ┌────────────────────────┐
 │   OCSF Normalization    │  │    QUARANTINE / DLQ    │
 │ (Class 4001: Net Flow)  │  │ Isolation & Review     │
 └────────────┬────────────┘  └────────────────────────┘
              │
              ▼
 ┌─────────────────────────┐
 │     Parser Registry     │
 │ Transactional SQLite    │
 │ + Atomic Cache Swap     │
 └────────────┬────────────┘
              │
              ▼
 ┌─────────────────────────┐
 │ Cryptographic Provenance│
 │ SHA-256 + Merkle Tree   │
 │ Append-Only Ledger      │
 └─────────────────────────┘
```

---

## 3. Component Details & Design Contracts

### 3.1 Lossless Raw Evidence Vault (`backend.storage.evidence_vault`)
- **Preservation Contract**: The original bytes are stored verbatim into `data/evidence/<event_id>.json` before any stripping, decoding, or regex is applied.
- **Cryptographic Footprint**: SHA-256 is computed directly on raw UTF-8 / surrogate-escaped bytes.
- **Processing Copy**: A separate downstream instance `ProcessingCopy` is spawned for cleaning and tokenization.

### 3.2 Fast-Path Engine (`backend.parsers.fast_path`)
- **Execution Mechanism**: Executes validated JSON specifications—never arbitrary code.
- **Throughput Profile**: Evaluates in sub-millisecond range using in-memory dictionary and pre-compiled regex structures.

### 3.3 Three-Tier Adaptive Engine (`backend.adaptive.*`)
- **Tier 1 (Drain Miner)**: Mines template patterns using prefix trees and similarity threshold $st = 0.5$. Wildcards `<*>` do not count towards similarity, preventing template collapse.
- **Tier 2 (Structural Analysis)**: Evaluates structural tokens (`KEY=VALUE`), identifies semantic types (IPv4, Port, Protocol, Action, Timestamp), and computes structural confidence.
- **Tier 3 (Local SLM + RAG)**:
  - **RAG**: Offline TF-IDF index retrieves top-3 historically validated templates.
  - **Inference**: Pluggable provider (`OllamaProvider` when active; `DemoFallbackProvider` when offline).
  - **Safety Guarantee**: The AI model emits purely structured JSON parser specifications—never Python scripts, preventing prompt injection execution risks.

### 3.4 Hybrid Trust Gate (`backend.validation.trust_gate`)
- **Layer A (Parser Safety Validation)**: Rejects forbidden keywords (`import`, `eval`, `exec`, `__`), validates separators, and enforces target field allowlists.
- **Layer B (Event Trust Validation)**: Enforces network domain invariants (e.g., $0 \le \text{port} \le 65535$, valid IPv4 octets, known IANA protocols).

### 3.5 Parser Registry (`backend.registry.parser_registry`)
- **Persistence Guarantee**: SQLite database transaction commits version increment and spec archive.
- **Cache Promotion**: Upon successful commit, an atomic in-memory cache swap occurs under `threading.Lock`. If cache synchronization fails, state is re-hydrated from disk.

### 3.6 Merkle Tree & Ledger (`backend.integrity.*`)
- **Merkle Roots**: Computed recursively over batches of SHA-256 event hashes.
- **Ledger**: Prototype Permissioned-Ledger Adapter recording `(batch_id, merkle_root, timestamp, previous_root)`. Any tampering with the raw evidence vault breaks root equality upon re-verification.
