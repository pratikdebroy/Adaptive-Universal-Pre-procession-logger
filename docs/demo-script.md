# 9-Step Live Judge Demonstration Script

**Project**: Universal Log Pre-processing Framework (SIH26156)  
**Evaluator Target**: Technical Judges at Smart India Hackathon 2026  
**Duration**: ~2 to 3 minutes  

---

### Step 1: Baseline Known Perimeter Traffic
- **Action**: Click `[STEP 1. KNOWN FORMAT]` on `/demo` (or click `[LOAD KNOWN FIREWALL LOG]` on `/`).
- **Input**:
  ```
  SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW
  ```
- **Observed Behavior**:
  - **Path**: `FAST_PATH`
  - **Latency**: Sub-millisecond parsing (< 1.5ms)
  - **Parser**: `firewall_v1`
  - **AI / Tier-3 Invocations**: `0`
  - **OCSF Output**: Class `4001` (Network Activity), `activity_id: 6`, `action_id: 1` (`Allowed`).
- **Key Talking Point**:
  > *"When format is known, execution stays on the deterministic fast path. No AI latency, no GPU cost."*

---

### Step 2: Unannounced Vendor Format Drift
- **Action**: Click `[STEP 2. INTRODUCE DRIFT]` on `/demo`.
- **Input**:
  ```
  SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW
  ```
- **Observed Behavior**:
  - **Path**: `FAST PATH MISS`
  - **Reason**: Format signature mismatch (`SRC_IP|DST_IP|...` vs `SRC|DST|...`).
- **Key Talking Point**:
  > *"The old parser fails to match with sufficient confidence. Rather than dropping the event or corrupting analytics, the pipeline initiates escalation."*

---

### Step 3: Tier-2 Structural Analysis & Tier-3 Escalation
- **Action**: Click `[STEP 3. ADAPT]` on `/demo`.
- **Observed Behavior**:
  - **Tier-1 (Drain Miner)**: Detects novel token structure.
  - **Tier-2 (Structural Tokenizer)**: Identifies key-value structure, types IPv4 addresses and port numbers.
  - **Tier-3 (Inference + RAG)**: Local RAG retrieves top-3 historical templates; inference provider proposes candidate OCSF mappings (`SRC_IP` → `source.ip`, `ACT` → `action`).
- **Key Talking Point**:
  > *"AI is invoked selectively—only when Tier 1 & Tier 2 cannot resolve the syntax."*

---

### Step 4: Generation of Declarative Parser Specification
- **Action**: Click `[STEP 4. CANDIDATE PARSER]` on `/demo`.
- **Observed Behavior**:
  - Displays generated JSON specification:
    ```json
    {
      "template": "SRC_IP=<*> DST_IP=<*> PROTO=<*> PORT=<*> ACT=<*>",
      "fields": {
        "SRC_IP": "source.ip",
        "DST_IP": "destination.ip",
        "PROTO": "network.transport",
        "PORT": "destination.port",
        "ACT": "action"
      }
    }
    ```
- **Key Talking Point**:
  > *"Security Critical: The AI model NEVER generates executable Python or regex bytecode. It only proposes declarative schema mappings."*

---

### Step 5: Hybrid Trust Gate Validation
- **Action**: Click `[STEP 5. TRUST GATE]` on `/demo`.
- **Observed Behavior**:
  - **Parser Safety**: Verifies no code injection patterns (`eval`, `import`), all target fields allowlisted.
  - **Event Trust Gate**: Tests sample outputs against RFC IP checks, port bounds ($0-65535$), and protocol allowlists.
  - **Status**: `APPROVED`.
- **Key Talking Point**:
  > *"AI proposes, but the symbolic Trust Gate decides. Hallucinations or malformed fields are quarantined immediately."*

---

### Step 6: Atomic Promotion to Registry
- **Action**: Click `[STEP 6. PARSER PROMOTION]` on `/demo`.
- **Observed Behavior**:
  - Parser record `adaptive_firewall_v2` is committed to SQLite.
  - In-memory cache swap promotes candidate to `ACTIVE`.
- **Key Talking Point**:
  > *"The learned grammar is saved to persistent registry and synchronized into RAM without downtime."*

---

### Step 7: Proof of Self-Healing (Replay on Fast Path)
- **Action**: Click `[STEP 7. REPLAY (FAST PATH)]` on `/demo`.
- **Input**:
  ```
  SRC_IP=192.168.1.100 DST_IP=10.0.0.1 PROTO=UDP PORT=53 ACT=ALLOW
  ```
- **Observed Behavior**:
  - **Path**: `FAST_PATH`!
  - **Active Parser**: `adaptive_firewall_v2`
  - **Tier-3 Invocations**: `0`!
- **Key Talking Point**:
  > *"This is the self-healing breakthrough: Once learned, subsequent logs return immediately to the deterministic fast path. The system continually optimizes itself."*

---

### Step 8: Forensic Traceability Audit
- **Action**: Click `[STEP 8. SHOW PROVENANCE]` on `/demo` (or inspect `/integrity`).
- **Observed Behavior**:
  - Shows end-to-end chain:
    `RAW LOG` → `SHA-256` → `PARSER VERSION (v2)` → `NORMALIZED OCSF`.
- **Key Talking Point**:
  > *"Raw evidence is preserved losslessly in the vault before parsing. Downstream investigations can verify cryptographic provenance at any time."*

---

### Step 9: Tamper Evident Verification & Ledger
- **Action**: Click `[STEP 9. TEST TAMPER]` on `/demo`.
- **Observed Behavior**:
  - Deliberately modifies a stored raw event in the Evidence Vault.
  - Recomputes Merkle tree across raw hashes.
  - **Result**: `INTEGRITY FAILURE: MERKLE ROOT MISMATCH`.
- **Key Talking Point**:
  > *"Cryptographic hashes and Merkle roots make tampering instantly detectable. The append-only ledger anchors the proof."*
