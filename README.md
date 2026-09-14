# Universal Log Pre-processing Framework
### SIH26156 — Smart India Hackathon 2026 Prototype
**Organization**: National Technical Research Organisation (NTRO)  
**Theme**: Blockchain & Cybersecurity  
**Core Principle**: *Deterministic when known · Adaptive when unknown · Verified before trust · Learned parsers return to fast path.*

---

## 1. Executive Summary

Perimeter cybersecurity infrastructure generates heterogeneous, drifting, and unannounced log formats from distributed firewalls, routers, WAFs, and intrusion detection systems. Traditional SIEMs suffer from high ingestion failure rates, rigid brittle parsers, and excessive computational overhead when attempting to use LLMs across full traffic streams.

This prototype demonstrates an operational **Universal Log Pre-processing Framework**:
1. **Lossless Evidence Preservation**: Raw logs are stored verbatim with SHA-256 hashes prior to sanitization.
2. **Deterministic Fast-Path**: Known formats parse in sub-millisecond execution loops using in-memory declarative rules without AI invocation.
3. **Three-Tier Adaptive Engine**: Unannounced format drifts escalate gracefully through (1) Drain-style template mining → (2) Structural token classification → (3) Offline RAG + Local SLM / Demo Fallback.
4. **Declarative Parser Specifications**: AI models synthesize strictly structured JSON parser specifications—**never executable code**.
5. **Hybrid Trust Gate**: Invariant validation (RFC IP checks, port bounds $0-65535$, protocol allowlists, action semantics) validates candidate outputs before approval.
6. **Self-Healing Registry**: Validated candidate parsers are atomically promoted into SQLite and the active in-memory cache. Subsequent logs of the new format immediately use the **FAST PATH** with **ZERO AI invocation**.
7. **Tamper-Evident Integrity**: SHA-256 Merkle trees anchored into an append-only ledger adapter prove evidence authenticity.

---

## 2. Architecture & Pipeline Flow

```
RAW LOG INFLUX
      │
      ▼
EVIDENCE VAULT (Verbatim Raw + SHA-256)
      │
      ▼
SANITIZATION & DEFENSIVE GATE (Separate Processing Copy)
      │
      ▼
FORMAT ROUTER (Signature Match)
      ├── [Known Match] ──────────► FAST PATH (< 1ms, 0 AI)
      │                                    │
      └── [Format Drift / Unknown]         │
              │                            │
              ▼                            │
      ADAPTIVE ENGINE                      │
        • Tier 1: Drain-style Miner        │
        • Tier 2: Structural Analysis      │
        • Tier 3: Local SLM + RAG          │
              │                            │
              ▼                            │
      PARSER SAFETY VALIDATION             │
      (No code, allowlisted fields)        │
              │                            │
              ▼                            │
      HYBRID TRUST GATE                    │
      (IP, Port, Protocol, Schema)         │
              │                            │
              ├── [Invalid] ───────────────┼────────► QUARANTINE (DLQ)
              │                            │
              └── [Approved]               │
                      │                    │
                      ▼                    │
              OCSF NORMALIZATION ◄─────────┘
              (Class 4001: Net Activity)
                      │
                      ▼
              ATOMIC PROMOTION
              (SQLite + In-Memory Swap)
```

---

## 3. Quick Start

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Node.js 18+ (tested on Node.js 24)
- (Optional) Docker & Docker Compose

---

### Option A: Local Development (Fastest)

#### 1. Backend Setup
```bash
# Clone and enter directory
cd "SIH Logger"

# Install backend dependencies
pip install -r backend/requirements.txt

# Start backend server (port 8000)
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Backend API will be accessible at `http://localhost:8000`  
Swagger API Documentation: `http://localhost:8000/docs`

#### 2. Frontend Setup (in a separate terminal)
```bash
cd "SIH Logger/frontend"

# Install dependencies (already built in repository)
npm install

# Start development server (port 5173)
npm run dev
```
Open your browser at `http://localhost:5173`

---

### Option B: Docker Compose Deployment

```bash
cd "SIH Logger"
docker-compose up --build
```
- Frontend UI: `http://localhost:5173`
- Backend API: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`

---

## 4. Verification & Testing

### Running the Automated Test Suite
The project includes a comprehensive suite of 27 unit and integration tests:

```bash
pytest backend/tests/ -v
```

Tests cover:
- Fast-path deterministic parsing
- Format drift detection & signature shift
- Tier-2 structural token classification
- Tier-3 RAG retrieval & fallback inference
- Parser safety validator (blocking code execution & forbidden syntax)
- Hybrid Trust Gate invariant enforcement (invalid IPs, out-of-range ports, unknown protocols, low confidence)
- OCSF Network Activity (class 4001) schema validation
- Lossless Evidence Vault & SHA-256 provenance
- Merkle tree tamper detection
- Transactional parser registry & rollback
- Append-only ledger chain continuity
- Plug-and-Play zero-code log source onboarding

---

## 5. Live Benchmarking

Execute the real benchmark suite measuring throughput, P50/P95 latencies, and Tier-3 AI invocation percentage:

```bash
# Benchmark 100 events
python -m backend.benchmark.runner --count 100

# Benchmark 1,000 events
python -m backend.benchmark.runner --count 1000
```

> **Note on Benchmarks**: All figures are real measurements generated on the host system. No metrics are fabricated.

---

## 6. Live SIH Judge Demonstration Flow

Navigate to the **JUDGE DEMO** tab in the dashboard (`http://localhost:5173/demo`) and execute the 9-step sequence:

1. **Step 1 (Known Format)**: Ingests `SRC=10.10.1.25 DST=...`. Processed via `FAST_PATH` (< 1ms, 0 AI).
2. **Step 2 (Introduce Drift)**: Vendor modifies syntax to `SRC_IP=... DST_IP=...`. Triggers `FAST PATH MISS`.
3. **Step 3 (Adapt)**: System activates Tier-2 Structural Analysis and escalates to Tier-3 Adaptive Inference.
4. **Step 4 (Candidate Parser)**: Synthesizes a structured JSON Parser Specification without executable code.
5. **Step 5 (Trust Gate)**: Validates IP addresses, port range, protocol, and required fields. Status: `APPROVED`.
6. **Step 6 (Parser Promotion)**: Commits parser `firewall_v2` to SQLite and performs an atomic in-memory cache swap.
7. **Step 7 (Replay Fast Path)**: Sends the drifted log again. Handled by **FAST PATH** with **ZERO AI invocation**! (Self-healing proof).
8. **Step 8 (Show Provenance)**: Audit trail: `RAW LOG` → `SHA-256` → `PARSER v2` → `OCSF CLASS 4001`.
9. **Step 9 (Test Tamper)**: Modifies raw file in Evidence Vault. Merkle verification reports `INTEGRITY FAILURE: MERKLE ROOT MISMATCH`.

---

## 7. Plug-and-Play Log Source Onboarding

Navigate to the **SOURCE ONBOARDING** tab (`http://localhost:5173/onboarding`):
- Select or paste sample logs from an unconfigured perimeter device (e.g., WAF, VPN gateway).
- Click `[Profile Source & Discover Template]`: System discovers grammar and maps fields to OCSF.
- Click `[Approve & Promote to FAST PATH]`: Promotes newly generated parser directly to the active registry without modifying backend source code.

---

## 8. Repository Structure

```
SIH Logger/
├── backend/
│   ├── adaptive/          # 3-tier adaptive parsing (Drain miner, structural, RAG, SLM interface)
│   ├── api/               # FastAPI routers (events, parsers, quarantine, integrity, demo, onboarding)
│   ├── benchmark/         # Ground-truth dataset & benchmark runner
│   ├── core/              # Pipeline orchestrator
│   ├── ingestion/         # Defensive validation, size limits, rate limiting
│   ├── integrity/         # Merkle trees, forensic audit, ledger adapter
│   ├── normalization/     # OCSF-compatible Network Activity (class 4001) mapping
│   ├── parsers/           # Deterministic fast-path engine & template specifications
│   ├── registry/          # Transactional parser registry & cache promotion
│   ├── storage/           # Evidence vault (lossless raw storage) & SQLite database
│   ├── tests/             # Automated test suite (24 tests)
│   ├── config.py          # Central application settings
│   ├── main.py            # FastAPI application entrypoint
│   └── models.py          # Pydantic v2 domain schemas
├── frontend/
│   ├── src/
│   │   ├── components/    # Reusable UI badges and cards
│   │   ├── pages/         # 8 SOC dashboard pages (Pipeline, Adaptive, Registry, Quarantine, etc.)
│   │   ├── services/      # Axios API service client
│   │   ├── App.tsx        # Application shell with sidebar & status bar
│   │   └── index.css      # Dark SOC cybersecurity theme styling
│   ├── package.json
│   └── vite.config.ts
├── docs/
│   ├── architecture.md    # In-depth architectural design and topology
│   ├── demo-script.md     # Step-by-step SIH judge evaluation guide
│   └── technical-notes.md # Feature classification & engineering clarifications
├── data/                  # SQLite storage, evidence vault, and template stores
├── docker-compose.yml     # Multi-container orchestration
└── README.md
```

---

## 9. Air-Gapped Operation

This prototype runs **completely offline without internet access**:
- **Embeddings & RAG**: Uses a standalone pure-Python TF-IDF sparse vector retrieval engine requiring no external downloads.
- **Inference**: Defaults to `DEMO INFERENCE FALLBACK` when Ollama is offline; automatically binds to local Ollama (`qwen2.5:3b `) if present on `localhost:11434`.
- **Zero Cloud Leakage**: No external cloud APIs (OpenAI, Gemini, Anthropic) are ever called.
