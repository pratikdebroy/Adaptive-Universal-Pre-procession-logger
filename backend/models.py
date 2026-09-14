"""
Domain models for the Universal Log Pre-processing Framework.
All data structures used across the pipeline are defined here.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────

class ProcessingMode(str, enum.Enum):
    FAST_PATH = "FAST_PATH"
    STRUCTURAL = "STRUCTURAL"
    TIER3_ADAPTIVE = "TIER3_ADAPTIVE"


class ParserStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    CANDIDATE = "CANDIDATE"
    ROLLED_BACK = "ROLLED_BACK"
    QUARANTINED = "QUARANTINED"


class ValidationResult(str, enum.Enum):
    APPROVED = "APPROVED"
    QUARANTINED = "QUARANTINED"


class QuarantineSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class QuarantineStatus(str, enum.Enum):
    QUARANTINED = "QUARANTINED"
    REVIEWED = "REVIEWED"
    RELEASED = "RELEASED"


class QuarantineReason(str, enum.Enum):
    # Transport / Framing
    EMPTY_EVENT = "EMPTY_EVENT"
    INVALID_ENCODING = "INVALID_ENCODING"
    INVALID_FRAMING = "INVALID_FRAMING"
    INVALID_SYSLOG_FRAME = "INVALID_SYSLOG_FRAME"

    # Resource / DoS Protection
    EVENT_TOO_LARGE = "EVENT_TOO_LARGE"
    FIELD_TOO_LARGE = "FIELD_TOO_LARGE"
    TOO_MANY_FIELDS = "TOO_MANY_FIELDS"
    EXCESSIVE_NESTING = "EXCESSIVE_NESTING"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    BURST_LIMIT_EXCEEDED = "BURST_LIMIT_EXCEEDED"

    # Structural / Format
    MALFORMED_JSON = "MALFORMED_JSON"
    MALFORMED_XML = "MALFORMED_XML"
    MALFORMED_CSV = "MALFORMED_CSV"
    INVALID_KV_STRUCTURE = "INVALID_KV_STRUCTURE"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    STRUCTURE_INVALID = "STRUCTURE_INVALID"

    # Field-Level Validation
    INVALID_IP = "INVALID_IP"
    INVALID_IPV6 = "INVALID_IPV6"
    INVALID_CIDR = "INVALID_CIDR"
    INVALID_PORT = "INVALID_PORT"
    INVALID_PROTOCOL = "INVALID_PROTOCOL"
    INVALID_MAC = "INVALID_MAC"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    TIMESTAMP_IMPLAUSIBLE = "TIMESTAMP_IMPLAUSIBLE"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    TYPE_MISMATCH = "TYPE_MISMATCH"

    # Security / Processing Safety & Semantic
    UNSAFE_PARSER_SPEC = "UNSAFE_PARSER_SPEC"
    INVALID_MAPPING = "INVALID_MAPPING"
    DISALLOWED_TRANSFORMATION = "DISALLOWED_TRANSFORMATION"
    LOW_CONFIDENCE_MAPPING = "LOW_CONFIDENCE_MAPPING"
    SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"
    TRUST_GATE_FAILED = "TRUST_GATE_FAILED"

    # Backwards Compatibility
    MALFORMED_INPUT = "MALFORMED_INPUT"
    OVERSIZED_INPUT = "OVERSIZED_INPUT"
    FAILED_VALIDATION = "FAILED_VALIDATION"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    SUSPICIOUS_PAYLOAD = "SUSPICIOUS_PAYLOAD"
    PARSER_SAFETY_FAILURE = "PARSER_SAFETY_FAILURE"


class InferenceMode(str, enum.Enum):
    LOCAL_SLM = "LOCAL_SLM"
    DEMO_FALLBACK = "DEMO_INFERENCE_FALLBACK"


class FeatureClassification(str, enum.Enum):
    IMPLEMENTED = "IMPLEMENTED"
    PROTOTYPE_ABSTRACTION = "PROTOTYPE_ABSTRACTION"


# ──────────────────────────────────────────────
# Raw Event
# ──────────────────────────────────────────────

class RawEvent(BaseModel):
    """Immutable raw event as received. NEVER modified after creation."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "unknown"
    raw_message: str
    raw_sha256: str = ""  # Computed at ingestion


# ──────────────────────────────────────────────
# Processing Copy
# ──────────────────────────────────────────────

class ProcessingCopy(BaseModel):
    """Sanitized copy of the raw event used for parsing. The raw event is preserved separately."""
    event_id: str  # Links back to RawEvent
    sanitized_message: str
    source: str = "unknown"
    sanitization_applied: list[str] = Field(default_factory=list)


# ──────────────────────────────────────────────
# Parser Specification
# ──────────────────────────────────────────────

class FieldMapping(BaseModel):
    """Maps a source field name to an OCSF-compatible field path."""
    source_field: str
    target_field: str
    field_type: str = "string"  # string, ip, port, protocol, action, timestamp


class ParserSpecification(BaseModel):
    """
    Structured parser specification. This is what the adaptive engine produces.
    The deterministic parser engine executes this — NOT arbitrary code.
    """
    template: str  # The log template pattern
    field_separator: str = "="  # Key-value separator
    entry_separator: str = " "  # Between key-value pairs
    fields: dict[str, str]  # {source_field: ocsf_target_field}
    field_types: dict[str, str] = Field(default_factory=dict)  # {source_field: type}
    constants: dict[str, str] = Field(default_factory=dict)  # Static parts
    regex_pattern: str = ""  # Optional compiled regex
    source_hint: str = ""
    confidence: float = 0.0


# ──────────────────────────────────────────────
# Parser Record (Registry)
# ──────────────────────────────────────────────

class ParserRecord(BaseModel):
    """Parser registry entry with versioning."""
    parser_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    source: str = ""
    format_signature: str = ""
    parser_version: int = 1
    schema_version: str = "1.0"
    status: ParserStatus = ParserStatus.CANDIDATE
    confidence: float = 0.0
    spec: ParserSpecification
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    test_results: dict[str, Any] = Field(default_factory=dict)


# ──────────────────────────────────────────────
# Parsed Event
# ──────────────────────────────────────────────

class ParsedFields(BaseModel):
    """Extracted fields from parsing."""
    fields: dict[str, Any] = Field(default_factory=dict)
    parser_id: str = ""
    parser_version: int = 0
    processing_mode: ProcessingMode = ProcessingMode.FAST_PATH
    confidence: float = 0.0
    tier_detail: str = ""


# ──────────────────────────────────────────────
# Trust Gate
# ──────────────────────────────────────────────

class ValidationCheck(BaseModel):
    """Individual validation check result."""
    check_name: str
    passed: bool
    detail: str = ""
    value: Any = None


class TrustGateResult(BaseModel):
    """Complete Trust Gate validation report."""
    result: ValidationResult
    checks: list[ValidationCheck] = Field(default_factory=list)
    confidence: float = 0.0
    overall_passed: int = 0
    overall_failed: int = 0
    failure_reasons: list[str] = Field(default_factory=list)
    primary_reason: QuarantineReason = QuarantineReason.FAILED_VALIDATION
    primary_severity: QuarantineSeverity = QuarantineSeverity.MEDIUM
    failed_check_name: str = ""
    failed_value: Any = None


class ParserSafetyResult(BaseModel):
    """Parser Safety Validation result — checks the spec itself."""
    safe: bool
    checks: list[ValidationCheck] = Field(default_factory=list)
    failure_reasons: list[str] = Field(default_factory=list)
    primary_reason: QuarantineReason = QuarantineReason.UNSAFE_PARSER_SPEC
    primary_severity: QuarantineSeverity = QuarantineSeverity.CRITICAL
    failed_check_name: str = ""


# ──────────────────────────────────────────────
# OCSF-Compatible Event
# ──────────────────────────────────────────────

class OCSFEvent(BaseModel):
    """OCSF-compatible Network Activity representation (class_uid: 4001)."""
    # OCSF core
    category_uid: int = 4
    category_name: str = "Network Activity"
    class_uid: int = 4001
    class_name: str = "Network Activity"
    activity_id: int = 6  # Traffic
    activity_name: str = "Traffic"
    type_uid: int = 400106
    type_name: str = "Network Activity: Traffic"
    severity_id: int = 1
    severity: str = "Informational"
    time: int = 0  # Unix timestamp ms

    # Action
    action_id: int = 0
    action: str = "Unknown"
    disposition_id: int = 0
    disposition: str = "Unknown"

    # Endpoints
    src_endpoint: dict[str, Any] = Field(default_factory=dict)
    dst_endpoint: dict[str, Any] = Field(default_factory=dict)

    # Connection
    connection_info: dict[str, Any] = Field(default_factory=dict)

    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Message
    message: str = ""

    # Provenance (custom extension)
    raw_event_id: str = ""
    raw_sha256: str = ""
    parser_id: str = ""
    parser_version: int = 0
    processing_mode: str = ""
    confidence: float = 0.0
    schema_version: str = "1.0"


# ──────────────────────────────────────────────
# Quarantine
# ──────────────────────────────────────────────

class QuarantineEntry(BaseModel):
    """Quarantined event entry."""
    quarantine_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str
    raw_message: str
    raw_sha256: str = ""
    source: str = "unknown"
    detected_format: str = "unknown"
    reason: QuarantineReason
    failed_check: str = ""
    severity: QuarantineSeverity = QuarantineSeverity.MEDIUM
    detail: str = ""
    validation_failures: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "QUARANTINED"  # QUARANTINED, REVIEWED, RELEASED, APPROVED, REPROCESSED, DISCARDED


# ──────────────────────────────────────────────
# Integrity
# ──────────────────────────────────────────────

class MerkleVerification(BaseModel):
    """Merkle tree verification result."""
    batch_id: str = ""
    expected_root: str = ""
    computed_root: str = ""
    integrity_status: str = ""  # VERIFIED, FAILURE
    event_hashes: list[str] = Field(default_factory=list)
    tampered_events: list[str] = Field(default_factory=list)


class LedgerEntry(BaseModel):
    """Append-only ledger entry — Prototype Permissioned-Ledger Adapter."""
    batch_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    merkle_root: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    previous_root: str = ""
    event_count: int = 0
    status: str = "COMMITTED"


# ──────────────────────────────────────────────
# Pipeline / Metrics
# ──────────────────────────────────────────────

class PipelineStageInfo(BaseModel):
    """Status of a pipeline stage."""
    name: str
    status: str = "READY"
    event_count: int = 0
    latency_ms: float = 0.0
    processing_mode: str = ""


class PipelineMetrics(BaseModel):
    """Aggregate pipeline metrics — all from actual execution."""
    total_events: int = 0
    fast_path_count: int = 0
    structural_count: int = 0
    tier3_count: int = 0
    quarantine_count: int = 0
    tier3_invocation_rate: float = 0.0  # percentage
    avg_fast_path_latency_ms: float = 0.0
    avg_adaptive_latency_ms: float = 0.0
    parsers_active: int = 0
    parsers_candidate: int = 0
    inference_mode: str = ""


# ──────────────────────────────────────────────
# Benchmark
# ──────────────────────────────────────────────

class BenchmarkResult(BaseModel):
    """Benchmark results — all values from actual execution."""
    label: str = "Prototype benchmark — local environment"
    total_events: int = 0
    known_events: int = 0
    drifted_events: int = 0
    malformed_events: int = 0
    events_per_second: float = 0.0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    parsing_accuracy: float = 0.0
    schema_validity_rate: float = 0.0
    fast_path_latency_ms: float = 0.0
    adaptive_latency_ms: float = 0.0
    tier3_invocation_count: int = 0
    tier3_invocation_rate: float = 0.0
    recovery_rate: float = 0.0
    parser_promotion_time_ms: float = 0.0
    quarantine_rate: float = 0.0
    classification: str = FeatureClassification.IMPLEMENTED


# ──────────────────────────────────────────────
# API Response
# ──────────────────────────────────────────────

class ProcessedEventResponse(BaseModel):
    """Full response after processing a single event."""
    event_id: str
    raw_sha256: str
    processing_mode: ProcessingMode
    parser_id: str = ""
    parser_name: str = ""
    parser_version: int = 0
    confidence: float = 0.0
    validation: TrustGateResult | None = None
    ocsf_event: OCSFEvent | None = None
    quarantine: QuarantineEntry | None = None
    tier_detail: str = ""
    stages: list[PipelineStageInfo] = Field(default_factory=list)
    inference_mode: str = ""
    tier3_invocations: int = 0


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    inference_mode: str = ""
    ollama_available: bool = False
    database_ok: bool = False
    parsers_loaded: int = 0
    uptime_seconds: float = 0.0
    classification: dict[str, str] = Field(default_factory=dict)
