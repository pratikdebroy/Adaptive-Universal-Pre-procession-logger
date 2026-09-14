"""
Defensive Ingestion — Pre-parsing transport, resource, and structural safety checks.

Every incoming event must pass through:
RAW EVENT → EVIDENCE PRESERVATION → INGESTION SAFETY CHECKS → SAFE?
- YES → Fast/Adaptive Parsing
- NO → QUARANTINE (with complete provenance and specific reason)

The purpose of ingestion quarantine is:
"Prevent malformed, unsafe, resource-exhausting, or untrustworthy events
from entering the parsing/normalization pipeline."

IMPORTANT:
Do NOT classify a valid security event as a malicious input simply because
it describes an attack. The preprocessing layer is NOT an IDS.

Classification: IMPLEMENTED
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from backend.config import settings
from backend.models import (
    QuarantineReason, QuarantineSeverity, RawEvent,
)


@dataclass
class IngestionSafetyResult:
    safe: bool
    detected_format: str = "unknown"
    reason: QuarantineReason | None = None
    failed_check: str = ""
    severity: QuarantineSeverity = QuarantineSeverity.MEDIUM
    detail: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class SourceRateLimiter:
    """Token-bucket rate limiter tracking events per source and burst limit."""

    def __init__(self, rate: int = 1000, burst: int = 100):
        self.rate = rate
        self.burst = burst
        self._buckets: dict[str, tuple[float, float]] = {}  # source -> (tokens, last_time)
        self._recent_hashes: dict[str, list[float]] = {}   # sha256 -> timestamps for burst repetition

    def check_rate(self, source: str, raw_sha256: str = "") -> tuple[bool, QuarantineReason | None, str]:
        """Check rate and burst limits for a source."""
        now = time.monotonic()

        # Check repeated identical event bursts (> burst occurrences of exact same hash within 1 second)
        if raw_sha256:
            timestamps = self._recent_hashes.get(raw_sha256, [])
            timestamps = [t for t in timestamps if now - t <= 1.0]
            if len(timestamps) >= self.burst:
                return False, QuarantineReason.BURST_LIMIT_EXCEEDED, f"Identical event burst limit ({self.burst}/sec) exceeded for payload"
            timestamps.append(now)
            self._recent_hashes[raw_sha256] = timestamps

        # Source token bucket
        tokens, last_time = self._buckets.get(source, (float(self.burst), now))
        elapsed = now - last_time
        tokens = min(float(self.burst), tokens + elapsed * self.rate)

        if tokens < 1.0:
            self._buckets[source] = (tokens, now)
            return False, QuarantineReason.RATE_LIMIT_EXCEEDED, f"Source '{source}' exceeded ingestion rate limit of {self.rate} eps (burst: {self.burst})"

        self._buckets[source] = (tokens - 1.0, now)
        return True, None, "Rate limit OK"

    def reset(self):
        self._buckets.clear()
        self._recent_hashes.clear()


# Module-level default rate limiter
global_rate_limiter = SourceRateLimiter(
    rate=settings.rate_limit_events_per_second,
    burst=settings.rate_limit_burst,
)


def _detect_format_hint(message: str) -> str:
    """Heuristic format detector for raw event."""
    msg = message.strip()
    if not msg:
        return "empty"
    if msg.startswith("[**"):
        return "text"
    if msg.startswith("{") or (msg.startswith("[") and (msg.endswith("]") or re.match(r"^\[\s*[\{\"]", msg))):
        return "json"
    if msg.startswith("<?xml") or (msg.startswith("<") and ">" in msg and not msg.startswith("<PRI>")):
        # Distinguish syslog <PRI> from XML tags
        if re.match(r"^<\d{1,3}>", msg):
            return "syslog"
        return "xml"
    if re.match(r"^<\d{1,3}>", msg) or re.match(r"^%[A-Z0-9_-]+:", msg):
        return "syslog"
    if "=" in msg and not msg.startswith(",") and not msg.endswith(","):
        return "key_value"
    if "," in msg and ("\"" in msg or len(msg.split(",")) >= 3):
        return "csv"
    return "text"


def _get_json_depth(obj: Any, current_depth: int = 1) -> int:
    """Calculate maximum nesting depth of JSON object."""
    if isinstance(obj, dict):
        if not obj:
            return current_depth
        return max(_get_json_depth(v, current_depth + 1) for v in obj.values())
    elif isinstance(obj, list):
        if not obj:
            return current_depth
        return max(_get_json_depth(item, current_depth + 1) for item in obj)
    return current_depth


def _count_json_fields(obj: Any) -> int:
    """Count total keys in a JSON object."""
    count = 0
    if isinstance(obj, dict):
        count += len(obj)
        for v in obj.values():
            count += _count_json_fields(v)
    elif isinstance(obj, list):
        for item in obj:
            count += _count_json_fields(item)
    return count


def _max_json_string_len(obj: Any) -> int:
    """Find maximum string field length in a JSON object."""
    max_len = 0
    if isinstance(obj, dict):
        for k, v in obj.items():
            max_len = max(max_len, len(str(k)), _max_json_string_len(v))
    elif isinstance(obj, list):
        for item in obj:
            max_len = max(max_len, _max_json_string_len(item))
    elif isinstance(obj, str):
        max_len = max(max_len, len(obj))
    return max_len


def check_transport_and_framing(raw_message: str, source: str = "unknown") -> IngestionSafetyResult:
    """
    Check transport & framing invariants:
    - Empty event
    - Invalid UTF-8 / binary corruption
    - Malformed syslog framing
    """
    # 1. Empty check
    if not raw_message or not raw_message.strip():
        return IngestionSafetyResult(
            safe=False,
            detected_format="empty",
            reason=QuarantineReason.EMPTY_EVENT,
            failed_check="transport.empty_event",
            severity=QuarantineSeverity.LOW,
            detail="Event is empty or whitespace-only",
            metadata={"source": source, "length": len(raw_message)},
        )

    # 2. Encoding / Binary check
    # Check for unprintable binary control characters (except common whitespace \t, \n, \r)
    # or binary garbage like \x00, \xff\xfe
    raw_bytes = raw_message.encode("utf-8", errors="surrogateescape")
    try:
        raw_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        return IngestionSafetyResult(
            safe=False,
            detected_format="binary",
            reason=QuarantineReason.INVALID_ENCODING,
            failed_check="transport.invalid_encoding",
            severity=QuarantineSeverity.HIGH,
            detail=f"Invalid UTF-8 byte sequence: {e}",
            metadata={"source": source, "error": str(e)},
        )

    # Detect raw binary headers / null bytes
    if "\x00" in raw_message:
        # If the message contains null bytes or binary control garbage
        if any(ord(c) < 32 and c not in "\t\n\r" for c in raw_message[:16]):
            return IngestionSafetyResult(
                safe=False,
                detected_format="binary",
                reason=QuarantineReason.INVALID_ENCODING,
                failed_check="transport.unexpected_binary_bytes",
                severity=QuarantineSeverity.HIGH,
                detail="Unexpected binary/control characters detected in event header",
                metadata={"source": source, "first_bytes": repr(raw_message[:16])},
            )

    # 3. Syslog framing check
    if raw_message.startswith("<"):
        # Check if syslog priority header is present and valid
        match = re.match(r"^<([^>]+)>", raw_message)
        if match:
            pri_str = match.group(1)
            if not pri_str.isdigit() or not (0 <= int(pri_str) <= 191):
                return IngestionSafetyResult(
                    safe=False,
                    detected_format="syslog",
                    reason=QuarantineReason.INVALID_SYSLOG_FRAME,
                    failed_check="transport.syslog_priority",
                    severity=QuarantineSeverity.MEDIUM,
                    detail=f"Malformed syslog framing: priority value <{pri_str}> is not a valid PRI (0-191)",
                    metadata={"pri_value": pri_str, "expected": "0-191"},
                )
        elif not raw_message.startswith("<?xml"):
            # Unclosed angle bracket framing
            if not re.search(r">", raw_message[:10]):
                return IngestionSafetyResult(
                    safe=False,
                    detected_format="syslog",
                    reason=QuarantineReason.INVALID_FRAMING,
                    failed_check="transport.unclosed_framing",
                    severity=QuarantineSeverity.MEDIUM,
                    detail="Malformed framing: unclosed transport header bracket",
                    metadata={"source": source},
                )

    return IngestionSafetyResult(safe=True)


def check_resource_limits(
    raw_message: str,
    source: str = "unknown",
    raw_sha256: str = "",
    rate_limiter: SourceRateLimiter | None = None,
) -> IngestionSafetyResult:
    """
    Check resource limits & DoS protection:
    - Maximum event size
    - Ingestion rate & burst protection
    """
    size_bytes = len(raw_message.encode("utf-8", errors="surrogateescape"))
    if size_bytes > settings.max_event_size_bytes:
        return IngestionSafetyResult(
            safe=False,
            detected_format=_detect_format_hint(raw_message),
            reason=QuarantineReason.EVENT_TOO_LARGE,
            failed_check="resource.max_event_size",
            severity=QuarantineSeverity.HIGH,
            detail=f"Event size {size_bytes} bytes exceeds maximum configured limit of {settings.max_event_size_bytes} bytes",
            metadata={"size_bytes": size_bytes, "limit_bytes": settings.max_event_size_bytes},
        )

    # Rate & Burst Limiting
    limiter = rate_limiter or global_rate_limiter
    rate_ok, rate_reason, rate_detail = limiter.check_rate(source, raw_sha256)
    if not rate_ok:
        return IngestionSafetyResult(
            safe=False,
            detected_format=_detect_format_hint(raw_message),
            reason=rate_reason or QuarantineReason.RATE_LIMIT_EXCEEDED,
            failed_check="resource.rate_limit",
            severity=QuarantineSeverity.HIGH,
            detail=rate_detail,
            metadata={"source": source, "rate_limit_eps": settings.rate_limit_events_per_second},
        )

    return IngestionSafetyResult(safe=True)


def check_structural_format(raw_message: str) -> IngestionSafetyResult:
    """
    Check structure and format conformance without executing log content.
    Validates JSON, XML, CSV, Key-Value, and Syslog structures.
    """
    detected_format = _detect_format_hint(raw_message)

    # 1. JSON Format Validation
    if detected_format == "json":
        try:
            parsed_json = json.loads(raw_message)
        except json.JSONDecodeError as e:
            return IngestionSafetyResult(
                safe=False,
                detected_format="json",
                reason=QuarantineReason.MALFORMED_JSON,
                failed_check="structure.json_syntax",
                severity=QuarantineSeverity.MEDIUM,
                detail=f"Invalid JSON syntax at line {e.lineno} col {e.colno}: {e.msg}",
                metadata={"error": str(e), "pos": e.pos},
            )

        # Check JSON nesting depth
        depth = _get_json_depth(parsed_json)
        if depth > settings.max_nesting_depth:
            return IngestionSafetyResult(
                safe=False,
                detected_format="json",
                reason=QuarantineReason.EXCESSIVE_NESTING,
                failed_check="resource.json_nesting_depth",
                severity=QuarantineSeverity.HIGH,
                detail=f"JSON nesting depth {depth} exceeds maximum configured depth of {settings.max_nesting_depth}",
                metadata={"nesting_depth": depth, "max_depth": settings.max_nesting_depth},
            )

        # Check field count
        field_count = _count_json_fields(parsed_json)
        if field_count > settings.max_field_count:
            return IngestionSafetyResult(
                safe=False,
                detected_format="json",
                reason=QuarantineReason.TOO_MANY_FIELDS,
                failed_check="resource.max_field_count",
                severity=QuarantineSeverity.HIGH,
                detail=f"JSON field count {field_count} exceeds maximum allowed of {settings.max_field_count}",
                metadata={"field_count": field_count, "limit": settings.max_field_count},
            )

        # Check field length
        max_str = _max_json_string_len(parsed_json)
        if max_str > settings.max_field_length:
            return IngestionSafetyResult(
                safe=False,
                detected_format="json",
                reason=QuarantineReason.FIELD_TOO_LARGE,
                failed_check="resource.max_field_length",
                severity=QuarantineSeverity.HIGH,
                detail=f"Individual JSON field string length {max_str} exceeds limit of {settings.max_field_length}",
                metadata={"max_field_length": max_str, "limit": settings.max_field_length},
            )

        return IngestionSafetyResult(safe=True, detected_format="json")

    # 2. XML Format Validation
    if detected_format == "xml":
        # Disallow XXE and Entity expansions (Security protection)
        if re.search(r"<!ENTITY", raw_message, re.IGNORECASE) or re.search(r"<!DOCTYPE.*SYSTEM", raw_message, re.IGNORECASE):
            return IngestionSafetyResult(
                safe=False,
                detected_format="xml",
                reason=QuarantineReason.UNSAFE_PARSER_SPEC,
                failed_check="security.xml_entity_expansion",
                severity=QuarantineSeverity.CRITICAL,
                detail="XML DOCTYPE or Entity expansion detected (XXE protection)",
                metadata={"threat": "XXE_ENTITY_EXPANSION"},
            )

        try:
            root = ET.fromstring(raw_message)
        except ET.ParseError as e:
            return IngestionSafetyResult(
                safe=False,
                detected_format="xml",
                reason=QuarantineReason.MALFORMED_XML,
                failed_check="structure.xml_syntax",
                severity=QuarantineSeverity.MEDIUM,
                detail=f"Malformed XML syntax: {e}",
                metadata={"error": str(e)},
            )

        # Calculate XML depth
        def _get_xml_depth(elem, cur=1):
            if len(elem) == 0:
                return cur
            return max(_get_xml_depth(child, cur + 1) for child in elem)

        xml_depth = _get_xml_depth(root)
        if xml_depth > settings.max_nesting_depth:
            return IngestionSafetyResult(
                safe=False,
                detected_format="xml",
                reason=QuarantineReason.EXCESSIVE_NESTING,
                failed_check="resource.xml_nesting_depth",
                severity=QuarantineSeverity.HIGH,
                detail=f"XML element nesting depth {xml_depth} exceeds limit of {settings.max_nesting_depth}",
                metadata={"xml_depth": xml_depth, "max_depth": settings.max_nesting_depth},
            )

        return IngestionSafetyResult(safe=True, detected_format="xml")

    # 3. CSV Format Validation
    if detected_format == "csv":
        try:
            reader = csv.reader(io.StringIO(raw_message))
            rows = list(reader)
            if rows:
                col_count = len(rows[0])
                if col_count > settings.max_field_count:
                    return IngestionSafetyResult(
                        safe=False,
                        detected_format="csv",
                        reason=QuarantineReason.TOO_MANY_FIELDS,
                        failed_check="resource.csv_column_count",
                        severity=QuarantineSeverity.HIGH,
                        detail=f"CSV column count {col_count} exceeds limit of {settings.max_field_count}",
                        metadata={"col_count": col_count, "limit": settings.max_field_count},
                    )
        except csv.Error as e:
            return IngestionSafetyResult(
                safe=False,
                detected_format="csv",
                reason=QuarantineReason.MALFORMED_CSV,
                failed_check="structure.csv_syntax",
                severity=QuarantineSeverity.MEDIUM,
                detail=f"Malformed CSV formatting: {e}",
                metadata={"error": str(e)},
            )
        return IngestionSafetyResult(safe=True, detected_format="csv")

    # 4. Key-Value Format Validation
    if detected_format == "key_value":
        # Check for unbalanced quotes in key=value pairs
        # e.g. key="unclosed string
        quote_count = raw_message.count('"')
        if quote_count % 2 != 0:
            return IngestionSafetyResult(
                safe=False,
                detected_format="key_value",
                reason=QuarantineReason.INVALID_KV_STRUCTURE,
                failed_check="structure.kv_unbalanced_quotes",
                severity=QuarantineSeverity.MEDIUM,
                detail="Invalid key-value structure: unbalanced quotes detected in field values",
                metadata={"quote_count": quote_count},
            )

        tokens = raw_message.split()
        kv_count = sum(1 for t in tokens if "=" in t)
        if kv_count > settings.max_field_count:
            return IngestionSafetyResult(
                safe=False,
                detected_format="key_value",
                reason=QuarantineReason.TOO_MANY_FIELDS,
                failed_check="resource.kv_field_count",
                severity=QuarantineSeverity.HIGH,
                detail=f"Key-value field count {kv_count} exceeds limit of {settings.max_field_count}",
                metadata={"kv_count": kv_count, "limit": settings.max_field_count},
            )

        # Check individual field length
        for token in tokens:
            if len(token) > settings.max_field_length:
                return IngestionSafetyResult(
                    safe=False,
                    detected_format="key_value",
                    reason=QuarantineReason.FIELD_TOO_LARGE,
                    failed_check="resource.kv_field_length",
                    severity=QuarantineSeverity.HIGH,
                    detail=f"Key-value field token length {len(token)} exceeds maximum allowed {settings.max_field_length}",
                    metadata={"token_length": len(token), "limit": settings.max_field_length},
                )

        return IngestionSafetyResult(safe=True, detected_format="key_value")

    return IngestionSafetyResult(safe=True, detected_format=detected_format)


def run_ingestion_safety_checks(
    raw_event: RawEvent,
    rate_limiter: SourceRateLimiter | None = None,
) -> IngestionSafetyResult:
    """
    Orchestrates all pre-parsing ingestion safety checks.
    Order of checks:
    1. Transport & Framing (empty, binary encoding, syslog framing)
    2. Resource & DoS Protection (size, rate limiting, burst limits)
    3. Structural / Format (JSON, XML, CSV, KV, syntax and nesting validation)

    Returns IngestionSafetyResult.
    """
    message = raw_event.raw_message

    # Step 1: Transport / Framing
    tf_res = check_transport_and_framing(message, raw_event.source)
    if not tf_res.safe:
        return tf_res

    # Step 2: Resource / DoS Limits
    res_res = check_resource_limits(message, raw_event.source, raw_event.raw_sha256, rate_limiter)
    if not res_res.safe:
        return res_res

    # Step 3: Structural / Format
    struct_res = check_structural_format(message)
    if not struct_res.safe:
        return struct_res

    # Passed all checks
    return IngestionSafetyResult(safe=True, detected_format=struct_res.detected_format)
