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
import datetime
import io
import ipaddress
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


def is_valid_ip(val: Any) -> tuple[bool, QuarantineReason, str]:
    """Validate IPv4 or IPv6 address format."""
    str_val = str(val).strip()
    is_v6 = ":" in str_val
    try:
        ipaddress.ip_address(str_val)
        return True, QuarantineReason.INVALID_IP, "valid"
    except ValueError:
        reason = QuarantineReason.INVALID_IPV6 if is_v6 else QuarantineReason.INVALID_IP
        return False, reason, f"Invalid IP address format: '{str_val}'"


def is_valid_port(val: Any) -> tuple[bool, QuarantineReason, str]:
    """Validate network port range (0-65535)."""
    try:
        port_int = int(str(val).strip())
        if 0 <= port_int <= 65535:
            return True, QuarantineReason.INVALID_PORT, "valid"
        return False, QuarantineReason.INVALID_PORT, f"Port '{val}' out of valid range (0-65535)"
    except (ValueError, TypeError):
        return False, QuarantineReason.INVALID_PORT, f"Port '{val}' is not a valid integer"


def is_valid_protocol(val: Any) -> tuple[bool, QuarantineReason, str]:
    """Validate transport protocol against configured allowlist or valid IANA protocol number."""
    proto_str = str(val).strip().upper()
    valid_protos = {p.upper() for p in settings.valid_protocols}
    if proto_str in valid_protos:
        return True, QuarantineReason.INVALID_PROTOCOL, "valid"
    if proto_str.isdigit():
        proto_num = int(proto_str)
        if 0 <= proto_num <= 255:
            return True, QuarantineReason.INVALID_PROTOCOL, "valid"
    return False, QuarantineReason.INVALID_PROTOCOL, f"Protocol '{val}' is not a recognized transport protocol"


def is_valid_cidr(val: Any) -> tuple[bool, QuarantineReason, str]:
    """Validate CIDR network notation."""
    cidr_str = str(val).strip()
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True, QuarantineReason.INVALID_CIDR, "valid"
    except ValueError:
        return False, QuarantineReason.INVALID_CIDR, f"Invalid CIDR prefix notation: '{cidr_str}'"


MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


def is_valid_mac(val: Any) -> tuple[bool, QuarantineReason, str]:
    """Validate standard 6-octet MAC address format."""
    mac_str = str(val).strip()
    if MAC_REGEX.match(mac_str):
        return True, QuarantineReason.INVALID_MAC, "valid"
    return False, QuarantineReason.INVALID_MAC, f"Invalid MAC address format: '{mac_str}'"


def is_valid_timestamp(val: Any) -> tuple[bool, QuarantineReason, str]:
    """Validate timestamp parseability and temporal plausibility."""
    parsed_ts: float | None = None
    try:
        if isinstance(val, (int, float)):
            parsed_ts = float(val) / 1000.0 if float(val) > 1e11 else float(val)
        else:
            str_val = str(val).strip()
            if re.match(r"^\d+(\.\d+)?$", str_val):
                num = float(str_val)
                parsed_ts = num / 1000.0 if num > 1e11 else num
            else:
                dt = datetime.datetime.fromisoformat(str_val.replace("Z", "+00:00"))
                parsed_ts = dt.timestamp()
    except Exception:
        parsed_ts = None

    if parsed_ts is None:
        return False, QuarantineReason.INVALID_TIMESTAMP, f"Cannot parse timestamp format: '{val}'"

    now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
    max_future = now_ts + settings.timestamp_max_future_seconds
    max_past = now_ts - (settings.timestamp_max_past_years * 365.25 * 86400)
    if not (max_past <= parsed_ts <= max_future):
        return False, QuarantineReason.TIMESTAMP_IMPLAUSIBLE, f"Timestamp '{val}' is outside plausible temporal window"

    return True, QuarantineReason.INVALID_TIMESTAMP, "valid"


def _extract_fields_for_inspection(event: dict[str, Any] | str) -> dict[str, Any]:
    """Extract key-value pairs from dict, JSON string, or Key-Value string for pre-parsing security inspection."""
    if isinstance(event, dict):
        raw_dict = event
    elif isinstance(event, str):
        msg = event.strip()
        if msg.startswith("{"):
            try:
                parsed = json.loads(msg)
                if isinstance(parsed, dict):
                    raw_dict = parsed
                else:
                    return {}
            except Exception:
                raw_dict = None
        else:
            raw_dict = None

        if raw_dict is None:
            # Extract key=value patterns (both unquoted and quoted values)
            pairs = re.findall(r'(?:^|\s+)([A-Za-z0-9_.\-]+)=(?:"([^"]*)"|(\S+))', msg)
            if pairs:
                extracted: dict[str, Any] = {}
                for k, v1, v2 in pairs:
                    val = v1 if v1 != "" else v2
                    extracted[k] = val
                return extracted
            return {}
    else:
        return {}

    # Flatten one level for nested objects (e.g. source.ip)
    flattened: dict[str, Any] = {}
    for k, v in raw_dict.items():
        flattened[k] = v
        if isinstance(v, dict):
            for sub_k, sub_v in v.items():
                flattened[f"{k}.{sub_k}"] = sub_v
                flattened[f"{k}_{sub_k}"] = sub_v
    return flattened


def get_field_case_insensitive(event_dict: dict[str, Any], aliases: list[str]) -> tuple[str | None, Any]:
    """
    Search for a field in event_dict matching any of the aliases (case-insensitive).
    Returns (matched_key, value) ONLY if the field is present and non-empty.
    If the field is absent, returns (None, None).
    """
    lower_map = {str(k).lower(): (k, v) for k, v in event_dict.items()}
    for alias in aliases:
        alias_lower = alias.lower()
        if alias_lower in lower_map:
            actual_key, val = lower_map[alias_lower]
            if val is not None and str(val).strip() != "":
                return actual_key, val
    return None, None


# Unambiguous / Confidently Known Semantic Field Names
# Only fields whose names explicitly and unambiguously denote their semantic type
# are validated at generic ingestion. Ambiguous fields (e.g. "source", "destination",
# "client", "server", "port", "time", "date") must NEVER be guessed or forced as
# a semantic type during generic ingestion.
EXPLICIT_IP_KEYS: set[str] = {
    "source.ip", "destination.ip", "src_ip", "dst_ip", "source_ip", "destination_ip",
    "srcip", "dstip", "client_ip", "server_ip", "remote_ip",
    "source_ipv4", "destination_ipv4", "source_ipv6", "destination_ipv6",
}

EXPLICIT_PORT_KEYS: set[str] = {
    "source.port", "destination.port", "src_port", "dst_port",
    "source_port", "destination_port", "sport", "dport", "dest_port",
    "spt", "dpt", "port",
}

EXPLICIT_PROTOCOL_KEYS: set[str] = {
    "network.transport", "transport_protocol", "ip_protocol", "proto", "protocol",
}

EXPLICIT_MAC_KEYS: set[str] = {
    "source.mac", "destination.mac", "src_mac", "dst_mac",
    "source_mac", "destination_mac",
}

EXPLICIT_CIDR_KEYS: set[str] = {
    "source.cidr", "destination.cidr", "src_cidr", "dst_cidr", "network_cidr", "cidr",
}

EXPLICIT_TIMESTAMP_KEYS: set[str] = {
    "event_timestamp", "event_time", "timestamp", "@timestamp",
}


def check_field_level_security(event: dict[str, Any] | str, source: str = "unknown") -> IngestionSafetyResult:
    """
    Validates field-level security constraints on raw/processing events BEFORE parsing.

    DECISION MODEL (SIH26156 Core Principle):
    - FIELD ABSENT
        → PROCEED
    - FIELD PRESENT + TYPE/SEMANTICS CONFIDENTLY KNOWN
        → VALIDATE
        → valid   → PROCEED
        → invalid → QUARANTINE
    - FIELD PRESENT + TYPE/SEMANTICS UNKNOWN/AMBIGUOUS
        → DO NOT FORCE VALIDATION
        → PROCEED TO NORMAL PARSING / STRUCTURAL ANALYSIS

    Generic ingestion safety is schema-agnostic: it does NOT infer that an arbitrary
    field like 'source=server.go:1347' or 'description="port 70000"' is an IP or port.
    """
    fields = _extract_fields_for_inspection(event)
    if not fields:
        return IngestionSafetyResult(safe=True)

    for key, val in fields.items():
        if val is None or str(val).strip() == "":
            continue

        k_norm = str(key).strip().lower()

        # 1. Confidently Known IP fields
        if k_norm in EXPLICIT_IP_KEYS:
            valid, reason, detail = is_valid_ip(val)
            if not valid:
                return IngestionSafetyResult(
                    safe=False,
                    reason=reason,
                    failed_check=f"field.ip:{key}",
                    severity=QuarantineSeverity.HIGH,
                    detail=f"Invalid IP address in explicitly typed field '{key}': {detail}",
                    metadata={"source": source, "field": key, "value": str(val)},
                )

        # 2. Confidently Known Port fields
        elif k_norm in EXPLICIT_PORT_KEYS:
            # If key is generically named "port", only validate if value looks numeric
            # (e.g. PORT=99999 or PORT=-1); do not force TCP/UDP port validation on
            # interface names like port=eth0 or port=GigabitEthernet0/1.
            if k_norm == "port":
                val_str = str(val).strip().lstrip("-")
                if not val_str.isdigit():
                    continue
            valid, reason, detail = is_valid_port(val)
            if not valid:
                return IngestionSafetyResult(
                    safe=False,
                    reason=reason,
                    failed_check=f"field.port:{key}",
                    severity=QuarantineSeverity.MEDIUM,
                    detail=f"Invalid port in explicitly typed field '{key}': {detail}",
                    metadata={"source": source, "field": key, "value": str(val)},
                )

        # 3. Confidently Known Protocol fields
        elif k_norm in EXPLICIT_PROTOCOL_KEYS:
            valid, reason, detail = is_valid_protocol(val)
            if not valid:
                return IngestionSafetyResult(
                    safe=False,
                    reason=reason,
                    failed_check=f"field.protocol:{key}",
                    severity=QuarantineSeverity.MEDIUM,
                    detail=f"Invalid transport protocol in explicitly typed field '{key}': {detail}",
                    metadata={"source": source, "field": key, "value": str(val)},
                )

        # 4. Confidently Known MAC fields
        elif k_norm in EXPLICIT_MAC_KEYS:
            valid, reason, detail = is_valid_mac(val)
            if not valid:
                return IngestionSafetyResult(
                    safe=False,
                    reason=reason,
                    failed_check=f"field.mac:{key}",
                    severity=QuarantineSeverity.MEDIUM,
                    detail=f"Invalid MAC address in explicitly typed field '{key}': {detail}",
                    metadata={"source": source, "field": key, "value": str(val)},
                )

        # 5. Confidently Known CIDR fields
        elif k_norm in EXPLICIT_CIDR_KEYS:
            valid, reason, detail = is_valid_cidr(val)
            if not valid:
                return IngestionSafetyResult(
                    safe=False,
                    reason=reason,
                    failed_check=f"field.cidr:{key}",
                    severity=QuarantineSeverity.MEDIUM,
                    detail=f"Invalid CIDR prefix in explicitly typed field '{key}': {detail}",
                    metadata={"source": source, "field": key, "value": str(val)},
                )

        # 6. Confidently Known Timestamp fields
        elif k_norm in EXPLICIT_TIMESTAMP_KEYS:
            valid, reason, detail = is_valid_timestamp(val)
            if not valid:
                return IngestionSafetyResult(
                    safe=False,
                    reason=reason,
                    failed_check=f"field.timestamp:{key}",
                    severity=QuarantineSeverity.LOW,
                    detail=f"Invalid timestamp in explicitly typed field '{key}': {detail}",
                    metadata={"source": source, "field": key, "value": str(val)},
                )

        # Unknown / ambiguous semantics -> do NOT force validation -> proceed
        else:
            continue

    return IngestionSafetyResult(safe=True)


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
    4. Field-level Security (presence-guarded: missing -> proceed, present+invalid -> quarantine)

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

    # Step 4: Field-level Security Checks (Missing -> Proceed, Present+Invalid -> Quarantine)
    field_res = check_field_level_security(message, raw_event.source)
    if not field_res.safe:
        field_res.detected_format = struct_res.detected_format
        return field_res

    # Passed all checks
    return IngestionSafetyResult(safe=True, detected_format=struct_res.detected_format)
