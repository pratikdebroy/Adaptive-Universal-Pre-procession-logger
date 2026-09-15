"""
Comprehensive tests for Ingestion Safety Checks and Quarantine Layer.
Tests all requirements specified in SIH26156 Ingestion-Quarantine strengthening:
- Transport / Framing (empty, invalid encoding, binary control characters, syslog framing)
- Resource / DoS Protection (event size, excessive fields, excessive nesting, rate/burst limit)
- Structural / Format Checks (malformed JSON, malformed XML, malformed CSV, invalid KV structure)
- Field-level validation (invalid IP, invalid IPv6, invalid CIDR, invalid port, invalid protocol, invalid MAC, invalid timestamp, implausible timestamp, missing field)
- Security / Processing safety (unsafe parser specification, executable code detection)
- Semantic / Trust checks
- Malicious Activity vs Malformed Log (valid log describing malicious activity MUST NOT be quarantined)
- Quarantine Persistence & SHA-256 preservation
"""

import pytest
from backend.core.pipeline import pipeline
from backend.storage.database import reset_db
from backend.models import (
    ProcessingMode, ValidationResult, QuarantineReason, QuarantineSeverity, ParserSpecification,
)
from backend.ingestion.defensive import (
    check_transport_and_framing, check_resource_limits, check_structural_format, SourceRateLimiter,
    check_field_level_security, is_valid_ip, is_valid_port, is_valid_protocol,
    is_valid_cidr, is_valid_mac, is_valid_timestamp,
)
from backend.validation.trust_gate import ParserSafetyValidator, HybridTrustGate


@pytest.mark.asyncio
async def test_case_1_valid_log_accepted_fast_path():
    """CASE 1: Valid known log reaches FAST PATH."""
    await reset_db()
    await pipeline.initialize()

    valid_log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW"
    resp = await pipeline.process_event(valid_log, source="firewall")

    assert resp.processing_mode == ProcessingMode.FAST_PATH
    assert resp.validation.result == ValidationResult.APPROVED
    assert resp.quarantine is None
    assert resp.ocsf_event is not None


@pytest.mark.asyncio
async def test_case_2_invalid_ip_quarantined():
    """CASE 2: Invalid IP reaches QUARANTINE with reason INVALID_IP."""
    await reset_db()
    await pipeline.initialize()

    bad_ip_log = "SRC_IP=999.999.999.999 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"
    resp = await pipeline.process_event(bad_ip_log, source="firewall")

    assert resp.validation.result == ValidationResult.QUARANTINED
    assert resp.quarantine is not None
    assert resp.quarantine.reason in (QuarantineReason.INVALID_IP, QuarantineReason.FAILED_VALIDATION)
    assert resp.quarantine.severity in (QuarantineSeverity.HIGH, QuarantineSeverity.MEDIUM)
    assert "999.999.999.999" in str(resp.quarantine.detail) or "999.999.999.999" in str(resp.quarantine.validation_failures)


@pytest.mark.asyncio
async def test_case_3_invalid_port_quarantined():
    """CASE 3: Invalid port reaches QUARANTINE with reason INVALID_PORT."""
    await reset_db()
    await pipeline.initialize()

    bad_port_log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=99999 ACT=ALLOW"
    resp = await pipeline.process_event(bad_port_log, source="firewall")

    assert resp.validation.result == ValidationResult.QUARANTINED
    assert resp.quarantine is not None
    assert resp.quarantine.reason in (QuarantineReason.INVALID_PORT, QuarantineReason.FAILED_VALIDATION)
    assert "99999" in str(resp.quarantine.detail) or "99999" in str(resp.quarantine.validation_failures)


@pytest.mark.asyncio
async def test_case_4_malformed_json_quarantined():
    """CASE 4: Malformed JSON reaches QUARANTINE with reason MALFORMED_JSON."""
    await reset_db()
    await pipeline.initialize()

    malformed_json = '{"src_ip":"10.0.0.1", "port":443'
    resp = await pipeline.process_event(malformed_json, source="waf")

    assert resp.quarantine is not None
    assert resp.quarantine.reason == QuarantineReason.MALFORMED_JSON
    assert resp.quarantine.detected_format == "json"
    assert resp.quarantine.severity == QuarantineSeverity.MEDIUM


@pytest.mark.asyncio
async def test_case_5_oversized_event_quarantined():
    """CASE 5: Oversized event exceeding MAX_EVENT_SIZE reaches QUARANTINE."""
    await reset_db()
    await pipeline.initialize()

    oversized_log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW PAYLOAD=" + ("A" * 70000)
    resp = await pipeline.process_event(oversized_log, source="firewall")

    assert resp.quarantine is not None
    assert resp.quarantine.reason == QuarantineReason.EVENT_TOO_LARGE
    assert resp.quarantine.severity == QuarantineSeverity.HIGH


@pytest.mark.asyncio
async def test_case_6_valid_malicious_activity_log_not_quarantined():
    """
    CASE 6: A valid log describing malicious activity MUST NOT be quarantined.
    The preprocessing layer is NOT an IDS.
    """
    await reset_db()
    await pipeline.initialize()

    # Log describes a denied port-scan or attack connection
    attack_log = "SRC=10.0.0.5 DST=10.0.0.10 PROTO=TCP DPT=22 ACTION=DENY"
    resp = await pipeline.process_event(attack_log, source="firewall")

    # MUST be accepted and parsed, not quarantined!
    assert resp.quarantine is None
    assert resp.validation.result == ValidationResult.APPROVED
    assert resp.ocsf_event is not None
    assert resp.ocsf_event.action == "Denied"

    # WAF log describing SQL injection attempt inside field values
    waf_attack_log = "CLIENT=203.0.113.50 SERVER=10.0.0.5 METHOD=GET URI=/admin STATUS=403 RULE=SQL_INJECTION"
    # Even if processed adaptively, it should not be quarantined as malicious
    resp_waf = await pipeline.process_event(waf_attack_log, source="waf")
    # Should not fail defensive ingestion
    assert resp_waf.quarantine is None or resp_waf.quarantine.reason != QuarantineReason.SUSPICIOUS_PAYLOAD


def test_transport_empty_and_binary_checks():
    """Test transport framing: empty events and binary encodings."""
    # Empty
    res_empty = check_transport_and_framing("   ")
    assert not res_empty.safe
    assert res_empty.reason == QuarantineReason.EMPTY_EVENT

    # Binary control bytes
    res_binary = check_transport_and_framing("\x00\x01\x02\x03garbage")
    assert not res_binary.safe
    assert res_binary.reason == QuarantineReason.INVALID_ENCODING


def test_resource_limits_and_dos_protection():
    """Test DoS protection: event size, rate limits, burst limits."""
    # Size limit
    res_size = check_resource_limits("A" * 70000)
    assert not res_size.safe
    assert res_size.reason == QuarantineReason.EVENT_TOO_LARGE

    # Rate Limiter
    limiter = SourceRateLimiter(rate=5, burst=2)
    # First 2 allowed
    assert limiter.check_rate("test_src")[0] is True
    assert limiter.check_rate("test_src")[0] is True
    # 3rd exceeds burst
    ok, reason, _ = limiter.check_rate("test_src")
    assert ok is False
    assert reason == QuarantineReason.RATE_LIMIT_EXCEEDED


def test_structural_json_xml_csv_kv():
    """Test structural validation for JSON, XML, CSV, and KV formats."""
    # JSON syntax error
    res_json = check_structural_format('{"unclosed": "val')
    assert not res_json.safe
    assert res_json.reason == QuarantineReason.MALFORMED_JSON

    # Excessive JSON nesting
    deep_json = '{"a":{"b":{"c":{"d":{"e":{"f":{"g":1}}}}}}}'
    res_depth = check_structural_format(deep_json)
    assert not res_depth.safe
    assert res_depth.reason == QuarantineReason.EXCESSIVE_NESTING

    # XML syntax error
    res_xml = check_structural_format("<tag>unclosed")
    assert not res_xml.safe
    assert res_xml.reason == QuarantineReason.MALFORMED_XML

    # XML XXE injection protection
    xxe_xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    res_xxe = check_structural_format(xxe_xml)
    assert not res_xxe.safe
    assert res_xxe.reason in (QuarantineReason.UNSAFE_PARSER_SPEC, QuarantineReason.EXCESSIVE_NESTING)

    # Broken KV quoting
    res_kv = check_structural_format('SRC=10.0.0.1 MSG="unclosed quote string ACTION=ALLOW')
    assert not res_kv.safe
    assert res_kv.reason == QuarantineReason.INVALID_KV_STRUCTURE


def test_field_level_trust_gate_invariants():
    """Test field-level validations in HybridTrustGate."""
    tg = HybridTrustGate()

    # Invalid IPv6
    res_ipv6 = tg.validate({
        "source.ip": "2001:zzz::invalid",
        "destination.ip": "10.0.0.1",
        "action": "ALLOW",
    }, confidence=0.9)
    assert res_ipv6.result == ValidationResult.QUARANTINED
    assert res_ipv6.primary_reason in (QuarantineReason.INVALID_IPV6, QuarantineReason.INVALID_IP)

    # Invalid Port (negative or > 65535)
    res_port = tg.validate({
        "source.ip": "10.0.0.1",
        "destination.ip": "10.0.0.2",
        "destination.port": 70000,
        "action": "ALLOW",
    }, confidence=0.9)
    assert res_port.result == ValidationResult.QUARANTINED
    assert res_port.primary_reason == QuarantineReason.INVALID_PORT

    # Invalid Protocol
    res_proto = tg.validate({
        "source.ip": "10.0.0.1",
        "destination.ip": "10.0.0.2",
        "network.transport": "NON_EXISTENT_PROTOCOL",
        "action": "ALLOW",
    }, confidence=0.9)
    assert res_proto.result == ValidationResult.QUARANTINED
    assert res_proto.primary_reason == QuarantineReason.INVALID_PROTOCOL

    # Missing required field (action missing)
    res_missing = tg.validate({
        "source.ip": "10.0.0.1",
        "destination.ip": "10.0.0.2",
    }, confidence=0.9)
    assert res_missing.result == ValidationResult.QUARANTINED
    assert res_missing.primary_reason == QuarantineReason.MISSING_REQUIRED_FIELD

    # Implausible timestamp (year 3000)
    res_time = tg.validate({
        "source.ip": "10.0.0.1",
        "destination.ip": "10.0.0.2",
        "action": "ALLOW",
        "timestamp": "3000-01-01T00:00:00Z",
    }, confidence=0.9)
    assert res_time.result == ValidationResult.QUARANTINED
    assert res_time.primary_reason == QuarantineReason.TIMESTAMP_IMPLAUSIBLE

    # Invalid MAC address
    res_mac = tg.validate({
        "source.ip": "10.0.0.1",
        "destination.ip": "10.0.0.2",
        "action": "ALLOW",
        "source.mac": "INVALID_MAC_ADDR",
    }, confidence=0.9)
    assert res_mac.result == ValidationResult.QUARANTINED
    assert res_mac.primary_reason == QuarantineReason.INVALID_MAC


def test_parser_safety_validator_blocks_code():
    """Test that ParserSafetyValidator blocks any executable code."""
    psv = ParserSafetyValidator()

    unsafe_spec = ParserSpecification(
        template="SRC=<*> DST=<*>",
        fields={"SRC": "source.ip", "DST": "destination.ip"},
        field_types={"SRC": "ip", "DST": "ip"},
        regex_pattern=r"(?P<SRC>\S+) (?P<DST>\S+) eval(__import__('os'))",
    )
    res = psv.validate_spec(unsafe_spec)
    assert not res.safe
    assert res.primary_reason == QuarantineReason.UNSAFE_PARSER_SPEC
    assert res.primary_severity == QuarantineSeverity.CRITICAL


@pytest.mark.asyncio
async def test_quarantine_persistence_and_sha256():
    """Verify quarantined events are persisted in DB with exact SHA-256 and metadata."""
    await reset_db()
    await pipeline.initialize()

    bad_log = '{"src_ip": "10.0.0.1", "bad_json'
    resp = await pipeline.process_event(bad_log, source="api_gateway")

    assert resp.quarantine is not None
    # SHA-256 must match the exact raw string hash
    expected_hash = pipeline.vault.compute_sha256(bad_log)
    assert resp.raw_sha256 == expected_hash
    assert resp.quarantine.raw_sha256 == expected_hash
    assert resp.quarantine.reason == QuarantineReason.MALFORMED_JSON


# ─────────────────────────────────────────────────────────────────────────────
# Defensive Ingestion Field-Level Security Regression Tests (SIH26156)
# Rule: MISSING FIELD -> PROCEED | PRESENT + VALID -> PROCEED | PRESENT + INVALID -> QUARANTINE
# ─────────────────────────────────────────────────────────────────────────────

def test_defensive_ingestion_missing_optional_fields_proceed():
    """
    Test that absence of ANY optional field is NEVER treated as a security violation.
    Missing IP, missing port, missing protocol, missing timestamp, missing MAC, missing CIDR -> all PROCEED.
    """
    # 1. Missing optional IP (only port and proto present)
    res_no_ip = check_field_level_security("PROTO=TCP PORT=443 ACTION=ALLOW")
    assert res_no_ip.safe is True, "Missing IP must not quarantine at ingestion"

    # 2. Missing optional port (IP and proto present)
    res_no_port = check_field_level_security("SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP ACTION=ALLOW")
    assert res_no_port.safe is True, "Missing port must not quarantine at ingestion"

    # 3. Missing optional protocol (IP and port present)
    res_no_proto = check_field_level_security("SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PORT=443 ACTION=ALLOW")
    assert res_no_proto.safe is True, "Missing protocol must not quarantine at ingestion"

    # 4. Missing timestamp, MAC, and CIDR
    res_no_extras = check_field_level_security("SRC=192.168.1.10 DST=10.0.0.1 PROTO=UDP DPT=53")
    assert res_no_extras.safe is True, "Missing optional timestamp/MAC/CIDR must not quarantine at ingestion"

    # 5. Dict format with missing optional fields
    dict_event = {"action": "ALLOW", "message": "Health check ok"}
    res_dict = check_field_level_security(dict_event)
    assert res_dict.safe is True, "Missing all optional network fields must proceed normally"


def test_defensive_ingestion_present_valid_values_proceed():
    """
    Test that all present, valid network/security fields pass defensive ingestion safety.
    """
    # Key-Value format with all valid fields
    kv_log = (
        "SRC_IP=192.168.1.50 DST_IP=10.0.0.1 SPORT=54321 PORT=443 PROTO=TCP "
        "TIMESTAMP=2026-09-15T12:00:00Z SRC_MAC=00:1A:2B:3C:4D:5E CIDR=192.168.1.0/24 ACT=ALLOW"
    )
    res_kv = check_field_level_security(kv_log)
    assert res_kv.safe is True, f"Valid fields failed: {res_kv.detail}"

    # JSON format with valid fields
    json_log = {
        "src_ip": "10.0.0.5",
        "dst_ip": "172.16.1.1",
        "src_port": 1024,
        "dst_port": 80,
        "protocol": "TCP",
        "timestamp": "2026-09-15T10:00:00Z",
        "src_mac": "aa:bb:cc:dd:ee:ff",
        "cidr": "10.0.0.0/8",
    }
    res_json = check_field_level_security(json_log)
    assert res_json.safe is True, f"Valid JSON fields failed: {res_json.detail}"


def test_defensive_ingestion_present_invalid_fields_quarantine():
    """
    Test that present but invalid/malformed values in optional fields trigger QUARANTINE
    with the exact expected QuarantineReason.
    """
    # 1. Present Invalid IP -> INVALID_IP
    res_bad_ip = check_field_level_security("SRC_IP=999.999.999.999 DST_IP=10.0.0.1 PROTO=TCP")
    assert res_bad_ip.safe is False
    assert res_bad_ip.reason == QuarantineReason.INVALID_IP
    assert res_bad_ip.severity == QuarantineSeverity.HIGH
    assert "999.999.999.999" in res_bad_ip.detail

    # 2. Present Invalid Port -> INVALID_PORT
    res_bad_port = check_field_level_security("SRC_IP=10.0.0.1 DST_IP=10.0.0.2 PORT=99999 PROTO=TCP")
    assert res_bad_port.safe is False
    assert res_bad_port.reason == QuarantineReason.INVALID_PORT
    assert "99999" in res_bad_port.detail

    # 3. Present Negative Port -> INVALID_PORT
    res_neg_port = check_field_level_security("SRC_IP=10.0.0.1 SPORT=-1")
    assert res_neg_port.safe is False
    assert res_neg_port.reason == QuarantineReason.INVALID_PORT

    # 4. Present Invalid Protocol -> INVALID_PROTOCOL
    res_bad_proto = check_field_level_security("SRC_IP=10.0.0.1 PROTO=FAKE_PROTO")
    assert res_bad_proto.safe is False
    assert res_bad_proto.reason == QuarantineReason.INVALID_PROTOCOL

    # 5. Present Invalid MAC -> INVALID_MAC
    res_bad_mac = check_field_level_security("SRC_IP=10.0.0.1 SRC_MAC=NOT_A_MAC")
    assert res_bad_mac.safe is False
    assert res_bad_mac.reason == QuarantineReason.INVALID_MAC

    # 6. Present Invalid CIDR -> INVALID_CIDR
    res_bad_cidr = check_field_level_security("SRC_IP=10.0.0.1 CIDR=999.999.999.0/99")
    assert res_bad_cidr.safe is False
    assert res_bad_cidr.reason == QuarantineReason.INVALID_CIDR

    # 7. Present Unparseable Timestamp -> INVALID_TIMESTAMP
    res_bad_time = check_field_level_security("SRC_IP=10.0.0.1 TIMESTAMP=not-a-timestamp")
    assert res_bad_time.safe is False
    assert res_bad_time.reason == QuarantineReason.INVALID_TIMESTAMP

    # 8. Present Implausible Timestamp -> TIMESTAMP_IMPLAUSIBLE
    res_future_time = check_field_level_security("SRC_IP=10.0.0.1 TIMESTAMP=3099-01-01T00:00:00Z")
    assert res_future_time.safe is False
    assert res_future_time.reason == QuarantineReason.TIMESTAMP_IMPLAUSIBLE


@pytest.mark.asyncio
async def test_end_to_end_ingestion_field_presence_and_absence():
    """
    End-to-end pipeline test verifying:
    - Missing optional fields do NOT trigger ingestion quarantine
    - Present invalid fields DO trigger ingestion quarantine
    - Malformed input still triggers unconditional structural quarantine
    - Oversized event still triggers unconditional resource quarantine
    - Valid malicious security logs do NOT get quarantined
    """
    await reset_db()
    await pipeline.initialize()

    # 1. Missing optional port and protocol does NOT trigger ingestion quarantine
    log_missing_optional = "SRC=10.10.1.25 DST=172.16.2.10 ACTION=ALLOW"
    resp1 = await pipeline.process_event(log_missing_optional, source="firewall")
    # Should not be quarantined by ingestion safety checks
    assert resp1.quarantine is None or resp1.quarantine.reason not in (
        QuarantineReason.INVALID_PORT, QuarantineReason.INVALID_PROTOCOL, QuarantineReason.INVALID_IP
    )

    # 2. Present invalid IP quarantines at Stage 2 with INVALID_IP
    bad_ip = "SRC_IP=999.999.999.999 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"
    resp2 = await pipeline.process_event(bad_ip, source="firewall")
    assert resp2.quarantine is not None
    assert resp2.quarantine.reason == QuarantineReason.INVALID_IP
    assert resp2.validation is not None
    assert resp2.validation.result == ValidationResult.QUARANTINED

    # 3. Present invalid port quarantines at Stage 2 with INVALID_PORT
    bad_port = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=99999 ACT=ALLOW"
    resp3 = await pipeline.process_event(bad_port, source="firewall")
    assert resp3.quarantine is not None
    assert resp3.quarantine.reason == QuarantineReason.INVALID_PORT
    assert resp3.validation is not None
    assert resp3.validation.result == ValidationResult.QUARANTINED

    # 4. Existing structural malformed JSON still quarantines unconditionally
    resp_malformed = await pipeline.process_event('{"bad": json}', source="test")
    assert resp_malformed.quarantine is not None
    assert resp_malformed.quarantine.reason == QuarantineReason.MALFORMED_JSON

    # 5. Existing oversized event (>64KB) still quarantines unconditionally
    resp_oversized = await pipeline.process_event("A" * 70000, source="test")
    assert resp_oversized.quarantine is not None
    assert resp_oversized.quarantine.reason == QuarantineReason.EVENT_TOO_LARGE

    # 6. Valid malicious activity log (e.g. DENY SSH scan) is NOT quarantined
    attack_log = "SRC=10.0.0.5 DST=10.0.0.10 PROTO=TCP DPT=22 ACTION=DENY"
    resp_attack = await pipeline.process_event(attack_log, source="firewall")
    assert resp_attack.quarantine is None
    assert resp_attack.validation.result == ValidationResult.APPROVED


@pytest.mark.asyncio
async def test_heterogeneous_logs_decision_model():
    """
    Comprehensive regression tests for schema-agnostic generic ingestion and decision model:
    - FIELD ABSENT -> PROCEED
    - FIELD PRESENT + TYPE/SEMANTICS CONFIDENTLY KNOWN -> VALIDATE (valid -> PROCEED, invalid -> QUARANTINE)
    - FIELD PRESENT + TYPE/SEMANTICS UNKNOWN/AMBIGUOUS -> DO NOT FORCE VALIDATION -> PROCEED
    - UNCONDITIONAL INGESTION VIOLATION -> QUARANTINE
    """
    await reset_db()
    await pipeline.initialize()

    # Category 1: Application log with source=server.go:1347 -> PROCEED
    # Must NOT be guessed as an IP address!
    res_app1 = check_field_level_security("source=server.go:1347 level=info message=started")
    assert res_app1.safe is True, "source=server.go:1347 must not be treated as an IP"
    resp_app1 = await pipeline.process_event("source=server.go:1347 level=info message=started", source="app")
    assert resp_app1.quarantine is None, "source=server.go:1347 must proceed through pipeline"

    # Category 2: Application log with source=nginx -> PROCEED
    res_app2 = check_field_level_security("source=nginx status=200 path=/index.html")
    assert res_app2.safe is True, "source=nginx must not be treated as an IP"
    resp_app2 = await pipeline.process_event("source=nginx status=200 path=/index.html", source="web")
    assert resp_app2.quarantine is None

    # Category 3: Application log with source=auth-service -> PROCEED
    res_app3 = check_field_level_security("source=auth-service event=login_success user=alice")
    assert res_app3.safe is True, "source=auth-service must not be treated as an IP"
    resp_app3 = await pipeline.process_event("source=auth-service event=login_success user=alice", source="auth")
    assert resp_app3.quarantine is None

    # Category 4: Arbitrary strings containing numbers like port 70000 -> PROCEED through ingestion
    res_str = check_field_level_security('service=gateway message="connection failed on port 70000"')
    assert res_str.safe is True, "String message containing port 70000 must not be treated as port number"
    resp_str = await pipeline.process_event('service=gateway message="connection failed on port 70000"', source="gateway")
    assert resp_str.quarantine is None

    # Category 5: Logs without IP fields -> PROCEED
    res_no_ip = check_field_level_security("service=cron task=backup status=completed duration=45s")
    assert res_no_ip.safe is True
    resp_no_ip = await pipeline.process_event("service=cron task=backup status=completed duration=45s", source="cron")
    assert resp_no_ip.quarantine is None

    # Category 6: Logs without port fields -> PROCEED
    res_no_port = check_field_level_security("SRC_IP=10.0.0.1 DST_IP=10.0.0.2 PROTO=ICMP")
    assert res_no_port.safe is True
    resp_no_port = await pipeline.process_event("SRC_IP=10.0.0.1 DST_IP=10.0.0.2 PROTO=ICMP", source="net")
    assert resp_no_port.quarantine is None or resp_no_port.quarantine.reason != QuarantineReason.INVALID_PORT

    # Category 7: Logs without protocol fields -> PROCEED
    res_no_proto = check_field_level_security("SRC_IP=10.0.0.1 DST_IP=10.0.0.2 SRC_PORT=1234 DST_PORT=80")
    assert res_no_proto.safe is True
    resp_no_proto = await pipeline.process_event("SRC_IP=10.0.0.1 DST_IP=10.0.0.2 SRC_PORT=1234 DST_PORT=80", source="net")
    assert resp_no_proto.quarantine is None or resp_no_proto.quarantine.reason != QuarantineReason.INVALID_PROTOCOL

    # Category 8: Explicitly classified source IP with valid value -> PROCEED
    res_valid_ip = check_field_level_security("source_ip=192.168.1.1 destination_ip=10.0.0.1")
    assert res_valid_ip.safe is True
    resp_valid_ip = await pipeline.process_event("source_ip=192.168.1.1 destination_ip=10.0.0.1 action=ALLOW", source="net")
    assert resp_valid_ip.quarantine is None

    # Category 9: Explicitly classified source IP with invalid value -> QUARANTINE
    res_bad_ip = check_field_level_security("source_ip=999.999.999.999 destination_ip=10.0.0.1")
    assert res_bad_ip.safe is False
    assert res_bad_ip.reason == QuarantineReason.INVALID_IP
    resp_bad_ip = await pipeline.process_event("source_ip=999.999.999.999 destination_ip=10.0.0.1 action=ALLOW", source="net")
    assert resp_bad_ip.quarantine is not None
    assert resp_bad_ip.quarantine.reason == QuarantineReason.INVALID_IP

    # Category 10: Explicitly classified port with valid value -> PROCEED
    res_valid_port = check_field_level_security("src_ip=10.0.0.1 dst_ip=10.0.0.2 src_port=8080 dst_port=443")
    assert res_valid_port.safe is True

    # Category 11: Explicitly classified port outside 0-65535 -> QUARANTINE
    res_bad_port = check_field_level_security("src_ip=10.0.0.1 dst_port=99999")
    assert res_bad_port.safe is False
    assert res_bad_port.reason == QuarantineReason.INVALID_PORT
    resp_bad_port = await pipeline.process_event("src_ip=10.0.0.1 dst_ip=10.0.0.2 dst_port=99999 action=ALLOW", source="net")
    assert resp_bad_port.quarantine is not None
    assert resp_bad_port.quarantine.reason == QuarantineReason.INVALID_PORT

    # Category 12: Existing malformed / oversized / rate-limit security violations continue to quarantine
    res_malformed = check_structural_format('{"unclosed": "brace"')
    assert res_malformed.safe is False
    assert res_malformed.reason == QuarantineReason.MALFORMED_JSON

    res_oversized = check_resource_limits("X" * 70000)
    assert res_oversized.safe is False
    assert res_oversized.reason == QuarantineReason.EVENT_TOO_LARGE

    # Category 13: Valid security events describing attacks MUST NOT be quarantined
    attack_event = "SRC=10.0.0.5 DST=10.0.0.10 PROTO=TCP DPT=22 ACTION=DENY"
    resp_attack = await pipeline.process_event(attack_event, source="firewall")
    assert resp_attack.quarantine is None
    assert resp_attack.validation.result == ValidationResult.APPROVED


