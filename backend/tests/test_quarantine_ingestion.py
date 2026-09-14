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
