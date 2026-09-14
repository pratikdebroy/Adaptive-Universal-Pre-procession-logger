"""
Tests for the two-tier Trust Gate:
A. Parser Safety Validator (structure, allowlisted fields, no executable code)
B. Event Trust Gate (IP validation, port range, protocol, actions, confidence)
"""

import pytest
from backend.models import ParserSpecification, ValidationResult
from backend.validation.trust_gate import ParserSafetyValidator, HybridTrustGate


def test_parser_safety_allows_valid_spec():
    validator = ParserSafetyValidator()
    spec = ParserSpecification(
        template="SRC=<*> DST=<*> PORT=<*>",
        fields={"SRC": "source.ip", "DST": "destination.ip", "PORT": "destination.port"},
        field_types={"SRC": "ip", "DST": "ip", "PORT": "port"},
    )
    result = validator.validate_spec(spec)
    assert result.safe is True
    assert len(result.failure_reasons) == 0


def test_parser_safety_blocks_executable_code():
    validator = ParserSafetyValidator()
    spec = ParserSpecification(
        template="LOG import os; os.system('cat /etc/passwd')",
        fields={"LOG": "message"},
    )
    result = validator.validate_spec(spec)
    assert result.safe is False
    assert any("Executable pattern" in r for r in result.failure_reasons)


def test_parser_safety_blocks_disallowed_target_fields():
    validator = ParserSafetyValidator()
    spec = ParserSpecification(
        template="SRC=<*>",
        fields={"SRC": "unauthorized.internal.field.name"},
    )
    result = validator.validate_spec(spec)
    assert result.safe is False
    assert any("not in the allowlist" in r or "not in allowlist" in r for r in result.failure_reasons)


def test_trust_gate_approves_valid_event():
    gate = HybridTrustGate()
    parsed = {
        "source.ip": "10.10.1.25",
        "destination.ip": "172.16.2.10",
        "destination.port": 443,
        "network.transport": "TCP",
        "action": "ALLOW",
    }
    result = gate.validate(parsed, confidence=0.95)
    assert result.result == ValidationResult.APPROVED
    assert result.overall_failed == 0


def test_trust_gate_rejects_invalid_ip():
    gate = HybridTrustGate()
    parsed = {
        "source.ip": "999.999.999.999",
        "destination.ip": "172.16.2.10",
        "destination.port": 443,
        "action": "ALLOW",
    }
    result = gate.validate(parsed, confidence=0.95)
    assert result.result == ValidationResult.QUARANTINED
    assert any("Invalid IP" in r for r in result.failure_reasons)


def test_trust_gate_rejects_invalid_port():
    gate = HybridTrustGate()
    parsed = {
        "source.ip": "10.10.1.25",
        "destination.ip": "172.16.2.10",
        "destination.port": 99999,  # Beyond 65535
        "action": "ALLOW",
    }
    result = gate.validate(parsed, confidence=0.95)
    assert result.result == ValidationResult.QUARANTINED
    assert any("Port out of range" in r for r in result.failure_reasons)


def test_trust_gate_rejects_unknown_protocol():
    gate = HybridTrustGate()
    parsed = {
        "source.ip": "10.10.1.25",
        "destination.ip": "172.16.2.10",
        "destination.port": 443,
        "network.transport": "NON_EXISTENT_PROTO_XYZ",
        "action": "ALLOW",
    }
    result = gate.validate(parsed, confidence=0.95)
    assert result.result == ValidationResult.QUARANTINED
    assert any("Unknown protocol" in r for r in result.failure_reasons)


def test_trust_gate_rejects_low_confidence():
    gate = HybridTrustGate()
    parsed = {
        "source.ip": "10.10.1.25",
        "destination.ip": "172.16.2.10",
        "action": "ALLOW",
    }
    result = gate.validate(parsed, confidence=0.40)  # Below 0.70 threshold
    assert result.result == ValidationResult.QUARANTINED
    assert any("below threshold" in r for r in result.failure_reasons)
