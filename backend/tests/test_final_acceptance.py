"""
Final Acceptance Test Suite (SIH26156)
Individual tests for Acceptance Criteria A through M.
Strict validation without mocks.
"""

import pytest
import pytest_asyncio
import hashlib
from backend.core.pipeline import pipeline
from backend.models import (
    ProcessingMode, ValidationResult, QuarantineReason, ParserSpecification, ParserStatus
)
from backend.validation.trust_gate import ParserSafetyValidator


@pytest_asyncio.fixture(autouse=True)
async def setup_pipeline():
    """Ensure pipeline and database are clean before every test."""
    await pipeline.reset()
    yield


@pytest.mark.asyncio
async def test_a_known_v1_fast_path():
    """A. Known V1: Fast Path hit, tier3_invocations == 0."""
    v1_log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW"
    resp = await pipeline.process_event(v1_log, source="firewall")
    assert resp.processing_mode == ProcessingMode.FAST_PATH
    assert resp.confidence >= 0.85
    assert resp.tier3_invocations == 0
    assert pipeline.metrics["tier3_count"] == 0
    assert resp.ocsf_event is not None
    assert resp.ocsf_event.action == "Allowed"


@pytest.mark.asyncio
async def test_b_drifted_v2_adaptive_pipeline():
    """B. Drifted V2: Fast Path Miss -> BDPT -> Structural -> Tier-3 -> Trust Gate APPROVED -> Active."""
    v2_log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"
    resp = await pipeline.process_event(v2_log, source="firewall", auto_promote=True)
    assert resp.processing_mode == ProcessingMode.TIER3_ADAPTIVE
    assert resp.tier3_invocations == 1
    assert pipeline.metrics["tier3_count"] == 1
    assert resp.validation is not None
    assert resp.validation.result == ValidationResult.APPROVED
    assert resp.ocsf_event is not None
    assert resp.ocsf_event.src_endpoint["ip"] == "10.10.1.25"
    assert resp.ocsf_event.dst_endpoint["ip"] == "172.16.2.10"
    assert resp.ocsf_event.dst_endpoint["port"] == 443


@pytest.mark.asyncio
async def test_c_v2_replay_fast_path():
    """C. V2 Replay: Fast Path hit, tier3_invocations == 0."""
    # First adapt and promote V2
    v2_log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"
    await pipeline.process_event(v2_log, source="firewall", auto_promote=True)
    tier3_before = pipeline.metrics["tier3_count"]

    # Replay with another V2 log
    v2_replay_log = "SRC_IP=192.168.1.100 DST_IP=10.0.0.1 PROTO=UDP PORT=53 ACT=ALLOW"
    resp_c = await pipeline.process_event(v2_replay_log, source="firewall")
    assert resp_c.processing_mode == ProcessingMode.FAST_PATH
    assert resp_c.tier3_invocations == 0
    assert pipeline.metrics["tier3_count"] == tier3_before
    assert resp_c.ocsf_event is not None
    assert resp_c.ocsf_event.src_endpoint["ip"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_d_invalid_ip_quarantined():
    """D. Invalid IP: SRC_IP=999.999.999.999 -> Quarantined with INVALID_IP."""
    invalid_ip_log = "SRC_IP=999.999.999.999 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"
    resp = await pipeline.process_event(invalid_ip_log, source="firewall")
    assert resp.quarantine is not None
    assert resp.quarantine.status == "QUARANTINED"
    assert resp.quarantine.reason == QuarantineReason.INVALID_IP


@pytest.mark.asyncio
async def test_e_invalid_port_quarantined():
    """E. Invalid Port: PORT=99999 -> Quarantined with INVALID_PORT."""
    invalid_port_log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=99999 ACT=ALLOW"
    resp = await pipeline.process_event(invalid_port_log, source="firewall")
    assert resp.quarantine is not None
    assert resp.quarantine.status == "QUARANTINED"
    assert resp.quarantine.reason == QuarantineReason.INVALID_PORT


@pytest.mark.asyncio
async def test_f_malformed_event_quarantined():
    """F. Malformed Event: Whitespace/binary garbage -> Quarantined."""
    malformed_log = "\x00\x01\x02binarygarbage\xff\xfe"
    resp = await pipeline.process_event(malformed_log, source="firewall")
    assert resp.quarantine is not None
    assert resp.quarantine.status == "QUARANTINED"


@pytest.mark.asyncio
async def test_g_oversized_event_quarantined():
    """G. Oversized Event: Payload > 64KB -> Quarantined with EVENT_TOO_LARGE."""
    oversized_log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW PAYLOAD=" + ("X" * 70000)
    resp = await pipeline.process_event(oversized_log, source="firewall")
    assert resp.quarantine is not None
    assert resp.quarantine.status == "QUARANTINED"
    assert resp.quarantine.reason == QuarantineReason.EVENT_TOO_LARGE


@pytest.mark.asyncio
async def test_h_raw_event_lossless_preservation():
    """H. Raw Event: Lossless preservation in vault with raw SHA-256 match."""
    raw_sample = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW"
    resp = await pipeline.process_event(raw_sample, source="firewall")
    raw_stored = pipeline.vault.retrieve(resp.event_id)
    assert raw_stored is not None
    assert raw_stored.raw_message == raw_sample
    expected_sha = hashlib.sha256(raw_sample.encode("utf-8")).hexdigest()
    assert raw_stored.raw_sha256 == expected_sha
    assert resp.raw_sha256 == expected_sha


@pytest.mark.asyncio
async def test_i_unsafe_parser_specification_blocked():
    """I. Unsafe Parser: Blocked by ParserSafetyValidator with UNSAFE_PARSER_SPEC."""
    safety_validator = ParserSafetyValidator()
    unsafe_spec = ParserSpecification(
        template="SRC=<*> DST=<*>",
        field_separator="=",
        entry_separator=" ",
        fields={"SRC": "source.ip", "CMD": "__import__('os').system('id')"},
        field_types={"SRC": "ip", "CMD": "string"},
    )
    safety_res = safety_validator.validate_spec(unsafe_spec)
    assert not safety_res.safe
    assert safety_res.primary_reason == QuarantineReason.UNSAFE_PARSER_SPEC


@pytest.mark.asyncio
async def test_j_tampered_evidence_detected():
    """J. Tampered Evidence: Modification detected as Merkle root mismatch."""
    from backend.api.integrity import ledger
    from backend.integrity.merkle import MerkleTree

    raw_sample = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW"
    resp = await pipeline.process_event(raw_sample, source="firewall")

    vault_events = pipeline.vault.list_events(limit=10)
    assert len(vault_events) > 0
    hashes = [pipeline.vault.retrieve(eid).raw_sha256 for eid in vault_events]
    await ledger.commit_batch(vault_events, hashes)
    latest_ledger = await ledger.get_latest()

    # Tamper 1 byte in vault
    pipeline.vault.tamper_for_demo(vault_events[0])
    intact, stored_hash, recomputed_hash = pipeline.vault.verify_integrity(vault_events[0])
    assert not intact
    assert stored_hash != recomputed_hash

    # Recomputed root must not match ledger root
    new_hashes = [pipeline.vault.verify_integrity(eid)[2] for eid in vault_events]
    tampered_tree = MerkleTree(new_hashes)
    assert tampered_tree.root != latest_ledger.merkle_root


@pytest.mark.asyncio
async def test_k_rollback_deactivates_and_restores():
    """K. Rollback: Deactivates promoted parser and restores previously active compatible parser."""
    # First promote drifted format
    v2_log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"
    resp_b = await pipeline.process_event(v2_log, source="firewall", auto_promote=True)
    promoted_parser_id = resp_b.parser_id
    assert promoted_parser_id != ""

    rollback_ok = await pipeline.registry.rollback(promoted_parser_id)
    assert rollback_ok

    # The promoted parser must now be ROLLED_BACK
    promoted_rec = await pipeline.registry.get_by_id(promoted_parser_id)
    assert promoted_rec is not None
    assert promoted_rec.status == ParserStatus.ROLLED_BACK

    # Previously active compatible parser (firewall_v1) is ACTIVE in registry & fast path
    baseline_rec = await pipeline.registry.get_by_id("firewall_v1")
    assert baseline_rec is not None
    assert baseline_rec.status == ParserStatus.ACTIVE
    assert "firewall_v1" in pipeline.fast_path.get_loaded_parsers()
    assert promoted_parser_id not in pipeline.fast_path.get_loaded_parsers()


@pytest.mark.asyncio
async def test_l_valid_malicious_activity_log():
    """L. Valid Malicious Activity Log: Attacker payloads in valid security logs parsed (not quarantined)."""
    security_log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=80 ACTION=DENY MSG=SQLi_ATTACK_SELECT_FROM_USERS"
    resp_l = await pipeline.process_event(security_log, source="firewall")
    assert resp_l.quarantine is None
    assert resp_l.processing_mode == ProcessingMode.FAST_PATH
    assert resp_l.ocsf_event is not None
    assert resp_l.ocsf_event.action == "Denied"
    assert resp_l.tier3_invocations == 0

    ids_log = '[**] [1:2100:5] GPL EXPLOIT CVE-2021-44228 Log4j RCE [**] {TCP} 203.0.113.50:12345 -> 10.0.0.5:8080'
    resp_l2 = await pipeline.process_event(ids_log, source="ids")
    assert resp_l2.quarantine is None
    assert resp_l2.event_id != ""


@pytest.mark.asyncio
async def test_m_tier3_invocation_tracking():
    """M. Tier-3 Invocation Tracking: Event-level and global counter verified."""
    v1_log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW"
    resp1 = await pipeline.process_event(v1_log, source="firewall")
    assert resp1.tier3_invocations == 0
    assert pipeline.metrics["tier3_count"] == 0

    v2_log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"
    resp2 = await pipeline.process_event(v2_log, source="firewall", auto_promote=True)
    assert resp2.tier3_invocations == 1
    assert pipeline.metrics["tier3_count"] == 1

    resp3 = await pipeline.process_event(v1_log, source="firewall")
    assert resp3.tier3_invocations == 0
    assert pipeline.metrics["tier3_count"] == 1
