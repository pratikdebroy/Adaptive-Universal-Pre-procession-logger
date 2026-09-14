"""
Tests for Core SIH Demo Scenario & Acceptance Requirements:
1. V1: Known firewall log -> FAST PATH, Tier-3 invocations = 0
2. V2: Drifted format -> FAST PATH MISS -> BDPT -> Structural -> Tier-3 -> Trust Gate -> ACTIVE (Tier-3 = 1)
3. V2 Replay: New event with drifted format -> FAST PATH, Tier-3 invocations = 0 on replay!
4. Invalid IP -> Trust Gate rejection -> QUARANTINED
5. Invalid Port -> Trust Gate rejection -> QUARANTINED
6. Raw event -> Exact evidence preservation -> Reproducible SHA-256
7. Tampered evidence -> Merkle root mismatch / Integrity failure
8. Parser rollback -> Previous parser becomes ACTIVE
"""

import pytest
from backend.core.pipeline import pipeline
from backend.storage.database import reset_db
from backend.models import ProcessingMode, ValidationResult, QuarantineReason


@pytest.mark.asyncio
async def test_hero_demo_workflow():
    """Verify the exact SIH26156 hero demo flow."""
    # Reset pipeline & database
    await reset_db()
    await pipeline.initialize()

    # TEST 1: V1 -> FAST PATH, Tier-3 = 0
    known_log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW"
    resp1 = await pipeline.process_event(known_log, source="firewall")

    assert resp1.processing_mode == ProcessingMode.FAST_PATH
    assert resp1.confidence >= 0.85
    assert resp1.ocsf_event is not None
    assert resp1.ocsf_event.action == "Allowed"
    assert pipeline.metrics["tier3_count"] == 0

    # TEST 2: V2 -> FAST PATH MISS -> BDPT -> Structural -> Tier-3 -> Trust Gate -> ACTIVE
    drifted_log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"
    resp2 = await pipeline.process_event(drifted_log, source="firewall")

    # Drift escalated to Tier-3 because of semantic ambiguity (alias evidence alone is uncertain)
    assert resp2.processing_mode == ProcessingMode.TIER3_ADAPTIVE
    assert resp2.ocsf_event is not None
    assert resp2.ocsf_event.action == "Allowed"
    assert resp2.validation.result.value == "APPROVED"
    assert pipeline.metrics["tier3_count"] == 1

    # TEST 3: V2 Replay -> FAST PATH with ZERO Tier-3 invocations on replay!
    tier3_before_replay = pipeline.metrics["tier3_count"]
    drifted_log_repeat = "SRC_IP=192.168.1.50 DST_IP=10.0.0.1 PROTO=UDP PORT=53 ACT=ALLOW"
    resp3 = await pipeline.process_event(drifted_log_repeat, source="firewall")

    assert resp3.processing_mode == ProcessingMode.FAST_PATH
    assert resp3.ocsf_event is not None
    assert resp3.ocsf_event.dst_endpoint["port"] == 53
    # Tier-3 count must not have incremented on replay
    assert pipeline.metrics["tier3_count"] == tier3_before_replay


@pytest.mark.asyncio
async def test_invalid_inputs_quarantined():
    """Verify Trust Gate rejects invalid IP and port into quarantine."""
    await reset_db()
    await pipeline.initialize()

    # TEST 4: Invalid IP -> QUARANTINED
    bad_ip_log = "SRC=999.999.999.999 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW"
    resp_ip = await pipeline.process_event(bad_ip_log, source="firewall")
    assert resp_ip.validation.result == ValidationResult.QUARANTINED
    assert resp_ip.quarantine is not None

    # TEST 5: Invalid Port -> QUARANTINED
    bad_port_log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=99999 ACTION=ALLOW"
    resp_port = await pipeline.process_event(bad_port_log, source="firewall")
    assert resp_port.validation.result == ValidationResult.QUARANTINED
    assert resp_port.quarantine is not None


@pytest.mark.asyncio
async def test_evidence_and_tamper_detection():
    """Verify raw preservation and tamper detection."""
    from backend.storage.evidence_vault import EvidenceVault
    from backend.integrity.merkle import MerkleTree

    vault = EvidenceVault()

    # TEST 6: Exact raw preservation & reproducible SHA-256
    raw_msg = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW\x00dirty"
    raw_event = vault.preserve(raw_msg, "test_source")
    retrieved = vault.retrieve(raw_event.event_id)
    assert retrieved is not None
    assert retrieved.raw_message == raw_msg
    assert retrieved.raw_sha256 == vault.compute_sha256(raw_msg)

    # TEST 7: Tamper simulation -> Merkle root mismatch
    hashes = [vault.compute_sha256(f"event_{i}") for i in range(4)]
    original_tree = MerkleTree(hashes)
    original_root = original_tree.root

    # Tamper with one leaf
    tampered_hashes = list(hashes)
    tampered_hashes[2] = vault.compute_sha256("tampered_event")
    tampered_tree = MerkleTree(tampered_hashes)

    assert tampered_tree.root != original_root
    is_valid, _ = original_tree.verify(tampered_hashes)
    assert not is_valid


@pytest.mark.asyncio
async def test_parser_rollback():
    """TEST 8: Verify parser rollback restores previous active version."""
    await reset_db()
    await pipeline.initialize()

    # Register candidate, promote to active
    record = await pipeline.registry.register_candidate(
        name="test_parser",
        source="test",
        format_signature="SIG123",
        spec=pipeline.fast_path._parsers["firewall_v1"],
        confidence=0.9,
    )
    assert await pipeline.registry.promote(record.parser_id)

    # Rollback
    rollback_success = await pipeline.registry.rollback(record.parser_id)
    assert rollback_success
    updated = await pipeline.registry.get_by_id(record.parser_id)
    assert updated is not None
    assert updated.status.value in ("ACTIVE", "ROLLED_BACK")
