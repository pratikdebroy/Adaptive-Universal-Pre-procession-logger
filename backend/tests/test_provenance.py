"""
Tests for Evidence Vault:
- Lossless raw event preservation (raw event is NEVER sanitized or modified before preservation)
- SHA-256 computation and provenance
- Tamper detection
"""

import shutil
from pathlib import Path
from backend.storage.evidence_vault import EvidenceVault, create_processing_copy


def test_lossless_raw_preservation():
    test_dir = Path("data/test_evidence")
    if test_dir.exists():
        shutil.rmtree(test_dir)

    vault = EvidenceVault(evidence_dir=test_dir)

    # Raw message with dirty characters: null byte, control chars, trailing space
    raw_dirty = "SRC=10.10.1.25\x00 DST=172.16.2.10\x07   "
    raw_event = vault.preserve(raw_dirty, source="dirty_source")

    # Vault must store the EXACT unmodified raw message
    retrieved = vault.retrieve(raw_event.event_id)
    assert retrieved is not None
    assert retrieved.raw_message == raw_dirty
    assert "\x00" in retrieved.raw_message
    assert "\x07" in retrieved.raw_message

    # Verify SHA-256 matches exact bytes
    assert raw_event.raw_sha256 == vault.compute_sha256(raw_dirty)

    # Processing copy is sanitized separately AFTER preservation
    proc_copy = create_processing_copy(raw_event)
    assert "\x00" not in proc_copy.sanitized_message
    assert "\x07" not in proc_copy.sanitized_message
    assert "null_bytes_stripped" in proc_copy.sanitization_applied
    assert "control_chars_stripped" in proc_copy.sanitization_applied

    # Clean up
    vault.clear()
    if test_dir.exists():
        shutil.rmtree(test_dir)


def test_evidence_tamper_detection():
    test_dir = Path("data/test_evidence_tamper")
    if test_dir.exists():
        shutil.rmtree(test_dir)

    vault = EvidenceVault(evidence_dir=test_dir)
    raw_msg = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW"
    raw_event = vault.preserve(raw_msg, source="firewall")

    # Initially intact
    intact, stored_hash, recomputed = vault.verify_integrity(raw_event.event_id)
    assert intact is True
    assert stored_hash == recomputed

    # Deliberately modify stored raw event
    vault.tamper_for_demo(raw_event.event_id)

    # Now verification must report failure
    intact_after, stored_hash_after, recomputed_after = vault.verify_integrity(raw_event.event_id)
    assert intact_after is False
    assert stored_hash_after != recomputed_after

    vault.clear()
    if test_dir.exists():
        shutil.rmtree(test_dir)
