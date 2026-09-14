"""
Tests for Ledger and Append-Only Integrity.
"""

import pytest
from backend.integrity.ledger import IntegrityLedger
from backend.storage.database import reset_db
import hashlib


@pytest.mark.asyncio
async def test_ledger_append_and_chain_verification():
    await reset_db()
    ledger = IntegrityLedger()

    batch1_hashes = [hashlib.sha256(b"e1").hexdigest(), hashlib.sha256(b"e2").hexdigest()]
    entry1 = await ledger.commit_batch(["e1", "e2"], batch1_hashes)
    assert entry1.previous_root == ""
    assert entry1.merkle_root != ""

    batch2_hashes = [hashlib.sha256(b"e3").hexdigest(), hashlib.sha256(b"e4").hexdigest()]
    entry2 = await ledger.commit_batch(["e3", "e4"], batch2_hashes)
    assert entry2.previous_root == entry1.merkle_root

    valid, issues = await ledger.verify_chain()
    assert valid is True
    assert len(issues) == 0
