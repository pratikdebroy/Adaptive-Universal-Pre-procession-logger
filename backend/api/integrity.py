"""
Integrity API — verify batch integrity, manage ledger, tamper demo.
"""

from fastapi import APIRouter, HTTPException

from backend.core.pipeline import pipeline
from backend.integrity.merkle import MerkleTree
from backend.integrity.ledger import IntegrityLedger
from backend.models import MerkleVerification

router = APIRouter(prefix="/api/integrity", tags=["Integrity"])

ledger = IntegrityLedger()


@router.post("/verify")
async def verify_integrity():
    """Verify integrity of all stored events."""
    event_ids = pipeline.vault.list_events(limit=100)
    if not event_ids:
        return {"status": "NO_EVENTS", "message": "No events to verify"}

    hashes = []
    tampered = []
    for eid in event_ids:
        intact, stored, recomputed = pipeline.vault.verify_integrity(eid)
        hashes.append(recomputed)
        if not intact:
            tampered.append(eid)

    tree = MerkleTree(hashes)

    # Check against ledger
    latest = await ledger.get_latest()
    if latest:
        matches = tree.root == latest.merkle_root
        status = "VERIFIED" if matches and not tampered else "FAILURE"
    else:
        status = "VERIFIED" if not tampered else "FAILURE"

    return MerkleVerification(
        batch_id=latest.batch_id if latest else "none",
        expected_root=latest.merkle_root if latest else "",
        computed_root=tree.root,
        integrity_status=status,
        event_hashes=hashes[:20],  # Limit response size
        tampered_events=tampered,
    )


@router.post("/commit")
async def commit_batch():
    """Commit current events to the ledger."""
    event_ids = pipeline.vault.list_events(limit=100)
    if not event_ids:
        raise HTTPException(400, "No events to commit")

    hashes = []
    for eid in event_ids:
        raw = pipeline.vault.retrieve(eid)
        if raw:
            hashes.append(raw.raw_sha256)

    entry = await ledger.commit_batch(event_ids, hashes)
    return {"status": "COMMITTED", "entry": entry.model_dump()}


@router.get("/ledger")
async def get_ledger(limit: int = 50):
    """Get ledger entries."""
    entries = await ledger.get_entries(limit=limit)
    return {
        "entries": [e.model_dump() for e in entries],
        "count": len(entries),
        "label": "Prototype Permissioned-Ledger Adapter",
    }


@router.post("/tamper-demo")
async def tamper_demo():
    """
    Deliberately modify a stored raw event for tamper detection demo.
    THIS IS ONLY FOR DEMONSTRATION PURPOSES.
    """
    event_ids = pipeline.vault.list_events(limit=10)
    if not event_ids:
        raise HTTPException(400, "No events to tamper")

    target_id = event_ids[0]
    success = pipeline.vault.tamper_for_demo(target_id)

    if not success:
        raise HTTPException(500, "Failed to tamper event")

    # Verify to show failure
    intact, stored, recomputed = pipeline.vault.verify_integrity(target_id)

    return {
        "status": "TAMPERED",
        "event_id": target_id,
        "integrity_intact": intact,
        "stored_hash": stored,
        "recomputed_hash": recomputed,
        "message": "Event has been deliberately modified for demonstration. Run /api/integrity/verify to see INTEGRITY FAILURE.",
    }


@router.post("/verify-chain")
async def verify_chain():
    """Verify the complete ledger chain."""
    valid, issues = await ledger.verify_chain()
    return {
        "chain_valid": valid,
        "issues": issues,
        "label": "Prototype Permissioned-Ledger Adapter",
    }
