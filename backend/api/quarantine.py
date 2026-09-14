"""
Quarantine API — list, inspect, review, reprocess, discard, approve quarantined events.
"""

from __future__ import annotations

import json
from typing import Any
from fastapi import APIRouter, HTTPException

from backend.core.pipeline import pipeline
from backend.storage.database import get_db

router = APIRouter(prefix="/api/quarantine", tags=["Quarantine"])


def _format_quarantine_row(row: dict[str, Any]) -> dict[str, Any]:
    """Format row and safely parse JSON fields."""
    item = dict(row)
    # Parse validation_failures
    if isinstance(item.get("validation_failures"), str):
        try:
            item["validation_failures"] = json.loads(item["validation_failures"])
        except Exception:
            item["validation_failures"] = [item["validation_failures"]]
    # Parse metadata
    if isinstance(item.get("metadata"), str):
        try:
            item["metadata"] = json.loads(item["metadata"])
        except Exception:
            item["metadata"] = {}
    return item


@router.get("")
async def list_quarantine(limit: int = 100, status: str | None = None):
    """List quarantined events with full provenance and diagnostic details."""
    db = await get_db()
    try:
        if status:
            cursor = await db.execute(
                "SELECT * FROM quarantine WHERE status = ? ORDER BY timestamp DESC LIMIT ?",
                (status, limit),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM quarantine ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        entries = [_format_quarantine_row(dict(r)) for r in rows]
        return {"entries": entries, "count": len(entries)}
    finally:
        await db.close()


@router.get("/{quarantine_id}")
async def get_quarantine_entry(quarantine_id: str):
    """Get single quarantined event details with provenance."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM quarantine WHERE quarantine_id = ? OR event_id = ?",
            (quarantine_id, quarantine_id),
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Quarantine entry not found")
        return _format_quarantine_row(dict(row))
    finally:
        await db.close()


@router.post("/{quarantine_id}/review")
async def mark_reviewed(quarantine_id: str):
    """Mark a quarantined event as REVIEWED by security analyst."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Quarantine entry not found")

        await db.execute(
            "UPDATE quarantine SET status = 'REVIEWED' WHERE quarantine_id = ?",
            (quarantine_id,),
        )
        await db.commit()
    finally:
        await db.close()
    return {"status": "REVIEWED", "quarantine_id": quarantine_id}


@router.post("/{quarantine_id}/reprocess")
async def reprocess(quarantine_id: str):
    """Reprocess a quarantined event through the pipeline."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Quarantine entry not found")

        raw_message = row["raw_message"]
        source = row["source"]

        # Update status
        await db.execute(
            "UPDATE quarantine SET status = 'REPROCESSED' WHERE quarantine_id = ?",
            (quarantine_id,),
        )
        await db.commit()
    finally:
        await db.close()

    # Reprocess through pipeline
    result = await pipeline.process_event(raw_message, source)
    return {"status": "REPROCESSED", "result": result.model_dump()}


@router.post("/{quarantine_id}/discard")
async def discard(quarantine_id: str):
    """Discard a quarantined event (status update, does not delete evidence)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Quarantine entry not found")

        await db.execute(
            "UPDATE quarantine SET status = 'DISCARDED' WHERE quarantine_id = ?",
            (quarantine_id,),
        )
        await db.commit()
    finally:
        await db.close()
    return {"status": "DISCARDED", "quarantine_id": quarantine_id}


@router.post("/{quarantine_id}/approve")
async def approve(quarantine_id: str):
    """Manually approve/release a quarantined event after review."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Quarantine entry not found")

        await db.execute(
            "UPDATE quarantine SET status = 'RELEASED' WHERE quarantine_id = ?",
            (quarantine_id,),
        )
        await db.commit()
    finally:
        await db.close()
    return {"status": "RELEASED", "quarantine_id": quarantine_id}
