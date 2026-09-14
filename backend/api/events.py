"""
Events API — process, list, inspect events.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.core.pipeline import pipeline
from backend.storage.database import get_db

router = APIRouter(prefix="/api/events", tags=["Events"])


class ProcessEventRequest(BaseModel):
    raw_message: str
    source: str = "manual"


class BatchProcessRequest(BaseModel):
    events: list[ProcessEventRequest]


@router.post("/process")
async def process_event(req: ProcessEventRequest):
    """Process a single raw event through the complete pipeline."""
    result = await pipeline.process_event(req.raw_message, req.source)
    return result


@router.post("/batch")
async def process_batch(req: BatchProcessRequest):
    """Process a batch of events."""
    results = []
    for event in req.events:
        result = await pipeline.process_event(event.raw_message, event.source)
        results.append(result)
    return {"results": results, "count": len(results)}


@router.get("")
async def list_events(limit: int = 50):
    """List processed events."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT 
                p.event_id, p.raw_sha256, p.parser_id, p.processing_mode, p.validation_result, p.created_at,
                r.source, r.raw_message, r.received_at as timestamp 
            FROM processed_events p
            JOIN raw_events r ON p.raw_event_id = r.event_id
            
            UNION ALL
            
            SELECT 
                q.event_id, r.raw_sha256, 'none' as parser_id, 'QUARANTINED' as processing_mode, q.status as validation_result, q.timestamp as created_at,
                r.source, r.raw_message, r.received_at as timestamp
            FROM quarantine q
            JOIN raw_events r ON q.event_id = r.event_id
            
            ORDER BY created_at DESC LIMIT ?
            """,
            (limit,),
        )
        rows = await cursor.fetchall()
        return {"events": [dict(row) for row in rows], "count": len(rows)}
    finally:
        await db.close()


@router.get("/{event_id}")
async def get_event(event_id: str):
    """Get full event with provenance: RAW → SHA-256 → PARSER → OCSF."""
    # Get raw event
    raw_event = pipeline.vault.retrieve(event_id)
    if not raw_event:
        raise HTTPException(404, "Event not found")

    # Get processed event
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM processed_events WHERE event_id = ?", (event_id,)
        )
        processed = await cursor.fetchone()
        processed_data = dict(processed) if processed else None
    finally:
        await db.close()

    # Verify integrity
    intact, stored_hash, recomputed = pipeline.vault.verify_integrity(event_id)

    return {
        "raw_event": {
            "event_id": raw_event.event_id,
            "received_at": raw_event.received_at.isoformat(),
            "source": raw_event.source,
            "raw_message": raw_event.raw_message,
            "raw_sha256": raw_event.raw_sha256,
        },
        "processed_event": processed_data,
        "integrity": {
            "intact": intact,
            "stored_hash": stored_hash,
            "recomputed_hash": recomputed,
        },
    }
