"""
Parsers API — list, inspect, rollback parsers.
"""

from fastapi import APIRouter, HTTPException

from backend.core.pipeline import pipeline

router = APIRouter(prefix="/api/parsers", tags=["Parsers"])


@router.get("")
async def list_parsers():
    """List all parsers in the registry."""
    if not pipeline.registry:
        return {"parsers": [], "count": 0}
    parsers = await pipeline.registry.get_all()
    return {
        "parsers": [p.model_dump() for p in parsers],
        "count": len(parsers),
    }


@router.get("/{parser_id}")
async def get_parser(parser_id: str):
    """Get parser details by ID."""
    if not pipeline.registry:
        raise HTTPException(404, "Registry not initialized")
    parser = await pipeline.registry.get_by_id(parser_id)
    if not parser:
        raise HTTPException(404, "Parser not found")
    return parser.model_dump()


@router.post("/{parser_id}/promote")
@router.post("/{parser_id}/approve")
async def promote_parser(parser_id: str):
    """Approve and promote a CANDIDATE parser to ACTIVE status."""
    if not pipeline.registry:
        raise HTTPException(500, "Registry not initialized")
    parser = await pipeline.registry.get_by_id(parser_id)
    if not parser:
        raise HTTPException(404, "Parser not found")
    
    success = await pipeline.registry.promote(parser_id)
    if not success:
        raise HTTPException(400, "Parser promotion failed")
        
    updated = await pipeline.registry.get_by_id(parser_id)
    return {
        "status": "ACTIVE",
        "parser_id": parser_id,
        "name": parser.name,
        "version": updated.parser_version if updated else parser.parser_version,
        "message": f"Parser '{parser.name}' approved and promoted to ACTIVE in SQLite registry + Fast Path engine",
    }


@router.post("/{parser_id}/rollback")
async def rollback_parser(parser_id: str):
    """Rollback parser to previous version."""
    if not pipeline.registry:
        raise HTTPException(500, "Registry not initialized")
    success = await pipeline.registry.rollback(parser_id)
    if not success:
        raise HTTPException(400, "Rollback failed")
    return {"status": "ROLLED_BACK", "parser_id": parser_id}

