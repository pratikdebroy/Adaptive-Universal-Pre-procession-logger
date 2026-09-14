"""
Tests for Parser Registry:
- Registering candidate parsers
- Promoting candidate to ACTIVE (SQLite transaction + in-memory cache update)
- Rollback functionality
"""

import pytest
from backend.models import ParserSpecification, ParserStatus
from backend.parsers.fast_path import FastPathEngine
from backend.registry.parser_registry import ParserRegistry
from backend.storage.database import init_db, reset_db


@pytest.mark.asyncio
async def test_parser_lifecycle_and_rollback():
    await reset_db()
    fast_path = FastPathEngine()
    registry = ParserRegistry(fast_path)
    await registry.initialize()

    # 1. Register candidate
    spec_v1 = ParserSpecification(
        template="SRC=<*> DST=<*>",
        fields={"SRC": "source.ip", "DST": "destination.ip"},
    )
    candidate = await registry.register_candidate(
        name="test_fw",
        source="firewall",
        format_signature="SIG_V1",
        spec=spec_v1,
        confidence=0.9,
    )
    assert candidate.status == ParserStatus.CANDIDATE

    # Not yet active in fast path
    assert fast_path.get_parser_count() == 0

    # 2. Promote candidate to ACTIVE
    promoted = await registry.promote(candidate.parser_id)
    assert promoted is True

    # Now loaded in fast path
    assert fast_path.get_parser_count() == 1
    active_rec = await registry.get_by_id(candidate.parser_id)
    assert active_rec.status == ParserStatus.ACTIVE
    assert active_rec.parser_version == 2

    # 3. Rollback
    rolled_back = await registry.rollback(candidate.parser_id)
    assert rolled_back is True


@pytest.mark.asyncio
async def test_parser_approval_endpoints():
    from httpx import AsyncClient, ASGITransport
    from backend.main import app
    from backend.core.pipeline import pipeline

    await reset_db()
    await pipeline.initialize()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register a candidate parser directly in pipeline registry
        spec = ParserSpecification(
            template="IP=<*> ACTION=<*>",
            fields={"IP": "source.ip", "ACTION": "action"},
        )
        record = await pipeline.registry.register_candidate(
            name="firewall_candidate_v2",
            source="firewall",
            format_signature="SIG_V2_TEST",
            spec=spec,
            confidence=0.95,
        )
        cand_id = record.parser_id

        # 2. Check list parsers
        list_resp = await client.get("/api/parsers")
        assert list_resp.status_code == 200
        parsers = list_resp.json()["parsers"]
        cand = next((p for p in parsers if p["parser_id"] == cand_id), None)
        assert cand is not None
        assert cand["status"] == "CANDIDATE"

        # 3. Approve and Promote via API
        approve_resp = await client.post(f"/api/parsers/{cand_id}/promote")
        assert approve_resp.status_code == 200
        data = approve_resp.json()
        assert data["status"] == "ACTIVE"
        assert "promoted to ACTIVE" in data["message"]

        # Verify it is now loaded in fast path
        active_rec = await pipeline.registry.get_by_id(cand_id)
        assert active_rec.status == ParserStatus.ACTIVE

        # 4. Rollback via API
        rollback_resp = await client.post(f"/api/parsers/{cand_id}/rollback")
        assert rollback_resp.status_code == 200
        assert rollback_resp.json()["status"] == "ROLLED_BACK"

