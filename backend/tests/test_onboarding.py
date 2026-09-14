"""
Tests for Plug-and-Play Onboarding:
NEW SOURCE SAMPLE → PROFILE → TEMPLATE DISCOVERY → FIELD MAPPING → VALIDATION → CANDIDATE PARSER → ACTIVE PARSER
"""

import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.storage.database import reset_db


@pytest.mark.asyncio
async def test_plug_and_play_onboarding_flow():
    await reset_db()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Step 1: Request profiling for a new WAF source
        waf_samples = [
            "CLIENT=203.0.113.50 SERVER=10.0.0.5 METHOD=GET URI=/admin STATUS=403 RULE=SQL_INJECTION",
            "CLIENT=198.51.100.20 SERVER=10.0.0.5 METHOD=POST URI=/login STATUS=200 RULE=NONE",
        ]

        resp = await client.post("/api/onboarding/profile", json={
            "source_name": "perimeter_waf",
            "sample_logs": waf_samples,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "CANDIDATE_READY"
        candidate_id = data["candidate_id"]
        assert candidate_id != ""
        assert data["safety_checks"]["safe"] is True

        # Step 2: Promote candidate to active fast-path parser
        promote_resp = await client.post(f"/api/onboarding/promote/{candidate_id}")
        assert promote_resp.status_code == 200
        promote_data = promote_resp.json()
        assert promote_data["status"] == "PROMOTED_TO_FAST_PATH"

        # Step 3: Send an event from this new source through the main pipeline
        new_event_resp = await client.post("/api/events/process", json={
            "raw_message": "CLIENT=203.0.113.99 SERVER=10.0.0.5 METHOD=GET URI=/api STATUS=200 RULE=NONE",
            "source": "perimeter_waf",
        })
        assert new_event_resp.status_code == 200
        new_data = new_event_resp.json()
        # Must be parsed via FAST_PATH now that it's promoted!
        assert new_data["processing_mode"] == "FAST_PATH"
