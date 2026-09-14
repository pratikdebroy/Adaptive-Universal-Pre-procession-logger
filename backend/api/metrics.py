"""
Metrics + Health API.
"""

from __future__ import annotations

import time
from fastapi import APIRouter

from backend.core.pipeline import pipeline
from backend.adaptive.slm_interface import get_current_inference_mode, is_ollama_available
from backend.models import FeatureClassification

router = APIRouter(tags=["Metrics"])

_start_time = time.time()


@router.get("/api/metrics")
async def get_metrics():
    """Pipeline metrics + Tier-3 invocation stats — all from actual execution."""
    return pipeline.get_metrics()


@router.get("/api/health")
@router.get("/health")
async def health_check():
    """Health check + AI mode status."""
    from backend.adaptive.slm_interface import check_ollama_availability, get_inference_provider, is_ollama_available
    ollama_ok = await check_ollama_availability(force_refresh=not is_ollama_available())
    await get_inference_provider()
    return {
        "status": "healthy",
        "inference_mode": get_current_inference_mode(),
        "ollama_available": ollama_ok,
        "parsers_loaded": pipeline.fast_path.get_parser_count(),
        "uptime_seconds": round(time.time() - _start_time, 1),
        "classification": {
            "pipeline": FeatureClassification.IMPLEMENTED,
            "fast_path": FeatureClassification.IMPLEMENTED,
            "adaptive_parsing": FeatureClassification.IMPLEMENTED,
            "trust_gate": FeatureClassification.IMPLEMENTED,
            "ocsf_normalization": FeatureClassification.IMPLEMENTED,
            "parser_registry": FeatureClassification.IMPLEMENTED,
            "evidence_vault": FeatureClassification.IMPLEMENTED,
            "merkle_integrity": FeatureClassification.IMPLEMENTED,
            "ledger": FeatureClassification.IMPLEMENTED,
            "quarantine": FeatureClassification.IMPLEMENTED,
            "ollama_integration": FeatureClassification.PROTOTYPE_ABSTRACTION,
            "distributed_deployment": FeatureClassification.PROTOTYPE_ABSTRACTION,
            "blockchain_ledger": FeatureClassification.PROTOTYPE_ABSTRACTION,
        },
    }


@router.get("/api/status")
@router.get("/status")
async def system_status():
    """General system status and live counts."""
    metrics = pipeline.get_metrics()
    quarantine_count = metrics.get("quarantine_count", 0)
    return {
        "status": "operational",
        "uptime_seconds": round(time.time() - _start_time, 1),
        "parsers_count": pipeline.fast_path.get_parser_count(),
        "quarantine_count": quarantine_count,
        "total_events": metrics.get("total_events", 0),
        "tier3_invocations": metrics.get("tier3_count", 0),
        "inference_mode": get_current_inference_mode(),
        "is_air_gapped": True,
    }


@router.get("/api/config/status")
@router.get("/config/status")
async def config_status():
    """Configuration status and active thresholds."""
    from backend.config import settings
    return {
        "fast_path_threshold": settings.fast_path_confidence_threshold,
        "structural_threshold": settings.structural_confidence_threshold,
        "semantic_threshold": settings.semantic_confidence_threshold,
        "tier3_threshold": settings.tier3_confidence_threshold,
        "trust_gate_threshold": settings.min_confidence_threshold,
        "inference_mode": settings.inference_mode,
        "ollama_model": settings.ollama_model,
        "ollama_base_url": settings.ollama_base_url,
    }


@router.get("/api/ollama/status")
@router.get("/ollama/status")
async def ollama_status():
    """Ollama local SLM runtime status."""
    from backend.adaptive.slm_interface import check_ollama_availability, get_inference_provider, get_current_inference_mode
    from backend.config import settings
    available = await check_ollama_availability(force_refresh=True)
    await get_inference_provider(force_refresh=True)
    return {
        "available": available,
        "status": "ACTIVE" if available else "UNAVAILABLE",
        "model": settings.ollama_model if available else None,
        "base_url": settings.ollama_base_url,
        "active_mode": "LOCAL_SLM" if available else "DEMO_INFERENCE_FALLBACK",
        "active_provider_label": get_current_inference_mode(),
    }
