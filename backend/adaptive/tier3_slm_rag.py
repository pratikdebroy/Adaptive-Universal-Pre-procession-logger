"""
Tier-3 adaptive parser — orchestrates RAG retrieval + inference (SLM or Fallback).

Terminology: "TIER-3 INFERENCE INVOCATIONS"

Classification: IMPLEMENTED
"""

from __future__ import annotations

from backend.adaptive.rag_index import ParserRAG
from backend.adaptive.slm_interface import get_inference_provider, InferenceResult, DemoFallbackProvider
from backend.models import ParserSpecification
import logging

logger = logging.getLogger(__name__)


class Tier3Adaptive:
    """
    Tier 3: Combines historical template retrieval (RAG) with
    inference (local SLM or Demo Fallback) to generate candidate parser specs.
    """

    def __init__(self, rag: ParserRAG):
        self.rag = rag

    async def adapt(
        self,
        message: str,
        structural_hints: dict,
    ) -> tuple[ParserSpecification | None, float, dict]:
        """
        Full Tier-3 adaptive flow:
        1. Retrieve similar templates from RAG
        2. Call inference provider (Ollama or Demo Fallback)
        3. Return candidate spec + confidence + detail

        Returns: (candidate_spec, confidence, detail_dict)
        """
        # Step 1: RAG retrieval
        retrieved = self.rag.retrieve_similar(message)

        # Step 2: Inference
        provider = await get_inference_provider()
        inference_mode = provider.get_mode_label()

        try:
            result: InferenceResult = await provider.infer(
                log_line=message,
                historical_templates=retrieved,
                structural_hints=structural_hints,
            )

            detail = {
                "retrieved_templates": [
                    {
                        "template_id": t.get("template_id", ""),
                        "similarity": round(t.get("similarity", 0), 4),
                        "source": t.get("source", ""),
                        "previously_validated": t.get("previously_validated", False),
                    }
                    for t in retrieved
                ],
                "inference_mode": inference_mode,
                "inference_detail": result.detail,
                "resolved_mappings": [r.model_dump() for r in result.resolved_mappings],
                "mapping": result.spec.fields if result.spec else {},
                "field_types": result.spec.field_types if result.spec else {},
                "confidence": result.confidence,
                "tier": "TIER-3 ADAPTIVE",
            }

            return result.spec, result.confidence, detail

        except Exception as e:
            logger.warning(f"Primary inference failed ({e}). Falling back to DemoFallbackProvider.")
            try:
                fallback_provider = DemoFallbackProvider()
                result = await fallback_provider.infer(
                    log_line=message,
                    historical_templates=retrieved,
                    structural_hints=structural_hints,
                )
                detail = {
                    "retrieved_templates": [
                        {
                            "template_id": t.get("template_id", ""),
                            "similarity": round(t.get("similarity", 0), 4),
                            "source": t.get("source", ""),
                            "previously_validated": t.get("previously_validated", False),
                        }
                        for t in retrieved
                    ],
                    "inference_mode": fallback_provider.get_mode_label(),
                    "inference_detail": f"Fallback after {inference_mode} error: {e}",
                    "resolved_mappings": [r.model_dump() for r in result.resolved_mappings],
                    "mapping": result.spec.fields if result.spec else {},
                    "field_types": result.spec.field_types if result.spec else {},
                    "confidence": result.confidence,
                    "tier": "TIER-3 ADAPTIVE",
                }
                return result.spec, result.confidence, detail
            except Exception as fb_err:
                detail = {
                    "retrieved_templates": [],
                    "inference_mode": inference_mode,
                    "inference_detail": f"Inference failed: {e}; fallback failed: {fb_err}",
                    "confidence": 0.0,
                    "tier": "TIER-3 ADAPTIVE",
                    "error": str(e),
                }
                return None, 0.0, detail
