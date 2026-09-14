"""
Plug-and-Play Onboarding API.

Demonstrates onboarding a completely new log source without modifying backend source code:
NEW SOURCE SAMPLE → PROFILE → TEMPLATE DISCOVERY → FIELD MAPPING → VALIDATION → CANDIDATE PARSER → ACTIVE PARSER

Classification: IMPLEMENTED
"""

from __future__ import annotations

import time
from typing import Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.core.pipeline import pipeline
from backend.models import ParserSpecification, ParserStatus, ProcessingMode
from backend.adaptive.tier2_structural import StructuralAnalyzer
from backend.validation.trust_gate import ParserSafetyValidator, HybridTrustGate
from backend.benchmark.demo_data import ONBOARDING_SAMPLES

router = APIRouter(prefix="/api/onboarding", tags=["Onboarding"])

analyzer = StructuralAnalyzer()
safety_validator = ParserSafetyValidator()
trust_gate = HybridTrustGate()


class OnboardingProfileRequest(BaseModel):
    source_name: str
    sample_logs: list[str] = Field(default_factory=list)


class OnboardingPromoteRequest(BaseModel):
    source_name: str
    spec: dict[str, Any]
    candidate_id: str | None = None


@router.get("/samples")
async def get_sample_sources():
    """Get pre-configured onboarding sample sources (e.g. WAF, VPN)."""
    return {
        "sources": [
            {
                "name": "waf_perimeter",
                "description": "Web Application Firewall perimeter traffic logs",
                "samples": ONBOARDING_SAMPLES.get("waf_logs", []),
            },
            {
                "name": "vpn_gateway",
                "description": "Remote Access VPN session logs",
                "samples": ONBOARDING_SAMPLES.get("vpn_logs", []),
            },
        ]
    }


@router.post("/profile")
async def profile_source(req: OnboardingProfileRequest):
    """
    Profile a new source:
    1. Analyze samples
    2. Discover template structure
    3. Map candidate fields to OCSF
    4. Validate parser safety
    5. Test candidate against sample events through Trust Gate
    6. Register as CANDIDATE parser
    """
    if not req.sample_logs:
        raise HTTPException(400, "At least one sample log is required.")

    first_log = req.sample_logs[0]

    # Step 1 & 2: Structural discovery
    confident, score, candidate_spec, detail = analyzer.analyze(first_log)

    if not candidate_spec:
        # Fallback to Tier-3 inference
        spec, conf, t3_detail = await pipeline.tier3.adapt(first_log, detail)
        candidate_spec = spec
        score = conf

    if not candidate_spec:
        raise HTTPException(422, "Unable to discover template structure for provided samples.")

    candidate_spec.source_hint = req.source_name

    # Step 3: Parser Safety Validation
    safety_result = safety_validator.validate_spec(candidate_spec)
    if not safety_result.safe:
        return {
            "status": "SAFETY_FAILED",
            "source_name": req.source_name,
            "safety_result": safety_result.model_dump(),
            "candidate_spec": candidate_spec.model_dump(),
        }

    # Step 4: Test against all samples through Trust Gate
    sample_test_results = []
    all_passed = True
    for sample in req.sample_logs:
        parsed_fields = pipeline._execute_spec(sample, candidate_spec, ProcessingMode.STRUCTURAL)
        gate_res = trust_gate.validate(parsed_fields.fields, score)
        sample_test_results.append({
            "sample": sample,
            "parsed_fields": parsed_fields.fields,
            "gate_result": gate_res.result.value,
            "checks": [c.model_dump() for c in gate_res.checks],
            "passed": gate_res.result.value == "APPROVED",
        })
        if gate_res.result.value != "APPROVED":
            all_passed = False

    # Step 5: Register CANDIDATE parser in registry
    format_sig = pipeline.fast_path.compute_format_signature(first_log)
    candidate_record = await pipeline.registry.register_candidate(
        name=f"custom_{req.source_name}_v1",
        source=req.source_name,
        format_signature=format_sig,
        spec=candidate_spec,
        confidence=score,
        test_results={
            "tested_samples": len(req.sample_logs),
            "all_passed": all_passed,
            "sample_results": sample_test_results,
        },
    )

    return {
        "status": "CANDIDATE_READY",
        "source_name": req.source_name,
        "candidate_id": candidate_record.parser_id,
        "format_signature": format_sig,
        "discovered_template": candidate_spec.template,
        "mapped_fields": candidate_spec.fields,
        "field_types": candidate_spec.field_types,
        "confidence": score,
        "safety_checks": safety_result.model_dump(),
        "sample_validation_passed": all_passed,
        "sample_test_results": sample_test_results,
    }


@router.post("/promote/{parser_id}")
async def promote_custom_parser(parser_id: str):
    """
    Promote discovered candidate parser to ACTIVE.
    Future matching events from this new source will immediately use FAST PATH.
    """
    success = await pipeline.registry.promote(parser_id)
    if not success:
        raise HTTPException(400, f"Failed to promote parser {parser_id}")

    record = await pipeline.registry.get_by_id(parser_id)
    return {
        "status": "PROMOTED_TO_FAST_PATH",
        "parser_id": parser_id,
        "parser_name": record.name if record else "",
        "version": record.parser_version if record else 1,
        "message": f"Source '{record.source if record else 'custom'}' is now fully active on the deterministic FAST PATH.",
    }
