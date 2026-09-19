"""
Pipeline Orchestrator — the central engine.

Implements the complete processing flow:
  RAW EVENT → PRESERVE → FAST PATH → FORMAT DRIFT → STRUCTURAL ANALYSIS
  → TIER-3 ADAPTIVE → PARSER SPECIFICATION → PARSER SAFETY VALIDATION
  → EVENT TRUST GATE → OCSF → PARSER REGISTRY → FAST PATH REPLAY

Classification: IMPLEMENTED
"""

from __future__ import annotations

import time
import json
import logging
from datetime import datetime, timezone
from typing import Any

from backend.config import settings
from backend.models import (
    ProcessingMode, ValidationResult, QuarantineReason, QuarantineSeverity,
    ProcessedEventResponse, PipelineStageInfo, RawEvent,
    ParsedFields, ParserSpecification, QuarantineEntry,
    TrustGateResult, ValidationCheck,
)
from backend.storage.evidence_vault import EvidenceVault, create_processing_copy
from backend.ingestion.defensive import (
    run_ingestion_safety_checks, SourceRateLimiter, global_rate_limiter,
)
from backend.parsers.fast_path import FastPathEngine
from backend.parsers.format_router import FormatRouter
from backend.adaptive.tier1_template import Tier1Matcher
from backend.adaptive.tier2_structural import StructuralAnalyzer
from backend.adaptive.tier3_slm_rag import Tier3Adaptive
from backend.adaptive.rag_index import ParserRAG
from backend.adaptive.slm_interface import get_current_inference_mode, get_inference_provider
from backend.validation.trust_gate import ParserSafetyValidator, HybridTrustGate
from backend.normalization.ocsf_normalizer import OCSFNormalizer
from backend.registry.parser_registry import ParserRegistry
from backend.storage.database import get_db

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """
    The central processing pipeline.
    Coordinates all stages from raw ingestion to OCSF output.
    """

    def __init__(self):
        # Core components
        self.vault = EvidenceVault()
        self.rate_limiter = global_rate_limiter
        self.fast_path = FastPathEngine()
        self.router = FormatRouter(self.fast_path)
        self.tier1 = Tier1Matcher()
        self.structural = StructuralAnalyzer()
        self.rag = ParserRAG()
        self.tier3 = Tier3Adaptive(self.rag)
        self.parser_safety = ParserSafetyValidator()
        self.trust_gate = HybridTrustGate()
        self.normalizer = OCSFNormalizer()
        self.registry: ParserRegistry | None = None

        # Metrics (from actual execution)
        self.metrics = {
            "total_events": 0,
            "fast_path_count": 0,
            "structural_count": 0,
            "tier3_count": 0,
            "quarantine_count": 0,
            "fast_path_latencies": [],
            "adaptive_latencies": [],
        }

    async def initialize(self):
        """Initialize all components. Called on startup."""
        from backend.parsers.templates import KNOWN_PARSERS

        # Initialize registry
        self.registry = ParserRegistry(self.fast_path)

        # Ensure only known baseline parsers exist from start (remove any leftover adaptive parsers from previous sessions)
        try:
            db = await get_db()
            try:
                placeholders = ",".join("?" * len(KNOWN_PARSERS))
                await db.execute(
                    f"DELETE FROM parsers WHERE parser_id NOT IN ({placeholders})",
                    tuple(KNOWN_PARSERS.keys()),
                )
                await db.commit()
            finally:
                await db.close()
        except Exception as e:
            logger.warning(f"Error cleaning leftover adaptive parsers on startup: {e}")

        # Seed known parsers
        for parser_id, (name, spec) in KNOWN_PARSERS.items():
            # Load into fast path engine directly
            self.fast_path.load_parser(parser_id, spec)

            # Register in DB if not exists
            try:
                existing = await self.registry.get_by_id(parser_id)
                if not existing:
                    record = await self.registry.register_candidate(
                        name=name,
                        source=spec.source_hint,
                        format_signature=self.fast_path.compute_format_signature(spec.template),
                        spec=spec,
                        confidence=1.0,
                        parser_id=parser_id,
                    )
                    await self.registry.promote(record.parser_id)
            except Exception as e:
                logger.warning(f"Error seeding parser {parser_id}: {e}")

        # Seed RAG
        self.rag.seed_known_templates()

        # Load active parsers from registry
        try:
            await self.registry.initialize()
        except Exception:
            pass  # Fresh DB

        # Probe and initialize inference provider
        await get_inference_provider()

        logger.info(
            f"Pipeline initialized. Active parsers: {self.fast_path.get_parser_count()}. Mode: {get_current_inference_mode()}"
        )

    async def process_event(
        self, raw_message: str, source: str = "unknown", auto_promote: bool = True
    ) -> ProcessedEventResponse:
        """
        Process a single raw event through the complete pipeline.
        Returns a full response with all stage information.
        """
        stages: list[PipelineStageInfo] = []
        start_time = time.perf_counter()

        # ── Stage 1: PRESERVE (lossless) ──
        stage_start = time.perf_counter()
        raw_event = self.vault.preserve(raw_message, source)
        stages.append(PipelineStageInfo(
            name="PRESERVE",
            status="COMPLETE",
            event_count=1,
            latency_ms=_ms(stage_start),
        ))

        # ── Stage 2: INGESTION SAFETY CHECKS (Defensive Transport, Resource & Format) ──
        stage_start = time.perf_counter()
        safety_res = run_ingestion_safety_checks(raw_event, self.rate_limiter)
        if not safety_res.safe:
            return await self._quarantine(
                raw_event=raw_event,
                reason=safety_res.reason or QuarantineReason.MALFORMED_INPUT,
                detail=safety_res.detail,
                stages=stages,
                detected_format=safety_res.detected_format,
                failed_check=safety_res.failed_check,
                severity=safety_res.severity,
                metadata=safety_res.metadata,
            )

        # Create processing copy (sanitization on copy only, raw event is preserved verbatim)
        proc_copy = create_processing_copy(raw_event)
        message = proc_copy.sanitized_message

        # Check if message is empty after sanitization
        if not message.strip():
            return await self._quarantine(
                raw_event=raw_event,
                reason=QuarantineReason.EMPTY_EVENT,
                detail="Empty message after sanitization",
                stages=stages,
                detected_format=safety_res.detected_format,
                failed_check="transport.empty_sanitized",
                severity=QuarantineSeverity.LOW,
            )

        stages.append(PipelineStageInfo(
            name="INGEST",
            status="COMPLETE",
            event_count=1,
            latency_ms=_ms(stage_start),
            processing_mode=f"format:{safety_res.detected_format}, sanitization:{proc_copy.sanitization_applied if proc_copy.sanitization_applied else 'clean'}",
        ))

        # ── Stage 3: ROUTE — Fast Path or Adaptive ──
        stage_start = time.perf_counter()
        route, parsed, parser_id = self.router.route(proc_copy)
        stages.append(PipelineStageInfo(
            name="ROUTE",
            status="COMPLETE",
            latency_ms=_ms(stage_start),
            processing_mode=route,
        ))

        tier_detail = ""
        processing_mode = ProcessingMode.FAST_PATH
        confidence = 0.0
        tier3_invocations_this_event = 0

        if route == "FAST_PATH" and parsed:
            # ── FAST PATH ──
            processing_mode = ProcessingMode.FAST_PATH
            confidence = parsed.confidence
            tier_detail = f"FAST PATH — parser: {parser_id}"
            latency = _ms(stage_start)
            self.metrics["fast_path_count"] += 1
            self.metrics["fast_path_latencies"].append(latency)

            stages.append(PipelineStageInfo(
                name="PARSE",
                status="COMPLETE",
                latency_ms=latency,
                processing_mode="FAST PATH",
            ))

        else:
            # ── ADAPTIVE PATH ──
            adaptive_start = time.perf_counter()

            # Tier 1: Template matching (BDPT)
            t1_confident, t1_score, t1_detail = self.tier1.match(message)
            tier_detail = f"Tier-1: {t1_detail.get('status', '')}"

            stages.append(PipelineStageInfo(
                name="TIER-1 TEMPLATE",
                status="MATCHED" if t1_confident else "ESCALATED",
                latency_ms=_ms(adaptive_start),
                processing_mode="TEMPLATE MATCHING (BDPT)",
            ))

            if not t1_confident:
                # Tier 2: Structural analysis (dual confidence: structural vs semantic)
                t2_start = time.perf_counter()
                known_keys = self.fast_path.get_known_keys(source) if self.fast_path else set()
                t2_confident, t2_score, t2_spec, t2_detail = self.structural.analyze(
                    message, known_keys
                )
                tier_detail += f" → Tier-2: struct_conf={t2_detail.get('structural_confidence', 0):.2f}, sem_conf={t2_score:.2f} (confident={t2_confident})"

                stages.append(PipelineStageInfo(
                    name="TIER-2 STRUCTURAL",
                    status="PARSED" if t2_confident else "ESCALATED",
                    latency_ms=_ms(t2_start),
                    processing_mode="STRUCTURAL ANALYSIS",
                ))

                if t2_confident and t2_spec:
                    # Structural analysis produced a spec
                    processing_mode = ProcessingMode.STRUCTURAL
                    confidence = t2_score
                    self.metrics["structural_count"] += 1

                    # Execute the structural spec to get parsed fields
                    parsed = self._execute_spec(message, t2_spec, ProcessingMode.STRUCTURAL)
                    parser_id = ""

                    # Try to register as candidate
                    candidate_spec = t2_spec
                    candidate_detail = t2_detail

                else:
                    # Tier 3: SLM/Fallback + RAG
                    t3_start = time.perf_counter()
                    t3_spec, t3_conf, t3_detail = await self.tier3.adapt(
                        message, t2_detail
                    )
                    processing_mode = ProcessingMode.TIER3_ADAPTIVE
                    tier3_invocations_this_event = 1
                    self.metrics["tier3_count"] += 1
                    tier_detail += f" → Tier-3: {t3_detail.get('inference_mode', '')}"

                    stages.append(PipelineStageInfo(
                        name="TIER-3 ADAPTIVE",
                        status="COMPLETE" if t3_spec else "FAILED",
                        latency_ms=_ms(t3_start),
                        processing_mode=t3_detail.get("inference_mode", ""),
                    ))

                    if t3_spec:
                        confidence = t3_conf
                        parsed = self._execute_spec(message, t3_spec, ProcessingMode.TIER3_ADAPTIVE)
                        parser_id = ""
                        candidate_spec = t3_spec
                        candidate_detail = t3_detail
                    else:
                        return await self._quarantine(
                            raw_event, QuarantineReason.UNSUPPORTED_FORMAT,
                            "All parsing tiers failed", stages
                        )

                # ── Parser Safety Validation ──
                if 'candidate_spec' in locals() and candidate_spec:
                    safety = self.parser_safety.validate_spec(candidate_spec)
                    stages.append(PipelineStageInfo(
                        name="PARSER SAFETY",
                        status="SAFE" if safety.safe else "UNSAFE",
                    ))
                    if not safety.safe:
                        return await self._quarantine(
                            raw_event=raw_event,
                            reason=safety.primary_reason,
                            detail=f"Parser safety check failed: {'; '.join(safety.failure_reasons)}",
                            stages=stages,
                            failed_check=safety.failed_check_name or "parser_safety",
                            severity=safety.primary_severity,
                        )

                    # Register candidate and promote
                    if self.registry and parsed:
                        try:
                            sig = self.fast_path.compute_format_signature(message)
                            record = await self.registry.register_candidate(
                                name=f"adaptive_{sig[:8]}",
                                source=source,
                                format_signature=sig,
                                spec=candidate_spec,
                                confidence=confidence,
                            )
                            parser_id = record.parser_id

                            # Update the BDPT tree with the new template
                            self.tier1.add_template(message)

                            # Promote immediately since it passed Parser Safety
                            if auto_promote:
                                await self.registry.promote(parser_id)
                                stages.append(PipelineStageInfo(
                                    name="REGISTRY",
                                    status="PROMOTED",
                                    processing_mode="CANDIDATE → ACTIVE",
                                ))

                        except Exception as e:
                            logger.warning(f"Failed to register/promote candidate: {e}")

                adaptive_latency = _ms(adaptive_start)
                self.metrics["adaptive_latencies"].append(adaptive_latency)

            else:
                # Tier 1 matched — this is structural path
                processing_mode = ProcessingMode.STRUCTURAL
                confidence = t1_score
                self.metrics["structural_count"] += 1

                # Still need to parse with fast path or structural
                parsed = self._try_parse_from_template(message, t1_detail)
                if not parsed:
                    known_keys = self.fast_path.get_known_keys(source) if self.fast_path else set()
                    t2_confident, t2_score, t2_spec, t2_detail = self.structural.analyze(message, known_keys)
                    if t2_spec:
                        parsed = self._execute_spec(message, t2_spec, ProcessingMode.STRUCTURAL)

        # ── Stage 4: VALIDATE (Event Trust Gate) ──
        if parsed and parsed.fields:
            stage_start = time.perf_counter()
            validation = self.trust_gate.validate(parsed.fields, confidence, source_hint=source)
            stages.append(PipelineStageInfo(
                name="VALIDATE",
                status=validation.result.value,
                latency_ms=_ms(stage_start),
            ))

            if validation.result == ValidationResult.QUARANTINED:
                return await self._quarantine(
                    raw_event=raw_event,
                    reason=validation.primary_reason,
                    detail="; ".join(validation.failure_reasons),
                    stages=stages,
                    validation=validation,
                    failed_check=validation.failed_check_name,
                    severity=validation.primary_severity,
                    metadata={"failed_value": validation.failed_value} if validation.failed_value is not None else {},
                )

            # ── Stage 5: PII MASKING ──
            stage_start = time.perf_counter()
            from backend.validation.pii_masking import pii_masker
            masked_fields = pii_masker.mask(parsed.fields)
            stages.append(PipelineStageInfo(
                name="PII MASKING",
                status="COMPLETE",
                latency_ms=_ms(stage_start),
            ))

            # ── Stage 6: NORMALIZE (OCSF) ──
            stage_start = time.perf_counter()
            ocsf_event = self.normalizer.normalize(
                parsed_fields=masked_fields,
                raw_event=raw_event,
                parser_id=parser_id or "",
                parser_version=parsed.parser_version,
                processing_mode=processing_mode,
                confidence=confidence,
            )
            stages.append(PipelineStageInfo(
                name="NORMALIZE",
                status="COMPLETE",
                latency_ms=_ms(stage_start),
                processing_mode="OCSF",
            ))

            # ── Save to DB ──
            await self._save_processed(raw_event, parsed, ocsf_event, processing_mode, parser_id, confidence, tier_detail)

            self.metrics["total_events"] += 1
            total_latency = _ms(start_time)

            # Look up parser name
            parser_name = ""
            if parser_id:
                if self.registry:
                    rec = await self.registry.get_by_id(parser_id)
                    if rec:
                        parser_name = rec.name
                        parsed.parser_version = rec.parser_version

            return ProcessedEventResponse(
                event_id=raw_event.event_id,
                raw_sha256=raw_event.raw_sha256,
                processing_mode=processing_mode,
                parser_id=parser_id or "",
                parser_name=parser_name,
                parser_version=parsed.parser_version,
                confidence=confidence,
                validation=validation,
                ocsf_event=ocsf_event,
                tier_detail=tier_detail,
                stages=stages,
                inference_mode=get_current_inference_mode(),
                tier3_invocations=tier3_invocations_this_event,
            )

        # Should not reach here normally
        return await self._quarantine(
            raw_event, QuarantineReason.MALFORMED_INPUT,
            "No parsed fields produced", stages
        )

    def _execute_spec(
        self, message: str, spec: ParserSpecification, mode: ProcessingMode
    ) -> ParsedFields:
        """Execute a parser spec against a message to extract fields."""
        fields, confidence = self.fast_path._execute_spec(message, spec)
        return ParsedFields(
            fields=fields,
            processing_mode=mode,
            confidence=confidence,
        )

    def _try_parse_from_template(self, message: str, t1_detail: dict) -> ParsedFields | None:
        """Try to parse using fast-path engine after Tier-1 match."""
        _, parsed, confidence = self.fast_path.parse(message)
        return parsed

    async def _quarantine(
        self,
        raw_event: RawEvent,
        reason: QuarantineReason,
        detail: str,
        stages: list[PipelineStageInfo],
        validation=None,
        detected_format: str = "unknown",
        failed_check: str = "",
        severity: QuarantineSeverity = QuarantineSeverity.MEDIUM,
        metadata: dict[str, Any] | None = None,
        processing_mode: ProcessingMode | None = None,
    ) -> ProcessedEventResponse:
        """Send event to quarantine."""
        self.metrics["quarantine_count"] += 1
        self.metrics["total_events"] += 1

        resolved_failures = validation.failure_reasons if validation and validation.failure_reasons else [detail]
        resolved_failed_check = failed_check or (validation.failed_check_name if validation and validation.failed_check_name else reason.value)

        if validation is None:
            validation = TrustGateResult(
                result=ValidationResult.QUARANTINED,
                passed=False,
                checks=[ValidationCheck(check_name=resolved_failed_check, passed=False, detail=detail)],
                failure_reasons=resolved_failures,
                primary_reason=reason,
                primary_severity=severity,
                failed_check_name=resolved_failed_check,
            )

        entry = QuarantineEntry(
            event_id=raw_event.event_id,
            raw_message=raw_event.raw_message,
            raw_sha256=raw_event.raw_sha256,
            source=raw_event.source,
            detected_format=detected_format,
            reason=reason,
            failed_check=resolved_failed_check,
            severity=severity,
            detail=detail,
            validation_failures=resolved_failures,
            metadata=metadata or {},
        )

        # Save to DB
        try:
            db = await get_db()
            try:
                await db.execute(
                    """INSERT OR IGNORE INTO raw_events
                       (event_id, received_at, source, raw_message, raw_sha256, evidence_path)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        raw_event.event_id, raw_event.received_at.isoformat(),
                        raw_event.source, raw_event.raw_message, raw_event.raw_sha256,
                        str(self.vault.evidence_dir / f"{raw_event.event_id}.json"),
                    ),
                )
                await db.execute(
                    """INSERT INTO quarantine
                       (quarantine_id, event_id, raw_message, raw_sha256, source, detected_format,
                        reason, failed_check, severity, detail, validation_failures, metadata, timestamp, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.quarantine_id, entry.event_id, entry.raw_message,
                        entry.raw_sha256, entry.source, entry.detected_format,
                        entry.reason.value, entry.failed_check, entry.severity.value,
                        entry.detail, json.dumps(entry.validation_failures),
                        json.dumps(entry.metadata), entry.timestamp.isoformat(),
                        entry.status,
                    ),
                )
                await db.commit()
            finally:
                await db.close()
        except Exception as e:
            logger.warning(f"Failed to save quarantine: {e}")

        stages.append(PipelineStageInfo(
            name="QUARANTINE",
            status=reason.value,
            processing_mode=f"[{severity.value}] {resolved_failed_check}: {detail}",
        ))

        # Infer mode if not explicitly provided
        if not processing_mode:
            processing_mode = ProcessingMode.FAST_PATH if any(s.processing_mode == "FAST PATH" for s in stages) else ProcessingMode.TIER3_ADAPTIVE

        return ProcessedEventResponse(
            event_id=raw_event.event_id,
            raw_sha256=raw_event.raw_sha256,
            processing_mode=processing_mode,
            quarantine=entry,
            tier_detail=f"QUARANTINED: [{severity.value}] {reason.value} ({resolved_failed_check}) — {detail}",
            stages=stages,
            inference_mode=get_current_inference_mode(),
            validation=validation,
            tier3_invocations=0,
        )

    async def _save_processed(
        self, raw_event, parsed, ocsf_event, mode, parser_id, confidence, tier_detail
    ):
        """Save processed event to DB."""
        try:
            db = await get_db()
            try:
                await db.execute(
                    """INSERT OR IGNORE INTO raw_events
                       (event_id, received_at, source, raw_message, raw_sha256, evidence_path)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        raw_event.event_id, raw_event.received_at.isoformat(),
                        raw_event.source, raw_event.raw_message, raw_event.raw_sha256,
                        str(self.vault.evidence_dir / f"{raw_event.event_id}.json"),
                    ),
                )
                await db.execute(
                    """INSERT OR REPLACE INTO processed_events
                       (event_id, raw_event_id, raw_sha256, parser_id, parser_name,
                        parser_version, processing_mode, confidence, ocsf_json,
                        validation_result, tier_detail, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        raw_event.event_id, raw_event.event_id, raw_event.raw_sha256,
                        parser_id or "", "", parsed.parser_version if parsed else 0,
                        mode.value, confidence,
                        ocsf_event.model_dump_json() if ocsf_event else "{}",
                        "APPROVED", tier_detail,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                await db.commit()
            finally:
                await db.close()
        except Exception as e:
            logger.warning(f"Failed to save processed event: {e}")

    def get_metrics(self) -> dict[str, Any]:
        """Return actual pipeline metrics."""
        total = self.metrics["total_events"]
        fp = self.metrics["fast_path_count"]
        sc = self.metrics["structural_count"]
        t3 = self.metrics["tier3_count"]
        qr = self.metrics["quarantine_count"]

        fp_lats = self.metrics["fast_path_latencies"]
        ad_lats = self.metrics["adaptive_latencies"]

        return {
            "total_events": total,
            "fast_path_count": fp,
            "structural_count": sc,
            "tier3_count": t3,
            "quarantine_count": qr,
            "tier3_invocation_rate": (t3 / total * 100) if total > 0 else 0.0,
            "avg_fast_path_latency_ms": sum(fp_lats) / len(fp_lats) if fp_lats else 0.0,
            "avg_adaptive_latency_ms": sum(ad_lats) / len(ad_lats) if ad_lats else 0.0,
            "inference_mode": get_current_inference_mode(),
            "parsers_active": self.fast_path.get_parser_count(),
        }

    async def reset(self):
        """Reset pipeline state for demo."""
        from backend.storage.database import reset_db
        self.vault.clear()
        await reset_db()
        self.metrics = {
            "total_events": 0,
            "fast_path_count": 0,
            "structural_count": 0,
            "tier3_count": 0,
            "quarantine_count": 0,
            "fast_path_latencies": [],
            "adaptive_latencies": [],
        }
        self.fast_path = FastPathEngine()
        self.router = FormatRouter(self.fast_path)
        self.tier1 = Tier1Matcher()
        self.rag = ParserRAG()
        self.tier3 = Tier3Adaptive(self.rag)
        await self.initialize()


# Singleton
pipeline = PipelineOrchestrator()


def _ms(start: float) -> float:
    """Convert perf_counter delta to milliseconds."""
    return (time.perf_counter() - start) * 1000
